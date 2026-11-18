<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use Closure;
use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\CloningVisitor;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Concerns\DetectsLaravelVersion;
use ShieldCI\Concerns\ReadsMiddlewareConfigurator;
use ShieldCI\Concerns\ResolvesClassNames;
use ShieldCI\Support\BootstrapRouteParser;
use ShieldCI\Support\ClassHierarchyIndex;

/**
 * Detects missing authentication and authorization protection.
 *
 * Checks for:
 * - Routes without authentication middleware
 * - Controllers without middleware protection
 * - Missing authorization checks
 * - Unprotected sensitive endpoints
 * - Auth::user() usage without null checks
 */
class AuthenticationAnalyzer extends AbstractFileAnalyzer
{
    use DetectsLaravelVersion;
    use ReadsMiddlewareConfigurator;
    use ResolvesClassNames;

    /**
     * The parameters of ApplicationBuilder::withRouting(), in order.
     */
    private const WITH_ROUTING_PARAMETERS = ['using', 'web', 'api', 'commands', 'channels', 'pages', 'health', 'apiPrefix', 'then'];

    /**
     * @var array<string>
     */
    private array $sensitiveControllerMethods = [
        'destroy',
        'delete',
        'update',
        'edit',
        'store',
        'create',
    ];

    /**
     * @var array<string>
     */
    private array $publicRoutes = [];

    /**
     * Cache of resolved custom middleware auth status.
     *
     * @var array<string, bool>
     */
    private array $resolvedAuthMiddleware = [];

    /**
     * Memoized middleware alias => FQCN map, parsed from bootstrap/app.php
     * (`$middleware->alias([...])`) and app/Http/Kernel.php ($middlewareAliases
     * / legacy $routeMiddleware). Null until first resolved.
     *
     * @var array<string, string>|null
     */
    private ?array $middlewareAliasMap = null;

    /**
     * Memoized middleware group name => members map, parsed from bootstrap/app.php
     * (`$middleware->group(...)` and the calls that add to or remove from a group) and
     * app/Http/Kernel.php ($middlewareGroups). Null until first resolved.
     *
     * @var array<string, list<string>>|null
     */
    private ?array $middlewareGroupMap = null;

    /**
     * The groups resolveMiddlewareGroups() cannot read, by name: one a replaceInGroup() call
     * targets, or a removeFromGroup() or replaceInGroup() call changes with an argument that
     * cannot be read, each mapped to no member; '*' when such a call names a group that cannot
     * be read, which may be any group. Set with $middlewareGroupMap.
     *
     * @var array<string, true>
     */
    private array $unreadMiddlewareGroups = [];

    /**
     * Map of controller methods that are intentionally public.
     * Format: ['ControllerClass::method' => true]
     *
     * @var array<string, true>
     */
    private array $publicControllerMethods = [];

    /**
     * Route-level auth statistics per controller method.
     *
     * Format:
     * [
     *   'Controller::method' => [
     *     'total' => int,
     *     'authenticated' => int,
     *   ]
     * ]
     *
     * @var array<string, array{total: int, authenticated: int}>
     */
    private array $routeAuthStats = [];

    /**
     * Per controller method, how many of the routes reaching it carry auth middleware,
     * counted alike whether or not the route's URI is public: a public_routes entry says
     * a route may go unauthenticated, not that the auth middleware it carries is gone.
     * Read beside $routeAuthStats['total'] by the Auth::user() null check only.
     *
     * @var array<string, int>
     */
    private array $routeAuthCarried = [];

    /**
     * Controller methods a route reaches without auth for a reason other than its URI being
     * listed as public: a guest route, a route that removes auth, which strips the
     * controller's own middleware too, or a GET-only route without auth middleware. Read by
     * the Auth::user() null check only, which lets controller-level auth protect a method
     * public only through public_routes.
     *
     * @var array<string, true>
     */
    private array $routeOpenControllerMethods = [];

    /**
     * Controller methods a route reaches with auth removed at any level, which strips the
     * controller's own auth middleware too (Router::gatherRouteMiddleware()). Read by the
     * Auth::user() null check only.
     *
     * @var array<string, true>
     */
    private array $routeAuthRemovedMethods = [];

    /**
     * Per-run memos of what the new controller-level and middleware-class reads compute:
     * App\ class declarations by lowercase name, whether a class extends Authenticate, and,
     * by spl_object_id() of a class declaration, whether it implements HasMiddleware and
     * the auth entries controllerAuthCovers() reads.
     *
     * @var array<string, array{Node\Stmt\Class_, array<Node>}|null>
     */
    private array $appClassMemo = [];

    /** @var array<string, bool> */
    private array $extendsAuthenticateMemo = [];

    /** @var array<int, bool> */
    private array $hasMiddlewareMemo = [];

    /** @var array<int, list<array{string, array{only?: array<string>, except?: array<string>}, bool}>> */
    private array $controllerAuthEntriesMemo = [];

    /**
     * File-level URI prefixes the framework applies when registering whole route
     * files (e.g. 'api' for routes/api.php), keyed by route file basename: one per
     * registration of the file, '' for one without a prefix, and whether they are required,
     * read from registrations that provably run, so every URL they give must be public for
     * the file's routes to be (see {@see self::resolveRouteFileBasePrefixes()}).
     *
     * @var array<string, array{prefixes: non-empty-list<string>, required: bool}>
     */
    private array $routeFileBasePrefixes = [];

    /**
     * Middleware the framework applies when registering whole route files, keyed by route
     * file basename: what every registration of the file applies, when each of them
     * authenticates (see {@see self::resolveRouteFileBaseMiddleware()}).
     *
     * @var array<string, list<string>>
     */
    private array $routeFileBaseMiddleware = [];

    /**
     * Per FormRequest class, lowercase, the public controller methods that take it (see
     * {@see self::controllerParameterTypes()}), read once per analysis. Null until read.
     *
     * @var array<string, list<array{controllerClass: string, namespace: string, methodName: string, classNode: Node\Stmt\Class_}>>|null
     */
    private ?array $controllerParameterTypes = null;

    /**
     * Each route file's routes and groups as RouteAuthVisitor collects them, keyed by path,
     * read once per analysis.
     *
     * @var array<string, RouteAuthVisitor>
     */
    private array $routeVisitors = [];

    public function __construct(
        private AstParser $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'authentication-authorization',
            name: 'Authentication & Authorization Analyzer',
            description: 'Detects missing authentication and authorization protection on routes and controllers',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['authentication', 'authorization', 'security', 'middleware'],
            timeToFix: 25
        );
    }

    public function shouldRun(): bool
    {
        $routePath = $this->buildPath('routes');
        $hasRoutes = is_dir($routePath) && ! empty($this->getRouteFiles());

        // Check if there are any PHP files to analyze (controllers)
        $hasPhpFiles = ! empty($this->getPhpFiles());

        // Run if we have either routes or PHP files to check
        return $hasRoutes || $hasPhpFiles;
    }

    public function getSkipReason(): string
    {
        return 'No routes or controllers found to analyze';
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load public routes from configuration
        $this->loadPublicRoutes();

        // Drop what an earlier analysis on this instance read, which may be of another project
        $this->resolvedAuthMiddleware = [];
        $this->middlewareAliasMap = null;
        $this->middlewareGroupMap = null;
        $this->publicControllerMethods = [];
        $this->routeAuthStats = [];
        $this->routeAuthCarried = [];
        $this->routeOpenControllerMethods = [];
        $this->routeAuthRemovedMethods = [];
        $this->appClassMemo = [];
        $this->extendsAuthenticateMemo = [];
        $this->hasMiddlewareMemo = [];
        $this->controllerAuthEntriesMemo = [];
        $this->routeVisitors = [];
        $this->controllerParameterTypes = null;

        // Resolve file-level prefixes and middleware the framework applies outside the route
        // files. One parser follows the registrations for both, as a closure importing a
        // registrar by value reads it (see BootstrapRouteParser::__construct()). Its walk gives
        // the variables it reads their values on the trees it parses, which other analyzers
        // reading a captured variable must not find, so it walks copies of the shared parser's
        // trees, which still parses each file once and logs each that does not parse
        $shared = $this->parser;
        $this->parser = new class($shared) extends AstParser
        {
            /** @var array<string, array<Node>> */
            private array $copies = [];

            public function __construct(private readonly AstParser $shared)
            {
                parent::__construct();
            }

            public function parseFile(string $filePath): array
            {
                return $this->copies[$filePath] ??= (new NodeTraverser(new CloningVisitor))->traverse($this->shared->parseFile($filePath));
            }

            public function hasFailure(string $path): bool
            {
                return $this->shared->hasFailure($path);
            }
        };
        try {
            $routeParser = new BootstrapRouteParser($this->getBasePath(), $this->parser, byValueCaptures: true);
            $this->routeFileBasePrefixes = $this->resolveRouteFileBasePrefixes($routeParser);
            $this->routeFileBaseMiddleware = $this->resolveRouteFileBaseMiddleware($routeParser);
        } finally {
            // What the registrations read memoized came from those trees: read the rest afresh
            $this->parser = $shared;
            $this->resolvedAuthMiddleware = [];
            $this->appClassMemo = [];
            $this->extendsAuthenticateMemo = [];
            $this->middlewareAliasMap = null;
            $this->middlewareGroupMap = null;
        }

        $issues = [];

        // First pass: Build map of public controller methods from routes
        $routeFiles = $this->getRouteFiles();
        foreach ($routeFiles as $file) {
            $this->buildPublicControllerMap($file);
        }

        // Check route files
        foreach ($routeFiles as $file) {
            $this->checkRouteFile($file, $issues);
        }

        // Check controllers
        $controllers = $this->getControllerFiles();
        foreach ($controllers as $file) {
            $this->checkController($file, $issues);
        }

        // Check FormRequest classes
        $formRequests = $this->getFormRequestFiles();
        foreach ($formRequests as $file) {
            $this->checkFormRequest($file, $issues);
        }

        // Check for unsafe Auth::user() usage
        foreach ($this->getPhpFiles() as $file) {
            $this->checkUnsafeAuthUsage($file, $issues);
        }

        $summary = empty($issues)
            ? 'No authentication/authorization issues detected'
            : sprintf('Found %d potential authentication/authorization issue%s', count($issues), count($issues) === 1 ? '' : 's');

        /** @var array<Issue> $issues */
        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Load public routes from configuration.
     */
    private function loadPublicRoutes(): void
    {
        $defaultRoutes = [
            '/login',
            '/register',
            '/password/reset',
            '/password/email',
            '/forgot-password',
            '/reset-password',
            '/email/verify',
            '/health',
            '/status',
            '/up',
        ];

        $configRoutes = $this->config->get(
            'shieldci.analyzers.security.authentication-authorization.public_routes', []
        );

        if (! is_array($configRoutes)) {
            $configRoutes = [];
        }

        $this->publicRoutes = array_values(array_unique(array_filter(array_merge($defaultRoutes, $configRoutes), 'is_string')));
    }

    /**
     * Determine whether a route URI is considered public.
     *
     * Matching is leading-slash insensitive and supports glob "*" wildcards
     * via fnmatch(), so a configured pattern like "/welcome/*" matches a route
     * registered as "welcome/{employee}". Patterns without wildcards fall back
     * to an exact (slash-normalized) comparison.
     */
    private function isPublicRoute(string $uri): bool
    {
        $normalizedUri = '/'.ltrim($uri, '/');

        foreach ($this->publicRoutes as $pattern) {
            $normalizedPattern = '/'.ltrim($pattern, '/');

            if ($normalizedPattern === $normalizedUri || fnmatch($normalizedPattern, $normalizedUri)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether a collected route is public through its URI candidates (full
     * composed path, AST-visible composition, own declared segment), one list per URL it is
     * served at, one per registration of its file: each URL must match when the URLs are
     * required (see {@see self::resolveRouteFileBasePrefixes()}), any one otherwise.
     *
     * @param  array{uri: string, match_uris: list<list<string>>, http_methods: list<string>, controller: string|null, action: string|null, is_closure: bool, middleware: list<string>, unregistered_middleware: list<string>, direct_remove: list<string>, removed: list<string>, opaque_removals: bool, line: int, every_url: bool}  $route
     */
    private function isRoutePublic(array $route): bool
    {
        foreach ($route['match_uris'] as $candidates) {
            $matches = array_filter($candidates, $this->isPublicRoute(...)) !== [];
            if ($matches !== $route['every_url']) {
                return $matches;
            }
        }

        return $route['every_url'];
    }

    /**
     * Resolve file-level URI prefixes the framework applies when registering
     * whole route files, keyed by route file basename, one per registration.
     *
     * - the registrations the route parser follows (see
     *   {@see self::extractFollowedRoutePrefixes()}): those that provably run give a file
     *   its required URLs, every one of which must be public for its routes to be; when it
     *   has none, the others give it optional URLs, any one of which suffices
     * - for a file those leave unmapped, optional URLs from best-effort literal discovery:
     *   bootstrap/app.php (Laravel 11+) withRouting(api: ..., apiPrefix: ...), and
     *   registrar chains inside its then: callback, read as below;
     *   app/Providers/RouteServiceProvider.php (Laravel 9/10) registrar chains
     *   ending ->group(base_path('routes/X.php')) or a list of such files,
     *   including custom route files
     * - convention fallback: routes/api.php → 'api', when nothing above maps it
     *
     * @return array<string, array{prefixes: non-empty-list<string>, required: bool}>
     */
    private function resolveRouteFileBasePrefixes(BootstrapRouteParser $routeParser): array
    {
        $map = [];
        foreach ($this->extractFollowedRoutePrefixes($routeParser) as $basename => $prefixes) {
            $list = $prefixes['required'] !== [] ? $prefixes['required'] : $prefixes['optional'];
            if ($list !== []) {
                $map[$basename] = ['prefixes' => $list, 'required' => $prefixes['required'] !== []];
            }
        }

        $bootstrap = $this->buildPath('bootstrap/app.php');
        $literal = $this->extractBootstrapRoutePrefixes($bootstrap);
        $registered = [
            $this->extractBootstrapThenRoutePrefixes($bootstrap),
            $this->extractProviderRoutePrefixes($this->buildPath('app/Providers/RouteServiceProvider.php')),
        ];
        foreach ($registered as $prefixes) {
            foreach ($prefixes as $basename => $list) {
                $literal[$basename] = array_values(array_unique([...$literal[$basename] ?? [], ...$list]));
            }
        }

        foreach ($literal as $basename => $prefixes) {
            $map[$basename] ??= ['prefixes' => $prefixes, 'required' => false];
        }
        $map['api.php'] ??= ['prefixes' => ['api'], 'required' => false];

        return $map;
    }

    /**
     * Extract the api route file and its prefix from bootstrap/app.php's
     * withRouting(...) call (Laravel 11+). An api file registered without an
     * explicit apiPrefix gets the framework default 'api'.
     *
     * @return array<string, non-empty-list<string>>
     */
    private function extractBootstrapRoutePrefixes(string $file): array
    {
        if (! is_file($file)) {
            return [];
        }

        $ast = $this->parser->parseFile($file);
        if (empty($ast)) {
            return [];
        }

        foreach ($this->parser->findMethodCalls($ast, 'withRouting') as $call) {
            if (! ($call instanceof Node\Expr\MethodCall)) {
                continue;
            }

            $apiFile = null;
            $apiPrefix = null;

            foreach ($call->args as $arg) {
                if (! ($arg instanceof Node\Arg) || $arg->name === null) {
                    continue;
                }

                if ($arg->name->toString() === 'api') {
                    $apiFile = $this->extractRouteFileBasename($arg->value);
                } elseif ($arg->name->toString() === 'apiPrefix' && $arg->value instanceof Node\Scalar\String_) {
                    $apiPrefix = trim($arg->value->value, '/');
                }
            }

            if ($apiFile !== null) {
                return [$apiFile => [$apiPrefix ?? 'api']];
            }
        }

        return [];
    }

    /**
     * Extract a route file's basename from a withRouting file argument:
     * a string literal or a __DIR__.'/../routes/api.php' style concat.
     */
    private function extractRouteFileBasename(Node\Expr $expr): ?string
    {
        if ($expr instanceof Node\Scalar\String_) {
            $path = $expr->value;
        } elseif ($expr instanceof Node\Expr\BinaryOp\Concat && $expr->right instanceof Node\Scalar\String_) {
            $path = $expr->right->value;
        } else {
            return null;
        }

        return str_ends_with($path, '.php') ? basename($path) : null;
    }

    /**
     * Extract per-file prefixes from registrar chains inside bootstrap/app.php's
     * withRouting(then: ...) callback (Laravel 11+), read as
     * {@see self::extractGroupRoutePrefixes()} reads them.
     *
     * @return array<string, non-empty-list<string>>
     */
    private function extractBootstrapThenRoutePrefixes(string $file): array
    {
        if (! is_file($file)) {
            return [];
        }

        $ast = $this->parser->parseFile($file);
        if (empty($ast)) {
            return [];
        }

        $callbacks = [];
        foreach ($this->parser->findMethodCalls($ast, 'withRouting') as $call) {
            if (! ($call instanceof Node\Expr\MethodCall)) {
                continue;
            }

            foreach ($call->args as $arg) {
                if ($arg instanceof Node\Arg
                    && $arg->name !== null
                    && $arg->name->toString() === 'then'
                    && ($arg->value instanceof Node\Expr\Closure || $arg->value instanceof Node\Expr\ArrowFunction)) {
                    $callbacks[] = $arg->value;
                }
            }
        }

        return $this->extractGroupRoutePrefixes($callbacks);
    }

    /**
     * Extract per-file prefixes from RouteServiceProvider registrations, read as
     * {@see self::extractGroupRoutePrefixes()} reads them.
     *
     * @return array<string, non-empty-list<string>>
     */
    private function extractProviderRoutePrefixes(string $file): array
    {
        if (! is_file($file)) {
            return [];
        }

        $ast = $this->parser->parseFile($file);
        if (empty($ast)) {
            return [];
        }

        return $this->extractGroupRoutePrefixes($ast);
    }

    /**
     * Extract per-file prefixes from registrar chains under the given nodes:
     * chains ending ->group(base_path('routes/X.php')) or a list of such files,
     * lifting prefix('...') from the same chain onto every file, each prefix a file is
     * given kept. A chain without a readable prefix gives none.
     *
     * @param  array<Node>  $nodes
     * @return array<string, non-empty-list<string>>
     */
    private function extractGroupRoutePrefixes(array $nodes): array
    {
        $map = [];
        $routeParser = new BootstrapRouteParser($this->getBasePath(), $this->parser);

        foreach ($this->parser->findMethodCalls($nodes, 'group') as $call) {
            if (! ($call instanceof Node\Expr\MethodCall)) {
                continue;
            }

            $prefix = $this->extractPrefixFromRegistrarChain($call);
            if ($prefix === '') {
                continue;
            }

            foreach ($routeParser->groupRoutes($call->args) as $entry) {
                $basename = $this->extractBasePathRouteFile($entry);
                if ($basename !== null && ! in_array($prefix, $map[$basename] ?? [], true)) {
                    $map[$basename][] = $prefix;
                }
            }
        }

        return $map;
    }

    /**
     * Extract a route file's basename from a base_path('routes/X.php') argument.
     */
    private function extractBasePathRouteFile(?Node\Expr $expr): ?string
    {
        if (! ($expr instanceof Node\Expr\FuncCall)
            || ! ($expr->name instanceof Node\Name)
            || $expr->name->toString() !== 'base_path') {
            return null;
        }

        $arg = $expr->args[0]->value ?? null;
        if (! ($arg instanceof Node\Scalar\String_) || ! str_ends_with($arg->value, '.php')) {
            return null;
        }

        return basename($arg->value);
    }

    /**
     * Lift the prefix('...') value from a route registrar chain ending in
     * ->group(...). Mirrors RouteAuthVisitor::extractGroupPrefix() for
     * provider-level route file registrations.
     */
    private function extractPrefixFromRegistrarChain(Node\Expr\MethodCall $groupCall): string
    {
        $current = $groupCall->var;

        while ($current instanceof Node\Expr\MethodCall) {
            if ($current->name instanceof Node\Identifier
                && $current->name->toLowerString() === 'prefix'
                && ($arg = $current->args[0]->value ?? null) instanceof Node\Scalar\String_) {
                return trim($arg->value, '/');
            }
            $current = $current->var;
        }

        if ($current instanceof Node\Expr\StaticCall
            && $current->name instanceof Node\Identifier
            && $current->name->toLowerString() === 'prefix'
            && ($arg = $current->args[0]->value ?? null) instanceof Node\Scalar\String_) {
            return trim($arg->value, '/');
        }

        return '';
    }

    /**
     * Per-file prefixes from the registrations the route parser follows, as csrf-protection
     * and login-throttling read them (see BootstrapRouteParser::getExternalRouteFileLoads()):
     * route files loaded by a group on the router, as a path argument, a list of them or a
     * variable holding them, or require'd inside a group's closure, in bootstrap/app.php and
     * every file under app/Providers/, with a variable holding a registrar followed to the
     * calls that built it. A file takes the prefixes of the groups loading it, composed as
     * Laravel composes them (see {@see self::composeGroupPrefixes()}), '' when they set none.
     *
     * Required: the registrations that provably run, those inside the routing callback
     * bootstrap/app.php's withRouting() runs (see {@see self::withRoutingCallback()}), the
     * web: and api: files it registers (see
     * {@see self::extractFollowedWithRoutingPrefixes()}), and those a provider Laravel
     * provably registers runs (see {@see self::registeredProviderCalls()}). Optional: those
     * in any other service provider under app/Providers/, in its boot(), register() or map(),
     * or a method of the same class they call (see {@see self::providerRegistrationCalls()}),
     * which Laravel runs only if something registers the provider.
     *
     * The map is keyed by basename, so only a file directly under routes/ is recorded: a
     * nested routes/partners/web.php would otherwise lend its prefix to routes/web.php.
     *
     * A file registered several times keeps the prefix of each registration, as Laravel
     * serves its routes at each URL whatever order it registers them in. A registration
     * whose prefix cannot be read adds none.
     *
     * @return array<string, array{required: list<string>, optional: list<string>}>
     */
    private function extractFollowedRoutePrefixes(BootstrapRouteParser $routeParser): array
    {
        $routesDir = realpath($this->buildPath('routes'));
        if ($routesDir === false) {
            return [];
        }
        $routesDir = str_replace('\\', '/', $routesDir);

        // The walk annotates the parser's cached trees, so it runs before bootstrap/app.php is read
        $loads = $routeParser->getExternalRouteFileLoads();

        $bootstrap = $this->getBasePath().'/bootstrap/app.php';
        $ast = is_file($bootstrap) ? $this->parser->parseFile($bootstrap) : [];

        $map = [];
        $registrationCalls = [$bootstrap => []];
        foreach ($this->parser->findMethodCalls($ast, 'withRouting') as $call) {
            if (! ($call instanceof Node\Expr\MethodCall)) {
                continue;
            }

            foreach ($this->extractFollowedWithRoutingPrefixes($call) as $basename => $prefixes) {
                $map[$basename]['required'] = [...$map[$basename]['required'] ?? [], ...$prefixes];
            }

            $callback = $this->withRoutingCallback($call);
            if ($callback !== null) {
                $registrationCalls[$bootstrap] += $this->callIds([$callback]);
            }
        }

        $registered = null;
        foreach ($loads as $load) {
            $calls = $load['calls'];
            if ($calls === [] || $this->normalizedDirname($load['file']) !== $routesDir) {
                continue;
            }

            $source = $load['source'];
            $id = spl_object_id($calls[0]);
            if ($source === $bootstrap) {
                $kind = isset($registrationCalls[$bootstrap][$id]) ? 'required' : null;
            } else {
                $registered ??= $this->registeredProviderCalls();
                $registrationCalls[$source] ??= $this->providerRegistrationCalls($source);
                $kind = isset($registered[$id]) ? 'required' : (isset($registrationCalls[$source][$id]) ? 'optional' : null);
            }

            $prefix = $kind !== null ? $this->composeGroupPrefixes($routeParser, $calls, '') : null;
            if ($kind !== null && $prefix !== null) {
                $map[basename($load['file'])][$kind][] = $prefix;
            }
        }

        return array_map(fn (array $prefixes): array => [
            'required' => array_values(array_unique($prefixes['required'] ?? [])),
            'optional' => array_values(array_unique($prefixes['optional'] ?? [])),
        ], $map);
    }

    /**
     * Per-file middleware from the registrations of the route files directly under routes/,
     * keyed by basename: the middleware every registration of a file gives it, when each of
     * them authenticates, as Laravel runs the file's routes under each registration's.
     *
     * A file's registrations are those the route parser follows (see
     * {@see self::extractFollowedRoutePrefixes()}), each giving what its groups would give
     * routes inside them (see RouteAuthVisitor::registrationMiddleware()), and the files
     * withRouting() names: its web: and api: files, under the web and api groups, and its
     * commands: and channels: files, under none. A file gets nothing when one of them gives
     * no authentication or cannot be read, when another route file loads it, or when a group
     * call or a require the walk does not follow may load it; and no file gets anything when
     * a withRouting() file argument, or the path a require in a route file, bootstrap/app.php
     * or a provider loads, cannot be read.
     *
     * @return array<string, list<string>>
     */
    private function resolveRouteFileBaseMiddleware(BootstrapRouteParser $routeParser): array
    {
        $routesDir = realpath($this->buildPath('routes'));
        if ($routesDir === false) {
            return [];
        }
        $routesDir = str_replace('\\', '/', $routesDir);

        // Each registration of a file, as the middleware it gives, null when it cannot be read
        $registrations = [];
        $followed = [];
        $reader = new RouteAuthVisitor($routeParser, []);
        foreach ($routeParser->getExternalRouteFileLoads() as $load) {
            foreach ($load['calls'] as $call) {
                $followed[spl_object_id($call)] = true;
            }
            if ($this->normalizedDirname($load['file']) === $routesDir) {
                $registrations[$this->routeFileKey($load['file'])][] = $this->registrationMiddleware($reader, $load['calls']);
            }
        }

        $bootstrap = $this->getBasePath().'/bootstrap/app.php';
        $ast = is_file($bootstrap) ? $this->parser->parseFile($bootstrap) : [];
        foreach ($this->parser->findMethodCalls($ast, 'withRouting') as $call) {
            foreach (['web' => ['web'], 'api' => ['api'], 'commands' => [], 'channels' => []] as $name => $middleware) {
                $files = $call instanceof Node\Expr\MethodCall ? $this->withRoutingArgument($call, $name) : null;
                if ($files === null) {
                    continue;
                }
                if (! $this->routeFileArgumentReadable($files)) {
                    return [];
                }
                foreach ($this->extractRouteFileBasenames($files) as $basename) {
                    $registrations[$this->routeFileKey($this->buildPath('routes/'.$basename))][] = ['add' => $middleware, 'remove' => []];
                }
            }
        }

        // The other loads: by a route file, a provider outside app/Providers/ the application
        // lists, or another file under app/ that may name the router; and any such load, in
        // any of these files, whose path cannot be read. A file the analysis reads nowhere
        // else is parsed apart, so the shared parser neither keeps it nor logs it when it does
        // not parse; one it reads is read by the path it reads it by
        $apart = new AstParser;
        $apartRouteParser = new BootstrapRouteParser($this->getBasePath(), $apart, byValueCaptures: true);
        $walked = array_fill_keys([$bootstrap, ...$routeParser->phpFilesUnder('app/Providers')], true);
        $routeFiles = array_fill_keys($routeParser->phpFilesUnder('routes'), true);
        $listed = $this->listedProviderFiles($apart);
        if ($listed === null) {
            return [];
        }
        $providers = array_fill_keys(array_diff($listed, array_keys($walked)), true);
        $analyzed = [];
        foreach ($this->getPhpFiles() as $file) {
            $analyzed[realpath($file) ?: $file] = $file;
        }
        // Laravel requires each config file when it boots
        $sources = array_values(array_unique([...array_keys($routeFiles), ...array_keys($walked), ...array_keys($providers), ...$routeParser->phpFilesUnder('app'), ...$routeParser->phpFilesUnder('config')]));
        // A provider a read provider registers is read as a listed one, appended as found
        for ($index = 0; $index < count($sources); $index++) {
            $source = $sources[$index];
            $routeFile = isset($routeFiles[$source]);
            if (! $routeFile && ! $this->mayLoadRouteFiles($source, isset($walked[$source]) || isset($providers[$source]))) {
                continue;
            }
            // Laravel reads route files directly under routes/, and the walk bootstrap/app.php
            // and app/Providers/
            $read = isset($walked[$source]) || ($routeFile && $this->normalizedDirname($source) === $routesDir);
            $path = $read ? $source : ($analyzed[realpath($source) ?: $source] ?? null);
            [$parser, $sourceRouteParser, $path] = $path !== null ? [$this->parser, $routeParser, $path] : [$apart, $apartRouteParser, $source];
            $tree = is_file($path) ? $parser->parseFile($path) : [];
            if ($parser->hasFailure($path)) {
                return [];
            }

            $registered = $this->registeredProviderNames($tree);
            $registeredFiles = $registered !== null ? $this->providerFiles($registered, $apart) : null;
            if ($registeredFiles === null) {
                return [];
            }
            foreach ($registeredFiles as $file) {
                if (! isset($walked[$file]) && ! isset($providers[$file])) {
                    $providers[$file] = true;
                    $sources[] = $file;
                }
            }

            $walk = $sourceRouteParser->routeFileWalk($path);
            $loads = isset($walked[$source]) ? [] : [...$walk['loads'], ...$walk['routesFrom']];
            $unfollowed = $this->unfollowedRouteFileLoads($sourceRouteParser, $tree, $walk, dirname($path));
            if ($unfollowed === null) {
                return [];
            }
            $sourceReader = $sourceRouteParser === $routeParser ? $reader : new RouteAuthVisitor($sourceRouteParser, []);
            foreach ($loads as $load) {
                if ($this->normalizedDirname($load['file']) === $routesDir) {
                    $registrations[$this->routeFileKey($load['file'])][] = isset($providers[$source]) ? $this->registrationMiddleware($sourceReader, $load['calls']) : null;
                }
            }
            foreach ($unfollowed as $file) {
                if ($this->normalizedDirname($file) === $routesDir) {
                    $registrations[$this->routeFileKey($file)][] = null;
                }
            }
        }

        $map = [];
        foreach ($registrations as $basename => $layers) {
            $shared = null;
            foreach ($layers as $layer) {
                if ($layer === null || $this->removesAuthInAnyForm($layer['remove']) || ! $this->isRouteMiddlewareAuthenticated($layer['add'], $layer['remove'])) {
                    continue 2;
                }
                $shared = $shared === null ? $layer['add'] : array_values(array_intersect($shared, $layer['add']));
            }
            if ($shared !== null && $this->isRouteMiddlewareAuthenticated($shared)) {
                $map[$basename] = $shared;
            }
        }

        return $map;
    }

    /**
     * The middleware a registration's group calls, outermost first, give the routes of the
     * file it loads (see RouteAuthVisitor::registrationMiddleware()): what they add less what
     * any of them excludes, as the groups' exclusions accumulate (RouteGroup::merge()), and
     * what they exclude. Null when one of them cannot be read.
     *
     * @param  list<Node\Expr\MethodCall|Node\Expr\StaticCall>  $calls
     * @return array{add: list<string>, remove: list<string>}|null
     */
    private function registrationMiddleware(RouteAuthVisitor $reader, array $calls): ?array
    {
        $add = [];
        $remove = [];
        foreach ($calls as $call) {
            $layer = $reader->registrationMiddleware($call);
            if ($layer === null) {
                return null;
            }
            array_push($add, ...$layer['add']);
            array_push($remove, ...$layer['remove']);
        }

        return ['add' => array_values(array_diff(array_unique($add), $remove)), 'remove' => array_values(array_unique($remove))];
    }

    /**
     * The providers a tree registers on the application: register() called on $this->app,
     * $app, app() or the App facade, given a ::class constant, a new expression or a class
     * name string. Null when one is given anything else.
     *
     * @param  array<Node>  $tree
     * @return list<string>|null
     */
    private function registeredProviderNames(array $tree): ?array
    {
        $names = [];
        foreach ($this->parser->findNodes($tree, Node\Expr\CallLike::class) as $call) {
            if (! ($call instanceof Node\Expr\MethodCall || $call instanceof Node\Expr\StaticCall)
                || ! $call->name instanceof Node\Identifier || $call->name->toLowerString() !== 'register') {
                continue;
            }
            $application = $call instanceof Node\Expr\StaticCall
                ? $call->class instanceof Node\Name && strcasecmp($call->class->getLast(), 'App') === 0
                : ($call->var instanceof Node\Expr\PropertyFetch && $call->var->var instanceof Node\Expr\Variable && $call->var->var->name === 'this'
                    && $call->var->name instanceof Node\Identifier && $call->var->name->toString() === 'app')
                    || ($call->var instanceof Node\Expr\Variable && $call->var->name === 'app')
                    || ($call->var instanceof Node\Expr\FuncCall && $call->var->name instanceof Node\Name && strtolower($call->var->name->toString()) === 'app' && $call->var->args === []);
            if (! $application) {
                continue;
            }
            $provider = $this->registeredProvider($call);
            if ($provider === []) {
                return null;
            }
            array_push($names, ...$provider);
        }

        return $names;
    }

    /**
     * Whether a file may load route files in a way the walk of the registrations does not
     * follow, as a cheap read of its text tells, erring towards yes: unless $namesRouter says
     * it is known to, it may name the router (the word router, the Router class, the
     * Registrar contract, a Route facade call or import, a group() or loadRoutesFrom() call)
     * or a filesystem; and it gives group() something other than a closure, calls
     * loadRoutesFrom() or a filesystem's require methods, or requires or includes a path
     * that names routes/, a variable or a call.
     */
    private function mayLoadRouteFiles(string $file, bool $namesRouter = false): bool
    {
        $code = is_file($file) ? file_get_contents($file) : false;
        if (! is_string($code) || (! $namesRouter && preg_match('/router|registrar|route::|facades\\\\route|->\s*group\s*\(|loadroutesfrom|requireonce|getrequire|files|filesystem|include|require|file::/i', $code) !== 1)) {
            return false;
        }
        if (preg_match('/\bgroup\s*\(\s*(?!(?:static\s+)?(?:function|fn)\b)|loadRoutesFrom\s*\(|\brequire(?:Once)?\s*\(|getRequire\s*\(|->\s*register\s*\(|App::register\s*\(/i', $code) === 1) {
            return true;
        }

        // A require or include of a literal path, alone or under __DIR__ or a path helper,
        // that names no route file loads a known file
        preg_match_all('/\b(?:require|include)(?:_once)?\b([^;]*)/i', $code, $includes);
        foreach ($includes[1] as $path) {
            if (stripos($path, 'routes') !== false
                || preg_match('/^\s*\(?\s*(?:(?:__DIR__\s*\.\s*)?[\'"][^\'"$]*[\'"]|(?:base|app|config|storage|database|resource|public|lang)_path\(\s*[\'"][^\'"$]*[\'"]\s*\))\s*\)?\s*$/i', $path) !== 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * The route files a file's tree loads in ways its walk (see
     * BootstrapRouteParser::routeFileWalk()) does not record: a group() on anything but a
     * facade other than Route the walk does not read as made on the router, a
     * loadRoutesFrom() not on $this, and a filesystem's require(), requireOnce() or
     * getRequire(). Null when one of them, or a group the walk finds made on the router, is
     * given a path that cannot be read, or a require or include inside code that registers
     * routes (see {@see self::routeRegisteringCode()}) is, as it may load any route file. A
     * closure loads no file but through its body, and neither does a variable holding one,
     * nor a parameter of a function the file declares, such as a macro's routes.
     *
     * @param  array<Node>  $tree
     * @param  array{groups: array<int, list<Node\Expr>>, closures: list<array{closure: Node, calls: non-empty-list<Node\Expr\MethodCall|Node\Expr\StaticCall>}>}  $walk
     * @return list<string>|null
     */
    private function unfollowedRouteFileLoads(BootstrapRouteParser $routeParser, array $tree, array $walk, string $dir): ?array
    {
        // One read of the tree: the parameters typed as closures, the calls, and the code that
        // registers routes
        $parameters = [];
        $calls = [];
        $code = array_column($walk['closures'], 'closure');
        $classes = [];
        foreach ($this->parser->findNodes($tree, Node::class) as $node) {
            // A parameter only a closure can be given loads no file but through its body
            $closureType = $node instanceof Node\Param ? ($node->type instanceof Node\NullableType ? $node->type->type : $node->type) : null;
            if ($node instanceof Node\Param && $node->var instanceof Node\Expr\Variable && is_string($node->var->name)
                && (($closureType instanceof Node\Name && strcasecmp($closureType->getLast(), 'Closure') === 0)
                    || ($closureType instanceof Node\Identifier && $closureType->toLowerString() === 'callable'))) {
                $parameters[$node->var->name] = true;
            }
            if (($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) && $node->name instanceof Node\Identifier) {
                $calls[] = $node;
            }
            if ($node instanceof Node\Stmt\Class_) {
                $classes[] = $node;
            }
        }

        $hierarchy = new ClassHierarchyIndex;
        foreach ($classes as $class) {
            if ($class->namespacedName instanceof Node\Name) {
                $hierarchy->record($class->namespacedName->toString(), $class->extends !== null ? $this->resolvedName($class->extends) : null, []);
            }
        }
        foreach ($classes as $class) {
            if ($this->extendsClassNamed($class, $hierarchy, '/^RouteServiceProvider$/i')) {
                foreach ($class->getMethods() as $method) {
                    if (str_starts_with($method->name->toLowerString(), 'map')) {
                        $code[] = $method;
                    }
                }
            }
        }

        $loads = [];
        foreach ($calls as $call) {
            $name = $call->name instanceof Node\Identifier ? $call->name->toLowerString() : '';
            if ($call instanceof Node\Expr\MethodCall) {
                $arguments = match ($name) {
                    'withrouting' => array_filter([$this->withRoutingArgument($call, 'then'), $this->withRoutingArgument($call, 'using')]),
                    'routes', 'loadroutesusing' => array_map(fn (Node\Arg $arg): Node\Expr => $arg->value, $call->getArgs()),
                    default => [],
                };
                foreach ($arguments as $argument) {
                    $callback = BootstrapRouteParser::heldValue($argument);
                    if ($callback instanceof Node\Expr\Closure || $callback instanceof Node\Expr\ArrowFunction) {
                        $code[] = $callback;
                    }
                }
            }

            $root = $this->chainRoot($call);
            $followed = isset($walk['groups'][spl_object_id($call)]);
            // A class whose name does not name a route or router, such as the Schedule facade,
            // is no router
            $facade = $root instanceof Node\Expr\StaticCall && $root->class instanceof Node\Name
                && stripos($this->resolvedName($root->class), 'route') === false;
            if ($name === 'group' && ($followed || ! $facade)) {
                // Router::group() takes its attribute array first
                $attributes = count($call->args) > 1 && $call->args[0] instanceof Node\Arg ? $call->args[0]->value : null;
                foreach ($walk['groups'][spl_object_id($call)] ?? $routeParser->groupRoutes($call->args) as $entry) {
                    $held = BootstrapRouteParser::heldValue($entry);
                    if ($held instanceof Node\Expr\Closure || $held instanceof Node\Expr\ArrowFunction) {
                        $code[] = $held;

                        continue;
                    }
                    if ($entry === $attributes || ($entry instanceof Node\Expr\Variable && $held === $entry && is_string($entry->name) && isset($parameters[$entry->name]))) {
                        continue;
                    }
                    $paths = $this->routeFilePaths($routeParser, $entry, $dir);
                    if ($paths === null) {
                        return null;
                    }
                    // The walk records the loads of the groups it reads as made on the router
                    if (! $followed) {
                        array_push($loads, ...$paths);
                    }
                }

                continue;
            }

            $receiver = $call instanceof Node\Expr\MethodCall ? $call->var : null;
            // Any require method on an object, as a filesystem may be reached any way, and on
            // the File facade by any import alias
            $files = $call instanceof Node\Expr\MethodCall
                || ($call->class instanceof Node\Name && (strcasecmp($this->resolvedName($call->class), 'Illuminate\\Support\\Facades\\File') === 0
                    || strcasecmp($call->class->getLast(), 'File') === 0));
            $onThis = $receiver instanceof Node\Expr\Variable && $receiver->name === 'this';
            if ($name !== 'loadroutesfrom' && ! ($files && in_array($name, ['require', 'requireonce', 'getrequire'], true))) {
                continue;
            }

            $path = $call->getArgs()[0] ?? null;
            $paths = $path !== null ? $this->routeFilePaths($routeParser, $path->value, $dir) : null;
            if ($paths === null) {
                return null;
            }
            // The walk records $this->loadRoutesFrom() of a path it reads
            if (! ($name === 'loadroutesfrom' && $onThis)) {
                array_push($loads, ...$paths);
            }
        }

        foreach ($code as $registering) {
            foreach ($this->parser->findNodes([$registering], Node\Expr\Include_::class) as $include) {
                if ($include instanceof Node\Expr\Include_ && $routeParser->includedFile($include, $dir) === null) {
                    return null;
                }
            }
        }

        return $loads;
    }

    /**
     * The files of the providers the application lists (see
     * {@see self::readableProviderLists()}) outside app/, which the analyzed project's
     * composer.json maps to a file through its PSR-4 autoload or autoload-dev entries, the
     * longest prefix first. A provider under an App\ name is read from app/ (see
     * {@see self::mayLoadRouteFiles()}), and the framework's, or one an installed package's
     * namespace holds (vendor/composer/autoload_psr4.php), loads none of the application's
     * route files. Null when a list cannot be read, or a listed provider is found nowhere,
     * as it may load any.
     *
     * @return list<string>|null
     */
    private function listedProviderFiles(AstParser $apart): ?array
    {
        $listed = $this->readableProviderLists($apart);

        return $listed !== null ? $this->providerFiles($listed, $apart) : null;
    }

    /**
     * The files of providers outside app/ (see {@see self::listedProviderFiles()}), null when
     * one is found nowhere.
     *
     * @param  list<string>  $listed
     * @return list<string>|null
     */
    private function providerFiles(array $listed, AstParser $apart): ?array
    {
        $composer = $this->buildPath('composer.json');
        $json = is_file($composer) ? json_decode((string) file_get_contents($composer), true) : null;

        $prefixes = [];
        foreach (['autoload', 'autoload-dev'] as $section) {
            $psr4 = is_array($json) && is_array($json[$section] ?? null) && is_array($json[$section]['psr-4'] ?? null) ? $json[$section]['psr-4'] : [];
            foreach ($psr4 as $prefix => $dirs) {
                foreach (is_array($dirs) ? $dirs : [$dirs] as $dir) {
                    if (is_string($prefix) && is_string($dir)) {
                        $prefixes[] = [ltrim($prefix, '\\'), rtrim($dir, '/')];
                    }
                }
            }
        }
        usort($prefixes, fn (array $a, array $b): int => strlen($b[0]) <=> strlen($a[0]));

        $files = [];
        $packages = null;
        foreach ($listed as $provider) {
            if (str_starts_with(strtolower($provider), 'illuminate\\')
                || (str_starts_with(strtolower($provider), 'app\\') && is_file($this->buildPath('app/'.str_replace('\\', '/', substr($provider, 4)).'.php')))) {
                continue;
            }
            foreach ($prefixes as [$prefix, $dir]) {
                $file = $this->buildPath(($dir !== '' ? $dir.'/' : '').str_replace('\\', '/', substr($provider, strlen($prefix))).'.php');
                if (str_starts_with($provider, $prefix) && is_file($file)) {
                    $files[] = $file;

                    continue 2;
                }
            }

            $packages ??= $this->packageNamespaces($apart);
            foreach ($packages as $namespace) {
                if (str_starts_with($provider, $namespace)) {
                    continue 2;
                }
            }

            return null;
        }

        return array_values(array_unique($files));
    }

    /**
     * The providers the application lists: those bootstrap/providers.php returns, those under
     * 'providers' in config/app.php, and those bootstrap/app.php passes to withProviders(),
     * each list a literal one, array_merge() of such lists, or the framework's
     * ServiceProvider::defaultProviders(), merge()d with one or not, as ->toArray(). The two
     * files bootstrap/app.php does not register routes in are parsed apart. Null when a list
     * or an entry is in any other form, or a file does not parse.
     *
     * @return list<string>|null
     */
    private function readableProviderLists(AstParser $apart): ?array
    {
        $lists = [];
        foreach (['bootstrap/providers.php', 'config/app.php'] as $relative) {
            $file = $this->buildPath($relative);
            if (! is_file($file)) {
                continue;
            }
            $ast = $this->resolveNamesForMatching($apart->parseFile($file));
            if ($apart->hasFailure($file)) {
                return null;
            }
            foreach ($ast as $statement) {
                if ($statement instanceof Node\Stmt\Use_ || $statement instanceof Node\Stmt\Declare_ || $statement instanceof Node\Stmt\Nop) {
                    continue;
                }
                if (! $statement instanceof Node\Stmt\Return_ || $statement->expr === null) {
                    return null;
                }
                if ($relative === 'bootstrap/providers.php') {
                    $lists[] = $statement->expr;

                    continue;
                }
                if (! $statement->expr instanceof Node\Expr\Array_) {
                    return null;
                }
                foreach ($statement->expr->items as $item) {
                    if ($item instanceof Node\Expr\ArrayItem && $item->key instanceof Node\Scalar\String_ && $item->key->value === 'providers') {
                        $lists[] = $item->value;
                    }
                }
            }
        }

        $bootstrap = $this->buildPath('bootstrap/app.php');
        $ast = is_file($bootstrap) ? $this->resolveNamesForMatching($this->parser->parseFile($bootstrap)) : [];
        foreach ($this->parser->findMethodCalls($ast, 'withProviders') as $call) {
            $argument = $call instanceof Node\Expr\MethodCall ? ($call->getArgs()[0] ?? null) : null;
            if ($argument !== null) {
                $lists[] = BootstrapRouteParser::heldValue($argument->value);
            }
        }

        $providers = [];
        foreach ($lists as $list) {
            $read = $this->providerList($list);
            if ($read === null) {
                return null;
            }
            array_push($providers, ...$read);
        }

        return $providers;
    }

    /**
     * The providers a provider list names (see {@see self::readableProviderLists()}), null
     * when it is in another form.
     *
     * @return list<string>|null
     */
    private function providerList(Node\Expr $list): ?array
    {
        if ($list instanceof Node\Expr\Array_) {
            $providers = [];
            foreach ($list->items as $item) {
                $value = $item instanceof Node\Expr\ArrayItem && ! $item->unpack ? $item->value : null;
                if ($value instanceof Node\Expr\ClassConstFetch && $value->class instanceof Node\Name) {
                    $providers[] = $this->resolvedName($value->class);
                } elseif ($value instanceof Node\Scalar\String_) {
                    $providers[] = ltrim($value->value, '\\');
                } else {
                    return null;
                }
            }

            return $providers;
        }

        if ($list instanceof Node\Expr\FuncCall && $list->name instanceof Node\Name && strtolower($list->name->toString()) === 'array_merge') {
            $providers = [];
            foreach ($list->args as $arg) {
                $read = $arg instanceof Node\Arg && ! $arg->unpack ? $this->providerList($arg->value) : null;
                if ($read === null) {
                    return null;
                }
                array_push($providers, ...$read);
            }

            return $providers;
        }

        // ServiceProvider::defaultProviders()[->merge([...])]->toArray()
        if ($list instanceof Node\Expr\MethodCall && $list->name instanceof Node\Identifier && $list->name->toLowerString() === 'toarray') {
            $inner = $list->var;
            $merged = [];
            if ($inner instanceof Node\Expr\MethodCall && $inner->name instanceof Node\Identifier && $inner->name->toLowerString() === 'merge') {
                $argument = $inner->getArgs()[0] ?? null;
                $merged = $argument !== null ? $this->providerList($argument->value) : null;
                $inner = $inner->var;
            }
            if ($merged !== null && $inner instanceof Node\Expr\StaticCall && $inner->name instanceof Node\Identifier && $inner->name->toLowerString() === 'defaultproviders') {
                return $merged;
            }
        }

        return null;
    }

    /**
     * The namespace prefixes of the installed packages: the keys of the PSR-4 map Composer
     * generates in vendor/composer/autoload_psr4.php whose directories are under the vendor
     * directory ($vendorDir), read from its tree.
     *
     * @return list<string>
     */
    private function packageNamespaces(AstParser $apart): array
    {
        $file = $this->buildPath('vendor/composer/autoload_psr4.php');
        $namespaces = [];
        foreach (is_file($file) ? $apart->findNodes($apart->parseFile($file), Node\Expr\ArrayItem::class) : [] as $item) {
            if (! $item instanceof Node\Expr\ArrayItem || ! $item->key instanceof Node\Scalar\String_ || ! $item->value instanceof Node\Expr\Array_) {
                continue;
            }
            $vendor = $item->value->items !== [];
            foreach ($item->value->items as $directory) {
                $vendor = $vendor && $directory instanceof Node\Expr\ArrayItem && $directory->value instanceof Node\Expr\BinaryOp\Concat
                    && $directory->value->left instanceof Node\Expr\Variable && $directory->value->left->name === 'vendorDir';
            }
            if ($vendor) {
                $namespaces[] = $item->key->value;
            }
        }

        return $namespaces;
    }

    /**
     * The basename a route file directly under routes/ is keyed by: the name the directory
     * lists for it, so a path naming it in another case on a filesystem that ignores case is
     * the same file.
     */
    private function routeFileKey(string $file): string
    {
        $name = basename($file);
        $listed = is_dir(dirname($file)) ? (scandir(dirname($file)) ?: []) : [];
        if (in_array($name, $listed, true)) {
            return $name;
        }
        foreach ($listed as $entry) {
            if (strcasecmp($entry, $name) === 0) {
                return $entry;
            }
        }

        return $name;
    }

    /**
     * The files a group() routes argument or a loadRoutesFrom() path names: a path, or each
     * path of a list, a variable read as the value the walk knows it holds, and a call the
     * walk computes the path of as that path; none for a closure or arrow function. Null
     * when one cannot be read.
     *
     * @return list<string>|null
     */
    private function routeFilePaths(BootstrapRouteParser $routeParser, Node\Expr $value, string $dir): ?array
    {
        $value = BootstrapRouteParser::heldValue($value);
        $computed = $value->getAttribute(BootstrapRouteParser::HELD_VALUE);
        if ($value instanceof Node\Expr\MethodCall && $computed instanceof Node\Expr) {
            $value = $computed;
        }

        if ($value instanceof Node\Expr\Closure || $value instanceof Node\Expr\ArrowFunction) {
            return [];
        }

        if ($value instanceof Node\Expr\Array_) {
            $paths = [];
            foreach ($value->items as $item) {
                $listed = $item instanceof Node\Expr\ArrayItem && ! $item->unpack ? $this->routeFilePaths($routeParser, $item->value, $dir) : null;
                if ($listed === null) {
                    return null;
                }
                array_push($paths, ...$listed);
            }

            return $paths;
        }

        $file = $routeParser->groupRouteFile($value, $dir);

        return $file !== null ? [$file] : null;
    }

    /**
     * Whether a withRouting() file argument names each of its files in a form
     * {@see self::extractRouteFileBasenames()} reads: a path, or a list of them, a variable
     * holding either read as its value.
     */
    private function routeFileArgumentReadable(Node\Expr $expr): bool
    {
        $expr = BootstrapRouteParser::heldValue($expr);
        $entries = [$expr];
        if ($expr instanceof Node\Expr\Array_) {
            $entries = [];
            foreach ($expr->items as $item) {
                if (! $item instanceof Node\Expr\ArrayItem || $item->unpack) {
                    return false;
                }
                $entries[] = BootstrapRouteParser::heldValue($item->value);
            }
        }

        foreach ($entries as $entry) {
            if (! $entry instanceof Node\Scalar\String_ && ! ($entry instanceof Node\Expr\BinaryOp\Concat && $entry->right instanceof Node\Scalar\String_)
                && $this->extractBasePathRouteFile($entry) === null) {
                return false;
            }
        }

        return true;
    }

    /**
     * A path's directory, with separators normalized as the route parser normalizes paths.
     */
    private function normalizedDirname(string $path): string
    {
        return dirname(str_replace('\\', '/', $path));
    }

    /**
     * The calls under the given nodes, by spl_object_id().
     *
     * @param  array<Node>  $nodes
     * @return array<int, true>
     */
    private function callIds(array $nodes): array
    {
        $ids = [];
        foreach ($this->parser->findNodes($nodes, Node\Expr\CallLike::class) as $call) {
            $ids[spl_object_id($call)] = true;
        }

        return $ids;
    }

    /**
     * The calls, by spl_object_id(), a file under app/Providers/ makes when Laravel runs its
     * service providers: those in a provider's boot() and register(), which Laravel calls,
     * and, in a RouteServiceProvider, in map(), which RouteServiceProvider::loadRoutes()
     * calls, and in each method of the same class one of those calls on $this, self or
     * static, at any depth. A class is a provider when a class it extends, as the file's
     * declarations read, is named *ServiceProvider, and a RouteServiceProvider when one is
     * named RouteServiceProvider. A method reached any other way, such as through a
     * callable array, is not read.
     *
     * Only code that runs when the provider does counts: an abstract provider's entry method
     * is skipped when a subclass the file declares overrides it without calling parent::,
     * and a method is read as {@see self::runningCalls()} reads it.
     *
     * @return array<int, true>
     */
    private function providerRegistrationCalls(string $file): array
    {
        $ast = is_file($file) ? $this->parser->parseFile($file) : [];
        $classes = array_filter(
            $this->parser->findNodes($ast, Node\Stmt\Class_::class),
            fn (Node $class): bool => $class instanceof Node\Stmt\Class_,
        );

        $hierarchy = new ClassHierarchyIndex;
        foreach ($classes as $class) {
            if ($class->namespacedName instanceof Node\Name) {
                $hierarchy->record($class->namespacedName->toString(), $class->extends !== null ? $this->resolvedName($class->extends) : null, []);
            }
        }

        $ids = [];
        foreach ($classes as $class) {
            if (! $this->extendsClassNamed($class, $hierarchy, '/ServiceProvider$/i')) {
                continue;
            }
            $entries = $this->extendsClassNamed($class, $hierarchy, '/^RouteServiceProvider$/i') ? ['boot', 'register', 'map'] : ['boot', 'register'];
            if ($class->isAbstract()) {
                $entries = array_values(array_filter($entries, fn (string $entry): bool => ! $this->overriddenInFile($class, $classes, $entry)));
            }

            $methods = [];
            foreach ($class->getMethods() as $method) {
                $methods[$method->name->toLowerString()] = $method;
            }

            $pending = array_values(array_intersect($entries, array_keys($methods)));
            $reached = array_fill_keys($pending, true);
            while ($pending !== []) {
                $method = $methods[array_pop($pending)];
                foreach ($this->runningCalls($method) as $call) {
                    $ids[spl_object_id($call)] = true;

                    $callee = $this->ownMethodCallee($call);
                    if ($callee !== null && isset($methods[$callee]) && ! isset($reached[$callee])) {
                        $reached[$callee] = true;
                        $pending[] = $callee;
                    }
                }
            }
        }

        return $ids;
    }

    /**
     * The calls a method makes when it runs: those in its statements up to its first
     * top-level return, less those in a closure or arrow function it assigns to a variable
     * it reads nowhere else, which it never calls.
     *
     * @return list<Node\Expr\CallLike>
     */
    private function runningCalls(Node\Stmt\ClassMethod $method): array
    {
        $statements = [];
        foreach ($method->stmts ?? [] as $statement) {
            $statements[] = $statement;
            if ($statement instanceof Node\Stmt\Return_) {
                break;
            }
        }

        $reads = [];
        foreach ($this->parser->findNodes([$method], Node\Expr\Variable::class) as $variable) {
            if ($variable instanceof Node\Expr\Variable && is_string($variable->name)) {
                $reads[$variable->name] = ($reads[$variable->name] ?? 0) + 1;
            }
        }

        $uncalled = [];
        foreach ($statements as $statement) {
            if ($statement instanceof Node\Stmt\Expression && $statement->expr instanceof Node\Expr\Assign
                && $statement->expr->var instanceof Node\Expr\Variable && is_string($statement->expr->var->name)
                && ($statement->expr->expr instanceof Node\Expr\Closure || $statement->expr->expr instanceof Node\Expr\ArrowFunction)
                && $reads[$statement->expr->var->name] === 1) {
                $uncalled += $this->callIds([$statement->expr->expr]);
            }
        }

        return array_values(array_filter(
            $this->parser->findNodes($statements, Node\Expr\CallLike::class),
            fn (Node $call): bool => $call instanceof Node\Expr\CallLike && ! isset($uncalled[spl_object_id($call)]),
        ));
    }

    /**
     * Whether a class among $classes extends $class and declares $method without calling
     * parent::$method(), so $class's own never runs for it.
     *
     * @param  array<Node\Stmt\Class_>  $classes
     */
    private function overriddenInFile(Node\Stmt\Class_ $class, array $classes, string $method): bool
    {
        if ($class->namespacedName === null) {
            return false;
        }

        foreach ($classes as $subclass) {
            $override = $subclass->getMethod($method);
            if ($override === null || $subclass->extends === null
                || strcasecmp($this->resolvedName($subclass->extends), $class->namespacedName->toString()) !== 0) {
                continue;
            }

            $callsParent = false;
            foreach ($this->parser->findNodes([$override], Node\Expr\StaticCall::class) as $call) {
                $callsParent = $callsParent || ($call instanceof Node\Expr\StaticCall && $call->class instanceof Node\Name
                    && $call->class->toLowerString() === 'parent' && $call->name instanceof Node\Identifier && $call->name->toLowerString() === $method);
            }
            if (! $callsParent) {
                return true;
            }
        }

        return false;
    }

    /**
     * The calls, by spl_object_id(), the service providers Laravel provably registers make
     * when it runs them: those bootstrap/providers.php returns, config/app.php lists under
     * 'providers' (see {@see self::mergedProviders()}) and bootstrap/app.php passes to
     * withProviders() (see {@see self::listedProviders()}), and those a provider so
     * registered registers in turn (see {@see self::registeredProvider()}). Each provider
     * runs its boot() and register(), and map() when it extends a RouteServiceProvider, as
     * the nearest class declaring each, itself or a parent, declares it, a parent's only
     * through parent::; and each method of the class it calls on $this, self or static, read
     * as {@see self::runningCalls()} reads them. A class is read only from the file declaring
     * its subclass or the one under app/ Laravel's convention gives an App\ class (see
     * {@see self::appClass()}).
     *
     * @return array<int, true>
     */
    private function registeredProviderCalls(): array
    {
        $pending = $this->listedProviders();
        $seen = [];
        $ids = [];
        while ($pending !== []) {
            $provider = array_pop($pending);
            if (isset($seen[strtolower($provider)])) {
                continue;
            }
            $seen[strtolower($provider)] = true;

            // The class and the parents read, nearest first
            $lineage = [];
            $found = $this->appClass($provider);
            while ($found !== null && count($lineage) < 10) {
                [$class, $ast] = $found;
                $lineage[] = $class;
                $found = $class->extends !== null ? $this->appClass($this->resolvedName($class->extends), $ast) : null;
            }

            $routeProvider = false;
            foreach ($lineage as $class) {
                $parent = $class->extends !== null ? explode('\\', $this->resolvedName($class->extends)) : [''];
                $routeProvider = $routeProvider || strcasecmp(end($parent), 'RouteServiceProvider') === 0;
            }

            // Each [depth to look the method up from, method name, whether it may not run] still
            // to read. RouteServiceProvider::loadRoutes() calls map() only when no routes()
            // callback is set, so beside a routes() call map() may not run
            $methods = $lineage === [] ? [] : [[0, 'boot', false], [0, 'register', false]];
            if ($routeProvider && $lineage !== []) {
                $methods[] = [0, 'map', $this->callsRoutes($lineage)];
            }
            $reached = [];
            while ($methods !== []) {
                [$from, $name, $conditional] = array_pop($methods);
                foreach (array_slice($lineage, $from, null, true) as $depth => $class) {
                    $method = $class->getMethod($name);
                    if ($method === null) {
                        continue;
                    }
                    $key = $depth.':'.$name.':'.($conditional ? 'conditional' : 'runs');
                    if (! isset($reached[$key])) {
                        $reached[$key] = true;
                        array_push($methods, ...$this->readProviderMethod($method, $depth, $conditional, $ids, $pending));
                    }

                    break;
                }
            }
        }

        return $ids;
    }

    /**
     * Record the calls a provider method declared at $depth of its lineage surely runs into
     * $ids, and the providers it surely registers into $pending, returning the methods it
     * calls on the provider as [depth to look the method up from, method name, whether it may
     * not run]. A call in a method that may not run, or in a conditional part of this one
     * (see {@see self::conditionalCallIds()}), may not run, so is not recorded.
     *
     * @param  array<int, true>  $ids
     * @param  list<string>  $pending
     * @return list<array{int, string, bool}>
     */
    private function readProviderMethod(Node\Stmt\ClassMethod $method, int $depth, bool $conditional, array &$ids, array &$pending): array
    {
        $branches = $this->conditionalCallIds($method->stmts ?? []);
        $callees = [];
        foreach ($this->runningCalls($method) as $call) {
            $mayNotRun = $conditional || isset($branches[spl_object_id($call)]);
            if (! $mayNotRun) {
                $ids[spl_object_id($call)] = true;
                array_push($pending, ...$this->registeredProvider($call));
            }

            $callee = $this->ownMethodCallee($call);
            if ($callee !== null) {
                $callees[] = [0, $callee, $mayNotRun];
            }
            if ($call instanceof Node\Expr\StaticCall && $call->class instanceof Node\Name && $call->class->toLowerString() === 'parent'
                && $call->name instanceof Node\Identifier) {
                $callees[] = [$depth + 1, $call->name->toLowerString(), $mayNotRun];
            }
        }

        return $callees;
    }

    /**
     * The calls, by spl_object_id(), in the parts of these statements that run only on some
     * condition: an if, elseif or else body, a switch case, a match arm, a ternary or ?:
     * operand, the right operand of &&, ||, and, or or ??, and a loop body.
     *
     * @param  array<Node>  $statements
     * @return array<int, true>
     */
    private function conditionalCallIds(array $statements): array
    {
        $parts = [];
        foreach ($this->parser->findNodes($statements, Node::class) as $node) {
            array_push($parts, ...match (true) {
                $node instanceof Node\Stmt\If_ => [...$node->stmts, ...$node->elseifs, ...($node->else !== null ? [$node->else] : [])],
                $node instanceof Node\Stmt\Switch_ => $node->cases,
                $node instanceof Node\Expr\Match_ => $node->arms,
                $node instanceof Node\Expr\Ternary => [...($node->if !== null ? [$node->if] : []), $node->else],
                $node instanceof Node\Expr\BinaryOp\BooleanAnd, $node instanceof Node\Expr\BinaryOp\BooleanOr,
                $node instanceof Node\Expr\BinaryOp\LogicalAnd, $node instanceof Node\Expr\BinaryOp\LogicalOr,
                $node instanceof Node\Expr\BinaryOp\Coalesce => [$node->right],
                $node instanceof Node\Stmt\For_, $node instanceof Node\Stmt\Foreach_, $node instanceof Node\Stmt\While_,
                $node instanceof Node\Stmt\Do_ => $node->stmts,
                default => [],
            });
        }

        return $this->callIds($parts);
    }

    /**
     * Whether a class or one of its parents calls $this->routes(...), which sets the callback
     * RouteServiceProvider::loadRoutes() runs in place of map().
     *
     * @param  list<Node\Stmt\Class_>  $lineage
     */
    private function callsRoutes(array $lineage): bool
    {
        foreach ($this->parser->findNodes($lineage, Node\Expr\MethodCall::class) as $call) {
            if ($call instanceof Node\Expr\MethodCall && $call->var instanceof Node\Expr\Variable && $call->var->name === 'this'
                && $call->name instanceof Node\Identifier && $call->name->toLowerString() === 'routes') {
                return true;
            }
        }

        return false;
    }

    /**
     * The provider a register(...) call registers: a ::class constant, a new expression or
     * a class name string as its first argument, the name resolved. None for any other call
     * or argument.
     *
     * @return list<string>
     */
    private function registeredProvider(Node\Expr\CallLike $call): array
    {
        if (! ($call instanceof Node\Expr\MethodCall || $call instanceof Node\Expr\StaticCall)
            || ! $call->name instanceof Node\Identifier || $call->name->toLowerString() !== 'register') {
            return [];
        }

        $argument = $call->args[0] ?? null;
        $value = $argument instanceof Node\Arg ? $argument->value : null;

        return match (true) {
            $value instanceof Node\Expr\ClassConstFetch && $value->class instanceof Node\Name => [$this->resolvedName($value->class)],
            $value instanceof Node\Expr\New_ && $value->class instanceof Node\Name => [$this->resolvedName($value->class)],
            $value instanceof Node\Scalar\String_ => [ltrim($value->value, '\\')],
            default => [],
        };
    }

    /**
     * The providers the application lists: the ::class constants and class name strings in
     * the list bootstrap/providers.php returns, in config/app.php's 'providers', and in each
     * literal list bootstrap/app.php passes to withProviders(). An entry of another form is
     * not read.
     *
     * @return list<string>
     */
    private function listedProviders(): array
    {
        $lists = [];

        $file = $this->buildPath('bootstrap/providers.php');
        foreach (is_file($file) ? $this->resolveNamesForMatching($this->parser->parseFile($file)) : [] as $statement) {
            if ($statement instanceof Node\Stmt\Return_ && $statement->expr !== null) {
                $lists[] = $statement->expr;
            }
        }

        $file = $this->buildPath('config/app.php');
        foreach (is_file($file) ? $this->resolveNamesForMatching($this->parser->parseFile($file)) : [] as $statement) {
            foreach ($statement instanceof Node\Stmt\Return_ && $statement->expr instanceof Node\Expr\Array_ ? $statement->expr->items : [] as $item) {
                if ($item instanceof Node\Expr\ArrayItem && $item->key instanceof Node\Scalar\String_ && $item->key->value === 'providers') {
                    $lists[] = $this->mergedProviders($item->value);
                }
            }
        }

        $file = $this->buildPath('bootstrap/app.php');
        $ast = is_file($file) ? $this->resolveNamesForMatching($this->parser->parseFile($file)) : [];
        foreach ($this->parser->findMethodCalls($ast, 'withProviders') as $call) {
            $argument = $call instanceof Node\Expr\MethodCall ? ($call->args[0] ?? null) : null;
            $lists[] = $argument instanceof Node\Arg ? $argument->value : null;
        }

        $providers = [];
        foreach ($lists as $list) {
            foreach ($list instanceof Node\Expr\Array_ ? $list->items : [] as $item) {
                $value = $item instanceof Node\Expr\ArrayItem ? $item->value : null;
                if ($value instanceof Node\Expr\ClassConstFetch && $value->class instanceof Node\Name) {
                    $providers[] = $this->resolvedName($value->class);
                } elseif ($value instanceof Node\Scalar\String_) {
                    $providers[] = ltrim($value->value, '\\');
                }
            }
        }

        return $providers;
    }

    /**
     * The declaration of a class, with the tree of the file declaring it: read from $near,
     * the tree of the file declaring a subclass of it, or, for an App\ class, from the file
     * under app/ Laravel's convention places it in, with names resolved. Null when neither
     * declares it.
     *
     * @param  array<Node>  $near
     * @return array{Node\Stmt\Class_, array<Node>}|null
     */
    private function appClass(string $name, array $near = []): ?array
    {
        if ($near === []) {
            $key = strtolower($name);

            return array_key_exists($key, $this->appClassMemo)
                ? $this->appClassMemo[$key]
                : $this->appClassMemo[$key] = $this->readAppClass($name, []);
        }

        return $this->readAppClass($name, $near);
    }

    /**
     * Read the declaration {@see self::appClass()} returns.
     *
     * @param  array<Node>  $near
     * @return array{Node\Stmt\Class_, array<Node>}|null
     */
    private function readAppClass(string $name, array $near): ?array
    {
        // The path the route parser reads app/Providers/ files under, so the trees are the same
        $file = $this->getBasePath().'/app/'.str_replace('\\', '/', substr($name, 4)).'.php';
        $conventional = str_starts_with(strtolower($name), 'app\\') && is_file($file) ? [$this->parser->parseFile($file)] : [];

        foreach ([$near, ...$conventional] as $ast) {
            $ast = $this->resolveNamesForMatching($ast);
            foreach ($this->parser->findNodes($ast, Node\Stmt\Class_::class) as $class) {
                if ($class instanceof Node\Stmt\Class_ && $class->namespacedName !== null && strcasecmp($class->namespacedName->toString(), $name) === 0) {
                    return [$class, $ast];
                }
            }
        }

        return null;
    }

    /**
     * The list a config/app.php 'providers' value adds to the framework's own: a list, or
     * the list ServiceProvider::defaultProviders()->merge([...])->toArray() merges in.
     */
    private function mergedProviders(Node\Expr $value): ?Node\Expr
    {
        if ($value instanceof Node\Expr\MethodCall && $value->name instanceof Node\Identifier && $value->name->toLowerString() === 'toarray'
            && $value->var instanceof Node\Expr\MethodCall && $value->var->name instanceof Node\Identifier && $value->var->name->toLowerString() === 'merge'
            && $value->var->var instanceof Node\Expr\StaticCall && $value->var->var->name instanceof Node\Identifier
            && $value->var->var->name->toLowerString() === 'defaultproviders') {
            $merged = $value->var->args[0] ?? null;

            return $merged instanceof Node\Arg ? $merged->value : null;
        }

        return $value;
    }

    /**
     * The method, lowercase, a call makes on the object or class it is made in:
     * $this->name(...), self::name(...) or static::name(...). Null for any other call.
     */
    private function ownMethodCallee(Node $call): ?string
    {
        if ($call instanceof Node\Expr\MethodCall
            && $call->var instanceof Node\Expr\Variable && $call->var->name === 'this'
            && $call->name instanceof Node\Identifier) {
            return $call->name->toLowerString();
        }

        if ($call instanceof Node\Expr\StaticCall
            && $call->class instanceof Node\Name && in_array($call->class->toLowerString(), ['self', 'static'], true)
            && $call->name instanceof Node\Identifier) {
            return $call->name->toLowerString();
        }

        return null;
    }

    /**
     * Whether a class extends, directly or through classes the file declares, a class
     * whose short name matches $pattern, such as /ServiceProvider$/i for
     * Illuminate\Support\ServiceProvider or
     * Illuminate\Foundation\Support\Providers\RouteServiceProvider. The class's own name
     * is not read.
     */
    private function extendsClassNamed(Node\Stmt\Class_ $class, ClassHierarchyIndex $hierarchy, string $pattern): bool
    {
        $parent = $class->extends !== null ? $this->resolvedName($class->extends) : null;
        $seen = [];
        while ($parent !== null && ! isset($seen[ClassHierarchyIndex::key($parent)])) {
            $seen[ClassHierarchyIndex::key($parent)] = true;
            $segments = explode('\\', $parent);
            if (preg_match($pattern, end($segments)) === 1) {
                return true;
            }
            $parent = $hierarchy->parentOf($parent);
        }

        return false;
    }

    /**
     * A name as the route parser's walk resolved it, without a leading backslash.
     */
    private function resolvedName(Node\Name $name): string
    {
        $resolved = $name->getAttribute('resolvedName');

        return ltrim(($resolved instanceof Node\Name ? $resolved : $name)->toString(), '\\');
    }

    /**
     * The route files withRouting() registers: its web: files without a prefix, and its api:
     * files under its apiPrefix, or 'api' when no apiPrefix is given, each a path, or each
     * path of a list, as ApplicationBuilder::buildRoutingCallback() reads both, a variable
     * holding either read as its value. No api: file when the apiPrefix given cannot be read,
     * and none at all when withRouting() runs a using: callback in place of its own, which
     * never registers web: or api: (a then: callback makes it build its own again).
     *
     * @return array<string, non-empty-list<string>>
     */
    private function extractFollowedWithRoutingPrefixes(Node\Expr\MethodCall $call): array
    {
        $then = $this->withRoutingArgument($call, 'then');
        $using = $this->withRoutingArgument($call, 'using');
        if (($then === null || $this->isNullLiteral($then)) && $using !== null && ! $this->isNullLiteral($using)) {
            return [];
        }

        $map = [];
        $web = $this->withRoutingArgument($call, 'web');
        foreach ($web !== null ? $this->extractRouteFileBasenames($web) : [] as $file) {
            $map[$file][] = '';
        }

        $api = $this->withRoutingArgument($call, 'api');
        $apiPrefix = $this->withRoutingArgument($call, 'apiPrefix');
        $apiPrefix = $apiPrefix !== null ? BootstrapRouteParser::heldValue($apiPrefix) : new Node\Scalar\String_('api');
        if ($api === null || ! $apiPrefix instanceof Node\Scalar\String_) {
            return $map;
        }

        foreach ($this->extractRouteFileBasenames($api) as $file) {
            $map[$file][] = trim($apiPrefix->value, '/');
        }

        return $map;
    }

    /**
     * The routing callback withRouting() runs, as ApplicationBuilder::withRouting() picks
     * it: its then: callback when one is given, as it then builds its own routing callback
     * and never calls using:, otherwise its using: callback. A callback held in a variable
     * is read as the closure the variable holds. Null when it is neither a closure nor an
     * arrow function.
     */
    private function withRoutingCallback(Node\Expr\MethodCall $call): Node\Expr\Closure|Node\Expr\ArrowFunction|null
    {
        $then = $this->withRoutingArgument($call, 'then');
        $callback = $then !== null && ! $this->isNullLiteral($then) ? $then : $this->withRoutingArgument($call, 'using');
        $callback = $callback !== null ? BootstrapRouteParser::heldValue($callback) : null;

        return $callback instanceof Node\Expr\Closure || $callback instanceof Node\Expr\ArrowFunction ? $callback : null;
    }

    /**
     * The value withRouting() is given for parameter $name, by name or at its position
     * in ApplicationBuilder::withRouting(), or null when it is not given.
     */
    private function withRoutingArgument(Node\Expr\MethodCall $call, string $name): ?Node\Expr
    {
        $position = array_search($name, self::WITH_ROUTING_PARAMETERS, true);

        foreach ($call->args as $index => $arg) {
            if (! ($arg instanceof Node\Arg) || $arg->unpack) {
                continue;
            }

            if ($arg->name !== null ? $arg->name->toString() === $name : $index === $position) {
                return $arg->value;
            }
        }

        return null;
    }

    /**
     * Whether an expression is the null literal, which withRouting() reads as no argument.
     */
    private function isNullLiteral(Node\Expr $expr): bool
    {
        return $expr instanceof Node\Expr\ConstFetch && $expr->name->toLowerString() === 'null';
    }

    /**
     * Extract the basenames of the route files directly under routes/ a withRouting file
     * argument names: a path, or each path of a list, a variable holding either read as
     * its value. A path is a string literal, a __DIR__.'/../routes/api.php' style concat or
     * a base_path('routes/api.php') call.
     *
     * @return list<string>
     */
    private function extractRouteFileBasenames(Node\Expr $expr): array
    {
        $expr = BootstrapRouteParser::heldValue($expr);

        $entries = [$expr];
        if ($expr instanceof Node\Expr\Array_) {
            $entries = [];
            foreach ($expr->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem) {
                    $entries[] = BootstrapRouteParser::heldValue($item->value);
                }
            }
        }

        $basenames = [];
        foreach ($entries as $entry) {
            $path = null;
            if ($entry instanceof Node\Scalar\String_) {
                $path = $entry->value;
            } elseif ($entry instanceof Node\Expr\BinaryOp\Concat && $entry->right instanceof Node\Scalar\String_) {
                $path = $entry->right->value;
            } elseif ($this->extractBasePathRouteFile($entry) !== null && $entry instanceof Node\Expr\FuncCall
                && ($arg = $entry->args[0]->value ?? null) instanceof Node\Scalar\String_) {
                $path = $arg->value;
            }

            if ($path !== null && str_ends_with($path, '.php')
                && preg_match('~(^|/)routes$~', $this->normalizedDirname($path)) === 1) {
                $basenames[] = basename($path);
            }
        }

        return $basenames;
    }

    /**
     * The prefix the given group calls, outermost first, register their routes under, with
     * $prefix the one they are registered within: each group's prefix appended to the one
     * before it, as RouteGroup::formatPrefix() merges a group's attributes into the group
     * stack. A group that sets none keeps the prefix before it. Null when a group's prefix
     * cannot be read (see {@see self::groupLayerPrefix()}).
     *
     * @param  list<Node\Expr\MethodCall|Node\Expr\StaticCall>  $calls
     */
    private function composeGroupPrefixes(BootstrapRouteParser $routeParser, array $calls, string $prefix): ?string
    {
        foreach ($calls as $call) {
            $layer = $this->groupLayerPrefix($routeParser, $call);
            if ($layer === null) {
                return null;
            }
            if ($layer !== '') {
                $prefix = trim($prefix, '/').'/'.trim($layer, '/');
            }
        }

        return trim($prefix, '/');
    }

    /**
     * The prefix one group call on the router sets, '' when it sets none, or null when it
     * cannot be read.
     *
     * A ->group() on a registrar: the argument of the last prefix() call among the calls
     * that built it, as the route parser reads them (see
     * BootstrapRouteParser::groupChain()), following a variable holding the registrar, as
     * RouteRegistrar::attribute() overwrites the prefix on each call. A group() made on the
     * router itself, Route::group([...], ...) or $router->group([...], ...): the last
     * 'prefix' key of its attribute array, as PHP keeps the last value an array literal
     * gives one key, or null when the attributes are not an array it can read. Only
     * Router::group() takes attributes: RouteRegistrar::group() takes the routes alone. A
     * chain that starts at a class named Route other than the Route facade or its global
     * alias registers nothing, and cannot be read either.
     */
    private function groupLayerPrefix(BootstrapRouteParser $routeParser, Node\Expr\MethodCall|Node\Expr\StaticCall $groupCall): ?string
    {
        $chain = $routeParser->groupChain($groupCall);

        $root = $chain[0];
        if ($root instanceof Node\Expr\StaticCall && $root->class instanceof Node\Name
            && ! in_array(strtolower($this->resolvedName($root->class)), ['illuminate\\support\\facades\\route', 'route'], true)) {
            return null;
        }

        if (count($chain) > 1) {
            foreach (array_reverse(array_slice($chain, 0, -1)) as $current) {
                if ($current->name instanceof Node\Identifier && $current->name->toLowerString() === 'prefix') {
                    $arg = $current->args[0] ?? null;

                    return $arg instanceof Node\Arg && $arg->value instanceof Node\Scalar\String_ ? $arg->value->value : null;
                }
            }

            return '';
        }

        // Router::group($attributes, $routes): attributes it cannot read may set a prefix
        $attributes = count($groupCall->args) > 1 ? $groupCall->args[0] : null;
        if ($attributes instanceof Node\Arg && ! BootstrapRouteParser::heldValue($attributes->value) instanceof Node\Expr\Array_) {
            return null;
        }

        $prefixes = $routeParser->groupAttributeEntries($groupCall->args, 'prefix');
        if ($prefixes === []) {
            return '';
        }
        $prefix = end($prefixes);

        return $prefix instanceof Node\Scalar\String_ ? $prefix->value : null;
    }

    /**
     * Build route-level authentication statistics per controller method.
     *
     * Uses PHP-Parser AST via RouteAuthVisitor so that all valid PHP formatting
     * variants are handled without regex fragility.
     */
    private function buildPublicControllerMap(string $file): void
    {
        $ast = $this->parser->parseFile($file);
        if (empty($ast)) {
            return;
        }

        // Two-pass: first resolve all names so ClassConstFetch nodes carry FQCNs
        // when the visitor's enterNode fires (enterNode runs before children are visited,
        // so a single-pass NameResolver won't have resolved children's names yet).
        $ast = $this->resolveNamesForMatching($ast);

        $visitor = $this->visitRouteFile($file, $ast);

        foreach ($visitor->getCollectedRoutes() as $route) {
            $controller = $route['controller'];
            if ($controller === null) {
                continue; // closure routes: no controller to map
            }

            // Expand resource/apiResource routes to individual methods
            $controllerMethods = $this->expandControllerMethods($controller, $route['action'], $route['http_methods']);

            $isGuestRoute = $this->isGuestRoute($route);
            $isPublicUri = $this->isRoutePublic($route);
            $hasExplicitAuthRemoval = $this->routeDirectRemoveHasAuth($route['direct_remove']);

            foreach ($controllerMethods as $method) {
                if (! isset($this->routeAuthStats[$method])) {
                    $this->routeAuthStats[$method] = ['total' => 0, 'authenticated' => 0];
                }
                $this->routeAuthStats[$method]['total']++;

                // Auth removed at any level is stripped from the controller's middleware too
                // (Router::gatherRouteMiddleware()); a group-level removal opens the method
                // here only on a public URI, where master already counts the method public
                $removesAuth = $this->routeDirectRemoveHasAuth($route['removed']);
                if ($this->removesAuthInAnyForm($route['removed'])) {
                    $this->routeAuthRemovedMethods[$method] = true;
                }
                if (! $removesAuth && ! $isGuestRoute && $this->isRouteMiddlewareAuthenticated($route['middleware'], $route['removed'])) {
                    $this->routeAuthCarried[$method] = ($this->routeAuthCarried[$method] ?? 0) + 1;
                } elseif ($hasExplicitAuthRemoval || $isGuestRoute || $route['http_methods'] === ['GET'] || ($isPublicUri && $removesAuth)) {
                    $this->routeOpenControllerMethods[$method] = true;
                }

                // Explicit public signals win
                if ($isPublicUri || $hasExplicitAuthRemoval || $isGuestRoute) {
                    $this->publicControllerMethods[$method] = true;

                    continue;
                }

                if ($this->isRouteMiddlewareAuthenticated($route['middleware'], $route['removed'])) {
                    $this->routeAuthStats[$method]['authenticated']++;
                }
                // Unauthenticated GET routes are read-only, intentionally public. One that only
                // the middleware its file's registration applies authenticates still counts, so
                // reading that middleware never opens a finding on the method
                if ($route['http_methods'] === ['GET'] && ! $this->isRouteMiddlewareAuthenticated($route['unregistered_middleware'], $route['removed'])) {
                    $this->publicControllerMethods[$method] = true;
                }
            }
        }
    }

    /**
     * Expand a controller + action into a list of 'Controller::method' keys,
     * accounting for resource / apiResource expansion.
     *
     * @param  list<string>  $httpMethods
     * @return list<string>
     */
    private function expandControllerMethods(string $controller, ?string $action, array $httpMethods): array
    {
        if (in_array('RESOURCE', $httpMethods, true)) {
            return array_map(
                fn ($m) => "{$controller}::{$m}",
                ['index', 'create', 'store', 'show', 'edit', 'update', 'destroy']
            );
        }

        if (in_array('APIRESOURCE', $httpMethods, true)) {
            return array_map(
                fn ($m) => "{$controller}::{$m}",
                ['index', 'store', 'show', 'update', 'destroy']
            );
        }

        return ["{$controller}::".($action ?? '__invoke')];
    }

    /**
     * Check whether a list of directly-removed middleware contains auth middleware.
     *
     * @param  list<string>  $directRemove
     */
    private function routeDirectRemoveHasAuth(array $directRemove): bool
    {
        foreach ($directRemove as $mw) {
            if ($this->isAuthMiddleware($mw) || $this->isAuthorizationMiddleware($mw)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check whether the effective middleware list provides authentication.
     *
     * Handles: 'auth', 'auth:api', 'auth.basic', 'can:ability', 'role:admin',
     * 'permission:x', fully-qualified custom auth middleware class names, and
     * bare string aliases that resolve (via bootstrap/app.php or Kernel) to a
     * custom auth middleware class. A middleware group the app defines is read as its
     * members, less those the route excludes (Router::resolveMiddleware()), and a group
     * among them as its own, each group once.
     *
     * @param  list<string>  $middleware
     * @param  list<string>  $removed  The middleware the route excludes
     * @param  array<string, true>  $expanded  The groups already read as their members
     */
    private function isRouteMiddlewareAuthenticated(array $middleware, array $removed = [], array $expanded = []): bool
    {
        foreach ($middleware as $mw) {
            // A group member counts only by a strict signal (see self::isStrictAuthMiddleware()),
            // and not at all once the route excludes auth in any form: Router::resolveMiddleware()
            // compares both sides as the classes they resolve to, subclasses included
            if ($expanded !== []) {
                if ($this->isStrictAuthMiddleware($mw)) {
                    if (! $this->excludesAuth($removed)) {
                        return true;
                    }

                    continue;
                }
                if (! isset($this->resolveMiddlewareGroups()[$mw])) {
                    continue;
                }
            } elseif ($this->isAuthMiddleware($mw) || ($this->isAuthMiddlewareClass($mw) && ! $this->excludesAuth($removed))) {
                return true;
            }

            if ($this->isAuthorizationMiddleware($mw)) {
                return true;
            }

            // A group name, matched exactly as MiddlewareNameResolver matches it, before
            // any alias of the same name
            $groups = $this->resolveMiddlewareGroups();
            if (isset($groups[$mw])) {
                if (! isset($expanded[$mw])
                    && $this->isRouteMiddlewareAuthenticated(array_values(array_diff($groups[$mw], $removed)), $removed, $expanded + [$mw => true])) {
                    return true;
                }

                continue;
            }

            // Class-like strings (contain backslash = FQCN from NameResolver)
            if (str_contains($mw, '\\')) {
                if ($this->isCustomAuthMiddlewareClass($mw) || ($this->extendsAuthenticateClass($mw) && ! $this->excludesAuth($removed))) {
                    return true;
                }

                continue;
            }

            // Bare string alias (e.g. 'device.token', 'device.token:param') —
            // resolve via the app's alias map, then introspect the target class
            // for auth signals. The map is memoized, so common 'auth' routes
            // never trigger this lookup.
            $alias = explode(':', $mw, 2)[0];
            $aliasMap = $this->resolveMiddlewareAliases();
            if (isset($aliasMap[$alias]) && ($this->isCustomAuthMiddlewareClass($aliasMap[$alias])
                || ($this->extendsAuthenticateClass($aliasMap[$alias]) && ! $this->excludesAuth($removed)))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a route is for guests: it carries the 'guest' middleware, or the guest
     * middleware with a guard and no auth middleware beside it.
     *
     * Read without the middleware its file's registration applies, which never makes a
     * route for guests or stops it being one.
     *
     * @param  array{unregistered_middleware: list<string>, removed: list<string>}  $route
     */
    private function isGuestRoute(array $route): bool
    {
        $middleware = $route['unregistered_middleware'];

        return in_array('guest', $middleware, true)
            || (RouteAuthVisitor::hasGuestMiddleware($middleware) && ! $this->isRouteMiddlewareAuthenticated($middleware, $route['removed']));
    }

    /**
     * Whether a route's exclusions take out auth: as routeDirectRemoveHasAuth() reads them,
     * or in any form self::excludesAuth() reads, such as the Authenticate class.
     *
     * @param  list<string>  $removed
     */
    private function removesAuthInAnyForm(array $removed): bool
    {
        return $this->routeDirectRemoveHasAuth($removed) || $this->excludesAuth($removed);
    }

    /**
     * Whether the controller a route reaches applies auth to every method the route runs,
     * through its constructor's $this->middleware(...) or its middleware() list, which
     * Route::controllerMiddleware() gathers for the route, unless the route removes auth,
     * which strips them too (Router::gatherRouteMiddleware()). The controller is read from
     * the file Laravel's convention gives an App\ class.
     *
     * @param  array{controller: string|null, action: string|null, http_methods: list<string>, removed: list<string>}  $route
     */
    private function controllerAuthCoversRoute(array $route): bool
    {
        if ($route['controller'] === null || $this->removesAuthInAnyForm($route['removed'])) {
            return false;
        }

        $declaration = $this->appClass(ltrim($route['controller'], '\\'));
        if ($declaration === null) {
            return false;
        }

        foreach ($this->expandControllerMethods($route['controller'], $route['action'], $route['http_methods']) as $key) {
            $parts = explode('::', $key);
            if (! $this->controllerAuthCovers($parts[count($parts) - 1], $declaration[0])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check route files for missing authentication using AST-based visitor.
     *
     * @param  array<mixed>  $issues
     */
    private function checkRouteFile(string $file, array &$issues): void
    {
        $ast = $this->parser->parseFile($file);
        if (empty($ast)) {
            return;
        }

        // Two-pass: resolve all names first so ClassConstFetch FQCNs are available in enterNode
        $ast = $this->resolveNamesForMatching($ast);

        $visitor = $this->visitRouteFile($file, $ast);

        // Check route groups (only Route::group([...], fn) static-call style)
        foreach ($visitor->getCollectedGroups() as $group) {
            if (! $group['is_static_group']) {
                continue;
            }

            $hasAuth = $this->isRouteMiddlewareAuthenticated($group['effective_middleware'], $group['removed']);

            if (! $hasAuth && ! $group['has_guest']) {
                // Skip when every route inside this group is explicitly public (the user has
                // opted these URIs out via the public_routes config) or carries auth of its own.
                if ($this->groupLeavesNoRouteOpen($group, $visitor->getCollectedRoutes())) {
                    continue;
                }

                $issues[] = $this->createIssueWithSnippet(
                    message: 'Route group without authentication middleware',
                    filePath: $file,
                    lineNumber: $group['line'],
                    severity: Severity::Critical,
                    recommendation: 'Add the auth middleware to this route group. If these routes are intentionally public, add their URIs to the public_routes config option.',
                    metadata: ['route_type' => 'group', 'file' => basename($file)]
                );
            }
        }

        // Check individual routes
        foreach ($visitor->getCollectedRoutes() as $route) {
            // Skip public URIs
            if ($this->isRoutePublic($route)) {
                continue;
            }

            // Skip guest routes (guest middleware means for unauthenticated users)
            if ($this->isGuestRoute($route)) {
                continue;
            }

            // Skip if the route explicitly opted out of auth (withoutMiddleware)
            if ($this->routeDirectRemoveHasAuth($route['direct_remove'])) {
                continue;
            }

            $httpMethod = $route['http_methods'][0] ?? 'GET';
            $isMutation = $this->isMutationRoute($httpMethod);

            if ($isMutation && ! $this->isRouteMiddlewareAuthenticated($route['middleware'], $route['removed'])
                && ! $this->controllerAuthCoversRoute($route)) {
                $isClosure = $route['is_closure'];

                $issues[] = $this->createIssueWithSnippet(
                    message: $isClosure
                        ? "{$httpMethod} closure route without authentication middleware"
                        : "{$httpMethod} route without authentication middleware",
                    filePath: $file,
                    lineNumber: $route['line'],
                    severity: Severity::Critical,
                    recommendation: $isClosure
                        ? 'Apply auth middleware to this closure route or extract the logic into a controller action and protect it with auth middleware at the route or group level. If intentionally public, add the route URI to the public_routes config option.'
                        : 'Apply auth middleware to this route at the route level or inside a middleware group. If intentionally public, add the route URI to the public_routes config option.',
                    metadata: [
                        'type' => 'authentication',
                        'method' => $httpMethod,
                        'is_closure' => $isClosure,
                    ]
                );
            }
        }
    }

    /**
     * Collect a route file's routes and groups with RouteAuthVisitor, once per analysis, under
     * the prefixes and middleware the file's registrations give it. The route parser walks the tree first, so the visitor reads as route groups the group calls
     * the parser finds made on the router, and a group or a route on a variable holding a
     * registrar reads the calls that built it (see BootstrapRouteParser::routerGroupCalls() and
     * groupChain()).
     *
     * @param  array<Node>  $ast  The file's tree, with names resolved
     */
    private function visitRouteFile(string $file, array $ast): RouteAuthVisitor
    {
        if (isset($this->routeVisitors[$file])) {
            return $this->routeVisitors[$file];
        }

        // A file whose groups and routes all start at a Route facade call needs no walk
        $routeParser = new BootstrapRouteParser($this->getBasePath(), $this->parser);
        $routerGroups = $this->registersOffTheFacade($ast) ? $routeParser->routerGroupCalls($ast) : [];
        $prefixes = $this->routeFileBasePrefixes[basename($file)] ?? ['prefixes' => [''], 'required' => false];
        // The middleware a registration applies is withheld from a file that excludes any,
        // as an exclusion the visitor does not attach to a route, such as one on a group given
        // a closure variable, may take it out
        $code = file_get_contents($file);
        $base = is_string($code) && preg_match('/withoutmiddleware|excluded_middleware/i', $code) !== 1 && ! $this->registersRoutesThroughOtherCalls($ast)
            ? $this->routeFileBaseMiddleware[basename($file)] ?? []
            : [];
        $visitor = new RouteAuthVisitor($routeParser, $routerGroups, $prefixes['prefixes'], $prefixes['required'], $base);
        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        // Router::resolveMiddleware() drops auth in any form a route excludes, and excluded
        // middleware that cannot be read may be auth
        $visitor->withholdRegistration(fn (array $removed, bool $opaque): bool => $opaque || $this->removesAuthInAnyForm($removed));

        return $this->routeVisitors[$file] = $visitor;
    }

    /**
     * Whether a route file registers routes in a closure it gives a call other than group(),
     * such as a macro or a helper, which may wrap them in a group excluding middleware the
     * file does not show: a closure or arrow function argument whose body makes a route verb
     * or group() call. A route's own handler registers none.
     *
     * @param  array<Node>  $ast
     */
    private function registersRoutesThroughOtherCalls(array $ast): bool
    {
        $registering = [...RouteAuthVisitor::ROUTE_VERBS, 'group', 'options', 'any', 'match', 'redirect', 'view', 'fallback'];
        // A call on the Route facade, under any import alias, or on a $router
        $onRouter = function (Node\Expr $call): bool {
            $root = $this->chainRoot($call);
            if ($root instanceof Node\Expr\StaticCall) {
                return $root->class instanceof Node\Name && strcasecmp(basename(str_replace('\\', '/', $this->resolvedName($root->class))), 'Route') === 0;
            }

            return ($root instanceof Node\Expr\Variable && $root->name === 'router')
                || ($root instanceof Node\Expr\PropertyFetch && $root->name instanceof Node\Identifier && $root->name->toString() === 'router');
        };
        foreach ($this->parser->findNodes($ast, Node\Expr\CallLike::class) as $call) {
            $name = ($call instanceof Node\Expr\MethodCall || $call instanceof Node\Expr\StaticCall) && $call->name instanceof Node\Identifier ? $call->name->toLowerString() : null;
            if ($name === 'group' || ! $call instanceof Node\Expr\CallLike || $call->isFirstClassCallable()) {
                continue;
            }
            foreach ($call->getArgs() as $arg) {
                if (! $arg->value instanceof Node\Expr\Closure && ! $arg->value instanceof Node\Expr\ArrowFunction) {
                    continue;
                }
                foreach ($this->parser->findNodes([$arg->value], Node\Expr\CallLike::class) as $inner) {
                    if (($inner instanceof Node\Expr\MethodCall || $inner instanceof Node\Expr\StaticCall) && $inner->name instanceof Node\Identifier
                        && in_array($inner->name->toLowerString(), $registering, true) && $onRouter($inner)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Whether a tree needs the route parser's walk: it makes a ->group() call, by any case,
     * on a chain that does not start at a Route facade call that builds a registrar, such as
     * one on a variable, app('router') or Route::getFacadeRoot(), as only the walk tells
     * whether its receiver is the router; or it reads a variable only the walk resolves: the
     * receiver of a route verb call, assigned a chain the Route facade starts (directly or
     * through another such variable), a ->middleware() / ->withoutMiddleware() argument, or a
     * group's attribute array or its 'middleware' or 'excluded_middleware' value, each
     * alone or as an item of a list.
     * A verb on anything else, such as $request->get(...), needs no walk.
     *
     * @param  array<Node>  $ast
     */
    private function registersOffTheFacade(array $ast): bool
    {
        $registrars = null;
        foreach ($this->parser->findNodes($ast, Node\Expr\MethodCall::class) as $call) {
            if (! $call instanceof Node\Expr\MethodCall || ! $call->name instanceof Node\Identifier) {
                continue;
            }
            $name = $call->name->toLowerString();
            if ((in_array($name, ['middleware', 'withoutmiddleware'], true) && $this->hasVariableArgument($call))
                || ($name === 'group' && $this->hasVariableMiddlewareAttribute($call))) {
                return true;
            }
            if (! in_array($name, ['group', ...RouteAuthVisitor::ROUTE_VERBS], true)) {
                continue;
            }
            $root = $this->chainRoot($call);
            if ($name !== 'group') {
                $registrars ??= $this->registrarVariables($ast);
                if ($root instanceof Node\Expr\Variable && is_string($root->name) && isset($registrars[$root->name])) {
                    return true;
                }

                continue;
            }
            if (! $root instanceof Node\Expr\StaticCall || ! $root->class instanceof Node\Name || ! $root->name instanceof Node\Identifier
                || strcasecmp($root->class->getLast(), 'Route') !== 0 || $root->name->toLowerString() === 'getfacaderoot') {
                return true;
            }
        }

        foreach ($this->parser->findNodes($ast, Node\Expr\StaticCall::class) as $call) {
            if ($call instanceof Node\Expr\StaticCall && $call->name instanceof Node\Identifier
                && ((in_array($call->name->toLowerString(), ['middleware', 'withoutmiddleware'], true) && $this->hasVariableArgument($call))
                    || ($call->name->toLowerString() === 'group' && $this->hasVariableMiddlewareAttribute($call)))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a call is given a variable as an argument.
     */
    private function hasVariableArgument(Node\Expr\MethodCall|Node\Expr\StaticCall $call): bool
    {
        foreach ($call->args as $arg) {
            if ($arg instanceof Node\Arg && $this->holdsVariable($arg->value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a value is a variable, or a list with a variable among its items.
     */
    private function holdsVariable(Node\Expr $value): bool
    {
        if ($value instanceof Node\Expr\Array_) {
            foreach ($value->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem && $item->value instanceof Node\Expr\Variable) {
                    return true;
                }
            }
        }

        return $value instanceof Node\Expr\Variable;
    }

    /**
     * Whether a group call is given its attribute array in a variable, or one whose
     * 'middleware' or 'excluded_middleware' key holds a variable (see
     * {@see self::holdsVariable()}).
     */
    private function hasVariableMiddlewareAttribute(Node\Expr\MethodCall|Node\Expr\StaticCall $call): bool
    {
        $attributes = $call->args[0] ?? null;
        if (! $attributes instanceof Node\Arg || count($call->args) < 2) {
            return false;
        }
        if ($attributes->value instanceof Node\Expr\Variable) {
            return true;
        }

        foreach ($attributes->value instanceof Node\Expr\Array_ ? $attributes->value->items : [] as $item) {
            if ($item instanceof Node\Expr\ArrayItem && $item->key instanceof Node\Scalar\String_
                && in_array($item->key->value, ['middleware', 'excluded_middleware'], true) && $this->holdsVariable($item->value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The node a method call chain starts at.
     */
    private function chainRoot(Node\Expr $expr): Node\Expr
    {
        while ($expr instanceof Node\Expr\MethodCall) {
            $expr = $expr->var;
        }

        return $expr;
    }

    /**
     * The names of the variables a tree assigns, at any depth, a chain that starts at a
     * Route static call, or at a variable an earlier assignment in the tree so assigned.
     *
     * @param  array<Node>  $ast
     * @return array<string, true>
     */
    private function registrarVariables(array $ast): array
    {
        $names = [];
        foreach ($this->parser->findNodes($ast, Node\Expr\Assign::class) as $assign) {
            if (! $assign instanceof Node\Expr\Assign || ! $assign->var instanceof Node\Expr\Variable || ! is_string($assign->var->name)) {
                continue;
            }
            $root = $this->chainRoot($assign->expr);
            if (($root instanceof Node\Expr\StaticCall && $root->class instanceof Node\Name && strcasecmp($root->class->getLast(), 'Route') === 0)
                || ($root instanceof Node\Expr\Variable && is_string($root->name) && isset($names[$root->name]))) {
                $names[$assign->var->name] = true;
            }
        }

        return $names;
    }

    /**
     * Determine whether every route physically nested within a group's line
     * range is explicitly public (whitelisted URI, guest, or auth removed) or
     * authenticated by middleware of its own, as the group's has none.
     *
     * Returns false when the group contains no routes, so genuinely empty or
     * non-whitelisted groups continue to be flagged.
     *
     * @param  array{middleware: list<string>, effective_middleware: list<string>, unregistered_middleware: list<string>, removed: list<string>, opaque_removals: bool, line: int, end_line: int, has_guest: bool, is_static_group: bool}  $group
     * @param  list<array{uri: string, match_uris: list<list<string>>, http_methods: list<string>, controller: string|null, action: string|null, is_closure: bool, middleware: list<string>, unregistered_middleware: list<string>, direct_remove: list<string>, removed: list<string>, opaque_removals: bool, line: int, every_url: bool}>  $routes
     */
    private function groupLeavesNoRouteOpen(array $group, array $routes): bool
    {
        $found = false;

        foreach ($routes as $route) {
            // Only consider routes that physically sit inside this group's braces.
            if ($route['line'] < $group['line'] || $route['line'] > $group['end_line']) {
                continue;
            }

            $found = true;

            $isClosed = $this->isRoutePublic($route)
                || $this->isGuestRoute($route)
                || $this->routeDirectRemoveHasAuth($route['direct_remove'])
                || $this->isRouteMiddlewareAuthenticated($route['middleware'], $route['removed'])
                || $this->controllerAuthCoversRoute($route);

            if (! $isClosed) {
                return false;
            }
        }

        return $found;
    }

    /**
     * Check controller for missing authentication.
     *
     * @param  array<mixed>  $issues
     */
    private function checkController(string $file, array &$issues): void
    {
        $ast = $this->parser->parseFile($file);
        if (empty($ast)) {
            return;
        }

        // Extract namespace once per file for FQCN key construction
        $namespaceNodes = $this->parser->findNodes($ast, Node\Stmt\Namespace_::class);
        $namespace = '';
        if (! empty($namespaceNodes) && $namespaceNodes[0] instanceof Node\Stmt\Namespace_ && $namespaceNodes[0]->name !== null) {
            $namespace = $namespaceNodes[0]->name->toString();
        }

        // Resolve names so a middleware() list's ::class constants and new Middleware(...)
        // read as the classes they name
        $classes = $this->parser->findClasses($this->resolveNamesForMatching($ast));

        foreach ($classes as $class) {
            $className = $class->name ? $class->name->toString() : 'Unknown';

            // Check if controller has middleware in constructor
            $constructorMiddlewareInfo = $this->getConstructorMiddlewareInfo($class);

            // Check if controller has middleware() method
            $middlewareMethodInfo = $this->getMiddlewareMethodInfo($class);

            // Check public methods
            foreach ($class->stmts as $stmt) {
                if ($stmt instanceof Node\Stmt\ClassMethod) {
                    $methodName = $stmt->name->toString();

                    // Skip constructors and special methods
                    if (in_array($methodName, ['__construct', 'middleware'])) {
                        continue;
                    }

                    // Skip if method is not public
                    if (! $stmt->isPublic()) {
                        continue;
                    }

                    // Check sensitive methods (including invokable controllers)
                    if (in_array($methodName, $this->sensitiveControllerMethods) || $methodName === '__invoke') {
                        // Build both short-name and FQCN keys for lookup
                        $controllerMethodKey = "{$className}::{$methodName}";
                        $fqcnKey = $namespace !== '' ? "{$namespace}\\{$className}::{$methodName}" : $controllerMethodKey;

                        // Skip if this controller method is intentionally public (check both key forms)
                        if (isset($this->publicControllerMethods[$fqcnKey]) || isset($this->publicControllerMethods[$controllerMethodKey])) {
                            continue; // Method is intentionally public via route-level decision
                        }

                        // Check if method has controller-level auth middleware
                        $hasAuthMiddleware = $this->isControllerMethodAuthenticated($methodName, $constructorMiddlewareInfo, $this->controllerMiddlewareInfoFor($class, $middlewareMethodInfo, $fqcnKey, $controllerMethodKey));

                        // Also consider method authenticated if protected at route level (check both key forms)
                        $stats = $this->routeAuthStats[$fqcnKey] ?? $this->routeAuthStats[$controllerMethodKey] ?? null;

                        $isRouteProtected = $stats !== null && $stats['total'] > 0 && $stats['authenticated'] === $stats['total'];

                        if (! $hasAuthMiddleware && ! $isRouteProtected) {
                            $issues[] = $this->createIssueWithSnippet(
                                message: "Sensitive method {$className}::{$methodName}() without authentication check",
                                filePath: $file,
                                lineNumber: $stmt->getLine(),
                                severity: Severity::High,
                                recommendation: $this->isLaravel11OrNewer()
                                    ? 'Apply the auth middleware at the route or route group level that reaches this method. Constructor-based middleware was removed in Laravel 11. If intentionally public, add route URIs to the public_routes config option.'
                                    : 'Apply the auth middleware in the controller constructor or on all routes that reach this method. If intentionally public, add route URIs to the public_routes config option.',
                            );

                            continue;
                        }
                    }
                }
            }
        }
    }

    /**
     * Check FormRequest for missing or weak authorization.
     *
     * @param  array<mixed>  $issues
     */
    private function checkFormRequest(string $file, array &$issues): void
    {
        $ast = $this->parser->parseFile($file);
        if (empty($ast)) {
            return;
        }

        $classes = $this->parser->findClasses($this->resolveNamesForMatching($ast));

        foreach ($classes as $class) {
            $className = $class->name ? $class->name->toString() : 'Unknown';

            // Check if it extends FormRequest
            if (! $this->extendsFormRequest($class)) {
                continue;
            }

            // Extract namespace for FQCN construction
            $namespaceNodes = $this->parser->findNodes($ast, Node\Stmt\Namespace_::class);
            $namespace = '';
            if (! empty($namespaceNodes) && $namespaceNodes[0] instanceof Node\Stmt\Namespace_
                    && $namespaceNodes[0]->name !== null) {
                $namespace = $namespaceNodes[0]->name->toString();
            }

            // Build FQCN from namespace + short name
            $fqcn = $namespace !== '' ? "{$namespace}\\{$className}" : $className;

            // Find authorize() method
            $authorizeMethod = null;
            foreach ($class->stmts as $stmt) {
                if ($stmt instanceof Node\Stmt\ClassMethod && $stmt->name->toLowerString() === 'authorize') {
                    $authorizeMethod = $stmt;
                    break;
                }
            }

            // FormRequest::passesAuthorization() authorizes every request when the class
            // declares no authorize() method, as when it returns true. Read only for a class
            // extending FormRequest itself and using no trait: another parent or a trait may
            // declare one
            if ($authorizeMethod === null) {
                if ($this->extendsFrameworkFormRequest($class) && $class->getTraitUses() === []
                    && $this->isFormRequestUsedInUnprotectedSensitiveAction($fqcn)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: "{$className} has no authorize() method, so every request is authorized",
                        filePath: $file,
                        lineNumber: $class->getStartLine(),
                        severity: Severity::High,
                        recommendation: 'Add an authorize() method with real authorization logic using a Gate or Policy check against the authenticated user, or apply auth middleware at the route or controller level.',
                        metadata: [
                            'type' => 'form_request_authorization',
                            'class' => $className,
                        ]
                    );
                }

                continue;
            }

            // Check if authorize() returns true without any checks
            if ($this->authorizesWithoutChecks($authorizeMethod)) {
                // Only flag if actually used in a sensitive, unprotected action.
                // Without usage context, authorize() => true is ambiguous.
                if ($this->isFormRequestUsedInUnprotectedSensitiveAction($fqcn)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: "{$className}::authorize() returns true without authorization checks",
                        filePath: $file,
                        lineNumber: $authorizeMethod->getLine(),
                        severity: Severity::High,
                        recommendation: 'Add real authorization logic in the authorize() method using a Gate or Policy check against the authenticated user, or apply auth middleware at the route or controller level.',
                        metadata: [
                            'type' => 'form_request_authorization',
                            'class' => $className,
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check if a class extends FormRequest.
     */
    private function extendsFormRequest(Node\Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $extends = $class->extends->toString();

        return str_contains($extends, 'FormRequest');
    }

    /**
     * Whether a class extends Illuminate\Foundation\Http\FormRequest directly, as its
     * imports resolve the parent's name.
     */
    private function extendsFrameworkFormRequest(Node\Stmt\Class_ $class): bool
    {
        return $class->extends !== null
            && strcasecmp($this->resolvedName($class->extends), 'Illuminate\\Foundation\\Http\\FormRequest') === 0;
    }

    /**
     * Check if authorize() method returns true without any checks.
     */
    private function authorizesWithoutChecks(Node\Stmt\ClassMethod $method): bool
    {
        if ($method->stmts === null || empty($method->stmts)) {
            return false;
        }

        // Look for immediate "return true;"
        foreach ($method->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Return_) {
                $returnValue = $stmt->expr;

                // Check for "return true;"
                if ($returnValue instanceof Node\Expr\ConstFetch) {
                    $constName = $returnValue->name->toString();
                    if (strcasecmp($constName, 'true') === 0) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Get FormRequest files.
     *
     * @return array<string>
     */
    private function getFormRequestFiles(): array
    {
        $files = [];

        foreach ($this->getPhpFiles() as $file) {
            if (str_contains($file, '/Requests/') || str_ends_with($file, 'Request.php')) {
                $files[] = $file;
            }
        }

        return $files;
    }

    /**
     * Find all controller methods that type-hint the given FormRequest, read from the index
     * {@see self::controllerParameterTypes()} builds once per analysis.
     *
     * @return list<array{controllerClass: string, namespace: string, methodName: string, classNode: Node\Stmt\Class_}>
     */
    private function findFormRequestUsagesInControllers(string $fqcn): array
    {
        $this->controllerParameterTypes ??= $this->controllerParameterTypes();

        return $this->controllerParameterTypes[strtolower($fqcn)] ?? [];
    }

    /**
     * The public controller methods each class is the type of a parameter of, keyed by the
     * class name, lowercase. Parameter type names are resolved through each file's namespace
     * and use imports, so only the FQCN matches: a type that cannot be resolved, or names
     * another class of the same short name, is no usage.
     *
     * @return array<string, list<array{controllerClass: string, namespace: string, methodName: string, classNode: Node\Stmt\Class_}>>
     */
    private function controllerParameterTypes(): array
    {
        $index = [];

        foreach ($this->getControllerFiles() as $file) {
            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            // Resolve names through the file's namespace and imports
            $ast = $this->resolveNamesForMatching($ast);

            // Extract namespace
            $namespaceNodes = $this->parser->findNodes($ast, Node\Stmt\Namespace_::class);
            $ns = '';
            if (! empty($namespaceNodes) && $namespaceNodes[0] instanceof Node\Stmt\Namespace_
                    && $namespaceNodes[0]->name !== null) {
                $ns = $namespaceNodes[0]->name->toString();
            }

            foreach ($this->parser->findClasses($ast) as $class) {
                $controllerClass = $class->name ? $class->name->toString() : 'Unknown';

                foreach ($class->stmts as $stmt) {
                    if (! ($stmt instanceof Node\Stmt\ClassMethod) || ! $stmt->isPublic()) {
                        continue;
                    }

                    // Each class the method takes, once
                    $types = [];
                    foreach ($stmt->getParams() as $param) {
                        $resolvedType = $param->type instanceof Node\Name ? $param->type->getAttribute('resolvedName') : null;
                        if ($resolvedType instanceof Node\Name\FullyQualified) {
                            $types[$resolvedType->toLowerString()] = true;
                        }
                    }

                    foreach (array_keys($types) as $type) {
                        $index[$type][] = [
                            'controllerClass' => $controllerClass,
                            'namespace' => $ns,
                            'methodName' => $stmt->name->toString(),
                            'classNode' => $class,
                        ];
                    }
                }
            }
        }

        return $index;
    }

    /**
     * Return true only when the FormRequest, one whose authorize() returns true or which
     * declares none, is injected into a sensitive controller action that is not protected
     * by any auth signal.
     */
    private function isFormRequestUsedInUnprotectedSensitiveAction(string $fqcn): bool
    {
        $usages = $this->findFormRequestUsagesInControllers($fqcn);

        if (empty($usages)) {
            return false; // No usage found — cannot determine risk
        }

        foreach ($usages as $usage) {
            $method = $usage['methodName'];
            $controllerClass = $usage['controllerClass'];
            $ns = $usage['namespace'];
            $classNode = $usage['classNode'];

            // Only flag if method is sensitive
            if (! in_array($method, $this->sensitiveControllerMethods, true)
                    && $method !== '__invoke') {
                continue;
            }

            // Build lookup keys (same pattern as checkController())
            $shortKey = "{$controllerClass}::{$method}";
            $fqcnKey = $ns !== '' ? "{$ns}\\{$controllerClass}::{$method}" : $shortKey;

            // 1. Intentionally public via route analysis
            //    (covers guest groups, GET routes, explicit ->withoutMiddleware(['auth']))
            if (isset($this->publicControllerMethods[$fqcnKey])
                    || isset($this->publicControllerMethods[$shortKey])) {
                continue;
            }

            // 2. Route-level auth/authorization middleware
            $stats = $this->routeAuthStats[$fqcnKey] ?? $this->routeAuthStats[$shortKey] ?? null;
            if ($stats !== null && $stats['total'] > 0
                    && $stats['authenticated'] === $stats['total']) {
                continue;
            }

            // 3. Controller constructor or middleware() method protection
            $constructorInfo = $this->getConstructorMiddlewareInfo($classNode);
            $middlewareMethodInfo = $this->controllerMiddlewareInfoFor($classNode, $this->getMiddlewareMethodInfo($classNode), $fqcnKey, $shortKey);
            if ($this->isControllerMethodAuthenticated($method, $constructorInfo, $middlewareMethodInfo)) {
                continue;
            }

            // Sensitive + unprotected across all signals → real risk
            return true;
        }

        return false; // All usages are either non-sensitive or already protected
    }

    /**
     * Get middleware information from controller's constructor.
     *
     * Returns array with 'auth' key containing 'only' or 'except' arrays, or null if no auth middleware.
     *
     * @return array<string, array{only?: array<string>, except?: array<string>, unread?: array<string>, option_only?: array<string>, option_except?: array<string>}>|null
     */
    private function getConstructorMiddlewareInfo(Node\Stmt\Class_ $class): ?array
    {
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\ClassMethod && $stmt->name->toLowerString() === '__construct') {
                foreach ($stmt->stmts ?? [] as $constructorStmt) {
                    if ($constructorStmt instanceof Node\Stmt\Expression) {
                        $expr = $constructorStmt->expr;

                        // Check for $this->middleware('auth') or chained methods
                        $middlewareInfo = $this->extractMiddlewareFromExpression($expr);
                        if ($middlewareInfo !== null) {
                            return $middlewareInfo;
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * Extract middleware information from an expression, including chained methods.
     *
     * Handles:
     * - $this->middleware('auth')
     * - $this->middleware('auth')->only(['destroy'])
     * - $this->middleware('auth')->except(['index'])
     *
     * @return array<string, array<string, array<string>>>|null
     */
    private function extractMiddlewareFromExpression(Node\Expr $expr): ?array
    {
        // Track chained method calls
        $middlewareName = null;
        $constraints = [];
        $currentExpr = $expr;

        // Walk through chained method calls (e.g., middleware()->only())
        while ($currentExpr instanceof Node\Expr\MethodCall) {
            $methodName = $currentExpr->name instanceof Node\Identifier ? $currentExpr->name->toLowerString() : null;

            if ($methodName === 'middleware') {
                // The options array of Controller::middleware($middleware, $options), its only
                // and except lists recorded apart, as only controllerAuthCovers() reads them
                $options = $currentExpr->args[1] ?? null;
                if ($options instanceof Node\Arg) {
                    foreach ($options->value instanceof Node\Expr\Array_ ? $options->value->items : [null] as $option) {
                        if (! $option instanceof Node\Expr\ArrayItem) {
                            $constraints['unread'] = [];

                            continue;
                        }
                        $key = $option->key instanceof Node\Scalar\String_ ? $option->key->value : null;
                        if ($key === 'only' || $key === 'except') {
                            $methods = $this->stringList($option->value);
                            if ($methods === null) {
                                $constraints['unread'] = [];
                            } else {
                                $constraints['option_'.$key] = $methods;
                            }
                        }
                    }
                }

                // Extract middleware name from arguments
                foreach ($currentExpr->args as $arg) {
                    // A first-class callable yields a VariadicPlaceholder, which has no value.
                    $value = $arg instanceof Node\Arg ? $arg->value : null;
                    if ($value instanceof Node\Scalar\String_) {
                        // Check for auth or authorization middleware
                        if ($this->isAuthMiddleware($value->value) || $this->isAuthorizationMiddleware($value->value)) {
                            $middlewareName = $value->value;
                        }
                    }
                    // Also check array arguments like ['auth', 'can:update,post']
                    if ($value instanceof Node\Expr\Array_) {
                        foreach ($value->items as $item) {
                            if ($item instanceof Node\Expr\ArrayItem && $item->value instanceof Node\Scalar\String_) {
                                if ($this->isAuthMiddleware($item->value->value) || $this->isAuthorizationMiddleware($item->value->value)) {
                                    $middlewareName = $item->value->value;
                                    break;
                                }
                            }
                        }
                    }
                }
            } elseif ($methodName === 'only' || $methodName === 'except') {
                // Extract method names from only/except
                $methods = [];
                foreach ($currentExpr->args as $arg) {
                    // A first-class callable yields a VariadicPlaceholder, which has no value.
                    $value = $arg instanceof Node\Arg ? $arg->value : null;
                    if ($value instanceof Node\Expr\Array_) {
                        foreach ($value->items as $item) {
                            if ($item instanceof Node\Expr\ArrayItem && $item->value instanceof Node\Scalar\String_) {
                                $methods[] = $item->value->value;
                            }
                        }
                    } elseif ($value instanceof Node\Scalar\String_) {
                        $methods[] = $value->value;
                    }
                    // A list that cannot be read, or an empty only list, is recorded under
                    // 'unread': it covers no method where controller auth credits a route
                    // or the Auth::user() check (see self::controllerAuthCovers())
                    if (! $value instanceof Node\Scalar\String_
                        && ($value === null || $this->stringList($value) === null)) {
                        $constraints['unread'] = [];
                    }
                }
                if (! empty($methods)) {
                    $constraints[$methodName] = $methods;
                } elseif ($methodName === 'only') {
                    $constraints['unread'] = [];
                }
            }

            // Move to the next expression in the chain (if any)
            $currentExpr = $currentExpr->var;
        }

        // If we found auth middleware, return the info
        if ($middlewareName !== null) {
            return [$middlewareName => $constraints];
        }

        return null;
    }

    /**
     * Get middleware information from controller's middleware() method.
     *
     * Returns each auth or authorization middleware the method's returned array lists, with
     * the 'only' or 'except' methods it is limited to, or null if it lists none. An entry is
     * a keyed 'auth' => ['only' => [...]] pair, or, as a HasMiddleware controller lists it, a
     * middleware string or ::class constant, or a new Middleware(...) definition (see
     * {@see self::controllerMiddlewareDefinition()}). The list form is read only from a
     * class that implements HasMiddleware, the only one Route::controllerMiddleware() reads
     * it from; the keyed form, read as master read it, is left out when $keyed is false.
     *
     * @return list<array{string, array{only?: array<string>, except?: array<string>}, bool}>|null
     */
    private function getMiddlewareMethodInfo(Node\Stmt\Class_ $class, bool $keyed = true, bool $listed = true): ?array
    {
        $hasMiddleware = null;
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\ClassMethod && $stmt->name->toLowerString() === 'middleware') {
                // Check if method returns an array
                foreach ($stmt->stmts ?? [] as $methodStmt) {
                    if ($methodStmt instanceof Node\Stmt\Return_ && $methodStmt->expr instanceof Node\Expr\Array_) {
                        $middlewareInfo = [];

                        foreach ($methodStmt->expr->items as $item) {
                            if (! ($item instanceof Node\Expr\ArrayItem)) {
                                continue;
                            }

                            if ($item->key === null) {
                                $hasMiddleware ??= $listed && $this->implementsHasMiddleware($class);
                                $entries = $hasMiddleware ? $this->controllerMiddlewareDefinition($item->value) : [];
                            } else {
                                $entries = $keyed ? $this->keyedControllerMiddleware($item) : [];
                            }

                            foreach ($entries as [$name, $constraints, $isListed]) {
                                if ($this->isAuthMiddleware($name) || $this->isAuthorizationMiddleware($name) || $this->isAuthMiddlewareClass($name)) {
                                    $middlewareInfo[] = [$name, $constraints, $isListed];
                                }
                            }
                        }

                        if (! empty($middlewareInfo)) {
                            return $middlewareInfo;
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * The middleware a keyed middleware() entry names: its key, such as 'auth', 'auth:api'
     * or 'can:update,post', limited by the 'only' or 'except' list its array value gives,
     * or applying to every method for any other value.
     *
     * @return list<array{string, array{only?: array<string>, except?: array<string>}, bool}>
     */
    private function keyedControllerMiddleware(Node\Expr\ArrayItem $item): array
    {
        $key = $this->extractArrayKeyValue($item->key);
        if ($key === null) {
            return [];
        }

        $constraints = [];
        if ($item->value instanceof Node\Expr\Array_) {
            foreach ($item->value->items as $constraintItem) {
                if (! ($constraintItem instanceof Node\Expr\ArrayItem)) {
                    continue;
                }

                $constraintKey = $this->extractArrayKeyValue($constraintItem->key);

                if ($constraintKey === 'only' || $constraintKey === 'except') {
                    $methods = [];
                    if ($constraintItem->value instanceof Node\Expr\Array_) {
                        foreach ($constraintItem->value->items as $methodItem) {
                            if ($methodItem instanceof Node\Expr\ArrayItem && $methodItem->value instanceof Node\Scalar\String_) {
                                $methods[] = $methodItem->value->value;
                            }
                        }
                    }
                    $constraints[$constraintKey] = $methods;
                }
            }
        }

        return [[$key, $constraints, false]];
    }

    /**
     * The middleware a HasMiddleware controller's middleware() list entry defines, each with
     * the methods it is limited to, as Route::staticallyProvidedControllerMiddleware() reads
     * the entry: a middleware string or ::class constant applies to every method, and a
     * new Middleware(...) applies its middleware, one or a list, to the methods its only
     * and except arguments, by name or position, leave in, or those its chained ->only() and
     * ->except() calls set in their place.
     *
     * @return list<array{string, array{only?: array<string>, except?: array<string>}, bool}>
     */
    private function controllerMiddlewareDefinition(Node\Expr $value): array
    {
        $constraints = [];
        while ($value instanceof Node\Expr\MethodCall && $value->name instanceof Node\Identifier
            && in_array($value->name->toLowerString(), ['only', 'except'], true)) {
            $argument = $value->args[0] ?? null;
            $constraints[$value->name->toLowerString()] ??= $argument instanceof Node\Arg ? $this->stringList($argument->value) : null;
            $value = $value->var;
        }

        if (! $value instanceof Node\Expr\New_) {
            return $constraints === [] ? array_map(fn (string $name): array => [$name, [], true], $this->middlewareNames($value)) : [];
        }
        // The class as resolved, or, in a tree whose names were not resolved, as written
        $class = $value->class;
        if (! $class instanceof Node\Name
            || ($class->getAttribute('resolvedName') !== null || $class->isFullyQualified()
                ? strcasecmp($this->resolvedName($class), 'Illuminate\\Routing\\Controllers\\Middleware') !== 0
                : strcasecmp($class->toString(), 'Middleware') !== 0)) {
            return [];
        }

        $arguments = [];
        foreach ($value->args as $position => $arg) {
            if ($arg instanceof Node\Arg && ! $arg->unpack) {
                $arguments[$arg->name !== null ? $arg->name->toString() : ['middleware', 'only', 'except'][$position] ?? ''] = $arg->value;
            }
        }
        foreach (['only', 'except'] as $option) {
            if (! array_key_exists($option, $constraints) && isset($arguments[$option]) && ! $this->isNullLiteral($arguments[$option])) {
                $constraints[$option] = $this->stringList($arguments[$option]);
            }
        }

        // An except list that cannot be read may leave out any method, so the definition
        // covers none; an only list that cannot be read covers none as it is
        if (array_key_exists('except', $constraints) && $constraints['except'] === null) {
            return [];
        }
        $limits = [];
        foreach ($constraints as $option => $methods) {
            $limits[$option] = $methods ?? [];
        }

        return array_map(fn (string $name): array => [$name, $limits, true], isset($arguments['middleware']) ? $this->middlewareNames($arguments['middleware']) : []);
    }

    /**
     * The strings a value lists, or the one string it is. Null when it cannot be read: any
     * other value, or a list with an entry that is not a literal string.
     *
     * @return list<string>|null
     */
    private function stringList(Node\Expr $value): ?array
    {
        if ($value instanceof Node\Scalar\String_) {
            return [$value->value];
        }
        if (! $value instanceof Node\Expr\Array_) {
            return null;
        }

        $strings = [];
        foreach ($value->items as $item) {
            if (! $item instanceof Node\Expr\ArrayItem || $item->unpack || ! $item->value instanceof Node\Scalar\String_) {
                return null;
            }
            $strings[] = $item->value->value;
        }

        return $strings;
    }

    /**
     * Whether a controller implements Illuminate\Routing\Controllers\HasMiddleware, itself or
     * through an App\ parent read from the file Laravel's convention places it in. A name
     * not resolved is read as written, the short name standing for the import.
     *
     * @param  array<string, true>  $seen  The parents already read, lowercase
     */
    private function implementsHasMiddleware(Node\Stmt\Class_ $class, array $seen = []): bool
    {
        return $this->hasMiddlewareMemo[spl_object_id($class)] ??= $this->readsHasMiddleware($class, $seen);
    }

    /**
     * Read what {@see self::implementsHasMiddleware()} returns.
     *
     * @param  array<string, true>  $seen
     */
    private function readsHasMiddleware(Node\Stmt\Class_ $class, array $seen): bool
    {
        foreach ($class->implements as $interface) {
            if ($interface->getAttribute('resolvedName') !== null || $interface->isFullyQualified()
                ? strcasecmp($this->resolvedName($interface), 'Illuminate\\Routing\\Controllers\\HasMiddleware') === 0
                : strcasecmp($interface->toString(), 'HasMiddleware') === 0) {
                return true;
            }
        }

        $parent = $class->extends !== null ? $this->resolvedName($class->extends) : null;
        if ($parent === null || isset($seen[strtolower($parent)])) {
            return false;
        }
        $declaration = $this->appClass($parent);

        return $declaration !== null && $this->implementsHasMiddleware($declaration[0], $seen + [strtolower($parent) => true]);
    }

    /**
     * Whether controller-level auth that Laravel applies covers a method, read only as far as
     * it can be: the constructor's auth middleware, less any whose method list cannot be
     * read, and a HasMiddleware controller's middleware() list. The keyed middleware() form
     * is left out, as Laravel never reads it.
     */
    private function controllerAuthCovers(string $methodName, Node\Stmt\Class_ $class): bool
    {
        $id = spl_object_id($class);
        if (! isset($this->controllerAuthEntriesMemo[$id])) {
            // The constructor's method lists: a chained ->only() or ->except() in place of
            // the one its options array gives (ControllerMiddlewareOptions), both applied
            $entries = [];
            foreach ($this->getConstructorMiddlewareInfo($class) ?? [] as $name => $constraints) {
                if (isset($constraints['unread'])) {
                    continue;
                }
                $limits = [];
                foreach (['only', 'except'] as $option) {
                    $methods = $constraints[$option] ?? $constraints['option_'.$option] ?? null;
                    if ($methods !== null) {
                        $limits[$option] = $methods;
                    }
                }
                $entries[] = [$name, $limits, true];
            }
            $this->controllerAuthEntriesMemo[$id] = [...$entries, ...$this->getMiddlewareMethodInfo($class, false) ?? []];
        }

        return $this->middlewareMethodProvidesAuthentication($methodName, $this->controllerAuthEntriesMemo[$id]);
    }

    /**
     * The middleware() entries the sensitive-method and Auth::user() checks credit a method
     * with: those given, less a HasMiddleware list when a route reaching the method removes
     * auth, which strips the controller's middleware too. The keyed form is read as master
     * read it.
     *
     * @param  list<array{string, array{only?: array<string>, except?: array<string>}, bool}>|null  $middlewareMethodInfo
     * @return list<array{string, array{only?: array<string>, except?: array<string>}, bool}>|null
     */
    private function controllerMiddlewareInfoFor(Node\Stmt\Class_ $class, ?array $middlewareMethodInfo, string $fqcnKey, string $shortKey): ?array
    {
        return isset($this->routeAuthRemovedMethods[$fqcnKey]) || isset($this->routeAuthRemovedMethods[$shortKey])
            ? $this->getMiddlewareMethodInfo($class, true, false)
            : $middlewareMethodInfo;
    }

    /**
     * Extract array key value from a PHP-Parser node.
     *
     * @param  Node\Expr|Node\Identifier|Node\Scalar\String_|Node\Scalar\LNumber|Node\Scalar\DNumber|null  $keyNode
     */
    private function extractArrayKeyValue($keyNode): ?string
    {
        if ($keyNode === null) {
            return null;
        }

        if ($keyNode instanceof Node\Identifier) {
            return $keyNode->toString();
        }

        if ($keyNode instanceof Node\Scalar\String_) {
            return $keyNode->value;
        }

        // For other types (numbers, expressions), return null
        return null;
    }

    /**
     * Check if controller method is authenticated.
     *
     * @param  array<string, array{only?: array<string>, except?: array<string>, unread?: array<string>, option_only?: array<string>, option_except?: array<string>}>|null  $constructorMiddlewareInfo
     * @param  list<array{string, array{only?: array<string>, except?: array<string>}, bool}>|null  $middlewareMethodInfo
     */
    private function isControllerMethodAuthenticated(string $methodName, ?array $constructorMiddlewareInfo, ?array $middlewareMethodInfo): bool
    {
        // Check constructor middleware with constraints
        $constructorEntries = [];
        foreach ($constructorMiddlewareInfo ?? [] as $name => $constraints) {
            $constructorEntries[] = [$name, $constraints, false];
        }
        if ($this->middlewareMethodProvidesAuthentication($methodName, $constructorEntries)) {
            return true;
        }

        // Check middleware() method
        return $this->middlewareMethodProvidesAuthentication(
            $methodName,
            $middlewareMethodInfo
        );
    }

    /**
     * Check if middleware method provides authentication or authorization. A HasMiddleware
     * list entry, or one controllerAuthCovers() reads, covers the method when it is in its
     * only list, if any, and not in its except list, as Route::methodExcludedByOptions()
     * reads both, and any such entry covering it is enough; a constructor or keyed entry is
     * read as master read it, the first auth entry deciding.
     *
     * @param  list<array{string, array{only?: array<string>, except?: array<string>, unread?: array<string>}, bool}>|null  $middlewareInfo
     */
    private function middlewareMethodProvidesAuthentication(string $methodName, ?array $middlewareInfo): bool
    {
        if ($middlewareInfo === null) {
            return false;
        }

        foreach ($middlewareInfo as [$middlewareName, $constraints, $listed]) {
            // Check for both auth and authorization middleware (can:, role:, permission:)
            if (! $this->isAuthMiddleware($middlewareName) && ! $this->isAuthorizationMiddleware($middlewareName) && ! $this->isAuthMiddlewareClass($middlewareName)) {
                continue;
            }

            // A listed entry applies when both its lists let the method in, and any one
            // applying covers it
            if ($listed) {
                if ((! isset($constraints['only']) || in_array($methodName, $constraints['only'], true))
                    && (! isset($constraints['except']) || ! in_array($methodName, $constraints['except'], true))) {
                    return true;
                }

                continue;
            }

            // A constructor or keyed entry: the first one decides, its only list over its
            // except list
            if (isset($constraints['only'])) {
                return in_array($methodName, $constraints['only'], true);
            }

            return ! isset($constraints['except']) || ! in_array($methodName, $constraints['except'], true);
        }

        return false;
    }

    /**
     * Check for unsafe Auth::user() usage without null checks.
     *
     * @param  array<mixed>  $issues
     */
    private function checkUnsafeAuthUsage(string $file, array &$issues): void
    {
        $lines = FileParser::getLines($file);

        $ast = $this->parser->parseFile($file);

        $namespaceNodes = $this->parser->findNodes($ast, Node\Stmt\Namespace_::class);
        $namespace = '';
        if (! empty($namespaceNodes) && $namespaceNodes[0] instanceof Node\Stmt\Namespace_
                && $namespaceNodes[0]->name !== null) {
            $namespace = $namespaceNodes[0]->name->toString();
        }

        $stringLines = $this->parser->collectStringLines($ast);

        foreach ($lines as $lineNumber => $line) {
            // $lines is 0-indexed (FileParser::getLines); $stringLines keys are 1-indexed (AST lines).
            if (isset($stringLines[$lineNumber + 1])) {
                continue;
            }

            // Check for Auth::user()-> (but NOT Auth::user()?-> which is safe)
            if (preg_match('/Auth::user\(\)\s*->/i', $line) && ! preg_match('/Auth::user\(\)\s*\?->/i', $line)) {
                $this->checkAuthUsageWithNullSafety(
                    file: $file,
                    lines: $lines,
                    lineNumber: $lineNumber,
                    method: 'Auth::user()',
                    checkMethod: 'Auth::check()',
                    issues: $issues,
                    ast: $ast,
                    namespace: $namespace
                );
            }

            // Check for auth()->user()-> (but NOT auth()->user()?-> which is safe)
            if (preg_match('/auth\(\)->user\(\)\s*->/i', $line) && ! preg_match('/auth\(\)->user\(\)\s*\?->/i', $line)) {
                $this->checkAuthUsageWithNullSafety(
                    file: $file,
                    lines: $lines,
                    lineNumber: $lineNumber,
                    method: 'auth()->user()',
                    checkMethod: 'auth()->check()',
                    issues: $issues,
                    ast: $ast,
                    namespace: $namespace
                );
            }

            // Check for $request->user()-> (but NOT $request->user()?-> which is safe)
            if (preg_match('/\$request->user\(\)\s*->/i', $line) && ! preg_match('/\$request->user\(\)\s*\?->/i', $line)) {
                $this->checkAuthUsageWithNullSafety(
                    file: $file,
                    lines: $lines,
                    lineNumber: $lineNumber,
                    method: '$request->user()',
                    checkMethod: '$request->user()',
                    issues: $issues,
                    ast: $ast,
                    namespace: $namespace
                );
            }
        }
    }

    /**
     * Check if auth method is used with proper null safety.
     *
     * @param  array<int, string>  $lines
     * @param  array<Node>  $ast
     * @param  array<mixed>  $issues
     */
    private function checkAuthUsageWithNullSafety(
        string $file,
        array $lines,
        int $lineNumber,
        string $method,
        string $checkMethod,
        array &$issues,
        array $ast = [],
        string $namespace = '',
    ): void {
        // Look for null checks in surrounding lines
        $searchRange = max(0, $lineNumber - 3);
        $hasNullCheck = false;

        for ($i = $searchRange; $i <= $lineNumber; $i++) {
            if (isset($lines[$i]) && $this->hasAuthNullCheck($lines[$i])) {
                $hasNullCheck = true;
                break;
            }
        }

        if (! $hasNullCheck) {
            // Suppress when the enclosing method is guaranteed non-null by auth middleware
            if (! empty($ast) && $this->isLineInAuthProtectedMethod($ast, $namespace, $lineNumber)) {
                return;
            }

            $issues[] = $this->createIssueWithSnippet(
                message: "Unsafe {$method} usage without null check",
                filePath: $file,
                lineNumber: $lineNumber + 1,
                severity: Severity::Medium,
                recommendation: 'Verify that the user is authenticated before accessing their properties. Guard the access with an authentication check condition, or switch to the nullsafe property access operator to safely handle unauthenticated users.',
                metadata: [
                    'method' => $method,
                    'check_method' => $checkMethod,
                    'file' => basename($file),
                ]
            );
        }
    }

    /**
     * Return true when the method enclosing $lineNumber is guaranteed to receive
     * only authenticated requests, making Auth::user() / $request->user() non-null.
     *
     * @param  array<Node>  $ast
     */
    private function isLineInAuthProtectedMethod(array $ast, string $namespace, int $lineNumber): bool
    {
        $enclosing = $this->findEnclosingClassMethod($ast, $lineNumber);
        if ($enclosing === null) {
            return false;
        }

        $className = $enclosing['className'];
        $methodName = $enclosing['methodName'];
        $classNode = $enclosing['classNode'];

        $shortKey = "{$className}::{$methodName}";
        $fqcnKey = $namespace !== '' ? "{$namespace}\\{$className}::{$methodName}" : $shortKey;

        // Every route to this class's method carries auth middleware, whether or not its URI
        // is listed as public, so the user is never null here. Read only when routes name the
        // class itself: a short name alone may be another class, which master's route-level
        // test below already reads as it reads it. Routes under the short name must carry
        // auth too, as they may reach this method.
        $carried = isset($this->routeAuthStats[$fqcnKey]);
        foreach (array_unique([$fqcnKey, $shortKey]) as $key) {
            if (isset($this->routeAuthStats[$key])) {
                $carried = $carried && ($this->routeAuthCarried[$key] ?? 0) === $this->routeAuthStats[$key]['total'];
            }
        }
        if ($carried) {
            return true;
        }

        // Controller-level auth covering the method runs on every route that reaches it,
        // open or not, unless one of them removes auth
        if (! isset($this->routeAuthRemovedMethods[$fqcnKey]) && ! isset($this->routeAuthRemovedMethods[$shortKey])
            && $this->controllerAuthCovers($methodName, $classNode)) {
            return true;
        }

        // Reached without auth on purpose (guest route, auth removed, unauthenticated GET) → do not suppress
        if (isset($this->routeOpenControllerMethods[$fqcnKey])
                || isset($this->routeOpenControllerMethods[$shortKey])) {
            return false;
        }

        // Route-level: every known route to this method is authenticated. A method public
        // only through public_routes skips this, as such a route never counts as authenticated
        // here, and falls through to the controller's own auth
        $isPublic = isset($this->publicControllerMethods[$fqcnKey]) || isset($this->publicControllerMethods[$shortKey]);
        $stats = $this->routeAuthStats[$fqcnKey] ?? $this->routeAuthStats[$shortKey] ?? null;
        if (! $isPublic && $stats !== null && $stats['total'] > 0
                && $stats['authenticated'] === $stats['total']) {
            return true;
        }

        // Controller-level: constructor $this->middleware('auth') or middleware() method
        $constructorInfo = $this->getConstructorMiddlewareInfo($classNode);
        $middlewareMethodInfo = $this->controllerMiddlewareInfoFor($classNode, $this->getMiddlewareMethodInfo($classNode), $fqcnKey, $shortKey);

        return $this->isControllerMethodAuthenticated($methodName, $constructorInfo, $middlewareMethodInfo);
    }

    /**
     * Find the class and method that encloses the given (0-indexed) line number.
     *
     * @param  array<Node>  $ast
     * @return array{className: string, methodName: string, classNode: Node\Stmt\Class_}|null
     */
    private function findEnclosingClassMethod(array $ast, int $lineNumber): ?array
    {
        // FileParser lines are 0-indexed; AST line numbers are 1-indexed
        $oneBased = $lineNumber + 1;

        foreach ($this->parser->findClasses($ast) as $class) {
            $className = $class->name ? $class->name->toString() : 'Unknown';

            foreach ($class->stmts as $stmt) {
                if (! ($stmt instanceof Node\Stmt\ClassMethod)) {
                    continue;
                }

                if ($oneBased >= $stmt->getStartLine() && $oneBased <= $stmt->getEndLine()) {
                    return [
                        'className' => $className,
                        'methodName' => $stmt->name->toString(),
                        'classNode' => $class,
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Check if a middleware name represents authentication middleware.
     * Supports: auth, auth:api, auth:sanctum, auth:web, and the built-in
     * HTTP Basic auth alias auth.basic (optionally auth.basic:guard,field).
     */
    private function isAuthMiddleware(string $middleware): bool
    {
        $middleware = trim($middleware);

        // Match 'auth' optionally followed by a colon and guard name
        // Examples: 'auth', 'auth:api', 'auth:sanctum', 'auth:web'
        // The built-in 'auth.basic' alias challenges and rejects unauthenticated
        // requests, so it counts as authentication too.
        return (bool) preg_match('/^auth(?::[a-zA-Z0-9_-]+)?$/i', $middleware)
            || (bool) preg_match('/^auth\.basic(?::.+)?$/i', $middleware);
    }

    /**
     * Whether a middleware names Laravel's authentication middleware class, Authenticate or
     * AuthenticateWithBasicAuth, which the auth and auth.basic aliases resolve to: with or
     * without a leading backslash and parameters, compared case-insensitively as PHP
     * compares class names.
     */
    private function isAuthMiddlewareClass(string $middleware): bool
    {
        $class = strtolower(ltrim(explode(':', trim($middleware), 2)[0], '\\'));

        return $class === 'illuminate\\auth\\middleware\\authenticate'
            || $class === 'illuminate\\auth\\middleware\\authenticatewithbasicauth';
    }

    /**
     * Whether a middleware authenticates by a strict signal: an auth alias, the Authenticate
     * or AuthenticateWithBasicAuth class, or a class, named or through the app's alias map,
     * that extends one.
     */
    private function isStrictAuthMiddleware(string $middleware): bool
    {
        if ($this->isAuthMiddleware($middleware) || $this->isAuthMiddlewareClass($middleware)) {
            return true;
        }

        return $this->extendsAuthenticateClass(str_contains($middleware, '\\')
            ? $middleware
            : ($this->resolveMiddlewareAliases()[explode(':', $middleware, 2)[0]] ?? ''));
    }

    /**
     * Whether a route's exclusions take out authentication in any form (see
     * self::isStrictAuthMiddleware()), an excluded group's members included.
     *
     * @param  list<string>  $removed
     * @param  array<string, true>  $expanded  The groups already read as their members
     */
    private function excludesAuth(array $removed, array $expanded = []): bool
    {
        foreach ($removed as $mw) {
            if ($this->isStrictAuthMiddleware($mw)) {
                return true;
            }

            // An excluded group takes out its members (MiddlewareNameResolver resolves it),
            // and one that cannot be read may take out auth
            $groups = $this->resolveMiddlewareGroups();
            if (isset($groups[$mw]) && ! isset($expanded[$mw])
                && (isset($this->unreadMiddlewareGroups[$mw]) || isset($this->unreadMiddlewareGroups['*'])
                    || $this->excludesAuth($groups[$mw], $expanded + [$mw => true]))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a middleware class is Authenticate or AuthenticateWithBasicAuth (see
     * {@see self::isAuthMiddlewareClass()}), or an App\ class that extends one, directly or
     * through other App\ classes, read from the file Laravel's convention places it in, none
     * of which declares handle(), authenticate() or unauthenticated().
     *
     * @param  array<string, true>  $seen  The classes already read, lowercase
     */
    private function extendsAuthenticateClass(string $class, array $seen = []): bool
    {
        if ($seen !== []) {
            return $this->readsExtendsAuthenticate($class, $seen);
        }

        return $this->extendsAuthenticateMemo[strtolower($class)] ??= $this->readsExtendsAuthenticate($class, []);
    }

    /**
     * Read what {@see self::extendsAuthenticateClass()} returns.
     *
     * @param  array<string, true>  $seen
     */
    private function readsExtendsAuthenticate(string $class, array $seen): bool
    {
        $class = ltrim(explode(':', $class, 2)[0], '\\');
        if ($class === '' || isset($seen[strtolower($class)])) {
            return false;
        }
        if ($this->isAuthMiddlewareClass($class)) {
            return true;
        }

        // A class that declares how it authenticates, such as an unauthenticated() that lets
        // guests through, may not authenticate; one read nowhere is not known to
        $declaration = $this->appClass($class);
        if ($declaration === null) {
            return false;
        }
        foreach ($declaration[0]->getMethods() as $method) {
            if (in_array($method->name->toLowerString(), ['handle', 'authenticate', 'unauthenticated'], true)) {
                return false;
            }
        }
        $parent = $declaration[0]->extends !== null ? $this->resolvedName($declaration[0]->extends) : null;

        return $parent !== null && $this->extendsAuthenticateClass($parent, $seen + [strtolower($class) => true]);
    }

    /**
     * Check if a middleware name represents authorization middleware.
     * Supports: can:ability, can:ability,model, role:admin, permission:delete-users
     */
    private function isAuthorizationMiddleware(string $middleware): bool
    {
        $middleware = trim($middleware);

        // Match can:, role:, permission:, ability:, etc.
        return (bool) preg_match('/^(can|role|permission|ability):/i', $middleware);
    }

    /**
     * Check if a line contains an auth null check.
     */
    private function hasAuthNullCheck(string $line): bool
    {
        // Look for actual auth checks: Auth::check(), auth()->check(), if (Auth::user()), if (auth()->user()), if ($request->user())
        // Also recognize nullsafe operators (?->) as safe
        return (bool) preg_match(
            '/(?:Auth::check\(\)|auth\(\)->check\(\)|if\s*\(\s*Auth::user\(\)|if\s*\(\s*auth\(\)->user\(\)|if\s*\(\s*\$request->user\(\)|Auth::user\(\)\?->|auth\(\)->user\(\)\?->|\$request->user\(\)\?->)/i',
            $line
        );
    }

    /**
     * Check if a route is a mutation route.
     */
    private function isMutationRoute(string $method): bool
    {
        return in_array($method, [
            'POST',
            'PUT',
            'PATCH',
            'DELETE',
            'RESOURCE',
            'APIRESOURCE',
        ], true);
    }

    /**
     * Get route files.
     *
     * @return array<string>
     */
    private function getRouteFiles(): array
    {
        $files = [];
        $routePath = $this->buildPath('routes');

        if (! is_dir($routePath)) {
            return $files;
        }

        try {
            foreach (new \DirectoryIterator($routePath) as $file) {
                if ($file->isFile() && $file->getExtension() === 'php') {
                    $files[] = $file->getPathname();
                }
            }
        } catch (\Throwable $e) {
            // Silently fail if directory iterator fails
        }

        return $files;
    }

    /**
     * Get controller files.
     *
     * @return array<string>
     */
    private function getControllerFiles(): array
    {
        $files = [];

        foreach ($this->getPhpFiles() as $file) {
            if (str_contains($file, '/Controllers/') || str_ends_with($file, 'Controller.php')) {
                $files[] = $file;
            }
        }

        return $files;
    }

    /**
     * Check if a custom middleware class is an auth middleware by introspecting its source code.
     *
     * Looks for auth signals: bearerToken(), getPassword(), AuthenticationException,
     * AuthenticatesRequests, Illuminate\Contracts\Auth\Factory.
     *
     * Expects a FQCN (resolved by NameResolver in the route visitor), read without the
     * parameters a middleware string may give it.
     */
    private function isCustomAuthMiddlewareClass(string $className): bool
    {
        $fqcn = ltrim(explode(':', $className, 2)[0], '\\');

        // Check cache
        if (isset($this->resolvedAuthMiddleware[$fqcn])) {
            return $this->resolvedAuthMiddleware[$fqcn];
        }

        // Convert FQCN to file path via PSR-4 convention (App\ -> app/)
        $relativePath = str_replace('\\', '/', $fqcn).'.php';
        if (str_starts_with($relativePath, 'App/')) {
            $relativePath = 'app'.substr($relativePath, 3);
        }

        $filePath = $this->buildPath($relativePath);
        $content = FileParser::readFile($filePath);

        if ($content === null) {
            $this->resolvedAuthMiddleware[$fqcn] = false;

            return false;
        }

        $isAuth = str_contains($content, 'bearerToken')
            || str_contains($content, 'getPassword')
            || str_contains($content, 'AuthenticationException')
            || str_contains($content, 'AuthenticatesRequests')
            || (bool) preg_match('/Illuminate\\\\Contracts\\\\Auth\\\\Factory|Auth\s+\$auth/', $content);

        $this->resolvedAuthMiddleware[$fqcn] = $isAuth;

        return $isAuth;
    }

    /**
     * Resolve the app's middleware alias => FQCN map, memoized.
     *
     * Combines aliases declared in bootstrap/app.php (Laravel 11+
     * `$middleware->alias([...])`) and app/Http/Kernel.php ($middlewareAliases /
     * legacy $routeMiddleware). Missing files simply contribute nothing, so an
     * unresolvable bare alias falls through unchanged.
     *
     * @return array<string, string>
     */
    private function resolveMiddlewareAliases(): array
    {
        if ($this->middlewareAliasMap !== null) {
            return $this->middlewareAliasMap;
        }

        return $this->middlewareAliasMap = array_merge(
            $this->extractKernelAliasMap($this->buildPath('app/Http/Kernel.php')),
            $this->extractBootstrapAliasMap($this->buildPath('bootstrap/app.php')),
        );
    }

    /**
     * Resolve the app's middleware group => members map, memoized: the Kernel's
     * $middlewareGroups, then what bootstrap/app.php's configurator calls make of them, as
     * Middleware::getMiddlewareGroups() applies them: group() sets a group,
     * removeFromGroup() takes members out of what group() set, and prependToGroup() and
     * appendToGroup() add members after any removal.
     *
     * @return array<string, list<string>>
     */
    private function resolveMiddlewareGroups(): array
    {
        if ($this->middlewareGroupMap !== null) {
            return $this->middlewareGroupMap;
        }

        $groups = $this->extractKernelGroupMap($this->buildPath('app/Http/Kernel.php'));

        $file = $this->buildPath('bootstrap/app.php');
        $ast = is_file($file) ? $this->parser->parseFile($file) : [];
        $removed = [];
        $added = [];
        $unread = [];
        foreach ($this->middlewareConfiguratorCalls($ast === [] ? [] : $this->resolveNamesForMatching($ast)) as $call) {
            $method = $call->name instanceof Node\Identifier ? $call->name->toLowerString() : '';
            $group = $this->callArgument($call, 0, 'group');
            $members = $this->callArgument($call, 1, 'middleware');

            // A replacement, or a removal that cannot be read, may take auth out: the group
            // it changes, or any group when that cannot be read, is not read at all
            if ($method === 'replaceingroup' || ($method === 'removefromgroup' && ($members === null || ! $this->middlewareNamesReadable($members)))) {
                $unread[$group instanceof Node\Scalar\String_ ? $group->value : '*'] = true;

                continue;
            }

            if (! in_array($method, ['group', 'removefromgroup', 'prependtogroup', 'appendtogroup'], true)
                || ! $group instanceof Node\Scalar\String_ || $members === null) {
                continue;
            }

            $names = $this->middlewareNames($members);
            match ($method) {
                'group' => $groups[$group->value] = $names,
                'removefromgroup' => $removed[$group->value] = [...$removed[$group->value] ?? [], ...$names],
                default => $added[$group->value] = [...$added[$group->value] ?? [], ...$names],
            };
        }

        foreach ($removed as $group => $names) {
            $groups[$group] = array_values(array_diff($groups[$group] ?? [], $names));
        }
        foreach ($added as $group => $names) {
            $groups[$group] = [...$groups[$group] ?? [], ...$names];
        }
        foreach (isset($unread['*']) ? $groups : $unread as $group => $_) {
            $groups[$group] = [];
        }
        $this->unreadMiddlewareGroups = $unread;

        return $this->middlewareGroupMap = $groups;
    }

    /**
     * The calls made on the Middleware configurator withMiddleware() hands its callback: the
     * calls in the callback whose chain starts at the callback's first parameter, so a
     * ->group(...) on another variable, such as a router in a withRouting() callback, is
     * left out.
     *
     * @param  array<Node>  $ast  bootstrap/app.php's tree
     * @return list<Node\Expr\MethodCall>
     */
    private function middlewareConfiguratorCalls(array $ast): array
    {
        $calls = [];
        foreach ($this->parser->findNodes($ast, Node\Expr\MethodCall::class) as $with) {
            if (! $with instanceof Node\Expr\MethodCall || ! $with->name instanceof Node\Identifier || $with->name->toLowerString() !== 'withmiddleware') {
                continue;
            }

            $callback = $this->callArgument($with, 0, 'callback');
            $param = $callback instanceof Node\Expr\Closure || $callback instanceof Node\Expr\ArrowFunction ? ($callback->params[0]->var ?? null) : null;
            if (! $param instanceof Node\Expr\Variable || ! is_string($param->name)) {
                continue;
            }

            $body = $callback instanceof Node\Expr\ArrowFunction ? [$callback->expr] : ($callback instanceof Node\Expr\Closure ? $callback->stmts : []);
            foreach ($this->configuratorCalls($this->parser, $body) as $call) {
                $root = $call->var;
                while ($root instanceof Node\Expr\MethodCall) {
                    $root = $root->var;
                }
                if ($root instanceof Node\Expr\Variable && $root->name === $param->name) {
                    $calls[] = $call;
                }
            }
        }

        return $calls;
    }

    /**
     * Extract the group map from app/Http/Kernel.php's $middlewareGroups property.
     *
     * @return array<string, list<string>>
     */
    private function extractKernelGroupMap(string $file): array
    {
        $ast = is_file($file) ? $this->parser->parseFile($file) : [];
        if ($ast === []) {
            return [];
        }

        $groups = [];
        foreach ($this->parser->findNodes($this->resolveNamesForMatching($ast), Node\Stmt\Property::class) as $property) {
            foreach ($property instanceof Node\Stmt\Property ? $property->props : [] as $prop) {
                if ($prop->name->toString() !== 'middlewareGroups' || ! $prop->default instanceof Node\Expr\Array_) {
                    continue;
                }

                foreach ($prop->default->items as $item) {
                    if ($item instanceof Node\Expr\ArrayItem && $item->key instanceof Node\Scalar\String_) {
                        $groups[$item->key->value] = $this->middlewareNames($item->value);
                    }
                }
            }
        }

        return $groups;
    }

    /**
     * Whether {@see self::middlewareNames()} reads every middleware a value names: a string,
     * a ::class constant, or a list of those.
     */
    private function middlewareNamesReadable(Node\Expr $value): bool
    {
        if ($value instanceof Node\Expr\Array_) {
            foreach ($value->items as $item) {
                if (! $item instanceof Node\Expr\ArrayItem || $item->unpack || ! $this->middlewareNamesReadable($item->value)) {
                    return false;
                }
            }

            return true;
        }

        return $value instanceof Node\Scalar\String_
            || ($value instanceof Node\Expr\ClassConstFetch && $value->class instanceof Node\Name);
    }

    /**
     * The middleware a value names, one or a list: each string as written and each ::class
     * constant as its resolved name. Any other entry names nothing.
     *
     * @return list<string>
     */
    private function middlewareNames(Node\Expr $value): array
    {
        if ($value instanceof Node\Expr\Array_) {
            $names = [];
            foreach ($value->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem) {
                    $names = [...$names, ...$this->middlewareNames($item->value)];
                }
            }

            return $names;
        }

        if ($value instanceof Node\Scalar\String_) {
            return [$value->value];
        }

        if ($value instanceof Node\Expr\ClassConstFetch && $value->class instanceof Node\Name
            && $value->name instanceof Node\Identifier && $value->name->toLowerString() === 'class') {
            return [$this->resolvedName($value->class)];
        }

        return [];
    }

    /**
     * Extract the alias map from bootstrap/app.php's `$middleware->alias([...])`
     * calls (Laravel 11+).
     *
     * @return array<string, string>
     */
    private function extractBootstrapAliasMap(string $file): array
    {
        if (! is_file($file)) {
            return [];
        }

        $ast = $this->parser->parseFile($file);
        if (empty($ast)) {
            return [];
        }

        // Resolve names so ::class values expose the `resolvedName` attribute
        // extractAliasMapFromArray() reads.
        $ast = $this->resolveNamesForMatching($ast);

        $map = [];

        foreach ($this->parser->findMethodCalls($ast, 'alias') as $call) {
            if (! ($call instanceof Node\Expr\MethodCall)) {
                continue;
            }

            // Middleware::alias() takes exactly one array argument; the shape
            // filter also rejects any unrelated ->alias(...) call.
            if (count($call->args) !== 1) {
                continue;
            }

            $arg = $call->args[0];
            if (! ($arg instanceof Node\Arg) || ! ($arg->value instanceof Node\Expr\Array_)) {
                continue;
            }

            $map = array_merge($map, $this->extractAliasMapFromArray($arg->value));
        }

        return $map;
    }

    /**
     * Extract the alias map from app/Http/Kernel.php's $middlewareAliases
     * (Laravel 10) or legacy $routeMiddleware (Laravel 8/9) property.
     *
     * @return array<string, string>
     */
    private function extractKernelAliasMap(string $file): array
    {
        if (! is_file($file)) {
            return [];
        }

        $ast = $this->parser->parseFile($file);
        if (empty($ast)) {
            return [];
        }

        $ast = $this->resolveNamesForMatching($ast);

        $map = [];

        foreach ($this->parser->findClasses($ast) as $class) {
            foreach ($class->stmts as $stmt) {
                if (! ($stmt instanceof Node\Stmt\Property)) {
                    continue;
                }

                $name = $stmt->props[0]->name->toString();
                if ($name !== 'middlewareAliases' && $name !== 'routeMiddleware') {
                    continue;
                }

                $default = $stmt->props[0]->default ?? null;
                if (! ($default instanceof Node\Expr\Array_)) {
                    continue;
                }

                $map = array_merge($map, $this->extractAliasMapFromArray($default));
            }
        }

        return $map;
    }

    /**
     * Turn an array literal of ['alias' => Class::class | 'Fqcn'] pairs into an
     * alias => FQCN map. Non-string keys and unrecognised values are skipped.
     *
     * @return array<string, string>
     */
    private function extractAliasMapFromArray(Node\Expr\Array_ $array): array
    {
        $map = [];

        foreach ($array->items as $item) {
            if (! ($item instanceof Node\Expr\ArrayItem)) {
                continue;
            }

            if (! ($item->key instanceof Node\Scalar\String_)) {
                continue;
            }

            $alias = $item->key->value;

            if ($item->value instanceof Node\Expr\ClassConstFetch) {
                // ::class value — read the FQCN from the NameResolver attribute
                // (populated by resolveNamesForMatching()).
                $classNode = $item->value->class;
                if (! ($classNode instanceof Node\Name)) {
                    continue;
                }
                $resolved = $classNode->getAttribute('resolvedName');
                $fqcn = $resolved instanceof Node\Name\FullyQualified
                    ? $resolved->toString()
                    : $classNode->toString();
            } elseif ($item->value instanceof Node\Scalar\String_) {
                $fqcn = ltrim($item->value->value, '\\');
            } else {
                continue;
            }

            if ($fqcn === '') {
                continue;
            }

            $map[$alias] = $fqcn;
        }

        return $map;
    }
}

/**
 * Visitor that traverses a route file AST and collects structured route and group records.
 *
 * Uses enterNode/leaveNode on group nodes to maintain a middleware stack, so that
 * inherited middleware from parent groups is automatically available when route calls
 * are processed in leaveNode(Stmt\Expression).
 *
 * NameResolver must run before this visitor so that ClassConstFetch nodes carry
 * fully-qualified class names in their 'resolvedName' attribute.
 *
 * @internal An implementation detail of authentication-authorization, outside this package's backward-compatibility promise.
 */
class RouteAuthVisitor extends NodeVisitorAbstract
{
    /**
     * Middleware stack — one entry per open group.
     * Each entry: ['add' => list<string>, 'remove' => list<string>], 'remove' holding what the
     * group excludes through ->withoutMiddleware() or an 'excluded_middleware' attribute.
     *
     * @var list<array{add: list<string>, remove: list<string>}>
     */
    private array $middlewareStack = [];

    /**
     * URI prefix stack — one entry per open group ('' when the group sets none).
     * Kept in lockstep with $middlewareStack.
     *
     * @var list<string>
     */
    private array $prefixStack = [];

    /**
     * Controller stack — one entry per open group, the controller class it names through
     * ->controller() or a 'controller' attribute, or null when it names none. Kept in lockstep
     * with $middlewareStack.
     *
     * @var list<string|null>
     */
    private array $controllerStack = [];

    /**
     * Per open group, kept in lockstep with $middlewareStack, whether it excludes middleware
     * this visitor cannot read (see {@see self::exclusionsReadable()}).
     *
     * @var list<bool>
     */
    private array $opaqueStack = [];

    /**
     * @var list<array{uri: string, match_uris: list<list<string>>, http_methods: list<string>, controller: string|null, action: string|null, is_closure: bool, middleware: list<string>, unregistered_middleware: list<string>, direct_remove: list<string>, removed: list<string>, opaque_removals: bool, line: int, every_url: bool}>
     */
    private array $collectedRoutes = [];

    /**
     * @var list<array{middleware: list<string>, effective_middleware: list<string>, unregistered_middleware: list<string>, removed: list<string>, opaque_removals: bool, line: int, end_line: int, has_guest: bool, is_static_group: bool}>
     */
    private array $collectedGroups = [];

    /** @var list<string> Supported route HTTP verb method names (lowercase) */
    public const ROUTE_VERBS = ['get', 'post', 'put', 'patch', 'delete', 'resource', 'apiresource'];

    /**
     * The statements of the file being traversed.
     *
     * @var array<Node>
     */
    private array $fileNodes = [];

    /**
     * The functions enclosing the node being visited, outermost first.
     *
     * @var list<Node\FunctionLike>
     */
    private array $functionStack = [];

    /**
     * Per function in $functionStack, the variables known there to hold the router (see
     * {@see self::functionRouters()}).
     *
     * @var list<array<string, true>>
     */
    private array $routerStack = [];

    /**
     * The closures and arrow functions route groups are given as their routes, by
     * spl_object_id(): Router::loadRoutes() calls each with the router.
     *
     * @var array<int, true>
     */
    private array $groupCallbacks = [];

    /**
     * Per function scope, by spl_object_id() of the function or 0 for the file's own, the
     * variables it reads (see {@see self::variableReads()}), read once per scope.
     *
     * @var array<int, array<string, list<array{Node\Expr\Variable, bool}>>|null>
     */
    private array $scopeReads = [];

    /**
     * @param  BootstrapRouteParser  $routeParser  The parser that has walked the route file's tree,
     *                                             which reads the chain of each group call
     * @param  array<int, true>  $routerGroups  The group calls the parser finds made on the router,
     *                                          by spl_object_id() (see BootstrapRouteParser::routerGroupCalls())
     * @param  non-empty-list<string>  $basePrefixes  File-level URI prefixes applied by the framework when
     *                                                registering the whole route file (e.g. 'api' for routes/api.php),
     *                                                one per registration of the file
     * @param  bool  $everyUrl  Whether the base prefixes are required, so each URL they give must be public for a route to be
     * @param  list<string>  $baseMiddleware  Middleware the framework applies when registering the whole route file,
     *                                        read as a group enclosing every route in it
     */
    public function __construct(
        private readonly BootstrapRouteParser $routeParser,
        private readonly array $routerGroups,
        private readonly array $basePrefixes = [''],
        private readonly bool $everyUrl = false,
        private readonly array $baseMiddleware = [],
    ) {
        if ($baseMiddleware !== []) {
            $this->middlewareStack[] = ['add' => $baseMiddleware, 'remove' => []];
        }
    }

    /**
     * @return list<array{uri: string, match_uris: list<list<string>>, http_methods: list<string>, controller: string|null, action: string|null, is_closure: bool, middleware: list<string>, unregistered_middleware: list<string>, direct_remove: list<string>, removed: list<string>, opaque_removals: bool, line: int, every_url: bool}>
     */
    public function getCollectedRoutes(): array
    {
        return $this->collectedRoutes;
    }

    /**
     * @return list<array{middleware: list<string>, effective_middleware: list<string>, unregistered_middleware: list<string>, removed: list<string>, opaque_removals: bool, line: int, end_line: int, has_guest: bool, is_static_group: bool}>
     */
    public function getCollectedGroups(): array
    {
        return $this->collectedGroups;
    }

    public function beforeTraverse(array $nodes): ?array
    {
        $this->fileNodes = $nodes;

        return null;
    }

    public function enterNode(Node $node): ?int
    {
        if ($node instanceof Node\FunctionLike) {
            $this->routerStack[] = $this->functionRouters($node);
            $this->functionStack[] = $node;
        }

        if ($this->isGroupNode($node)) {
            if ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) {
                foreach ($this->routeParser->closureArguments($node->args) as $callback) {
                    $this->groupCallbacks[spl_object_id($callback)] = true;
                }
            }

            $own = $this->extractGroupMiddleware($node);
            $this->middlewareStack[] = $own;
            $this->prefixStack[] = $this->extractGroupPrefix($node);
            $this->controllerStack[] = $this->extractGroupController($node);
            $this->opaqueStack[] = ! $this->exclusionsReadable($node);

            $this->collectedGroups[] = [
                'middleware' => $own['add'],
                'effective_middleware' => $this->computeStackMiddleware(),
                'unregistered_middleware' => $this->computeStackMiddleware(false),
                'removed' => $this->stackRemovals(),
                'opaque_removals' => in_array(true, $this->opaqueStack, true),
                'line' => $node->getStartLine(),
                'end_line' => $node->getEndLine(),
                'has_guest' => self::hasGuestMiddleware($own['add']),
                'is_static_group' => $node instanceof Node\Expr\StaticCall,
            ];
        }

        return null;
    }

    public function leaveNode(Node $node): ?int
    {
        if ($this->isGroupNode($node)) {
            array_pop($this->middlewareStack);
            array_pop($this->prefixStack);
            array_pop($this->controllerStack);
            array_pop($this->opaqueStack);
        }

        if ($node instanceof Node\FunctionLike) {
            // An arrow function group callback registers the route its body expression makes,
            // read while the callback's router parameter is in scope
            if ($node instanceof Node\Expr\ArrowFunction && isset($this->groupCallbacks[spl_object_id($node)])) {
                $this->processExpression($node->expr);
            }

            array_pop($this->routerStack);
            array_pop($this->functionStack);
        }

        // Process route calls at the Stmt\Expression boundary so we see the
        // complete method-call chain (including chained ->middleware() / ->withoutMiddleware())
        // in one pass, and the value a statement assigns to a variable.
        if ($node instanceof Node\Stmt\Expression) {
            if (! $node->expr instanceof Node\Expr\Assign) {
                $this->processExpression($node->expr);
            } elseif ($node->expr->var instanceof Node\Expr\Variable && is_string($node->expr->var->name)) {
                $this->processExpression($node->expr->expr, $node->expr->var->name);
            }
        }

        return null;
    }

    // -------------------------------------------------------------------------
    // Variable scopes
    // -------------------------------------------------------------------------

    /**
     * The variables known to hold the router inside a function: the first parameter of a
     * route group's callback, which Laravel calls with the router, when the callback reads
     * it only to call methods on it or to hand it to a closure by value, so it never holds
     * anything else.
     *
     * @return array<string, true>
     */
    private function functionRouters(Node\FunctionLike $function): array
    {
        $param = $function->getParams()[0] ?? null;
        if (! isset($this->groupCallbacks[spl_object_id($function)])
            || $param === null || ! $param->var instanceof Node\Expr\Variable || ! is_string($param->var->name)) {
            return [];
        }

        $reads = $this->scopeReads($function);
        if ($reads === null) {
            return [];
        }
        foreach ($reads[$param->var->name] ?? [] as [, $onlyCalled]) {
            if (! $onlyCalled) {
                return [];
            }
        }

        return [$param->var->name => true];
    }

    /**
     * The variables a function scope reads, the innermost enclosing function's or the
     * file's own when none is given (see {@see self::variableReads()}), read once per scope.
     *
     * @return array<string, list<array{Node\Expr\Variable, bool}>>|null
     */
    private function scopeReads(?Node\FunctionLike $function = null): ?array
    {
        $function ??= end($this->functionStack) ?: null;
        $key = $function !== null ? spl_object_id($function) : 0;
        if (! array_key_exists($key, $this->scopeReads)) {
            $this->scopeReads[$key] = $this->variableReads($function !== null ? $function->getStmts() ?? [] : $this->fileNodes);
        }

        return $this->scopeReads[$key];
    }

    /**
     * Each read or write of each variable in one function scope, by name, with whether it
     * only calls a method on the variable or hands it to a closure by value. A function,
     * class or closure body declared in the scope is a scope of its own; the variables a
     * closure imports are read in this one, and so is an arrow function's body, as it
     * captures the scope's variables by value, but for the names its own parameters shadow
     * there. Null when the scope may read or write variables it does not name: through a
     * require or include, eval(), a variable variable, extract(), parse_str(), compact() or
     * get_defined_vars().
     *
     * @param  array<Node>  $nodes
     * @return array<string, list<array{Node\Expr\Variable, bool}>>|null
     */
    private function variableReads(array $nodes): ?array
    {
        $reads = [];
        $receivers = [];
        // Each node with the names an enclosing arrow function's parameters shadow there
        $pending = array_map(fn (Node $node): array => [$node, []], $nodes);
        while ($pending !== []) {
            [$node, $shadowed] = array_pop($pending);
            if ($node instanceof Node\Expr\Include_ || $node instanceof Node\Expr\Eval_
                || ($node instanceof Node\Expr\Variable && ! is_string($node->name))
                || ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name
                    && in_array(ltrim($node->name->toLowerString(), '\\'), ['extract', 'parse_str', 'compact', 'get_defined_vars'], true))) {
                return null;
            }

            if ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\NullsafeMethodCall) {
                $receivers[spl_object_id($node->var)] = true;
            }
            if ($node instanceof Node\Expr\Variable && is_string($node->name) && ! isset($shadowed[$node->name])) {
                $reads[$node->name][] = [$node, isset($receivers[spl_object_id($node)])];
            }

            if ($node instanceof Node\Expr\Closure) {
                foreach ($node->uses as $use) {
                    if (is_string($use->var->name) && ! isset($shadowed[$use->var->name])) {
                        $reads[$use->var->name][] = [$use->var, ! $use->byRef];
                    }
                }

                continue;
            }
            if ($node instanceof Node\Stmt\Function_ || $node instanceof Node\Stmt\ClassLike) {
                continue;
            }

            if ($node instanceof Node\Expr\ArrowFunction) {
                foreach ($node->getParams() as $param) {
                    if ($param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                        $shadowed[$param->var->name] = true;
                    }
                }
            }

            foreach ($node->getSubNodeNames() as $subNode) {
                foreach (is_array($node->$subNode) ? $node->$subNode : [$node->$subNode] as $child) {
                    if ($child instanceof Node) {
                        $pending[] = [$child, $shadowed];
                    }
                }
            }
        }

        return $reads;
    }

    // -------------------------------------------------------------------------
    // Group detection
    // -------------------------------------------------------------------------

    /**
     * Detect Route::group([...], fn) StaticCalls and ->group(fn) MethodCalls.
     */
    private function isGroupNode(Node $node): bool
    {
        // Route::group([...], fn); PHP matches method names case-insensitively
        if ($node instanceof Node\Expr\StaticCall
            && $node->name instanceof Node\Identifier
            && $node->name->toLowerString() === 'group'
            && $node->class instanceof Node\Name
            && $this->isRouteFacade($node->class)) {
            return true;
        }

        // Route::middleware(...)->group(fn), Route::withoutMiddleware(...)->group(fn), a
        // ->group(fn) on a variable holding a registrar such a chain built, or a group the
        // route parser finds made on the router another way, such as $router->group(...)
        if ($node instanceof Node\Expr\MethodCall
            && $node->name instanceof Node\Identifier
            && $node->name->toLowerString() === 'group') {
            if (isset($this->routerGroups[spl_object_id($node)])) {
                return true;
            }
            $root = $this->routeParser->groupChain($node)[0];

            return $root instanceof Node\Expr\StaticCall
                && $root->class instanceof Node\Name
                && $this->isRouteFacade($root->class);
        }

        return false;
    }

    /**
     * Extract the middleware this group node adds/removes from its own definition.
     *
     * For a group given an attribute array, Route::group(['middleware' => 'auth'], fn) or
     *   $router->group([...], fn):
     *   → parses the config array's 'middleware' key, and its 'excluded_middleware' key
     *     into the removals.
     *
     * For MethodCall ->group() chains (e.g. Route::middleware('auth')->group(fn)):
     *   → walks the chain the route parser reads for the call (see
     *     BootstrapRouteParser::groupChain()) collecting the first argument of every
     *     ->withoutMiddleware() call, as RouteRegistrar merges them, and only the last
     *     ->middleware() call, as each middleware() call replaces the last (the first
     *     one found walking outward-in), including Route::middleware() /
     *     Route::withoutMiddleware() as the root.
     *
     * @return array{add: list<string>, remove: list<string>}
     */
    private function extractGroupMiddleware(Node $node): array
    {
        $add = [];
        $remove = [];

        if ($node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall) {
            // Route::group(['middleware' => ...], fn) or $router->group([...], fn): look at the first arg
            if (! empty($node->args)) {
                $firstArg = $node->args[0]->value ?? null;
                $firstArg = $firstArg !== null ? BootstrapRouteParser::heldValue($firstArg) : null;
                if ($firstArg instanceof Node\Expr\Array_) {
                    foreach ($firstArg->items as $item) {
                        if (! ($item instanceof Node\Expr\ArrayItem)) {
                            continue;
                        }
                        if (! ($item->key instanceof Node\Scalar\String_)
                            || $item->key->value !== 'middleware') {
                            continue;
                        }

                        $add = array_merge($add, $this->extractMiddlewareValue($item->value));
                    }
                }
            }
        }

        if ($node instanceof Node\Expr\MethodCall) {
            // Walk the chain outward-in: ->middleware, ..., StaticCall Route::X
            $applied = null;
            $can = null;
            foreach ($this->registrarCalls($node) as $current) {
                if ($current->name instanceof Node\Identifier) {
                    $name = $current->name->toLowerString();
                    if ($name === 'middleware') {
                        $applied ??= $this->extractMiddlewareArgs($current->args);
                    } elseif ($name === 'can') {
                        // RouteRegistrar's can attribute becomes can: middleware on each route
                        $can ??= $this->canMiddleware($current);
                    } elseif ($name === 'withoutmiddleware') {
                        // RouteRegistrar passes on only the first argument, a list or one middleware
                        $remove = array_merge($remove, $this->extractMiddlewareArgs(array_slice($current->args, 0, 1)));
                    }
                }
            }

            $add = [...$applied ?? [], ...$can !== null ? [$can] : [], ...$add];
        }

        return ['add' => $add, 'remove' => [...$remove, ...$this->extractGroupExcludedMiddleware($node)]];
    }

    /**
     * The middleware a group's attribute array excludes under 'excluded_middleware', read
     * from the first argument as {@see self::extractGroupMiddleware()} reads 'middleware'.
     *
     * @return list<string>
     */
    private function extractGroupExcludedMiddleware(Node $node): array
    {
        $firstArg = ($node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall) ? ($node->args[0]->value ?? null) : null;
        $firstArg = $firstArg !== null ? BootstrapRouteParser::heldValue($firstArg) : null;
        if (! ($firstArg instanceof Node\Expr\Array_)) {
            return [];
        }

        $excluded = [];
        foreach ($firstArg->items as $item) {
            if ($item instanceof Node\Expr\ArrayItem
                && $item->key instanceof Node\Scalar\String_
                && $item->key->value === 'excluded_middleware') {
                $excluded = array_merge($excluded, $this->extractMiddlewareValue($item->value));
            }
        }

        return $excluded;
    }

    /**
     * Extract the URI prefix this group node contributes, or '' if it sets none.
     *
     * For a group given an attribute array, Route::group(['prefix' => 'admin'], fn) or
     *   $router->group([...], fn):
     *   → parses the config array's 'prefix' key.
     *
     * For MethodCall ->group() chains (e.g. Route::prefix('admin')->group(fn)):
     *   → walks the chain the route parser reads for the call for ->prefix() calls
     *     (the first one found walking outward-in is the last one called, which wins
     *     per Laravel's overwrite semantics), down to a Route::prefix() static root.
     *
     * Non-literal prefix arguments yield '' (best-effort, like route URIs).
     */
    private function extractGroupPrefix(Node $node): string
    {
        if ($node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall) {
            // Route::group(['prefix' => ...], fn) or $router->group([...], fn): look at the first arg
            $firstArg = $node->args[0]->value ?? null;
            $firstArg = $firstArg !== null ? BootstrapRouteParser::heldValue($firstArg) : null;
            if ($firstArg instanceof Node\Expr\Array_) {
                foreach ($firstArg->items as $item) {
                    if (! ($item instanceof Node\Expr\ArrayItem)) {
                        continue;
                    }
                    if ($item->key instanceof Node\Scalar\String_
                        && $item->key->value === 'prefix'
                        && $item->value instanceof Node\Scalar\String_) {
                        return trim($item->value->value, '/');
                    }
                }
            }
        }

        if ($node instanceof Node\Expr\MethodCall) {
            // Walk the chain outward-in: ->prefix, ..., StaticCall Route::X
            foreach ($this->registrarCalls($node) as $current) {
                if ($current->name instanceof Node\Identifier
                    && $current->name->toLowerString() === 'prefix'
                    && ($arg = $current->args[0]->value ?? null) instanceof Node\Scalar\String_) {
                    return trim($arg->value, '/');
                }
            }
        }

        return '';
    }

    /**
     * The controller class this group node names, or null if it names none: the 'controller'
     * key of a group's attribute array, or the last ->controller() call of a ->group() chain
     * (the first one found walking outward-in), a ::class constant or a class name string.
     */
    private function extractGroupController(Node $node): ?string
    {
        if ($node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall) {
            $firstArg = $node->args[0]->value ?? null;
            $firstArg = $firstArg !== null ? BootstrapRouteParser::heldValue($firstArg) : null;
            if ($firstArg instanceof Node\Expr\Array_ && ($controller = $this->actionAttribute($firstArg, 'controller')) !== null) {
                return $this->controllerName($controller);
            }
        }

        if ($node instanceof Node\Expr\MethodCall) {
            foreach ($this->registrarCalls($node) as $current) {
                if ($current->name instanceof Node\Identifier && $current->name->toLowerString() === 'controller') {
                    $arg = $current->args[0] ?? null;

                    return $arg instanceof Node\Arg ? $this->controllerName($arg->value) : null;
                }
            }
        }

        return null;
    }

    /**
     * The class a ::class constant or class name string names, without a leading backslash.
     */
    private function controllerName(Node\Expr $value): ?string
    {
        if ($value instanceof Node\Expr\ClassConstFetch) {
            $class = $this->resolveClassFqcn($value->class);

            return $class !== null ? ltrim($class, '\\') : null;
        }

        return $value instanceof Node\Scalar\String_ && $value->value !== '' ? ltrim($value->value, '\\') : null;
    }

    /**
     * The value an attribute or action array gives under a string key, the last one when
     * the key repeats, as PHP keeps it.
     */
    private function actionAttribute(Node\Expr\Array_ $array, string $key): ?Node\Expr
    {
        $value = null;
        foreach ($array->items as $item) {
            if ($item instanceof Node\Expr\ArrayItem && $item->key instanceof Node\Scalar\String_ && $item->key->value === $key) {
                $value = $item->value;
            }
        }

        return $value;
    }

    /**
     * The calls before a ->group() call that set its registrar's attributes, outermost first,
     * as the route parser reads them (see BootstrapRouteParser::groupChain()).
     *
     * @return list<Node\Expr\MethodCall|Node\Expr\StaticCall>
     */
    private function registrarCalls(Node\Expr\MethodCall $group): array
    {
        return array_reverse(array_slice($this->routeParser->groupChain($group), 0, -1));
    }

    /**
     * The middleware a group call registering a whole route file applies to the file's routes,
     * read as {@see self::extractGroupMiddleware()} reads a group enclosing them. Null when it
     * cannot be read: a chain that does not start at the Route facade, a call setting an
     * attribute by a name it cannot read, an attribute array it cannot read, or an exclusion
     * it cannot read, which may take out any middleware.
     *
     * @return array{add: list<string>, remove: list<string>}|null
     *
     * @internal An implementation detail of authentication-authorization, outside this package's backward-compatibility promise.
     */
    public function registrationMiddleware(Node\Expr\MethodCall|Node\Expr\StaticCall $group): ?array
    {
        $chain = $group instanceof Node\Expr\MethodCall ? $this->routeParser->groupChain($group) : [$group];
        $root = $chain[0];
        // RouteRegistrar::group() takes the routes alone, so an attribute array before them is
        // read as the routes
        if (! $root instanceof Node\Expr\StaticCall || ! $root->class instanceof Node\Name || ! $this->isRouteFacade($root->class)
            || (count($chain) > 1 && count($group->args) > 1) || ! $this->exclusionsReadable($group)) {
            return null;
        }

        return $this->extractGroupMiddleware($group);
    }

    /**
     * Whether a group call's exclusions can be read: each ->withoutMiddleware() call of its
     * chain, as the route parser reads it (see BootstrapRouteParser::groupChain()), is given
     * middleware {@see self::middlewareReadable()} reads, no call sets an attribute by a name
     * it cannot read, and the attribute array of Router::group($attributes, $routes) is one,
     * whose 'excluded_middleware' it reads. Excluded middleware it cannot read may be auth.
     */
    private function exclusionsReadable(Node $group): bool
    {
        if (! $group instanceof Node\Expr\MethodCall && ! $group instanceof Node\Expr\StaticCall) {
            return true;
        }

        $chain = $group instanceof Node\Expr\MethodCall ? $this->routeParser->groupChain($group) : [$group];
        if (! $this->routeExclusionsReadable($chain, null)) {
            return false;
        }

        $attributes = count($group->args) > 1 ? $group->args[0] : null;
        if ($attributes === null) {
            return true;
        }
        $array = $attributes instanceof Node\Arg ? BootstrapRouteParser::heldValue($attributes->value) : null;
        if (! $array instanceof Node\Expr\Array_) {
            return false;
        }
        foreach ($array->items as $item) {
            if ($item instanceof Node\Expr\ArrayItem && $item->key instanceof Node\Scalar\String_
                && $item->key->value === 'excluded_middleware' && ! $this->middlewareReadable($item->value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether the exclusions of a chain of calls and of an action array's
     * 'excluded_middleware' value can be read (see {@see self::exclusionsReadable()}).
     *
     * @param  list<Node\Expr\MethodCall|Node\Expr\StaticCall>  $calls
     */
    private function routeExclusionsReadable(array $calls, ?Node\Expr $actionExcluded): bool
    {
        foreach ($calls as $call) {
            $name = $call->name instanceof Node\Identifier ? $call->name->toLowerString() : 'attribute';
            // attribute('excluded_middleware', ...) names no attribute RouteRegistrar allows
            if (in_array($name, ['attribute', 'excluded_middleware'], true)) {
                return false;
            }
            foreach ($name === 'withoutmiddleware' ? $call->args : [] as $arg) {
                if (! $arg instanceof Node\Arg || ! $this->middlewareReadable($arg->value)) {
                    return false;
                }
            }
        }

        return $actionExcluded === null || $this->middlewareReadable($actionExcluded);
    }

    /**
     * Read, for each route and group the middleware the file's registration applies reaches,
     * the middleware they would have without it when $withholds says so, given what they
     * exclude and whether they exclude middleware this visitor cannot read.
     *
     * @param  Closure(list<string>, bool): bool  $withholds
     *
     * @internal An implementation detail of authentication-authorization, outside this package's backward-compatibility promise.
     */
    public function withholdRegistration(Closure $withholds): void
    {
        if ($this->baseMiddleware === []) {
            return;
        }

        foreach ($this->collectedRoutes as $index => $route) {
            if ($withholds($route['removed'], $route['opaque_removals'])) {
                $this->collectedRoutes[$index]['middleware'] = $route['unregistered_middleware'];
            }
        }
        foreach ($this->collectedGroups as $index => $group) {
            if ($withholds($group['removed'], $group['opaque_removals'])) {
                $this->collectedGroups[$index]['effective_middleware'] = $group['unregistered_middleware'];
            }
        }
    }

    /**
     * Whether {@see self::extractMiddlewareValue()} reads every middleware a value names.
     */
    private function middlewareReadable(Node\Expr $value): bool
    {
        if ($value instanceof Node\Expr\Variable) {
            $held = BootstrapRouteParser::heldValue($value);

            return $held !== $value && $this->middlewareReadable($held);
        }

        if ($value instanceof Node\Expr\Array_) {
            foreach ($value->items as $item) {
                if (! $item instanceof Node\Expr\ArrayItem || $item->unpack || ! $this->middlewareReadable($item->value)) {
                    return false;
                }
            }

            return true;
        }

        return $value instanceof Node\Scalar\String_
            || ($value instanceof Node\Expr\ClassConstFetch && $value->class instanceof Node\Name)
            || ($value instanceof Node\Expr\BinaryOp\Concat && $value->left instanceof Node\Expr\ClassConstFetch && $value->left->class instanceof Node\Name
                && $value->right instanceof Node\Scalar\String_ && str_starts_with($value->right->value, ':'))
            || ($value instanceof Node\Expr\StaticCall && $value->class instanceof Node\Name
                && $value->name instanceof Node\Identifier && $value->name->toLowerString() === 'using');
    }

    // -------------------------------------------------------------------------
    // Route expression processing
    // -------------------------------------------------------------------------

    /**
     * If the expression (top of a Stmt\Expression, or the value it assigns) registers a route,
     * collect it.
     *
     * Walks the MethodCall chain from the outermost node down to the route verb call,
     * collecting ->middleware() / ->withoutMiddleware() / ->prefix() on the route along the
     * way. The verb is called on the Route facade, or on a registrar (see
     * {@see self::registrarRouteCalls()}), whose attributes the route takes.
     *
     * A route assigned to variable $assignedTo is collected only when the scope reads the
     * variable nowhere else, as a later $route->middleware(...) would change it.
     */
    private function processExpression(Node\Expr $expr, ?string $assignedTo = null): void
    {
        // Collect the chain, outermost first, down to the call that registers the route
        $chain = [];
        $current = $expr;
        while ($current instanceof Node\Expr\MethodCall && ! $this->isRouteVerbCall($current)) {
            $chain[] = $current;
            $current = $current->var;
        }

        if ($current instanceof Node\Expr\StaticCall) {
            // Route::post(...), on the Route facade
            if (! ($current->class instanceof Node\Name) || ! $this->isRouteFacade($current->class) || ! $this->isRouteVerbCall($current)) {
                return;
            }
            $registrar = [];
        } elseif ($current instanceof Node\Expr\MethodCall) {
            $registrar = $this->registrarRouteCalls($current);
            if ($registrar === null) {
                return;
            }
        } else {
            return;
        }

        if (! $current->name instanceof Node\Identifier
            || ($assignedTo !== null && count($this->scopeReads()[$assignedTo] ?? []) !== 1)) {
            return;
        }

        $httpMethod = strtoupper($current->name->toString());

        // Extract URI and handler from the verb call's args
        $ownUri = $this->extractUri($current);
        [$controller, $action, $isClosure] = $this->extractHandler($current);

        // The registrar's attributes: its last middleware() and prefix() calls, as each
        // replaces the last (RouteRegistrar::attribute()), and every withoutMiddleware()
        // call, as RouteRegistrar merges them
        $registrarAdd = [];
        $registrarCan = [];
        $directRemove = [];
        $registrarPrefix = null;
        foreach ($registrar as $call) {
            $name = $call->name instanceof Node\Identifier ? $call->name->toLowerString() : '';
            if ($name === 'middleware') {
                $registrarAdd = $this->extractMiddlewareArgs($call->args);
            } elseif ($name === 'can') {
                $registrarCan = [$this->canMiddleware($call)];
            } elseif ($name === 'withoutmiddleware') {
                $directRemove = array_merge($directRemove, $this->extractMiddlewareArgs($call->args));
            } elseif ($name === 'prefix') {
                $arg = $call->args[0] ?? null;
                $registrarPrefix = $arg instanceof Node\Arg && $arg->value instanceof Node\Scalar\String_ ? trim($arg->value->value, '/') : null;
            }
        }

        // Collect direct middleware and ->prefix() calls from the outer chain.
        // The chain is outermost-first, which for prefixes is framework-true
        // left-to-right order: each later ->prefix() call prepends to the URI.
        $directAdd = [];
        $directPrefixes = [];
        foreach ($chain as $methodCall) {
            if (! ($methodCall->name instanceof Node\Identifier)) {
                continue;
            }
            $name = $methodCall->name->toLowerString();
            if ($name === 'middleware') {
                $directAdd = array_merge($directAdd, $this->extractMiddlewareArgs($methodCall->args));
            } elseif ($name === 'can') {
                // Route::can() adds can: middleware
                $directAdd[] = $this->canMiddleware($methodCall);
            } elseif ($name === 'withoutmiddleware') {
                $directRemove = array_merge($directRemove, $this->extractMiddlewareArgs($methodCall->args));
            } elseif ($name === 'prefix'
                && ($arg = $methodCall->args[0]->value ?? null) instanceof Node\Scalar\String_) {
                $directPrefixes[] = trim($arg->value, '/');
            }
        }

        // The Route constructor applies the registrar's prefix before any ->prefix() call on the route
        if ($registrarPrefix !== null && $registrarPrefix !== '') {
            $directPrefixes[] = $registrarPrefix;
        }

        // The middleware an action array names takes the place of the registrar's, as
        // RouteRegistrar::compileAction() merges the action over its attributes, and the
        // groups' middleware adds to it (Router::mergeWithLastGroup())
        $actionArray = $this->actionArray($current);
        $actionMiddleware = $actionArray !== null ? $this->actionAttribute($actionArray, 'middleware') : null;
        if ($actionMiddleware !== null) {
            $registrarAdd = $this->extractMiddlewareValue($actionMiddleware);
        }

        // The middleware an action array excludes, which Router::resolveMiddleware() drops
        // from every middleware the route gathers, read as a group's exclusions are: it takes
        // auth away without opting the route out as public
        $actionExcluded = $actionArray !== null ? $this->actionAttribute($actionArray, 'excluded_middleware') : null;
        $actionRemove = $actionExcluded !== null ? $this->extractMiddlewareValue($actionExcluded) : [];

        [$uri, $matchUris] = $this->composeRouteUris($ownUri, $directPrefixes);

        // Compute effective middleware: inherited from stack → apply direct. Every exclusion,
        // the groups' and the route's own, drops the route's own middleware too
        // (Router::resolveMiddleware())
        $removed = array_values(array_unique([...$this->stackRemovals(), ...$directRemove, ...$actionRemove]));
        $own = [...$registrarAdd, ...$registrarCan, ...$directAdd];
        $effective = array_diff(array_unique([...$this->computeStackMiddleware(), ...$own]), $removed);

        $this->collectedRoutes[] = [
            'uri' => $uri,
            'match_uris' => $matchUris,
            'http_methods' => [$httpMethod],
            'controller' => $controller,
            'action' => $action,
            'is_closure' => $isClosure,
            'middleware' => array_values($effective),
            'unregistered_middleware' => array_values(array_diff(array_unique([...$this->computeStackMiddleware(false), ...$own]), $removed)),
            'direct_remove' => $directRemove,
            'removed' => $removed,
            'opaque_removals' => in_array(true, $this->opaqueStack, true) || ! $this->routeExclusionsReadable([...$registrar, ...$chain], $actionExcluded),
            'line' => $current->getStartLine(),
            'every_url' => $this->everyUrl,
        ];
    }

    /**
     * Whether a call is named for a route verb this visitor reads (see {@see self::ROUTE_VERBS}).
     */
    private function isRouteVerbCall(Node\Expr\MethodCall|Node\Expr\StaticCall $call): bool
    {
        return $call->name instanceof Node\Identifier && in_array($call->name->toLowerString(), self::ROUTE_VERBS, true);
    }

    /**
     * The calls that set the attributes of the registrar a route verb is called on, root
     * first, as the route parser reads the chain (see BootstrapRouteParser::groupChain()),
     * following a variable that holds a registrar to the calls that built it. Null when the
     * receiver is not known to be the router or a registrar it hands back: the chain must
     * start at the Route facade, or at a variable that holds the router where it is read (see
     * {@see self::functionRouters()}), and set only registrar attributes on the way.
     *
     * @return list<Node\Expr\MethodCall|Node\Expr\StaticCall>|null
     */
    private function registrarRouteCalls(Node\Expr\MethodCall $verb): ?array
    {
        $chain = $this->routeParser->groupChain($verb);
        $registrar = array_slice($chain, 0, -1);
        foreach ($registrar as $call) {
            if (! $call->name instanceof Node\Identifier || in_array($call->name->toLowerString(), [...self::ROUTE_VERBS, 'group'], true)) {
                return null;
            }
        }

        $root = $chain[0];
        if ($root instanceof Node\Expr\StaticCall) {
            return $root->class instanceof Node\Name && $this->isRouteFacade($root->class) ? $registrar : null;
        }

        $routers = end($this->routerStack);

        return $root->var instanceof Node\Expr\Variable && is_string($root->var->name) && isset(($routers ?: [])[$root->var->name])
            ? $registrar
            : null;
    }

    // -------------------------------------------------------------------------
    // Handler / URI extraction
    // -------------------------------------------------------------------------

    /**
     * Extract the URI string from a route verb call's first argument.
     */
    private function extractUri(Node\Expr\MethodCall|Node\Expr\StaticCall $call): string
    {
        if (empty($call->args)) {
            return '';
        }

        $firstArg = $call->args[0]->value ?? null;
        if ($firstArg instanceof Node\Scalar\String_) {
            return $firstArg->value;
        }

        return '';
    }

    /**
     * Compose the route's real URI and its public-route matching candidates from
     * the file-level base prefixes, enclosing group prefixes, direct ->prefix()
     * calls, and the route's own declared segment.
     *
     * One candidate list per file-level base prefix, as the route is served at one URL
     * per registration of its file. Candidates are [full real path, AST-visible
     * composition, own segment]: patterns written against partial paths keep working.
     *
     * @param  list<string>  $directPrefixes
     * @return array{string, list<list<string>>} [full URI of the first registration, match candidates per URL]
     */
    private function composeRouteUris(string $ownUri, array $directPrefixes): array
    {
        if ($ownUri === '') {
            // Unresolvable route URI — don't fabricate a path from prefixes alone.
            return ['', [['']]];
        }

        $groupSegments = array_values(array_filter($this->prefixStack, static fn (string $p): bool => $p !== ''));

        $visible = $directPrefixes === [] && $groupSegments === []
            ? $ownUri
            : $this->joinUriSegments(array_merge($directPrefixes, $groupSegments, [$ownUri]));

        // Direct ->prefix() calls prepend in front of the already-prefixed URI,
        // so the framework-true order is direct/base/groups/own.
        $full = fn (string $basePrefix): string => $basePrefix === ''
            ? $visible
            : $this->joinUriSegments(array_merge($directPrefixes, [$basePrefix], $groupSegments, [$ownUri]));

        return [
            $full($this->basePrefixes[0]),
            array_map(fn (string $basePrefix): array => array_values(array_unique([$full($basePrefix), $visible, $ownUri])), $this->basePrefixes),
        ];
    }

    /**
     * Join URI segments with '/', trimming slashes and dropping empty segments,
     * so a '/' root route composes to just its prefixes (matching Laravel's
     * RouteGroup::formatPrefix behaviour).
     *
     * @param  list<string>  $segments
     */
    private function joinUriSegments(array $segments): string
    {
        $parts = [];
        foreach ($segments as $segment) {
            $trimmed = trim($segment, '/');
            if ($trimmed !== '') {
                $parts[] = $trimmed;
            }
        }

        return implode('/', $parts);
    }

    /**
     * Extract controller FQCN, action, and closure flag from the route handler argument.
     *
     * Supports:
     *   [Controller::class, 'method']  — array tuple
     *   Controller::class              — invokable (action = '__invoke')
     *   'Controller@method'            — legacy string, or Controller::class.'@method'
     *   'method'                       — a method of the controller the enclosing groups name
     *   Closure / ArrowFunction        — closure route
     *   ['uses' => ..., ...]           — an action array, read as the controller its 'uses'
     *                                    key gives
     *
     * @return array{0: string|null, 1: string|null, 2: bool} [controller, action, isClosure]
     */
    private function extractHandler(Node\Expr\MethodCall|Node\Expr\StaticCall $call): array
    {
        if (count($call->args) < 2) {
            return [null, null, false];
        }

        $handlerArg = $call->args[1]->value ?? null;

        // An action array's 'uses' handler; one whose handler is a closure, under 'uses' or
        // listed without a key, has no controller and keeps the route message of any other
        // array action, as the message is baseline-hashed
        $action = $this->actionArray($call);
        if ($action !== null) {
            $handlerArg = $this->actionAttribute($action, 'uses');
            if ($handlerArg instanceof Node\Expr\Closure || $handlerArg instanceof Node\Expr\ArrowFunction) {
                return [null, null, false];
            }
        }

        // Closure or ArrowFunction
        if ($handlerArg instanceof Node\Expr\Closure
            || $handlerArg instanceof Node\Expr\ArrowFunction) {
            return [null, null, true];
        }

        // [Controller::class, 'method']
        if ($handlerArg instanceof Node\Expr\Array_
            && count($handlerArg->items) >= 2) {
            $classItem = $handlerArg->items[0];
            $methodItem = $handlerArg->items[1];
            if ($classItem instanceof Node\Expr\ArrayItem
                && $methodItem instanceof Node\Expr\ArrayItem
                && $classItem->value instanceof Node\Expr\ClassConstFetch
                && $methodItem->value instanceof Node\Scalar\String_) {
                $controller = $this->resolveClassFqcn($classItem->value->class);

                return [$controller, $methodItem->value->value, false];
            }
        }

        // Controller::class (invokable)
        if ($handlerArg instanceof Node\Expr\ClassConstFetch) {
            $controller = $this->resolveClassFqcn($handlerArg->class);

            return [$controller, '__invoke', false];
        }

        // Controller::class.'@method'
        if ($handlerArg instanceof Node\Expr\BinaryOp\Concat
            && $handlerArg->left instanceof Node\Expr\ClassConstFetch
            && $handlerArg->right instanceof Node\Scalar\String_
            && str_starts_with($handlerArg->right->value, '@')) {
            return [$this->resolveClassFqcn($handlerArg->left->class), substr($handlerArg->right->value, 1), false];
        }

        // 'Controller@method' or 'Controller' (legacy string)
        if ($handlerArg instanceof Node\Scalar\String_) {
            $value = $handlerArg->value;
            if (str_contains($value, '@')) {
                [$class, $method] = explode('@', $value, 2);

                return [$class, $method, false];
            }

            // A bare method of the controller the enclosing groups name, which
            // Router::prependGroupController() puts before it; a class name stays one, and
            // so does a resource's controller, which ResourceRegistrar registers itself
            $groupController = $this->groupController();
            if ($groupController !== null && ! str_contains($value, '\\')
                && $call->name instanceof Node\Identifier && ! in_array($call->name->toLowerString(), ['resource', 'apiresource'], true)) {
                return [$groupController, $value, false];
            }

            return [$value, '__invoke', false];
        }

        return [null, null, false];
    }

    /**
     * The action array a route verb call is given in place of a handler: an array, or a
     * variable holding one, with a string key, such as 'uses' or 'middleware'.
     */
    private function actionArray(Node\Expr\MethodCall|Node\Expr\StaticCall $call): ?Node\Expr\Array_
    {
        $value = $call->args[1]->value ?? null;
        $value = $value instanceof Node\Expr ? BootstrapRouteParser::heldValue($value) : null;
        if (! $value instanceof Node\Expr\Array_) {
            return null;
        }

        foreach ($value->items as $item) {
            if ($item instanceof Node\Expr\ArrayItem && $item->key instanceof Node\Scalar\String_) {
                return $value;
            }
        }

        return null;
    }

    /**
     * The controller the innermost enclosing group naming one names (RouteGroup::merge()
     * keeps an inner group's controller over an outer one's).
     */
    private function groupController(): ?string
    {
        foreach (array_reverse($this->controllerStack) as $controller) {
            if ($controller !== null) {
                return $controller;
            }
        }

        return null;
    }

    /**
     * Resolve a class Name node to a FQCN string using NameResolver's 'resolvedName' attribute.
     */
    private function resolveClassFqcn(Node\Name|Node\Expr $nameNode): ?string
    {
        if (! ($nameNode instanceof Node\Name)) {
            return null;
        }

        $resolvedName = $nameNode->getAttribute('resolvedName');
        if ($resolvedName instanceof Node\Name\FullyQualified) {
            return $resolvedName->toString();
        }

        return $nameNode->toString();
    }

    // -------------------------------------------------------------------------
    // Middleware extraction helpers
    // -------------------------------------------------------------------------

    /**
     * Extract middleware strings from a ->middleware() or ->withoutMiddleware() arg list.
     *
     * Handles:
     *   ->middleware('auth')
     *   ->middleware(['auth', 'verified'])
     *   ->middleware(SomeClass::class)
     *
     * @param  array<Node>  $args  Raw argument list; only plain Args carry a value.
     * @return list<string>
     */
    private function extractMiddlewareArgs(array $args): array
    {
        $middleware = [];

        foreach ($args as $arg) {
            if (! ($arg instanceof Node\Arg)) {
                continue;
            }

            $middleware = array_merge($middleware, $this->extractMiddlewareValue($arg->value));
        }

        return $middleware;
    }

    /**
     * Extract middleware strings from a value node (String_, Array_, or ClassConstFetch), or a
     * variable holding one.
     *
     * @return list<string>
     */
    private function extractMiddlewareValue(Node\Expr $value): array
    {
        // A variable read as the value the route parser's walk knows it holds here
        if ($value instanceof Node\Expr\Variable && ($held = BootstrapRouteParser::heldValue($value)) !== $value) {
            return $this->extractMiddlewareValue($held);
        }

        // Single string: 'auth'
        if ($value instanceof Node\Scalar\String_) {
            return [$value->value];
        }

        // Array: ['auth', 'verified']  or  [SomeClass::class, 'throttle:60']
        if ($value instanceof Node\Expr\Array_) {
            $result = [];
            foreach ($value->items as $item) {
                if (! ($item instanceof Node\Expr\ArrayItem)) {
                    continue;
                }
                $result = array_merge($result, $this->extractMiddlewareValue($item->value));
            }

            return $result;
        }

        // ClassConstFetch: SomeClass::class
        if ($value instanceof Node\Expr\ClassConstFetch) {
            $fqcn = $this->resolveClassFqcn($value->class);
            if ($fqcn !== null) {
                return [$fqcn];
            }
        }

        // SomeClass::class.':guard', the class with its parameters
        if ($value instanceof Node\Expr\BinaryOp\Concat
            && $value->left instanceof Node\Expr\ClassConstFetch
            && $value->right instanceof Node\Scalar\String_
            && str_starts_with($value->right->value, ':')) {
            $fqcn = $this->resolveClassFqcn($value->left->class);

            return $fqcn !== null ? [$fqcn.$value->right->value] : [];
        }

        // SomeClass::using('guard'), which middleware such as Authenticate and
        // ThrottleRequests define to give the class name with its parameters
        if ($value instanceof Node\Expr\StaticCall
            && $value->name instanceof Node\Identifier
            && $value->name->toLowerString() === 'using'
            && ($fqcn = $this->resolveClassFqcn($value->class)) !== null) {
            $parameters = [];
            foreach ($value->args as $arg) {
                if ($arg instanceof Node\Arg && $arg->value instanceof Node\Scalar\String_) {
                    $parameters[] = $arg->value->value;
                }
            }

            return [$fqcn.':'.implode(',', $parameters)];
        }

        return [];
    }

    /**
     * Whether a middleware list carries the guest middleware, the 'guest' alias with or
     * without a guard.
     *
     * @param  list<string>  $middleware
     *
     * @internal An implementation detail of authentication-authorization, outside this package's backward-compatibility promise.
     */
    public static function hasGuestMiddleware(array $middleware): bool
    {
        foreach ($middleware as $mw) {
            if ($mw === 'guest' || str_starts_with($mw, 'guest:')) {
                return true;
            }
        }

        return false;
    }

    /**
     * The can: middleware a can() call adds, as Route::can() and RouteRegistrar's can
     * attribute do: its literal string arguments joined, or can:* when they cannot be read,
     * as any can: middleware is read as authorization.
     */
    private function canMiddleware(Node\Expr\MethodCall|Node\Expr\StaticCall $call): string
    {
        $abilities = [];
        foreach ($call->args as $arg) {
            if (! $arg instanceof Node\Arg || ! $arg->value instanceof Node\Scalar\String_) {
                return 'can:*';
            }
            $abilities[] = $arg->value->value;
        }

        return $abilities === [] ? 'can:*' : 'can:'.implode(',', $abilities);
    }

    // -------------------------------------------------------------------------
    // Stack helpers
    // -------------------------------------------------------------------------

    /**
     * Compute the effective middleware set from the current stack (without any direct overrides).
     *
     * Every layer's removals apply to every layer's additions, outer or inner: a route's
     * excluded middleware accumulates across its groups (RouteGroup::merge()), and
     * Router::resolveMiddleware() drops it from all the middleware the route gathers.
     *
     * @param  bool  $registered  Whether to include the middleware the file's registration applies
     * @return list<string>
     */
    private function computeStackMiddleware(bool $registered = true): array
    {
        $removed = $this->stackRemovals();
        $middleware = [];

        $layers = $registered || $this->baseMiddleware === [] ? $this->middlewareStack : array_slice($this->middlewareStack, 1);
        foreach ($layers as $layer) {
            foreach ($layer['add'] as $mw) {
                if (! in_array($mw, $removed, true)) {
                    $middleware[] = $mw;
                }
            }
        }

        return array_values(array_unique($middleware));
    }

    /**
     * The middleware the open groups exclude, outermost first.
     *
     * @return list<string>
     */
    private function stackRemovals(): array
    {
        return array_merge(...array_column($this->middlewareStack, 'remove'));
    }

    // -------------------------------------------------------------------------
    // Route facade detection
    // -------------------------------------------------------------------------

    /**
     * Check whether a Name node refers to the Route facade.
     *
     * Handles both the short alias (Route) and the full class name
     * (Illuminate\Support\Facades\Route) after NameResolver processing.
     */
    private function isRouteFacade(Node\Name $name): bool
    {
        $resolvedName = $name->getAttribute('resolvedName');
        $className = $resolvedName instanceof Node\Name\FullyQualified
            ? $resolvedName->toString()
            : $name->toString();
        $className = ltrim($className, '\\');

        return $className === 'Illuminate\\Support\\Facades\\Route'
            || $className === 'Route';
    }
}
