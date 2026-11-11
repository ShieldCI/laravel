<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use PhpParser\NodeTraverser;
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
     * File-level URI prefixes the framework applies when registering whole route
     * files (e.g. 'api' for routes/api.php), keyed by route file basename.
     *
     * @var array<string, string>
     */
    private array $routeFileBasePrefixes = [];

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

        // Resolve file-level prefixes the framework applies outside the route files
        $this->routeFileBasePrefixes = $this->resolveRouteFileBasePrefixes();
        $this->routeVisitors = [];

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
     * Determine whether a collected route is public via any of its URI candidates
     * (full composed path, AST-visible composition, own declared segment).
     *
     * @param  array{uri: string, match_uris: list<string>, http_methods: list<string>, controller: string|null, action: string|null, is_closure: bool, middleware: list<string>, direct_remove: list<string>, removed: list<string>, line: int}  $route
     */
    private function isRoutePublic(array $route): bool
    {
        foreach ($route['match_uris'] as $uri) {
            if ($this->isPublicRoute($uri)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Resolve file-level URI prefixes the framework applies when registering
     * whole route files, keyed by route file basename.
     *
     * Best-effort, literal-only discovery:
     * - bootstrap/app.php (Laravel 11+): withRouting(api: ..., apiPrefix: ...),
     *   and registrar chains inside its then: callback, read as below
     * - app/Providers/RouteServiceProvider.php (Laravel 9/10): registrar chains
     *   ending ->group(base_path('routes/X.php')) or a list of such files,
     *   including custom route files
     * - convention fallback: routes/api.php → 'api'
     * - then, for a file none of the above maps, the registrations the route parser
     *   follows (see {@see self::extractFollowedRoutePrefixes()})
     *
     * A wrong or missing guess is harmless: routes are matched against all
     * their URI candidates, including the AST-visible composition.
     *
     * @return array<string, string>
     */
    private function resolveRouteFileBasePrefixes(): array
    {
        $bootstrap = $this->buildPath('bootstrap/app.php');
        $map = $this->extractBootstrapRoutePrefixes($bootstrap);

        $registered = $this->extractBootstrapThenRoutePrefixes($bootstrap)
            + $this->extractProviderRoutePrefixes($this->buildPath('app/Providers/RouteServiceProvider.php'));

        foreach ($registered as $basename => $prefix) {
            $map[$basename] ??= $prefix;
        }

        $map['api.php'] ??= 'api';

        // Fills only the files the literal reading leaves unmapped, so a public_routes
        // pattern written for the prefix that reading gives a file keeps matching
        return $map + $this->extractFollowedRoutePrefixes();
    }

    /**
     * Extract the api route file and its prefix from bootstrap/app.php's
     * withRouting(...) call (Laravel 11+). An api file registered without an
     * explicit apiPrefix gets the framework default 'api'.
     *
     * @return array<string, string>
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
                return [$apiFile => $apiPrefix ?? 'api'];
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
     * @return array<string, string>
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
     * @return array<string, string>
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
     * lifting prefix('...') from the same chain onto every file.
     *
     * @param  array<Node>  $nodes
     * @return array<string, string>
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
                if ($basename !== null) {
                    $map[$basename] = $prefix;
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
                && $current->name->toString() === 'prefix'
                && ($arg = $current->args[0]->value ?? null) instanceof Node\Scalar\String_) {
                return trim($arg->value, '/');
            }
            $current = $current->var;
        }

        if ($current instanceof Node\Expr\StaticCall
            && $current->name instanceof Node\Identifier
            && $current->name->toString() === 'prefix'
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
     * Laravel composes them (see {@see self::composeGroupPrefixes()}).
     *
     * Only registrations Laravel runs count: in bootstrap/app.php, those inside the routing
     * callback withRouting() runs (see {@see self::withRoutingCallback()}); under
     * app/Providers/, those in a service provider's boot(), register() or map(), or a method
     * of the same class they call (see {@see self::providerRegistrationCalls()}). The api:
     * files withRouting() registers under apiPrefix are added (see
     * {@see self::extractFollowedApiPrefixes()}).
     *
     * The map is keyed by basename, so only a file directly under routes/ is recorded: a
     * nested routes/partners/web.php would otherwise lend its prefix to routes/web.php.
     *
     * Precedence follows {@see self::resolveRouteFileBasePrefixes()}: api: files, then the
     * routing callback, then the providers. Within one file the later registration wins;
     * providers giving one file different prefixes give it none, as the order Laravel
     * registers providers in is not read.
     *
     * @return array<string, string>
     */
    private function extractFollowedRoutePrefixes(): array
    {
        $routesDir = realpath($this->buildPath('routes'));
        if ($routesDir === false) {
            return [];
        }
        $routesDir = str_replace('\\', '/', $routesDir);

        $routeParser = new BootstrapRouteParser($this->getBasePath(), $this->parser);
        // The walk annotates the parser's cached trees, so it runs before bootstrap/app.php is read
        $loads = $routeParser->getExternalRouteFileLoads();

        $bootstrap = $this->getBasePath().'/bootstrap/app.php';
        $ast = is_file($bootstrap) ? $this->parser->parseFile($bootstrap) : [];

        $api = [];
        $registrationCalls = [$bootstrap => []];
        foreach ($this->parser->findMethodCalls($ast, 'withRouting') as $call) {
            if (! ($call instanceof Node\Expr\MethodCall)) {
                continue;
            }

            $api += $this->extractFollowedApiPrefixes($call);

            $callback = $this->withRoutingCallback($call);
            if ($callback !== null) {
                $registrationCalls[$bootstrap] += $this->callIds([$callback]);
            }
        }

        $then = [];
        $bySource = [];
        foreach ($loads as $load) {
            $calls = $load['calls'];
            if ($calls === [] || $this->normalizedDirname($load['file']) !== $routesDir) {
                continue;
            }

            $source = $load['source'];
            $registrationCalls[$source] ??= $this->providerRegistrationCalls($source);
            if (! isset($registrationCalls[$source][spl_object_id($calls[0])])) {
                continue;
            }

            $prefix = $this->composeGroupPrefixes($routeParser, $calls, '');
            if ($prefix === null || $prefix === '') {
                continue;
            }

            if ($source === $bootstrap) {
                $then[basename($load['file'])] = $prefix;
            } else {
                $bySource[$source][basename($load['file'])] = $prefix;
            }
        }

        $providers = [];
        $conflicts = [];
        foreach ($bySource as $prefixes) {
            foreach ($prefixes as $basename => $prefix) {
                if (isset($providers[$basename]) && $providers[$basename] !== $prefix) {
                    $conflicts[$basename] = true;
                }
                $providers[$basename] = $prefix;
            }
        }

        return $api + $then + array_diff_key($providers, $conflicts);
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

            $methods = [];
            foreach ($class->getMethods() as $method) {
                $methods[$method->name->toLowerString()] = $method;
            }

            $pending = array_values(array_intersect($entries, array_keys($methods)));
            $reached = array_fill_keys($pending, true);
            while ($pending !== []) {
                $method = $methods[array_pop($pending)];
                foreach ($this->parser->findNodes([$method], Node\Expr\CallLike::class) as $call) {
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
     * The api: route files withRouting() registers, each under its apiPrefix, or 'api'
     * when no apiPrefix is given: a path, or each path of a list, as
     * ApplicationBuilder::buildRoutingCallback() reads both, a variable holding either read
     * as its value. None when the apiPrefix given cannot be read, or when withRouting() runs
     * a using: callback in place of its own, which never registers api: (a then: callback
     * makes it build its own again).
     *
     * @return array<string, string>
     */
    private function extractFollowedApiPrefixes(Node\Expr\MethodCall $call): array
    {
        $then = $this->withRoutingArgument($call, 'then');
        $using = $this->withRoutingArgument($call, 'using');
        if (($then === null || $this->isNullLiteral($then)) && $using !== null && ! $this->isNullLiteral($using)) {
            return [];
        }

        $api = $this->withRoutingArgument($call, 'api');
        $files = $api !== null ? $this->extractRouteFileBasenames($api) : [];
        if ($files === []) {
            return [];
        }

        $apiPrefix = $this->withRoutingArgument($call, 'apiPrefix');
        if ($apiPrefix === null) {
            return array_fill_keys($files, 'api');
        }

        $apiPrefix = BootstrapRouteParser::heldValue($apiPrefix);

        return $apiPrefix instanceof Node\Scalar\String_ ? array_fill_keys($files, trim($apiPrefix->value, '/')) : [];
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
     * gives one key. Only Router::group() takes attributes: RouteRegistrar::group() takes
     * the routes alone. A chain that starts at a class named Route other than the Route
     * facade or its global alias registers nothing, and cannot be read either.
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

            $isGuestRoute = in_array('guest', $route['middleware'], true);
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
                if (! $removesAuth && ! $isGuestRoute && $this->isRouteMiddlewareAuthenticated($route['middleware'])) {
                    $this->routeAuthCarried[$method] = ($this->routeAuthCarried[$method] ?? 0) + 1;
                } elseif ($hasExplicitAuthRemoval || $isGuestRoute || $route['http_methods'] === ['GET'] || ($isPublicUri && $removesAuth)) {
                    $this->routeOpenControllerMethods[$method] = true;
                }

                // Explicit public signals win
                if ($isPublicUri || $hasExplicitAuthRemoval || $isGuestRoute) {
                    $this->publicControllerMethods[$method] = true;

                    continue;
                }

                if ($this->isRouteMiddlewareAuthenticated($route['middleware'])) {
                    $this->routeAuthStats[$method]['authenticated']++;
                } elseif ($route['http_methods'] === ['GET']) {
                    // Unauthenticated GET routes are read-only, intentionally public
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
     * custom auth middleware class.
     *
     * @param  list<string>  $middleware
     */
    private function isRouteMiddlewareAuthenticated(array $middleware): bool
    {
        foreach ($middleware as $mw) {
            if ($this->isAuthMiddleware($mw) || $this->isAuthorizationMiddleware($mw)) {
                return true;
            }

            // Class-like strings (contain backslash = FQCN from NameResolver)
            if (str_contains($mw, '\\')) {
                if ($this->isCustomAuthMiddlewareClass($mw)) {
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
            if (isset($aliasMap[$alias]) && $this->isCustomAuthMiddlewareClass($aliasMap[$alias])) {
                return true;
            }
        }

        return false;
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

            $allMiddleware = array_merge($group['inherited_middleware'], $group['middleware']);
            $hasAuth = $this->isRouteMiddlewareAuthenticated($allMiddleware);

            if (! $hasAuth && ! $group['has_guest']) {
                // Skip when every route inside this group is explicitly public —
                // the user has opted these URIs out via the public_routes config.
                if ($this->groupContainsOnlyPublicRoutes($group, $visitor->getCollectedRoutes())) {
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
            if (in_array('guest', $route['middleware'], true)) {
                continue;
            }

            // Skip if the route explicitly opted out of auth (withoutMiddleware)
            if ($this->routeDirectRemoveHasAuth($route['direct_remove'])) {
                continue;
            }

            $isAuthenticated = $this->isRouteMiddlewareAuthenticated($route['middleware']);
            $httpMethod = $route['http_methods'][0] ?? 'GET';
            $isMutation = $this->isMutationRoute($httpMethod);

            if (! $isAuthenticated && $isMutation) {
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
     * Collect a route file's routes and groups with RouteAuthVisitor, once per analysis. The
     * route parser walks the tree first, so the visitor reads as route groups the group calls
     * the parser finds made on the router, and a group on a variable holding a registrar reads
     * the calls that built it (see BootstrapRouteParser::routerGroupCalls() and groupChain()).
     *
     * @param  array<Node>  $ast  The file's tree, with names resolved
     */
    private function visitRouteFile(string $file, array $ast): RouteAuthVisitor
    {
        if (isset($this->routeVisitors[$file])) {
            return $this->routeVisitors[$file];
        }

        // A file whose groups all start at a Route facade call needs no walk
        $routeParser = new BootstrapRouteParser($this->getBasePath(), $this->parser);
        $routerGroups = $this->groupsOffTheFacade($ast) ? $routeParser->routerGroupCalls($ast) : [];
        $visitor = new RouteAuthVisitor($routeParser, $routerGroups, $this->routeFileBasePrefixes[basename($file)] ?? '');
        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $this->routeVisitors[$file] = $visitor;
    }

    /**
     * Whether a tree makes a ->group() call, by any case, on a chain that does not start at a
     * Route facade call that builds a registrar, such as one on a variable, app('router') or
     * Route::getFacadeRoot(): only the route parser's walk tells whether its receiver is the
     * router.
     *
     * @param  array<Node>  $ast
     */
    private function groupsOffTheFacade(array $ast): bool
    {
        foreach ($this->parser->findNodes($ast, Node\Expr\MethodCall::class) as $call) {
            if (! $call instanceof Node\Expr\MethodCall || ! $call->name instanceof Node\Identifier
                || $call->name->toLowerString() !== 'group') {
                continue;
            }
            $root = $call;
            while ($root instanceof Node\Expr\MethodCall) {
                $root = $root->var;
            }
            if (! $root instanceof Node\Expr\StaticCall || ! $root->class instanceof Node\Name || ! $root->name instanceof Node\Identifier
                || strcasecmp($root->class->getLast(), 'Route') !== 0 || $root->name->toLowerString() === 'getfacaderoot') {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether every route physically nested within a group's line
     * range is explicitly public (whitelisted URI, guest, or auth removed).
     *
     * Returns false when the group contains no routes, so genuinely empty or
     * non-whitelisted groups continue to be flagged.
     *
     * @param  array{middleware: list<string>, inherited_middleware: list<string>, line: int, end_line: int, has_guest: bool, is_static_group: bool}  $group
     * @param  list<array{uri: string, match_uris: list<string>, http_methods: list<string>, controller: string|null, action: string|null, is_closure: bool, middleware: list<string>, direct_remove: list<string>, removed: list<string>, line: int}>  $routes
     */
    private function groupContainsOnlyPublicRoutes(array $group, array $routes): bool
    {
        $found = false;

        foreach ($routes as $route) {
            // Only consider routes that physically sit inside this group's braces.
            if ($route['line'] < $group['line'] || $route['line'] > $group['end_line']) {
                continue;
            }

            $found = true;

            $isPublic = $this->isRoutePublic($route)
                || in_array('guest', $route['middleware'], true)
                || $this->routeDirectRemoveHasAuth($route['direct_remove']);

            if (! $isPublic) {
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

        $classes = $this->parser->findClasses($ast);

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
                        $hasAuthMiddleware = $this->isControllerMethodAuthenticated($methodName, $constructorMiddlewareInfo, $middlewareMethodInfo);

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

        $classes = $this->parser->findClasses($ast);

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
                if ($stmt instanceof Node\Stmt\ClassMethod && $stmt->name->toString() === 'authorize') {
                    $authorizeMethod = $stmt;
                    break;
                }
            }

            // Missing authorize() method defaults to false (secure by default)
            if ($authorizeMethod === null) {
                continue;
            }

            // Check if authorize() returns true without any checks
            if ($this->authorizesWithoutChecks($authorizeMethod)) {
                // Only flag if actually used in a sensitive, unprotected action.
                // Without usage context, authorize() => true is ambiguous.
                if ($this->isFormRequestUsedInUnprotectedSensitiveAction($className, $fqcn)) {
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
     * Find all controller methods that type-hint the given FormRequest.
     *
     * Resolves parameter type names through each file's use imports so that
     * imported short names (e.g. "DeleteAccountRequest") correctly match the FQCN.
     *
     * @return array<array{controllerClass: string, namespace: string, methodName: string, classNode: Node\Stmt\Class_}>
     */
    private function findFormRequestUsagesInControllers(string $shortClassName, string $fqcn): array
    {
        $usages = [];

        foreach ($this->getControllerFiles() as $file) {
            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            // Resolve use imports so short names expand to their FQCN
            $fileLines = FileParser::getLines($file);
            $useImports = $this->extractUseImports($fileLines);

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

                    foreach ($stmt->getParams() as $param) {
                        if ($param->type === null) {
                            continue;
                        }

                        $typeName = $param->type instanceof Node\Name
                            ? $param->type->toString()
                            : '';

                        if ($typeName === '') {
                            continue;
                        }

                        // Resolve through use imports (covers the common "imported short name" case)
                        $resolvedType = $useImports[$typeName] ?? $typeName;

                        $matches = $resolvedType === $fqcn
                            || $typeName === $shortClassName
                            || str_ends_with($resolvedType, '\\'.$shortClassName);

                        if ($matches) {
                            $usages[] = [
                                'controllerClass' => $controllerClass,
                                'namespace' => $ns,
                                'methodName' => $stmt->name->toString(),
                                'classNode' => $class,
                            ];
                            break; // Found usage in this method; skip remaining params
                        }
                    }
                }
            }
        }

        return $usages;
    }

    /**
     * Return true only when the FormRequest with authorize() => true is injected into
     * a sensitive controller action that is not protected by any auth signal.
     */
    private function isFormRequestUsedInUnprotectedSensitiveAction(
        string $shortClassName,
        string $fqcn
    ): bool {
        $usages = $this->findFormRequestUsagesInControllers($shortClassName, $fqcn);

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
            $middlewareMethodInfo = $this->getMiddlewareMethodInfo($classNode);
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
     * @return array<string, array{only?: array<string>, except?: array<string>}>|null
     */
    private function getConstructorMiddlewareInfo(Node\Stmt\Class_ $class): ?array
    {
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\ClassMethod && $stmt->name->toString() === '__construct') {
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
            $methodName = $currentExpr->name instanceof Node\Identifier ? $currentExpr->name->toString() : null;

            if ($methodName === 'middleware') {
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
                }
                if (! empty($methods)) {
                    $constraints[$methodName] = $methods;
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
     * Returns array with 'auth' key containing 'only' or 'except' arrays, or null if no auth middleware.
     *
     * @return array<string, array{only?: array<string>, except?: array<string>}>|null
     */
    private function getMiddlewareMethodInfo(Node\Stmt\Class_ $class): ?array
    {
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\ClassMethod && $stmt->name->toString() === 'middleware') {
                // Check if method returns an array
                foreach ($stmt->stmts ?? [] as $methodStmt) {
                    if ($methodStmt instanceof Node\Stmt\Return_ && $methodStmt->expr instanceof Node\Expr\Array_) {
                        $middlewareInfo = [];

                        foreach ($methodStmt->expr->items as $item) {
                            if (! ($item instanceof Node\Expr\ArrayItem)) {
                                continue;
                            }

                            // Get the key (middleware name like 'auth', 'auth:api', 'can:update,post')
                            $key = $this->extractArrayKeyValue($item->key);

                            if ($key === null || (! $this->isAuthMiddleware($key) && ! $this->isAuthorizationMiddleware($key))) {
                                continue;
                            }

                            // Get the value (array with 'only' or 'except')
                            $value = $item->value;
                            if ($value instanceof Node\Expr\Array_) {
                                $constraints = [];
                                foreach ($value->items as $constraintItem) {
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
                                $middlewareInfo[$key] = $constraints;
                            } else {
                                // If value is not an array, middleware applies to all methods
                                $middlewareInfo[$key] = [];
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
     * @param  array<string, array{only?: array<string>, except?: array<string>}>|null  $constructorMiddlewareInfo
     * @param  array<string, array{only?: array<string>, except?: array<string>}>|null  $middlewareMethodInfo
     */
    private function isControllerMethodAuthenticated(string $methodName, ?array $constructorMiddlewareInfo, ?array $middlewareMethodInfo): bool
    {
        // Check constructor middleware with constraints
        if ($this->middlewareMethodProvidesAuthentication($methodName, $constructorMiddlewareInfo)) {
            return true;
        }

        // Check middleware() method
        return $this->middlewareMethodProvidesAuthentication(
            $methodName,
            $middlewareMethodInfo
        );
    }

    /**
     * Check if middleware method provides authentication or authorization.
     *
     * @param  array<string, array{only?: array<string>, except?: array<string>}>|null  $middlewareInfo
     */
    private function middlewareMethodProvidesAuthentication(string $methodName, ?array $middlewareInfo): bool
    {
        if ($middlewareInfo === null) {
            return false;
        }

        foreach ($middlewareInfo as $middlewareName => $constraints) {
            // Check for both auth and authorization middleware (can:, role:, permission:)
            if (! $this->isAuthMiddleware($middlewareName) && ! $this->isAuthorizationMiddleware($middlewareName)) {
                continue;
            }

            // Applies to all methods
            if ($constraints === []) {
                return true;
            }

            // only = whitelist
            if (isset($constraints['only'])) {
                return in_array($methodName, $constraints['only'], true);
            }

            // except = blacklist
            if (isset($constraints['except'])) {
                return ! in_array($methodName, $constraints['except'], true);
            }
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
        $middlewareMethodInfo = $this->getMiddlewareMethodInfo($classNode);

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
     * Extract use imports from file lines.
     *
     * Maps short class names to FQCNs, e.g.:
     * 'use App\Http\Middleware\ValidateApiToken;' -> ['ValidateApiToken' => 'App\Http\Middleware\ValidateApiToken']
     *
     * @param  array<int, string>  $lines
     * @return array<string, string>
     */
    private function extractUseImports(array $lines): array
    {
        $imports = [];

        foreach ($lines as $line) {
            if (! is_string($line)) {
                continue;
            }

            if (preg_match('/^use\s+([\w\\\\]+?)(?:\s+as\s+(\w+))?\s*;/', trim($line), $matches)) {
                $fqcn = $matches[1];
                $alias = $matches[2] ?? null;

                // Use alias if provided, otherwise extract short class name
                $shortName = $alias ?? substr($fqcn, (int) strrpos($fqcn, '\\') + 1);
                $imports[$shortName] = $fqcn;
            }
        }

        return $imports;
    }

    /**
     * Check if a custom middleware class is an auth middleware by introspecting its source code.
     *
     * Looks for auth signals: bearerToken(), getPassword(), AuthenticationException,
     * AuthenticatesRequests, Illuminate\Contracts\Auth\Factory.
     *
     * Expects a FQCN (resolved by NameResolver in the route visitor).
     */
    private function isCustomAuthMiddlewareClass(string $className): bool
    {
        $fqcn = $className;

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
     * Each entry: ['add' => list<string>, 'remove' => list<string>]
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
     * The middleware each open group excludes, through ->withoutMiddleware() or an
     * 'excluded_middleware' attribute, kept in lockstep with $middlewareStack. Read only into
     * each route's 'removed' list.
     *
     * @var list<list<string>>
     */
    private array $excludedStack = [];

    /**
     * @var list<array{uri: string, match_uris: list<string>, http_methods: list<string>, controller: string|null, action: string|null, is_closure: bool, middleware: list<string>, direct_remove: list<string>, removed: list<string>, line: int}>
     */
    private array $collectedRoutes = [];

    /**
     * @var list<array{middleware: list<string>, inherited_middleware: list<string>, line: int, end_line: int, has_guest: bool, is_static_group: bool}>
     */
    private array $collectedGroups = [];

    /** @var list<string> Supported route HTTP verb method names (lowercase) */
    private const ROUTE_VERBS = ['get', 'post', 'put', 'patch', 'delete', 'resource', 'apiresource'];

    /**
     * @param  BootstrapRouteParser  $routeParser  The parser that has walked the route file's tree,
     *                                             which reads the chain of each group call
     * @param  array<int, true>  $routerGroups  The group calls the parser finds made on the router,
     *                                          by spl_object_id() (see BootstrapRouteParser::routerGroupCalls())
     * @param  string  $basePrefix  File-level URI prefix applied by the framework when
     *                              registering the whole route file (e.g. 'api' for routes/api.php).
     */
    public function __construct(
        private readonly BootstrapRouteParser $routeParser,
        private readonly array $routerGroups,
        private readonly string $basePrefix = '',
    ) {}

    /**
     * @return list<array{uri: string, match_uris: list<string>, http_methods: list<string>, controller: string|null, action: string|null, is_closure: bool, middleware: list<string>, direct_remove: list<string>, removed: list<string>, line: int}>
     */
    public function getCollectedRoutes(): array
    {
        return $this->collectedRoutes;
    }

    /**
     * @return list<array{middleware: list<string>, inherited_middleware: list<string>, line: int, end_line: int, has_guest: bool, is_static_group: bool}>
     */
    public function getCollectedGroups(): array
    {
        return $this->collectedGroups;
    }

    public function enterNode(Node $node): ?int
    {
        if ($this->isGroupNode($node)) {
            // Snapshot inherited middleware BEFORE pushing this group's own layer
            $inherited = $this->computeStackMiddleware();
            $own = $this->extractGroupMiddleware($node);
            $this->middlewareStack[] = $own;
            $this->prefixStack[] = $this->extractGroupPrefix($node);
            $this->excludedStack[] = [...$own['remove'], ...$this->extractGroupExcludedMiddleware($node)];

            $this->collectedGroups[] = [
                'middleware' => $own['add'],
                'inherited_middleware' => $inherited,
                'line' => $node->getStartLine(),
                'end_line' => $node->getEndLine(),
                'has_guest' => in_array('guest', $own['add'], true),
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
            array_pop($this->excludedStack);
        }

        // Process route calls at the Stmt\Expression boundary so we see the
        // complete method-call chain (including chained ->middleware() / ->withoutMiddleware())
        // in one pass.
        if ($node instanceof Node\Stmt\Expression) {
            $this->processExpression($node->expr);
        }

        return null;
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
     *   → parses the config array's 'middleware' key.
     *
     * For MethodCall ->group() chains (e.g. Route::middleware('auth')->group(fn)):
     *   → walks the chain the route parser reads for the call (see
     *     BootstrapRouteParser::groupChain()) collecting every ->withoutMiddleware() call,
     *     as RouteRegistrar merges them, and only the last ->middleware() call, as each
     *     middleware() call replaces the last (the first one found walking outward-in),
     *     including Route::middleware() / Route::withoutMiddleware() as the root.
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
            foreach ($this->registrarCalls($node) as $current) {
                if ($current->name instanceof Node\Identifier) {
                    $name = $current->name->toString();
                    if ($name === 'middleware') {
                        $applied ??= $this->extractMiddlewareArgs($current->args);
                    } elseif ($name === 'withoutMiddleware') {
                        $remove = array_merge($remove, $this->extractMiddlewareArgs($current->args));
                    }
                }
            }

            $add = [...$applied ?? [], ...$add];
        }

        return ['add' => $add, 'remove' => $remove];
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
                    && $current->name->toString() === 'prefix'
                    && ($arg = $current->args[0]->value ?? null) instanceof Node\Scalar\String_) {
                    return trim($arg->value, '/');
                }
            }
        }

        return '';
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

    // -------------------------------------------------------------------------
    // Route expression processing
    // -------------------------------------------------------------------------

    /**
     * If the expression (top of a Stmt\Expression) is a route verb call, collect it.
     *
     * Walks the MethodCall chain from the outermost node down to the innermost
     * StaticCall, collecting ->middleware() / ->withoutMiddleware() along the way.
     */
    private function processExpression(Node\Expr $expr): void
    {
        // Collect the MethodCall chain (outermost first)
        $chain = [];
        $current = $expr;
        while ($current instanceof Node\Expr\MethodCall) {
            $chain[] = $current;
            $current = $current->var;
        }

        // The innermost node must be a StaticCall on the Route facade
        if (! ($current instanceof Node\Expr\StaticCall)) {
            return;
        }
        if (! ($current->class instanceof Node\Name) || ! $this->isRouteFacade($current->class)) {
            return;
        }
        if (! ($current->name instanceof Node\Identifier)) {
            return;
        }

        $verbLower = strtolower($current->name->toString());

        // Skip group calls (handled via enterNode/leaveNode)
        if ($verbLower === 'group') {
            return;
        }

        if (! in_array($verbLower, self::ROUTE_VERBS, true)) {
            return;
        }

        $httpMethod = strtoupper($current->name->toString());

        // Extract URI and handler from the StaticCall args
        $ownUri = $this->extractUri($current);
        [$controller, $action, $isClosure] = $this->extractHandler($current);

        // Collect direct middleware and ->prefix() calls from the outer chain.
        // The chain is outermost-first, which for prefixes is framework-true
        // left-to-right order: each later ->prefix() call prepends to the URI.
        $directAdd = [];
        $directRemove = [];
        $directPrefixes = [];
        foreach ($chain as $methodCall) {
            if (! ($methodCall->name instanceof Node\Identifier)) {
                continue;
            }
            $name = $methodCall->name->toString();
            if ($name === 'middleware') {
                $directAdd = array_merge($directAdd, $this->extractMiddlewareArgs($methodCall->args));
            } elseif ($name === 'withoutMiddleware') {
                $directRemove = array_merge($directRemove, $this->extractMiddlewareArgs($methodCall->args));
            } elseif ($name === 'prefix'
                && ($arg = $methodCall->args[0]->value ?? null) instanceof Node\Scalar\String_) {
                $directPrefixes[] = trim($arg->value, '/');
            }
        }

        [$uri, $matchUris] = $this->composeRouteUris($ownUri, $directPrefixes);

        // Compute effective middleware: inherited from stack → apply direct
        $effective = $this->computeStackMiddleware();
        foreach ($directAdd as $mw) {
            $effective[] = $mw;
        }
        foreach ($directRemove as $mw) {
            $effective = array_values(array_filter($effective, fn ($x) => $x !== $mw));
        }
        $effective = array_unique($effective);

        $this->collectedRoutes[] = [
            'uri' => $uri,
            'match_uris' => $matchUris,
            'http_methods' => [$httpMethod],
            'controller' => $controller,
            'action' => $action,
            'is_closure' => $isClosure,
            'middleware' => array_values($effective),
            'direct_remove' => $directRemove,
            'removed' => array_values(array_unique([...array_merge(...$this->excludedStack), ...$directRemove])),
            'line' => $current->getStartLine(),
        ];
    }

    // -------------------------------------------------------------------------
    // Handler / URI extraction
    // -------------------------------------------------------------------------

    /**
     * Extract the URI string from a route StaticCall's first argument.
     */
    private function extractUri(Node\Expr\StaticCall $call): string
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
     * the file-level base prefix, enclosing group prefixes, direct ->prefix()
     * calls, and the route's own declared segment.
     *
     * Candidates are [full real path, AST-visible composition, own segment]:
     * patterns written against partial paths keep working, and a wrong
     * file-level prefix guess can never hide a match.
     *
     * @param  list<string>  $directPrefixes
     * @return array{string, list<string>} [full URI, match candidates]
     */
    private function composeRouteUris(string $ownUri, array $directPrefixes): array
    {
        if ($ownUri === '') {
            // Unresolvable route URI — don't fabricate a path from prefixes alone.
            return ['', ['']];
        }

        $groupSegments = array_values(array_filter($this->prefixStack, static fn (string $p): bool => $p !== ''));

        $visible = $directPrefixes === [] && $groupSegments === []
            ? $ownUri
            : $this->joinUriSegments(array_merge($directPrefixes, $groupSegments, [$ownUri]));

        // Direct ->prefix() calls prepend in front of the already-prefixed URI,
        // so the framework-true order is direct/base/groups/own.
        $full = $this->basePrefix === ''
            ? $visible
            : $this->joinUriSegments(array_merge($directPrefixes, [$this->basePrefix], $groupSegments, [$ownUri]));

        return [$full, array_values(array_unique([$full, $visible, $ownUri]))];
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
     *   'Controller@method'            — legacy string
     *   Closure / ArrowFunction        — closure route
     *
     * @return array{0: string|null, 1: string|null, 2: bool} [controller, action, isClosure]
     */
    private function extractHandler(Node\Expr\StaticCall $call): array
    {
        if (count($call->args) < 2) {
            return [null, null, false];
        }

        $handlerArg = $call->args[1]->value ?? null;

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

        // 'Controller@method' or 'Controller' (legacy string)
        if ($handlerArg instanceof Node\Scalar\String_) {
            $value = $handlerArg->value;
            if (str_contains($value, '@')) {
                [$class, $method] = explode('@', $value, 2);

                return [$class, $method, false];
            }

            return [$value, '__invoke', false];
        }

        return [null, null, false];
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
     * Extract middleware strings from a value node (String_, Array_, or ClassConstFetch).
     *
     * @return list<string>
     */
    private function extractMiddlewareValue(Node\Expr $value): array
    {
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

        return [];
    }

    // -------------------------------------------------------------------------
    // Stack helpers
    // -------------------------------------------------------------------------

    /**
     * Compute the effective middleware set from the current stack (without any direct overrides).
     *
     * Applies each layer in order: adds first, then removes.
     *
     * @return list<string>
     */
    private function computeStackMiddleware(): array
    {
        $middleware = [];

        foreach ($this->middlewareStack as $layer) {
            foreach ($layer['add'] as $mw) {
                $middleware[] = $mw;
            }
            foreach ($layer['remove'] as $mw) {
                $middleware = array_values(array_filter($middleware, fn ($x) => $x !== $mw));
            }
        }

        return array_values(array_unique($middleware));
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
