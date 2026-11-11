<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use PhpParser\Node;
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
use ShieldCI\Concerns\TracksImportedNames;
use ShieldCI\Support\BootstrapRouteParser;
use ShieldCI\Support\MiddlewareThrottleDetector;

/**
 * Detects missing login throttling/rate limiting.
 *
 * Checks for:
 * - ThrottleRequests middleware on login routes
 * - RateLimiter usage in authentication controllers
 * - Login routes without rate limiting protection
 * - Brute force attack vulnerability
 *
 * @phpstan-type RouteGroup array{start: int, end: int, middleware: list<string>, excluded: list<string>, controller: ?string, registration: bool, scope: string}
 * @phpstan-type RegisteredMiddleware array{class: string, names: list<string>, only: array<int, string>|null, except: array<int, string>}
 * @phpstan-type RouteCall array{verbs: list<string>, uri: string, written: bool, chained: bool, offset: int}
 */
class LoginThrottlingAnalyzer extends AbstractFileAnalyzer
{
    use DetectsLaravelVersion;
    use ReadsMiddlewareConfigurator;
    use TracksImportedNames;

    /**
     * Whether a class throttles login, keyed by fully qualified name and the method
     * judged (see classThrottleVerdict()), for this run; null when it cannot be read.
     *
     * @var array<string, bool|null>
     */
    private array $throttlingClasses = [];

    /**
     * Route middleware aliases the app registers, mapped to their classes, for this run.
     *
     * @var array<string, string>
     */
    private array $middlewareAliases = [];

    /**
     * Middleware groups the app defines, mapped to their entries: a class name or
     * a middleware name still to resolve.
     *
     * @var array<string, array<int, string>>
     */
    private array $middlewareGroups = [];

    /**
     * The throttles the 'web' and 'api' groups list, as MiddlewareThrottleDetector reads
     * them from the Kernel and the withMiddleware() configurator, which the group names
     * resolve to beside the entries $middlewareGroups holds.
     *
     * @var array{web: list<string>, api: list<string>}
     */
    private array $groupThrottles = ['web' => [], 'api' => []];

    /**
     * The class Laravel itself registers the 'throttle' alias as, for this run (see
     * MiddlewareThrottleDetector::frameworkThrottleClass()); an alias the app registers
     * is read with the others.
     */
    private string $throttleAliasClass = MiddlewareThrottleDetector::THROTTLE_MIDDLEWARE[0];

    private const ROUTE_VERBS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'any', 'match', 'resource'];

    public function __construct(
        private AstParser $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'login-throttling',
            name: 'Login Throttling Analyzer',
            description: 'Detects missing rate limiting on authentication endpoints to prevent brute force attacks',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['authentication', 'rate-limiting', 'brute-force', 'security', 'throttling'],
            timeToFix: 20
        );
    }

    public function shouldRun(): bool
    {
        $routePath = $this->getBasePath().DIRECTORY_SEPARATOR.'routes';

        return is_dir($routePath);
    }

    public function getSkipReason(): string
    {
        return 'No routes directory found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $this->throttlingClasses = [];
        // Judging a middleware class reads its file against its own imports and then puts
        // the caller's table back, so a table has to exist before any file is tracked: a
        // provider's route group is judged before the first route file is read.
        $this->startTrackingImports();
        $this->middlewareAliases = $this->readMiddlewareAliases();
        $this->middlewareGroups = $this->readMiddlewareGroups();

        // Throttle on the 'web' and 'api' middleware groups: app/Http/Kernel.php
        // (Laravel 10 and earlier) or bootstrap/app.php (Laravel 11+). The two are
        // kept apart because each only covers the routes registered in its group:
        // the stock Laravel 9/10 Kernel throttles 'api' out of the box, and that
        // says nothing about a login route in routes/web.php. A throttle on the
        // global stack runs on every route, so it covers both. Each middleware there
        // is judged as a route's own is, so an app alias for ThrottleRequests counts.
        // A route can exclude a group's throttle by name, but never one on the global stack.
        $throttles = new MiddlewareThrottleDetector($this->getBasePath(), $this->parser, $this->middlewareNameThrottles(...));
        $webThrottles = $throttles->groupThrottleNames(['web']);
        $apiThrottles = $throttles->groupThrottleNames(['api']);
        $this->groupThrottles = ['web' => $webThrottles['names'], 'api' => $apiThrottles['names']];
        $this->throttleAliasClass = $throttles->frameworkThrottleClass();
        $hasWebGroupThrottle = $webThrottles['global'] || $webThrottles['names'] !== [];

        // Check route files for login routes without throttling
        $coveredControllers = $this->checkRouteFiles($issues, globalThrottled: $webThrottles['global']);

        // Check authentication controllers not already reached through a throttled route
        $this->checkAuthControllers($issues, $coveredControllers);

        // Fortify registers its login route itself, in the 'web' group, so a
        // web-group throttle, its route limiter or its login pipeline covers it.
        // Throttling in the app's controllers never runs on that route. Breeze and Jetstream need no
        // check of their own: Breeze's login routes are in routes/auth.php, which
        // checkRouteFiles() reads, and Jetstream logs in through Fortify.
        if (! $hasWebGroupThrottle && $this->hasFortify()) {
            $this->checkFortifyThrottling($issues);
        }

        $summary = empty($issues)
            ? 'Login throttling/rate limiting is properly configured'
            : sprintf('Found %d login throttling issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Read a PHP file with its comments blanked out, line numbering preserved,
     * so commented-out code is never matched as live code.
     */
    private function readCode(string $path): ?string
    {
        $content = FileParser::readFile($path);

        return $content === null ? null : FileParser::stripAllComments($content);
    }

    /**
     * Check if a file contains login-specific throttling patterns.
     */
    private function hasLoginThrottlingInFile(string $file): bool
    {
        $content = $this->readCode($file);
        if ($content === null) {
            return false;
        }

        // Pattern 1: Login-specific RateLimiter keys
        // RateLimiter::attempt('login:', ...), RateLimiter::for('login', ...)
        if (preg_match('/RateLimiter::(attempt|for)\s*\(\s*["\']login[:_\-]?/i', $content)) {
            return true;
        }

        // Pattern 2: ThrottlesLogins trait methods
        // tooManyAttempts(), hasTooManyLoginAttempts(), clearLoginAttempts()
        if (preg_match('/\b(tooManyAttempts|hasTooManyLoginAttempts|clearLoginAttempts)\s*\(/i', $content)) {
            return true;
        }

        // Pattern 3: AST-based detection - RateLimiter in auth methods
        if ($this->hasRateLimiterInAuthMethodAST($file)) {
            return true;
        }

        return false;
    }

    /**
     * Whether a class in the file uses AuthenticatesUsers or ThrottlesLogins.
     *
     * Read from the AST, so the trait named only in an import or a comment
     * does not count.
     */
    private function usesLoginThrottlingTrait(string $file): bool
    {
        foreach ($this->parser->findClasses($this->parser->parseFile($file)) as $class) {
            foreach ($class->stmts as $stmt) {
                if (! $stmt instanceof Node\Stmt\TraitUse) {
                    continue;
                }

                foreach ($stmt->traits as $trait) {
                    if (in_array($trait->getLast(), ['AuthenticatesUsers', 'ThrottlesLogins'], true)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Use AST to check if RateLimiter is used within authentication methods.
     */
    private function hasRateLimiterInAuthMethodAST(string $file): bool
    {
        try {
            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                return false;
            }

            $classes = $this->parser->findClasses($ast);
            foreach ($classes as $class) {
                if (! isset($class->stmts) || ! is_array($class->stmts)) {
                    continue;
                }

                foreach ($class->stmts as $stmt) {
                    if (! $stmt instanceof Node\Stmt\ClassMethod) {
                        continue;
                    }

                    $methodName = $stmt->name->toString();

                    // Check if this is an auth-related method
                    // Note: __invoke is included for single-action controllers (Laravel best practice)
                    // e.g., class LoginController { public function __invoke() {...} }
                    // 'ensureIsNotRateLimited' is the canonical throttling guard in the
                    // official starter-kit LoginRequest.
                    $authMethods = ['login', 'authenticate', 'attempt', 'postLogin', 'handleLogin', 'store', '__invoke', 'ensureIsNotRateLimited'];
                    if (! in_array(strtolower($methodName), array_map('strtolower', $authMethods), true)) {
                        continue;
                    }

                    // Check if method body contains RateLimiter static calls
                    if ($this->methodContainsRateLimiter($stmt)) {
                        return true;
                    }
                }
            }
        } catch (\Throwable $e) {
            // Fall back to false if AST parsing fails
            return false;
        }

        return false;
    }

    /**
     * Check if a method contains RateLimiter static calls.
     */
    private function methodContainsRateLimiter(Node\Stmt\ClassMethod $method): bool
    {
        if (! isset($method->stmts) || ! is_array($method->stmts)) {
            return false;
        }

        // Recursively search for RateLimiter static calls
        return $this->nodeContainsRateLimiter($method->stmts);
    }

    /**
     * Recursively search nodes for RateLimiter usage.
     *
     * @param  array<Node>|Node  $nodes
     */
    private function nodeContainsRateLimiter(array|Node $nodes): bool
    {
        if ($nodes instanceof Node) {
            $nodes = [$nodes];
        }

        foreach ($nodes as $node) {
            if (! $node instanceof Node) {
                continue;
            }

            // Check for RateLimiter::method() calls
            if ($node instanceof Node\Expr\StaticCall) {
                if ($node->class instanceof Node\Name) {
                    $className = $node->class->toString();
                    if (in_array($className, ['RateLimiter', 'Illuminate\Support\Facades\RateLimiter'], true)) {
                        return true;
                    }
                }
            }

            // Recursively check all sub-nodes
            foreach ($node->getSubNodeNames() as $subNodeName) {
                $subNode = $node->$subNodeName;

                if ($subNode instanceof Node) {
                    if ($this->nodeContainsRateLimiter($subNode)) {
                        return true;
                    }
                } elseif (is_array($subNode)) {
                    /** @var array<Node> $subNode */
                    if ($this->nodeContainsRateLimiter($subNode)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check route files for login routes without throttling.
     *
     * Login routes are read from each file's AST (see routeMiddleware() and
     * firstLoginRoute()), keyed and reported by the line their verb is written on, as is
     * the middleware that reaches them. Each file is judged as part of the middleware
     * group it is registered under: routes/api.php and files registered in the 'api'
     * group are judged by the API rules (see isLoginRoute()) and get the 'api' group's
     * middleware, every other file the web rules and the 'web' group's. A route is
     * covered by a throttle on the global stack ($globalThrottled), by one its group,
     * its file's registration or its own statement applies and none of them excludes by
     * name (see middlewareThrottles()), or by a class its statement names that throttles
     * login itself (see routeClassesThrottle()). Login rate limiting elsewhere in the
     * code covers no route.
     *
     * Returns the controllers that throttled login routes point at, so the
     * controller check does not report a controller whose route is already
     * throttled. A login rate limiter defined somewhere in the app does not count:
     * it says nothing about whether this route applies it, and the controller
     * check is then the only signal left that it does not.
     *
     * @param  array<int, Issue>  &$issues
     * @return array<string, true>
     */
    private function checkRouteFiles(array &$issues, bool $globalThrottled): array
    {
        $coveredControllers = [];
        $routePath = $this->getBasePath().DIRECTORY_SEPARATOR.'routes';

        if (! is_dir($routePath)) {
            return $coveredControllers;
        }

        // The middleware of the groups that register a file applies to every route in it,
        // and is judged as a route's own is. Files in the 'api' group get the 'api' group's
        // middleware. A registration names the 'web' group itself, and the framework
        // registers routes/web.php in it (see fileGroupMiddleware()), so only a file no
        // registration reaches gets the 'web' group's middleware: being in the web group
        // says nothing about whether it is throttled.
        $bootstrapParser = new BootstrapRouteParser($this->getBasePath(), $this->parser, $this->middlewareNameThrottles(...));
        $apiFiles = array_fill_keys($bootstrapParser->getApiRegisteredRouteFiles(), true);
        $fileGroups = $this->fileGroupMiddleware($bootstrapParser, $apiFiles);

        try {
            foreach (new \DirectoryIterator($routePath) as $file) {
                if (! $file->isFile() || $file->getExtension() !== 'php') {
                    continue;
                }

                $filePath = $file->getPathname();
                $real = realpath($filePath);
                $normalizedPath = str_replace('\\', '/', $real !== false ? $real : $filePath);

                $isApiRoute = $file->getFilename() === 'api.php' || isset($apiFiles[$normalizedPath]);
                $fileMiddleware = $isApiRoute || ! isset($fileGroups[$normalizedPath]) ? $this->resolvedMiddlewareNames($isApiRoute ? 'api' : 'web') : [];
                // The source as written, which a route's URI is read from, and without
                // comments, which the Auth::routes() and controller scans read
                $source = FileParser::readFile($filePath);
                if ($source === null) {
                    continue;
                }
                $content = FileParser::stripAllComments($source);

                // Comment-free source, split so index $i is line $i + 1: stripAllComments()
                // keeps every newline, so line numbers match the file and the AST ranges.
                $lines = explode("\n", $content);

                // A route reference string carries no position, so controller names
                // resolve against the imports the file declares by its end.
                $ast = $this->parser->parseFile($filePath);

                // A file that does not parse is left to the report's parse-failure
                // notice, as every analyzer leaves it; one that parses empty has no routes.
                if ($ast === []) {
                    continue;
                }
                $this->trackFileImports($ast);

                // Middleware each route statement and each route group applies and
                // excludes, so a throttling middleware covers the routes it reaches, and
                // the routes the file registers.
                [$statementMiddleware, $groupMiddleware, $routeActions, $routeCalls] = $this->routeMiddleware($ast, $bootstrapParser->routerGroupCalls($ast), $bootstrapParser, $source);
                array_push($groupMiddleware, ...$fileGroups[$normalizedPath] ?? []);

                // $lines is 0-based; findings report $lineNumber + 1, which is the
                // 1-based scale the AST ranges use.
                foreach ($lines as $lineNumber => $line) {
                    // Check for Auth::routes() helper
                    if (preg_match('/Auth::routes\s*\(/i', $line)) {
                        // Auth::routes() includes login routes - check if throttled
                        // laravel/ui registers these against App\Http\Controllers\Auth\LoginController,
                        // posting the credentials to its login() method
                        $loginController = 'App\\Http\\Controllers\\Auth\\LoginController';
                        $loginAction = ['class' => $loginController, 'method' => 'login'];
                        $routeThrottled = $globalThrottled
                            || $this->middlewareThrottles($lineNumber + 1, $statementMiddleware, $groupMiddleware, $fileMiddleware, $loginAction);

                        if ($routeThrottled) {
                            $coveredControllers[$loginController] = true;
                        }

                        if (! $routeThrottled && ! $this->middlewareThrottles($lineNumber + 1, $statementMiddleware, $groupMiddleware, $fileMiddleware, $loginAction, [$loginController])) {
                            $issues[] = $this->createIssueWithSnippet(
                                message: 'Auth::routes() includes login endpoint without explicit rate limiting',
                                filePath: $filePath,
                                lineNumber: $lineNumber + 1,
                                severity: Severity::High,
                                recommendation: $this->isLaravel11OrNewer()
                                    ? 'Configure a rate limiter for the login endpoint in a service provider or via the middleware configuration in bootstrap/app.php to prevent brute force attacks.'
                                    : 'Apply rate limiting middleware to the login endpoint or configure a login rate limiter in your AuthServiceProvider to prevent brute force attacks.',
                                metadata: [
                                    'route' => 'Auth::routes()',
                                    'issue_type' => 'missing_route_throttle',
                                ]
                            );
                        }
                    }

                    // The login route registered on this line, if any (see firstLoginRoute()):
                    // /login, /signin, /auth or /authenticate in any file, and /token or
                    // /oauth on a POST in an API file
                    $routeUri = $this->firstLoginRoute($routeCalls[$lineNumber + 1] ?? [], $isApiRoute);

                    if ($routeUri !== null) {
                        // Skip endpoints matched only on the broad 'auth'/'oauth'
                        // substring whose action segment is a non-credential one
                        // (token revocation / identity reads). The credential-keyword
                        // guard ensures a real login/token route is never suppressed.
                        $segments = explode('/', trim((string) strtok($routeUri, '?'), '/'));
                        $lastSegment = strtolower((string) end($segments));
                        $isCredentialUri = preg_match('/login|signin|authenticate|token/i', $routeUri) === 1;
                        if (! $isCredentialUri && in_array($lastSegment, ['logout', 'signout', 'me'], true)) {
                            continue;
                        }

                        // A throttle the route, its group or its file applies covers the
                        // controllers the route names; one its controller registers on
                        // itself clears only the route.
                        $action = $routeActions[$lineNumber + 1] ?? null;
                        $routeThrottled = $globalThrottled
                            || $this->middlewareThrottles($lineNumber + 1, $statementMiddleware, $groupMiddleware, $fileMiddleware, $action);

                        // The action's controller too, which a route written over more lines than
                        // controllersReferencedByRoute() reads names out of its reach
                        if ($routeThrottled) {
                            foreach ([...$this->controllersReferencedByRoute($lines, $lineNumber), ...$this->actionClasses($action)] as $controller) {
                                $coveredControllers[$controller] = true;
                            }
                        }

                        if (! $routeThrottled && ! $this->middlewareThrottles($lineNumber + 1, $statementMiddleware, $groupMiddleware, $fileMiddleware, $action, $this->actionClasses($action))) {
                            $routeType = $isApiRoute ? 'API authentication' : 'Login';
                            $issues[] = $this->createIssueWithSnippet(
                                message: sprintf('%s route "%s" lacks rate limiting protection', $routeType, $routeUri),
                                filePath: $filePath,
                                lineNumber: $lineNumber + 1,
                                severity: Severity::High,
                                recommendation: 'Apply rate limiting middleware to this route to cap authentication attempts and prevent brute force attacks.',
                                metadata: [
                                    'route' => $routeUri,
                                    'route_type' => $isApiRoute ? 'api' : 'web',
                                    'issue_type' => 'missing_route_throttle',
                                ]
                            );
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            // Silently fail if directory iterator fails
        }

        return $coveredControllers;
    }

    /**
     * The URI of the login route a line registers (see isLoginRoute()), or null when it
     * registers none. Findings are keyed by line, so a line reports one route: one
     * written as a Route::verb('...') call, an API file's POST and any() before its GET,
     * resource() and controller(), then the last one chained after another Route:: call,
     * then any other, each other group in the order they are written. A line whose first
     * login route is a logout, sign-out or identity read (see checkRouteFiles()) reports
     * none.
     *
     * @param  list<RouteCall>  $calls  The routes registered on the line (see routeMiddleware())
     */
    private function firstLoginRoute(array $calls, bool $isApiRoute): ?string
    {
        $first = null;
        $firstRank = null;
        foreach ($calls as $call) {
            $verbs = array_values(array_filter($call['verbs'], fn (string $verb): bool => $this->isLoginRoute($verb, $call['uri'], $isApiRoute)));
            if ($verbs === []) {
                continue;
            }

            $rank = [match (true) {
                $call['written'] => $isApiRoute && ! in_array($verbs[0], ['post', 'any'], true) ? 1 : 0,
                $call['chained'] => 2,
                default => 3,
            }, $call['chained'] ? -$call['offset'] : $call['offset']];
            if ($firstRank === null || $rank < $firstRank) {
                $first = $call['uri'];
                $firstRank = $rank;
            }
        }

        return $first;
    }

    /**
     * Whether a route with this verb and URI takes login credentials: in an API file,
     * a POST/any/match URI with a login, auth or token keyword, or a
     * GET/resource/controller URI with a login or auth one; in a web file, a
     * POST/any/match/resource/controller URI with a login or auth keyword. A
     * match() route is judged by each method it lists (see routeCallVerbs()), and a
     * controller() one is only ever Route::controller('...') given a string.
     */
    private function isLoginRoute(string $verb, string $uri, bool $isApiRoute): bool
    {
        $login = preg_match('/login|signin|auth|authenticate/', $uri) === 1;

        if ($isApiRoute) {
            return (in_array($verb, ['post', 'any', 'match'], true) && ($login || preg_match('/token|oauth/', $uri) === 1))
                || (in_array($verb, ['get', 'resource', 'controller'], true) && $login);
        }

        return in_array($verb, ['post', 'any', 'match', 'resource', 'controller'], true) && $login;
    }

    /**
     * The middleware a route file applies and excludes, as resolved names (see
     * resolvedMiddlewareNames()): per route statement, keyed by the line its verb is
     * written on, from ->middleware(...) and ->withoutMiddleware(...) calls before the
     * verb (Route::middleware(...)->post(...)) and after it
     * (Route::post(...)->middleware(...)), and per route group, with the line range of
     * the group's closure (Route::middleware(...)->group(...),
     * Route::group(['middleware' => ..., 'excluded_middleware' => ...], ...)).
     * A group also records the controller a Route::controller(...) group names,
     * since its routes reach that controller. The third list is each route's
     * action (see routeAction()), keyed like the statements. The fourth is the
     * routes the file registers whose URI is a string literal, keyed the same way:
     * on the Route facade (see registersOnFacade()), on a chain that starts at it, or on
     * the router or a registrar held in a variable (see
     * BootstrapRouteParser::ROUTE_ON_ROUTER), each with the verbs it answers (see
     * routeCallVerbs()) and its URI (see routeUri()). A route on a variable whose
     * middleware this cannot read, one the router hands a registrar it may have changed,
     * is left out, as no throttle it may carry can be ruled out, and so is one on a variable
     * or the router that shares its line with another route, or whose chain starts at
     * another class (see chainStartsAtOtherClass()).
     *
     * Reads the import table, so trackFileImports() must have seen the route file. Only
     * the group calls in $routerGroups are route groups (see
     * BootstrapRouteParser::routerGroupCalls()), and only a tree that call has walked
     * carries the receivers it reads.
     *
     * @param  array<Node>  $ast
     * @param  array<int, true>  $routerGroups
     * @param  string  $source  The file as written, which the AST positions index
     * @return array{0: array<int, array{middleware: list<string>, excluded: list<string>}>, 1: list<RouteGroup>, 2: array<int, array{class: ?string, method: ?string}>, 3: array<int, list<RouteCall>>}
     */
    private function routeMiddleware(array $ast, array $routerGroups, BootstrapRouteParser $bootstrapParser, string $source): array
    {
        $statements = [];
        $groups = [];
        $actions = [];
        $routes = [];
        $verbs = [];
        $receiverRoutes = [];
        $reported = [];

        foreach ($this->parser->findNodes($ast, Node\Expr\MethodCall::class) as $call) {
            if (! $call instanceof Node\Expr\MethodCall || ! $call->name instanceof Node\Identifier) {
                continue;
            }

            $method = $call->name->toLowerString();
            if (in_array($method, self::ROUTE_VERBS, true)) {
                $verbs[$call->name->getStartLine()] = ($verbs[$call->name->getStartLine()] ?? 0) + 1;
            }

            // Route::post(...)->middleware(...) / ->withoutMiddleware(...): the verb is
            // further down the chain
            if (in_array($method, ['middleware', 'withoutmiddleware'], true)
                && ($verb = $this->routeVerbIn($call->var)) !== null && $verb->name instanceof Node\Identifier) {
                $line = $verb->name->getStartLine();
                $statements[$line] ??= ['middleware' => [], 'excluded' => []];
                if ($method === 'middleware') {
                    array_push($statements[$line]['middleware'], ...$this->middlewareArgumentNames($call, $bootstrapParser));
                } else {
                    array_push($statements[$line]['excluded'], ...$this->excludedMiddlewareNames($call));
                }
            }

            if ($method === 'group' && isset($routerGroups[spl_object_id($call)])) {
                [$middleware, $excluded, $controller] = $this->chainMiddleware($call->var, $bootstrapParser);
                $this->collectGroupMiddleware($call->args, $middleware, $excluded, $controller, $groups, $bootstrapParser);
            }

            // Route::middleware(...)->post(...), a verb chained after another Route:: call,
            // or $router->post(...) / $guest->post(...) on a variable holding the router or a
            // registrar
            $onRouter = $call->getAttribute(BootstrapRouteParser::ROUTE_ON_ROUTER);
            $chained = $this->chainStartsAtRoute($call->var);
            if (in_array($method, self::ROUTE_VERBS, true) && $chained) {
                $line = $call->name->getStartLine();
                [$middleware, $excluded] = $this->chainMiddleware($call->var, $bootstrapParser);
                $statements[$line] ??= ['middleware' => [], 'excluded' => []];
                array_push($statements[$line]['middleware'], ...$middleware);
                array_push($statements[$line]['excluded'], ...$excluded);
                $this->recordRouteAction($call, $method, $line, $actions);
                // A chain on the facade is read whatever its middleware, as it always was, and
                // its URI as a plain string literal; its URI and action now by name too, and a
                // match() by the methods it lists (see routeCallVerbs())
                $this->recordRouteCall($call, $method, false, true, $source, $routes);
            } elseif (in_array($method, self::ROUTE_VERBS, true) && is_bool($onRouter) && ! $this->chainStartsAtOtherClass($call->var)) {
                $receiverRoutes[] = [$call, $method, $onRouter];
            }
        }

        foreach ($this->parser->findNodes($ast, Node\Expr\StaticCall::class) as $call) {
            if (! $call instanceof Node\Expr\StaticCall || ! $call->name instanceof Node\Identifier) {
                continue;
            }

            $method = $call->name->toLowerString();
            if ($method === 'group' && isset($routerGroups[spl_object_id($call)])) {
                $this->collectGroupMiddleware($call->args, [], [], null, $groups, $bootstrapParser);
            }

            if (in_array($method, self::ROUTE_VERBS, true)) {
                $verbs[$call->name->getStartLine()] = ($verbs[$call->name->getStartLine()] ?? 0) + 1;
                $this->recordRouteAction($call, $method, $call->name->getStartLine(), $actions);
            }

            if ((in_array($method, self::ROUTE_VERBS, true) || $method === 'controller') && $this->registersOnFacade($call)) {
                $line = $call->name->getStartLine();
                $recorded = count($routes[$line] ?? []);
                $this->recordRouteCall($call, $method, true, false, $source, $routes);
                // A Route::controller('...') route is one the line reports too
                if ($method === 'controller' && count($routes[$line] ?? []) > $recorded) {
                    $reported[$line] = ($reported[$line] ?? 0) + 1;
                }
            }

            // So is Auth::routes()
            if ($method === 'routes' && $call->class instanceof Node\Name && strcasecmp($call->class->getLast(), 'Auth') === 0) {
                $reported[$call->name->getStartLine()] = ($reported[$call->name->getStartLine()] ?? 0) + 1;
            }
        }

        // A route on the router or a registrar held in a variable is read only alone on its
        // line, Auth::routes() and Route::controller('...') counted with the verbs: statements
        // and actions are keyed by line, so its middleware and its action would reach another
        // route there. Its middleware is read unless the variable's value cannot be, as no
        // throttle it may carry can be ruled out.
        foreach ($receiverRoutes as [$call, $method, $onRouter]) {
            if (! $call->name instanceof Node\Identifier || ($verbs[$line = $call->name->getStartLine()] ?? 0) + ($reported[$line] ?? 0) !== 1) {
                continue;
            }

            [$middleware, $excluded, , $unread] = $this->chainMiddleware($call->var, $bootstrapParser, $onRouter);
            if ($unread) {
                continue;
            }
            $statements[$line] ??= ['middleware' => [], 'excluded' => []];
            array_push($statements[$line]['middleware'], ...$middleware);
            array_push($statements[$line]['excluded'], ...$excluded);
            $this->recordRouteAction($call, $method, $line, $actions);
            $this->recordRouteCall($call, $method, false, false, $source, $routes);
        }

        // Statements are keyed by line, so with two routes on a line, on any receiver, an
        // exclusion cannot be told apart from the other route's, and none is read
        foreach ($statements as $line => $statement) {
            if (($verbs[$line] ?? 0) > 1) {
                $statements[$line]['excluded'] = [];
            }
        }

        return [$statements, $groups, $actions, $routes];
    }

    /**
     * Records the action a route verb call names, under the line its verb is on.
     * Route::match() takes its methods first, the others their URI, each by position
     * or by name (see routeArgument()). A resource route names its controller with no
     * method: its routes reach several.
     *
     * @param  array<int, array{class: ?string, method: ?string}>  $actions
     */
    private function recordRouteAction(Node\Expr\MethodCall|Node\Expr\StaticCall $call, string $verb, int $line, array &$actions): void
    {
        $action = match ($verb) {
            'match' => self::routeArgument($call, 2, 'action'),
            'resource' => self::routeArgument($call, 1, 'controller'),
            default => self::routeArgument($call, 1, 'action'),
        };
        if ($action !== null && ($routeAction = $this->routeAction($action->value)) !== null) {
            $actions[$line] = $verb === 'resource' ? ['class' => $routeAction['class'], 'method' => null] : $routeAction;
        }
    }

    /**
     * Records the route a verb call registers, under the line its verb is on, when its
     * URI can be read (see routeUri()) and so can the methods a match() call lists (see
     * routeCallVerbs()). A static call whose URI comes first by position is the
     * Route::post('...') form a written route takes. Every URI but that of a verb chained
     * after a Route facade call is read as written (see routeUri()).
     *
     * @param  bool  $chained  Whether the verb is chained after a Route facade call
     * @param  array<int, list<RouteCall>>  $routes
     */
    private function recordRouteCall(Node\Expr\MethodCall|Node\Expr\StaticCall $call, string $verb, bool $static, bool $chained, string $source, array &$routes): void
    {
        $uri = match ($verb) {
            'match' => self::routeArgument($call, 1, 'uri'),
            'resource' => self::routeArgument($call, 0, 'name'),
            'controller' => self::routeArgument($call, 0, 'controller'),
            default => self::routeArgument($call, 0, 'uri'),
        };
        $written = $static && $verb !== 'match' && $uri !== null && $uri->name === null;
        $text = $uri !== null ? $this->routeUri($uri->value, ! $chained, $source) : null;
        $verbs = $this->routeCallVerbs($call, $verb, $chained);
        if ($text === null || $verbs === null || ! $call->name instanceof Node\Identifier) {
            return;
        }

        $routes[$call->name->getStartLine()][] = ['verbs' => $verbs, 'uri' => $text, 'written' => $written, 'chained' => $chained, 'offset' => $call->getStartFilePos()];
    }

    /**
     * The verbs a route call answers, lowercase: its own, or for match() each method its
     * first argument lists, a string or a list of strings, by position or by name, or
     * a variable holding one (see heldValue()). Null when a match() call's methods
     * cannot be read, unless it is chained after a Route facade call, which stays
     * the match route it always was.
     *
     * @return list<string>|null
     */
    private function routeCallVerbs(Node\Expr\MethodCall|Node\Expr\StaticCall $call, string $verb, bool $chained): ?array
    {
        if ($verb !== 'match') {
            return [$verb];
        }

        $methods = self::routeArgument($call, 0, 'methods');
        $value = $methods !== null ? self::heldValue($methods->value) : null;
        $items = $value instanceof Node\Expr\Array_ ? $value->items : [$value];
        $verbs = [];
        foreach ($items as $item) {
            $method = $item instanceof Node\Expr\ArrayItem && ! $item->unpack ? $item->value : $item;
            if (! $method instanceof Node\Scalar\String_) {
                return $chained ? ['match'] : null;
            }
            $verbs[] = strtolower($method->value);
        }

        return $verbs;
    }

    /**
     * The URI a route call's argument gives. One read $asWritten is read as the
     * Route::post('...') text match always read it: the string literal it starts with,
     * the leftmost operand of a concatenation, from its opening quote to the next quote,
     * as written, interpolation and escapes included; a heredoc for its value. A verb
     * chained after a Route facade call keeps the reading it always had: a plain string
     * literal, for its value.
     *
     * @param  string  $source  The file as written, which the AST positions index
     */
    private function routeUri(Node\Expr $uri, bool $asWritten, string $source): ?string
    {
        if (! $asWritten) {
            return $uri instanceof Node\Scalar\String_ ? $uri->value : null;
        }

        while ($uri instanceof Node\Expr\BinaryOp\Concat) {
            $uri = $uri->left;
        }
        $literal = $uri instanceof Node\Scalar\InterpolatedString || $uri instanceof Node\Scalar\String_;
        if ($literal && in_array($uri->getAttribute('kind'), [Node\Scalar\String_::KIND_SINGLE_QUOTED, Node\Scalar\String_::KIND_DOUBLE_QUOTED], true)) {
            $text = substr($source, $uri->getStartFilePos() + 1, max(0, $uri->getEndFilePos() - $uri->getStartFilePos() - 1));

            return substr($text, 0, strcspn($text, '"\''));
        }

        return $uri instanceof Node\Scalar\String_ ? $uri->value : null;
    }

    /**
     * Whether a method chain, followed through a variable that holds part of it (see
     * heldValue()), starts at a static call on a class other than the Route facade (see
     * namesRouteFacade()), such as one imported as App\Support\Route under another name.
     */
    private function chainStartsAtOtherClass(Node\Expr $node): bool
    {
        $node = self::heldValue($node);
        while ($node instanceof Node\Expr\MethodCall) {
            $node = self::heldValue($node->var);
        }

        return $node instanceof Node\Expr\StaticCall && $node->class instanceof Node\Name && ! $this->namesRouteFacade($node->class);
    }

    /**
     * A route call's argument, by its parameter's name or, when no argument names it, by
     * its position among the positional ones, which PHP requires first.
     */
    private static function routeArgument(Node\Expr\MethodCall|Node\Expr\StaticCall $call, int $position, string $name): ?Node\Arg
    {
        foreach ($call->args as $index => $arg) {
            if ($arg instanceof Node\Arg && ! $arg->unpack && ($arg->name !== null ? $arg->name->toString() === $name : $index === $position)) {
                return $arg;
            }
        }

        return null;
    }

    /**
     * Whether a static call is made on the Route facade: a class whose name ends in
     * Route as written, as the Route::post( text match always read it, or one the file
     * imports as Illuminate\Support\Facades\Route under another name.
     */
    private function registersOnFacade(Node\Expr\StaticCall $call): bool
    {
        return $call->class instanceof Node\Name
            && (str_ends_with($call->class->toString(), 'Route') || $this->namesRouteFacade($call->class));
    }

    /**
     * Whether a class name is the Route facade: Route as written, or a name the file's
     * imports resolve to Illuminate\Support\Facades\Route.
     */
    private function namesRouteFacade(Node\Name $class): bool
    {
        return $class->getLast() === 'Route' || $this->resolvedClassFqn($class) === 'Illuminate\\Support\\Facades\\Route';
    }

    /**
     * The route verb call nearest the end of a method chain, followed through a variable
     * that holds part of it (see heldValue()), so $route->middleware(...) reaches the
     * Route::post(...) $route was assigned, or null when the chain reaches its Route:: start
     * without one.
     */
    private function routeVerbIn(Node\Expr $node): Node\Expr\MethodCall|Node\Expr\StaticCall|null
    {
        $node = self::heldValue($node);
        while ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) {
            if ($node->name instanceof Node\Identifier && in_array($node->name->toLowerString(), self::ROUTE_VERBS, true)) {
                return $node;
            }

            if ($node instanceof Node\Expr\StaticCall) {
                return null;
            }
            $node = self::heldValue($node->var);
        }

        return null;
    }

    /**
     * Whether a method chain starts with a call on the Route facade (see
     * namesRouteFacade()), so a verb called on it registers a route.
     */
    private function chainStartsAtRoute(Node\Expr $node): bool
    {
        while ($node instanceof Node\Expr\MethodCall) {
            $node = $node->var;
        }

        return $node instanceof Node\Expr\StaticCall
            && $node->class instanceof Node\Name
            && $this->namesRouteFacade($node->class);
    }

    /**
     * The controller method a route action calls: [X::class, 'method'], 'X@method',
     * an invokable X::class (__invoke), or a bare 'method' a Route::controller()
     * group resolves, with no class. An X::class name is resolved against the
     * import table; an 'X@method' string is kept as written, as
     * controllersReferencedByRoute() keeps it.
     *
     * @return array{class: ?string, method: string}|null
     */
    private function routeAction(Node\Expr $action): ?array
    {
        if ($action instanceof Node\Expr\Array_) {
            $class = $action->items[0]->value ?? null;
            $method = $action->items[1]->value ?? null;

            return $class instanceof Node\Expr\ClassConstFetch && $class->class instanceof Node\Name
                && $method instanceof Node\Scalar\String_
                ? ['class' => $this->resolvedClassFqn($class->class), 'method' => $method->value]
                : null;
        }

        if ($action instanceof Node\Expr\ClassConstFetch && $action->class instanceof Node\Name) {
            return ['class' => $this->resolvedClassFqn($action->class), 'method' => '__invoke'];
        }

        if ($action instanceof Node\Scalar\String_) {
            $at = strpos($action->value, '@');

            return $at === false
                ? ['class' => null, 'method' => $action->value]
                : ['class' => ltrim(substr($action->value, 0, $at), '\\'), 'method' => substr($action->value, $at + 1)];
        }

        return null;
    }

    /**
     * The middleware, and any Route::controller() controller, of the groups each
     * group-registered route file sits in, keyed by the file's normalized path, as
     * a group that spans the whole file, one per registration. Middleware and
     * excluded middleware merge from every enclosing group, and the innermost
     * controller wins. Each group is resolved against the imports of the file that
     * declares it.
     *
     * A file a route file loads, by require/include or a group path argument, gets one
     * registration for each path that reaches it: the registration of the file that loads
     * it merged with the groups around the load, down chains of any depth, as Laravel
     * loads it in that context. A path never re-enters a file already on it, as a
     * require_once back to it loads nothing. Paths start at the bootstrap and provider
     * registrations and at the files the framework registers itself (see
     * frameworkRegisteredFiles()), its web files in the 'web' group and its api files
     * under its api prefix. A registration carries only the middleware its groups name, so
     * a file registered without 'web' does not get the web group's.
     * A route file no path reaches and no route file loads is taken to load in the 'web'
     * group, unless it is routes/api.php, and passes that only to files no other path
     * reaches, so a route file nothing loads never uncovers a registered one. A file also
     * joins $apiFiles when a file in it loads it.
     *
     * @param  array<string, true>  $apiFiles  Files in the 'api' group, by normalized path
     * @return array<string, list<RouteGroup>>
     */
    private function fileGroupMiddleware(BootstrapRouteParser $bootstrapParser, array &$apiFiles): array
    {
        $loads = [];
        foreach ($bootstrapParser->getRouteFileLoads() as $source => $sourceLoads) {
            foreach ($sourceLoads as $load) {
                $loads[$source][] = ['file' => $load['file'], 'group' => $this->registrationGroup($source, $load['calls'], $bootstrapParser)];
            }
        }

        $groups = [];
        $external = [];
        foreach ($bootstrapParser->getGroupRegisteredRouteFiles(routeFiles: false) as $registration) {
            $external[$registration['file']] = true;
            $this->followLoads($registration['file'], $this->registrationGroup($registration['source'], $registration['calls'], $bootstrapParser), [], $loads, $groups);
        }

        $unregistered = ['start' => 1, 'end' => PHP_INT_MAX, 'middleware' => [], 'excluded' => [], 'controller' => null, 'registration' => true, 'scope' => ''];
        $web = [...$unregistered, 'middleware' => $this->resolvedMiddlewareNames('web')];
        $loaded = [];
        foreach ($loads as $source => $sourceLoads) {
            // routes/api.php is judged as an api file by its name, so what it loads is too
            if (str_ends_with($source, '/routes/api.php')) {
                $apiFiles[$source] = true;
            }
            foreach ($sourceLoads as $load) {
                if ($load['file'] !== $source) {
                    $loaded[$load['file']] = true;
                }
            }
        }
        foreach ($this->frameworkRegisteredFiles($bootstrapParser) as $file => $api) {
            if (! isset($external[$file])) {
                $this->followLoads($file, $api ? [...$unregistered, 'scope' => $this->apiPrefixScope()] : $web, [], $loads, $groups);
            }
        }

        $reached = $groups;
        foreach (array_keys($loads) as $source) {
            if (! isset($reached[$source]) && ! isset($loaded[$source])) {
                $this->followLoads($source, str_ends_with($source, '/routes/api.php') ? $unregistered : $web, $reached, $loads, $groups);
            }
        }

        do {
            $changed = false;
            foreach ($loads as $source => $sourceLoads) {
                foreach ($sourceLoads as $load) {
                    if (isset($apiFiles[$source]) && ! isset($apiFiles[$load['file']])) {
                        $apiFiles[$load['file']] = true;
                        $changed = true;
                    }
                }
            }
        } while ($changed);

        return array_map(array_values(...), $groups);
    }

    /**
     * Records $group as a registration of $file and passes it down every load $file
     * makes, merged with the groups around the load, skipping files already on this path
     * and files in $frozen. A registration already recorded for a file is not followed
     * again, which keeps a graph of many paths linear; only a require cycle can then
     * depend on the order the registrations are read in.
     *
     * @param  RouteGroup  $group
     * @param  array<string, mixed>  $frozen  Files this pass leaves as they are
     * @param  array<string, list<array{file: string, group: RouteGroup}>>  $loads
     * @param  array<string, array<string, RouteGroup>>  $groups
     * @param  array<string, true>  $path  Files on the path that reached $file
     */
    private function followLoads(string $file, array $group, array $frozen, array $loads, array &$groups, array $path = []): void
    {
        $key = $this->groupKey($group);
        if (isset($frozen[$file]) || isset($groups[$file][$key])) {
            return;
        }
        $groups[$file][$key] = $group;
        $path[$file] = true;

        foreach ($loads[$file] ?? [] as $load) {
            if (isset($path[$load['file']])) {
                continue;
            }

            $this->followLoads($load['file'], [
                ...$group,
                'middleware' => array_values(array_unique([...$group['middleware'], ...$load['group']['middleware']])),
                'excluded' => array_values(array_unique([...$group['excluded'], ...$load['group']['excluded']])),
                'controller' => $load['group']['controller'] ?? $group['controller'],
                'scope' => self::nestedScope($group['scope'], $load['group']['scope']),
            ], $frozen, $loads, $groups, $path);
        }
    }

    /**
     * The withRouting() call in bootstrap/app.php, if any.
     */
    private function withRoutingCall(): ?Node\Expr\MethodCall
    {
        $bootstrap = $this->getBasePath().DIRECTORY_SEPARATOR.'bootstrap'.DIRECTORY_SEPARATOR.'app.php';
        if (! file_exists($bootstrap)) {
            return null;
        }

        foreach ($this->parser->findMethodCalls($this->parser->parseFile($bootstrap), 'withRouting') as $call) {
            if ($call instanceof Node\Expr\MethodCall) {
                return $call;
            }
        }

        return null;
    }

    /**
     * The route files the framework registers itself, by normalized path, each mapped to
     * whether it registers the file in the 'api' group rather than the 'web' one: those
     * withRouting() names under web: and api:, by name or by position, unless a using:
     * callback replaces them, and routes/web.php. With no bootstrap/app.php to say
     * otherwise, routes/api.php is taken to be registered too. A provider that registers a
     * file is read as a registration of its own.
     *
     * @return array<string, bool>
     */
    private function frameworkRegisteredFiles(BootstrapRouteParser $bootstrapParser): array
    {
        $routes = $this->getBasePath().DIRECTORY_SEPARATOR.'routes'.DIRECTORY_SEPARATOR;
        $files = [];
        foreach (['web.php' => false, 'api.php' => true] as $name => $api) {
            $real = realpath($routes.$name);
            if ($real !== false && (! $api || ! file_exists($this->getBasePath().DIRECTORY_SEPARATOR.'bootstrap'.DIRECTORY_SEPARATOR.'app.php'))) {
                $files[str_replace('\\', '/', $real)] = $api;
            }
        }

        $call = $this->withRoutingCall();
        $using = $call === null ? null : $this->callArgument($call, 0, 'using');
        if ($call === null || ($using !== null && ! ($using instanceof Node\Expr\ConstFetch && $using->name->toLowerString() === 'null'))) {
            return $files;
        }

        foreach ($bootstrapParser->withRoutingFiles('web') as $file) {
            $files[$file] = false;
        }
        foreach ($bootstrapParser->withRoutingFiles('api') as $file) {
            $files[$file] = true;
        }

        return $files;
    }

    /**
     * The scope (see groupScope()) withRouting() registers its api files under: its
     * apiPrefix argument, by name or by position, 'api' by default. A computed prefix is a
     * scope of its own, equal to no other, so another registration's throttle does not
     * cover it.
     */
    private function apiPrefixScope(): string
    {
        $call = $this->withRoutingCall();
        $prefix = $call === null ? null : $this->callArgument($call, 7, 'apiPrefix');
        if ($prefix === null) {
            return self::scopeOf('', 'api');
        }

        return $prefix instanceof Node\Scalar\String_
            ? self::scopeOf('', $prefix->value)
            : '|'.self::unknownMiddlewareText($prefix);
    }

    /**
     * The whole-file group a registration's group calls give the file it loads, read
     * against the imports of $source, the file that declares them. A group whose middleware
     * this cannot read may name 'web', so the registration keeps the 'web' group's
     * middleware, as a file no registration reaches does.
     *
     * @param  list<Node\Expr\MethodCall|Node\Expr\StaticCall>  $calls  Outermost first
     * @return RouteGroup
     */
    private function registrationGroup(string $source, array $calls, BootstrapRouteParser $bootstrapParser): array
    {
        $this->trackFileImports($this->parser->parseFile($source));
        $middleware = [];
        $excluded = [];
        $controller = null;
        $scope = '';
        $unread = false;
        foreach ($calls as $call) {
            [$chainMiddleware, $chainExcluded, $chainController, $chainUnread] = $call instanceof Node\Expr\MethodCall ? $this->chainMiddleware($call->var, $bootstrapParser) : [[], [], null, false];
            $unread = $unread || $chainUnread || $this->attributeMiddlewareUnread($call->args);
            array_push($middleware, ...$chainMiddleware, ...$this->groupAttributeMiddleware($call->args, 'middleware'));
            array_push($excluded, ...$chainExcluded, ...$this->groupAttributeMiddleware($call->args, 'excluded_middleware'));
            $controller = $chainController ?? $controller;
            $scope = self::nestedScope($scope, $this->groupScope($call));
        }
        if ($unread) {
            array_push($middleware, ...$this->resolvedMiddlewareNames('web'));
        }

        return ['start' => 1, 'end' => PHP_INT_MAX, 'middleware' => $middleware, 'excluded' => $excluded, 'controller' => $controller, 'registration' => true, 'scope' => $scope];
    }

    /**
     * The domain and URI prefix one group call gives its routes, as 'domain|prefix' or
     * empty for neither (see scopeOf()), from
     * ->domain(...) / ->prefix(...) on its chain, the last one winning as RouteRegistrar
     * keeps it, or its 'domain' / 'prefix' attributes. A domain or prefix that is not a
     * literal gives a scope of its own, equal to no other, so another registration's
     * throttle does not cover it.
     */
    private function groupScope(Node\Expr\MethodCall|Node\Expr\StaticCall $call): string
    {
        $values = ['domain' => '', 'prefix' => ''];
        $node = $call;
        $chain = [];
        while ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) {
            array_unshift($chain, $node);
            if (! $node instanceof Node\Expr\MethodCall) {
                break;
            }
            $node = self::heldValue($node->var);
        }

        foreach ($chain as $link) {
            $name = $link->name instanceof Node\Identifier ? $link->name->toLowerString() : '';
            $first = $link->args[0] ?? null;
            if (isset($values[$name]) && $link !== $call) {
                if (! $first instanceof Node\Arg || ! $first->value instanceof Node\Scalar\String_) {
                    return self::unknownMiddlewareText($link).'|';
                }
                $values[$name] = $first->value->value;
            }
        }

        foreach ($call->args as $arg) {
            $attributes = $arg instanceof Node\Arg ? self::heldValue($arg->value) : null;
            if ($attributes instanceof Node\Expr\Array_) {
                foreach ($attributes->items as $item) {
                    if ($item instanceof Node\Expr\ArrayItem && $item->key instanceof Node\Scalar\String_ && isset($values[$item->key->value])) {
                        if (! $item->value instanceof Node\Scalar\String_) {
                            return self::unknownMiddlewareText($item->value).'|';
                        }
                        $values[$item->key->value] = $item->value->value;
                    }
                }
            }
        }

        return self::scopeOf($values['domain'], $values['prefix']);
    }

    /**
     * A scope as groupScope() writes it: empty for no domain and no prefix.
     */
    private static function scopeOf(string $domain, string $prefix): string
    {
        $prefix = trim($prefix, '/');

        return $domain === '' && $prefix === '' ? '' : $domain.'|'.$prefix;
    }

    /**
     * The scope (see groupScope()) a group gives routes nested in an outer scope: Laravel
     * appends the inner prefix to the outer one and lets an inner domain replace the outer.
     */
    private static function nestedScope(string $outer, string $inner): string
    {
        if ($outer === '') {
            return $inner;
        }
        if ($inner === '') {
            return $outer;
        }

        [$outerDomain, $outerPrefix] = explode('|', $outer, 2) + [1 => ''];
        [$innerDomain, $innerPrefix] = explode('|', $inner, 2) + [1 => ''];

        return self::scopeOf($innerDomain !== '' ? $innerDomain : $outerDomain, $outerPrefix.'/'.$innerPrefix);
    }

    /**
     * What tells two whole-file groups apart: their middleware and excluded middleware
     * as sets, their controller and their scope.
     *
     * @param  RouteGroup  $group
     */
    private function groupKey(array $group): string
    {
        $middleware = array_unique($group['middleware']);
        $excluded = array_unique($group['excluded']);
        sort($middleware);
        sort($excluded);

        return serialize([$middleware, $excluded, $group['controller'], $group['scope']]);
    }

    /**
     * The middleware a group's attribute array, or a variable holding one (see
     * heldValue()), lists under $key, 'middleware' or 'excluded_middleware', as resolved
     * names.
     *
     * @param  array<Node>  $args
     * @return list<string>
     */
    private function groupAttributeMiddleware(array $args, string $key): array
    {
        $names = [];
        foreach ($args as $arg) {
            $attributes = $arg instanceof Node\Arg ? self::heldValue($arg->value) : null;
            if ($attributes instanceof Node\Expr\Array_) {
                foreach ($attributes->items as $item) {
                    if ($item instanceof Node\Expr\ArrayItem
                        && $item->key instanceof Node\Scalar\String_
                        && $item->key->value === $key) {
                        array_push($names, ...$this->middlewareNamesIn($item->value));
                    }
                }
            }
        }

        return $names;
    }

    /**
     * Records the range of each closure a group loads, including each closure in a list,
     * with the middleware its chain and its attribute array apply and exclude, when there
     * is a closure and any.
     *
     * @param  array<Node>  $args
     * @param  list<string>  $middleware  Middleware the group's method chain applies (see chainMiddleware())
     * @param  list<string>  $excluded  Middleware the group's method chain excludes
     * @param  ?string  $controller  The controller the group's method chain names
     * @param  list<RouteGroup>  $groups
     */
    private function collectGroupMiddleware(array $args, array $middleware, array $excluded, ?string $controller, array &$groups, BootstrapRouteParser $bootstrapParser): void
    {
        array_push($middleware, ...$this->groupAttributeMiddleware($args, 'middleware'));
        array_push($excluded, ...$this->groupAttributeMiddleware($args, 'excluded_middleware'));

        if ($middleware === [] && $excluded === [] && $controller === null) {
            return;
        }

        foreach ($bootstrapParser->closureArguments($args) as $closure) {
            $groups[] = ['start' => $closure->getStartLine(), 'end' => $closure->getEndLine(), 'middleware' => $middleware, 'excluded' => $excluded, 'controller' => $controller, 'registration' => false, 'scope' => ''];
        }
    }

    /**
     * What a registrar chain, the calls before a group() or a route verb, sends its routes
     * through, followed through a variable that holds part of it (see heldValue()): the
     * middleware its last ->middleware(...) / Route::middleware(...) call applies, as each
     * middleware() call replaces the last, and the middleware every ->withoutMiddleware(...)
     * call excludes, as RouteRegistrar merges those, as resolved names, and the controller a
     * ->controller(X::class) / Route::controller(X::class) call names, whose routes give
     * only a method. An ->attribute(...) call is read as the call it stands for (see
     * BootstrapRouteParser::attributeStandIn()). The fourth says whether that middleware call names one this cannot
     * read, or, with no middleware call, the chain starts at a variable whose value this
     * cannot read, unless $routerItself says the variable holds the router itself (see
     * BootstrapRouteParser::ROUTE_ON_ROUTER), which carries no middleware.
     *
     * @return array{0: list<string>, 1: list<string>, 2: ?string, 3: bool}
     */
    private function chainMiddleware(Node\Expr $node, BootstrapRouteParser $bootstrapParser, bool $routerItself = false): array
    {
        $middleware = null;
        $unread = false;
        $excluded = [];
        $controller = null;
        $node = self::heldValue($node);
        while ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) {
            // ->attribute('middleware', ...) reads as the call it stands for
            $call = $bootstrapParser->attributeStandIn($node);
            $first = $call->args[0] ?? null;
            if ($call->name instanceof Node\Identifier && $first instanceof Node\Arg) {
                $method = $call->name->toLowerString();
                if ($method === 'middleware') {
                    // Walking inward, the first call met is the last one written
                    if ($middleware === null) {
                        $middleware = $this->middlewareArgumentNames($call, $bootstrapParser);
                        $unread = array_filter($bootstrapParser->middlewareEntries($call), $this->middlewareUnread(...)) !== [];
                    }
                } elseif ($method === 'withoutmiddleware') {
                    array_push($excluded, ...$this->excludedMiddlewareNames($call));
                } elseif ($method === 'controller') {
                    $controller = $this->middlewareClassName($first->value);
                }
            }

            if (! $node instanceof Node\Expr\MethodCall) {
                break;
            }
            // A registrar held in a variable continues the chain it was assigned
            $node = self::heldValue($node->var);
        }

        // A chain that starts at a variable whose value cannot be read may hold any middleware
        $unread = $unread || ($middleware === null && $node instanceof Node\Expr\Variable && ! $routerItself);

        return [$middleware ?? [], $excluded, $controller, $unread];
    }

    /**
     * Whether a middleware value, one or a list, or a variable holding one (see
     * heldValue()), names a middleware this cannot read, such as config('auth.middleware').
     */
    private function middlewareUnread(Node\Expr $expr): bool
    {
        $expr = self::heldValue($expr);
        if ($expr instanceof Node\Expr\Array_) {
            foreach ($expr->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem && $this->middlewareUnread($item->value)) {
                    return true;
                }
            }

            return false;
        }

        return $this->middlewareText($expr) === null;
    }

    /**
     * Whether a group call's attributes may name middleware this cannot read: the
     * attributes Router::group() takes, positionally first when it is given its routes
     * too or by the name attributes:, are read only as an array literal, or a variable
     * holding one (see heldValue()), whose 'middleware' entry, if any, this can read (see
     * middlewareUnread()). Anything else, such as config(...), an array union,
     * array_merge() or a list spread from anything but a literal, may hold any middleware.
     *
     * @param  array<Node>  $args
     */
    private function attributeMiddlewareUnread(array $args): bool
    {
        $attributes = null;
        foreach ($args as $index => $arg) {
            if ($arg instanceof Node\Arg && ($arg->name !== null ? $arg->name->toString() === 'attributes' : $index === 0 && count($args) > 1)) {
                $attributes = $arg->value;
            }
        }

        return $attributes !== null && $this->attributesUnread(self::heldValue($attributes));
    }

    /**
     * Whether a group's attributes are anything but an array literal whose 'middleware'
     * entry, if any, this can read, a list spread into it read the same way.
     */
    private function attributesUnread(Node\Expr $attributes): bool
    {
        if (! $attributes instanceof Node\Expr\Array_) {
            return true;
        }

        foreach ($attributes->items as $item) {
            if (! $item instanceof Node\Expr\ArrayItem) {
                continue;
            }
            if ($item->unpack ? $this->attributesUnread(self::heldValue($item->value))
                : $item->key instanceof Node\Scalar\String_ && $item->key->value === 'middleware' && $this->middlewareUnread($item->value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The value a variable holds where it is read, as BootstrapRouteParser's walk of its
     * file reads it (see BootstrapRouteParser::HELD_VALUE), or the expression itself.
     */
    private static function heldValue(Node\Expr $expr): Node\Expr
    {
        $value = $expr instanceof Node\Expr\Variable ? $expr->getAttribute(BootstrapRouteParser::HELD_VALUE) : null;

        return $value instanceof Node\Expr ? $value : $expr;
    }

    /**
     * The middleware a route's or group's ->withoutMiddleware(...) call excludes, as
     * resolved names: its first argument, a list or one middleware. Laravel wraps only
     * that argument, so ->withoutMiddleware('auth', 'throttle:6,1') excludes 'auth' alone.
     *
     * @return list<string>
     */
    private function excludedMiddlewareNames(Node\Expr\MethodCall|Node\Expr\StaticCall $call): array
    {
        $first = $call->args[0] ?? null;

        return $first instanceof Node\Arg ? $this->middlewareNamesIn($first->value) : [];
    }

    /**
     * The middleware a route's or group's ->middleware(...) call names, as resolved
     * names, with its arguments read as BootstrapRouteParser::middlewareEntries() reads
     * them: ->middleware('auth', 'throttle:6,1') names both, while
     * ->middleware(['auth'], 'throttle:6,1') names only 'auth'.
     *
     * @return list<string>
     */
    private function middlewareArgumentNames(Node\Expr\MethodCall|Node\Expr\StaticCall $call, BootstrapRouteParser $bootstrapParser): array
    {
        $names = [];
        foreach ($bootstrapParser->middlewareEntries($call) as $entry) {
            array_push($names, ...$this->middlewareNamesIn($entry));
        }

        return $names;
    }

    /**
     * Whether a middleware applied to the route on this 1-based line and not excluded
     * from it throttles login, or a controller a group around it names does.
     *
     * The route gets the middleware its file's group gives ($fileMiddleware), its own
     * statement's, every in-file group's around it and one file registration's, minus
     * what any of them excludes: Laravel merges both down nested groups and drops an
     * applied middleware only when an excluded one resolves to the same name and
     * parameters. Laravel registers a file's routes once per registration, so a file
     * registered under several domains or prefixes is covered only when each of them is.
     * Registrations under the same domain and prefix register the same routes, so any of
     * them covers those. A group's controller is judged, for the method the route calls, only
     * when the route's action names a method and no class: a route that names its own
     * controller does not reach the group's.
     *
     * $classes, when given, also credits those classes, the ones the route's action names,
     * as routeClassesThrottle() judges them against the middleware each registration's copy
     * of the route excludes: Laravel gathers the
     * middleware a controller registers with the route's own before it excludes any, so
     * a registration that excludes it leaves its copy unthrottled, and only that one.
     *
     * @param  array<int, array{middleware: list<string>, excluded: list<string>}>  $statementMiddleware
     * @param  list<RouteGroup>  $groupMiddleware
     * @param  list<string>  $fileMiddleware
     * @param  array{class: ?string, method: ?string}|null  $action  See routeAction()
     * @param  array<int, string>|null  $classes
     */
    private function middlewareThrottles(int $line, array $statementMiddleware, array $groupMiddleware, array $fileMiddleware, ?array $action = null, ?array $classes = null): bool
    {
        $middleware = [...$fileMiddleware, ...$statementMiddleware[$line]['middleware'] ?? []];
        $excluded = $statementMiddleware[$line]['excluded'] ?? [];
        $registrations = [];
        $controllers = [];
        foreach ($groupMiddleware as $group) {
            if ($line < $group['start'] || $line > $group['end']) {
                continue;
            }

            if ($group['controller'] !== null && $action !== null && $action['class'] === null) {
                $controllers[] = $group['controller'];
            }

            if ($group['registration']) {
                $registrations[] = $group;
            } else {
                array_push($middleware, ...$group['middleware']);

                // Lines are all a route is known by, so a group's exclusion reaches only the
                // lines strictly inside its closure: the lines it opens and closes on can hold
                // routes outside it
                if ($line > $group['start'] && $line < $group['end']) {
                    array_push($excluded, ...$group['excluded']);
                }
            }
        }

        if ($registrations === []) {
            return $this->covers($middleware, $excluded, $controllers, $action, $classes);
        }

        // Registrations with the same domain and prefix register the same routes, and the
        // last one replaces the others, or only one of them runs, so any of them covers
        // the routes; registrations with a different domain or prefix, a computed one
        // included, each register their own, and each must.
        $scopes = [];
        foreach ($registrations as $registration) {
            $scopes[$registration['scope']][] = $registration;
        }

        foreach ($scopes as $scoped) {
            $covered = false;
            foreach ($scoped as $registration) {
                $covered = $covered || $this->covers([...$middleware, ...$registration['middleware']], [...$excluded, ...$registration['excluded']], $controllers, $action, $classes);
            }
            if (! $covered) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether one copy of a route, with this middleware and these exclusions, is throttled:
     * a middleware it keeps throttles login (see namesThrottle()), or a group's controller
     * or one of $classes does, judged against the exclusions.
     *
     * @param  list<string>  $middleware  Resolved names
     * @param  list<string>  $excluded  Resolved names
     * @param  list<string>  $controllers  The controllers of the groups around the route
     * @param  array{class: ?string, method: ?string}|null  $action
     * @param  array<int, string>|null  $classes
     */
    private function covers(array $middleware, array $excluded, array $controllers, ?array $action, ?array $classes): bool
    {
        if ($this->namesThrottle($middleware, $excluded) || ($classes !== null && $this->routeClassesThrottle($classes, $action, $excluded))) {
            return true;
        }
        foreach ($controllers as $controller) {
            if ($this->classThrottlesLogin($controller, $action['method'] ?? null, excluded: $excluded)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a middleware among $middleware that $excluded does not remove (see
     * isExcluded()) throttles login.
     *
     * @param  list<string>  $middleware  Resolved names
     * @param  list<string>  $excluded  Resolved names
     */
    private function namesThrottle(array $middleware, array $excluded): bool
    {
        foreach ($middleware as $name) {
            if (! $this->isExcluded($name, $excluded) && $this->resolvedNameThrottles($name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether Laravel's Router drops an applied middleware for the excluded ones: one
     * resolves to the same name, parameters included, or, both named without parameters,
     * the applied class extends an excluded one (see
     * MiddlewareThrottleDetector::extendsExcludedClass()).
     *
     * @param  string  $name  A resolved name
     * @param  list<string>  $excluded  Resolved names
     */
    private function isExcluded(string $name, array $excluded): bool
    {
        return in_array($name, $excluded, true) || MiddlewareThrottleDetector::extendsExcludedClass($name, $excluded);
    }

    /**
     * Whether a middleware registered with these resolved names survives the exclusions:
     * one of them is not excluded (see isExcluded()). Middleware whose names cannot be
     * read survives.
     *
     * @param  list<string>  $names
     * @param  list<string>  $excluded
     */
    private function survivesExclusion(array $names, array $excluded): bool
    {
        if ($names === [] || $excluded === []) {
            return true;
        }

        foreach ($names as $name) {
            if (! $this->isExcluded($name, $excluded)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Class names of the controllers a route definition points at, read from the
     * route's line up to the first line holding a ';', at most five lines.
     * Matches both the [X::class, 'method'] and the 'X@method' action forms.
     *
     * An X::class name is resolved against the file's imports. An 'X@method'
     * string is kept as written, without a leading backslash: Laravel resolves
     * it against the route group's controller namespace, which the file does not
     * state. Either way a name may still be partial, so
     * isCoveredController() matches it against the end of a class name.
     *
     * @param  array<int, string>  $lines
     * @return array<int, string>
     */
    private function controllersReferencedByRoute(array $lines, int $lineNumber): array
    {
        $statement = '';
        $end = min($lineNumber + 5, count($lines));
        for ($i = $lineNumber; $i < $end; $i++) {
            $statement .= $lines[$i] ?? '';

            if (str_contains($lines[$i] ?? '', ';')) {
                break;
            }
        }

        preg_match_all('/([A-Za-z_\\\\][A-Za-z0-9_\\\\]*)::class|["\']([A-Za-z0-9_\\\\]+)@\w+["\']/', $statement, $matches, PREG_SET_ORDER);

        $controllers = [];
        foreach ($matches as $match) {
            // Exactly one of the two alternatives matched
            if (($match[2] ?? '') !== '') {
                $controllers[] = ltrim($match[2], '\\');

                continue;
            }

            $name = $match[1] ?? '';
            $controllers[] = $this->resolvedClassFqn(
                str_starts_with($name, '\\') ? new Node\Name\FullyQualified(ltrim($name, '\\')) : new Node\Name($name)
            );
        }

        return $controllers;
    }

    /**
     * Check authentication controllers for throttling logic.
     *
     * @param  array<int, Issue>  &$issues
     * @param  array<string, true>  $coveredControllers  Controllers a throttled login route points at
     */
    private function checkAuthControllers(array &$issues, array $coveredControllers): void
    {
        $basePath = $this->getBasePath();
        $authControllers = [
            $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Controllers'.DIRECTORY_SEPARATOR.'Auth'.DIRECTORY_SEPARATOR.'LoginController.php',
            $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Controllers'.DIRECTORY_SEPARATOR.'AuthController.php',
            $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Controllers'.DIRECTORY_SEPARATOR.'LoginController.php',
        ];

        foreach ($authControllers as $controllerPath) {
            if (! file_exists($controllerPath)) {
                continue;
            }

            try {
                $ast = $this->parser->parseFile($controllerPath);
                if (empty($ast)) {
                    continue;
                }

                // Parameter types resolve against the controller's own imports
                $this->trackFileImports($ast);

                // Check if controller uses login-specific throttling
                if (! $this->hasLoginThrottlingInFile($controllerPath) && ! $this->usesLoginThrottlingTrait($controllerPath)) {
                    $classes = $this->parser->findClasses($ast);

                    foreach ($classes as $class) {
                        if (! isset($class->name)) {
                            continue;
                        }

                        $className = $class->name->toString();

                        if ($this->isCoveredController($this->controllerFqn($ast, $class), $coveredControllers)) {
                            continue;
                        }

                        // Middleware the controller registers on itself wraps the method it
                        // applies to. Throttling a parent or trait does is not credited: the
                        // methods reported here are declared on this class, overriding theirs.
                        $registered = [];
                        foreach ($class->getMethods() as $classMethod) {
                            array_push($registered, ...$this->middlewareRegisteredBy($classMethod));
                        }

                        // Look for login methods
                        if (! isset($class->stmts) || ! is_array($class->stmts)) {
                            continue;
                        }

                        foreach ($class->stmts as $stmt) {
                            if ($stmt instanceof Node\Stmt\ClassMethod) {
                                $methodName = $stmt->name->toString();

                                // Check for auth methods including __invoke (single-action controllers)
                                if (in_array($methodName, ['login', 'authenticate', 'postLogin', 'attempt', '__invoke'], true)
                                    && ! $this->delegatesToThrottlingRequest($stmt)
                                    && ! $this->registeredMiddlewareThrottles($registered, $methodName)) {
                                    $issues[] = $this->createIssueWithSnippet(
                                        message: sprintf('Authentication method %s::%s() lacks rate limiting', $className, $methodName),
                                        filePath: $controllerPath,
                                        lineNumber: $stmt->getLine(),
                                        severity: Severity::High,
                                        recommendation: 'Implement rate limiting using RateLimiter facade or throttle middleware to prevent brute force attacks',
                                        metadata: [
                                            'class' => $className,
                                            'method' => $methodName,
                                            'issue_type' => 'missing_controller_throttle',
                                        ]
                                    );
                                }
                            }
                        }
                    }
                }
            } catch (\Throwable $e) {
                // Silently fail if parsing fails
                continue;
            }
        }
    }

    /**
     * Whether middleware a controller registers on itself applies to this method, survives
     * the route's exclusions and throttles login.
     *
     * @param  array<int, RegisteredMiddleware>  $registered
     * @param  list<string>  $excluded  Resolved names the route excludes
     */
    private function registeredMiddlewareThrottles(array $registered, string $methodName, array $excluded = []): bool
    {
        $method = strtolower($methodName);
        foreach ($registered as $middleware) {
            if (($middleware['only'] === null || in_array($method, $middleware['only'], true))
                && ! in_array($method, $middleware['except'], true)
                && $this->survivesExclusion($middleware['names'], $excluded)
                && $this->classThrottlesLogin($middleware['class'])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Record the namespace and imports a file declares, replacing any earlier table.
     *
     * @param  array<Node>  $ast
     */
    private function trackFileImports(array $ast): void
    {
        $this->startTrackingImports();
        foreach ($ast as $stmt) {
            $this->trackImports($stmt);
            if ($stmt instanceof Node\Stmt\Namespace_) {
                foreach ($stmt->stmts as $inner) {
                    $this->trackImports($inner);
                }
            }
        }
    }

    /**
     * Whether an authentication method throttles through a request class it type-hints.
     *
     * The starter kits throttle login inside the FormRequest (authenticate() calling
     * ensureIsNotRateLimited()), and a controller that adopts the pattern only calls
     * into it. A parameter counts when its class lives under app/ and either a method
     * the controller calls on it, or a hook Laravel's validateResolved() runs on every
     * request, reaches a RateLimiter call, directly or through $this->method() calls.
     * Methods inherited from App\ parents and traits count as the class's own.
     * Type-hinting the request is not enough: the throttling method has to run.
     *
     * Reads the import table, so trackFileImports() must have seen the controller file.
     */
    private function delegatesToThrottlingRequest(Node\Stmt\ClassMethod $method): bool
    {
        foreach ($method->params as $param) {
            $type = $param->type instanceof Node\NullableType ? $param->type->type : $param->type;
            if (! $type instanceof Node\Name || ! $param->var instanceof Node\Expr\Variable || ! is_string($param->var->name)) {
                continue;
            }

            $requestMethods = $this->appClassMethods($this->resolvedClassFqn($type));
            if ($requestMethods === []) {
                continue;
            }

            // failedAuthorization() and failedValidation() are left out: they run only
            // on a request that is already being rejected.
            $entryPoints = [
                'prepareforvalidation' => true,
                'authorize' => true,
                'validator' => true,
                'withvalidator' => true,
                'after' => true,
                'passedvalidation' => true,
            ];
            foreach ($this->parser->findNodes($method->stmts ?? [], Node\Expr\MethodCall::class) as $call) {
                if ($call instanceof Node\Expr\MethodCall
                    && $call->var instanceof Node\Expr\Variable
                    && $call->var->name === $param->var->name
                    && $call->name instanceof Node\Identifier) {
                    $entryPoints[$call->name->toLowerString()] = true;
                }
            }

            $visited = [];
            foreach (array_keys($entryPoints) as $name) {
                if ($this->requestMethodThrottles($name, $requestMethods, $visited)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Whether a class method reaches a RateLimiter call, or ThrottlesLogins'
     * hasTooManyLoginAttempts() or a limiter's tooManyAttempts(), directly or
     * through $this->method() calls within the same class.
     *
     * @param  array<string, Node\Stmt\ClassMethod>  $methods  Keyed by lowercased name
     * @param  array<string, true>  $visited
     */
    private function requestMethodThrottles(string $name, array $methods, array &$visited): bool
    {
        if (! isset($methods[$name]) || isset($visited[$name])) {
            return false;
        }
        $visited[$name] = true;

        $stmts = $methods[$name]->stmts ?? [];
        if ($this->nodeContainsRateLimiter($stmts)) {
            return true;
        }

        foreach ($this->parser->findNodes($stmts, Node\Expr\MethodCall::class) as $call) {
            if ($call instanceof Node\Expr\MethodCall
                && $call->name instanceof Node\Identifier
                && in_array($call->name->toLowerString(), ['hastoomanyloginattempts', 'toomanyattempts'], true)) {
                return true;
            }

            if ($call instanceof Node\Expr\MethodCall
                && $call->var instanceof Node\Expr\Variable
                && $call->var->name === 'this'
                && $call->name instanceof Node\Identifier
                && $this->requestMethodThrottles($call->name->toLowerString(), $methods, $visited)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The methods of an App\ class or trait, keyed by lowercased name, read from the
     * file Laravel's default autoload mapping (App\ to app/) puts it in. Methods from
     * the traits it uses and the class it extends are merged in, in the order PHP
     * resolves them: its own first, then its traits', then its parent's. The walk stops
     * at the first name outside App\ or whose file is missing, which is where
     * FormRequest itself sits.
     *
     * @param  array<string, true>  $seen  Lowercased names already read, so a cycle ends
     * @return array<string, Node\Stmt\ClassMethod>
     */
    private function appClassMethods(string $fqn, array &$seen = []): array
    {
        if (! str_starts_with($fqn, 'App\\') || isset($seen[strtolower($fqn)])) {
            return [];
        }
        $seen[strtolower($fqn)] = true;

        $path = $this->appClassPath($fqn);
        if ($path === null) {
            return [];
        }

        $ast = $this->parser->parseFile($path);
        $shortName = substr($fqn, (int) strrpos($fqn, '\\') + 1);
        foreach ($this->parser->findNodes($ast, Node\Stmt\ClassLike::class) as $class) {
            if (! ($class instanceof Node\Stmt\Class_ || $class instanceof Node\Stmt\Trait_)
                || $class->name?->toString() !== $shortName) {
                continue;
            }

            $methods = [];
            foreach ($class->getMethods() as $classMethod) {
                $methods[$classMethod->name->toLowerString()] = $classMethod;
            }

            $inherited = $this->inheritedNames($class);

            // These names are written in this file, so they resolve against its imports.
            // The controller's table is put back afterwards: the caller is still reading
            // the controller's parameters with it.
            $controllerImports = $this->importedNames;
            $this->trackFileImports($ast);
            $inheritedFqns = array_map(fn (Node\Name $name): string => $this->resolvedClassFqn($name), $inherited);
            $this->importedNames = $controllerImports;

            foreach ($inheritedFqns as $inheritedFqn) {
                $methods += $this->appClassMethods($inheritedFqn, $seen);
            }

            return $methods;
        }

        return [];
    }

    /**
     * The file Laravel's default autoload mapping (App\ to app/) puts an App\ class
     * in, or null when the name is outside App\ or the file is missing.
     */
    private function appClassPath(string $fqn): ?string
    {
        if (! str_starts_with($fqn, 'App\\')) {
            return null;
        }

        $path = $this->getBasePath().DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR
            .str_replace('\\', DIRECTORY_SEPARATOR, substr($fqn, 4)).'.php';

        return file_exists($path) ? $path : null;
    }

    /**
     * The controller class a route's action names, when it names one. Only the
     * action counts: other classes on the statement are middleware, which
     * routeMiddleware() reads, or ones it removes with withoutMiddleware().
     *
     * @param  array{class: ?string, method: ?string}|null  $action
     * @return array<int, string>
     */
    private function actionClasses(?array $action): array
    {
        return $action !== null && $action['class'] !== null ? [$action['class']] : [];
    }

    /**
     * Whether the controller a route's action names throttles login itself.
     *
     * Names come from actionClasses(). One outside App\ (a string
     * action or a name the route file never imported) is read as relative to
     * App\Http\Controllers, the namespace legacy route groups and laravel/ui fall
     * back to. Nothing looser: a name that does not resolve to a file covers nothing.
     * The route's action, when the statement names one, is checked for the method
     * it calls; every other name for the class as a whole.
     *
     * Middleware the class registers on itself counts only when the route's exclusions
     * leave it, as Laravel excludes it with the route's own.
     *
     * @param  array<int, string>  $names
     * @param  array{class: ?string, method: ?string}|null  $action  See routeActions()
     * @param  list<string>  $excluded  Resolved names the route excludes
     */
    private function routeClassesThrottle(array $names, ?array $action = null, array $excluded = []): bool
    {
        foreach ($names as $name) {
            $fqn = str_starts_with($name, 'App\\') ? $name : 'App\\Http\\Controllers\\'.$name;
            $method = $action !== null && $action['class'] === $name ? $action['method'] : null;
            if ($this->classThrottlesLogin($fqn, $method, excluded: $excluded)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a class throttles login (see classThrottleVerdict()). A class this run
     * cannot read does not.
     */
    /**
     * @param  list<string>  $excluded  See classThrottleVerdict()
     */
    private function classThrottlesLogin(string $fqn, ?string $method = null, bool $middlewareOnly = false, array $excluded = []): bool
    {
        return $this->classThrottleVerdict($fqn, $method, $middlewareOnly, $excluded) === true;
    }

    /**
     * Whether an App\ class throttles login: its file has login throttling, it uses
     * AuthenticatesUsers or ThrottlesLogins, one of its methods delegates to a
     * throttling FormRequest, or a class it reaches does: the middleware it
     * registers on itself, the traits it uses and the class it extends.
     * Memoised for the run.
     *
     * With a method, the one a route calls, only that method is judged. Middleware
     * counts when its only()/except() lets the method through. A method the class
     * declares itself replaces the one its traits and parent declare, so their
     * throttling, AuthenticatesUsers' login() included, is not credited; only the
     * middleware they register still runs. Without one, as for a middleware class or
     * a route that names no method, any of its methods and middleware count.
     *
     * Null when nothing credits the class and this run cannot read all of it: it is
     * outside App\ and the framework, its file is missing or does not declare it (as
     * one that does not parse), or a trait it uses or the class it extends cannot be
     * read.
     *
     * @param  bool  $middlewareOnly  Credit only registered middleware: the class's
     *                                method is overridden by the class that reached it
     * @param  list<string>  $excluded  Resolved names the route excludes, which registered
     *                                  middleware must survive (see survivesExclusion())
     */
    private function classThrottleVerdict(string $fqn, ?string $method = null, bool $middlewareOnly = false, array $excluded = []): ?bool
    {
        // The framework's own throttle middleware, which 'throttle' names
        if (in_array($fqn, MiddlewareThrottleDetector::THROTTLE_MIDDLEWARE, true)) {
            return true;
        }

        // The framework's other classes are known not to, though this run cannot read
        // them, so neither a framework parent or trait nor 'throttle' re-registered to
        // one (Authenticate::class, say) leaves the verdict unknown
        if (str_starts_with($fqn, 'Illuminate\\')) {
            return false;
        }

        $method = $method === null ? null : strtolower($method);
        $key = $fqn.'::'.($method ?? '*').($middlewareOnly ? ':middleware' : '').($excluded === [] ? '' : '|'.serialize($excluded));
        if (array_key_exists($key, $this->throttlingClasses)) {
            return $this->throttlingClasses[$key];
        }

        // Seeded so an inheritance or middleware cycle ends instead of recursing
        $this->throttlingClasses[$key] = false;

        $path = $this->appClassPath($fqn);
        if ($path === null) {
            return $this->throttlingClasses[$key] = null;
        }

        $facts = $this->classFacts($path, $fqn);
        $declared = $method !== null && isset($facts['methods'][$method]);

        if (! $middlewareOnly) {
            // With a method, only its body and the $this->method() calls it makes
            // count, so throttling in a sibling method covers nothing.
            $visited = [];
            $bodyThrottles = $method === null
                ? $this->hasLoginThrottlingInFile($path)
                : $declared && $this->requestMethodThrottles($method, $this->appClassMethods($fqn), $visited);

            if ($bodyThrottles
                || (! $declared && $this->usesLoginThrottlingTrait($path))
                || ($method === null ? $facts['delegating'] !== [] : isset($facts['delegating'][$method]))) {
                return $this->throttlingClasses[$key] = true;
            }
        }

        if ($method === null) {
            foreach ($facts['middleware'] as $middleware) {
                if ($this->survivesExclusion($middleware['names'], $excluded) && $this->classThrottlesLogin($middleware['class'])) {
                    return $this->throttlingClasses[$key] = true;
                }
            }
        } elseif ($this->registeredMiddlewareThrottles($facts['middleware'], $method, $excluded)) {
            return $this->throttlingClasses[$key] = true;
        }

        // A file that does not declare the class says nothing about it, and a trait or
        // parent that cannot be read leaves what it adds unknown
        $verdict = $facts['found'] ? false : null;
        foreach ($facts['inherited'] as $class) {
            $inherited = $this->classThrottleVerdict($class, $method, $middlewareOnly || $declared, $excluded);
            if ($inherited === true) {
                return $this->throttlingClasses[$key] = true;
            }
            if ($inherited === null) {
                $verdict = null;
            }
        }

        return $this->throttlingClasses[$key] = $verdict;
    }

    /**
     * What an App\ class or trait declares that bears on its throttling: its own
     * methods, those of them that delegate to a throttling FormRequest, the
     * middleware it registers on itself (in a constructor, $this->middleware(...),
     * or through HasMiddleware's static middleware()), and the traits it uses and
     * the class it extends. Method names are lowercased. found says whether the file
     * declares the class at all; one that does not parse declares nothing.
     *
     * @return array{found: bool, methods: array<string, true>, delegating: array<string, true>, middleware: array<int, RegisteredMiddleware>, inherited: array<int, string>}
     */
    private function classFacts(string $path, string $fqn): array
    {
        $ast = $this->parser->parseFile($path);
        $shortName = substr($fqn, (int) strrpos($fqn, '\\') + 1);
        $facts = ['found' => false, 'methods' => [], 'delegating' => [], 'middleware' => [], 'inherited' => []];

        // Names in the class resolve against its own imports. The caller's table is
        // put back afterwards: a route file's remaining routes are still read with it.
        $callerImports = $this->importedNames;
        $this->trackFileImports($ast);

        foreach ($this->parser->findNodes($ast, Node\Stmt\ClassLike::class) as $class) {
            if (! ($class instanceof Node\Stmt\Class_ || $class instanceof Node\Stmt\Trait_)
                || strcasecmp($class->name?->toString() ?? '', $shortName) !== 0) {
                continue;
            }

            $facts['found'] = true;
            foreach ($class->getMethods() as $classMethod) {
                $name = $classMethod->name->toLowerString();
                $facts['methods'][$name] = true;

                if ($this->delegatesToThrottlingRequest($classMethod)) {
                    $facts['delegating'][$name] = true;
                }

                array_push($facts['middleware'], ...$this->middlewareRegisteredBy($classMethod));
            }

            foreach ($this->inheritedNames($class) as $name) {
                $facts['inherited'][] = $this->resolvedClassFqn($name);
            }

            break;
        }

        $this->importedNames = $callerImports;

        return $facts;
    }

    /**
     * Middleware classes a controller method registers on its own controller,
     * with the methods it is limited to: $this->middleware(...)->only(...) /
     * ->except(...) in the constructor, or the list HasMiddleware's static
     * middleware() returns, with new Middleware(..., only: ..., except: ...).
     * Method names are lowercased; a null only means every method.
     *
     * @return array<int, RegisteredMiddleware>
     */
    private function middlewareRegisteredBy(Node\Stmt\ClassMethod $method): array
    {
        $name = $method->name->toLowerString();
        $registered = [];

        if ($name === '__construct') {
            $calls = $this->parser->findNodes($method->stmts ?? [], Node\Expr\MethodCall::class);

            // only()/except() wrap the middleware() call they limit
            $filters = [];
            foreach ($calls as $call) {
                if (! $call instanceof Node\Expr\MethodCall
                    || ! $call->name instanceof Node\Identifier
                    || ! in_array($call->name->toLowerString(), ['only', 'except'], true)) {
                    continue;
                }

                $inner = $call->var;
                while ($inner instanceof Node\Expr\MethodCall && ! $this->isThisMiddlewareCall($inner)) {
                    $inner = $inner->var;
                }
                if ($inner instanceof Node\Expr\MethodCall) {
                    $names = [];
                    foreach ($call->args as $arg) {
                        if ($arg instanceof Node\Arg) {
                            array_push($names, ...$this->methodNamesIn($arg->value));
                        }
                    }
                    $filters[spl_object_id($inner)][$call->name->toLowerString()] = $names;
                }
            }

            foreach ($calls as $call) {
                if ($call instanceof Node\Expr\MethodCall
                    && $this->isThisMiddlewareCall($call)
                    && ($call->args[0] ?? null) instanceof Node\Arg) {
                    $filter = $filters[spl_object_id($call)] ?? [];
                    array_push($registered, ...$this->registeredMiddleware($call->args[0]->value, $filter['only'] ?? null, $filter['except'] ?? []));
                }
            }
        }

        if ($name === 'middleware' && $method->isStatic()) {
            foreach ($this->parser->findNodes($method->stmts ?? [], Node\Stmt\Return_::class) as $return) {
                if (! $return instanceof Node\Stmt\Return_ || $return->expr === null) {
                    continue;
                }

                $entries = $return->expr instanceof Node\Expr\Array_
                    ? array_map(fn (?Node\Expr\ArrayItem $item): ?Node\Expr => $item?->value, $return->expr->items)
                    : [$return->expr];
                foreach ($entries as $entry) {
                    if ($entry !== null) {
                        array_push($registered, ...$this->declaredMiddleware($entry));
                    }
                }
            }
        }

        return $registered;
    }

    /**
     * Whether a call is $this->middleware(...).
     */
    private function isThisMiddlewareCall(Node\Expr\MethodCall $call): bool
    {
        return $call->var instanceof Node\Expr\Variable
            && $call->var->name === 'this'
            && $call->name instanceof Node\Identifier
            && $call->name->toLowerString() === 'middleware';
    }

    /**
     * The middleware one entry of HasMiddleware's list names: new Middleware(X,
     * only: [...], except: [...]), with its arguments named or positional, or a
     * bare middleware value that applies to every method.
     *
     * @return array<int, RegisteredMiddleware>
     */
    private function declaredMiddleware(Node\Expr $entry): array
    {
        $only = null;
        $except = [];
        $value = $entry;

        if ($entry instanceof Node\Expr\New_) {
            $value = null;
            foreach ($entry->args as $position => $arg) {
                if (! $arg instanceof Node\Arg) {
                    continue;
                }

                $param = $arg->name?->toLowerString() ?? [0 => 'middleware', 1 => 'only', 2 => 'except'][$position] ?? null;
                match ($param) {
                    'middleware' => $value = $arg->value,
                    'only' => $only = $this->methodNamesIn($arg->value),
                    'except' => $except = $this->methodNamesIn($arg->value),
                    default => null,
                };
            }
        }

        return $value === null ? [] : $this->registeredMiddleware($value, $only, $except);
    }

    /**
     * The middleware one registered middleware value names, one or a list, each class with
     * the resolved names its entry hands the router, so a route's exclusions can drop it.
     *
     * @param  array<int, string>|null  $only
     * @param  array<int, string>  $except
     * @return list<RegisteredMiddleware>
     */
    private function registeredMiddleware(Node\Expr $value, ?array $only, array $except): array
    {
        $entries = $value instanceof Node\Expr\Array_
            ? array_map(fn (Node\Expr\ArrayItem $item): Node\Expr => $item->value, array_values(array_filter($value->items, fn (?Node\Expr\ArrayItem $item): bool => $item !== null)))
            : [$value];

        $registered = [];
        foreach ($entries as $entry) {
            $names = $this->middlewareNamesIn($entry);
            foreach ($this->middlewareClassesIn($entry) as $class) {
                $registered[] = ['class' => $class, 'names' => $names, 'only' => $only, 'except' => $except];
            }
        }

        return $registered;
    }

    /**
     * The lowercased method names one only()/except() argument lists: a string
     * or a list of them.
     *
     * @return array<int, string>
     */
    private function methodNamesIn(Node\Expr $expr): array
    {
        if ($expr instanceof Node\Scalar\String_) {
            return [strtolower($expr->value)];
        }

        $names = [];
        if ($expr instanceof Node\Expr\Array_) {
            foreach ($expr->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem && $item->value instanceof Node\Scalar\String_) {
                    $names[] = strtolower($item->value->value);
                }
            }
        }

        return $names;
    }

    /**
     * The traits a class or trait uses and the class it extends, as written.
     *
     * @return array<int, Node\Name>
     */
    private function inheritedNames(Node\Stmt\ClassLike $class): array
    {
        $names = [];
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\TraitUse) {
                array_push($names, ...$stmt->traits);
            }
        }
        if ($class instanceof Node\Stmt\Class_ && $class->extends !== null) {
            $names[] = $class->extends;
        }

        return $names;
    }

    /**
     * The middleware classes a middleware value names, resolved against the current
     * import table: X::class, X::class.':5,1', a class-name string, an alias
     * string ('signin.cap:5,1'), or a list of any of these.
     * 'throttle' resolves to the framework's ThrottleRequests unless the app
     * registers a class this run can read; any other name that resolves to no
     * class (a built-in alias like 'auth' that the app does not register) is dropped.
     *
     * @return array<int, string>
     */
    private function middlewareClassesIn(Node\Expr $expr): array
    {
        if ($expr instanceof Node\Expr\Array_) {
            $classes = [];
            foreach ($expr->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem) {
                    array_push($classes, ...$this->middlewareClassesIn($item->value));
                }
            }

            return $classes;
        }

        if ($expr instanceof Node\Scalar\String_) {
            return $this->middlewareClassesNamed($expr->value);
        }

        $named = $this->computedMiddlewareName($expr);
        if ($named !== null) {
            return $this->middlewareClassesNamed($named);
        }

        $class = $this->middlewareClassName($expr);

        return $class === null ? [] : [$class];
    }

    /**
     * The literal text a computed middleware string starts with, as in
     * 'throttle:'.config('auth.limit') or "throttle:{$limit}", when it already
     * holds the ':' that ends the name. Before that ':' the name is not finished:
     * 'throttle'.$suffix may be 'throttles.audit'.
     */
    private function computedMiddlewareName(Node\Expr $expr): ?string
    {
        while ($expr instanceof Node\Expr\BinaryOp\Concat) {
            $expr = $expr->left;
        }

        $text = match (true) {
            $expr instanceof Node\Scalar\String_ => $expr->value,
            $expr instanceof Node\Scalar\InterpolatedString && ($expr->parts[0] ?? null) instanceof Node\InterpolatedStringPart => $expr->parts[0]->value,
            default => null,
        };

        return $text !== null && str_contains($text, ':') ? $text : null;
    }

    /**
     * The middleware classes a middleware name resolves to, as Laravel's
     * MiddlewareNameResolver does: a class name, a group the app defines (its
     * entries resolved in turn), or an alias. 'throttle' resolves to the
     * framework's ThrottleRequests unless the app registers a class this run can
     * read.
     *
     * @param  array<string, true>  $expanding  Groups being expanded, so a group naming itself ends
     * @return array<int, string>
     */
    private function middlewareClassesNamed(string $value, array $expanding = []): array
    {
        $name = strtok($value, ':');
        if ($name === false) {
            return [];
        }

        if (str_contains($name, '\\')) {
            return [ltrim($name, '\\')];
        }

        if (isset($this->middlewareGroups[$name])) {
            if (isset($expanding[$name])) {
                return [];
            }

            $classes = [];
            foreach ($this->middlewareGroups[$name] as $entry) {
                array_push($classes, ...$this->middlewareClassesNamed($entry, $expanding + [$name => true]));
            }

            return $classes;
        }

        if (isset($this->middlewareAliases[$name])) {
            $class = $this->middlewareAliases[$name];

            // Re-registering 'throttle' is deliberate, so a class this run cannot read,
            // such as a package's, keeps the framework's verdict: only one read as not
            // throttling replaces it.
            return $name === 'throttle' && $this->classThrottleVerdict($class) === null
                ? [MiddlewareThrottleDetector::THROTTLE_MIDDLEWARE[0]]
                : [$class];
        }

        // Laravel registers 'throttle' itself, so an app need not
        return $name === 'throttle' ? [$this->throttleAliasClass] : [];
    }

    /**
     * Whether a middleware name throttles login: one of the classes it resolves to,
     * through the app's aliases and groups, does.
     */
    private function middlewareNameThrottles(string $name): bool
    {
        foreach ($this->middlewareClassesNamed($name) as $class) {
            if ($this->classThrottlesLogin($class)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The names a middleware value hands the router, one or a list, or a variable holding
     * one (see heldValue()), resolved as resolvedMiddlewareNames() resolves them.
     *
     * @return list<string>
     */
    private function middlewareNamesIn(Node\Expr $expr): array
    {
        $expr = self::heldValue($expr);
        if ($expr instanceof Node\Expr\Array_) {
            $names = [];
            foreach ($expr->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem) {
                    array_push($names, ...$this->middlewareNamesIn($item->value));
                }
            }

            return $names;
        }

        $text = $this->middlewareText($expr);
        if ($text === null) {
            return [];
        }

        // A class string written with a leading backslash is compared as written: the
        // 'throttle' alias never resolves to it, so excluding it leaves 'throttle:5,1'
        $left = $expr;
        while ($left instanceof Node\Expr\BinaryOp\Concat) {
            $left = $left->left;
        }

        return $left instanceof Node\Scalar\String_ && str_starts_with($left->value, '\\')
            ? [$text]
            : $this->resolvedMiddlewareNames($text);
    }

    /**
     * The name a middleware value hands the router, with its parameters: a string as
     * written, or a class reference resolved against the current import table, with a
     * leading backslash, followed by the parameters X::class.':5,1', X::using('login')
     * or X::with(5, 1) gives it. A part that is not a literal reads as text that equals
     * no other, so it never matches an exclusion. After a class reference it starts the
     * parameters, as Laravel's name ends at the class; after a string with no ':' yet it
     * leaves the name unfinished, since 'throttle'.$suffix may be 'throttles.audit'.
     * Null for a value that names no middleware.
     */
    private function middlewareText(Node\Expr $expr): ?string
    {
        if ($expr instanceof Node\Scalar\String_) {
            return $expr->value;
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            $text = '';
            foreach ($expr->parts as $part) {
                $text .= $part instanceof Node\InterpolatedStringPart ? $part->value : self::unknownMiddlewareText($part);
            }

            return $text;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            $left = $this->middlewareText($expr->left);
            if ($left === null) {
                return null;
            }
            $right = $expr->right instanceof Node\Scalar\String_ ? $expr->right->value : self::unknownMiddlewareText($expr->right);

            return $left.(str_starts_with($left, '\\') && ! str_contains($left, ':') && ! $expr->right instanceof Node\Scalar\String_ ? ':' : '').$right;
        }

        $class = $this->middlewareClassName($expr);
        if ($class === null) {
            return null;
        }

        // ThrottleRequests::using($name) builds 'Class:'.$name, ::with(...) 'Class:' and
        // its arguments joined by commas
        if ($expr instanceof Node\Expr\StaticCall) {
            $parameters = [];
            foreach ($expr->args as $arg) {
                $value = $arg instanceof Node\Arg ? $arg->value : $arg;
                $parameters[] = match (true) {
                    $value instanceof Node\Scalar\String_ => $value->value,
                    $value instanceof Node\Scalar\Int_ => (string) $value->value,
                    default => self::unknownMiddlewareText($value),
                };
            }

            return '\\'.$class.':'.implode(',', $parameters);
        }

        return '\\'.$class;
    }

    /**
     * Text standing for a value that is not a literal, unique to that value, so it never
     * equals text written anywhere else.
     */
    private static function unknownMiddlewareText(Node $value): string
    {
        return "\0".spl_object_id($value);
    }

    /**
     * The names a middleware name resolves to, as Laravel's MiddlewareNameResolver
     * resolves a route's applied and excluded middleware before it compares them: a
     * group the app defines expands to its entries, each resolved in turn ('web' and
     * 'api' also to the throttles groupThrottleNames() reads for them), and an alias or
     * class name to the class middlewareClassesNamed() gives, with its parameters kept.
     * A name that resolves to no class is kept as written.
     *
     * @param  array<string, true>  $expanding  Groups being expanded, so a group naming itself ends
     * @return list<string>
     */
    private function resolvedMiddlewareNames(string $value, array $expanding = []): array
    {
        $colon = strpos($value, ':');
        $name = $colon === false ? $value : substr($value, 0, $colon);
        $parameters = $colon === false ? '' : substr($value, $colon);

        if ($colon === false && (isset($this->middlewareGroups[$name]) || isset($this->groupThrottles[$name]))) {
            if (isset($expanding[$name])) {
                return [];
            }

            $names = [];
            foreach ([...$this->middlewareGroups[$name] ?? [], ...$this->groupThrottles[$name] ?? []] as $entry) {
                array_push($names, ...$this->resolvedMiddlewareNames($entry, $expanding + [$name => true]));
            }

            return $names;
        }

        $classes = $this->middlewareClassesNamed($name);

        return $classes === [] ? [$value] : array_values(array_map(fn (string $class): string => $class.$parameters, $classes));
    }

    /**
     * Whether a resolved middleware name (see resolvedMiddlewareNames()) names a class
     * that throttles login.
     */
    private function resolvedNameThrottles(string $name): bool
    {
        $class = (string) strtok($name, ':');

        return str_contains($class, '\\') && $this->classThrottlesLogin(ltrim($class, '\\'));
    }

    /**
     * The class an X::class, X::class.':params' or X::using(...) / X::with(...)
     * expression names, resolved against the current import table.
     */
    private function middlewareClassName(Node\Expr $expr): ?string
    {
        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->middlewareClassName($expr->left);
        }

        // ThrottleRequests::using('login') and ::with(5, 1) build the 'Class:params' string
        if ($expr instanceof Node\Expr\StaticCall
            && $expr->class instanceof Node\Name
            && $expr->name instanceof Node\Identifier
            && in_array($expr->name->toLowerString(), ['using', 'with'], true)) {
            return $this->resolvedClassFqn($expr->class);
        }

        if ($expr instanceof Node\Expr\ClassConstFetch
            && $expr->class instanceof Node\Name
            && $expr->name instanceof Node\Identifier
            && $expr->name->toLowerString() === 'class') {
            return $this->resolvedClassFqn($expr->class);
        }

        if ($expr instanceof Node\Scalar\String_ && str_contains($expr->value, '\\')) {
            return ltrim((string) strtok($expr->value, ':'), '\\');
        }

        return null;
    }

    /**
     * Route middleware aliases the app registers, mapped to their classes: the
     * Kernel's $middlewareAliases / $routeMiddleware (Laravel 10 and earlier) and
     * $middleware->alias([...]) in bootstrap/app.php (Laravel 11+).
     *
     * Runs before any other file's imports are tracked, so it leaves no table to
     * put back.
     *
     * @return array<string, string>
     */
    private function readMiddlewareAliases(): array
    {
        $basePath = $this->getBasePath();
        $aliases = [];

        $kernelPath = $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Kernel.php';
        if (file_exists($kernelPath)) {
            $ast = $this->parser->parseFile($kernelPath);
            $this->trackFileImports($ast);
            foreach ($this->parser->findNodes($ast, Node\Stmt\Property::class) as $property) {
                foreach ($property instanceof Node\Stmt\Property ? $property->props : [] as $prop) {
                    if (in_array($prop->name->toString(), ['middlewareAliases', 'routeMiddleware'], true)
                        && $prop->default instanceof Node\Expr\Array_) {
                        $aliases += $this->aliasesIn($prop->default);
                    }
                }
            }
        }

        $bootstrapPath = $basePath.DIRECTORY_SEPARATOR.'bootstrap'.DIRECTORY_SEPARATOR.'app.php';
        if (file_exists($bootstrapPath)) {
            $ast = $this->parser->parseFile($bootstrapPath);
            $this->trackFileImports($ast);
            foreach ($this->parser->findMethodCalls($ast, 'alias') as $call) {
                $first = $call instanceof Node\Expr\MethodCall ? ($call->args[0] ?? null) : null;
                if ($first instanceof Node\Arg && $first->value instanceof Node\Expr\Array_) {
                    $aliases += $this->aliasesIn($first->value);
                }
            }
        }

        return $aliases;
    }

    /**
     * Middleware groups the app defines: the Kernel's $middlewareGroups (Laravel 10
     * and earlier) and $middleware->group() / appendToGroup() / prependToGroup() in
     * bootstrap/app.php (Laravel 11+). A class entry is resolved against the
     * declaring file's imports; any other entry is kept as a name. A removal,
     * removeFromGroup() or web() / api() with remove:, takes an entry out of what group()
     * lists, as the configurator removes before it appends and prepends.
     *
     * Runs before any other file's imports are tracked, so it leaves no table to
     * put back.
     *
     * @return array<string, array<int, string>>
     */
    private function readMiddlewareGroups(): array
    {
        $basePath = $this->getBasePath();
        $groups = [];

        $kernelPath = $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Kernel.php';
        if (file_exists($kernelPath)) {
            $ast = $this->parser->parseFile($kernelPath);
            $this->trackFileImports($ast);
            foreach ($this->parser->findNodes($ast, Node\Stmt\Property::class) as $property) {
                foreach ($property instanceof Node\Stmt\Property ? $property->props : [] as $prop) {
                    if ($prop->name->toString() === 'middlewareGroups' && $prop->default instanceof Node\Expr\Array_) {
                        foreach ($prop->default->items as $item) {
                            if ($item instanceof Node\Expr\ArrayItem && $item->key instanceof Node\Scalar\String_) {
                                $groups[$item->key->value] = $this->middlewareEntries($item->value);
                            }
                        }
                    }
                }
            }
        }

        $bootstrapPath = $basePath.DIRECTORY_SEPARATOR.'bootstrap'.DIRECTORY_SEPARATOR.'app.php';
        if (file_exists($bootstrapPath)) {
            $ast = $this->parser->parseFile($bootstrapPath);
            $this->trackFileImports($ast);
            $added = [];
            $removed = [];
            foreach ($this->parser->findNodes($ast, Node\Expr\MethodCall::class) as $call) {
                $method = $call instanceof Node\Expr\MethodCall && $call->name instanceof Node\Identifier ? $call->name->toLowerString() : '';
                if (! $call instanceof Node\Expr\MethodCall || ! in_array($method, ['group', 'appendtogroup', 'prependtogroup', 'removefromgroup', 'web', 'api'], true)) {
                    continue;
                }

                if (in_array($method, ['web', 'api'], true)) {
                    $remove = $this->callArgument($call, 2, 'remove');
                    $removed[$method] = [...$removed[$method] ?? [], ...$remove === null ? [] : $this->middlewareEntries($remove)];

                    continue;
                }

                $name = $call->args[0] ?? null;
                $entries = $call->args[1] ?? null;
                if ($name instanceof Node\Arg && $name->value instanceof Node\Scalar\String_ && $entries instanceof Node\Arg) {
                    $group = $name->value->value;
                    if ($method === 'group') {
                        $groups[$group] = [...$groups[$group] ?? [], ...$this->middlewareEntries($entries->value)];
                    } elseif ($method === 'removefromgroup') {
                        $removed[$group] = [...$removed[$group] ?? [], ...$this->middlewareEntries($entries->value)];
                    } else {
                        $added[$group] = [...$added[$group] ?? [], ...$this->middlewareEntries($entries->value)];
                    }
                }
            }

            foreach ($removed as $group => $entries) {
                if (isset($groups[$group])) {
                    $groups[$group] = array_values(array_diff($groups[$group], $entries));
                }
            }
            foreach ($added as $group => $entries) {
                $groups[$group] = [...$groups[$group] ?? [], ...$entries];
            }
        }

        return $groups;
    }

    /**
     * The entries one middleware value lists: a class name for X::class or a
     * class-name string, the name itself for any other string, each with the
     * parameters it carries (see middlewareText()).
     *
     * @return array<int, string>
     */
    private function middlewareEntries(Node\Expr $expr): array
    {
        if ($expr instanceof Node\Expr\Array_) {
            $entries = [];
            foreach ($expr->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem) {
                    array_push($entries, ...$this->middlewareEntries($item->value));
                }
            }

            return $entries;
        }

        if ($expr instanceof Node\Scalar\String_) {
            return [$expr->value];
        }

        $text = $this->middlewareClassName($expr) === null ? null : $this->middlewareText($expr);

        return $text === null ? [] : [ltrim($text, '\\')];
    }

    /**
     * @return array<string, string>
     */
    private function aliasesIn(Node\Expr\Array_ $array): array
    {
        $aliases = [];
        foreach ($array->items as $item) {
            if ($item instanceof Node\Expr\ArrayItem && $item->key instanceof Node\Scalar\String_) {
                $class = $this->middlewareClassName($item->value);
                if ($class !== null) {
                    $aliases[$item->key->value] = $class;
                }
            }
        }

        return $aliases;
    }

    /**
     * Whether a throttled route names this controller.
     *
     * A route name equal to the class's fully qualified name, or to a tail of it
     * that starts at a namespace boundary, matches. An unqualified name that the
     * route file never imported matches every class with that short name, since
     * nothing in the file says which one it means.
     *
     * @param  array<string, true>  $coveredControllers
     */
    private function isCoveredController(string $fqn, array $coveredControllers): bool
    {
        foreach (array_keys($coveredControllers) as $name) {
            if ($fqn === $name || str_ends_with($fqn, '\\'.$name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The fully qualified name of a class declared in a controller file.
     *
     * @param  array<Node>  $ast
     */
    private function controllerFqn(array $ast, Node\Stmt\ClassLike $class): string
    {
        $className = $class->name?->toString() ?? '';

        foreach ($ast as $stmt) {
            if ($stmt instanceof Node\Stmt\Namespace_
                && $stmt->name !== null
                && in_array($class, $this->parser->findClasses($stmt->stmts), true)) {
                return $stmt->name->toString().'\\'.$className;
            }
        }

        return $className;
    }

    /**
     * Whether a RateLimiter::for() call defines the named limiter.
     */
    private function definesLimiter(Node\Expr\StaticCall $call, string $limiter): bool
    {
        $name = $call->args[0] ?? null;

        return $name instanceof Node\Arg
            && $name->value instanceof Node\Scalar\String_
            && $name->value->value === $limiter;
    }

    /**
     * The limiter Fortify throttles its login route with: the value of
     * fortify.limiters.login. Fortify's routes add throttle:<limiter> only when it
     * is set; when it is not, which is the package default, its login pipeline runs
     * EnsureLoginIsNotThrottled instead, so login is throttled either way.
     *
     * Returns false when the value is unset or empty, null when it is set by
     * something other than a literal (env(), a constant), or the name.
     *
     * @param  array<Node>  $config
     */
    private function fortifyLoginLimiter(array $config): string|false|null
    {
        $limiters = $this->fortifyConfigValue($config, 'limiters');
        $login = $limiters instanceof Node\Expr\Array_ ? $this->arrayValue($limiters, 'login') : null;

        if ($login === null
            || ($login instanceof Node\Expr\ConstFetch && in_array($login->name->toLowerString(), ['null', 'false'], true))
            || ($login instanceof Node\Scalar\String_ && $login->value === '')) {
            return false;
        }

        return $login instanceof Node\Scalar\String_ ? $login->value : null;
    }

    /**
     * The value config/fortify.php returns under a top-level key, or null.
     *
     * @param  array<Node>  $config
     */
    private function fortifyConfigValue(array $config, string $key): ?Node\Expr
    {
        foreach ($this->parser->findNodes($config, Node\Stmt\Return_::class) as $return) {
            if ($return instanceof Node\Stmt\Return_ && $return->expr instanceof Node\Expr\Array_) {
                return $this->arrayValue($return->expr, $key);
            }
        }

        return null;
    }

    /**
     * Whether a login pipeline the app gives Fortify names EnsureLoginIsNotThrottled,
     * the step that throttles login when no route limiter does. The conditional
     * form Fortify's documentation shows counts.
     */
    private function pipelineThrottles(Node $pipeline): bool
    {
        foreach ($this->parser->findNodes([$pipeline], Node\Expr\ClassConstFetch::class) as $fetch) {
            if ($fetch instanceof Node\Expr\ClassConstFetch
                && $fetch->class instanceof Node\Name
                && $fetch->class->getLast() === 'EnsureLoginIsNotThrottled') {
                return true;
            }
        }

        return false;
    }

    /**
     * The value an array literal holds under a string key, or null when it has none.
     */
    private function arrayValue(Node\Expr\Array_ $array, string $key): ?Node\Expr
    {
        foreach ($array->items as $item) {
            if ($item instanceof Node\Expr\ArrayItem
                && $item->key instanceof Node\Scalar\String_
                && $item->key->value === $key) {
                return $item->value;
            }
        }

        return null;
    }

    /**
     * Whether an expression calls Limit::none() anywhere inside it.
     */
    private function containsLimitNone(Node\Expr $expr): bool
    {
        foreach ($this->parser->findNodes([$expr], Node\Expr\StaticCall::class) as $call) {
            if ($call instanceof Node\Expr\StaticCall
                && $call->class instanceof Node\Name
                && $call->class->getLast() === 'Limit'
                && $call->name instanceof Node\Identifier
                && $call->name->toLowerString() === 'none') {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether laravel/fortify is installed, read from composer.lock.
     */
    private function hasFortify(): bool
    {
        $lockContent = FileParser::readFile($this->getBasePath().DIRECTORY_SEPARATOR.'composer.lock');

        return $lockContent !== null && str_contains($lockContent, '"name": "laravel/fortify"');
    }

    /**
     * Check Fortify-specific throttling configuration.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function checkFortifyThrottling(array &$issues): void
    {
        $basePath = $this->getBasePath();
        $fortifyConfigPath = $basePath.DIRECTORY_SEPARATOR.'config'.DIRECTORY_SEPARATOR.'fortify.php';
        $config = file_exists($fortifyConfigPath) ? $this->parser->parseFile($fortifyConfigPath) : [];
        $configLimiter = $this->fortifyLoginLimiter($config);

        // A limiter named by something other than a literal is most likely still 'login'
        $limiter = is_string($configLimiter) ? $configLimiter : 'login';

        // Check all provider files for the login limiter's definition and the login pipeline
        $providerPath = $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Providers';
        $throttleDisabledFile = null;
        $customPipeline = null;

        if (is_dir($providerPath)) {
            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($providerPath, \RecursiveDirectoryIterator::SKIP_DOTS)
                );

                foreach ($iterator as $file) {
                    if (! $file instanceof \SplFileInfo) {
                        continue;
                    }

                    if (! $file->isFile() || $file->getExtension() !== 'php') {
                        continue;
                    }

                    foreach ($this->parser->findNodes($this->parser->parseFile($file->getPathname()), Node\Expr\StaticCall::class) as $call) {
                        if (! $call instanceof Node\Expr\StaticCall
                            || ! $call->class instanceof Node\Name
                            || ! $call->name instanceof Node\Identifier) {
                            continue;
                        }

                        $class = $call->class->getLast();
                        $method = $call->name->toLowerString();

                        // Fortify::ignoreRoutes() registers no Fortify routes: the app's own
                        // login routes are in routes/, which checkRouteFiles() judges.
                        if ($class === 'Fortify' && $method === 'ignoreroutes') {
                            return;
                        }

                        // Fortify::authenticateThrough() replaces the login pipeline,
                        // EnsureLoginIsNotThrottled included unless the callback lists it.
                        $first = $call->args[0] ?? null;
                        if ($class === 'Fortify' && $method === 'authenticatethrough' && $first instanceof Node\Arg) {
                            $customPipeline = ['throttles' => $this->pipelineThrottles($first->value), 'file' => $file->getPathname(), 'line' => $call->getStartLine()];
                        }

                        // Limit::none() disables the login limiter only when the limiter's own
                        // callback returns it, not when another limiter in the file does.
                        $callback = $call->args[1] ?? null;
                        if ($class === 'RateLimiter' && $method === 'for' && $this->definesLimiter($call, $limiter)
                            && $callback instanceof Node\Arg && $this->containsLimitNone($callback->value)) {
                            $throttleDisabledFile = $file->getPathname();
                        }
                    }
                }
            } catch (\Throwable $e) {
                // Silently fail if directory iterator fails
            }
        }

        // Without a route limiter, Fortify's login pipeline throttles, unless the app
        // replaces it: authenticateThrough() first, then fortify.pipelines.login, as
        // Fortify's AuthenticatedSessionController reads them.
        if ($configLimiter === false) {
            $pipelines = $this->fortifyConfigValue($config, 'pipelines');
            $configPipeline = $pipelines instanceof Node\Expr\Array_ ? $this->arrayValue($pipelines, 'login') : null;
            if ($customPipeline === null && $configPipeline instanceof Node\Expr\Array_) {
                $customPipeline = ['throttles' => $this->pipelineThrottles($configPipeline), 'file' => $fortifyConfigPath, 'line' => $configPipeline->getStartLine()];
            }

            if ($customPipeline !== null && ! $customPipeline['throttles']) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'Fortify login pipeline does not throttle login attempts',
                    filePath: $customPipeline['file'],
                    lineNumber: $customPipeline['line'],
                    severity: Severity::High,
                    recommendation: 'Add EnsureLoginIsNotThrottled to the custom login pipeline, or set limiters.login in config/fortify.php to a named rate limiter so Fortify throttles the login route, to prevent brute force attacks.',
                    metadata: [
                        'framework' => 'fortify',
                        'issue_type' => 'fortify_pipeline_unthrottled',
                    ]
                );
            }

            return;
        }

        // If throttling is explicitly disabled, flag as critical
        if ($throttleDisabledFile !== null) {
            $issues[] = $this->createIssueWithSnippet(
                message: 'Fortify login throttling is explicitly disabled',
                filePath: $throttleDisabledFile,
                lineNumber: 1,
                severity: Severity::Critical,
                recommendation: 'Enable Fortify login throttling by defining a named rate limiter for the login endpoint with appropriate attempt limits and time windows.',
                metadata: [
                    'framework' => 'fortify',
                    'issue_type' => 'fortify_throttle_disabled',
                ]
            );
        }
    }
}
