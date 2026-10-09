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
use ShieldCI\Concerns\TracksImportedNames;
use ShieldCI\Support\BootstrapRouteParser;

/**
 * Detects missing login throttling/rate limiting.
 *
 * Checks for:
 * - ThrottleRequests middleware on login routes
 * - RateLimiter usage in authentication controllers
 * - Login routes without rate limiting protection
 * - Brute force attack vulnerability
 */
class LoginThrottlingAnalyzer extends AbstractFileAnalyzer
{
    use DetectsLaravelVersion;
    use TracksImportedNames;

    /**
     * Whether a class throttles login, keyed by fully qualified name, for this run.
     *
     * @var array<string, bool>
     */
    private array $throttlingClasses = [];

    /**
     * Route middleware aliases the app registers, mapped to their classes, for this run.
     *
     * @var array<string, string>
     */
    private array $middlewareAliases = [];

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
        $this->middlewareAliases = $this->readMiddlewareAliases();

        // Throttle on the 'web' and 'api' middleware groups: app/Http/Kernel.php
        // (Laravel 10 and earlier) or bootstrap/app.php (Laravel 11+). The two are
        // kept apart because each only covers the routes registered in its group:
        // the stock Laravel 9/10 Kernel throttles 'api' out of the box, and that
        // says nothing about a login route in routes/web.php. A throttle on the
        // Kernel's global $middleware runs on every route, so it covers both.
        $hasGlobalKernelThrottle = $this->hasThrottleInKernelGlobalMiddleware();
        $hasWebGroupThrottle = $hasGlobalKernelThrottle
            || $this->hasThrottleInWebMiddlewareGroup()
            || $this->hasThrottleInLaravel11Middleware('web');
        $hasApiGroupThrottle = $hasGlobalKernelThrottle
            || $this->hasThrottleInApiMiddlewareGroup()
            || $this->hasThrottleInLaravel11Middleware('api');

        // Check route files for login routes without throttling
        $coveredControllers = $this->checkRouteFiles(
            $issues,
            webThrottled: $hasWebGroupThrottle,
            apiThrottled: $hasApiGroupThrottle,
        );

        // Check authentication controllers not already reached through a throttled route
        $this->checkAuthControllers($issues, $coveredControllers);

        // Fortify registers its login route itself, in the 'web' group, so a
        // web-group throttle or Fortify's own limiter covers it. Throttling in the
        // app's controllers never runs on that route. Breeze and Jetstream need no
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
     * Check if throttle middleware is configured in the 'web' middleware group (Laravel 10 and earlier).
     *
     * Checks app/Http/Kernel.php for:
     * protected $middlewareGroups = [
     *     'web' => [
     *         ThrottleRequests::class,
     *         // or
     *         'throttle:60,1',
     *     ],
     * ];
     */
    private function hasThrottleInWebMiddlewareGroup(): bool
    {
        $basePath = $this->getBasePath();
        $kernelPath = $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Kernel.php';

        if (! file_exists($kernelPath)) {
            return false;
        }

        try {
            $ast = $this->parser->parseFile($kernelPath);
            if (empty($ast)) {
                return false;
            }

            $classes = $this->parser->findClasses($ast);
            foreach ($classes as $class) {
                if (! isset($class->stmts) || ! is_array($class->stmts)) {
                    continue;
                }

                // Look for $middlewareGroups property
                foreach ($class->stmts as $stmt) {
                    if (! $stmt instanceof Node\Stmt\Property) {
                        continue;
                    }

                    $propertyName = $stmt->props[0]->name->toString();
                    if ($propertyName !== 'middlewareGroups') {
                        continue;
                    }

                    // Check if property has a default value (array)
                    if (! isset($stmt->props[0]->default)) {
                        continue;
                    }

                    $default = $stmt->props[0]->default;
                    if (! $default instanceof Node\Expr\Array_) {
                        continue;
                    }

                    // Look for 'web' key in the array
                    foreach ($default->items as $item) {
                        if (! $item instanceof Node\Expr\ArrayItem) {
                            continue;
                        }

                        // Check if key is 'web'
                        if ($item->key instanceof Node\Scalar\String_ && $item->key->value === 'web') {
                            // Check if value (middleware array) contains throttle
                            if ($item->value instanceof Node\Expr\Array_) {
                                if ($this->arrayContainsThrottle($item->value)) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            // If parsing fails, fall back to string matching
            return $this->hasThrottleInWebMiddlewareGroupFallback($kernelPath);
        }

        return false;
    }

    /**
     * Check if an AST array contains throttle middleware references.
     */
    private function arrayContainsThrottle(Node\Expr\Array_ $array): bool
    {
        foreach ($array->items as $item) {
            if ($item instanceof Node\Expr\ArrayItem && $this->expressionIsThrottle($item->value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a middleware expression is, or (as an array) lists, a throttle:
     * 'throttle:60,1', ThrottleRequests::class or ThrottleRequests::class.':60,1'.
     */
    private function expressionIsThrottle(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Scalar\String_) {
            return str_contains($expr->value, 'throttle');
        }

        if ($expr instanceof Node\Expr\ClassConstFetch) {
            return $expr->class instanceof Node\Name
                && str_contains($expr->class->toString(), 'ThrottleRequests');
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->concatContainsThrottle($expr);
        }

        if ($expr instanceof Node\Expr\Array_) {
            return $this->arrayContainsThrottle($expr);
        }

        return false;
    }

    /**
     * Check if throttle middleware is in the Kernel's global $middleware stack
     * (Laravel 10 and earlier), which runs on every route in every group.
     */
    private function hasThrottleInKernelGlobalMiddleware(): bool
    {
        $kernelPath = $this->getBasePath().DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Kernel.php';

        if (! file_exists($kernelPath)) {
            return false;
        }

        foreach ($this->parser->findClasses($this->parser->parseFile($kernelPath)) as $class) {
            foreach ($class->stmts as $stmt) {
                if (! $stmt instanceof Node\Stmt\Property) {
                    continue;
                }

                foreach ($stmt->props as $prop) {
                    if ($prop->name->toString() === 'middleware'
                        && $prop->default instanceof Node\Expr\Array_
                        && $this->arrayContainsThrottle($prop->default)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check if a concatenation expression contains ThrottleRequests.
     */
    private function concatContainsThrottle(Node\Expr\BinaryOp\Concat $concat): bool
    {
        // Check left side
        if ($concat->left instanceof Node\Expr\ClassConstFetch) {
            if ($concat->left->class instanceof Node\Name) {
                $className = $concat->left->class->toString();
                if (str_contains($className, 'ThrottleRequests')) {
                    return true;
                }
            }
        }

        // Recursively check if left is also a concat
        if ($concat->left instanceof Node\Expr\BinaryOp\Concat) {
            if ($this->concatContainsThrottle($concat->left)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Fallback string-based detection for Kernel.php middleware groups.
     */
    private function hasThrottleInWebMiddlewareGroupFallback(string $kernelPath): bool
    {
        $content = FileParser::readFile($kernelPath);
        if ($content === null) {
            return false;
        }

        // Look for $middlewareGroups['web'] or $middlewareGroups = ['web' => [
        // containing ThrottleRequests or 'throttle'
        if (preg_match('/\$middlewareGroups\s*=\s*\[/s', $content)) {
            // Extract the middlewareGroups array section
            if (preg_match('/["\']web["\']\s*=>\s*\[(.*?)\]/s', $content, $matches)) {
                $webMiddleware = $matches[1];
                if (str_contains($webMiddleware, 'ThrottleRequests') || str_contains($webMiddleware, 'throttle')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if throttle middleware is configured in the 'api' middleware group (Laravel 10 and earlier).
     *
     * Same as hasThrottleInWebMiddlewareGroup() but checks the 'api' group.
     */
    private function hasThrottleInApiMiddlewareGroup(): bool
    {
        $basePath = $this->getBasePath();
        $kernelPath = $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Kernel.php';

        if (! file_exists($kernelPath)) {
            return false;
        }

        try {
            $ast = $this->parser->parseFile($kernelPath);
            if (empty($ast)) {
                return false;
            }

            $classes = $this->parser->findClasses($ast);
            foreach ($classes as $class) {
                if (! isset($class->stmts) || ! is_array($class->stmts)) {
                    continue;
                }

                // Look for $middlewareGroups property
                foreach ($class->stmts as $stmt) {
                    if (! $stmt instanceof Node\Stmt\Property) {
                        continue;
                    }

                    $propertyName = $stmt->props[0]->name->toString();
                    if ($propertyName !== 'middlewareGroups') {
                        continue;
                    }

                    if (! isset($stmt->props[0]->default)) {
                        continue;
                    }

                    $default = $stmt->props[0]->default;
                    if (! $default instanceof Node\Expr\Array_) {
                        continue;
                    }

                    // Look for 'api' key in the array
                    foreach ($default->items as $item) {
                        if (! $item instanceof Node\Expr\ArrayItem) {
                            continue;
                        }

                        // Check if key is 'api'
                        if ($item->key instanceof Node\Scalar\String_ && $item->key->value === 'api') {
                            // Check if value (middleware array) contains throttle
                            if ($item->value instanceof Node\Expr\Array_) {
                                if ($this->arrayContainsThrottle($item->value)) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            // If parsing fails, fall back to string matching
            $content = FileParser::readFile($kernelPath);
            if ($content === null) {
                return false;
            }

            if (preg_match('/["\']api["\']\s*=>\s*\[(.*?)\]/s', $content, $matches)) {
                $apiMiddleware = $matches[1];
                if (str_contains($apiMiddleware, 'ThrottleRequests') || str_contains($apiMiddleware, 'throttle')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if throttle middleware covers a group in Laravel 11+ bootstrap/app.php.
     *
     * Reads the Middleware configurator calls inside withMiddleware():
     * - $middleware->web(append: [...]) / ->api(prepend: [...], replace: [...])
     * - $middleware->appendToGroup('web', ...) / ->prependToGroup('web', ...)
     * - $middleware->group('web', [...])
     * - $middleware->append(...) / ->prepend(...) / ->use([...]), the global
     *   stack, which runs on every route in every group
     * - $middleware->throttleApi(), for the api group only
     *
     * @param  string  $group  The middleware group to check ('web' or 'api')
     */
    private function hasThrottleInLaravel11Middleware(string $group = 'web'): bool
    {
        $bootstrapPath = $this->getBasePath().DIRECTORY_SEPARATOR.'bootstrap'.DIRECTORY_SEPARATOR.'app.php';

        if (! file_exists($bootstrapPath)) {
            return false;
        }

        foreach ($this->parser->findNodes($this->parser->parseFile($bootstrapPath), Node\Expr\MethodCall::class) as $call) {
            if (! $call instanceof Node\Expr\MethodCall
                || ! $call->var instanceof Node\Expr\Variable
                || ! $call->name instanceof Node\Identifier) {
                continue;
            }

            if ($this->middlewareCallThrottlesGroup($call, $call->name->toLowerString(), $group)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether one Middleware configurator call adds a throttle that covers $group.
     */
    private function middlewareCallThrottlesGroup(Node\Expr\MethodCall $call, string $method, string $group): bool
    {
        switch ($method) {
            // throttleApi() injects throttle:api into the api group at runtime (with
            // or without arguments). There is no throttleWeb() equivalent, and
            // throttleWithRedis() merely swaps the driver, so it must not count.
            case 'throttleapi':
                return $group === 'api';

            case 'append':
            case 'prepend':
            case 'use':
                $middleware = $this->callArgument($call, 0, 'middleware');

                return $middleware !== null && $this->expressionIsThrottle($middleware);

            case 'appendtogroup':
            case 'prependtogroup':
            case 'group':
                $groupName = $this->callArgument($call, 0, 'group');
                $middleware = $this->callArgument($call, 1, 'middleware');

                return $groupName instanceof Node\Scalar\String_
                    && $groupName->value === $group
                    && $middleware !== null
                    && $this->expressionIsThrottle($middleware);

            case 'web':
            case 'api':
                if ($method !== $group) {
                    return false;
                }

                // web(append, prepend, remove, replace): a throttle under remove:
                // takes it out of the group, so only the other three count.
                foreach (['append' => 0, 'prepend' => 1, 'replace' => 3] as $name => $position) {
                    $middleware = $this->callArgument($call, $position, $name);
                    if ($middleware !== null && $this->expressionIsThrottle($middleware)) {
                        return true;
                    }
                }

                return false;
        }

        return false;
    }

    /**
     * The value of a call argument, given by name or by position.
     */
    private function callArgument(Node\Expr\MethodCall $call, int $position, string $name): ?Node\Expr
    {
        foreach ($call->args as $index => $arg) {
            if (! $arg instanceof Node\Arg) {
                continue;
            }

            if ($arg->name !== null ? $arg->name->toString() === $name : $index === $position) {
                return $arg->value;
            }
        }

        return null;
    }

    /**
     * Check route files for login routes without throttling.
     *
     * Each file is judged as part of the middleware group it is registered under:
     * routes/api.php and files registered in the 'api' group are matched with the
     * API route patterns and use the api flags, every other file the web patterns
     * and the web flags. A route is covered by a throttle its group applies
     * ($webThrottled / $apiThrottled), or by a class its statement names that
     * throttles login itself (see routeClassesThrottle()). Login rate limiting
     * elsewhere in the code covers no route.
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
    private function checkRouteFiles(
        array &$issues,
        bool $webThrottled,
        bool $apiThrottled,
    ): array {
        $coveredControllers = [];
        $routePath = $this->getBasePath().DIRECTORY_SEPARATOR.'routes';

        if (! is_dir($routePath)) {
            return $coveredControllers;
        }

        // Files registered with throttle middleware on their own group are covered
        // outright; they are still scanned, for the controllers their routes name.
        // Files registered in the 'web' group are judged against the web-group
        // throttle: that includes routes/web.php itself on every real install,
        // and being in the web group says nothing about whether it is throttled.
        $bootstrapParser = new BootstrapRouteParser($this->getBasePath(), $this->parser);
        $throttledFiles = $bootstrapParser->getThrottleProtectedRouteFiles();
        $apiGroupFiles = $bootstrapParser->getApiRegisteredRouteFiles();

        try {
            foreach (new \DirectoryIterator($routePath) as $file) {
                if (! $file->isFile() || $file->getExtension() !== 'php') {
                    continue;
                }

                $filePath = $file->getPathname();
                $real = realpath($filePath);
                $normalizedPath = str_replace('\\', '/', $real !== false ? $real : $filePath);

                $isApiRoute = $file->getFilename() === 'api.php' || in_array($normalizedPath, $apiGroupFiles, true);
                $fileThrottled = in_array($normalizedPath, $throttledFiles, true)
                    || ($isApiRoute ? $apiThrottled : $webThrottled);
                $content = $this->readCode($filePath);
                if ($content === null) {
                    continue;
                }

                // Comment-free source, split so index $i is line $i + 1: stripAllComments()
                // keeps every newline, so line numbers match the file and the AST ranges.
                $lines = explode("\n", $content);

                // A route reference string carries no position, so controller names
                // resolve against the imports the file declares by its end.
                $ast = $this->parser->parseFile($filePath);
                $this->trackFileImports($ast);

                // Middleware classes each route statement and each route group names,
                // so a throttling middleware covers the routes it is applied to.
                [$statementMiddleware, $groupMiddleware] = $this->routeMiddleware($ast);

                // AST-derived line ranges of throttled route groups (fluent and
                // array forms, nesting-safe) — replaces the former brace-depth
                // heuristic. A route whose line sits inside a range is covered by
                // group-level throttling.
                $throttledRanges = $bootstrapParser->getThrottledGroupLineRanges($filePath);

                foreach ($lines as $lineNumber => $line) {
                    // $lines is 0-based; findings report $lineNumber + 1,
                    // which is the 1-based scale the AST ranges use.
                    $inThrottledGroup = $this->lineInRanges($lineNumber + 1, $throttledRanges);

                    // Check for Auth::routes() helper
                    if (preg_match('/Auth::routes\s*\(/i', $line, $authCall, PREG_OFFSET_CAPTURE)) {
                        // Auth::routes() includes login routes - check if throttled
                        // laravel/ui registers these against App\Http\Controllers\Auth\LoginController
                        $hasThrottle = $this->checkRouteHasThrottling($lines, $lineNumber, $authCall[0][1])
                            || $this->routeClassesThrottle(['App\\Http\\Controllers\\Auth\\LoginController'])
                            || $this->middlewareThrottles($lineNumber + 1, $statementMiddleware, $groupMiddleware);

                        if (! $hasThrottle && ! $fileThrottled && ! $inThrottledGroup) {
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

                    // Check for login-related routes
                    // Web routes: /login, /signin, /auth, /authenticate
                    // API routes: /api/login, /api/auth, /api/token, /oauth/token, /sanctum/token
                    // For API files: token/oauth only match on POST/any/match (not GET — those
                    // are management endpoints like /token/verify, not credential submission).
                    // For web files GET never matches: a GET login route renders the form,
                    // and the credentials arrive on the POST.
                    $routeUri = null;
                    $routeColumn = 0;
                    if ($isApiRoute) {
                        if (preg_match('/Route::(post|any|match)\s*\(["\']([^"\']*(?:login|signin|auth|authenticate|token|oauth)[^"\']*)["\']/', $line, $m, PREG_OFFSET_CAPTURE)) {
                            [$routeUri, $routeColumn] = [$m[2][0], $m[0][1]];
                        } elseif (preg_match('/Route::(get|resource|controller)\s*\(["\']([^"\']*(?:login|signin|auth|authenticate)[^"\']*)["\']/', $line, $m, PREG_OFFSET_CAPTURE)) {
                            [$routeUri, $routeColumn] = [$m[2][0], $m[0][1]];
                        }
                    } elseif (preg_match('/Route::(post|any|match|resource|controller)\s*\(["\']([^"\']*(?:login|signin|auth|authenticate)[^"\']*)["\']/', $line, $m, PREG_OFFSET_CAPTURE)) {
                        [$routeUri, $routeColumn] = [$m[2][0], $m[0][1]];
                    }

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

                        // Check if this route or surrounding lines have throttle middleware
                        $hasThrottle = $this->checkRouteHasThrottling($lines, $lineNumber, $routeColumn) || $inThrottledGroup;
                        $routeClasses = $this->controllersReferencedByRoute($lines, $lineNumber);

                        if ($hasThrottle || $fileThrottled) {
                            foreach ($routeClasses as $controller) {
                                $coveredControllers[$controller] = true;
                            }
                        }

                        if (! $hasThrottle
                            && ! $fileThrottled
                            && ! $this->routeClassesThrottle($routeClasses)
                            && ! $this->middlewareThrottles($lineNumber + 1, $statementMiddleware, $groupMiddleware)) {
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
     * The middleware classes a route file applies: per route statement, keyed by
     * the line its Route:: call starts on (Route::post(...)->middleware(...)), and
     * per route group, with the line range of the group's closure
     * (Route::middleware(...)->group(...), Route::group(['middleware' => ...], ...)).
     * A group's classes also hold the controller a Route::controller(...) group
     * names, since its routes reach that controller.
     *
     * Reads the import table, so trackFileImports() must have seen the route file.
     *
     * @param  array<Node>  $ast
     * @return array{0: array<int, array<int, string>>, 1: array<int, array{start: int, end: int, classes: array<int, string>}>}
     */
    private function routeMiddleware(array $ast): array
    {
        $statements = [];
        $groups = [];

        foreach ($this->parser->findNodes($ast, Node\Expr\MethodCall::class) as $call) {
            if (! $call instanceof Node\Expr\MethodCall || ! $call->name instanceof Node\Identifier) {
                continue;
            }

            $method = $call->name->toLowerString();

            if ($method === 'middleware' && ($call->args[0] ?? null) instanceof Node\Arg) {
                $root = $call->var;
                while ($root instanceof Node\Expr\MethodCall) {
                    $root = $root->var;
                }

                if ($root instanceof Node\Expr\StaticCall
                    && $root->name instanceof Node\Identifier
                    && in_array($root->name->toLowerString(), ['get', 'post', 'put', 'patch', 'delete', 'options', 'any', 'match'], true)) {
                    $line = $root->getStartLine();
                    $statements[$line] = [...$statements[$line] ?? [], ...$this->middlewareClassesIn($call->args[0]->value)];
                }
            }

            if ($method === 'group') {
                $this->collectGroupMiddleware($call->args, $this->chainClasses($call->var), $groups);
            }
        }

        foreach ($this->parser->findNodes($ast, Node\Expr\StaticCall::class) as $call) {
            if ($call instanceof Node\Expr\StaticCall
                && $call->name instanceof Node\Identifier
                && $call->name->toLowerString() === 'group') {
                $this->collectGroupMiddleware($call->args, [], $groups);
            }
        }

        return [$statements, $groups];
    }

    /**
     * Records a group's closure range with the middleware its chain and its
     * ['middleware' => ...] attribute array name, when there is a closure and any.
     *
     * @param  array<Node>  $args
     * @param  array<int, string>  $classes  Classes the group's method chain applies (see chainClasses())
     * @param  array<int, array{start: int, end: int, classes: array<int, string>}>  $groups
     */
    private function collectGroupMiddleware(array $args, array $classes, array &$groups): void
    {
        $closure = null;
        foreach ($args as $arg) {
            if (! $arg instanceof Node\Arg) {
                continue;
            }

            if ($arg->value instanceof Node\Expr\Closure || $arg->value instanceof Node\Expr\ArrowFunction) {
                $closure ??= $arg->value;
            }

            if ($arg->value instanceof Node\Expr\Array_) {
                foreach ($arg->value->items as $item) {
                    if ($item instanceof Node\Expr\ArrayItem
                        && $item->key instanceof Node\Scalar\String_
                        && $item->key->value === 'middleware') {
                        array_push($classes, ...$this->middlewareClassesIn($item->value));
                    }
                }
            }
        }

        if ($closure !== null && $classes !== []) {
            $groups[] = ['start' => $closure->getStartLine(), 'end' => $closure->getEndLine(), 'classes' => $classes];
        }
    }

    /**
     * The classes a group's method chain sends its routes through: the middleware
     * its ->middleware(...) / Route::middleware(...) calls name, and the controller
     * a ->controller(X::class) / Route::controller(X::class) call names, whose
     * routes give only a method.
     *
     * @return array<int, string>
     */
    private function chainClasses(Node\Expr $node): array
    {
        $classes = [];
        while ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) {
            $first = $node->args[0] ?? null;
            if ($node->name instanceof Node\Identifier && $first instanceof Node\Arg) {
                $method = $node->name->toLowerString();
                if ($method === 'middleware') {
                    array_push($classes, ...$this->middlewareClassesIn($first->value));
                } elseif ($method === 'controller' && ($controller = $this->middlewareClassName($first->value)) !== null) {
                    $classes[] = $controller;
                }
            }

            if (! $node instanceof Node\Expr\MethodCall) {
                break;
            }
            $node = $node->var;
        }

        return $classes;
    }

    /**
     * Whether a class applied to the route on this 1-based line, a middleware on
     * its own statement or a middleware or controller a group around it names,
     * throttles login.
     *
     * @param  array<int, array<int, string>>  $statementMiddleware
     * @param  array<int, array{start: int, end: int, classes: array<int, string>}>  $groupMiddleware
     */
    private function middlewareThrottles(int $line, array $statementMiddleware, array $groupMiddleware): bool
    {
        $classes = $statementMiddleware[$line] ?? [];
        foreach ($groupMiddleware as $group) {
            if ($line >= $group['start'] && $line <= $group['end']) {
                array_push($classes, ...$group['classes']);
            }
        }

        foreach ($classes as $class) {
            if ($this->classThrottlesLogin($class)) {
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
     * Check if a route has throttling in nearby lines or on the same line (before/after).
     * $column is the offset on the route's line where the route call starts.
     *
     * @param  array<int, string>  $lines
     */
    private function checkRouteHasThrottling(array $lines, int $lineNumber, int $column): bool
    {
        // Check current line first (for patterns like: Route::middleware('throttle')->post(...))
        if (isset($lines[$lineNumber]) && is_string($lines[$lineNumber])) {
            if ($this->lineHasThrottle($lines[$lineNumber])) {
                return true;
            }
        }

        // Check previous 3 lines (for multi-line route definitions)
        $startLine = max(0, $lineNumber - 3);
        for ($i = $startLine; $i < $lineNumber; $i++) {
            if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                continue;
            }

            if ($this->lineHasThrottle($lines[$i])) {
                // Make sure we haven't hit a semicolon between the throttle and current line
                $hasSemicolon = false;
                for ($j = $i; $j < $lineNumber; $j++) {
                    if (isset($lines[$j]) && is_string($lines[$j]) && str_contains($lines[$j], ';')) {
                        $hasSemicolon = true;
                        break;
                    }
                }
                if (! $hasSemicolon) {
                    return true;
                }
            }
        }

        // The lines after the route carry its chain only up to the end of its
        // statement; past that, a throttle belongs to another statement.
        $endLine = $this->statementEndLine($lines, $lineNumber, $column);
        for ($i = $lineNumber + 1; $i <= $endLine; $i++) {
            if (isset($lines[$i]) && $this->lineHasThrottle($lines[$i])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Index of the line where the statement starting at $column on $lineNumber
     * ends: its ';', or the bracket of an enclosing group it sits in without
     * one, as in an arrow-function group. The source is tokenized so that a ';'
     * inside brackets, as in a closure body, or inside a string does not count.
     * Reading from $column rather than the start of the line keeps a statement
     * or group opener written before the route on that line out of the count.
     * A statement that is never closed runs to the last line.
     *
     * @param  array<int, string>  $lines
     */
    private function statementEndLine(array $lines, int $lineNumber, int $column): int
    {
        $lastLine = count($lines) - 1;

        // Tokenize a window that doubles until it holds the statement's end, so a
        // route costs the length of its statement rather than the rest of the
        // file. Cutting at a line break is safe: the tokens before the cut are the
        // ones the whole file yields, and a string the cut leaves open stays a
        // single token, so no ';' or bracket inside it counts.
        for ($size = 8; ; $size *= 2) {
            $window = array_slice($lines, $lineNumber, $size);
            $window[0] = substr($window[0] ?? '', $column);
            $depth = 0;

            // The '<?php ' prefix shares the route's line, so token line 1 is $lineNumber.
            foreach (\PhpToken::tokenize('<?php '.implode("\n", $window)) as $token) {
                if ($token->is(['(', '[', '{', T_DOLLAR_OPEN_CURLY_BRACES])) {
                    $depth++;
                } elseif ($token->is([')', ']', '}'])) {
                    $depth--;
                }

                // A closer that takes the depth below zero belongs to an enclosing
                // group, so the statement ended before it.
                if ($depth < 0 || ($depth === 0 && $token->is(';'))) {
                    return $lineNumber + $token->line - 1;
                }
            }

            if ($lineNumber + $size > $lastLine) {
                return $lastLine;
            }
        }
    }

    /**
     * Check if a single line contains throttle middleware.
     */
    private function lineHasThrottle(string $line): bool
    {
        // Improved patterns to catch more throttle variations
        return preg_match('/->middleware\(["\']throttle/i', $line) ||  // Single string
               preg_match('/->middleware\(\[.*["\']throttle/i', $line) ||  // Array with quotes
               preg_match('/->middleware\(["\'][^"\']*["\'],\s*["\']throttle/i', $line) ||  // Varargs
               preg_match('/ThrottleRequests::class/i', $line);  // Class reference
    }

    /**
     * Whether a 1-based line falls within any of the given inclusive ranges.
     *
     * @param  array<int, array{start: int, end: int}>  $ranges
     */
    private function lineInRanges(int $line, array $ranges): bool
    {
        foreach ($ranges as $range) {
            if ($line >= $range['start'] && $line <= $range['end']) {
                return true;
            }
        }

        return false;
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
     * Whether middleware a controller registers on itself applies to this method and
     * throttles login.
     *
     * @param  array<int, array{class: string, only: array<int, string>|null, except: array<int, string>}>  $registered
     */
    private function registeredMiddlewareThrottles(array $registered, string $methodName): bool
    {
        $method = strtolower($methodName);
        foreach ($registered as $middleware) {
            if (($middleware['only'] === null || in_array($method, $middleware['only'], true))
                && ! in_array($method, $middleware['except'], true)
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
     * Whether a request-class method reaches a RateLimiter call, directly or through
     * $this->method() calls within the same class.
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
     * Whether a class a route statement names throttles login itself: its
     * controller, or a middleware class it passes by ::class.
     *
     * Names come from controllersReferencedByRoute(). One outside App\ (a string
     * action or a name the route file never imported) is read as relative to
     * App\Http\Controllers, the namespace legacy route groups and laravel/ui fall
     * back to. Nothing looser: a name that does not resolve to a file covers nothing.
     *
     * @param  array<int, string>  $names
     */
    private function routeClassesThrottle(array $names): bool
    {
        foreach ($names as $name) {
            $fqn = str_starts_with($name, 'App\\') ? $name : 'App\\Http\\Controllers\\'.$name;
            if ($this->classThrottlesLogin($fqn)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether an App\ class throttles login: its file has login throttling, it uses
     * AuthenticatesUsers or ThrottlesLogins, one of its methods delegates to a
     * throttling FormRequest, or a class it reaches does (see reachedClasses()).
     * Memoised for the run.
     */
    private function classThrottlesLogin(string $fqn): bool
    {
        if (isset($this->throttlingClasses[$fqn])) {
            return $this->throttlingClasses[$fqn];
        }

        // Seeded so an inheritance or middleware cycle ends instead of recursing
        $this->throttlingClasses[$fqn] = false;

        $path = $this->appClassPath($fqn);
        if ($path === null) {
            return false;
        }

        if ($this->hasLoginThrottlingInFile($path) || $this->usesLoginThrottlingTrait($path)) {
            return $this->throttlingClasses[$fqn] = true;
        }

        $delegates = false;
        $reached = $this->reachedClasses($path, $fqn, $delegates);
        if ($delegates) {
            return $this->throttlingClasses[$fqn] = true;
        }

        foreach ($reached as $class) {
            if ($this->classThrottlesLogin($class)) {
                return $this->throttlingClasses[$fqn] = true;
            }
        }

        return false;
    }

    /**
     * The classes whose throttling an App\ class takes on: the traits it uses, the
     * class it extends, and the middleware it registers on itself, in a constructor
     * ($this->middleware(...)) or through HasMiddleware's static middleware().
     * Also sets $delegates when one of its own methods delegates to a throttling
     * FormRequest.
     *
     * Middleware is credited whatever only()/except() it is limited to: the
     * route names the controller, not the method.
     *
     * @return array<int, string>
     */
    private function reachedClasses(string $path, string $fqn, bool &$delegates): array
    {
        $ast = $this->parser->parseFile($path);
        $shortName = substr($fqn, (int) strrpos($fqn, '\\') + 1);

        // Names in the class resolve against its own imports. The caller's table is
        // put back afterwards: a route file's remaining routes are still read with it.
        $callerImports = $this->importedNames;
        $this->trackFileImports($ast);

        $reached = [];
        foreach ($this->parser->findNodes($ast, Node\Stmt\ClassLike::class) as $class) {
            if (! ($class instanceof Node\Stmt\Class_ || $class instanceof Node\Stmt\Trait_)
                || $class->name?->toString() !== $shortName) {
                continue;
            }

            foreach ($class->getMethods() as $method) {
                if ($this->delegatesToThrottlingRequest($method)) {
                    $delegates = true;
                }

                foreach ($this->middlewareRegisteredBy($method) as $middleware) {
                    $reached[] = $middleware['class'];
                }
            }

            foreach ($this->inheritedNames($class) as $name) {
                $reached[] = $this->resolvedClassFqn($name);
            }

            break;
        }

        $this->importedNames = $callerImports;

        return $reached;
    }

    /**
     * Middleware classes a controller method registers on its own controller,
     * with the methods it is limited to: $this->middleware(...)->only(...) /
     * ->except(...) in the constructor, or the list HasMiddleware's static
     * middleware() returns, with new Middleware(..., only: ..., except: ...).
     * Method names are lowercased; a null only means every method.
     *
     * @return array<int, array{class: string, only: array<int, string>|null, except: array<int, string>}>
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
                    foreach ($this->middlewareClassesIn($call->args[0]->value) as $class) {
                        $registered[] = ['class' => $class, 'only' => $filter['only'] ?? null, 'except' => $filter['except'] ?? []];
                    }
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
     * @return array<int, array{class: string, only: array<int, string>|null, except: array<int, string>}>
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

        if ($value === null) {
            return [];
        }

        return array_map(
            fn (string $class): array => ['class' => $class, 'only' => $only, 'except' => $except],
            $this->middlewareClassesIn($value),
        );
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
     * A name that resolves to no class (a built-in alias like 'auth' that the
     * app does not register) is dropped.
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
            $name = strtok($expr->value, ':');
            if ($name === false) {
                return [];
            }

            if (str_contains($name, '\\')) {
                return [ltrim($name, '\\')];
            }

            return isset($this->middlewareAliases[$name]) ? [$this->middlewareAliases[$name]] : [];
        }

        $class = $this->middlewareClassName($expr);

        return $class === null ? [] : [$class];
    }

    /**
     * The class an X::class or X::class.':params' expression names, resolved
     * against the current import table.
     */
    private function middlewareClassName(Node\Expr $expr): ?string
    {
        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->middlewareClassName($expr->left);
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

        // Check all provider files for RateLimiter configuration
        $providerPath = $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Providers';
        $hasLoginRateLimiter = false;
        $hasDisabledThrottling = false;
        $throttleDisabledFile = null;

        if (is_dir($providerPath)) {
            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($providerPath, \RecursiveDirectoryIterator::SKIP_DOTS)
                );

                foreach ($iterator as $file) {
                    if (! $file instanceof \SplFileInfo) {
                        continue;
                    }

                    if ($file->isFile() && $file->getExtension() === 'php') {
                        $content = $this->readCode($file->getPathname());
                        if ($content === null) {
                            continue;
                        }

                        // Check if Fortify throttling is explicitly disabled
                        if (preg_match('/RateLimiter::for\s*\(\s*["\']login["\']\s*,\s*.*Limit::none\(\)/is', $content)) {
                            $hasDisabledThrottling = true;
                            $throttleDisabledFile = $file->getPathname();
                        }

                        // Check if custom login rate limiter is defined
                        if (preg_match('/RateLimiter::for\s*\(\s*["\']login["\']\s*,/i', $content)) {
                            $hasLoginRateLimiter = true;
                        }
                    }
                }
            } catch (\Throwable $e) {
                // Silently fail if directory iterator fails
            }
        }

        // If throttling is explicitly disabled, flag as critical
        if ($hasDisabledThrottling && $throttleDisabledFile !== null) {
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

            return;
        }

        // If custom login rate limiter is defined, we're good
        if ($hasLoginRateLimiter) {
            return;
        }

        // Check Fortify configuration file
        $fortifyConfigPath = $basePath.DIRECTORY_SEPARATOR.'config'.DIRECTORY_SEPARATOR.'fortify.php';
        if (file_exists($fortifyConfigPath)) {
            $fortifyConfig = $this->readCode($fortifyConfigPath);
            if ($fortifyConfig !== null) {
                // Check if limiters configuration exists
                if (! preg_match('/["\']limiters["\']\s*=>/i', $fortifyConfig)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Fortify authentication lacks custom rate limiter configuration',
                        filePath: $fortifyConfigPath,
                        lineNumber: 1,
                        severity: Severity::High,
                        recommendation: 'Configure login rate limiting in config/fortify.php or register a named rate limiter for the login endpoint in a service provider.',
                        metadata: [
                            'framework' => 'fortify',
                            'issue_type' => 'fortify_no_custom_limiter',
                        ]
                    );
                }
            }
        }
    }
}
