<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

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

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'authentication-authorization',
            name: 'Authentication & Authorization Analyzer',
            description: 'Detects missing authentication and authorization protection on routes and controllers',
            category: Category::Security,
            severity: Severity::High,
            tags: ['authentication', 'authorization', 'security', 'middleware'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/authentication-authorization',
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

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Load public routes from configuration.
     */
    private function loadPublicRoutes(): void
    {
        $defaultRoutes = [
            'login',
            'register',
            'password',
            'forgot-password',
            'reset-password',
            'verify',
            'health',
            'status',
            'up',
            'webhook',
        ];

        $configRoutes = $this->config->get('shieldci.analyzers.security.authentication-authorization.public_routes', []);

        // Ensure configRoutes is an array
        if (! is_array($configRoutes)) {
            $configRoutes = [];
        }

        // Merge config routes with defaults, ensuring no duplicates
        $this->publicRoutes = array_values(array_unique(array_merge($defaultRoutes, $configRoutes)));
    }

    /**
     * Build route-level authentication statistics per controller method.
     *
     * - Tracks total routes pointing to each controller method
     * - Tracks how many of those routes are authenticated
     * - Tracks intentionally public controller methods
     */
    private function buildPublicControllerMap(string $file): void
    {
        $lines = FileParser::getLines($file);
        $routeGroups = $this->identifyRouteGroups($lines);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Match route definitions
            if (! preg_match('/Route::(get|post|put|patch|delete|resource|apiResource)\s*\(/i', $line)) {
                continue;
            }

            // Extract controller + method
            $controllerMethod = $this->extractControllerMethod($line, $lines, $lineNumber);
            if ($controllerMethod === null) {
                continue;
            }

            // Ensure stats bucket exists
            if (! isset($this->routeAuthStats[$controllerMethod])) {
                $this->routeAuthStats[$controllerMethod] = [
                    'total' => 0,
                    'authenticated' => 0,
                ];
            }

            // Count this route
            $this->routeAuthStats[$controllerMethod]['total']++;

            // Explicit public route always wins
            if (
                $this->isPublicRouteLine($line) ||
                $this->routeHasExplicitAuthRemoval($lineNumber, $lines)
            ) {
                $this->publicControllerMethods[$controllerMethod] = true;

                continue;
            }

            // Check if this specific route is authenticated
            $isAuthenticated = $this->isRouteAuthenticated($lineNumber, $lines, $routeGroups);

            if ($isAuthenticated) {
                $this->routeAuthStats[$controllerMethod]['authenticated']++;
            }
        }
    }

    /**
     * Extract controller and method from a route line.
     * Returns format: 'ControllerClass::method' or null if not found.
     */
    private function extractControllerMethod(string $line, array $lines, int $lineNumber): ?string
    {
        // Look for [ControllerClass::class, 'method'] pattern
        $searchRange = min($lineNumber + 10, count($lines));
        $routeContent = '';

        for ($i = $lineNumber; $i < $searchRange; $i++) {
            if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                continue;
            }

            $routeContent .= $lines[$i];

            if (str_contains($lines[$i], ';')) {
                break;
            }
        }

        // Match [SomeController::class, 'method']
        if (preg_match('/\[([A-Za-z_\\\\]+)::class,\s*[\'"]([a-zA-Z_][a-zA-Z0-9_]*)[\'"]/', $routeContent, $matches)) {
            $controller = $matches[1];
            $method = $matches[2];

            // Extract just the class name if it's fully qualified
            $parts = explode('\\', $controller);
            $className = end($parts);

            return "{$className}::{$method}";
        }

        return null;
    }

    /**
     * Check route files for missing authentication.
     */
    private function checkRouteFile(string $file, array &$issues): void
    {
        // Skip api.php if it uses sanctum/passport
        if (str_contains($file, 'api.php')) {
            $content = FileParser::readFile($file);
            if ($content !== null && (str_contains($content, 'sanctum') || str_contains($content, 'passport'))) {
                return;
            }
        }

        $lines = FileParser::getLines($file);

        // First pass: Identify route groups and their auth status
        // Track groups as [startLine => endLine, hasAuth => bool]
        $routeGroups = $this->identifyRouteGroups($lines);

        // Second pass: Check individual routes and route groups
        foreach ($lines as $lineNumber => $line) {
            // Check for route groups without middleware
            if (preg_match('/Route::group\s*\(/i', $line)) {
                $hasAuthMiddleware = $this->checkRouteGroupForAuth($lines, $lineNumber);

                // Check if this route group is inside a protected parent group
                // If it is, don't flag it (routes inside will be protected by parent)
                $isInProtectedParentGroup = $this->isRouteGroupInProtectedParentGroup($lineNumber, $routeGroups);

                if (! $hasAuthMiddleware && ! $isInProtectedParentGroup && ! $this->isPublicRouteLine($line)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Route group without authentication middleware',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Add auth middleware to this route group',
                        metadata: ['route_type' => 'group', 'file' => basename($file)]
                    );
                }
            }

            // Check for routes without middleware
            if (preg_match('/Route::(get|post|put|patch|delete|resource|apiResource)\s*\(/i', $line, $matches)) {
                $method = strtoupper($matches[1]);

                // Skip if it's clearly a public route
                if ($this->isPublicRouteLine($line)) {
                    continue;
                }

                // Check if route has auth middleware directly (early optimization)
                // Supports auth, auth:api, auth:sanctum, auth:web, etc.
                $searchRange = min($lineNumber + 10, count($lines));

                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                        continue;
                    }

                    if (preg_match('/->middleware\s*\(\s*["\']auth(?::[a-zA-Z0-9_-]+)?["\']|->middleware\s*\(\s*\[[^\]]*["\']auth(?::[a-zA-Z0-9_-]+)?["\']/i', $lines[$i])) {
                        break;
                    }

                    if (str_contains($lines[$i], ';')) {
                        break;
                    }
                }

                if ($this->routeHasExplicitAuthRemoval($lineNumber, $lines)) {
                    continue; // explicit opt-out wins, skip entirely
                }

                $isAuthenticated = $this->isRouteAuthenticated($lineNumber, $lines, $routeGroups);
                $isMutation = $this->isMutationRoute($method);

                if (! $isAuthenticated && $isMutation) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: "{$method} route without authentication middleware",
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Protect this route with auth middleware or wrap in Route::middleware(["auth"])->group()',
                        metadata: [
                            'type' => 'authentication',
                            'method' => $method,
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check controller for missing authentication.
     */
    private function checkController(string $file, array &$issues): void
    {
        $ast = $this->parser->parseFile($file);
        if (empty($ast)) {
            return;
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
                        // Skip if this controller method is intentionally public (from route analysis)
                        $controllerMethodKey = "{$className}::{$methodName}";
                        if (isset($this->publicControllerMethods[$controllerMethodKey])) {
                            continue; // Method is intentionally public via route-level decision
                        }

                        // Check if method has controller-level auth middleware
                        $hasAuthMiddleware = $this->isControllerMethodAuthenticated($methodName, $constructorMiddlewareInfo, $middlewareMethodInfo);

                        // Also consider method authenticated if protected at route level
                        $stats = $this->routeAuthStats[$controllerMethodKey] ?? null;

                        $isRouteProtected = $stats !== null && $stats['total'] > 0 && $stats['authenticated'] === $stats['total'];

                        if (! $hasAuthMiddleware && ! $isRouteProtected) {
                            $issues[] = $this->createIssueWithSnippet(
                                message: "Sensitive method {$className}::{$methodName}() without authentication check",
                                filePath: $file,
                                lineNumber: $stmt->getLine(),
                                severity: Severity::High,
                                recommendation: 'Add $this->middleware("auth") in constructor or protect all routes to this method with route-level auth middleware'
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
                $issues[] = $this->createIssueWithSnippet(
                    message: "{$className}::authorize() returns true without authorization checks",
                    filePath: $file,
                    lineNumber: $authorizeMethod->getLine(),
                    severity: Severity::High,
                    recommendation: 'Add proper authorization logic to the authorize() method or remove it to deny by default',
                    metadata: [
                        'type' => 'form_request_authorization',
                        'class' => $className,
                    ]
                );
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
                    $value = $arg->value;
                    if ($value instanceof Node\Scalar\String_ && $this->isAuthMiddleware($value->value)) {
                        $middlewareName = $value->value;
                    }
                    // Also check array arguments like ['auth', 'verified']
                    if ($value instanceof Node\Expr\Array_) {
                        foreach ($value->items as $item) {
                            if ($item instanceof Node\Expr\ArrayItem && $item->value instanceof Node\Scalar\String_) {
                                if ($this->isAuthMiddleware($item->value->value)) {
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
                    $value = $arg->value;
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

                            // Get the key (middleware name like 'auth' or 'auth:api')
                            $key = $this->extractArrayKeyValue($item->key);

                            if ($key === null || ! $this->isAuthMiddleware($key)) {
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
     * Check if middleware method provides authentication.
     *
     * @param  array<string, array{only?: array<string>, except?: array<string>}>|null  $middlewareInfo
     */
    private function middlewareMethodProvidesAuthentication(string $methodName, ?array $middlewareInfo): bool
    {
        if ($middlewareInfo === null) {
            return false;
        }

        foreach ($middlewareInfo as $middlewareName => $constraints) {
            if (! $this->isAuthMiddleware($middlewareName)) {
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
     * Check if a line removes auth middleware.
     * Supports: auth, auth:api, auth:sanctum, auth:web, etc.
     */
    private function removesAuthMiddleware(string $line): bool
    {
        return (bool) preg_match(
            '/->withoutMiddleware\s*\(\s*(?:\[[^\]]*["\']auth(?::[a-zA-Z0-9_-]+)?["\']|["\']auth(?::[a-zA-Z0-9_-]+)?["\'])/i',
            $line
        );
    }

    /**
     * Check for unsafe Auth::user() usage without null checks.
     */
    private function checkUnsafeAuthUsage(string $file, array &$issues): void
    {
        $lines = FileParser::getLines($file);

        foreach ($lines as $lineNumber => $line) {
            // Check for Auth::user()-> (but NOT Auth::user()?-> which is safe)
            if (preg_match('/Auth::user\(\)\s*->/i', $line) && ! preg_match('/Auth::user\(\)\s*\?->/i', $line)) {
                $this->checkAuthUsageWithNullSafety(
                    file: $file,
                    lines: $lines,
                    lineNumber: $lineNumber,
                    method: 'Auth::user()',
                    checkMethod: 'Auth::check()',
                    issues: $issues
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
                    issues: $issues
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
                    issues: $issues
                );
            }
        }
    }

    /**
     * Check if auth method is used with proper null safety.
     */
    private function checkAuthUsageWithNullSafety(
        string $file,
        array $lines,
        int $lineNumber,
        string $method,
        string $checkMethod,
        array &$issues
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
            $issues[] = $this->createIssueWithSnippet(
                message: "Unsafe {$method} usage without null check",
                filePath: $file,
                lineNumber: $lineNumber + 1,
                severity: Severity::Medium,
                recommendation: "Check if user is authenticated before accessing: if ({$checkMethod}) or use {$method}?->property",
                metadata: [
                    'method' => $method,
                    'check_method' => $checkMethod,
                    'file' => basename($file),
                ]
            );
        }
    }

    /**
     * Check if a middleware name represents authentication middleware.
     * Supports: auth, auth:api, auth:sanctum, auth:web, etc.
     */
    private function isAuthMiddleware(string $middleware): bool
    {
        // Match 'auth' optionally followed by a colon and guard name
        // Examples: 'auth', 'auth:api', 'auth:sanctum', 'auth:web'
        return (bool) preg_match('/^auth(?::[a-zA-Z0-9_-]+)?$/i', trim($middleware));
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
     * Check if a route is authenticated.
     *
     * @param  array<int, string>  $lines
     * @param  array<int, array{startLine: int, endLine: int, hasAuth: bool}>  $routeGroups
     */
    private function isRouteAuthenticated(int $lineNumber, array $lines, array $routeGroups): bool
    {
        // 🔥 Hard stop: route explicitly removes auth
        if ($this->routeHasExplicitAuthRemoval($lineNumber, $lines)) {
            return false;
        }

        $isAuthenticated = false;

        // Inherited from group
        if ($this->isRouteInProtectedGroup($lineNumber, $routeGroups)) {
            $isAuthenticated = true;
        }

        // Direct middleware on route
        $searchRange = min($lineNumber + 10, count($lines));
        for ($i = $lineNumber; $i < $searchRange; $i++) {
            if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                continue;
            }

            if ($this->addsAuthMiddleware($lines[$i])) {
                $isAuthenticated = true;
            }

            if ($this->removesAuthMiddleware($lines[$i])) {
                return false;
            }

            if (str_contains($lines[$i], ';')) {
                break;
            }
        }

        return $isAuthenticated;
    }

    /**
     * Check if a route has explicit auth removal.
     */
    private function routeHasExplicitAuthRemoval(int $lineNumber, array $lines): bool
    {
        $searchRange = min($lineNumber + 10, count($lines));

        for ($i = $lineNumber; $i < $searchRange; $i++) {
            if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                continue;
            }

            if ($this->removesAuthMiddleware($lines[$i])) {
                return true;
            }

            if (str_contains($lines[$i], ';')) {
                break;
            }
        }

        return false;
    }

    /**
     * Check if a line adds auth middleware.
     * Supports: auth, auth:api, auth:sanctum, auth:web, etc.
     */
    private function addsAuthMiddleware(string $line): bool
    {
        return (bool) preg_match(
            '/->middleware\s*\(\s*(?:\[[^\]]*["\']auth(?::[a-zA-Z0-9_-]+)?["\']|["\']auth(?::[a-zA-Z0-9_-]+)?["\'])/i',
            $line
        );
    }

    /**
     * Identify all route groups in the file and determine their auth status.
     *
     * @param  array<int, string>  $lines
     * @return array<int, array{startLine: int, endLine: int, hasAuth: bool}>
     */
    private function identifyRouteGroups(array $lines): array
    {
        $groups = [];
        $totalLines = count($lines);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Match both Route::group() and Route::*()->group() patterns
            if (preg_match('/->group\s*\(|Route::group\s*\(/i', $line)) {
                $hasAuth = $this->checkRouteGroupForAuth($lines, $lineNumber);
                $endLine = $this->findRouteGroupEndLine($lines, $lineNumber, $totalLines);

                $groups[] = [
                    'startLine' => $lineNumber,
                    'endLine' => $endLine,
                    'hasAuth' => $hasAuth,
                ];
            }
        }

        return $groups;
    }

    /**
     * Find the end line of a route group by matching opening/closing braces.
     *
     * @param  array<int, string>  $lines
     * @return int The line number where the route group ends (inclusive)
     */
    private function findRouteGroupEndLine(array $lines, int $startLine, int $totalLines): int
    {
        // Look for the closing brace of the route group's closure
        $braceCount = 0;
        $inGroup = false;
        // Use a larger search range to handle large route groups (up to 500 lines)
        // This is necessary for real-world applications with many routes
        $searchRange = min($startLine + 500, $totalLines);

        for ($i = $startLine; $i < $searchRange; $i++) {
            if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                continue;
            }

            $line = $lines[$i];

            // Count opening braces
            $braceCount += substr_count($line, '{') - substr_count($line, '}');

            // Once we enter the closure (after the array definition)
            if (str_contains($line, 'function') || str_contains($line, 'fn(')) {
                $inGroup = true;
            }

            // If we're in the group and braces are balanced, we found the end
            if ($inGroup && $braceCount === 0 && str_contains($line, '}')) {
                return $i;
            }
        }

        // Fallback: if we couldn't find the exact end, search backwards from the end
        // to find the last closing brace that might be our group's end
        // This handles edge cases where the group is very large
        for ($i = min($startLine + 500, $totalLines - 1); $i > $startLine; $i--) {
            if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                continue;
            }

            if (str_contains($lines[$i], '}')) {
                return $i;
            }
        }

        // Final fallback: return end of file
        return $totalLines - 1;
    }

    /**
     * Check if a route at the given line number is inside a protected route group.
     *
     * Handles nested groups: if a route is inside multiple nested groups,
     * it's considered protected if ANY of those groups has auth middleware.
     *
     * @param  array<int, array{startLine: int, endLine: int, hasAuth: bool}>  $routeGroups
     */
    private function isRouteInProtectedGroup(int $routeLineNumber, array $routeGroups): bool
    {
        foreach ($routeGroups as $group) {
            if (
                $routeLineNumber >= $group['startLine'] &&
                $routeLineNumber <= $group['endLine'] &&
                $group['hasAuth']
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a route group at the given line number is inside a protected parent route group.
     *
     * A route group should not be flagged if it's nested inside a protected parent group,
     * as routes inside it will be protected by the parent's middleware.
     *
     * @param  int  $groupLineNumber  The line number where the route group starts
     * @param  array<int, array{startLine: int, endLine: int, hasAuth: bool}>  $routeGroups
     */
    private function isRouteGroupInProtectedParentGroup(int $groupLineNumber, array $routeGroups): bool
    {
        // Find all groups that contain this route group (parent groups)
        foreach ($routeGroups as $group) {
            // Skip the group itself (we're looking for parent groups)
            if ($group['startLine'] === $groupLineNumber) {
                continue;
            }

            // Check if this route group is within a parent group's boundaries
            if ($groupLineNumber > $group['startLine'] && $groupLineNumber < $group['endLine']) {
                // If the parent group has auth, this nested group is protected
                if ($group['hasAuth']) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if route group has authentication middleware.
     * Supports both string and array syntax for middleware.
     *
     * Examples:
     * - 'middleware' => 'auth'
     * - 'middleware' => ['auth']
     * - 'middleware' => ['login.user', 'auth', 'auth.admin']
     */
    private function checkRouteGroupForAuth(array $lines, int $startLine): bool
    {
        // Search for the route group definition (usually within 15-20 lines)
        $searchRange = min($startLine + 20, count($lines));
        $groupDefinition = '';

        // Collect the route group definition across multiple lines
        for ($i = $startLine; $i < $searchRange; $i++) {
            if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                continue;
            }

            $groupDefinition .= $lines[$i]."\n";

            // Stop when we find the closing of the array and function call
            // This handles both single-line and multi-line array definitions
            if (str_contains($lines[$i], '],') || str_contains($lines[$i], '], function')) {
                break;
            }
        }

        // Check for chained middleware: Route::middleware('auth')->group() or Route->middleware(['auth'])->group()
        // Must match both :: (static) and -> (instance) calls
        // Supports auth, auth:api, auth:sanctum, auth:web
        if (preg_match('/(->|::)middleware\s*\(\s*["\']auth(?::[a-zA-Z0-9_-]+)?["\']\s*\)|(->|::)middleware\s*\(\s*\[[^\]]*["\']auth(?::[a-zA-Z0-9_-]+)?["\'][^\]]*\]\s*\)/i', $groupDefinition)) {
            return true;
        }

        // Check for string middleware: 'middleware' => 'auth' or "middleware" => "auth:api"
        if (preg_match('/["\']middleware["\']\s*=>\s*["\']auth(?::[a-zA-Z0-9_-]+)?["\']/i', $groupDefinition)) {
            return true;
        }

        // Check for array middleware: 'middleware' => ['auth', ...] or ['login.user', 'auth:api', 'auth.admin']
        // First, try simple single-line array pattern
        if (preg_match('/["\']middleware["\']\s*=>\s*\[[^\]]*["\']auth(?::[a-zA-Z0-9_-]+)?["\'][^\]]*\]/i', $groupDefinition)) {
            return true;
        }

        // Handle multi-line arrays - find the middleware array and extract its content
        if (preg_match('/["\']middleware["\']\s*=>\s*\[/i', $groupDefinition, $matches, PREG_OFFSET_CAPTURE)) {
            $matchPos = $matches[0][1];
            $afterMatch = substr($groupDefinition, $matchPos);

            // Find the opening bracket position after 'middleware' => [
            $bracketStart = strpos($afterMatch, '[');
            if ($bracketStart === false) {
                return false;
            }

            // Find the matching closing bracket (handle nested arrays)
            $bracketCount = 1;
            $arrayContent = '';
            $pos = $bracketStart + 1;
            $maxPos = strlen($afterMatch);

            while ($pos < $maxPos) {
                $char = $afterMatch[$pos];

                if ($char === '[') {
                    $bracketCount++;
                } elseif ($char === ']') {
                    $bracketCount--;
                    if ($bracketCount === 0) {
                        break;
                    }
                }

                $arrayContent .= $char;
                $pos++;
            }

            // Check if 'auth' (with optional guard) appears in the array content
            // Matches: 'auth', 'auth:api', 'auth:sanctum', 'auth:web', etc.
            if (preg_match('/["\']auth(?::[a-zA-Z0-9_-]+)?["\']/i', $arrayContent)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a line is a public route line.
     */
    private function isPublicRouteLine(string $line): bool
    {
        return
            $this->hasPublicUri($line) ||
            $this->hasPublicRouteName($line) ||
            $this->hasGuestMiddleware($line);
    }

    /**
     * Check if a line has a public URI.
     */
    private function hasPublicUri(string $line): bool
    {
        foreach ($this->publicRoutes as $route) {
            if (preg_match(
                '/Route::\w+\s*\(\s*[\'"]\/?'.preg_quote($route, '/').'(?:\/|\'|")/i',
                $line
            )) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a line has a public route name.
     */
    private function hasPublicRouteName(string $line): bool
    {
        foreach ($this->publicRoutes as $route) {
            if (preg_match(
                '/->name\s*\(\s*[\'"]'.preg_quote($route, '/').'[\'"]\s*\)/i',
                $line
            )) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a line has a guest middleware.
     */
    private function hasGuestMiddleware(string $line): bool
    {
        return (bool) preg_match(
            '/->middleware\s*\(\s*(?:\[[^\]]*["\']guest["\']|["\']guest["\'])/i',
            $line
        );
    }

    /**
     * Get route files.
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
}
