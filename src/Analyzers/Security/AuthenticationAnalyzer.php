<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitorAbstract;
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
     * Cache of resolved custom middleware auth status.
     *
     * @var array<string, bool>
     */
    private array $resolvedAuthMiddleware = [];

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

        $this->publicRoutes = array_values(array_unique(array_merge($defaultRoutes, $configRoutes)));
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
        $nameTraverser = new NodeTraverser;
        $nameTraverser->addVisitor(new NameResolver(null, ['replaceNodes' => false]));
        $nameTraverser->traverse($ast);

        $visitor = new RouteAuthVisitor;
        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        foreach ($visitor->getCollectedRoutes() as $route) {
            $controller = $route['controller'];
            if ($controller === null) {
                continue; // closure routes: no controller to map
            }

            // Expand resource/apiResource routes to individual methods
            $controllerMethods = $this->expandControllerMethods($controller, $route['action'], $route['http_methods']);

            $isGuestRoute = in_array('guest', $route['middleware'], true);
            $isPublicUri = in_array($route['uri'], $this->publicRoutes, true);
            $hasExplicitAuthRemoval = $this->routeDirectRemoveHasAuth($route['direct_remove']);

            foreach ($controllerMethods as $method) {
                if (! isset($this->routeAuthStats[$method])) {
                    $this->routeAuthStats[$method] = ['total' => 0, 'authenticated' => 0];
                }
                $this->routeAuthStats[$method]['total']++;

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
     * Handles: 'auth', 'auth:api', 'can:ability', 'role:admin', 'permission:x',
     * and fully-qualified custom auth middleware class names.
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
            if (str_contains($mw, '\\') && $this->isCustomAuthMiddlewareClass($mw)) {
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
        $nameTraverser = new NodeTraverser;
        $nameTraverser->addVisitor(new NameResolver(null, ['replaceNodes' => false]));
        $nameTraverser->traverse($ast);

        $visitor = new RouteAuthVisitor;
        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        // Check route groups (only Route::group([...], fn) static-call style)
        foreach ($visitor->getCollectedGroups() as $group) {
            if (! $group['is_static_group']) {
                continue;
            }

            $allMiddleware = array_merge($group['inherited_middleware'], $group['middleware']);
            $hasAuth = $this->isRouteMiddlewareAuthenticated($allMiddleware);

            if (! $hasAuth && ! $group['has_guest']) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'Route group without authentication middleware',
                    filePath: $file,
                    lineNumber: $group['line'],
                    severity: Severity::High,
                    recommendation: 'Add auth middleware to this route group: Route::middleware(["auth"])->group(). If these routes are intentionally public, add their URIs to the public_routes config option.',
                    metadata: ['route_type' => 'group', 'file' => basename($file)]
                );
            }
        }

        // Check individual routes
        foreach ($visitor->getCollectedRoutes() as $route) {
            // Skip public URIs
            if (in_array($route['uri'], $this->publicRoutes, true)) {
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
                    severity: Severity::High,
                    recommendation: $isClosure
                        ? 'Add auth middleware: ->middleware("auth") or wrap in Route::middleware(["auth"])->group(). If intentionally public, add the route URI to the public_routes config option. Consider moving closure logic to a controller.'
                        : 'Protect this route with auth middleware or wrap in Route::middleware(["auth"])->group(). If intentionally public, add the route URI to the public_routes config option.',
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
                                recommendation: 'Add $this->middleware("auth") in constructor, or protect all routes to this method with route-level auth middleware. If intentionally public, add route URIs to the public_routes config option.'
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
                        recommendation: 'Add authorization logic in authorize() (e.g., return $this->user()->can(\'delete\', $model)), add auth middleware to the route, or add $this->middleware(\'auth\') in the controller constructor.',
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
                    $value = $arg->value;
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

        foreach ($lines as $lineNumber => $line) {
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
     * @param  array<\PhpParser\Node>  $ast
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
     * Return true when the method enclosing $lineNumber is guaranteed to receive
     * only authenticated requests, making Auth::user() / $request->user() non-null.
     *
     * @param  array<\PhpParser\Node>  $ast
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

        // Intentionally public (guest route, unauthenticated GET) → do not suppress
        if (isset($this->publicControllerMethods[$fqcnKey])
                || isset($this->publicControllerMethods[$shortKey])) {
            return false;
        }

        // Route-level: every known route to this method is authenticated
        $stats = $this->routeAuthStats[$fqcnKey] ?? $this->routeAuthStats[$shortKey] ?? null;
        if ($stats !== null && $stats['total'] > 0
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
     * @param  array<\PhpParser\Node>  $ast
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
     * Supports: auth, auth:api, auth:sanctum, auth:web, etc.
     */
    private function isAuthMiddleware(string $middleware): bool
    {
        // Match 'auth' optionally followed by a colon and guard name
        // Examples: 'auth', 'auth:api', 'auth:sanctum', 'auth:web'
        return (bool) preg_match('/^auth(?::[a-zA-Z0-9_-]+)?$/i', trim($middleware));
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
     * @var list<array{uri: string, http_methods: list<string>, controller: string|null, action: string|null, is_closure: bool, middleware: list<string>, direct_remove: list<string>, line: int}>
     */
    private array $collectedRoutes = [];

    /**
     * @var list<array{middleware: list<string>, inherited_middleware: list<string>, line: int, has_guest: bool, is_static_group: bool}>
     */
    private array $collectedGroups = [];

    /** @var list<string> Supported route HTTP verb method names (lowercase) */
    private const ROUTE_VERBS = ['get', 'post', 'put', 'patch', 'delete', 'resource', 'apiresource'];

    public function __construct() {}

    /**
     * @return list<array{uri: string, http_methods: list<string>, controller: string|null, action: string|null, is_closure: bool, middleware: list<string>, direct_remove: list<string>, line: int}>
     */
    public function getCollectedRoutes(): array
    {
        return $this->collectedRoutes;
    }

    /**
     * @return list<array{middleware: list<string>, inherited_middleware: list<string>, line: int, has_guest: bool, is_static_group: bool}>
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

            $this->collectedGroups[] = [
                'middleware' => $own['add'],
                'inherited_middleware' => $inherited,
                'line' => $node->getStartLine(),
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
        // Route::group([...], fn)
        if ($node instanceof Node\Expr\StaticCall
            && $node->name instanceof Node\Identifier
            && $node->name->toString() === 'group'
            && $node->class instanceof Node\Name
            && $this->isRouteFacade($node->class)) {
            return true;
        }

        // Route::middleware(...)->group(fn)  or  Route::withoutMiddleware(...)->group(fn)
        if ($node instanceof Node\Expr\MethodCall
            && $node->name instanceof Node\Identifier
            && $node->name->toString() === 'group'
            && $this->chainRootsToRoute($node->var)) {
            return true;
        }

        return false;
    }

    /**
     * Walk a MethodCall chain downward until we reach a StaticCall.
     * Returns true if that StaticCall is on the Route facade.
     */
    private function chainRootsToRoute(Node\Expr $node): bool
    {
        while ($node instanceof Node\Expr\MethodCall) {
            $node = $node->var;
        }

        return $node instanceof Node\Expr\StaticCall
            && $node->class instanceof Node\Name
            && $this->isRouteFacade($node->class);
    }

    /**
     * Extract the middleware this group node adds/removes from its own definition.
     *
     * For StaticCall Route::group(['middleware' => 'auth'], fn):
     *   → parses the config array's 'middleware' key.
     *
     * For MethodCall ->group() chains (e.g. Route::middleware('auth')->group(fn)):
     *   → walks the chain collecting ->middleware() and ->withoutMiddleware() calls,
     *     and also handles Route::middleware() / Route::withoutMiddleware() as the root.
     *
     * @return array{add: list<string>, remove: list<string>}
     */
    private function extractGroupMiddleware(Node $node): array
    {
        $add = [];
        $remove = [];

        if ($node instanceof Node\Expr\StaticCall) {
            // Route::group(['middleware' => ...], fn) — look at first arg
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

            return ['add' => $add, 'remove' => $remove];
        }

        if ($node instanceof Node\Expr\MethodCall) {
            // Walk the chain: [MethodCall ->group], [MethodCall ->middleware], ..., StaticCall Route::X
            $current = $node->var;

            while ($current instanceof Node\Expr\MethodCall) {
                if ($current->name instanceof Node\Identifier) {
                    $name = $current->name->toString();
                    if ($name === 'middleware') {
                        $add = array_merge($add, $this->extractMiddlewareArgs($current->args));
                    } elseif ($name === 'withoutMiddleware') {
                        $remove = array_merge($remove, $this->extractMiddlewareArgs($current->args));
                    }
                }
                $current = $current->var;
            }

            // Handle the StaticCall root: Route::middleware(...) or Route::withoutMiddleware(...)
            if ($current instanceof Node\Expr\StaticCall
                && $current->name instanceof Node\Identifier) {
                $name = $current->name->toString();
                if ($name === 'middleware') {
                    $add = array_merge($add, $this->extractMiddlewareArgs($current->args));
                } elseif ($name === 'withoutMiddleware') {
                    $remove = array_merge($remove, $this->extractMiddlewareArgs($current->args));
                }
            }
        }

        return ['add' => $add, 'remove' => $remove];
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
        $uri = $this->extractUri($current);
        [$controller, $action, $isClosure] = $this->extractHandler($current);

        // Collect direct middleware from the outer chain
        $directAdd = [];
        $directRemove = [];
        foreach ($chain as $methodCall) {
            if (! ($methodCall->name instanceof Node\Identifier)) {
                continue;
            }
            $name = $methodCall->name->toString();
            if ($name === 'middleware') {
                $directAdd = array_merge($directAdd, $this->extractMiddlewareArgs($methodCall->args));
            } elseif ($name === 'withoutMiddleware') {
                $directRemove = array_merge($directRemove, $this->extractMiddlewareArgs($methodCall->args));
            }
        }

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
            'http_methods' => [$httpMethod],
            'controller' => $controller,
            'action' => $action,
            'is_closure' => $isClosure,
            'middleware' => array_values($effective),
            'direct_remove' => $directRemove,
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
     * @param  array<Node\Arg|\PhpParser\Node\VariadicPlaceholder>  $args
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
