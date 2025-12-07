<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use PhpParser\Node;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

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
    private array $publicRoutes = [
        'login',
        'register',
        'password',
        'forgot-password',
        'reset-password',
        'verify',
        'health',
        'status',
    ];

    public function __construct(
        private ParserInterface $parser
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
        $issues = [];

        // Check route files
        $routeFiles = $this->getRouteFiles();
        foreach ($routeFiles as $file) {
            $this->checkRouteFile($file, $issues);
        }

        // Check controllers
        $controllers = $this->getControllerFiles();
        foreach ($controllers as $file) {
            $this->checkController($file, $issues);
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

        foreach ($lines as $lineNumber => $line) {
            // Check for routes without middleware
            if (preg_match('/Route::(get|post|put|patch|delete|resource|apiResource)\s*\(/i', $line, $matches)) {
                $method = strtoupper($matches[1]);

                // Skip if it's clearly a public route
                if ($this->isPublicRoute($line)) {
                    continue;
                }

                // Check if route has auth middleware
                $searchRange = min($lineNumber + 10, count($lines));
                $hasAuthMiddleware = false;
                $routeDefinition = '';

                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    $routeDefinition .= $lines[$i];

                    if (preg_match('/->middleware\s*\(\s*["\']auth["\']|->middleware\s*\(\s*\[[^\]]*["\']auth["\']/i', $lines[$i])) {
                        $hasAuthMiddleware = true;
                        break;
                    }

                    if (str_contains($lines[$i], ';')) {
                        break;
                    }
                }

                // Resource routes that modify data should require auth
                if (! $hasAuthMiddleware && in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE', 'RESOURCE', 'APIRESOURCE'])) {
                    $issues[] = $this->createIssue(
                        message: sprintf('%s route without authentication middleware', $method),
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::High,
                        recommendation: 'Add ->middleware("auth") or wrap in Route::middleware(["auth"])->group()',
                        code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                        metadata: ['method' => $method]
                    );
                }
            }

            // Check for route groups without middleware
            if (preg_match('/Route::group\s*\(/i', $line)) {
                $searchRange = min($lineNumber + 5, count($lines));
                $hasAuthMiddleware = false;

                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    if (preg_match('/["\']middleware["\']\s*=>\s*.*?["\']auth["\']/', $lines[$i])) {
                        $hasAuthMiddleware = true;
                        break;
                    }
                }

                if (! $hasAuthMiddleware && ! $this->isPublicRoute($line)) {
                    $issues[] = $this->createIssue(
                        message: 'Route group without authentication middleware',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Medium,
                        recommendation: 'Add "middleware" => "auth" to route group configuration',
                        code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                        metadata: ['route_type' => 'group', 'file' => basename($file)]
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
            $hasAuthMiddleware = $this->hasAuthMiddlewareInConstructor($class);

            // Check public methods
            foreach ($class->stmts as $stmt) {
                if ($stmt instanceof Node\Stmt\ClassMethod) {
                    $methodName = $stmt->name->toString();

                    // Skip constructors and special methods
                    if (in_array($methodName, ['__construct', '__invoke', 'middleware'])) {
                        continue;
                    }

                    // Skip if method is not public
                    if (! $stmt->isPublic()) {
                        continue;
                    }

                    // Check sensitive methods
                    if (in_array($methodName, $this->sensitiveControllerMethods)) {
                        if (! $hasAuthMiddleware && ! $this->hasAuthCheckInMethod($stmt)) {
                            $issues[] = $this->createIssue(
                                message: "Sensitive method {$className}::{$methodName}() without authentication check",
                                location: new Location(
                                    $this->getRelativePath($file),
                                    $stmt->getLine()
                                ),
                                severity: Severity::High,
                                recommendation: 'Add $this->middleware("auth") in constructor or use authorization checks',
                                code: FileParser::getCodeSnippet($file, $stmt->getLine())
                            );
                        }
                    }
                }
            }
        }
    }

    /**
     * Check if controller has auth middleware in constructor.
     */
    private function hasAuthMiddlewareInConstructor(Node\Stmt\Class_ $class): bool
    {
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\ClassMethod && $stmt->name->toString() === '__construct') {
                foreach ($stmt->stmts as $constructorStmt) {
                    if ($constructorStmt instanceof Node\Stmt\Expression) {
                        $expr = $constructorStmt->expr;

                        if ($expr instanceof Node\Expr\MethodCall) {
                            if ($expr->name instanceof Node\Identifier && $expr->name->toString() === 'middleware') {
                                // Check if 'auth' is in the arguments
                                foreach ($expr->args as $arg) {
                                    $value = $arg->value;
                                    if ($value instanceof Node\Scalar\String_ && str_contains($value->value, 'auth')) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check if method has authorization checks.
     */
    private function hasAuthCheckInMethod(Node\Stmt\ClassMethod $method): bool
    {
        foreach ($method->stmts as $stmt) {
            // Check for $this->authorize()
            if ($stmt instanceof Node\Stmt\Expression &&
                $stmt->expr instanceof Node\Expr\MethodCall &&
                $stmt->expr->name instanceof Node\Identifier &&
                $stmt->expr->name->toString() === 'authorize') {
                return true;
            }

            // Check for Gate::authorize() or Gate::allows()
            if ($this->hasGateCheck($stmt)) {
                return true;
            }

            // Check for policy checks
            if ($this->hasPolicyCheck($stmt)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for Gate authorization in a statement.
     *
     * Looks for Gate::authorize(), Gate::allows(), Gate::denies(), Gate::check()
     */
    private function hasGateCheck(Node $stmt): bool
    {
        if ($stmt instanceof Node\Stmt\Expression) {
            $expr = $stmt->expr;

            if ($expr instanceof Node\Expr\StaticCall) {
                if ($expr->class instanceof Node\Name && $expr->class->toString() === 'Gate') {
                    if ($expr->name instanceof Node\Identifier &&
                        in_array($expr->name->toString(), ['authorize', 'allows', 'denies', 'check'])) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check for policy checks in a statement.
     *
     * Looks for ->can(), ->cannot(), ->authorize() method calls
     */
    private function hasPolicyCheck(Node $stmt): bool
    {
        if ($stmt instanceof Node\Stmt\Expression) {
            $expr = $stmt->expr;

            if ($expr instanceof Node\Expr\MethodCall) {
                if ($expr->name instanceof Node\Identifier &&
                    in_array($expr->name->toString(), ['can', 'cannot', 'authorize'])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check for unsafe Auth::user() usage without null checks.
     */
    private function checkUnsafeAuthUsage(string $file, array &$issues): void
    {
        $lines = FileParser::getLines($file);

        foreach ($lines as $lineNumber => $line) {
            // Check for Auth::user()->
            if (preg_match('/Auth::user\(\)->/i', $line)) {
                $this->checkAuthUsageWithNullSafety(
                    file: $file,
                    lines: $lines,
                    lineNumber: $lineNumber,
                    method: 'Auth::user()',
                    checkMethod: 'Auth::check()',
                    issues: $issues
                );
            }

            // Check for auth()->user()->
            if (preg_match('/auth\(\)->user\(\)->/i', $line)) {
                $this->checkAuthUsageWithNullSafety(
                    file: $file,
                    lines: $lines,
                    lineNumber: $lineNumber,
                    method: 'auth()->user()',
                    checkMethod: 'auth()->check()',
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
            $issues[] = $this->createIssue(
                message: "Unsafe {$method} usage without null check",
                location: new Location(
                    $this->getRelativePath($file),
                    $lineNumber + 1
                ),
                severity: Severity::Medium,
                recommendation: "Check if user is authenticated before accessing: if ({$checkMethod}) or use {$method}?->property",
                code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                metadata: [
                    'method' => $method,
                    'check_method' => $checkMethod,
                    'file' => basename($file),
                ]
            );
        }
    }

    /**
     * Check if a line contains an auth null check.
     */
    private function hasAuthNullCheck(string $line): bool
    {
        // Look for actual auth checks: Auth::check(), auth()->check(), if (Auth::user()), if (auth()->user())
        return (bool) preg_match(
            '/(?:Auth::check\(\)|auth\(\)->check\(\)|if\s*\(\s*Auth::user\(\)|if\s*\(\s*auth\(\)->user\(\))/i',
            $line
        );
    }

    /**
     * Check if route is a known public route.
     */
    private function isPublicRoute(string $line): bool
    {
        foreach ($this->publicRoutes as $route) {
            if (str_contains($line, $route)) {
                return true;
            }
        }

        return false;
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
