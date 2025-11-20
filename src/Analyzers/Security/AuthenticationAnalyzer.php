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
    private array $sensitiveControllerMethods = [
        'destroy',
        'delete',
        'update',
        'edit',
        'store',
        'create',
    ];

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
            id: 'authentication-protection',
            name: 'Authentication & Authorization Analyzer',
            description: 'Detects missing authentication and authorization protection on routes and controllers',
            category: Category::Security,
            severity: Severity::High,
            tags: ['authentication', 'authorization', 'security', 'middleware'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/authentication-protection'
        );
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

        if (empty($issues)) {
            return $this->passed('No authentication/authorization issues detected');
        }

        return $this->failed(
            sprintf('Found %d potential authentication/authorization issues', count($issues)),
            $issues
        );
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
                        message: "{$method} route without authentication middleware",
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::High,
                        recommendation: 'Add ->middleware("auth") or wrap in Route::middleware(["auth"])->group()',
                        code: trim($line)
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
                        code: trim($line)
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
     * Check for Gate authorization.
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
     * Check for policy checks.
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
            // Check for Auth::user()-> without null checks
            if (preg_match('/Auth::user\(\)->/i', $line)) {
                // Look for null checks in surrounding lines
                $searchRange = max(0, $lineNumber - 3);
                $hasNullCheck = false;

                for ($i = $searchRange; $i <= $lineNumber; $i++) {
                    if (isset($lines[$i]) && preg_match('/if\s*\(\s*.*?Auth::user\(\)|Auth::check\(\)|auth\(\)->check\(\)/i', $lines[$i])) {
                        $hasNullCheck = true;
                        break;
                    }
                }

                if (! $hasNullCheck) {
                    $issues[] = $this->createIssue(
                        message: 'Unsafe Auth::user() usage without null check',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Medium,
                        recommendation: 'Check if user is authenticated before accessing: if (Auth::check()) or use Auth::user()?->property',
                        code: trim($line)
                    );
                }
            }

            // Check for auth()->user()-> without null checks
            if (preg_match('/auth\(\)->user\(\)->/i', $line)) {
                $searchRange = max(0, $lineNumber - 3);
                $hasNullCheck = false;

                for ($i = $searchRange; $i <= $lineNumber; $i++) {
                    if (isset($lines[$i]) && preg_match('/if\s*\(|auth\(\)->check\(\)|Auth::check\(\)/i', $lines[$i])) {
                        $hasNullCheck = true;
                        break;
                    }
                }

                if (! $hasNullCheck) {
                    $issues[] = $this->createIssue(
                        message: 'Unsafe auth()->user() usage without null check',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Medium,
                        recommendation: 'Check if user is authenticated or use null-safe operator: auth()->user()?->property',
                        code: trim($line)
                    );
                }
            }
        }
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
        $routePath = $this->basePath.'/routes';

        if (! is_dir($routePath)) {
            return $files;
        }

        foreach (new \DirectoryIterator($routePath) as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
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
