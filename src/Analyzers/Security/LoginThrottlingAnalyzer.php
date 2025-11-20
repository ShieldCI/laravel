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
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'login-throttling',
            name: 'Login Throttling Analyzer',
            description: 'Detects missing rate limiting on authentication endpoints to prevent brute force attacks',
            category: Category::Security,
            severity: Severity::High,
            tags: ['authentication', 'rate-limiting', 'brute-force', 'security', 'throttling'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/login-throttling',
            timeToFix: 20
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $hasThrottling = false;

        // Check for ThrottleRequests middleware in Kernel
        if ($this->hasThrottleMiddleware()) {
            $hasThrottling = true;
        }

        // Check for RateLimiter usage in code
        if ($this->hasRateLimiterUsage()) {
            $hasThrottling = true;
        }

        // Check route files for login routes without throttling
        $this->checkRouteFiles($issues, $hasThrottling);

        // Check authentication controllers
        $this->checkAuthControllers($issues);

        if (empty($issues)) {
            return $this->passed('Login throttling/rate limiting is properly configured');
        }

        return $this->failed(
            sprintf('Found %d login throttling issues', count($issues)),
            $issues
        );
    }

    /**
     * Check if ThrottleRequests middleware exists in Kernel.
     */
    private function hasThrottleMiddleware(): bool
    {
        $kernelFile = $this->basePath.'/app/Http/Kernel.php';

        if (! file_exists($kernelFile)) {
            // Check bootstrap/app.php for Laravel 11+
            $bootstrapApp = $this->basePath.'/bootstrap/app.php';
            if (file_exists($bootstrapApp)) {
                $content = FileParser::readFile($bootstrapApp);

                return $content !== null && (
                    str_contains($content, 'ThrottleRequests') ||
                    str_contains($content, 'throttle')
                );
            }

            return false;
        }

        $content = FileParser::readFile($kernelFile);
        if ($content === null) {
            return false;
        }

        return str_contains($content, 'ThrottleRequests') ||
               str_contains($content, '\\throttle');
    }

    /**
     * Check if RateLimiter is used in the codebase.
     */
    private function hasRateLimiterUsage(): bool
    {
        foreach ($this->getPhpFiles() as $file) {
            $content = FileParser::readFile($file);
            if ($content === null) {
                continue;
            }

            if (str_contains($content, 'RateLimiter') ||
                str_contains($content, 'RateLimiter::')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check route files for login routes without throttling.
     */
    private function checkRouteFiles(array &$issues, bool $hasGlobalThrottling): void
    {
        $routePath = $this->basePath.'/routes';

        if (! is_dir($routePath)) {
            return;
        }

        foreach (new \DirectoryIterator($routePath) as $file) {
            if (! $file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            // Skip API routes if they use token authentication
            if ($file->getFilename() === 'api.php') {
                continue;
            }

            $content = FileParser::readFile($file->getPathname());
            if ($content === null) {
                continue;
            }

            $lines = FileParser::getLines($file->getPathname());

            foreach ($lines as $lineNumber => $line) {
                // Check for login-related routes
                if (preg_match('/Route::(post|any)\s*\(["\']([^"\']*(?:login|signin|auth|authenticate)[^"\']*)["\']/', $line, $matches)) {
                    $routeUri = $matches[2];

                    // Check if this route or surrounding lines have throttle middleware
                    $hasThrottle = $this->checkRouteHasThrottling($lines, $lineNumber);

                    if (! $hasThrottle && ! $hasGlobalThrottling) {
                        $issues[] = $this->createIssue(
                            message: sprintf('Login route "%s" lacks rate limiting protection', $routeUri),
                            location: new Location(
                                $this->getRelativePath($file->getPathname()),
                                $lineNumber + 1
                            ),
                            severity: Severity::High,
                            recommendation: 'Add ->middleware("throttle:5,1") or similar rate limiting to prevent brute force attacks',
                            code: trim($line)
                        );
                    }
                }
            }
        }
    }

    /**
     * Check if a route has throttling in nearby lines.
     */
    private function checkRouteHasThrottling(array $lines, int $lineNumber): bool
    {
        // Check current line and next 5 lines for throttle middleware
        $searchRange = min($lineNumber + 5, count($lines));

        for ($i = $lineNumber; $i < $searchRange; $i++) {
            if (preg_match('/->middleware\(["\']throttle/i', $lines[$i]) ||
                preg_match('/->middleware\(\[.*["\']throttle/i', $lines[$i])) {
                return true;
            }

            // Stop at semicolon (end of route definition)
            if (str_contains($lines[$i], ';')) {
                break;
            }
        }

        return false;
    }

    /**
     * Check authentication controllers for throttling logic.
     */
    private function checkAuthControllers(array &$issues): void
    {
        $authControllers = [
            $this->basePath.'/app/Http/Controllers/Auth/LoginController.php',
            $this->basePath.'/app/Http/Controllers/AuthController.php',
            $this->basePath.'/app/Http/Controllers/LoginController.php',
        ];

        foreach ($authControllers as $controllerPath) {
            if (! file_exists($controllerPath)) {
                continue;
            }

            $ast = $this->parser->parseFile($controllerPath);
            if (empty($ast)) {
                continue;
            }

            $content = FileParser::readFile($controllerPath);
            if ($content === null) {
                continue;
            }

            // Check if controller uses throttling traits or has throttle middleware
            $hasThrottling = str_contains($content, 'ThrottlesLogins') ||
                           str_contains($content, 'RateLimiter') ||
                           str_contains($content, 'throttle') ||
                           str_contains($content, 'AuthenticatesUsers'); // Laravel UI trait includes throttling

            if (! $hasThrottling) {
                $classes = $this->parser->findClasses($ast);

                foreach ($classes as $class) {
                    $className = $class->name ? $class->name->toString() : 'Unknown';

                    // Look for login methods
                    foreach ($class->stmts as $stmt) {
                        if ($stmt instanceof Node\Stmt\ClassMethod) {
                            $methodName = $stmt->name->toString();

                            if (in_array($methodName, ['login', 'authenticate', 'postLogin', 'attempt'])) {
                                $issues[] = $this->createIssue(
                                    message: sprintf('Authentication method %s::%s() lacks rate limiting', $className, $methodName),
                                    location: new Location(
                                        $this->getRelativePath($controllerPath),
                                        $stmt->getLine()
                                    ),
                                    severity: Severity::High,
                                    recommendation: 'Implement rate limiting using RateLimiter facade or throttle middleware to prevent brute force attacks',
                                    code: FileParser::getCodeSnippet($controllerPath, $stmt->getLine())
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
