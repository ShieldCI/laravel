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

        // Check for RateLimiter usage in code (global check)
        $hasGlobalRateLimiter = $this->hasRateLimiterUsage();

        // Check route files for login routes without throttling
        $this->checkRouteFiles($issues, $hasGlobalRateLimiter);

        // Check authentication controllers
        $this->checkAuthControllers($issues);

        $summary = empty($issues)
            ? 'Login throttling/rate limiting is properly configured'
            : sprintf('Found %d login throttling issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check if RateLimiter is used in the codebase.
     */
    private function hasRateLimiterUsage(): bool
    {
        foreach ($this->getPhpFiles() as $file) {
            $content = FileParser::readFile($file);
            if ($content === null || ! is_string($content)) {
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
        $routePath = $this->getBasePath().DIRECTORY_SEPARATOR.'routes';

        if (! is_dir($routePath)) {
            return;
        }

        try {
            foreach (new \DirectoryIterator($routePath) as $file) {
                if (! $file->isFile() || $file->getExtension() !== 'php') {
                    continue;
                }

                // Skip API routes if they use token authentication
                if ($file->getFilename() === 'api.php') {
                    continue;
                }

                $filePath = $file->getPathname();
                $content = FileParser::readFile($filePath);
                if ($content === null || ! is_string($content)) {
                    continue;
                }

                $lines = FileParser::getLines($filePath);

                foreach ($lines as $lineNumber => $line) {
                    if (! is_string($line)) {
                        continue;
                    }

                    // Check for login-related routes (improved regex to catch GET, MATCH, RESOURCE)
                    if (preg_match('/Route::(post|get|any|match|resource|controller)\s*\(["\']([^"\']*(?:login|signin|auth|authenticate)[^"\']*)["\']/', $line, $matches)) {
                        $routeUri = $matches[2];

                        // Check if this route or surrounding lines have throttle middleware
                        $hasThrottle = $this->checkRouteHasThrottling($lines, $lineNumber);

                        if (! $hasThrottle && ! $hasGlobalThrottling) {
                            $issues[] = $this->createIssueWithSnippet(
                                message: sprintf('Login route "%s" lacks rate limiting protection', $routeUri),
                                filePath: $filePath,
                                lineNumber: $lineNumber + 1,
                                severity: Severity::High,
                                recommendation: 'Add ->middleware("throttle:5,1") or similar rate limiting to prevent brute force attacks',
                                metadata: [
                                    'route' => $routeUri,
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
    }

    /**
     * Check if a route has throttling in nearby lines.
     */
    private function checkRouteHasThrottling(array $lines, int $lineNumber): bool
    {
        // Check current line and next 5 lines for throttle middleware
        $searchRange = min($lineNumber + 5, count($lines));

        for ($i = $lineNumber; $i < $searchRange; $i++) {
            if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                continue;
            }

            // Improved patterns to catch more throttle variations
            if (preg_match('/->middleware\(["\']throttle/i', $lines[$i]) ||  // Single string
                preg_match('/->middleware\(\[.*["\']throttle/i', $lines[$i]) ||  // Array with quotes
                preg_match('/->middleware\(["\'][^"\']*["\'],\s*["\']throttle/i', $lines[$i]) ||  // Varargs
                preg_match('/ThrottleRequests::class/i', $lines[$i])) {  // Class reference
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

                $content = FileParser::readFile($controllerPath);
                if ($content === null || ! is_string($content)) {
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
                        if (! isset($class->name)) {
                            continue;
                        }

                        $className = $class->name->toString();

                        // Look for login methods
                        if (! isset($class->stmts) || ! is_array($class->stmts)) {
                            continue;
                        }

                        foreach ($class->stmts as $stmt) {
                            if ($stmt instanceof Node\Stmt\ClassMethod) {
                                $methodName = $stmt->name->toString();

                                if (in_array($methodName, ['login', 'authenticate', 'postLogin', 'attempt'], true)) {
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
}
