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

        // Check Fortify/Breeze/Jetstream configuration
        if (! $hasGlobalRateLimiter) {
            $this->checkAuthenticationPackages($issues);
        }

        $summary = empty($issues)
            ? 'Login throttling/rate limiting is properly configured'
            : sprintf('Found %d login throttling issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check if login-specific RateLimiter is used in authentication contexts.
     *
     * Only searches auth-related files and looks for login-specific rate limiting patterns:
     * - RateLimiter::attempt('login:...')
     * - RateLimiter::for('login', ...)
     * - tooManyAttempts() / hasTooManyLoginAttempts()
     * - RateLimiter::hit() / clear() near auth methods
     */
    private function hasRateLimiterUsage(): bool
    {
        $authFiles = $this->getAuthenticationFiles();

        foreach ($authFiles as $file) {
            if ($this->hasLoginThrottlingInFile($file)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get authentication-related files (controllers, middleware, traits).
     *
     * @return array<int, string>
     */
    private function getAuthenticationFiles(): array
    {
        $basePath = $this->getBasePath();
        $authFiles = [];

        // Check auth controllers
        $authPaths = [
            $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Controllers'.DIRECTORY_SEPARATOR.'Auth',
            $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Controllers',
        ];

        foreach ($authPaths as $path) {
            if (! is_dir($path)) {
                continue;
            }

            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS)
                );

                foreach ($iterator as $file) {
                    if (! $file instanceof \SplFileInfo) {
                        continue;
                    }

                    if ($file->isFile() && $file->getExtension() === 'php') {
                        $filename = strtolower($file->getFilename());
                        // Only check auth-related controllers
                        if (str_contains($filename, 'auth') ||
                            str_contains($filename, 'login') ||
                            str_contains($filename, 'session')) {
                            $authFiles[] = $file->getPathname();
                        }
                    }
                }
            } catch (\Throwable $e) {
                continue;
            }
        }

        // Check middleware
        $middlewarePath = $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Middleware';
        if (is_dir($middlewarePath)) {
            try {
                foreach (new \DirectoryIterator($middlewarePath) as $file) {
                    if ($file->isFile() && $file->getExtension() === 'php') {
                        $authFiles[] = $file->getPathname();
                    }
                }
            } catch (\Throwable $e) {
                // Ignore
            }
        }

        return $authFiles;
    }

    /**
     * Check if a file contains login-specific throttling patterns.
     */
    private function hasLoginThrottlingInFile(string $file): bool
    {
        $content = FileParser::readFile($file);
        if ($content === null || ! is_string($content)) {
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
                    $authMethods = ['login', 'authenticate', 'attempt', 'postLogin', 'handleLogin', 'store'];
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

                // Track route groups for context
                // NOTE: This uses brace-depth tracking which can drift with string literals containing braces,
                // heredocs, or complex nested structures. AST-based route group detection would be more robust
                // but requires parsing route files as PHP AST, which can be complex due to facade calls.
                // TODO: Consider migrating to AST-based route group detection for better accuracy.
                $inWebGroup = false;
                $groupDepth = 0;
                $braceDepth = 0;

                foreach ($lines as $lineNumber => $line) {
                    if (! is_string($line)) {
                        continue;
                    }

                    // Track brace depth for group nesting (heuristic - can drift)
                    $braceDepth += substr_count($line, '{') - substr_count($line, '}');

                    // Detect Route::group with middleware
                    if (preg_match('/Route::group\s*\(\s*\[/i', $line)) {
                        $groupDepth = $braceDepth;
                        // Check if group has throttle middleware
                        if (preg_match('/["\']middleware["\']\s*=>\s*.*["\']throttle/i', $line)) {
                            $inWebGroup = true;
                        }
                    }

                    // Exit group when braces close
                    if ($inWebGroup && $braceDepth <= $groupDepth - 1) {
                        $inWebGroup = false;
                    }

                    // Check for Auth::routes() helper
                    if (preg_match('/Auth::routes\s*\(/i', $line)) {
                        // Auth::routes() includes login routes - check if throttled
                        $hasThrottle = $this->checkRouteHasThrottling($lines, $lineNumber);

                        if (! $hasThrottle && ! $hasGlobalThrottling && ! $inWebGroup) {
                            $issues[] = $this->createIssueWithSnippet(
                                message: 'Auth::routes() includes login endpoint without explicit rate limiting',
                                filePath: $filePath,
                                lineNumber: $lineNumber + 1,
                                severity: Severity::High,
                                recommendation: 'Add ->middleware("throttle:5,1") to Auth::routes() or configure rate limiting in AuthServiceProvider',
                                metadata: [
                                    'route' => 'Auth::routes()',
                                    'issue_type' => 'missing_route_throttle',
                                ]
                            );
                        }
                    }

                    // Check for login-related routes (expanded to catch more patterns)
                    if (preg_match('/Route::(post|get|any|match|resource|controller)\s*\(["\']([^"\']*(?:login|signin|auth|authenticate)[^"\']*)["\']/', $line, $matches)) {
                        $routeUri = $matches[2];

                        // Check if this route or surrounding lines have throttle middleware
                        $hasThrottle = $this->checkRouteHasThrottling($lines, $lineNumber) || $inWebGroup;

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
     * Check if a route has throttling in nearby lines or on the same line (before/after).
     */
    private function checkRouteHasThrottling(array $lines, int $lineNumber): bool
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

        // Check next 5 lines (for routes defined across multiple lines)
        $searchRange = min($lineNumber + 5, count($lines));
        for ($i = $lineNumber + 1; $i < $searchRange; $i++) {
            if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                continue;
            }

            if ($this->lineHasThrottle($lines[$i])) {
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

                // Check if controller uses login-specific throttling
                $hasThrottling = str_contains($content, 'ThrottlesLogins') ||
                               str_contains($content, 'AuthenticatesUsers') || // Laravel UI trait includes throttling
                               $this->hasLoginThrottlingInFile($controllerPath);

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

    /**
     * Check Fortify/Breeze/Jetstream configuration for throttling.
     */
    private function checkAuthenticationPackages(array &$issues): void
    {
        $basePath = $this->getBasePath();

        // Check if Fortify is installed
        $composerLock = $basePath.DIRECTORY_SEPARATOR.'composer.lock';
        $hasFortify = false;
        $hasBreeze = false;
        $hasJetstream = false;

        if (file_exists($composerLock)) {
            $lockContent = FileParser::readFile($composerLock);
            if ($lockContent !== null && is_string($lockContent)) {
                $hasFortify = str_contains($lockContent, '"name": "laravel/fortify"');
                $hasBreeze = str_contains($lockContent, '"name": "laravel/breeze"');
                $hasJetstream = str_contains($lockContent, '"name": "laravel/jetstream"');
            }
        }

        // If none are installed, skip
        if (! $hasFortify && ! $hasBreeze && ! $hasJetstream) {
            return;
        }

        // Check Fortify configuration
        if ($hasFortify) {
            $this->checkFortifyThrottling($issues);
        }

        // Check Breeze/Jetstream service providers
        if ($hasBreeze || $hasJetstream) {
            $this->checkBreezeJetstreamThrottling($issues, $hasBreeze, $hasJetstream);
        }
    }

    /**
     * Check Fortify-specific throttling configuration.
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
                        $content = FileParser::readFile($file->getPathname());
                        if ($content === null || ! is_string($content)) {
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
                recommendation: 'Enable Fortify login throttling by configuring RateLimiter::for(\'login\', ...) with appropriate limits',
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
            $fortifyConfig = FileParser::readFile($fortifyConfigPath);
            if ($fortifyConfig !== null && is_string($fortifyConfig)) {
                // Check if limiters configuration exists
                if (! preg_match('/["\']limiters["\']\s*=>/i', $fortifyConfig)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Fortify authentication lacks custom rate limiter configuration',
                        filePath: $fortifyConfigPath,
                        lineNumber: 1,
                        severity: Severity::High,
                        recommendation: 'Configure rate limiters in config/fortify.php or define RateLimiter::for(\'login\', ...) in a service provider',
                        metadata: [
                            'framework' => 'fortify',
                            'issue_type' => 'fortify_no_custom_limiter',
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check Breeze/Jetstream throttling in their routes/configuration.
     *
     * NOTE: Both Breeze and Jetstream rely on Fortify for authentication by default,
     * and Fortify includes throttling out of the box. This method only flags issues
     * if the default throttling has been explicitly disabled or misconfigured.
     */
    private function checkBreezeJetstreamThrottling(array &$issues, bool $hasBreeze, bool $hasJetstream): void
    {
        $basePath = $this->getBasePath();

        // Breeze (Blade/Inertia/React) uses Fortify for authentication
        // Jetstream also uses Fortify under the hood
        // Both include default throttling via Fortify's RateLimiter::for('login', ...)
        // We only need to check if they've explicitly disabled it or used custom routes

        // Check if they're using custom authentication routes instead of Fortify
        $authRoutesPath = $basePath.DIRECTORY_SEPARATOR.'routes'.DIRECTORY_SEPARATOR.'auth.php';

        if (file_exists($authRoutesPath)) {
            $authRoutes = FileParser::readFile($authRoutesPath);
            if ($authRoutes !== null && is_string($authRoutes)) {
                // Check if these are custom routes (not using Fortify/Breeze defaults)
                $hasCustomLoginRoute = preg_match('/Route::(post|get|any)\s*\(["\'][^"\']*login[^"\']*["\'],\s*\[.*Controller/i', $authRoutes);

                if ($hasCustomLoginRoute) {
                    // Custom routes detected - check for throttling
                    $hasThrottling = str_contains($authRoutes, 'throttle') ||
                                   str_contains($authRoutes, 'ThrottleRequests');

                    if (! $hasThrottling) {
                        $framework = $hasBreeze ? 'Breeze' : ($hasJetstream ? 'Jetstream' : 'Laravel');

                        $issues[] = $this->createIssueWithSnippet(
                            message: sprintf('%s uses custom authentication routes without rate limiting', $framework),
                            filePath: $authRoutesPath,
                            lineNumber: 1,
                            severity: Severity::High,
                            recommendation: sprintf(
                                'Add throttle middleware to custom login routes in routes/auth.php. '.
                                'Alternatively, use %s default Fortify-based authentication which includes throttling.',
                                $framework
                            ),
                            metadata: [
                                'framework' => strtolower($framework),
                                'issue_type' => 'custom_routes_no_throttle',
                            ]
                        );
                    }
                }
            }
        }

        // For Breeze/Jetstream using default Fortify routes, the Fortify check above
        // already validates throttling configuration, so we don't need additional checks here.
        // This avoids false positives since Fortify's default behavior includes throttling.
    }
}
