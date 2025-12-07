<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects missing CSRF protection vulnerabilities.
 *
 * Checks for:
 * - Forms without @csrf directive
 * - AJAX requests without CSRF token
 * - Routes without VerifyCsrfToken middleware
 * - Overly broad CSRF exceptions
 */
class CsrfAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'csrf-protection',
            name: 'CSRF Protection Analyzer',
            description: 'Detects missing CSRF (Cross-Site Request Forgery) protection',
            category: Category::Security,
            severity: Severity::High,
            tags: ['csrf', 'cross-site-request-forgery', 'security', 'forms'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/csrf-protection',
            timeToFix: 20
        );
    }

    public function shouldRun(): bool
    {
        // Check if there are any files to analyze
        $hasBladeFiles = ! empty($this->getBladeFiles());
        $hasJsFiles = ! empty($this->getJavaScriptFiles());
        $hasRoutes = ! empty($this->getRouteFiles());
        $middlewarePath = $this->buildPath('app', 'Http', 'Middleware', 'VerifyCsrfToken.php');
        $hasMiddleware = file_exists($middlewarePath);
        $kernelFile = $this->buildPath('app', 'Http', 'Kernel.php');
        $bootstrapApp = $this->buildPath('bootstrap', 'app.php');
        $hasKernelOrBootstrap = file_exists($kernelFile) || file_exists($bootstrapApp);

        return $hasBladeFiles || $hasJsFiles || $hasRoutes || $hasMiddleware || $hasKernelOrBootstrap;
    }

    public function getSkipReason(): string
    {
        return 'No Blade templates, JavaScript files, routes, or CSRF middleware found to analyze';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check Blade templates for forms without @csrf
        $bladeFiles = $this->getBladeFiles();
        foreach ($bladeFiles as $file) {
            $this->checkBladeFormsForCsrf($file, $issues);
            $this->checkAjaxRequestsForCsrf($file, $issues);
        }

        // Check JavaScript files for AJAX without CSRF token
        $jsFiles = $this->getJavaScriptFiles();
        foreach ($jsFiles as $file) {
            $this->checkJavaScriptAjaxForCsrf($file, $issues);
        }

        // Check VerifyCsrfToken middleware for overly broad exceptions
        $this->checkCsrfMiddlewareExceptions($issues);

        // Check VerifyCsrfToken middleware registration
        $this->checkCsrfMiddlewareRegistration($issues);

        // Check route files for routes that should have CSRF protection
        $routeFiles = $this->getRouteFiles();
        foreach ($routeFiles as $file) {
            $this->checkRoutesForCsrfMiddleware($file, $issues);
        }

        $summary = empty($issues)
            ? 'No CSRF protection issues detected'
            : sprintf('Found %d potential CSRF protection issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check Blade templates for forms without @csrf directive.
     */
    private function checkBladeFormsForCsrf(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($file);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check for form opening tags (POST, PUT, PATCH, DELETE)
            if (preg_match('/<form[^>]*method\s*=\s*["\'](?:POST|PUT|PATCH|DELETE)["\'][^>]*>/i', $line, $matches)) {
                // Look ahead to check if @csrf is present in the next few lines
                $hasCsrf = false;
                $searchRange = min($lineNumber + 10, count($lines));
                $method = preg_match('/method\s*=\s*["\']([^"\']+)["\']/', $matches[0], $methodMatch) ? strtoupper($methodMatch[1]) : 'POST';

                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    if (preg_match('/@csrf|csrf_field\(\)|<input[^>]*name\s*=\s*["\']_token["\']/', $lines[$i])) {
                        $hasCsrf = true;
                        break;
                    }

                    // Stop if we hit the closing form tag
                    if (str_contains($lines[$i], '</form>')) {
                        break;
                    }
                }

                if (! $hasCsrf && ! $this->isApiRoute($content)) {
                    $issues[] = $this->createIssue(
                        message: 'Form without CSRF protection - missing @csrf directive',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::High,
                        recommendation: 'Add @csrf directive inside the form or use {{ csrf_field() }}',
                        code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                        metadata: [
                            'file' => basename($file),
                            'form_method' => $method,
                            'line' => $lineNumber + 1,
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check for AJAX requests without CSRF token in Blade files.
     */
    private function checkAjaxRequestsForCsrf(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($file);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check for jQuery AJAX with POST/PUT/PATCH/DELETE
            if (preg_match('/\$\.ajax\s*\(|fetch\s*\(/i', $line, $ajaxMatch)) {
                // Look for method: POST/PUT/PATCH/DELETE
                $searchRange = min($lineNumber + 15, count($lines));
                $hasPostMethod = false;
                $hasCsrfToken = false;
                $ajaxType = str_contains($ajaxMatch[0], 'fetch') ? 'fetch' : 'jQuery';

                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    if (preg_match('/method\s*:\s*["\'](?:POST|PUT|PATCH|DELETE)["\']|method:\s*["\']POST["\']/i', $lines[$i])) {
                        $hasPostMethod = true;
                    }

                    if (preg_match('/X-CSRF-TOKEN|_token|csrf|@csrf/i', $lines[$i])) {
                        $hasCsrfToken = true;
                    }
                }

                if ($hasPostMethod && ! $hasCsrfToken) {
                    $issues[] = $this->createIssue(
                        message: 'AJAX request without CSRF token',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::High,
                        recommendation: 'Add X-CSRF-TOKEN header: headers: { "X-CSRF-TOKEN": $("meta[name=csrf-token]").attr("content") }',
                        code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                        metadata: [
                            'file' => basename($file),
                            'ajax_type' => $ajaxType,
                            'line' => $lineNumber + 1,
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check JavaScript files for AJAX without CSRF token.
     */
    private function checkJavaScriptAjaxForCsrf(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($file);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check for fetch API or axios with POST methods
            if (preg_match('/fetch\s*\(|axios\.(post|put|patch|delete)|\.ajax\s*\(/i', $line, $jsMatch)) {
                // Look for CSRF token in the next few lines
                $searchRange = min($lineNumber + 10, count($lines));
                $hasCsrfToken = false;
                $ajaxLibrary = str_contains($jsMatch[0], 'axios') ? 'axios' : (str_contains($jsMatch[0], 'fetch') ? 'fetch' : 'jQuery');

                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    if (preg_match('/X-CSRF-TOKEN|csrf[-_]?token|_token/i', $lines[$i])) {
                        $hasCsrfToken = true;
                        break;
                    }
                }

                if (! $hasCsrfToken) {
                    $issues[] = $this->createIssue(
                        message: 'JavaScript AJAX request may be missing CSRF token',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Medium,
                        recommendation: 'Add CSRF token to headers or ensure Laravel\'s default CSRF setup is configured',
                        code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                        metadata: [
                            'file' => basename($file),
                            'ajax_library' => $ajaxLibrary,
                            'line' => $lineNumber + 1,
                            'severity_reason' => 'Medium severity because JS files may use global CSRF configuration',
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check VerifyCsrfToken middleware for overly broad exceptions.
     */
    private function checkCsrfMiddlewareExceptions(array &$issues): void
    {
        // Look for VerifyCsrfToken middleware file
        $middlewarePath = $this->buildPath('app', 'Http', 'Middleware', 'VerifyCsrfToken.php');

        if (! file_exists($middlewarePath)) {
            return;
        }

        $content = FileParser::readFile($middlewarePath);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($middlewarePath);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check for overly broad exceptions
            if (preg_match('/\$except\s*=\s*\[/', $line)) {
                $searchRange = min($lineNumber + 20, count($lines));
                $exceptions = [];

                for ($i = $lineNumber + 1; $i < $searchRange; $i++) {
                    if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                        continue;
                    }

                    if (preg_match('/["\']([^"\']+)["\']/', $lines[$i], $matches)) {
                        $exceptions[] = $matches[1];
                    }

                    if (str_contains($lines[$i], '];')) {
                        break;
                    }
                }

                // Check for dangerous wildcards
                foreach ($exceptions as $exception) {
                    if (! is_string($exception)) {
                        continue;
                    }

                    if ($exception === '*' || $exception === '/*') {
                        $issues[] = $this->createIssue(
                            message: 'Critical: All routes excluded from CSRF protection with wildcard',
                            location: new Location(
                                $this->getRelativePath($middlewarePath),
                                $lineNumber + 1
                            ),
                            severity: Severity::Critical,
                            recommendation: 'Remove wildcard CSRF exceptions and specify exact routes that need exclusion',
                            code: FileParser::getCodeSnippet($middlewarePath, $lineNumber + 1),
                            metadata: [
                                'exception' => $exception,
                                'file' => 'VerifyCsrfToken.php',
                                'risk_level' => 'critical',
                                'line' => $lineNumber + 1,
                            ]
                        );
                    } elseif (preg_match('/\*/', $exception) && ! str_contains($exception, 'api/')) {
                        $issues[] = $this->createIssue(
                            message: sprintf('Broad CSRF exception pattern: %s', $exception),
                            location: new Location(
                                $this->getRelativePath($middlewarePath),
                                $lineNumber + 1
                            ),
                            severity: Severity::High,
                            recommendation: 'Use more specific route patterns for CSRF exceptions',
                            code: FileParser::getCodeSnippet($middlewarePath, $lineNumber + 1),
                            metadata: [
                                'exception' => $exception,
                                'file' => 'VerifyCsrfToken.php',
                                'risk_level' => 'high',
                                'line' => $lineNumber + 1,
                            ]
                        );
                    }
                }
            }
        }
    }

    /**
     * Check if VerifyCsrfToken middleware is registered in Kernel.php.
     */
    private function checkCsrfMiddlewareRegistration(array &$issues): void
    {
        $kernelFile = $this->buildPath('app', 'Http', 'Kernel.php');

        if (! file_exists($kernelFile)) {
            // Check bootstrap/app.php for Laravel 11+
            $bootstrapApp = $this->buildPath('bootstrap', 'app.php');
            if (file_exists($bootstrapApp)) {
                $this->checkBootstrapApp($bootstrapApp, $issues);
            }

            return;
        }

        $content = FileParser::readFile($kernelFile);
        if ($content === null || ! is_string($content)) {
            return;
        }

        // Check if VerifyCsrfToken middleware is present
        if (! str_contains($content, 'VerifyCsrfToken')) {
            $issues[] = $this->createIssue(
                message: 'VerifyCsrfToken middleware is not registered in HTTP Kernel',
                location: new Location(
                    $this->getRelativePath($kernelFile),
                    1
                ),
                severity: Severity::Critical,
                recommendation: 'Add \\App\\Http\\Middleware\\VerifyCsrfToken::class to $middleware or $middlewareGroups[\'web\'] array in app/Http/Kernel.php',
                code: FileParser::getCodeSnippet($kernelFile, 1),
                metadata: [
                    'file' => 'Kernel.php',
                    'middleware' => 'VerifyCsrfToken',
                    'status' => 'missing',
                ]
            );
        }

        // Check if it's commented out
        $lines = FileParser::getLines($kernelFile);
        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            if (str_contains($line, 'VerifyCsrfToken') &&
                preg_match('/^\s*\/\//', $line)) {
                $issues[] = $this->createIssue(
                    message: 'VerifyCsrfToken middleware is commented out',
                    location: new Location(
                        $this->getRelativePath($kernelFile),
                        $lineNumber + 1
                    ),
                    severity: Severity::Critical,
                    recommendation: 'Uncomment the VerifyCsrfToken middleware to enable CSRF protection',
                    code: FileParser::getCodeSnippet($kernelFile, $lineNumber + 1),
                    metadata: [
                        'file' => 'Kernel.php',
                        'middleware' => 'VerifyCsrfToken',
                        'status' => 'commented',
                        'line' => $lineNumber + 1,
                    ]
                );
            }
        }
    }

    /**
     * Check bootstrap/app.php for Laravel 11+ applications.
     */
    private function checkBootstrapApp(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null || ! is_string($content)) {
            return;
        }

        if (! str_contains($content, 'VerifyCsrfToken') && ! str_contains($content, 'csrf')) {
            $issues[] = $this->createIssue(
                message: 'VerifyCsrfToken middleware may not be properly configured',
                location: new Location(
                    $this->getRelativePath($file),
                    1
                ),
                severity: Severity::High,
                recommendation: 'Ensure CSRF protection is enabled in your middleware configuration',
                code: FileParser::getCodeSnippet($file, 1),
                metadata: [
                    'file' => 'bootstrap/app.php',
                    'laravel_version' => '11+',
                    'middleware' => 'VerifyCsrfToken',
                ]
            );
        }
    }

    /**
     * Check route files for routes that should have CSRF middleware.
     */
    private function checkRoutesForCsrfMiddleware(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }

        // Skip API routes - they typically use token authentication
        if (str_contains($file, 'api.php')) {
            return;
        }

        $lines = FileParser::getLines($file);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check for POST/PUT/PATCH/DELETE routes
            if (preg_match('/Route::(post|put|patch|delete)\s*\(/i', $line, $matches)) {
                $method = strtoupper($matches[1]);

                // Check if the route has middleware
                $searchRange = min($lineNumber + 5, count($lines));
                $hasMiddleware = false;

                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    if (preg_match('/->middleware\s*\(|[\'"](web|auth)[\'"]/', $lines[$i])) {
                        $hasMiddleware = true;
                        break;
                    }

                    if (str_contains($lines[$i], ';')) {
                        break;
                    }
                }

                if (! $hasMiddleware) {
                    $issues[] = $this->createIssue(
                        message: sprintf('%s route may be missing CSRF protection middleware', $method),
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Medium,
                        recommendation: 'Ensure route uses "web" middleware group which includes CSRF protection',
                        code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                        metadata: [
                            'method' => $method,
                            'file' => basename($file),
                            'line' => $lineNumber + 1,
                        ]
                    );
                }
            }
        }
    }

    /**
     * Get all Blade template files.
     */
    private function getBladeFiles(): array
    {
        $files = [];

        foreach ($this->getFilesToAnalyze() as $file) {
            if (str_ends_with($file->getFilename(), '.blade.php')) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * Get all JavaScript files.
     */
    private function getJavaScriptFiles(): array
    {
        $files = [];

        foreach ($this->getFilesToAnalyze() as $file) {
            if ($file->getExtension() === 'js') {
                $files[] = $file->getPathname();
            }
        }

        return $files;
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
     * Check if content indicates an API route.
     */
    private function isApiRoute(string $content): bool
    {
        return str_contains($content, 'api/') ||
               str_contains($content, 'sanctum') ||
               str_contains($content, 'bearer') ||
               str_contains($content, 'Authorization:');
    }

    /**
     * Override to include blade and JS files.
     */
    protected function shouldAnalyzeFile(\SplFileInfo $file): bool
    {
        // Include PHP files
        if ($file->getExtension() === 'php') {
            return parent::shouldAnalyzeFile($file);
        }

        // Include blade files
        if (str_ends_with($file->getFilename(), '.blade.php')) {
            $path = $file->getPathname();

            foreach ($this->excludePatterns as $pattern) {
                if ($this->matchesPattern($path, $pattern)) {
                    return false;
                }
            }

            return true;
        }

        // Include JS files
        if ($file->getExtension() === 'js') {
            $path = $file->getPathname();

            foreach ($this->excludePatterns as $pattern) {
                if ($this->matchesPattern($path, $pattern)) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }
}
