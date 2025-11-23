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

        // Check route files for routes that should have CSRF protection
        $routeFiles = $this->getRouteFiles();
        foreach ($routeFiles as $file) {
            $this->checkRoutesForCsrfMiddleware($file, $issues);
        }

        if (empty($issues)) {
            return $this->passed('No CSRF protection issues detected');
        }

        return $this->failed(
            sprintf('Found %d potential CSRF protection issues', count($issues)),
            $issues
        );
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
            // Check for form opening tags (POST, PUT, PATCH, DELETE)
            if (preg_match('/<form[^>]*method\s*=\s*["\'](?:POST|PUT|PATCH|DELETE)["\'][^>]*>/i', $line)) {
                // Look ahead to check if @csrf is present in the next few lines
                $hasCsrf = false;
                $searchRange = min($lineNumber + 10, count($lines));

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
                        code: trim($line)
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
            // Check for jQuery AJAX with POST/PUT/PATCH/DELETE
            if (preg_match('/\$\.ajax\s*\(|fetch\s*\(/i', $line)) {
                // Look for method: POST/PUT/PATCH/DELETE
                $searchRange = min($lineNumber + 15, count($lines));
                $hasPostMethod = false;
                $hasCsrfToken = false;

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
                        code: trim($line)
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
            // Check for fetch API or axios with POST methods
            if (preg_match('/fetch\s*\(|axios\.(post|put|patch|delete)|\.ajax\s*\(/i', $line)) {
                // Look for CSRF token in the next few lines
                $searchRange = min($lineNumber + 10, count($lines));
                $hasCsrfToken = false;

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
                        code: trim($line)
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
        $middlewarePath = $this->basePath.'/app/Http/Middleware/VerifyCsrfToken.php';

        if (! file_exists($middlewarePath)) {
            return;
        }

        $content = FileParser::readFile($middlewarePath);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($middlewarePath);

        foreach ($lines as $lineNumber => $line) {
            // Check for overly broad exceptions
            if (preg_match('/\$except\s*=\s*\[/', $line)) {
                $searchRange = min($lineNumber + 20, count($lines));
                $exceptions = [];

                for ($i = $lineNumber + 1; $i < $searchRange; $i++) {
                    if (preg_match('/["\']([^"\']+)["\']/', $lines[$i], $matches)) {
                        $exceptions[] = $matches[1];
                    }

                    if (str_contains($lines[$i], '];')) {
                        break;
                    }
                }

                // Check for dangerous wildcards
                foreach ($exceptions as $exception) {
                    if ($exception === '*' || $exception === '/*') {
                        $issues[] = $this->createIssue(
                            message: 'Critical: All routes excluded from CSRF protection with wildcard',
                            location: new Location(
                                $this->getRelativePath($middlewarePath),
                                $lineNumber + 1
                            ),
                            severity: Severity::Critical,
                            recommendation: 'Remove wildcard CSRF exceptions and specify exact routes that need exclusion',
                            code: trim($line)
                        );
                    } elseif (preg_match('/\*/', $exception) && ! str_contains($exception, 'api/')) {
                        $issues[] = $this->createIssue(
                            message: "Broad CSRF exception pattern: {$exception}",
                            location: new Location(
                                $this->getRelativePath($middlewarePath),
                                $lineNumber + 1
                            ),
                            severity: Severity::High,
                            recommendation: 'Use more specific route patterns for CSRF exceptions',
                            code: "'{$exception}'"
                        );
                    }
                }
            }
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
                        message: "{$method} route may be missing CSRF protection middleware",
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Medium,
                        recommendation: 'Ensure route uses "web" middleware group which includes CSRF protection',
                        code: trim($line)
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
