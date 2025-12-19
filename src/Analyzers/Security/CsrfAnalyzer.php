<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Detects missing CSRF protection vulnerabilities.
 *
 * Checks for:
 * - Forms without @csrf directive
 * - AJAX requests without CSRF token
 * - Routes without CSRF middleware (VerifyCsrfToken in Laravel 9/10, ValidateCsrfToken in Laravel 11+)
 * - Overly broad CSRF exceptions in middleware $except array (Laravel 9/10)
 * - Overly broad CSRF exceptions in validateCsrfTokens() method (Laravel 11+)
 * - Explicitly disabled CSRF protection in bootstrap/app.php (Laravel 11+):
 *   - $middleware->remove(ValidateCsrfToken::class)
 *   - $middleware->web(remove: [ValidateCsrfToken::class])
 *   - $middleware->use([...]) without ValidateCsrfToken in the array
 *   - validateCsrfTokens(except: ['*'])
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
            severity: Severity::Critical,
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

        // Check for CSRF middleware (Laravel 9/10: VerifyCsrfToken, Laravel 11+: ValidateCsrfToken)
        $verifyCsrfPath = $this->buildPath('app', 'Http', 'Middleware', 'VerifyCsrfToken.php');
        $validateCsrfPath = $this->buildPath('app', 'Http', 'Middleware', 'ValidateCsrfToken.php');
        $hasMiddleware = file_exists($verifyCsrfPath) || file_exists($validateCsrfPath);

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
     *
     * ALL forms in Blade templates require CSRF protection - no exceptions.
     * Blade templates are web views; if building an API, use JSON responses instead of forms.
     *
     * Accepts multiple CSRF protection patterns:
     * - @csrf or @csrf() - Blade directive
     * - <x-csrf /> or <x-csrf/> - Blade component
     * - csrf_field() - Helper function
     * - <input name="_token" ... /> - Manual token input
     *
     * Scans until </form> is found (no hardcoded line limit).
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
                $hasCsrf = false;
                $method = preg_match('/method\s*=\s*["\']([^"\']+)["\']/', $matches[0], $methodMatch) ? strtoupper($methodMatch[1]) : 'POST';

                // Scan from form opening until </form> is found
                for ($i = $lineNumber; $i < count($lines); $i++) {
                    if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                        continue;
                    }

                    // Check for CSRF token patterns:
                    // - @csrf or @csrf() - Blade directive (with or without parentheses)
                    // - <x-csrf /> or <x-csrf/> - Blade component
                    // - csrf_field() - Helper function
                    // - <input name="_token" ... /> - Manual token input
                    if (preg_match('/@csrf(\(\))?|<x-csrf\s*\/?>|csrf_field\(\)|<input[^>]*name\s*=\s*["\']_token["\']/', $lines[$i])) {
                        $hasCsrf = true;
                        break;
                    }

                    // Stop if we hit the closing form tag
                    if (str_contains($lines[$i], '</form>')) {
                        break;
                    }
                }

                if (! $hasCsrf) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Form without CSRF protection - missing @csrf directive',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Add @csrf or <x-csrf /> inside the form, or use {{ csrf_field() }}',
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
     *
     * Scans until natural boundary (closing parenthesis + semicolon) instead of hardcoded line limit.
     * Uses parenthesis depth tracking to find the end of AJAX call.
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
                $hasPostMethod = false;
                $hasCsrfToken = false;
                $ajaxType = str_contains($ajaxMatch[0], 'fetch') ? 'fetch' : 'jQuery';
                $parenDepth = 0;
                $foundOpeningParen = false;

                // Scan until we find the closing statement (closing paren + semicolon, or just semicolon)
                for ($i = $lineNumber; $i < count($lines); $i++) {
                    if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                        continue;
                    }

                    $currentLine = $lines[$i];

                    // Track parenthesis depth to find end of AJAX call
                    $parenDepth += substr_count($currentLine, '(') - substr_count($currentLine, ')');
                    if (substr_count($currentLine, '(') > 0) {
                        $foundOpeningParen = true;
                    }

                    // Check for method: POST/PUT/PATCH/DELETE
                    if (preg_match('/method\s*:\s*["\']?\s*(?:POST|PUT|PATCH|DELETE)\s*["\']?/i', $currentLine)) {
                        $hasPostMethod = true;
                    }

                    // Check for CSRF token
                    if (preg_match('/X-CSRF-TOKEN|_token|csrf|@csrf/i', $currentLine)) {
                        $hasCsrfToken = true;
                    }

                    // Stop if we've closed all parentheses and hit a semicolon, or exceeded reasonable search range
                    if ($foundOpeningParen && $parenDepth <= 0 && str_contains($currentLine, ';')) {
                        break;
                    }

                    // Safety limit: don't scan more than 30 lines for a single AJAX call
                    if ($i - $lineNumber > 30) {
                        break;
                    }
                }

                if ($hasPostMethod && ! $hasCsrfToken) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'AJAX request without CSRF token',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Add X-CSRF-TOKEN header: headers: { "X-CSRF-TOKEN": $("meta[name=csrf-token]").attr("content") }',
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
     *
     * Only flags POST/PUT/PATCH/DELETE requests:
     * - axios.post/put/patch/delete - method explicit in function name
     * - fetch(url, {method: 'POST'}) - checks for method property
     * - $.ajax({method: 'POST'}) - checks for method property
     *
     * GET requests (fetch(url) without method, or method: 'GET') are not flagged.
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
                $searchRange = min($lineNumber + 10, count($lines));
                $hasCsrfToken = false;
                $hasPostMethod = false;
                $ajaxLibrary = str_contains($jsMatch[0], 'axios') ? 'axios' : (str_contains($jsMatch[0], 'fetch') ? 'fetch' : 'jQuery');

                // For axios.post/put/patch/delete, the method is explicit in the function name
                if (preg_match('/axios\.(post|put|patch|delete)/i', $jsMatch[0])) {
                    $hasPostMethod = true;
                }

                // For fetch() and $.ajax(), check if method is POST/PUT/PATCH/DELETE
                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    // Check for method: 'POST' or method:'POST' (with or without quotes)
                    if (preg_match('/method\s*:\s*["\']?\s*(POST|PUT|PATCH|DELETE)\s*["\']?/i', $lines[$i])) {
                        $hasPostMethod = true;
                    }

                    if (preg_match('/X-CSRF-TOKEN|csrf[-_]?token|_token/i', $lines[$i])) {
                        $hasCsrfToken = true;
                    }

                    // Stop searching if we hit a semicolon or closing brace at statement level
                    if (preg_match('/^\s*[;}]\s*$/', $lines[$i])) {
                        break;
                    }
                }

                // Only flag if it's a POST/PUT/PATCH/DELETE request without CSRF token
                if ($hasPostMethod && ! $hasCsrfToken) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'JavaScript AJAX request may be missing CSRF token',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::Medium,
                        recommendation: 'Add CSRF token to headers or ensure Laravel\'s default CSRF setup is configured',
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
     * Check CSRF middleware for overly broad exceptions.
     * Supports both VerifyCsrfToken (Laravel 10) and ValidateCsrfToken (Laravel 11+).
     */
    private function checkCsrfMiddlewareExceptions(array &$issues): void
    {
        // Look for CSRF middleware file (Laravel 10 uses VerifyCsrfToken, Laravel 11+ uses ValidateCsrfToken)
        $middlewarePath = $this->buildPath('app', 'Http', 'Middleware', 'VerifyCsrfToken.php');

        if (! file_exists($middlewarePath)) {
            // Try Laravel 11+ middleware name
            $middlewarePath = $this->buildPath('app', 'Http', 'Middleware', 'ValidateCsrfToken.php');

            if (! file_exists($middlewarePath)) {
                return;
            }
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
                        $issues[] = $this->createIssueWithSnippet(
                            message: 'Critical: All routes excluded from CSRF protection with wildcard',
                            filePath: $middlewarePath,
                            lineNumber: $lineNumber + 1,
                            severity: Severity::Critical,
                            recommendation: 'Remove wildcard CSRF exceptions and specify exact routes that need exclusion',
                            metadata: [
                                'exception' => $exception,
                                'file' => 'VerifyCsrfToken.php',
                                'line' => $lineNumber + 1,
                            ]
                        );
                    } elseif (preg_match('/\*/', $exception) && $this->isBroadCsrfException($exception)) {
                        $issues[] = $this->createIssueWithSnippet(
                            message: sprintf('Broad CSRF exception pattern: %s', $exception),
                            filePath: $middlewarePath,
                            lineNumber: $lineNumber + 1,
                            severity: Severity::High,
                            recommendation: 'Use more specific route patterns for CSRF exceptions (e.g., "service/webhooks/*" instead of "webhooks/*")',
                            metadata: [
                                'exception' => $exception,
                                'file' => 'VerifyCsrfToken.php',
                                'line' => $lineNumber + 1,
                            ]
                        );
                    }
                }
            }
        }
    }

    /**
     * Determine if a CSRF exception pattern is overly broad.
     *
     * Patterns are considered broad if they:
     * - Have only one path segment before wildcard (e.g., 'admin/*', 'webhook/*')
     * - Exception: 'api/*' patterns are allowed as APIs typically use token auth
     *
     * Patterns are considered specific if they:
     * - Have 2+ path segments (e.g., 'service/webhooks/*', '/clock/switch/*')
     * - Are for known webhook/integration services (e.g., 'stripe/*', 'mailgun/*')
     */
    private function isBroadCsrfException(string $exception): bool
    {
        // Allow API routes - they typically use token authentication
        if (str_starts_with(trim($exception, '/'), 'api/')) {
            return false;
        }

        // Allow known webhook/integration services (single segment is OK for these)
        $allowedServices = [
            'stripe', 'mailgun', 'mailslurp', 'twilio', 'slack',
            'github', 'gitlab', 'bitbucket', 'webhooks',
            'paddle', 'paypal', 'braintree', 'plaid',
        ];

        $cleanException = trim($exception, '/');
        foreach ($allowedServices as $service) {
            if (str_starts_with($cleanException, $service.'/')) {
                return false;
            }
        }

        // Count path segments (excluding wildcard)
        $pathWithoutWildcard = str_replace('*', '', $exception);
        $segments = array_filter(explode('/', $pathWithoutWildcard), fn ($seg) => $seg !== '');

        // If 2+ segments before wildcard, it's specific enough (e.g., '/clock/switch/*')
        if (count($segments) >= 2) {
            return false;
        }

        // Single segment patterns are broad (e.g., 'admin/*', 'dashboard/*')
        return true;
    }

    /**
     * Check if CSRF middleware is registered in Kernel.php.
     * Supports both VerifyCsrfToken (Laravel 10) and ValidateCsrfToken (Laravel 11+).
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

        // Check if CSRF middleware is present (Laravel 10: VerifyCsrfToken, Laravel 11+: ValidateCsrfToken)
        $hasVerifyCsrfToken = str_contains($content, 'VerifyCsrfToken');
        $hasValidateCsrfToken = str_contains($content, 'ValidateCsrfToken');

        if (! $hasVerifyCsrfToken && ! $hasValidateCsrfToken) {
            $issues[] = $this->createIssueWithSnippet(
                message: 'CSRF middleware is not registered in HTTP Kernel',
                filePath: $kernelFile,
                lineNumber: 1,
                severity: Severity::Critical,
                recommendation: 'Add \\App\\Http\\Middleware\\VerifyCsrfToken::class (Laravel 10) or \\App\\Http\\Middleware\\ValidateCsrfToken::class (Laravel 11+) to $middleware or $middlewareGroups[\'web\'] array',
                metadata: [
                    'file' => 'Kernel.php',
                    'middleware' => 'CSRF',
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

            if ((str_contains($line, 'VerifyCsrfToken') || str_contains($line, 'ValidateCsrfToken')) &&
                preg_match('/^\s*\/\//', $line)) {
                $middlewareName = str_contains($line, 'ValidateCsrfToken') ? 'ValidateCsrfToken' : 'VerifyCsrfToken';

                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf('%s middleware is commented out', $middlewareName),
                    filePath: $kernelFile,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Critical,
                    recommendation: sprintf('Uncomment the %s middleware to enable CSRF protection', $middlewareName),
                    metadata: [
                        'file' => 'Kernel.php',
                        'middleware' => $middlewareName,
                        'status' => 'commented',
                        'line' => $lineNumber + 1,
                    ]
                );
            }
        }
    }

    /**
     * Check bootstrap/app.php for Laravel 11+ applications.
     *
     * Laravel 11+ includes ValidateCsrfToken globally by default.
     * Users can:
     * 1. Manually manage middleware with withMiddleware() - check if CSRF is disabled
     * 2. Exclude URIs using validateCsrfTokens() method - check for overly broad patterns
     */
    private function checkBootstrapApp(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null || ! is_string($content)) {
            return;
        }

        $lines = FileParser::getLines($file);

        // Check if middleware is manually managed
        $hasWithMiddleware = str_contains($content, 'withMiddleware');

        if ($hasWithMiddleware) {
            // Check if CSRF protection is explicitly disabled or not mentioned
            $hasCsrfReference = str_contains($content, 'ValidateCsrfToken') ||
                               str_contains($content, 'VerifyCsrfToken') ||
                               str_contains($content, 'validateCsrfTokens') ||
                               str_contains($content, 'csrf');

            if (! $hasCsrfReference) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'CSRF middleware may not be properly configured',
                    filePath: $file,
                    lineNumber: 1,
                    severity: Severity::High,
                    recommendation: 'Ensure CSRF protection is enabled. Laravel 11+ includes ValidateCsrfToken in the web middleware group by default, but verify it hasn\'t been removed.',
                    metadata: [
                        'file' => 'bootstrap/app.php',
                        'laravel_version' => '11+',
                        'middleware' => 'ValidateCsrfToken',
                    ]
                );
            }

            /**
             * ALWAYS inspect $middleware->use([...])
             * If CSRF is missing, this must emit the Critical issue
             */
            $this->checkCsrfDisabledInBootstrap($lines, $file, $issues);
        }

        // Check for CSRF exception patterns in validateCsrfTokens() method
        $this->checkBootstrapCsrfExceptions($lines, $file, $issues);
    }

    /**
     * Check if CSRF protection is explicitly disabled in bootstrap/app.php.
     */
    private function checkCsrfDisabledInBootstrap(array $lines, string $file, array &$issues): void
    {
        $inUseMethod = false;
        $useMethodStartLine = 0;
        $hasValidateCsrfTokenInUse = false;

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check for $middleware->use([...]) - manual global middleware stack
            if (preg_match('/\$middleware\s*->\s*use\s*\(\s*\[/', $line)) {
                $inUseMethod = true;
                $useMethodStartLine = $lineNumber;
                $hasValidateCsrfTokenInUse = false;
            }

            // Check if ValidateCsrfToken is in the use() array
            if ($inUseMethod && preg_match('/ValidateCsrfToken/', $line)) {
                $hasValidateCsrfTokenInUse = true;
            }

            // Check for end of use() method (both ']); ' and '])' patterns)
            if ($inUseMethod && (str_contains($line, ']);') || preg_match('/\]\s*\)\s*;?/', $line))) {
                $inUseMethod = false;

                // If use() method was found but ValidateCsrfToken wasn't in it
                if (! $hasValidateCsrfTokenInUse) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Critical: ValidateCsrfToken missing from global middleware stack',
                        filePath: $file,
                        lineNumber: $useMethodStartLine + 1,
                        severity: Severity::Critical,
                        recommendation: 'Add \\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class to the $middleware->use() array to enable CSRF protection globally.',
                        metadata: [
                            'file' => 'bootstrap/app.php',
                            'laravel_version' => '11+',
                            'middleware' => 'ValidateCsrfToken',
                            'status' => 'missing_from_use',
                            'line' => $useMethodStartLine + 1,
                        ]
                    );
                }
            }

            // Check for $middleware->web(remove: [...]) with ValidateCsrfToken
            if (preg_match('/\$middleware\s*->\s*web\s*\(\s*remove\s*:\s*\[/', $line)) {
                // Look ahead to check if ValidateCsrfToken is in the remove array
                $searchRange = min($lineNumber + 10, count($lines));
                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                        continue;
                    }

                    if (preg_match('/ValidateCsrfToken/', $lines[$i])) {
                        $issues[] = $this->createIssueWithSnippet(
                            message: 'Critical: ValidateCsrfToken removed from web middleware group',
                            filePath: $file,
                            lineNumber: $lineNumber + 1,
                            severity: Severity::Critical,
                            recommendation: 'Do not remove ValidateCsrfToken from the web middleware group. This disables CSRF protection for all web routes.',
                            metadata: [
                                'file' => 'bootstrap/app.php',
                                'laravel_version' => '11+',
                                'middleware' => 'ValidateCsrfToken',
                                'status' => 'removed_from_web',
                                'line' => $lineNumber + 1,
                            ]
                        );
                        break;
                    }

                    if (str_contains($lines[$i], '])')) {
                        break;
                    }
                }
            }

            // Check for patterns that disable CSRF:
            // - validateCsrfTokens(except: ['*'])
            if (preg_match('/validateCsrfTokens\s*\(\s*except\s*:\s*\[\s*[\'\"]\*[\'\"]\s*\]/', $line)) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'Critical: All routes excluded from CSRF protection in bootstrap/app.php',
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Critical,
                    recommendation: 'Remove wildcard CSRF exception. In Laravel 11+, ValidateCsrfToken is global by default - only exclude specific URIs that need it.',
                    metadata: [
                        'file' => 'bootstrap/app.php',
                        'laravel_version' => '11+',
                        'exception' => '*',
                        'line' => $lineNumber + 1,
                    ]
                );
            }

            // Check for $middleware->remove(ValidateCsrfToken::class) - older approach
            if (preg_match('/\$middleware\s*->\s*remove\s*\(\s*.*ValidateCsrfToken/', $line)) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'Critical: ValidateCsrfToken middleware has been removed',
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Critical,
                    recommendation: 'Do not remove ValidateCsrfToken middleware. This disables CSRF protection for all routes.',
                    metadata: [
                        'file' => 'bootstrap/app.php',
                        'laravel_version' => '11+',
                        'middleware' => 'ValidateCsrfToken',
                        'status' => 'removed',
                        'line' => $lineNumber + 1,
                    ]
                );
            }
        }
    }

    /**
     * Check for overly broad CSRF exception patterns in validateCsrfTokens() calls.
     */
    private function checkBootstrapCsrfExceptions(array $lines, string $file, array &$issues): void
    {
        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check for validateCsrfTokens(except: [...])
            if (preg_match('/validateCsrfTokens\s*\(\s*except\s*:\s*\[/', $line)) {
                // Extract exceptions from the array
                $searchRange = min($lineNumber + 20, count($lines));
                $exceptions = [];

                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                        continue;
                    }

                    if (preg_match_all('/[\'"]([^\'"]+)[\'"]/', $lines[$i], $matches)) {
                        foreach ($matches[1] as $match) {
                            if ($match !== 'except') { // Skip the 'except' keyword
                                $exceptions[] = $match;
                            }
                        }
                    }

                    // Stop at the end of the array
                    if (str_contains($lines[$i], '])')) {
                        break;
                    }
                }

                // Check each exception pattern using the same logic as middleware $except
                foreach ($exceptions as $exception) {
                    if (! is_string($exception)) {
                        continue;
                    }

                    if ($exception === '*' || $exception === '/*') {
                        // Already caught above, skip duplicate
                        continue;
                    }

                    if (preg_match('/\*/', $exception) && $this->isBroadCsrfException($exception)) {
                        $issues[] = $this->createIssueWithSnippet(
                            message: sprintf('Broad CSRF exception pattern in bootstrap/app.php: %s', $exception),
                            filePath: $file,
                            lineNumber: $lineNumber + 1,
                            severity: Severity::High,
                            recommendation: 'Use more specific route patterns for CSRF exceptions (e.g., "service/webhooks/*" instead of "webhooks/*")',
                            metadata: [
                                'exception' => $exception,
                                'file' => 'bootstrap/app.php',
                                'laravel_version' => '11+',
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
     * Check route files for routes that should have CSRF middleware.
     *
     * IMPORTANT: routes/web.php automatically has 'web' middleware applied globally
     * via RouteServiceProvider (Laravel 10) or bootstrap/app.php (Laravel 11+).
     *
     * This check only flags routes in:
     * - Custom route files (not web.php or api.php)
     * - That are missing explicit 'web' middleware
     *
     * Only accepts explicit 'web' middleware:
     * - middleware('web')
     * - middleware(['web', ...])
     * - Route::group(['middleware' => 'web'], ...)
     * - Route::group(['middleware' => ['web', ...]], ...)
     *
     * Does NOT accept:
     * - 'auth' middleware (doesn't include CSRF)
     * - Just ->middleware( without 'web'
     * - Assumed middleware from elsewhere
     */
    private function checkRoutesForCsrfMiddleware(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }

        $normalizedPath = str_replace('\\', '/', $file);

        // Skip api.php - API routes typically use token authentication
        if (str_ends_with($normalizedPath, '/routes/api.php')) {
            return;
        }

        // Skip web.php - routes in web.php automatically get 'web' middleware applied globally
        // via RouteServiceProvider (Laravel 10) or bootstrap/app.php (Laravel 11+)
        if (str_ends_with($normalizedPath, '/routes/web.php')) {
            return;
        }

        $lines = FileParser::getLines($file);
        $insideWebGroup = false;
        $groupDepth = 0;

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check for Route::group with 'web' middleware
            if (preg_match('/Route::group\s*\(\s*\[/', $line)) {
                // Look ahead to check if this group has 'web' middleware
                $searchRange = min($lineNumber + 10, count($lines));
                $hasWebInGroup = false;

                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                        continue;
                    }

                    // Check for 'middleware' => 'web' or 'middleware' => ['web', ...]
                    if (preg_match('/[\'"]middleware[\'"]\s*=>\s*[\'"]\s*web\s*[\'"]/', $lines[$i]) ||
                        preg_match('/[\'"]middleware[\'"]\s*=>\s*\[\s*[\'"]\s*web\s*[\'"]/', $lines[$i])) {
                        $hasWebInGroup = true;
                        break;
                    }

                    // Stop at the end of the array
                    if (str_contains($lines[$i], '],')) {
                        break;
                    }
                }

                if ($hasWebInGroup) {
                    $insideWebGroup = true;
                    $groupDepth++;
                }
            }

            // Track when we exit a group
            if ($insideWebGroup && preg_match('/^\s*\}\s*\);\s*$/', $line)) {
                $groupDepth--;
                if ($groupDepth <= 0) {
                    $insideWebGroup = false;
                    $groupDepth = 0;
                }
            }

            // Check for POST/PUT/PATCH/DELETE routes
            if (preg_match('/Route::(post|put|patch|delete)\s*\(/i', $line, $matches)) {
                $method = strtoupper($matches[1]);

                // If inside a web group, the route is protected
                if ($insideWebGroup) {
                    continue;
                }

                // Check if the route has explicit 'web' middleware
                $searchRange = min($lineNumber + 10, count($lines));
                $hasWebMiddleware = false;

                for ($i = $lineNumber; $i < $searchRange; $i++) {
                    if (! isset($lines[$i]) || ! is_string($lines[$i])) {
                        continue;
                    }

                    // Check for middleware('web') or middleware(['web', ...])
                    if (preg_match('/->middleware\s*\(\s*[\'"]\s*web\s*[\'"]/', $lines[$i]) ||
                        preg_match('/->middleware\s*\(\s*\[\s*[\'"]\s*web\s*[\'"]/', $lines[$i])) {
                        $hasWebMiddleware = true;
                        break;
                    }

                    // Stop at semicolon (end of route definition)
                    if (str_contains($lines[$i], ';')) {
                        break;
                    }
                }

                if (! $hasWebMiddleware) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: sprintf('%s route in custom route file missing CSRF protection - no "web" middleware detected', $method),
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Add ->middleware(\'web\') to the route or wrap it in Route::group([\'middleware\' => \'web\'], ...).',
                        metadata: [
                            'method' => $method,
                            'file' => basename($file),
                            'line' => $lineNumber + 1,
                            'severity_reason' => 'High severity for custom route files - web.php is automatically protected',
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
