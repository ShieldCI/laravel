<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Concerns\AnalyzesMiddleware;

/**
 * Validates cookie security configuration.
 *
 * Checks for:
 * - EncryptCookies middleware is enabled
 * - HttpOnly flag is enabled for session cookies
 * - Secure flag for HTTPS-only cookies
 * - SameSite cookie attribute configuration
 */
class CookieSecurityAnalyzer extends AbstractFileAnalyzer
{
    use AnalyzesMiddleware;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'cookie',
            name: 'Cookie Analyzer',
            description: 'Validates cookie encryption and security configuration',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['cookies', 'encryption', 'xss', 'security', 'configuration'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/cookie',
            timeToFix: 15
        );
    }

    public function shouldRun(): bool
    {
        // Check if there are any files to analyze
        $sessionConfig = ConfigFileHelper::getConfigPath($this->getBasePath(), 'session.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);
        $kernelFile = $this->buildPath('app', 'Http', 'Kernel.php');
        $bootstrapApp = $this->buildPath('bootstrap', 'app.php');

        return file_exists($sessionConfig) ||
               file_exists($kernelFile) ||
               file_exists($bootstrapApp);
    }

    public function getSkipReason(): string
    {
        return 'No session configuration or middleware files found to analyze';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check session configuration
        $this->checkSessionConfig($issues);

        // Check for EncryptCookies middleware
        $this->checkEncryptCookiesMiddleware($issues);

        $summary = empty($issues)
            ? 'Cookie security configuration is properly set'
            : sprintf('Found %d cookie security issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check session configuration file.
     */
    private function checkSessionConfig(array &$issues): void
    {
        $sessionConfig = ConfigFileHelper::getConfigPath($this->getBasePath(), 'session.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        if (! file_exists($sessionConfig)) {
            return;
        }

        $content = FileParser::readFile($sessionConfig);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($sessionConfig);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Skip commented lines
            if (preg_match('/^\s*\/\//', $line)) {
                continue;
            }

            // Check HttpOnly flag
            if (preg_match('/["\']http_only["\']\s*=>\s*(false|0)/i', $line, $matches)) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'Session cookies are not secured with HttpOnly flag',
                    filePath: $sessionConfig,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Critical,
                    recommendation: 'Set "http_only" => true in config/session.php to protect against XSS attacks',
                    code: 'http_only',
                    metadata: [
                        'file' => 'session.php',
                        'config_key' => 'http_only',
                        'current_value' => $matches[1],
                    ]
                );
            }

            // Check Secure flag (should be true for HTTPS sites)
            if (preg_match('/["\']secure["\']\s*=>\s*(false|0)/i', $line, $matches)) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'Session cookies are not restricted to HTTPS (secure flag disabled)',
                    filePath: $sessionConfig,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::High,
                    recommendation: 'Set "secure" => env("SESSION_SECURE_COOKIE", true) for HTTPS-only applications',
                    code: 'secure',
                    metadata: [
                        'file' => 'session.php',
                        'config_key' => 'secure',
                        'current_value' => $matches[1],
                    ]
                );
            }

            // Check SameSite attribute
            if (preg_match('/["\']same_site["\']\s*=>\s*["\']?(null|none)["\']?/i', $line, $matches)) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'Session cookies have weak SameSite protection',
                    filePath: $sessionConfig,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Medium,
                    recommendation: 'Use "same_site" => "lax" or "strict" to protect against CSRF attacks',
                    code: 'same_site',
                    metadata: [
                        'file' => 'session.php',
                        'config_key' => 'same_site',
                        'current_value' => $matches[1],
                    ]
                );
            }
        }
    }

    /**
     * Check for EncryptCookies middleware.
     */
    private function checkEncryptCookiesMiddleware(array &$issues): void
    {
        // First, try to check if middleware is registered at runtime (most accurate)
        if ($this->checkRuntimeMiddleware($issues)) {
            return; // Runtime check succeeded, no need for file-based checks
        }

        // Fall back to file-based checks if app isn't bootstrapped
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

        // Check if EncryptCookies middleware is present
        if (! str_contains($content, 'EncryptCookies')) {
            $issues[] = $this->createIssueWithSnippet(
                message: 'EncryptCookies middleware is not registered in HTTP Kernel',
                filePath: $kernelFile,
                lineNumber: null,
                severity: Severity::Critical,
                recommendation: 'Add \\App\\Http\\Middleware\\EncryptCookies::class to $middleware array in app/Http/Kernel.php',
                code: 'EncryptCookies',
                metadata: [
                    'file' => 'Kernel.php',
                    'middleware' => 'EncryptCookies',
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

            if (str_contains($line, 'EncryptCookies') &&
                preg_match('/^\s*\/\//', $line)) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'EncryptCookies middleware is commented out',
                    filePath: $kernelFile,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Critical,
                    recommendation: 'Uncomment the EncryptCookies middleware to enable cookie encryption',
                    code: 'EncryptCookies',
                    metadata: [
                        'file' => 'Kernel.php',
                        'middleware' => 'EncryptCookies',
                        'status' => 'commented',
                        'line' => $lineNumber + 1,
                    ]
                );
            }
        }
    }

    /**
     * Check if EncryptCookies middleware is registered at runtime.
     * Returns true if check was successful (app is bootstrapped), false otherwise.
     *
     * This method is conservative - it only uses runtime checks when we're confident
     * the app is fully bootstrapped with the actual application code. In test scenarios
     * or when the app path doesn't match, it falls back to file-based checks.
     */
    private function checkRuntimeMiddleware(array &$issues): bool
    {
        // Check if Laravel app is bootstrapped
        if (! function_exists('app')) {
            return false;
        }

        try {
            $app = app();

            // Type check: ensure app() returned an Application instance
            if (! $app instanceof Application) {
                return false;
            }

            if (! $app->bound(Router::class) || ! $app->bound(Kernel::class)) {
                return false;
            }

            // Conservative check: Only use runtime checks if the app's base path matches
            // our analyzer's base path. If they don't match, we're likely in a test scenario
            // and should use file-based checks instead.
            $appBasePath = $app->basePath();
            $analyzerBasePath = $this->getBasePath();

            // Normalize paths for comparison
            $appBasePath = rtrim(str_replace('\\', '/', $appBasePath), '/');
            $analyzerBasePath = rtrim(str_replace('\\', '/', $analyzerBasePath), '/');

            // If paths don't match, we're probably in a test scenario - use file checks
            if ($appBasePath !== $analyzerBasePath && $analyzerBasePath !== '') {
                return false;
            }

            $router = $app->make(Router::class);
            $kernel = $app->make(Kernel::class);

            if ($router === null || $kernel === null) {
                return false;
            }

            $this->router = $router;
            $this->kernel = $kernel;

            // Check if EncryptCookies is registered globally
            // Use try-catch around the middleware check since reflection can fail
            try {
                $encryptCookiesClasses = [
                    'Illuminate\Cookie\Middleware\EncryptCookies',
                    'App\Http\Middleware\EncryptCookies',
                    'EncryptCookies',
                ];

                $isRegistered = false;
                foreach ($encryptCookiesClasses as $middlewareClass) {
                    try {
                        if ($this->appUsesGlobalMiddleware($middlewareClass)) {
                            $isRegistered = true;
                            break;
                        }
                    } catch (\ReflectionException $e) {
                        // If reflection fails, we can't reliably check - fall back to file checks
                        return false;
                    }
                }

                if (! $isRegistered) {
                    // Check if it's registered on any route (less ideal but still acceptable)
                    try {
                        $isRegistered = $this->appUsesMiddleware('Illuminate\Cookie\Middleware\EncryptCookies');
                    } catch (\ReflectionException $e) {
                        // If reflection fails, we can't reliably check - fall back to file checks
                        return false;
                    }
                }

                // Only create issue if we're certain it's not registered
                if (! $isRegistered) {
                    $kernelFile = $this->buildPath('app', 'Http', 'Kernel.php');
                    $bootstrapApp = $this->buildPath('bootstrap', 'app.php');
                    $configFile = file_exists($kernelFile) ? $kernelFile : (file_exists($bootstrapApp) ? $bootstrapApp : $kernelFile);

                    $issues[] = $this->createIssueWithSnippet(
                        message: 'EncryptCookies middleware is not registered globally',
                        filePath: $configFile,
                        lineNumber: null,
                        severity: Severity::Critical,
                        recommendation: 'Register EncryptCookies middleware globally in app/Http/Kernel.php (Laravel 9/10) or bootstrap/app.php (Laravel 11+) to enable cookie encryption',
                        code: 'EncryptCookies',
                        metadata: [
                            'file' => file_exists($kernelFile) ? 'Kernel.php' : 'bootstrap/app.php',
                            'middleware' => 'EncryptCookies',
                            'status' => 'missing',
                            'detection_method' => 'runtime',
                        ]
                    );
                }

                return true; // Runtime check completed successfully
            } catch (\ReflectionException $e) {
                // If reflection fails, we can't reliably check - fall back to file checks
                return false;
            }
        } catch (\Throwable $e) {
            // If runtime check fails for any reason, fall back to file-based checks
            return false;
        }
    }

    /**
     * Check bootstrap/app.php for Laravel 11+ applications.
     * This is a fallback when runtime checks aren't available.
     */
    private function checkBootstrapApp(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null || ! is_string($content)) {
            return;
        }

        // Check for various ways EncryptCookies might be registered in Laravel 11+
        $hasEncryptCookies = str_contains($content, 'EncryptCookies') ||
                             str_contains($content, 'encryptCookies') ||
                             str_contains($content, 'EncryptCookies::class') ||
                             preg_match('/->withMiddleware\s*\([^)]*EncryptCookies/i', $content) ||
                             preg_match('/->withMiddleware\s*\([^)]*encryptCookies/i', $content);

        if (! $hasEncryptCookies) {
            $issues[] = $this->createIssueWithSnippet(
                message: 'EncryptCookies middleware may not be properly configured in bootstrap/app.php',
                filePath: $file,
                lineNumber: null,
                severity: Severity::High,
                recommendation: 'Add EncryptCookies middleware using ->withMiddleware() in bootstrap/app.php to enable cookie encryption',
                code: 'EncryptCookies',
                metadata: [
                    'file' => 'bootstrap/app.php',
                    'laravel_version' => '11+',
                    'middleware' => 'EncryptCookies',
                    'detection_method' => 'file_analysis',
                ]
            );
        }
    }
}
