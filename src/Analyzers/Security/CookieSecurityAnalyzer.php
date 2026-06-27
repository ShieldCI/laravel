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
use ShieldCI\Concerns\InspectsCode;

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
    use InspectsCode;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'cookie',
            name: 'Cookie Analyzer',
            description: 'Validates cookie encryption and security configuration',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['cookies', 'encryption', 'xss', 'security', 'configuration'],
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
     * Check session configuration file using AST parsing.
     */
    private function checkSessionConfig(array &$issues): void
    {
        $sessionConfig = ConfigFileHelper::getConfigPath($this->getBasePath(), 'session.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        if (! file_exists($sessionConfig)) {
            return;
        }

        $config = $this->parseConfigArray($sessionConfig);

        if ($config === []) {
            return;
        }

        // Check HttpOnly flag
        if (isset($config['http_only'])) {
            $entry = $config['http_only'];
            $effectiveValue = $this->resolveConfigValue($entry);

            if ($effectiveValue === false || $effectiveValue === 0) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'Session cookies are not secured with HttpOnly flag',
                    filePath: $sessionConfig,
                    lineNumber: $entry['line'],
                    severity: Severity::Critical,
                    recommendation: 'Enable the http_only flag in config/session.php to prevent client-side scripts from accessing session cookies, protecting against XSS-based session theft.',
                    metadata: [
                        'file' => 'session.php',
                        'config_key' => 'http_only',
                        'current_value' => $this->configValueToString($effectiveValue),
                        'code' => 'http-only',
                    ]
                );
            }
        }

        // Check Secure flag (should be true for HTTPS sites)
        if (isset($config['secure'])) {
            $entry = $config['secure'];
            $effectiveValue = $this->resolveConfigValue($entry);

            if ($effectiveValue === false || $effectiveValue === 0) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'Session cookies are not restricted to HTTPS (secure flag disabled)',
                    filePath: $sessionConfig,
                    lineNumber: $entry['line'],
                    severity: Severity::High,
                    recommendation: 'Enable the secure cookie flag in config/session.php so session cookies are only transmitted over HTTPS. Use an environment variable to control this setting per environment.',
                    metadata: [
                        'file' => 'session.php',
                        'config_key' => 'secure',
                        'current_value' => $this->configValueToString($effectiveValue),
                        'code' => 'secure',
                    ]
                );
            }
        }

        // Check SameSite attribute
        if (isset($config['same_site'])) {
            $entry = $config['same_site'];

            // env() with no default — runtime-dependent, cannot determine statically
            $hasIndeterminateDefault = $entry['isEnvCall'] && ! $entry['envHasDefault'];

            if (! $hasIndeterminateDefault) {
                $effectiveValue = $this->resolveConfigValue($entry);
                $isWeak = $effectiveValue === null
                    || (is_string($effectiveValue) && in_array(strtolower($effectiveValue), ['null', 'none'], true));

                if ($isWeak) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Session cookies have weak SameSite protection',
                        filePath: $sessionConfig,
                        lineNumber: $entry['line'],
                        severity: Severity::Medium,
                        recommendation: 'Set the same_site option to lax or strict in config/session.php to restrict cross-site cookie transmission and protect against CSRF attacks.',
                        metadata: [
                            'file' => 'session.php',
                            'config_key' => 'same_site',
                            'current_value' => $this->configValueToString($effectiveValue),
                            'code' => 'same-site',
                        ]
                    );
                }
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
            // No app/Http/Kernel.php means a Laravel 11+ app, where EncryptCookies
            // ships in the framework-default `web` middleware group. The runtime
            // check above is the authoritative signal; a missing static reference
            // in bootstrap/app.php is the normal, secure default, not a problem.
            return;
        }

        $content = FileParser::readFile($kernelFile);
        if ($content === null) {
            return;
        }

        // Check if EncryptCookies middleware is present
        if (! str_contains($content, 'EncryptCookies')) {
            $issues[] = $this->createIssueWithSnippet(
                message: 'EncryptCookies middleware is not registered in HTTP Kernel',
                filePath: $kernelFile,
                lineNumber: null,
                severity: Severity::Critical,
                recommendation: 'Register the EncryptCookies middleware in the global middleware stack in app/Http/Kernel.php to enable cookie encryption.',
                metadata: [
                    'file' => 'Kernel.php',
                    'middleware' => 'EncryptCookies',
                    'status' => 'missing',
                    'code' => 'encrypt-cookies',
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
                    metadata: [
                        'file' => 'Kernel.php',
                        'middleware' => 'EncryptCookies',
                        'status' => 'commented',
                        'line' => $lineNumber + 1,
                        'code' => 'encrypt-cookies',
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
                    // Laravel 11+ registers EncryptCookies in the default `web` middleware
                    // group rather than the global stack, so inspect groups before failing.
                    foreach ($encryptCookiesClasses as $middlewareClass) {
                        if ($this->appUsesGroupMiddleware($middlewareClass)) {
                            $isRegistered = true;
                            break;
                        }
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
                        message: 'EncryptCookies middleware is not registered',
                        filePath: $configFile,
                        lineNumber: null,
                        severity: Severity::Critical,
                        recommendation: 'Without EncryptCookies, cookies are stored in plaintext and can be read or tampered with by the client. Register it so the app encrypts cookies — in the web middleware group (the Laravel 11+ default) or the global middleware stack in app/Http/Kernel.php (Laravel 9/10).',
                        metadata: [
                            'file' => file_exists($kernelFile) ? 'Kernel.php' : 'bootstrap/app.php',
                            'middleware' => 'EncryptCookies',
                            'status' => 'missing',
                            'detection_method' => 'runtime',
                            'code' => 'encrypt-cookies',
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
     * Convert a config value to its string representation for metadata.
     */
    private function configValueToString(mixed $value): string
    {
        if ($value === null) {
            return 'null';
        }

        if ($value === true) {
            return 'true';
        }

        if ($value === false) {
            return 'false';
        }

        if (is_int($value) || is_float($value) || is_string($value)) {
            return (string) $value;
        }

        return 'unknown';
    }
}
