<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

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
                lineNumber: 1,
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
     * Check bootstrap/app.php for Laravel 11+ applications.
     */
    private function checkBootstrapApp(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null || ! is_string($content)) {
            return;
        }

        if (! str_contains($content, 'EncryptCookies') && ! str_contains($content, 'encryptCookies')) {
            $issues[] = $this->createIssueWithSnippet(
                message: 'EncryptCookies middleware may not be properly configured',
                filePath: $file,
                lineNumber: 1,
                severity: Severity::High,
                recommendation: 'Ensure cookie encryption is enabled in your middleware configuration',
                code: 'EncryptCookies',
                metadata: [
                    'file' => 'bootstrap/app.php',
                    'laravel_version' => '11+',
                    'middleware' => 'EncryptCookies',
                ]
            );
        }
    }
}
