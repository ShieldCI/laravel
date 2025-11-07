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
            id: 'cookie-security',
            name: 'Cookie Security Analyzer',
            description: 'Validates cookie encryption and security configuration',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['cookies', 'encryption', 'xss', 'security', 'configuration'],
            docsUrl: 'https://laravel.com/docs/requests#cookies'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check session configuration
        $this->checkSessionConfig($issues);

        // Check for EncryptCookies middleware
        $this->checkEncryptCookiesMiddleware($issues);

        if (empty($issues)) {
            return $this->passed('Cookie security configuration is properly set');
        }

        return $this->failed(
            sprintf('Found %d cookie security issues', count($issues)),
            $issues
        );
    }

    /**
     * Check session configuration file.
     */
    private function checkSessionConfig(array &$issues): void
    {
        $sessionConfig = $this->basePath.'/config/session.php';

        if (! file_exists($sessionConfig)) {
            return;
        }

        $content = FileParser::readFile($sessionConfig);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($sessionConfig);

        foreach ($lines as $lineNumber => $line) {
            // Check HttpOnly flag
            if (preg_match('/["\']http_only["\']\s*=>\s*(false|0)/i', $line)) {
                $issues[] = $this->createIssue(
                    message: 'Session cookies are not secured with HttpOnly flag',
                    location: new Location(
                        $this->getRelativePath($sessionConfig),
                        $lineNumber + 1
                    ),
                    severity: Severity::Critical,
                    recommendation: 'Set "http_only" => true in config/session.php to protect against XSS attacks',
                    code: trim($line)
                );
            }

            // Check Secure flag (should be true for HTTPS sites)
            if (preg_match('/["\']secure["\']\s*=>\s*(false|0)/i', $line)) {
                $issues[] = $this->createIssue(
                    message: 'Session cookies are not restricted to HTTPS (secure flag disabled)',
                    location: new Location(
                        $this->getRelativePath($sessionConfig),
                        $lineNumber + 1
                    ),
                    severity: Severity::High,
                    recommendation: 'Set "secure" => env("SESSION_SECURE_COOKIE", true) for HTTPS-only applications',
                    code: trim($line)
                );
            }

            // Check SameSite attribute
            if (preg_match('/["\']same_site["\']\s*=>\s*["\']?(?:null|none)["\']?/i', $line)) {
                $issues[] = $this->createIssue(
                    message: 'Session cookies have weak SameSite protection',
                    location: new Location(
                        $this->getRelativePath($sessionConfig),
                        $lineNumber + 1
                    ),
                    severity: Severity::Medium,
                    recommendation: 'Use "same_site" => "lax" or "strict" to protect against CSRF attacks',
                    code: trim($line)
                );
            }
        }
    }

    /**
     * Check for EncryptCookies middleware.
     */
    private function checkEncryptCookiesMiddleware(array &$issues): void
    {
        $kernelFile = $this->basePath.'/app/Http/Kernel.php';

        if (! file_exists($kernelFile)) {
            // Check bootstrap/app.php for Laravel 11+
            $bootstrapApp = $this->basePath.'/bootstrap/app.php';
            if (file_exists($bootstrapApp)) {
                $this->checkBootstrapApp($bootstrapApp, $issues);
            }

            return;
        }

        $content = FileParser::readFile($kernelFile);
        if ($content === null) {
            return;
        }

        // Check if EncryptCookies middleware is present
        if (! str_contains($content, 'EncryptCookies')) {
            $issues[] = $this->createIssue(
                message: 'EncryptCookies middleware is not registered in HTTP Kernel',
                location: new Location(
                    $this->getRelativePath($kernelFile),
                    1
                ),
                severity: Severity::Critical,
                recommendation: 'Add \\App\\Http\\Middleware\\EncryptCookies::class to $middleware array in app/Http/Kernel.php',
                code: 'Missing EncryptCookies middleware'
            );
        }

        // Check if it's commented out
        $lines = FileParser::getLines($kernelFile);
        foreach ($lines as $lineNumber => $line) {
            if (str_contains($line, 'EncryptCookies') &&
                preg_match('/^\s*\/\//', $line)) {
                $issues[] = $this->createIssue(
                    message: 'EncryptCookies middleware is commented out',
                    location: new Location(
                        $this->getRelativePath($kernelFile),
                        $lineNumber + 1
                    ),
                    severity: Severity::Critical,
                    recommendation: 'Uncomment the EncryptCookies middleware to enable cookie encryption',
                    code: trim($line)
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
        if ($content === null) {
            return;
        }

        if (! str_contains($content, 'EncryptCookies') && ! str_contains($content, 'encryptCookies')) {
            $issues[] = $this->createIssue(
                message: 'EncryptCookies middleware may not be properly configured',
                location: new Location(
                    $this->getRelativePath($file),
                    1
                ),
                severity: Severity::High,
                recommendation: 'Ensure cookie encryption is enabled in your middleware configuration',
                code: 'EncryptCookies middleware not found in bootstrap/app.php'
            );
        }
    }
}
