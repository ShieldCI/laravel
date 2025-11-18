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
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Validates HTTP Strict Transport Security (HSTS) header configuration.
 *
 * Checks for:
 * - HSTS header in middleware
 * - Proper max-age configuration
 * - includeSubDomains directive
 * - preload directive
 */
class HSTSHeaderAnalyzer extends AbstractFileAnalyzer
{
    /**
     * HSTS header checks require a live web server, not applicable in CI.
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'hsts-header',
            name: 'HSTS Header Analyzer',
            description: 'Validates HTTP Strict Transport Security (HSTS) header configuration for HTTPS-only applications',
            category: Category::Security,
            severity: Severity::High,
            tags: ['hsts', 'https', 'headers', 'security', 'ssl', 'tls'],
            docsUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check if app is configured for HTTPS
        $isHttpsOnly = $this->isHttpsOnlyApp();

        if (! $isHttpsOnly) {
            // Skip HSTS check if not HTTPS-only
            return $this->passed('HSTS not required for non-HTTPS-only applications');
        }

        // Check for HSTS configuration in middleware
        $this->checkMiddlewareConfiguration($issues);

        // Check session configuration
        $this->checkSessionConfiguration($issues);

        // Check for security middleware packages
        $hasSecurityMiddleware = $this->checkSecurityMiddlewarePackages();

        if (empty($issues) || $hasSecurityMiddleware) {
            return $this->passed('HSTS header configuration is properly set');
        }

        return $this->failed(
            sprintf('Found %d HSTS header configuration issues', count($issues)),
            $issues
        );
    }

    /**
     * Check if application is configured for HTTPS only.
     */
    private function isHttpsOnlyApp(): bool
    {
        // Check session configuration
        $sessionConfig = ConfigFileHelper::getConfigPath($this->basePath, 'session.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        if (file_exists($sessionConfig)) {
            $content = FileParser::readFile($sessionConfig);
            if ($content !== null && preg_match('/["\']secure["\']\s*=>\s*true/i', $content)) {
                return true;
            }
        }

        // Check .env for FORCE_HTTPS or APP_URL with https
        $envFile = $this->basePath.'/.env';
        if (file_exists($envFile)) {
            $content = FileParser::readFile($envFile);
            if ($content !== null) {
                if (preg_match('/^APP_URL\s*=\s*https:/im', $content) ||
                    preg_match('/^FORCE_HTTPS\s*=\s*true/im', $content)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check middleware configuration for HSTS headers.
     */
    private function checkMiddlewareConfiguration(array &$issues): void
    {
        $middlewarePaths = [
            $this->basePath.'/app/Http/Middleware',
            $this->basePath.'/app/Http/Middleware/Security',
        ];

        $hasHSTSMiddleware = false;

        foreach ($middlewarePaths as $path) {
            if (! is_dir($path)) {
                continue;
            }

            foreach (new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS)
            ) as $file) {
                if ($file->getExtension() !== 'php') {
                    continue;
                }

                $content = FileParser::readFile($file->getPathname());
                if ($content === null) {
                    continue;
                }

                // Check for HSTS header configuration
                if (str_contains($content, 'Strict-Transport-Security') ||
                    str_contains($content, 'HSTS')) {
                    $hasHSTSMiddleware = true;

                    // Validate HSTS configuration
                    $this->validateHSTSConfiguration($file->getPathname(), $content, $issues);
                }
            }
        }

        if (! $hasHSTSMiddleware) {
            $issues[] = $this->createIssue(
                message: 'HTTPS-only application missing HSTS (Strict-Transport-Security) header',
                location: new Location(
                    'app/Http/Middleware',
                    1
                ),
                severity: Severity::High,
                recommendation: 'Add middleware to set Strict-Transport-Security header: "max-age=31536000; includeSubDomains; preload"',
                code: 'Missing HSTS header protection'
            );
        }
    }

    /**
     * Validate HSTS configuration in middleware.
     */
    private function validateHSTSConfiguration(string $file, string $content, array &$issues): void
    {
        $lines = FileParser::getLines($file);

        foreach ($lines as $lineNumber => $line) {
            if (str_contains($line, 'Strict-Transport-Security')) {
                // Check max-age value
                if (preg_match('/max-age\s*=\s*(\d+)/i', $line, $matches)) {
                    $maxAge = (int) $matches[1];

                    // Recommended minimum is 6 months (15768000 seconds), ideally 1 year (31536000)
                    if ($maxAge < 15768000) {
                        $issues[] = $this->createIssue(
                            message: sprintf('HSTS max-age (%d seconds) is below recommended minimum of 6 months', $maxAge),
                            location: new Location(
                                $this->getRelativePath($file),
                                $lineNumber + 1
                            ),
                            severity: Severity::Medium,
                            recommendation: 'Set HSTS max-age to at least 15768000 (6 months) or 31536000 (1 year)',
                            code: trim($line)
                        );
                    }
                }

                // Check for includeSubDomains
                if (! str_contains($line, 'includeSubDomains')) {
                    $issues[] = $this->createIssue(
                        message: 'HSTS header missing "includeSubDomains" directive',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Low,
                        recommendation: 'Add "includeSubDomains" to HSTS header for complete subdomain protection',
                        code: trim($line)
                    );
                }
            }
        }
    }

    /**
     * Check session configuration for HTTPS.
     */
    private function checkSessionConfiguration(array &$issues): void
    {
        $sessionConfig = ConfigFileHelper::getConfigPath($this->basePath, 'session.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        if (! file_exists($sessionConfig)) {
            return;
        }

        $content = FileParser::readFile($sessionConfig);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($sessionConfig);

        foreach ($lines as $lineNumber => $line) {
            // If app is HTTPS-only but secure cookies are disabled
            if (preg_match('/["\']secure["\']\s*=>\s*(false|0)/i', $line)) {
                $issues[] = $this->createIssue(
                    message: 'HTTPS-only application has secure cookies disabled',
                    location: new Location(
                        $this->getRelativePath($sessionConfig),
                        $lineNumber + 1
                    ),
                    severity: Severity::High,
                    recommendation: 'Set "secure" => true in config/session.php for HTTPS-only applications',
                    code: trim($line)
                );
            }
        }
    }

    /**
     * Check for popular security middleware packages.
     */
    private function checkSecurityMiddlewarePackages(): bool
    {
        $composerJson = $this->basePath.'/composer.json';

        if (! file_exists($composerJson)) {
            return false;
        }

        $content = FileParser::readFile($composerJson);
        if ($content === null) {
            return false;
        }

        // Check for packages that handle security headers
        $securityPackages = [
            'bepsvpt/secure-headers',
            'spatie/laravel-csp',
            'beyondcode/laravel-secure-headers',
        ];

        foreach ($securityPackages as $package) {
            if (str_contains($content, $package)) {
                return true;
            }
        }

        return false;
    }
}
