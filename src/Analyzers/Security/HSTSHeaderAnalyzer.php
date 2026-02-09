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
 * - Proper max-age configuration (>= 6 months)
 * - includeSubDomains directive
 * - preload directive (optional)
 * - Secure cookie configuration for HTTPS apps
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
            timeToFix: 10
        );
    }

    public function shouldRun(): bool
    {
        // Check if app is configured for HTTPS
        $isHttpsOnly = $this->isHttpsOnlyApp();

        if (! $isHttpsOnly) {
            return false;
        }

        return true;
    }

    public function getSkipReason(): string
    {
        // Skip HSTS check if not HTTPS-only
        return 'HSTS not required for non-HTTPS-only applications';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check for HSTS configuration in middleware
        $this->checkMiddlewareConfiguration($issues);

        // Check session configuration
        $this->checkSessionConfiguration($issues);

        $summary = empty($issues)
            ? 'HSTS header configuration is properly set'
            : sprintf('Found %d HSTS header configuration issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check if application is configured for HTTPS only.
     */
    private function isHttpsOnlyApp(): bool
    {
        // Check session configuration
        $sessionConfig = ConfigFileHelper::getConfigPath($this->getBasePath(), 'session.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        if (file_exists($sessionConfig)) {
            $content = FileParser::readFile($sessionConfig);
            if ($content !== null && preg_match('/["\']secure["\']\s*=>\s*true/i', $content)) {
                return true;
            }
        }

        // Check .env for FORCE_HTTPS or APP_URL with https
        $envFile = $this->getBasePath().DIRECTORY_SEPARATOR.'.env';
        if (file_exists($envFile)) {
            $content = FileParser::readFile($envFile);
            if ($content !== null && is_string($content)) {
                if (preg_match('/^APP_URL\s*=\s*https:/im', $content) ||
                    preg_match('/^FORCE_HTTPS\s*=\s*true/im', $content)) {
                    return true;
                }
            }
        }

        // Check config/app.php for force_https
        $appConfig = ConfigFileHelper::getConfigPath($this->getBasePath(), 'app.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);
        if (file_exists($appConfig)) {
            $content = FileParser::readFile($appConfig);
            if ($content !== null && preg_match('/["\']force_https["\']\s*=>\s*true/i', $content)) {
                return true;
            }
        }

        // AppServiceProvider URL::forceScheme('https')
        if ($this->hasForceHttpsInServiceProvider()) {
            return true;
        }

        // Check for HTTPS enforcement middleware in Kernel.php
        $kernelFile = $this->getBasePath().DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Kernel.php';
        if (file_exists($kernelFile)) {
            $content = FileParser::readFile($kernelFile);
            if ($content !== null && (
                str_contains($content, 'ForceHttps') ||
                str_contains($content, 'HttpsProtocol')
            )) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for HTTPS enforcement middleware in AppServiceProvider.php
     */
    private function hasForceHttpsInServiceProvider(): bool
    {
        $providerPath = $this->getBasePath().DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Providers'.DIRECTORY_SEPARATOR.'AppServiceProvider.php';

        if (! file_exists($providerPath)) {
            return false;
        }

        $content = FileParser::readFile($providerPath);
        if (! is_string($content)) {
            return false;
        }

        // Strip comments
        $content = preg_replace('/^\s*\/\/.*$/m', '', $content) ?? '';
        $content = preg_replace('/\/\*.*?\*\//s', '', $content) ?? '';

        return preg_match('/\bURL::force(?:Scheme\s*\(\s*[\'"]https[\'"]\s*\)|Https\s*\(\s*\))/i', $content) === 1;
    }

    /**
     * Check middleware configuration for HSTS headers.
     */
    private function checkMiddlewareConfiguration(array &$issues): void
    {
        $hasHSTSMiddleware = false;
        $config = $this->getConfiguration();

        // Scan middleware directories directly
        $middlewarePaths = [
            $this->getBasePath().DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Middleware',
            $this->getBasePath().DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Middleware'.DIRECTORY_SEPARATOR.'Security',
        ];

        foreach ($middlewarePaths as $path) {
            if (! is_dir($path)) {
                continue;
            }

            /** @var \SplFileInfo $file */
            foreach (new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS)
            ) as $file) {
                if ($file->getExtension() !== 'php') {
                    continue;
                }

                // Check if this file is in ignored list
                $relativePath = $this->getRelativePath($file->getPathname());
                $shouldIgnore = false;
                foreach ($config['ignored_middleware'] as $ignoredPath) {
                    if (is_string($ignoredPath) && str_contains($relativePath, $ignoredPath)) {
                        $shouldIgnore = true;
                        break;
                    }
                }

                if ($shouldIgnore) {
                    continue;
                }

                $content = FileParser::readFile($file->getPathname());
                if ($content === null || ! is_string($content)) {
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

        // Check for security packages that might handle HSTS
        $hasSecurityPackage = $this->checkSecurityMiddlewarePackages();

        if (! $hasHSTSMiddleware && ! $hasSecurityPackage) {
            $middlewarePath = $this->getBasePath().DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Middleware';
            $issues[] = $this->createIssue(
                message: 'HTTPS-only application missing HSTS (Strict-Transport-Security) header',
                location: new Location($middlewarePath),
                severity: Severity::High,
                recommendation: 'Add middleware to set Strict-Transport-Security header: "max-age=31536000; includeSubDomains; preload"',
                metadata: [
                    'issue_type' => 'missing_hsts',
                    'https_only' => true,
                ]
            );
        }
    }

    /**
     * Validate HSTS configuration in middleware.
     */
    private function validateHSTSConfiguration(string $file, string $content, array &$issues): void
    {
        $lines = FileParser::getLines($file);
        $config = $this->getConfiguration();

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            if (str_contains($line, 'Strict-Transport-Security')) {
                // Check max-age value
                if (preg_match('/max-age\s*=\s*(\d+)/i', $line, $matches)) {
                    $maxAge = (int) $matches[1];

                    // Check against configured minimum
                    /** @var int $minMaxAge */
                    $minMaxAge = $config['min_max_age'];

                    if ($maxAge < $minMaxAge) {
                        $daysVulnerable = ($minMaxAge - $maxAge) / 86400;

                        $issues[] = $this->createIssue(
                            message: sprintf('HSTS max-age (%d seconds) is below recommended minimum of %d seconds', $maxAge, $minMaxAge),
                            location: new Location($this->getRelativePath($file), $lineNumber + 1),
                            severity: Severity::High,
                            recommendation: sprintf('Set HSTS max-age to at least %d (6 months) or 31536000 (1 year)', $minMaxAge),
                            code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                            metadata: [
                                'issue_type' => 'weak_max_age',
                                'max_age' => $maxAge,
                                'min_recommended' => $minMaxAge,
                                'days_vulnerable' => (int) $daysVulnerable,
                            ]
                        );
                    }
                }

                // Check for includeSubDomains
                if ($config['require_include_subdomains'] && ! str_contains($line, 'includeSubDomains')) {
                    $issues[] = $this->createIssue(
                        message: 'HSTS header missing "includeSubDomains" directive',
                        location: new Location($this->getRelativePath($file), $lineNumber + 1),
                        severity: Severity::Medium,
                        recommendation: 'Add "includeSubDomains" to HSTS header for complete subdomain protection',
                        code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                        metadata: [
                            'issue_type' => 'missing_directive',
                            'missing_directive' => 'includeSubDomains',
                            'current_header' => trim($line),
                        ]
                    );
                }

                // Check for preload (if required by configuration)
                if ($config['require_preload'] && ! str_contains($line, 'preload')) {
                    $issues[] = $this->createIssue(
                        message: 'HSTS header missing "preload" directive',
                        location: new Location($this->getRelativePath($file), $lineNumber + 1),
                        severity: Severity::Low,
                        recommendation: 'Add "preload" to HSTS header and submit to https://hstspreload.org/ for browser preload list inclusion',
                        code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                        metadata: [
                            'issue_type' => 'missing_directive',
                            'missing_directive' => 'preload',
                            'current_header' => trim($line),
                        ]
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
        $config = $this->getConfiguration();

        if (! $config['check_session_secure']) {
            return;
        }

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

            // If app is HTTPS-only but secure cookies are disabled
            if (preg_match('/["\']secure["\']\s*=>\s*(false|0)/i', $line)) {
                $issues[] = $this->createIssue(
                    message: 'HTTPS-only application has secure cookies disabled',
                    location: new Location($this->getRelativePath($sessionConfig), $lineNumber + 1),
                    severity: Severity::High,
                    recommendation: 'Set "secure" => true in config/session.php for HTTPS-only applications',
                    code: FileParser::getCodeSnippet($sessionConfig, $lineNumber + 1),
                    metadata: [
                        'issue_type' => 'insecure_cookies',
                        'https_only' => true,
                    ]
                );
            }
        }
    }

    /**
     * Check for popular security middleware packages.
     */
    private function checkSecurityMiddlewarePackages(): bool
    {
        $composerJson = $this->getBasePath().DIRECTORY_SEPARATOR.'composer.json';

        if (! file_exists($composerJson)) {
            return false;
        }

        $content = FileParser::readFile($composerJson);
        if ($content === null || ! is_string($content)) {
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

    /**
     * Get analyzer configuration.
     *
     * @return array<string, mixed>
     */
    private function getConfiguration(): array
    {
        /** @var array<string, mixed> $config */
        $config = config('shieldci.hsts_header', []);

        return array_merge([
            'min_max_age' => 15768000,  // 6 months in seconds
            'require_include_subdomains' => true,
            'require_preload' => false,  // Optional by default
            'ignored_middleware' => [],
            'check_session_secure' => true,
        ], $config);
    }
}
