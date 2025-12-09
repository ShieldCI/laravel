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
 * Validates that the application encryption key is properly configured.
 *
 * Checks for:
 * - APP_KEY is set in .env files
 * - APP_KEY is not the default/example value
 * - APP_KEY follows proper format (base64: prefix)
 * - config/app.php has proper key configuration
 */
class AppKeyAnalyzer extends AbstractFileAnalyzer
{
    /**
     * App key configuration is environment-specific, not applicable in CI.
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'app-key-security',
            name: 'Application Key Analyzer',
            description: 'Validates that the application encryption key is properly configured and secure',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['encryption', 'app-key', 'security', 'configuration'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/app-key',
            timeToFix: 5
        );
    }

    public function shouldRun(): bool
    {
        // Check if there is .env file or config/app.php to analyze
        return file_exists($this->buildPath('.env')) ||
               file_exists($this->buildPath('config', 'app.php'));
    }

    public function getSkipReason(): string
    {
        return 'No .env files or app configuration found to analyze';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check for cached config (must be first to warn about effectiveness of changes)
        $this->checkCachedConfig($issues);

        // Check .env file for APP_KEY
        $this->checkEnvFile($issues);

        // Check config/app.php
        $this->checkAppConfig($issues);

        $summary = empty($issues)
            ? 'Application encryption key is properly configured'
            : sprintf('Found %d application key security issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check .env file for APP_KEY configuration.
     *
     * @param  array<int, mixed>  &$issues
     */
    private function checkEnvFile(array &$issues): void
    {
        $envFile = $this->buildPath('.env');

        if (! file_exists($envFile)) {
            // Don't report missing .env - EnvFileAnalyzer handles this
            return;
        }

        $content = FileParser::readFile($envFile);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($envFile);
        $hasAppKey = false;
        $appKeyValue = null;
        $appKeyCount = 0;
        $firstKeyLine = 0;

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            $trimmedLine = trim($line);

            // Skip comments
            if ($trimmedLine === '' ||
                str_starts_with($trimmedLine, '#') ||
                str_starts_with($trimmedLine, '//')) {
                continue;
            }

            // Check for APP_KEY setting
            if (preg_match('/^APP_KEY\s*=\s*(.*)$/i', $trimmedLine, $matches)) {
                $appKeyCount++;

                if ($appKeyCount === 1) {
                    $firstKeyLine = $lineNumber;
                }

                $hasAppKey = true;

                // Extract and validate match result
                if (! is_string($matches[1])) {
                    continue;
                }

                $appKeyValue = trim($matches[1]);

                // Detect multiple APP_KEY definitions
                if ($appKeyCount > 1) {
                    $issues[] = $this->createIssue(
                        message: sprintf('Multiple APP_KEY definitions found (first at line %d, duplicate at line %d)', $firstKeyLine + 1, $lineNumber + 1),
                        location: new Location(
                            $this->getRelativePath($envFile),
                            $lineNumber + 1
                        ),
                        severity: Severity::High,
                        recommendation: 'Remove duplicate APP_KEY definitions. Only one APP_KEY should be defined per file.',
                        code: FileParser::getCodeSnippet($envFile, $lineNumber + 1),
                        metadata: ['duplicate_count' => $appKeyCount]
                    );

                    continue; // Skip validation for duplicate entries
                }

                $normalizedValue = $this->normalizeKeyValue($appKeyValue);

                // Check if APP_KEY is empty or whitespace
                if ($normalizedValue === '') {
                    $issues[] = $this->createIssue(
                        message: 'APP_KEY is not set or is empty',
                        location: new Location(
                            $this->getRelativePath($envFile),
                            $lineNumber + 1
                        ),
                        severity: Severity::Critical,
                        recommendation: 'Run "php artisan key:generate" to generate a secure application key',
                        code: FileParser::getCodeSnippet($envFile, $lineNumber + 1),
                        metadata: ['file' => basename($envFile)]
                    );
                }
                // Check if APP_KEY is a placeholder (case-insensitive)
                elseif ($this->isPlaceholderValue($appKeyValue)) {
                    $issues[] = $this->createIssue(
                        message: 'APP_KEY is set to a placeholder/example value',
                        location: new Location(
                            $this->getRelativePath($envFile),
                            $lineNumber + 1
                        ),
                        severity: Severity::Critical,
                        recommendation: 'Run "php artisan key:generate" to generate a secure application key',
                        code: FileParser::getCodeSnippet($envFile, $lineNumber + 1),
                        metadata: [
                            'file' => basename($envFile),
                            'placeholder_detected' => $normalizedValue,
                        ]
                    );
                }
                // Validate APP_KEY format and strength
                elseif (! $this->isValidAppKey($appKeyValue)) {
                    $issues[] = $this->createIssue(
                        message: 'APP_KEY does not follow the expected format or is too short',
                        location: new Location(
                            $this->getRelativePath($envFile),
                            $lineNumber + 1
                        ),
                        severity: Severity::High,
                        recommendation: 'Ensure APP_KEY is properly generated with "php artisan key:generate". Valid keys must be at least 32 characters or use base64: prefix with properly encoded content (minimum 16 bytes decoded).',
                        code: FileParser::getCodeSnippet($envFile, $lineNumber + 1),
                        metadata: [
                            'file' => basename($envFile),
                            'provided_length' => strlen($normalizedValue),
                            'minimum_length' => 32,
                        ]
                    );
                }
            }
        }

        // Flag missing APP_KEY
        if (! $hasAppKey) {
            $issues[] = $this->createIssue(
                message: 'APP_KEY is not defined in .env file',
                location: new Location(
                    $this->getRelativePath($envFile),
                    1
                ),
                severity: Severity::Critical,
                recommendation: 'Add APP_KEY to your .env file and run "php artisan key:generate"',
                code: FileParser::getCodeSnippet($envFile, 1),
                metadata: ['file' => basename($envFile)]
            );
        }
    }

    /**
     * Check config/app.php for key configuration.
     *
     * @param  array<int, mixed>  &$issues
     */
    private function checkAppConfig(array &$issues): void
    {
        $basePath = $this->getBasePath();
        $appConfig = ConfigFileHelper::getConfigPath($basePath, 'app.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        if (! file_exists($appConfig)) {
            return;
        }

        $content = FileParser::readFile($appConfig);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($appConfig);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check for hardcoded key (security issue)
            // Skip if it's using env()
            if (preg_match('/["\']key["\']\s*=>\s*env\s*\(/i', $line)) {
                continue;
            }

            // Check for hardcoded key value
            if (preg_match('/["\']key["\']\s*=>\s*["\'][^"\']+["\']/i', $line)) {
                // Check if it's a real hardcoded key (not a comment or documentation)
                if (! preg_match('/^\s*\/\/|^\s*\*/', $line)) {
                    $issues[] = $this->createIssue(
                        message: 'Application key is hardcoded in config/app.php instead of using environment variable',
                        location: new Location(
                            $this->getRelativePath($appConfig),
                            $lineNumber + 1
                        ),
                        severity: Severity::Critical,
                        recommendation: 'Use env("APP_KEY") to reference the key from .env file',
                        code: FileParser::getCodeSnippet($appConfig, $lineNumber + 1),
                        metadata: [
                            'file' => 'app.php',
                            'config_key' => 'key',
                        ]
                    );
                }
            }

            // Check for insecure cipher configuration
            if (preg_match('/["\']cipher["\']\s*=>\s*["\']([^"\']+)["\']/i', $line, $matches)) {
                if (is_string($matches[1])) {
                    $cipher = strtolower($matches[1]);

                    // Laravel supports AES-128-CBC and AES-256-CBC
                    if (! in_array($cipher, ['aes-128-cbc', 'aes-256-cbc'], true)) {
                        $issues[] = $this->createIssue(
                            message: sprintf('Unsupported or weak cipher algorithm: %s', $cipher),
                            location: new Location(
                                $this->getRelativePath($appConfig),
                                $lineNumber + 1
                            ),
                            severity: Severity::High,
                            recommendation: 'Use "AES-256-CBC" or "AES-128-CBC" cipher',
                            code: FileParser::getCodeSnippet($appConfig, $lineNumber + 1),
                            metadata: [
                                'file' => 'app.php',
                                'config_key' => 'cipher',
                                'cipher' => $cipher,
                            ]
                        );
                    }
                }
            }
        }
    }

    /**
     * Normalize key value by removing quotes and whitespace.
     */
    private function normalizeKeyValue(string $value): string
    {
        return trim($value, '"\'  ');
    }

    /**
     * Check if value is a placeholder/example value.
     */
    private function isPlaceholderValue(string $value): bool
    {
        $normalized = $this->normalizeKeyValue($value);
        $lower = strtolower($normalized);

        // Empty or null
        if ($lower === '' || $lower === 'null') {
            return true;
        }

        // Common placeholder patterns
        $patterns = [
            '/^base64:\s*$/',                    // base64: with nothing after
            '/your[-_]?key[-_]?here/i',          // your-key-here variants
            '/change[-_]?me/i',                  // change-me variants
            '/replace[-_]?this/i',               // replace-this variants
            '/example[-_]?key/i',                // example-key variants
            '/test[-_]?key/i',                   // test-key variants
            '/secret[-_]?key[-_]?here/i',        // secret-key-here variants
            '/random[-_]?string/i',              // random-string variants
            '/^(xxx+|yyy+|zzz+|aaa+)$/i',       // repeated chars
            '/placeholder/i',                    // contains "placeholder"
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $normalized)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validate APP_KEY format and strength.
     */
    private function isValidAppKey(string $value): bool
    {
        $normalized = $this->normalizeKeyValue($value);

        // Check for base64: prefix
        if (str_starts_with($normalized, 'base64:')) {
            return $this->validateBase64Key($normalized);
        }

        // Keys without base64: prefix should be at least 32 characters
        return strlen($normalized) >= 32;
    }

    /**
     * Validate base64-encoded APP_KEY.
     */
    private function validateBase64Key(string $value): bool
    {
        // Extract encoded portion after 'base64:' prefix
        $encoded = substr($value, 7);

        // Check if empty
        if ($encoded === '') {
            return false;
        }

        // Validate base64 format (alphanumeric + / + = for padding)
        if (! preg_match('/^[A-Za-z0-9+\/]+=*$/', $encoded)) {
            return false;
        }

        // Validate base64 padding
        if (! $this->isValidBase64Padding($encoded)) {
            return false;
        }

        // Check minimum encoded length
        // AES-128 requires 16 bytes (24 base64 chars)
        // AES-256 requires 32 bytes (44 base64 chars)
        if (strlen($encoded) < 24) {
            return false;
        }

        // Verify it decodes properly
        $decoded = base64_decode($encoded, true);
        if ($decoded === false) {
            return false;
        }

        // Check decoded length (minimum 16 bytes for AES-128)
        if (strlen($decoded) < 16) {
            return false;
        }

        return true;
    }

    /**
     * Validate base64 padding is correct.
     */
    private function isValidBase64Padding(string $encoded): bool
    {
        // Count padding characters
        $paddingCount = substr_count($encoded, '=');

        // Max 2 padding chars for base64
        if ($paddingCount > 2) {
            return false;
        }

        // Padding must be at the end
        if ($paddingCount > 0) {
            $paddingStart = strlen($encoded) - $paddingCount;
            if (substr($encoded, $paddingStart) !== str_repeat('=', $paddingCount)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check for cached config files.
     *
     * @param  array<int, mixed>  &$issues
     */
    private function checkCachedConfig(array &$issues): void
    {
        $cachedConfigPath = $this->buildPath('bootstrap', 'cache', 'config.php');

        if (file_exists($cachedConfigPath)) {
            $issues[] = $this->createIssue(
                message: 'Configuration is cached - .env changes will not take effect',
                location: new Location(
                    'bootstrap/cache/config.php',
                    1
                ),
                severity: Severity::High,
                recommendation: 'Run "php artisan config:clear" to clear the configuration cache and make .env changes effective. After making changes, run "php artisan config:cache" to rebuild the cache.',
                metadata: ['cached_file' => $cachedConfigPath]
            );
        }
    }
}
