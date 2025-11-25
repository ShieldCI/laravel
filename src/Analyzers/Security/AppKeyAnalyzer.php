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
            name: 'Application Key Security Analyzer',
            description: 'Validates that the application encryption key is properly configured and secure',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['encryption', 'app-key', 'security', 'configuration'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/app-key-security',
            timeToFix: 5
        );
    }

    public function shouldRun(): bool
    {
        // Check if there are any .env files or config/app.php to analyze
        return file_exists($this->buildPath('.env')) ||
               file_exists($this->buildPath('.env.production')) ||
               file_exists($this->buildPath('.env.prod')) ||
               file_exists($this->buildPath('.env.example')) ||
               file_exists($this->buildPath('config/app.php'));
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

        // Check .env files for APP_KEY
        $envKeys = [];
        $this->checkEnvFiles($issues, $envKeys);

        // Check for inconsistent keys across env files
        $this->checkKeyConsistency($envKeys, $issues);

        // Check config/app.php
        $this->checkAppConfig($issues);

        $summary = empty($issues)
            ? 'Application encryption key is properly configured'
            : sprintf('Found %d application key security issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check .env files for APP_KEY configuration.
     *
     * @param  array<string, string>  &$envKeys  Map of file paths to their APP_KEY values
     */
    private function checkEnvFiles(array &$issues, array &$envKeys): void
    {
        $envFiles = [
            $this->buildPath('.env'),
            $this->buildPath('.env.example'),
            $this->buildPath('.env.production'),
            $this->buildPath('.env.prod'),
        ];

        foreach ($envFiles as $envFile) {
            if (! file_exists($envFile)) {
                continue;
            }

            $content = FileParser::readFile($envFile);
            if ($content === null) {
                continue;
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

                // Check for APP_KEY setting
                if (preg_match('/^APP_KEY\s*=\s*(.*)$/i', trim($line), $matches)) {
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

                    // Check if APP_KEY is empty or whitespace
                    if ($appKeyValue === '' || trim($appKeyValue, '"\'  ') === '') {
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
                                'placeholder_detected' => trim($appKeyValue, '"\'  '),
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
                                'provided_length' => strlen(trim($appKeyValue, '"\'  ')),
                                'minimum_length' => 32,
                            ]
                        );
                    }
                }
            }

            // Only flag missing APP_KEY in actual .env files, not examples
            if (! $hasAppKey && ! str_contains($envFile, '.example')) {
                $issues[] = $this->createIssue(
                    message: 'APP_KEY is not defined in environment file',
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

            // Track valid keys for cross-file consistency checking
            if ($hasAppKey && $appKeyValue !== null && ! str_contains($envFile, '.example')) {
                $normalizedKey = trim($appKeyValue, '"\'');
                if ($normalizedKey !== '' && ! $this->isPlaceholderValue($appKeyValue)) {
                    $envKeys[$envFile] = $normalizedKey;
                }
            }
        }
    }

    /**
     * Check config/app.php for key configuration.
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
            // The regex already excludes env() with negative lookahead
            if (preg_match('/["\']key["\']\s*=>\s*["\'](?!env\()/i', $line)) {
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
     * Check if value is a placeholder/example value.
     */
    private function isPlaceholderValue(string $value): bool
    {
        // Remove quotes and trim whitespace
        $normalized = trim($value, '"\'  ');
        $lower = strtolower($normalized);

        $placeholders = [
            'base64:your-key-here',
            'somerandomstring',
            'null',
            '',
        ];

        return in_array($lower, $placeholders, true);
    }

    /**
     * Validate APP_KEY format and strength.
     */
    private function isValidAppKey(string $value): bool
    {
        // Remove surrounding quotes if present
        $value = trim($value, '"\'');

        // Check for base64: prefix
        if (str_starts_with($value, 'base64:')) {
            return $this->validateBase64Key($value);
        }

        // Keys without base64: prefix should be at least 32 characters
        return strlen($value) >= 32;
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
     */
    private function checkCachedConfig(array &$issues): void
    {
        $cachedConfigPath = $this->buildPath('bootstrap/cache/config.php');

        if (file_exists($cachedConfigPath)) {
            $issues[] = $this->createIssue(
                message: 'Configuration is cached - .env changes will not take effect',
                location: new Location(
                    'bootstrap/cache/config.php',
                    1
                ),
                severity: Severity::High,
                recommendation: 'Run "php artisan config:clear" to clear the configuration cache and make .env changes effective. After making changes, run "php artisan config:cache" to rebuild the cache.',
                code: FileParser::getCodeSnippet($cachedConfigPath, 1),
                metadata: ['cached_file' => $cachedConfigPath]
            );
        }
    }

    /**
     * Check for inconsistent APP_KEY values across environment files.
     *
     * @param  array<string, string>  $envKeys  Map of file paths to their APP_KEY values
     */
    private function checkKeyConsistency(array $envKeys, array &$issues): void
    {
        if (count($envKeys) < 2) {
            return;
        }

        // Get the keys and their files
        $keys = array_values($envKeys);
        $files = array_keys($envKeys);

        // Check if all keys are identical
        $uniqueKeys = array_unique($keys);

        if (count($uniqueKeys) > 1) {
            // Build a list of files and their keys
            $keyList = [];
            foreach ($envKeys as $file => $key) {
                $shortKey = strlen($key) > 20 ? substr($key, 0, 20).'...' : $key;
                $keyList[] = basename($file).' has key: '.$shortKey;
            }

            $issues[] = $this->createIssue(
                message: 'Inconsistent APP_KEY values across environment files',
                location: new Location(
                    $this->getRelativePath($files[0]),
                    1
                ),
                severity: Severity::High,
                recommendation: 'Ensure all environment files use the same APP_KEY. Different keys will cause encryption/decryption issues when moving between environments. Keys found: '.implode('; ', $keyList),
                code: FileParser::getCodeSnippet($files[0], 1),
                metadata: [
                    'files_with_different_keys' => array_map('basename', $files),
                    'unique_key_count' => count($uniqueKeys),
                ]
            );
        }
    }
}
