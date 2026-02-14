<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Validates PHP configuration (php.ini) security settings.
 *
 * Checks for:
 * - allow_url_fopen disabled
 * - allow_url_include disabled
 * - expose_php disabled
 * - display_errors disabled in production
 * - display_startup_errors disabled in production
 * - log_errors enabled
 * - ignore_repeated_errors disabled
 *
 * Note: error_reporting is intentionally NOT checked because Laravel
 * sets error_reporting(-1) by design and controls visibility via display_errors.
 */
class PHPIniAnalyzer extends AbstractFileAnalyzer
{
    /**
     * PHP ini settings checks are environment-specific and not applicable in CI.
     */
    public static bool $runInCI = false;

    /**
     * This analyzer is only relevant in production and staging environments.
     *
     * In local/development, developers may have different PHP ini settings
     * for debugging purposes, which is acceptable.
     *
     * @var array<string>
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    /**
     * Default secure values for php.ini directives.
     *
     * @var array<string, bool>
     */
    private array $defaultSecureSettings = [
        'allow_url_fopen' => false,
        'allow_url_include' => false,
        'expose_php' => false,
        'display_errors' => false,
        'display_startup_errors' => false,
        'log_errors' => true,
        'ignore_repeated_errors' => false,
    ];

    /**
     * @var array<string, string|int|bool>|null
     */
    private ?array $iniValueOverrides = null;

    private ?string $phpIniPathOverride = null;

    /**
     * Cache for multiple ini file contents.
     * Key: file path, Value: array of lines.
     *
     * @var array<string, array<int, string>>
     */
    private array $phpIniLinesCache = [];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'php-ini',
            name: 'PHP Configuration Analyzer',
            description: 'Validates that PHP ini settings are configured securely',
            category: Category::Security,
            severity: Severity::High,
            tags: ['php', 'configuration', 'ini', 'security', 'server'],
            timeToFix: 15
        );
    }

    public function shouldRun(): bool
    {
        return $this->isRelevantForCurrentEnvironment();
    }

    public function getSkipReason(): string
    {
        if (! $this->isRelevantForCurrentEnvironment()) {
            $currentEnv = $this->getEnvironment();
            $relevantEnvs = implode(', ', $this->relevantEnvironments ?? []);

            return "Not relevant in '{$currentEnv}' environment (only relevant in: {$relevantEnvs})";
        }

        return 'Analyzer is not applicable in current context';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $phpIniPath = $this->getPhpIniPath();
        $configuration = $this->getConfiguration();

        // Check PHP ini settings
        $this->checkPhpIniSettings($issues, $phpIniPath, $configuration['secure_settings']);

        if (empty($issues)) {
            return $this->passed('PHP configuration is secure');
        }

        return $this->resultBySeverity(
            sprintf('Found %d PHP configuration issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Check PHP ini settings.
     *
     * @param  array<int, Issue>  $issues
     * @param  array<string, bool>  $secureSettings
     */
    private function checkPhpIniSettings(array &$issues, string $phpIniPath, array $secureSettings): void
    {
        foreach ($secureSettings as $setting => $expectedValue) {
            $currentValue = $this->getIniValue($setting);

            // Handle non-existent settings (ini_get() returns false)
            if ($currentValue === false) {
                $issues[] = $this->createPhpIniIssueWithValue(
                    phpIniPath: $phpIniPath,
                    setting: $setting,
                    expectedValue: $expectedValue,
                    message: sprintf('PHP ini setting "%s" is not configured (setting does not exist)', $setting),
                    severity: $this->getSeverityForSetting($setting),
                    metadata: [
                        'setting' => $setting,
                        'current_value' => 'not_configured',
                        'expected_value' => $expectedValue ? 'enabled' : 'disabled',
                        'issue_type' => 'missing_setting',
                    ]
                );

                continue;
            }

            // Normalize values for comparison
            // IMPORTANT: Empty string is now treated separately - it's ambiguous
            $normalized = strtolower($currentValue);
            $isEnabled = in_array($normalized, ['1', 'on', 'yes', 'true'], true);
            // Removed '' from disabled check - empty is now treated as ambiguous
            $isDisabled = in_array($normalized, ['0', 'off', 'no', 'false'], true);
            $isAmbiguous = $normalized === '';

            $expected = $expectedValue ? 'enabled' : 'disabled';

            // Handle ambiguous empty values
            if ($isAmbiguous) {
                $issues[] = $this->createPhpIniIssueWithValue(
                    phpIniPath: $phpIniPath,
                    setting: $setting,
                    expectedValue: $expectedValue,
                    message: sprintf(
                        'PHP ini setting "%s" is set to empty string (ambiguous - could be misconfigured)',
                        $setting
                    ),
                    severity: $this->getSeverityForSetting($setting),
                    metadata: [
                        'setting' => $setting,
                        'current_value' => '',
                        'expected_value' => $expected,
                        'issue_type' => 'ambiguous_value',
                    ]
                );

                continue;
            }

            $actual = $isEnabled ? 'enabled' : ($isDisabled ? 'disabled' : $currentValue);

            // Check if current value matches expected
            if ($expectedValue && ! $isEnabled) {
                $issues[] = $this->createPhpIniIssueWithValue(
                    phpIniPath: $phpIniPath,
                    setting: $setting,
                    expectedValue: true,
                    message: sprintf('PHP ini setting "%s" should be enabled but is %s', $setting, $actual),
                    severity: $this->getSeverityForSetting($setting),
                    metadata: [
                        'setting' => $setting,
                        'current_value' => $currentValue,
                        'expected_value' => $expected,
                    ]
                );
            } elseif (! $expectedValue && $isEnabled) {
                $issues[] = $this->createPhpIniIssueWithValue(
                    phpIniPath: $phpIniPath,
                    setting: $setting,
                    expectedValue: false,
                    message: sprintf('PHP ini setting "%s" should be disabled but is %s', $setting, $actual),
                    severity: $this->getSeverityForSetting($setting),
                    metadata: [
                        'setting' => $setting,
                        'current_value' => $currentValue,
                        'expected_value' => $expected,
                    ]
                );
            }
        }
    }

    /**
     * Get severity level for specific PHP ini setting.
     */
    private function getSeverityForSetting(string $setting): Severity
    {
        // Critical: Settings that can directly lead to RCE or similar severe vulnerabilities
        $criticalSettings = ['allow_url_include'];

        // High: Settings that enable dangerous features or expose sensitive information
        $highSettings = ['allow_url_fopen', 'display_errors', 'display_startup_errors', 'expose_php'];

        if (in_array($setting, $criticalSettings)) {
            return Severity::Critical;
        }

        if (in_array($setting, $highSettings)) {
            return Severity::High;
        }

        // Medium: Settings that should be configured securely but aren't immediately exploitable
        return Severity::Medium;
    }

    /**
     * Provide overrides for ini values (testing only).
     *
     * @param  array<string, string|int|bool>  $values
     */
    public function setIniValues(array $values): void
    {
        $this->iniValueOverrides = $values;
    }

    public function setPhpIniPath(string $phpIniPath): void
    {
        $this->phpIniPathOverride = $phpIniPath;
        $this->phpIniLinesCache = [];
    }

    /**
     * @return array{
     *     ini_path: string|null,
     *     secure_settings: array<string, bool>
     * }
     */
    private function getConfiguration(): array
    {
        $defaults = [
            'ini_path' => null,
            'secure_settings' => $this->defaultSecureSettings,
        ];

        if (function_exists('config')) {
            $config = config('shieldci.analyzers.security.php-ini.php_configuration', []);
            if (is_array($config)) {
                /** @var array{ini_path?: string|null, secure_settings?: array<string, bool>} $config */
                $merged = array_replace_recursive($defaults, $config);

                return [
                    'ini_path' => $merged['ini_path'],
                    'secure_settings' => $merged['secure_settings'],
                ];
            }
        }

        return [
            'ini_path' => $defaults['ini_path'],
            'secure_settings' => $defaults['secure_settings'],
        ];
    }

    private function getPhpIniPath(): string
    {
        if (is_string($this->phpIniPathOverride) && $this->phpIniPathOverride !== '') {
            return $this->phpIniPathOverride;
        }

        $configPath = null;
        if (function_exists('config')) {
            $configPath = config('shieldci.analyzers.security.php-ini.ini_path');
        }

        if (is_string($configPath) && $configPath !== '') {
            return $configPath;
        }

        $phpIniPath = php_ini_loaded_file();

        return $phpIniPath !== false && is_string($phpIniPath) ? $phpIniPath : 'php.ini';
    }

    /**
     * Get INI value with special handling for non-existent settings.
     *
     * @return string|false Returns false if setting doesn't exist, string value otherwise
     */
    private function getIniValue(string $setting): string|false
    {
        if (is_array($this->iniValueOverrides) && array_key_exists($setting, $this->iniValueOverrides)) {
            $overrideValue = $this->iniValueOverrides[$setting];

            // IMPORTANT: Preserve false values from test overrides
            // This allows tests to simulate non-existent settings
            if ($overrideValue === false) {
                return false;
            }

            return $this->normalizeIniValue($overrideValue);
        }

        $value = ini_get($setting);

        // IMPORTANT: ini_get() returns false when setting doesn't exist
        // We preserve this to distinguish between "not configured" and "disabled"
        if ($value === false) {
            return false;
        }

        return $this->normalizeIniValue($value);
    }

    private function normalizeIniValue(mixed $value): string
    {
        if (is_string($value)) {
            return trim($value);
        }

        if (is_bool($value)) {
            return $value ? '1' : '0';
        }

        if (is_scalar($value)) {
            return trim((string) $value);
        }

        return '';
    }

    /**
     * Get all PHP configuration sources (main php.ini + additional ini files).
     *
     * @return array{main: string|null, additional: array<int, string>}
     */
    private function getConfigurationSources(): array
    {
        $sources = [
            'main' => null,
            'additional' => [],
        ];

        // Get main php.ini file (respecting override for testing)
        if (is_string($this->phpIniPathOverride) && $this->phpIniPathOverride !== '') {
            $sources['main'] = $this->phpIniPathOverride;
        } else {
            $mainIni = php_ini_loaded_file();
            if ($mainIni !== false && is_string($mainIni) && $mainIni !== '') {
                $sources['main'] = $mainIni;
            }
        }

        // Get additional .ini files from conf.d/ directories
        // Note: In test mode with override, we don't scan for additional files
        if (! is_string($this->phpIniPathOverride) || $this->phpIniPathOverride === '') {
            $scannedFiles = php_ini_scanned_files();
            if ($scannedFiles !== false && is_string($scannedFiles) && $scannedFiles !== '') {
                $files = array_filter(
                    array_map('trim', explode(',', $scannedFiles)),
                    fn ($file) => $file !== '' && is_string($file)
                );
                $sources['additional'] = $files;
            }
        }

        return $sources;
    }

    /**
     * Find the actual source file where a setting is defined.
     *
     * @return array{file: string, type: string, line: int}|null
     */
    private function findSettingSource(string $setting): ?array
    {
        $sources = $this->getConfigurationSources();

        // Check additional ini files first (they override main php.ini)
        // Process in reverse order because later files override earlier ones
        if (! empty($sources['additional'])) {
            foreach (array_reverse($sources['additional']) as $iniFile) {
                if ($this->settingExistsInFile($iniFile, $setting)) {
                    return [
                        'file' => $iniFile,
                        'type' => 'additional_ini',
                        'line' => $this->getSettingLine($iniFile, $setting),
                    ];
                }
            }
        }

        // Check main php.ini
        if ($sources['main'] !== null) {
            if ($this->settingExistsInFile($sources['main'], $setting)) {
                return [
                    'file' => $sources['main'],
                    'type' => 'main_ini',
                    'line' => $this->getSettingLine($sources['main'], $setting),
                ];
            }
        }

        // Setting not found in any file (might be PHP default or runtime override)
        return null;
    }

    /**
     * Find a setting in an ini file and return its line number.
     *
     * Returns array with 'found' (bool) and 'line' (int).
     * Searches for active (uncommented) settings first, then commented ones as fallback.
     *
     * @return array{found: bool, line: int, commented: bool}
     */
    private function findSettingInFile(string $file, string $setting): array
    {
        $lines = $this->getPhpIniLines($file);
        $commentedLine = null;

        foreach ($lines as $index => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Remove comments from the line
            $lineWithoutComments = preg_replace('/[;#].*$/', '', $line);
            $lineWithoutComments = preg_replace('/\/\/.*$/', '', $lineWithoutComments ?? '');

            // Check if setting is defined (not commented out)
            $pattern = '/^\s*'.preg_quote($setting, '/').'\s*=/i';
            if (preg_match($pattern, $lineWithoutComments ?? '') === 1) {
                return [
                    'found' => true,
                    'line' => $index + 1,
                    'commented' => false,
                ];
            }

            // Also check for commented settings (as fallback)
            if ($commentedLine === null) {
                $commentedPattern = '/^\s*[;#]\s*'.preg_quote($setting, '/').'\s*=/i';
                if (preg_match($commentedPattern, $line) === 1) {
                    $commentedLine = $index + 1;
                }
            }
        }

        // If we found a commented version, return that
        if ($commentedLine !== null) {
            return [
                'found' => false,
                'line' => $commentedLine,
                'commented' => true,
            ];
        }

        // Not found at all
        return [
            'found' => false,
            'line' => 1,
            'commented' => false,
        ];
    }

    /**
     * Check if a setting exists (uncommented) in a specific ini file.
     */
    private function settingExistsInFile(string $file, string $setting): bool
    {
        return $this->findSettingInFile($file, $setting)['found'];
    }

    /**
     * Create an issue for a PHP ini setting with expected value context.
     *
     * This is a convenience wrapper that generates appropriate recommendations
     * based on the expected value.
     *
     * @param  array<string, mixed>  $metadata
     */
    private function createPhpIniIssueWithValue(
        string $phpIniPath,
        string $setting,
        bool $expectedValue,
        string $message,
        Severity $severity,
        array $metadata = []
    ): Issue {
        $recommendedValue = $expectedValue ? 'On' : 'Off';
        $baseRecommendation = sprintf('Set %s = %s', $setting, $recommendedValue);

        return $this->createPhpIniIssue(
            phpIniPath: $phpIniPath,
            setting: $setting,
            message: $message,
            recommendation: $baseRecommendation,
            severity: $severity,
            metadata: $metadata,
            expectedValue: $recommendedValue
        );
    }

    /**
     * Create an issue for a PHP ini setting with automatic location and code snippet.
     *
     * Uses actual source detection to find where the setting is really defined,
     * rather than just pointing to the main php.ini file.
     *
     * @param  array<string, mixed>  $metadata
     */
    private function createPhpIniIssue(
        string $phpIniPath,
        string $setting,
        string $message,
        string $recommendation,
        Severity $severity,
        array $metadata = [],
        ?string $expectedValue = null
    ): Issue {
        // Try to find the actual source of this setting
        $source = $this->findSettingSource($setting);

        if ($source !== null) {
            // We found the actual file where the setting is defined
            $actualFile = $source['file'];
            $line = $source['line'];
            $sourceType = $source['type'] === 'additional_ini' ? 'additional configuration file' : 'main php.ini';

            // Update recommendation to point to the correct file
            if ($expectedValue !== null) {
                $recommendation = sprintf(
                    'Set %s = %s in %s (%s)',
                    $setting,
                    $expectedValue,
                    basename($actualFile),
                    $sourceType
                );
            } else {
                $recommendation = sprintf(
                    'Update %s in %s (%s)',
                    $setting,
                    basename($actualFile),
                    $sourceType
                );
            }
        } else {
            // Setting not found in any file - might be PHP default or runtime override
            $actualFile = $phpIniPath;
            $line = 1;
            $sources = $this->getConfigurationSources();

            // Build list of all loaded ini files
            $allFiles = array_filter([
                $sources['main'] ?? null,
                ...($sources['additional'] ?? []),
            ]);

            // Keep recommendation concise - details go in metadata
            $recommendation .= ' | WARNING: Setting not found in loaded .ini files. May be from PHP defaults, .user.ini, .htaccess, or web server config.';

            // Add detailed information to metadata for debugging
            $metadata['possible_sources'] = [
                'php_defaults' => 'PHP compiled-in default value',
                'user_ini' => '.user.ini files in directory hierarchy',
                'htaccess' => '.htaccess php_value/php_flag directives',
                'apache_config' => 'Apache VirtualHost or Directory php_value directives',
                'nginx_config' => 'Nginx fastcgi_param PHP_VALUE/PHP_ADMIN_VALUE',
            ];
            $metadata['checked_files'] = $allFiles;
        }

        // Add metadata about configuration sources for debugging
        $metadata['configuration_sources'] = $this->getConfigurationSources();
        $metadata['actual_source'] = $source;

        return $this->createIssue(
            message: $message,
            location: new Location($actualFile, $line),
            severity: $severity,
            recommendation: $recommendation,
            code: FileParser::getCodeSnippet($actualFile, $line),
            metadata: $metadata
        );
    }

    private function getSettingLine(string $phpIniPath, string $setting): int
    {
        return $this->findSettingInFile($phpIniPath, $setting)['line'];
    }

    /**
     * Get lines from a PHP ini file with per-file caching.
     *
     * Now supports multiple files (main php.ini + additional .ini files from conf.d/).
     * Each file is cached separately by its full path.
     *
     * @return array<int, string>
     */
    private function getPhpIniLines(string $phpIniPath): array
    {
        // Check if this specific file is already cached
        if (! isset($this->phpIniLinesCache[$phpIniPath])) {
            // Try to read the file, but handle open_basedir restrictions gracefully
            try {
                $this->phpIniLinesCache[$phpIniPath] = FileParser::getLines($phpIniPath);
            } catch (\Throwable $e) {
                // If we can't read the file (e.g., due to open_basedir restrictions), cache empty array
                $this->phpIniLinesCache[$phpIniPath] = [];
            }
        }

        return $this->phpIniLinesCache[$phpIniPath];
    }
}
