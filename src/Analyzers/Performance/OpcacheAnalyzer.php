<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Checks if OPcache is enabled in PHP.
 *
 * Checks for:
 * - OPcache extension loaded
 * - OPcache enabled
 * - OPcache configuration recommendations
 *
 * Environment Relevance:
 * - Production/Staging: Critical for performance
 * - Local/Development: Not relevant (opcache adds complexity for local dev)
 * - Testing: Not relevant (PHPUnit doesn't need opcache)
 */
class OpcacheAnalyzer extends AbstractAnalyzer
{
    /**
     * OPcache configuration is not applicable in CI environments.
     */
    public static bool $runInCI = false;

    /**
     * Minimum memory consumption in MB (recommended: 128MB+).
     */
    private const MIN_MEMORY_CONSUMPTION = 128;

    /**
     * Recommended memory consumption in MB for Laravel apps.
     */
    private const RECOMMENDED_MEMORY_CONSUMPTION = 256;

    /**
     * Minimum interned strings buffer in MB (recommended: 16MB+).
     */
    private const MIN_INTERNED_STRINGS_BUFFER = 16;

    /**
     * Minimum max accelerated files (recommended: 10000+).
     */
    private const MIN_MAX_ACCELERATED_FILES = 10000;

    /**
     * Recommended max accelerated files for Laravel apps.
     */
    private const RECOMMENDED_MAX_ACCELERATED_FILES = 20000;

    /**
     * This analyzer is only relevant in production and staging environments.
     *
     * OPcache is a production optimization that caches compiled bytecode.
     * It's not needed in local development or testing environments.
     *
     * @var array<string>
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    /**
     * For testing, allow overriding relevant environments.
     *
     * @param  array<string>|null  $environments
     */
    public function setRelevantEnvironments(?array $environments): void
    {
        $this->relevantEnvironments = $environments;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'opcache-enabled',
            name: 'OPcache Enabled Analyzer',
            description: 'Ensures OPcache is enabled for PHP bytecode caching and performance',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['php', 'opcache', 'performance', 'optimization', 'bytecode'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/opcache-enabled',
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

    /**
     * For testing, allow overriding the opcache configuration.
     *
     * @param  array<string, mixed>|null  $configuration
     */
    public function setConfiguration(?array $configuration): void
    {
        $this->configurationOverride = $configuration;
    }

    /**
     * For testing, allow overriding the extension check.
     */
    public function setExtensionLoaded(bool $loaded): void
    {
        $this->extensionLoadedOverride = $loaded;
    }

    private ?array $configurationOverride = null;

    private ?bool $extensionLoadedOverride = null;

    private ?string $cachedPhpIniPath = null;

    /** @var array<int, string>|null */
    private ?array $phpIniLinesCache = null;

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $phpIniPath = $this->getPhpIniPath();

        // Check if OPcache extension is loaded
        if (! $this->isOpcacheLoaded()) {
            $issues[] = $this->createIssue(
                message: 'OPcache extension is not loaded',
                location: new Location($phpIniPath, 1),
                severity: Severity::Critical,
                recommendation: 'Install and enable the OPcache extension. OPcache can improve PHP performance by 30-70% by caching precompiled bytecode. Add "zend_extension=opcache.so" to your php.ini file and restart your web server.',
                metadata: [
                    'php_version' => PHP_VERSION,
                    'loaded_extensions' => get_loaded_extensions(),
                ]
            );

            return $this->failed('OPcache extension not loaded', $issues);
        }

        // Check if OPcache is enabled
        $opcacheConfig = $this->configurationOverride ?? (function_exists('opcache_get_configuration') ? opcache_get_configuration() : null);

        if ($opcacheConfig === false || ! is_array($opcacheConfig) || ! isset($opcacheConfig['directives']) || ! is_array($opcacheConfig['directives'])) {
            $issues[] = $this->createIssue(
                message: 'Unable to retrieve OPcache configuration',
                location: new Location($phpIniPath, 1),
                severity: Severity::Medium,
                recommendation: 'OPcache is loaded but configuration cannot be retrieved. Verify OPcache is properly configured in php.ini.',
                metadata: ['php_version' => PHP_VERSION]
            );

            return $this->resultBySeverity('Unable to retrieve OPcache configuration', $issues);
        }

        // Check if OPcache is enabled
        if (! isset($opcacheConfig['directives']['opcache.enable'])
            || $opcacheConfig['directives']['opcache.enable'] !== true
        ) {
            $issues[] = $this->createOpcacheIssue(
                phpIniPath: $phpIniPath,
                setting: 'opcache.enable',
                message: 'OPcache is disabled',
                severity: Severity::High,
                recommendation: 'Enable OPcache by setting "opcache.enable=1" in php.ini. OPcache provides significant performance improvements by caching compiled bytecode.',
                metadata: [
                    'php_version' => PHP_VERSION,
                    'opcache_enabled' => false,
                ]
            );

            return $this->resultBySeverity('OPcache is disabled', $issues);
        }

        // OPcache is enabled, check configuration recommendations
        $this->checkOpcacheConfiguration($opcacheConfig, $issues, $phpIniPath);

        if (count($issues) === 0) {
            return $this->passed('OPcache is enabled and properly configured');
        }

        return $this->resultBySeverity(
            sprintf('Found %d OPcache configuration issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Get the path to the loaded php.ini file.
     */
    private function getPhpIniPath(): string
    {
        $phpIniPath = php_ini_loaded_file();

        return $phpIniPath !== false && is_string($phpIniPath) ? $phpIniPath : 'php.ini';
    }

    private function isOpcacheLoaded(): bool
    {
        if ($this->extensionLoadedOverride !== null) {
            return $this->extensionLoadedOverride;
        }

        return extension_loaded('Zend OPcache') || extension_loaded('opcache');
    }

    /**
     * Check OPcache configuration for optimization opportunities.
     *
     * @param  array<string, mixed>  $config
     * @param  array<\ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function checkOpcacheConfiguration(array $config, array &$issues, string $phpIniPath): void
    {
        if (! isset($config['directives']) || ! is_array($config['directives'])) {
            return; // Can't check configuration without directives
        }

        $directives = $config['directives'];

        // Check opcache.validate_timestamps (should be 0 in production)
        $this->checkValidateTimestamps($directives, $issues, $phpIniPath);

        // Check opcache.memory_consumption (recommended: 128MB+)
        $this->checkMemoryConsumption($directives, $issues, $phpIniPath);

        // Check opcache.interned_strings_buffer (recommended: 16MB+)
        $this->checkInternedStringsBuffer($directives, $issues, $phpIniPath);

        // Check opcache.max_accelerated_files (recommended: 10000+)
        $this->checkMaxAcceleratedFiles($directives, $issues, $phpIniPath);

        // Check opcache.revalidate_freq (should be 0 in production when validate_timestamps=0)
        $this->checkRevalidateFreq($directives, $issues, $phpIniPath);

        // Check opcache.fast_shutdown (should be 1 for better performance)
        $this->checkFastShutdown($directives, $issues, $phpIniPath);
    }

    /**
     * Check opcache.validate_timestamps setting.
     *
     * @param  array<string, mixed>  $directives
     * @param  array<\ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function checkValidateTimestamps(array $directives, array &$issues, string $phpIniPath): void
    {
        if (! isset($directives['opcache.validate_timestamps']) || $directives['opcache.validate_timestamps'] !== true) {
            return;
        }

        $currentValue = $directives['opcache.validate_timestamps'];
        $issues[] = $this->createOpcacheIssue(
            phpIniPath: $phpIniPath,
            setting: 'opcache.validate_timestamps',
            message: 'opcache.validate_timestamps is enabled in production',
            severity: Severity::Low,
            recommendation: 'Set "opcache.validate_timestamps=0" in production for maximum performance. This disables checking for file changes on every request. You\'ll need to restart PHP after code changes.',
            metadata: [
                'current_value' => $currentValue,
                'recommended_value' => 0,
            ]
        );
    }

    /**
     * Check opcache.memory_consumption setting.
     *
     * @param  array<string, mixed>  $directives
     * @param  array<\ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function checkMemoryConsumption(array $directives, array &$issues, string $phpIniPath): void
    {
        if (! isset($directives['opcache.memory_consumption']) || ! is_numeric($directives['opcache.memory_consumption'])) {
            return;
        }

        $memoryConsumption = (int) $directives['opcache.memory_consumption'];

        if ($memoryConsumption >= 0 && $memoryConsumption < self::MIN_MEMORY_CONSUMPTION) {
            $issues[] = $this->createOpcacheIssue(
                phpIniPath: $phpIniPath,
                setting: 'opcache.memory_consumption',
                message: 'OPcache memory consumption is low',
                severity: Severity::Low,
                recommendation: sprintf(
                    'Increase "opcache.memory_consumption" to at least %dMB (recommended: %dMB for Laravel apps). Current: %dMB. This ensures all your application code can be cached.',
                    self::MIN_MEMORY_CONSUMPTION,
                    self::RECOMMENDED_MEMORY_CONSUMPTION,
                    $memoryConsumption
                ),
                metadata: [
                    'current_value' => $memoryConsumption,
                    'recommended_value' => self::RECOMMENDED_MEMORY_CONSUMPTION,
                ]
            );
        }
    }

    /**
     * Check opcache.interned_strings_buffer setting.
     *
     * @param  array<string, mixed>  $directives
     * @param  array<\ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function checkInternedStringsBuffer(array $directives, array &$issues, string $phpIniPath): void
    {
        if (! isset($directives['opcache.interned_strings_buffer']) || ! is_numeric($directives['opcache.interned_strings_buffer'])) {
            return;
        }

        $internedStringsBuffer = (int) $directives['opcache.interned_strings_buffer'];

        if ($internedStringsBuffer >= 0 && $internedStringsBuffer < self::MIN_INTERNED_STRINGS_BUFFER) {
            $issues[] = $this->createOpcacheIssue(
                phpIniPath: $phpIniPath,
                setting: 'opcache.interned_strings_buffer',
                message: 'OPcache interned strings buffer is low',
                severity: Severity::Low,
                recommendation: sprintf(
                    'Increase "opcache.interned_strings_buffer" to at least %dMB. Current: %dMB. This caches common strings and improves memory efficiency.',
                    self::MIN_INTERNED_STRINGS_BUFFER,
                    $internedStringsBuffer
                ),
                metadata: [
                    'current_value' => $internedStringsBuffer,
                    'recommended_value' => self::MIN_INTERNED_STRINGS_BUFFER,
                ]
            );
        }
    }

    /**
     * Check opcache.max_accelerated_files setting.
     *
     * @param  array<string, mixed>  $directives
     * @param  array<\ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function checkMaxAcceleratedFiles(array $directives, array &$issues, string $phpIniPath): void
    {
        if (! isset($directives['opcache.max_accelerated_files']) || ! is_numeric($directives['opcache.max_accelerated_files'])) {
            return;
        }

        $maxAcceleratedFiles = (int) $directives['opcache.max_accelerated_files'];

        if ($maxAcceleratedFiles >= 0 && $maxAcceleratedFiles < self::MIN_MAX_ACCELERATED_FILES) {
            $issues[] = $this->createOpcacheIssue(
                phpIniPath: $phpIniPath,
                setting: 'opcache.max_accelerated_files',
                message: 'OPcache max accelerated files is low',
                severity: Severity::Low,
                recommendation: sprintf(
                    'Increase "opcache.max_accelerated_files" to at least %d (recommended: %d for Laravel apps). Current: %d. This ensures all your application files can be cached.',
                    self::MIN_MAX_ACCELERATED_FILES,
                    self::RECOMMENDED_MAX_ACCELERATED_FILES,
                    $maxAcceleratedFiles
                ),
                metadata: [
                    'current_value' => $maxAcceleratedFiles,
                    'recommended_value' => self::RECOMMENDED_MAX_ACCELERATED_FILES,
                ]
            );
        }
    }

    /**
     * Check opcache.revalidate_freq setting.
     *
     * @param  array<string, mixed>  $directives
     * @param  array<\ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function checkRevalidateFreq(array $directives, array &$issues, string $phpIniPath): void
    {
        if (! isset($directives['opcache.revalidate_freq']) || ! is_numeric($directives['opcache.revalidate_freq'])) {
            return;
        }

        $revalidateFreq = (int) $directives['opcache.revalidate_freq'];

        if ($revalidateFreq > 0
            && isset($directives['opcache.validate_timestamps'])
            && $directives['opcache.validate_timestamps'] === false
        ) {
            $issues[] = $this->createOpcacheIssue(
                phpIniPath: $phpIniPath,
                setting: 'opcache.revalidate_freq',
                message: 'opcache.revalidate_freq should be 0 when validate_timestamps is disabled',
                severity: Severity::Low,
                recommendation: sprintf(
                    'Set "opcache.revalidate_freq=0" when "opcache.validate_timestamps=0" for maximum performance. Current: %d seconds.',
                    $revalidateFreq
                ),
                metadata: [
                    'current_value' => $revalidateFreq,
                    'recommended_value' => 0,
                ]
            );
        }
    }

    /**
     * Check opcache.fast_shutdown setting.
     *
     * @param  array<string, mixed>  $directives
     * @param  array<\ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function checkFastShutdown(array $directives, array &$issues, string $phpIniPath): void
    {
        if (! isset($directives['opcache.fast_shutdown']) || $directives['opcache.fast_shutdown'] === true) {
            return;
        }

        $currentValue = $directives['opcache.fast_shutdown'];
        // At this point, we know:
        // - isset() returned true, so value is NOT null
        // - value !== true (filtered by early return)
        // Therefore: $currentValue can be false, int, float, string, array, object, or resource
        if (is_bool($currentValue)) {
            $currentValueString = '0'; // Must be false since true was filtered out
        } elseif (is_scalar($currentValue)) {
            // Handles int, float, string (bool already handled above)
            $currentValueString = (string) $currentValue;
        } else {
            // Handle arrays, objects, resources, etc.
            $currentValueString = 'invalid value';
        }

        $issues[] = $this->createOpcacheIssue(
            phpIniPath: $phpIniPath,
            setting: 'opcache.fast_shutdown',
            message: 'opcache.fast_shutdown is disabled',
            severity: Severity::Low,
            recommendation: sprintf(
                'Enable "opcache.fast_shutdown=1" for faster PHP shutdown and better performance. Current: %s.',
                $currentValueString
            ),
            metadata: [
                'current_value' => $currentValue,
                'recommended_value' => 1,
            ]
        );
    }

    /**
     * Create an issue for an OPcache setting with automatic location and code snippet.
     *
     * @param  array<string, mixed>  $metadata
     */
    private function createOpcacheIssue(
        string $phpIniPath,
        string $setting,
        string $message,
        string $recommendation,
        Severity $severity,
        array $metadata = []
    ): Issue {
        $line = $this->getSettingLine($phpIniPath, $setting);

        // Try to get code snippet, but handle open_basedir restrictions gracefully
        return $this->createIssueWithSnippet(
            message: $message,
            filePath: $phpIniPath,
            lineNumber: $line,
            severity: $severity,
            recommendation: $recommendation,
            code: 'opcache-setting',
            metadata: $metadata
        );
    }

    /**
     * Get the line number where a setting is defined in php.ini.
     */
    private function getSettingLine(string $phpIniPath, string $setting): int
    {
        $lines = $this->getPhpIniLines($phpIniPath);
        $commentedLine = null;

        foreach ($lines as $index => $line) {
            if (! is_string($line)) {
                continue;
            }

            // First, check for active (uncommented) settings
            $lineWithoutComments = preg_replace('/[;#].*$/', '', $line);
            $lineWithoutComments = preg_replace('/\/\/.*$/', '', $lineWithoutComments ?? '');

            $pattern = '/^\s*'.preg_quote($setting, '/').'\s*=/i';
            if (preg_match($pattern, $lineWithoutComments ?? '') === 1) {
                return $index + 1;
            }

            // Also check for commented settings (as fallback)
            if ($commentedLine === null) {
                $commentedPattern = '/^\s*[;#]\s*'.preg_quote($setting, '/').'\s*=/i';
                if (preg_match($commentedPattern, $line) === 1) {
                    $commentedLine = $index + 1;
                }
            }
        }

        // Return commented line if found, otherwise default to 1
        return $commentedLine ?? 1;
    }

    /**
     * Get the lines of the php.ini file with caching.
     *
     * @return array<int, string>
     */
    private function getPhpIniLines(string $phpIniPath): array
    {
        if ($this->cachedPhpIniPath !== $phpIniPath) {
            $this->phpIniLinesCache = null;
            $this->cachedPhpIniPath = $phpIniPath;
        }

        if ($this->phpIniLinesCache === null) {
            // Try to read the file, but handle open_basedir restrictions gracefully
            try {
                $this->phpIniLinesCache = FileParser::getLines($phpIniPath);
            } catch (\Throwable $e) {
                // If we can't read the file (e.g., due to open_basedir restrictions), return empty array
                $this->phpIniLinesCache = [];
            }
        }

        return $this->phpIniLinesCache ?? [];
    }
}
