<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\Support\PlatformDetector;
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

    /**
     * Override the php.ini path (testing only).
     */
    public function setPhpIniPath(string $phpIniPath): void
    {
        $this->phpIniPathOverride = $phpIniPath;
        $this->phpIniLinesCache = [];
    }

    /**
     * Override the conf.d drop-in files to scan (testing only).
     *
     * @param  array<int, string>  $paths
     */
    public function setScannedIniFiles(array $paths): void
    {
        $this->scannedIniFilesOverride = $paths;
        $this->phpIniLinesCache = [];
    }

    /**
     * Override deployment platform detection (testing only).
     */
    public function setDeploymentPlatform(string $platform): void
    {
        $this->deploymentPlatformOverride = $platform;
    }

    /** @var array<string, mixed>|null */
    private ?array $configurationOverride = null;

    private ?bool $extensionLoadedOverride = null;

    private ?string $phpIniPathOverride = null;

    private ?string $deploymentPlatformOverride = null;

    /** @var array<int, string>|null */
    private ?array $scannedIniFilesOverride = null;

    /** @var array<string, array<int, string>> */
    private array $phpIniLinesCache = [];

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $phpIniPath = $this->getPhpIniPath();

        // Check if OPcache extension is loaded
        if (! $this->isOpcacheLoaded()) {
            $issues[] = $this->createIssue(
                message: 'OPcache extension is not loaded',
                location: new Location($phpIniPath),
                severity: Severity::Critical,
                recommendation: 'Install and enable the OPcache extension in your PHP installation / php.ini (zend_extension/opcache depending on distribution).',
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
                location: new Location($phpIniPath),
                severity: Severity::Medium,
                recommendation: 'OPcache is loaded but configuration cannot be retrieved. Verify OPcache is properly configured in php.ini.',
                metadata: ['php_version' => PHP_VERSION]
            );

            return $this->resultBySeverity('Unable to retrieve OPcache configuration', $issues);
        }

        // Check if OPcache is enabled
        if (! isset($opcacheConfig['directives']['opcache.enable']) || ! $this->isIniEnabled($opcacheConfig['directives']['opcache.enable'])) {
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
        if (is_string($this->phpIniPathOverride) && $this->phpIniPathOverride !== '') {
            return $this->phpIniPathOverride;
        }

        $phpIniPath = php_ini_loaded_file();

        return $phpIniPath !== false ? $phpIniPath : 'php.ini';
    }

    private function isOpcacheLoaded(): bool
    {
        if ($this->extensionLoadedOverride !== null) {
            return $this->extensionLoadedOverride;
        }

        return extension_loaded('Zend OPcache') || extension_loaded('opcache');
    }

    /**
     * Check if the deployment platform is Laravel Cloud.
     */
    private function isLaravelCloud(): bool
    {
        if ($this->deploymentPlatformOverride !== null) {
            return $this->deploymentPlatformOverride === 'laravel-cloud';
        }

        return PlatformDetector::isLaravelCloud();
    }

    /**
     * Check if running inside a Docker container.
     */
    private function isDocker(): bool
    {
        if ($this->deploymentPlatformOverride !== null) {
            return $this->deploymentPlatformOverride === 'docker';
        }

        return PlatformDetector::isDocker();
    }

    /**
     * Check if the deployment platform is Laravel Vapor or another serverless environment.
     */
    private function isVaporOrServerless(): bool
    {
        if ($this->deploymentPlatformOverride !== null) {
            return in_array($this->deploymentPlatformOverride, ['vapor', 'serverless'], true);
        }

        return PlatformDetector::isLaravelVapor($this->getBasePath())
            || PlatformDetector::isServerless();
    }

    /**
     * Build a Vapor-specific recommendation that replaces the original.
     *
     * Uses relative path and Vapor-appropriate guidance (redeploy, not restart).
     */
    private function buildVaporRecommendation(string $setting, string $recommendation): string
    {
        // Extract the setting value from the original recommendation (e.g., "opcache.validate_timestamps=0")
        if (preg_match('/["\']('.preg_quote($setting, '/').'[^"\']*)["\']/', $recommendation, $matches) === 1) {
            $settingDirective = $matches[1];
        } else {
            $settingDirective = $setting;
        }

        return sprintf(
            'Set "%s" in your project\'s php/conf.d/php.ini (system php.ini is read-only on Laravel Vapor). Redeploy after changes.',
            $settingDirective
        );
    }

    /**
     * Check OPcache configuration for optimization opportunities.
     *
     * @param  array<string, mixed>  $config
     * @param  array<Issue>  $issues
     */
    private function checkOpcacheConfiguration(array $config, array &$issues, string $phpIniPath): void
    {
        if (! isset($config['directives']) || ! is_array($config['directives'])) {
            return; // Can't check configuration without directives
        }

        /** @var array<string, mixed> $directives */
        $directives = $config['directives'];

        $isCloud = $this->isLaravelCloud();
        $isCloudOrDocker = $isCloud || $this->isDocker();

        // PHP_INI_SYSTEM — base image controls these on Cloud and Docker; cannot be changed by the app
        if (! $isCloudOrDocker) {
            // Check opcache.memory_consumption (recommended: 128MB+)
            $this->checkMemoryConsumption($directives, $issues, $phpIniPath);

            // Check opcache.interned_strings_buffer (recommended: 16MB+)
            $this->checkInternedStringsBuffer($directives, $issues, $phpIniPath);

            // Check opcache.max_accelerated_files (recommended: 10000+)
            $this->checkMaxAcceleratedFiles($directives, $issues, $phpIniPath);
        }

        // PHP_INI_ALL — actionable on Docker (user controls container build) and traditional servers,
        // but no documented fix path on Laravel Cloud (only memory_limit is documented as configurable)
        if (! $isCloud) {
            // Check opcache.validate_timestamps (should be 0 in production)
            $this->checkValidateTimestamps($directives, $issues, $phpIniPath);

            // Check opcache.revalidate_freq (should be 0 in production when validate_timestamps=0)
            $this->checkRevalidateFreq($directives, $issues, $phpIniPath);
        }
    }

    /**
     * Check opcache.validate_timestamps setting.
     *
     * @param  array<string, mixed>  $directives
     * @param  array<Issue>  $issues
     */
    private function checkValidateTimestamps(array $directives, array &$issues, string $phpIniPath): void
    {
        if (! isset($directives['opcache.validate_timestamps']) || ! $this->isIniEnabled($directives['opcache.validate_timestamps'])) {
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
     * @param  array<Issue>  $issues
     */
    private function checkMemoryConsumption(array $directives, array &$issues, string $phpIniPath): void
    {
        if (! isset($directives['opcache.memory_consumption']) || ! is_numeric($directives['opcache.memory_consumption'])) {
            return;
        }

        // opcache_get_configuration() reports memory_consumption in bytes
        // (e.g. 134217728 for 128MB), unlike interned_strings_buffer which is
        // reported in MB. Convert to MB before comparing against the thresholds.
        $memoryConsumption = (int) round(((int) $directives['opcache.memory_consumption']) / 1048576);

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
     * @param  array<Issue>  $issues
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
     * @param  array<Issue>  $issues
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
     * @param  array<Issue>  $issues
     */
    private function checkRevalidateFreq(array $directives, array &$issues, string $phpIniPath): void
    {
        if (! isset($directives['opcache.revalidate_freq']) || ! is_numeric($directives['opcache.revalidate_freq'])) {
            return;
        }

        $revalidateFreq = (int) $directives['opcache.revalidate_freq'];

        if ($revalidateFreq > 0 && isset($directives['opcache.validate_timestamps']) && ! $this->isIniEnabled($directives['opcache.validate_timestamps'])) {
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
     * Create an issue for an OPcache setting with automatic location and code snippet.
     *
     * @param  array<string, mixed>  $metadata
     */
    private function createOpcacheIssue(
        string $phpIniPath,
        string $setting,
        string $message,
        Severity $severity,
        string $recommendation,
        array $metadata = []
    ): Issue {
        // Point at the file/line where the directive is actively set (the loaded
        // php.ini or a conf.d drop-in). When it isn't set anywhere we can see,
        // fall back to the loaded php.ini with no line — the runtime value is a
        // PHP default, so there's no line to highlight.
        $location = $this->findSettingLocation($setting);
        $filePath = $location['file'] ?? $phpIniPath;
        $line = $location['line'] ?? null;

        if ($this->isVaporOrServerless()) {
            $recommendation = $this->buildVaporRecommendation($setting, $recommendation);
            $metadata['deployment_platform'] = $this->deploymentPlatformOverride ?? 'vapor';
        }

        // Try to get code snippet, but handle open_basedir restrictions gracefully
        return $this->createIssueWithSnippet(
            message: $message,
            filePath: $filePath,
            lineNumber: $line,
            severity: $severity,
            recommendation: $recommendation,
            metadata: array_merge($metadata, ['code' => 'opcache-setting'])
        );
    }

    /**
     * Find the file and line where a setting is actively defined.
     *
     * Searches the loaded php.ini followed by any conf.d drop-ins, returning the
     * first active (uncommented) match. Returns null when the directive isn't
     * explicitly set anywhere we scan — its runtime value is then a PHP default.
     *
     * @return array{file: string, line: int}|null
     */
    private function findSettingLocation(string $setting): ?array
    {
        foreach ($this->getIniFilesToScan() as $file) {
            $line = $this->getSettingLine($file, $setting);

            if ($line !== null) {
                return ['file' => $file, 'line' => $line];
            }
        }

        return null;
    }

    /**
     * Get the ini files that may define directives, in precedence order: the
     * loaded php.ini followed by any conf.d drop-ins (the "Additional .ini files
     * parsed" list). On the common Debian/Ubuntu layout OPcache is loaded and
     * tuned from a drop-in (e.g. conf.d/10-opcache.ini), not the main php.ini.
     *
     * @return array<int, string>
     */
    private function getIniFilesToScan(): array
    {
        $files = [$this->getPhpIniPath()];

        // Explicit override (testing): scan exactly what was provided.
        if ($this->scannedIniFilesOverride !== null) {
            return array_merge($files, $this->scannedIniFilesOverride);
        }

        // When the php.ini path is overridden (testing) without drop-ins, don't
        // reach into the real system's scanned directory.
        if ($this->phpIniPathOverride !== null) {
            return $files;
        }

        $scanned = php_ini_scanned_files();

        if (is_string($scanned) && $scanned !== '') {
            foreach (explode(',', $scanned) as $scannedFile) {
                $scannedFile = trim($scannedFile);

                if ($scannedFile !== '') {
                    $files[] = $scannedFile;
                }
            }
        }

        return $files;
    }

    /**
     * Get the line number where a setting is actively defined in php.ini.
     *
     * Returns null when the setting has no active (uncommented) line. The
     * runtime value still comes from opcache_get_configuration(), so a missing
     * line just means the directive isn't explicitly set in this file (it may
     * be a PHP default or set in a conf.d drop-in). Returning null avoids
     * pinning the issue to an unrelated line (e.g. a comment), which previously
     * made commented directives look active.
     */
    private function getSettingLine(string $phpIniPath, string $setting): ?int
    {
        $lines = $this->getPhpIniLines($phpIniPath);

        foreach ($lines as $index => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Only match active (uncommented) settings — skip commented lines
            $lineWithoutComments = preg_replace('/[;#].*$/', '', $line);
            $lineWithoutComments = preg_replace('/\/\/.*$/', '', $lineWithoutComments ?? '');

            $pattern = '/^\s*'.preg_quote($setting, '/').'\s*=/i';
            if (preg_match($pattern, $lineWithoutComments ?? '') === 1) {
                return $index + 1;
            }
        }

        return null;
    }

    /**
     * Get the lines of the php.ini file with caching.
     *
     * @return array<int, string>
     */
    private function getPhpIniLines(string $phpIniPath): array
    {
        if (! array_key_exists($phpIniPath, $this->phpIniLinesCache)) {
            // Try to read the file, but handle open_basedir restrictions gracefully
            try {
                $this->phpIniLinesCache[$phpIniPath] = FileParser::getLines($phpIniPath);
            } catch (\Throwable $e) {
                // If we can't read the file (e.g., due to open_basedir restrictions), cache empty
                $this->phpIniLinesCache[$phpIniPath] = [];
            }
        }

        return $this->phpIniLinesCache[$phpIniPath];
    }

    /**
     * Check if an INI-style value represents "enabled".
     *
     * Handles: true, 1, "1", "on", "yes", "true" (case-insensitive)
     * Returns false for: false, 0, "0", "off", "no", "false", "" (case-insensitive)
     */
    private function isIniEnabled(mixed $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) === true;
    }
}
