<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
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
     * This analyzer is only relevant in production and staging environments.
     *
     * OPcache is a production optimization that caches compiled bytecode.
     * It's not needed in local development or testing environments.
     *
     * @var array<string>
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'opcache-enabled',
            name: 'OPcache Enabled',
            description: 'Ensures OPcache is enabled for PHP bytecode caching and performance',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['php', 'opcache', 'performance', 'optimization', 'bytecode'],
            docsUrl: 'https://www.php.net/manual/en/opcache.installation.php'
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

        // Check if OPcache extension is loaded
        if (! extension_loaded('Zend OPcache')) {
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
        $opcacheConfig = function_exists('opcache_get_configuration') ? opcache_get_configuration() : null;

        if ($opcacheConfig === false || ! is_array($opcacheConfig) || ! isset($opcacheConfig['directives']) || ! is_array($opcacheConfig['directives'])) {
            $issues[] = $this->createIssue(
                message: 'Unable to retrieve OPcache configuration',
                location: new Location($phpIniPath, 1),
                severity: Severity::Medium,
                recommendation: 'OPcache is loaded but configuration cannot be retrieved. Verify OPcache is properly configured in php.ini.',
                metadata: ['php_version' => PHP_VERSION]
            );

            return $this->failed('Unable to retrieve OPcache configuration', $issues);
        }

        // Check if OPcache is enabled
        if (! isset($opcacheConfig['directives']['opcache.enable']) || ! $opcacheConfig['directives']['opcache.enable']) {
            $issues[] = $this->createIssue(
                message: 'OPcache is disabled',
                location: new Location($phpIniPath, 1),
                severity: Severity::High,
                recommendation: 'Enable OPcache by setting "opcache.enable=1" in php.ini. OPcache provides significant performance improvements by caching compiled bytecode.',
                metadata: [
                    'php_version' => PHP_VERSION,
                    'opcache_enabled' => false,
                ]
            );

            return $this->failed('OPcache is disabled', $issues);
        }

        // OPcache is enabled, check configuration recommendations
        $this->checkOpcacheConfiguration($opcacheConfig, $issues, $phpIniPath);

        if (empty($issues)) {
            return $this->passed('OPcache is enabled and properly configured');
        }

        return $this->failed(
            sprintf('Found %d OPcache configuration issues', count($issues)),
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
        if (isset($directives['opcache.validate_timestamps']) && $directives['opcache.validate_timestamps'] === true) {
            $currentValue = $directives['opcache.validate_timestamps'];
            $issues[] = $this->createIssue(
                message: 'opcache.validate_timestamps is enabled in production',
                location: new Location($phpIniPath, 1),
                severity: Severity::Low,
                recommendation: 'Set "opcache.validate_timestamps=0" in production for maximum performance. This disables checking for file changes on every request. You\'ll need to restart PHP after code changes.',
                metadata: [
                    'current_value' => $currentValue,
                    'recommended_value' => 0,
                ]
            );
        }

        // Check opcache.memory_consumption (recommended: 128MB+)
        if (isset($directives['opcache.memory_consumption']) && is_numeric($directives['opcache.memory_consumption'])) {
            $memoryConsumption = (int) $directives['opcache.memory_consumption'];
            if ($memoryConsumption < 128) {
                $issues[] = $this->createIssue(
                    message: 'OPcache memory consumption is low',
                    location: new Location($phpIniPath, 1),
                    severity: Severity::Low,
                    recommendation: 'Increase "opcache.memory_consumption" to at least 128MB (recommended: 256MB for Laravel apps). Current: '.$memoryConsumption.'MB. This ensures all your application code can be cached.',
                    metadata: [
                        'current_value' => $memoryConsumption,
                        'recommended_value' => 256,
                    ]
                );
            }
        }

        // Check opcache.interned_strings_buffer (recommended: 16MB+)
        if (isset($directives['opcache.interned_strings_buffer']) && is_numeric($directives['opcache.interned_strings_buffer'])) {
            $internedStringsBuffer = (int) $directives['opcache.interned_strings_buffer'];
            if ($internedStringsBuffer < 16) {
                $issues[] = $this->createIssue(
                    message: 'OPcache interned strings buffer is low',
                    location: new Location($phpIniPath, 1),
                    severity: Severity::Low,
                    recommendation: 'Increase "opcache.interned_strings_buffer" to at least 16MB. Current: '.$internedStringsBuffer.'MB. This caches common strings and improves memory efficiency.',
                    metadata: [
                        'current_value' => $internedStringsBuffer,
                        'recommended_value' => 16,
                    ]
                );
            }
        }

        // Check opcache.max_accelerated_files (recommended: 10000+)
        if (isset($directives['opcache.max_accelerated_files']) && is_numeric($directives['opcache.max_accelerated_files'])) {
            $maxAcceleratedFiles = (int) $directives['opcache.max_accelerated_files'];
            if ($maxAcceleratedFiles < 10000) {
                $issues[] = $this->createIssue(
                    message: 'OPcache max accelerated files is low',
                    location: new Location($phpIniPath, 1),
                    severity: Severity::Low,
                    recommendation: 'Increase "opcache.max_accelerated_files" to at least 10000 (recommended: 20000 for Laravel apps). Current: '.$maxAcceleratedFiles.'. This ensures all your application files can be cached.',
                    metadata: [
                        'current_value' => $maxAcceleratedFiles,
                        'recommended_value' => 20000,
                    ]
                );
            }
        }

        // Check opcache.revalidate_freq (should be 0 in production when validate_timestamps=0)
        if (isset($directives['opcache.revalidate_freq']) && is_numeric($directives['opcache.revalidate_freq'])) {
            $revalidateFreq = (int) $directives['opcache.revalidate_freq'];
            if ($revalidateFreq > 0 && isset($directives['opcache.validate_timestamps']) && $directives['opcache.validate_timestamps'] === false) {
                $issues[] = $this->createIssue(
                    message: 'opcache.revalidate_freq should be 0 when validate_timestamps is disabled',
                    location: new Location($phpIniPath, 1),
                    severity: Severity::Low,
                    recommendation: 'Set "opcache.revalidate_freq=0" when "opcache.validate_timestamps=0" for maximum performance. Current: '.$revalidateFreq.' seconds.',
                    metadata: [
                        'current_value' => $revalidateFreq,
                        'recommended_value' => 0,
                    ]
                );
            }
        }

        // Check opcache.fast_shutdown (should be 1 for better performance)
        if (isset($directives['opcache.fast_shutdown']) && $directives['opcache.fast_shutdown'] !== true) {
            $currentValue = $directives['opcache.fast_shutdown'];
            $issues[] = $this->createIssue(
                message: 'opcache.fast_shutdown is disabled',
                location: new Location($phpIniPath, 1),
                severity: Severity::Low,
                recommendation: 'Enable "opcache.fast_shutdown=1" for faster PHP shutdown and better performance. Current: '.($currentValue ? '1' : '0').'.',
                metadata: [
                    'current_value' => $currentValue,
                    'recommended_value' => 1,
                ]
            );
        }
    }
}
