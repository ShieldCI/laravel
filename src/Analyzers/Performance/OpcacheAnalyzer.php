<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
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
 */
class OpcacheAnalyzer extends AbstractFileAnalyzer
{
    /**
     * OPcache configuration is not applicable in CI environments.
     */
    public static bool $runInCI = false;

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
        // Skip if user configured to skip in local environment
        return ! $this->isLocalAndShouldSkip();
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check if OPcache extension is loaded
        if (! extension_loaded('Zend OPcache')) {
            $issues[] = $this->createIssue(
                message: 'OPcache extension is not loaded',
                location: new Location('php.ini', 1),
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

        if ($opcacheConfig === false || ! isset($opcacheConfig['directives']['opcache.enable'])) {
            $issues[] = $this->createIssue(
                message: 'Unable to retrieve OPcache configuration',
                location: new Location('php.ini', 1),
                severity: Severity::Medium,
                recommendation: 'OPcache is loaded but configuration cannot be retrieved. Verify OPcache is properly configured in php.ini.',
                metadata: ['php_version' => PHP_VERSION]
            );
        } elseif (! $opcacheConfig['directives']['opcache.enable']) {
            $issues[] = $this->createIssue(
                message: 'OPcache is disabled',
                location: new Location('php.ini', 1),
                severity: Severity::High,
                recommendation: 'Enable OPcache by setting "opcache.enable=1" in php.ini. OPcache provides significant performance improvements by caching compiled bytecode.',
                metadata: [
                    'php_version' => PHP_VERSION,
                    'opcache_enabled' => false,
                ]
            );
        } else {
            // OPcache is enabled, check configuration recommendations
            $this->checkOpcacheConfiguration($opcacheConfig, $issues);
        }

        if (empty($issues)) {
            return $this->passed('OPcache is enabled and properly configured');
        }

        return $this->failed(
            sprintf('Found %d OPcache configuration issues', count($issues)),
            $issues
        );
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private function checkOpcacheConfiguration(array $config, array &$issues): void
    {
        $directives = $config['directives'];

        // Check opcache.validate_timestamps (should be 0 in production)
        if (isset($directives['opcache.validate_timestamps']) && $directives['opcache.validate_timestamps'] === true) {
            $issues[] = $this->createIssue(
                message: 'opcache.validate_timestamps is enabled in production',
                location: new Location('php.ini', 1),
                severity: Severity::Low,
                recommendation: 'Set "opcache.validate_timestamps=0" in production for maximum performance. This disables checking for file changes on every request. You\'ll need to restart PHP after code changes.',
                metadata: [
                    'current_value' => 1,
                    'recommended_value' => 0,
                ]
            );
        }

        // Check opcache.memory_consumption (recommended: 128MB+)
        if (isset($directives['opcache.memory_consumption']) && $directives['opcache.memory_consumption'] < 128) {
            $issues[] = $this->createIssue(
                message: 'OPcache memory consumption is low',
                location: new Location('php.ini', 1),
                severity: Severity::Low,
                recommendation: 'Increase "opcache.memory_consumption" to at least 128MB (recommended: 256MB for Laravel apps). Current: '.$directives['opcache.memory_consumption'].'MB. This ensures all your application code can be cached.',
                metadata: [
                    'current_value' => $directives['opcache.memory_consumption'],
                    'recommended_value' => 256,
                ]
            );
        }

        // Check opcache.interned_strings_buffer (recommended: 16MB+)
        if (isset($directives['opcache.interned_strings_buffer']) && $directives['opcache.interned_strings_buffer'] < 16) {
            $issues[] = $this->createIssue(
                message: 'OPcache interned strings buffer is low',
                location: new Location('php.ini', 1),
                severity: Severity::Low,
                recommendation: 'Increase "opcache.interned_strings_buffer" to at least 16MB. Current: '.$directives['opcache.interned_strings_buffer'].'MB. This caches common strings and improves memory efficiency.',
                metadata: [
                    'current_value' => $directives['opcache.interned_strings_buffer'],
                    'recommended_value' => 16,
                ]
            );
        }
    }
}
