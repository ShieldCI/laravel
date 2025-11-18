<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Analyzes cache driver configuration for performance best practices.
 *
 * Checks for:
 * - Null or array cache drivers in production
 * - File cache driver in non-local environments
 * - Database cache driver in production
 * - Recommends Redis/Memcached for production
 *
 * This analyzer uses Laravel's config repository to get runtime values,
 * which respects environment variables and config caching.
 */
class CacheDriverAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ConfigRepository $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'cache-driver',
            name: 'Cache Driver Configuration',
            description: 'Ensures a proper cache driver is configured for optimal performance',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['cache', 'performance', 'configuration', 'redis', 'memcached'],
            docsUrl: 'https://laravel.com/docs/cache#configuration'
        );
    }

    public function shouldRun(): bool
    {
        // Check if cache.default is configured
        $defaultStore = $this->config->get('cache.default');

        return $defaultStore !== null;
    }

    public function getSkipReason(): string
    {
        return 'Cache default store not configured';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Use injected config repository to get runtime values (respects .env and config:cache)
        $defaultStore = $this->config->get('cache.default');
        if (! is_string($defaultStore)) {
            return $this->error('Cache default store is not configured properly');
        }

        $environment = $this->config->get('app.env', 'production');

        // Validate that the store exists in configuration
        $driver = $this->config->get("cache.stores.{$defaultStore}.driver");
        if ($driver === null) {
            $configFile = ConfigFileHelper::getConfigPath($this->basePath, 'cache.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);
            $issues[] = $this->createIssue(
                message: "Cache store '{$defaultStore}' is not defined in cache configuration",
                location: new Location($configFile, ConfigFileHelper::findKeyLine($configFile, 'default')),
                severity: Severity::Critical,
                recommendation: 'Define the cache store in config/cache.php or change the default store in your .env file (CACHE_STORE)',
                metadata: ['store' => $defaultStore, 'environment' => $environment]
            );

            return $this->failed('Cache configuration is invalid', $issues);
        }

        $configFile = ConfigFileHelper::getConfigPath($this->basePath, 'cache.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        // Check for problematic drivers
        if ($driver === 'null') {
            $lineNumber = ConfigFileHelper::findNestedKeyLine($configFile, 'stores', 'driver', $defaultStore);
            $issues[] = $this->createIssue(
                message: 'Cache driver is set to null - caching is disabled',
                location: new Location($configFile, $lineNumber),
                severity: Severity::Critical,
                recommendation: 'Set CACHE_STORE to redis, memcached, or dynamodb in your .env file for production. Null driver means all cache operations will be no-ops.',
                metadata: ['driver' => 'null', 'store' => $defaultStore, 'environment' => $environment]
            );
        } elseif ($driver === 'array') {
            $lineNumber = ConfigFileHelper::findNestedKeyLine($configFile, 'stores', 'driver', $defaultStore);
            $issues[] = $this->createIssue(
                message: 'Cache driver is set to array - cache not persisted',
                location: new Location($configFile, $lineNumber),
                severity: Severity::Critical,
                recommendation: 'Array driver only caches within a single request and is only suitable for testing. Use redis, memcached, or dynamodb for production.',
                metadata: ['driver' => 'array', 'store' => $defaultStore, 'environment' => $environment]
            );
        } elseif ($driver === 'file' && $environment !== 'local') {
            $lineNumber = ConfigFileHelper::findNestedKeyLine($configFile, 'stores', 'driver', $defaultStore);
            $issues[] = $this->createIssue(
                message: "File cache driver in {$environment} environment",
                location: new Location($configFile, $lineNumber),
                severity: Severity::Medium,
                recommendation: 'File cache is only suitable for single-server setups. For better performance, use Redis or Memcached with unix sockets. They provide faster access and more efficient eviction of expired cache items.',
                metadata: ['driver' => 'file', 'store' => $defaultStore, 'environment' => $environment]
            );
        } elseif ($driver === 'database' && $environment !== 'local') {
            $lineNumber = ConfigFileHelper::findNestedKeyLine($configFile, 'stores', 'driver', $defaultStore);
            $issues[] = $this->createIssue(
                message: "Database cache driver in {$environment} environment",
                location: new Location($configFile, $lineNumber),
                severity: Severity::Medium,
                recommendation: 'Database cache driver is not recommended for production. Use Redis or Memcached for better performance and robustness.',
                metadata: ['driver' => 'database', 'store' => $defaultStore, 'environment' => $environment]
            );
        }

        if (empty($issues)) {
            return $this->passed("Cache driver '{$driver}' is properly configured for {$environment} environment");
        }

        return $this->failed(
            sprintf('Found %d cache driver configuration issues', count($issues)),
            $issues
        );
    }
}
