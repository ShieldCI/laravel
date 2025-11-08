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
 * Analyzes cache driver configuration for performance best practices.
 *
 * Checks for:
 * - Null or array cache drivers in production
 * - File cache driver in non-local environments
 * - Database cache driver in production
 * - Recommends Redis/Memcached for production
 */
class CacheDriverAnalyzer extends AbstractFileAnalyzer
{
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
        return file_exists($this->getConfigPath('cache.php'));
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $cacheConfig = $this->getCacheConfig();
        $defaultStore = $cacheConfig['default'] ?? 'file';
        $environment = $this->getEnvironment();

        $store = $cacheConfig['stores'][$defaultStore] ?? null;

        if ($store === null) {
            $issues[] = $this->createIssue(
                message: "Cache store '{$defaultStore}' is not defined in cache configuration",
                location: new Location($this->getConfigPath('cache.php'), 1),
                severity: Severity::Critical,
                recommendation: 'Define the cache store in config/cache.php or change the default store'
            );

            return $this->failed('Cache configuration is invalid', $issues);
        }

        $driver = $store['driver'] ?? 'null';

        // Check for problematic drivers
        if ($driver === 'null') {
            $issues[] = $this->createIssue(
                message: 'Cache driver is set to null - caching is disabled',
                location: new Location($this->getConfigPath('cache.php'), $this->findLineInConfig('cache', 'default')),
                severity: Severity::Critical,
                recommendation: 'Set CACHE_STORE to redis, memcached, or dynamodb in your .env file for production. Null driver means all cache operations will be no-ops.',
                metadata: ['driver' => 'null', 'environment' => $environment]
            );
        } elseif ($driver === 'array') {
            $issues[] = $this->createIssue(
                message: 'Cache driver is set to array - cache not persisted',
                location: new Location($this->getConfigPath('cache.php'), $this->findLineInConfig('cache', 'default')),
                severity: Severity::Critical,
                recommendation: 'Array driver only caches within a single request and is only suitable for testing. Use redis, memcached, or dynamodb for production.',
                metadata: ['driver' => 'array', 'environment' => $environment]
            );
        } elseif ($driver === 'file' && $environment !== 'local') {
            $issues[] = $this->createIssue(
                message: "File cache driver in {$environment} environment",
                location: new Location($this->getConfigPath('cache.php'), $this->findLineInConfig('cache', 'default')),
                severity: Severity::Medium,
                recommendation: 'File cache is only suitable for single-server setups. For better performance, use Redis or Memcached with unix sockets. They provide faster access and more efficient eviction of expired cache items.',
                metadata: ['driver' => 'file', 'environment' => $environment]
            );
        } elseif ($driver === 'database' && $environment !== 'local') {
            $issues[] = $this->createIssue(
                message: "Database cache driver in {$environment} environment",
                location: new Location($this->getConfigPath('cache.php'), $this->findLineInConfig('cache', 'default')),
                severity: Severity::Medium,
                recommendation: 'Database cache driver is not recommended for production. Use Redis or Memcached for better performance and robustness.',
                metadata: ['driver' => 'database', 'environment' => $environment]
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

    private function getCacheConfig(): array
    {
        $configFile = $this->getConfigPath('cache.php');

        if (! file_exists($configFile)) {
            return [];
        }

        return include $configFile;
    }

    private function getEnvironment(): string
    {
        $envFile = $this->basePath.'/.env';

        if (! file_exists($envFile)) {
            return 'production';
        }

        $content = file_get_contents($envFile);

        if (preg_match('/^APP_ENV\s*=\s*(\w+)/m', $content, $matches)) {
            return $matches[1];
        }

        return 'production';
    }

    private function getConfigPath(string $file): string
    {
        return $this->basePath.'/config/'.$file;
    }

    private function findLineInConfig(string $file, string $key): int
    {
        $configFile = $this->getConfigPath($file.'.php');

        if (! file_exists($configFile)) {
            return 1;
        }

        $lines = file($configFile);

        foreach ($lines as $lineNumber => $line) {
            if (str_contains($line, "'{$key}'") || str_contains($line, "\"{$key}\"")) {
                return $lineNumber + 1;
            }
        }

        return 1;
    }
}
