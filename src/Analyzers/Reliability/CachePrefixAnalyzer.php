<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Checks cache prefix configuration to avoid collisions.
 *
 * Checks for:
 * - Cache prefix is set and not generic
 * - Prevents cache key collisions in shared cache servers
 * - Validates unique app identification
 */
class CachePrefixAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<string>
     */
    private array $genericPrefixes = [
        'laravel_cache',
        'laravel',
        'app',
        'cache',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'cache-prefix-configuration',
            name: 'Cache Prefix Configuration',
            description: 'Ensures cache prefix is set to avoid collisions with other applications sharing cache servers',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['cache', 'configuration', 'reliability', 'multi-tenant'],
            docsUrl: 'https://laravel.com/docs/cache#configuration'
        );
    }

    public function shouldRun(): bool
    {
        // Skip if not using shared cache drivers
        $driver = config('cache.default');

        return in_array($driver, ['redis', 'memcached', 'dynamodb', 'database']);
    }

    public function getSkipReason(): string
    {
        $driver = config('cache.default');

        return "Not using shared cache driver (current: {$driver}, requires: redis/memcached/dynamodb/database)";
    }

    protected function runAnalysis(): ResultInterface
    {
        $cacheConfig = $this->getCacheConfig();
        $prefix = $cacheConfig['prefix'] ?? '';

        // Check if prefix is empty
        if (empty($prefix)) {
            return $this->failed(
                'Cache prefix is not configured',
                [$this->createIssue(
                    message: 'Cache prefix is empty or not set',
                    location: new Location($this->basePath.'/config/cache.php', $this->findLineInConfig('cache', 'prefix')),
                    severity: Severity::High,
                    recommendation: 'Set a unique cache prefix in config/cache.php to avoid collisions with other applications sharing the same cache server. Use your application name or a unique identifier. Example: \'prefix\' => env(\'CACHE_PREFIX\', Str::slug(env(\'APP_NAME\', \'laravel\'), \'_\').\'_cache\')',
                    metadata: [
                        'cache_driver' => config('cache.default'),
                        'prefix' => $prefix,
                    ]
                )]
            );
        }

        // Check if prefix is too generic
        if (is_string($prefix) && in_array(strtolower($prefix), $this->genericPrefixes)) {
            return $this->failed(
                'Cache prefix is too generic',
                [$this->createIssue(
                    message: "Cache prefix '{$prefix}' is too generic and may cause collisions",
                    location: new Location($this->basePath.'/config/cache.php', $this->findLineInConfig('cache', 'prefix')),
                    severity: Severity::High,
                    recommendation: "The cache prefix '{$prefix}' is generic and may collide with other applications using the same cache server. ".
                                   'Use a unique prefix based on your application name. Example: \'myapp_cache\' or use env(\'APP_NAME\') to generate it dynamically. '.
                                   'In config/cache.php, set: \'prefix\' => env(\'CACHE_PREFIX\', Str::slug(env(\'APP_NAME\', \'laravel\'), \'_\').\'_cache\')',
                    metadata: [
                        'cache_driver' => config('cache.default'),
                        'prefix' => $prefix,
                        'app_name' => config('app.name'),
                    ]
                )]
            );
        }

        return $this->passed('Cache prefix is properly configured');
    }

    /**
     * @return array<string, mixed>
     */
    private function getCacheConfig(): array
    {
        $configFile = $this->basePath.'/config/cache.php';

        if (! file_exists($configFile)) {
            return [];
        }

        $config = include $configFile;

        return is_array($config) ? $config : [];
    }

    private function findLineInConfig(string $file, string $key): int
    {
        $configFile = $this->basePath.'/config/'.$file.'.php';

        if (! file_exists($configFile)) {
            return 1;
        }

        $content = file_get_contents($configFile);

        if ($content === false) {
            return 1;
        }

        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            if (str_contains($line, "'{$key}'") || str_contains($line, "\"{$key}\"")) {
                return $lineNumber + 1;
            }
        }

        return 1;
    }
}
