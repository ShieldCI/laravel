<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Checks that the application cache is working properly.
 *
 * Checks for:
 * - Cache driver is accessible and functional
 * - Cache can store and retrieve values
 * - Cache operations don't throw exceptions
 */
class CacheStatusAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Cache connectivity checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'cache-status',
            name: 'Cache Status',
            description: 'Ensures the application cache is working properly and can store/retrieve values',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['cache', 'infrastructure', 'reliability', 'availability'],
            docsUrl: 'https://laravel.com/docs/cache'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $testKey = 'shieldci:cache:test:'.Str::random(10);
        $testValue = Str::random(20);

        try {
            // Test cache write
            Cache::put($testKey, $testValue, 60);

            // Test cache read
            $retrievedValue = Cache::get($testKey);

            // Clean up test key
            Cache::forget($testKey);

            if ($retrievedValue !== $testValue) {
                return $this->failed(
                    'Cache storage is not working correctly - values are not being retrieved as expected',
                    [$this->createIssue(
                        message: 'Cache write/read test failed',
                        location: new Location($this->basePath.'/config/cache.php', 1),
                        severity: Severity::Critical,
                        recommendation: 'Check your cache configuration in config/cache.php. Ensure the cache driver is properly configured and the cache server (Redis, Memcached, etc.) is running and accessible. Test connection to cache server manually.',
                        metadata: [
                            'cache_driver' => config('cache.default'),
                            'expected' => $testValue,
                            'received' => $retrievedValue,
                        ]
                    )]
                );
            }

            return $this->passed('Cache is working correctly');
        } catch (\Throwable $e) {
            return $this->failed(
                'Cache is not accessible or not functioning properly',
                [$this->createIssue(
                    message: 'Cache connection/operation failed',
                    location: new Location($this->basePath.'/config/cache.php', 1),
                    severity: Severity::Critical,
                    recommendation: 'Check your cache configuration and ensure the cache server is running. Error: '.$e->getMessage().'. Common issues: 1) Redis/Memcached server not running, 2) Incorrect host/port configuration, 3) Authentication issues, 4) Firewall blocking connection.',
                    metadata: [
                        'cache_driver' => config('cache.default'),
                        'exception' => get_class($e),
                        'error' => $e->getMessage(),
                    ]
                )]
            );
        }
    }
}
