<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Contracts\Config\Repository as Config;
use ShieldCI\Analyzers\Reliability\CachePrefixAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\Tests\AnalyzerTestCase;

class CachePrefixAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CachePrefixAnalyzer;
    }

    public function test_skips_when_cache_driver_not_shared(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'file',
            'prefix' => null,
            'stores' => [
                'file' => [
                    'driver' => 'file',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertEquals(Status::Skipped, $result->getStatus());
    }

    public function test_fails_with_empty_cache_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache prefix is empty', $result);
    }

    public function test_fails_with_generic_cache_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'Laravel_Cache',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('too generic', $result);
    }

    public function test_passes_with_unique_cache_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'myapp_cache',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_store_specific_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'prefix' => 'tenant_cache',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_missing_config_file(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
        ], writeFile: false);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    // =========================================================================
    // Generic Prefix Variation Tests
    // =========================================================================

    public function test_fails_with_app_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'app',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('too generic', $result);
    }

    public function test_fails_with_cache_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'cache',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('too generic', $result);
    }

    public function test_fails_with_laravel_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'laravel',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('too generic', $result);
    }

    public function test_fails_with_slugified_generic_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'Laravel Cache',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('too generic', $result);
    }

    public function test_fails_with_my_app_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'my_app',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('too generic', $result);
    }

    public function test_fails_with_test_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'test',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('too generic', $result);
    }

    // =========================================================================
    // Store-Specific Prefix Tests
    // =========================================================================

    public function test_fails_with_generic_store_specific_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'unique_global',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'prefix' => 'cache',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('too generic', $result);
    }

    public function test_prefers_store_specific_over_global_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'cache',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'prefix' => 'unique_redis_cache',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass because store-specific prefix overrides generic global prefix
        $this->assertPassed($result);
    }

    public function test_fails_when_store_prefix_empty_and_global_empty(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'prefix' => '',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('empty', $result);
    }

    // =========================================================================
    // Different Cache Driver Tests
    // =========================================================================

    public function test_runs_for_memcached_driver(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'memcached',
            'prefix' => 'unique_memcached_cache',
            'stores' => [
                'memcached' => [
                    'driver' => 'memcached',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_runs_for_dynamodb_driver(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'dynamodb',
            'prefix' => 'unique_dynamo_cache',
            'stores' => [
                'dynamodb' => [
                    'driver' => 'dynamodb',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_runs_for_database_driver(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'database',
            'prefix' => 'unique_database_cache',
            'stores' => [
                'database' => [
                    'driver' => 'database',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_for_array_driver(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'array',
            'prefix' => null,
            'stores' => [
                'array' => [
                    'driver' => 'array',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertEquals(Status::Skipped, $result->getStatus());
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    public function test_handles_null_cache_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => null,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('empty', $result);
    }

    public function test_handles_whitespace_only_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '   ',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Whitespace-only prefix should be treated as generic
        $this->assertFailed($result);
    }

    public function test_handles_very_short_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'ab',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Very short prefixes (1-2 chars) are considered generic
        $this->assertFailed($result);
        $this->assertHasIssueContaining('too generic', $result);
    }

    public function test_handles_underscore_only_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '___',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Underscore-only prefix should be treated as generic
        $this->assertFailed($result);
        $this->assertHasIssueContaining('too generic', $result);
    }

    public function test_passes_with_environment_based_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'production_mycompany_cache',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private function setupCacheConfig(string $basePath, array $overrides = [], bool $writeFile = true): void
    {
        $default = [
            'default' => 'redis',
            'prefix' => '',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'connection' => 'cache',
                ],
            ],
        ];

        $config = array_replace_recursive($default, $overrides);

        /** @var Config $configRepo */
        $configRepo = $this->app?->make('config') ?? app('config');
        $configRepo->set('cache', $config);
        $configRepo->set('cache.default', $config['default']);
        $configRepo->set('cache.prefix', $config['prefix']);
        $configRepo->set('cache.stores', $config['stores']);
        $configRepo->set('app.name', 'ShieldCI Demo');

        if (! $writeFile) {
            return;
        }

        $configDir = $basePath.'/config';
        if (! is_dir($configDir)) {
            mkdir($configDir, 0755, true);
        }

        $content = "<?php\n\nreturn ".var_export($config, true).";\n";
        file_put_contents($configDir.'/cache.php', $content);
    }
}
