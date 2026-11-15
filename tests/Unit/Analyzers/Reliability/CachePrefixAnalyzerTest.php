<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Contracts\Config\Repository as Config;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\Reliability\CachePrefixAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Cache prefix is empty', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertNull($issues[0]->location);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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
        $this->assertWarning($result);
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
        $this->assertWarning($result);
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
        $this->assertWarning($result);
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

    // =========================================================================
    // Issue Location (#358)
    // =========================================================================

    public function test_omits_the_location_for_a_generic_prefix_when_cache_config_is_not_published(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'laravel_cache',
        ], writeFile: false);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('too generic', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertNull($issues[0]->location);
    }

    public function test_locates_the_global_prefix_in_a_published_cache_config(): void
    {
        $config = <<<'PHP'
<?php

return [
    'default' => env('CACHE_STORE', 'redis'),

    'prefix' => env('CACHE_PREFIX', 'laravel_cache'),

    'stores' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'cache',
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/cache.php' => $config]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'laravel_cache',
        ], writeFile: false);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $location = $issues[0]->location;
        $this->assertNotNull($location);
        $this->assertSame('config/cache.php', $location->file);
        $this->assertNotNull($location->line);

        $lines = file($tempDir.'/config/cache.php', FILE_IGNORE_NEW_LINES);
        $this->assertIsArray($lines);
        $this->assertStringContainsString("'prefix' =>", $lines[$location->line - 1]);
    }

    public function test_locates_a_store_specific_prefix_in_a_published_cache_config(): void
    {
        $config = <<<'PHP'
<?php

return [
    'default' => env('CACHE_STORE', 'redis'),

    'stores' => [
        'redis' => [
            'driver' => 'redis',
            'prefix' => 'laravel_cache',
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/cache.php' => $config]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'prefix' => 'laravel_cache',
                ],
            ],
        ], writeFile: false);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $location = $issues[0]->location;
        $this->assertNotNull($location);
        $this->assertNotNull($location->line);

        $lines = file($tempDir.'/config/cache.php', FILE_IGNORE_NEW_LINES);
        $this->assertIsArray($lines);
        $this->assertStringContainsString("'prefix' =>", $lines[$location->line - 1]);
    }

    // =========================================================================
    // Severity By Driver
    // =========================================================================

    public function test_grades_an_empty_prefix_on_the_database_store_low(): void
    {
        $tempDir = $this->createTempDirectory([]);

        // The Laravel 11 skeleton: database store, empty global prefix.
        $this->setupCacheConfig($tempDir, [
            'default' => 'database',
            'prefix' => '',
            'stores' => [
                'database' => [
                    'driver' => 'database',
                    'table' => 'cache',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Cache prefix is empty or not set', $result);
        $this->assertOnlySeverity(Severity::Low, $result);
    }

    public function test_grades_a_generic_prefix_on_the_database_store_low(): void
    {
        $tempDir = $this->createTempDirectory([]);

        // The Laravel 12 and 13 skeleton: database store, slugged app name plus '-cache-'.
        $this->setupCacheConfig($tempDir, [
            'default' => 'database',
            'prefix' => 'laravel-cache-',
            'stores' => [
                'database' => [
                    'driver' => 'database',
                    'table' => 'cache',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining("Cache prefix 'laravel-cache-' is too generic", $result);
        $this->assertOnlySeverity(Severity::Low, $result);
    }

    /**
     * @dataProvider serverDriverProvider
     */
    #[DataProvider('serverDriverProvider')]
    public function test_grades_an_empty_prefix_on_a_cache_server_medium(string $driver): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'orbit',
            'prefix' => '',
            'stores' => [
                'orbit' => [
                    'driver' => $driver,
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Cache prefix is empty or not set', $result);
        $this->assertOnlySeverity(Severity::Medium, $result);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function serverDriverProvider(): array
    {
        return [
            'redis' => ['redis'],
            'memcached' => ['memcached'],
            'dynamodb' => ['dynamodb'],
        ];
    }

    // =========================================================================
    // Store Prefix Resolution
    // =========================================================================

    public function test_reports_an_empty_store_prefix_that_overrides_a_unique_global_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        // CacheManager::getPrefix() reads the store's key with ??, so '' wins over the global.
        $this->setupCacheConfig($tempDir, [
            'prefix' => 'acme_cache',
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Cache prefix is empty or not set', $result);
    }

    public function test_falls_back_to_the_global_prefix_when_the_store_prefix_is_null(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'acme_cache',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'prefix' => null,
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // Redis Connection Prefix
    // =========================================================================

    public function test_passes_when_the_redis_connection_options_carry_a_unique_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
        ], redis: [
            'options' => ['prefix' => 'acme_database_'],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_the_store_connection_carries_a_unique_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
        ], redis: [
            'options' => ['prefix' => 'laravel-database-'],
            'cache' => ['prefix' => 'orbit_'],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_the_store_connection_options_carry_a_unique_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
        ], redis: [
            'options' => ['prefix' => 'laravel-database-'],
            'cache' => ['options' => ['prefix' => 'orbit_']],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_reads_the_default_redis_connection_when_the_store_names_none(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'connection' => null,
                ],
            ],
        ], redis: [
            'default' => ['prefix' => 'orbit_'],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_reports_an_empty_connection_prefix_that_overrides_the_options_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        // The connectors copy the connection's own prefix over the merged options.
        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
        ], redis: [
            'options' => ['prefix' => 'acme_database_'],
            'cache' => ['prefix' => ''],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Cache prefix is empty or not set', $result);
    }

    /**
     * @dataProvider genericConnectionPrefixProvider
     */
    #[DataProvider('genericConnectionPrefixProvider')]
    public function test_reports_a_generic_connection_prefix_without_a_unique_cache_prefix(string $connectionPrefix, string $cachePrefix): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => $cachePrefix,
        ], redis: [
            'options' => ['prefix' => $connectionPrefix],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining("Cache prefix '{$connectionPrefix}{$cachePrefix}' is too generic", $result);
        $this->assertOnlySeverity(Severity::Medium, $result);
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function genericConnectionPrefixProvider(): array
    {
        return [
            'laravel 12 connection prefix, empty cache prefix' => ['laravel-database-', ''],
            'laravel 11 connection prefix, empty cache prefix' => ['laravel_database_', ''],
            'generic connection prefix, generic cache prefix' => ['laravel-database-', 'laravel-cache-'],
        ];
    }

    public function test_passes_with_a_unique_cache_prefix_behind_a_generic_connection_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'acme-cache-',
        ], redis: [
            'options' => ['prefix' => 'laravel-database-'],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_reads_the_prefix_of_a_redis_cluster_connection(): void
    {
        $tempDir = $this->createTempDirectory([]);

        // RedisManager::resolve() falls back to clusters, whose shared options override the global ones.
        $this->setupCacheConfig($tempDir, [
            'prefix' => 'laravel-cache-',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'connection' => 'orbit',
                ],
            ],
        ], redis: [
            'options' => ['prefix' => 'laravel-database-'],
            'clusters' => [
                'options' => ['prefix' => 'acme_cluster_'],
                'orbit' => [['host' => '127.0.0.1']],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_reads_the_options_of_a_single_redis_cluster(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'laravel-cache-',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'connection' => 'orbit',
                ],
            ],
        ], redis: [
            'options' => ['prefix' => 'laravel-database-'],
            'clusters' => [
                'options' => ['prefix' => 'laravel-cluster-'],
                'orbit' => [
                    ['host' => '127.0.0.1'],
                    'options' => ['prefix' => 'acme_cluster_'],
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @dataProvider redisClientProvider
     */
    #[DataProvider('redisClientProvider')]
    public function test_ignores_a_cluster_level_prefix_key(string $client): void
    {
        $tempDir = $this->createTempDirectory([]);

        // RedisManager::resolveCluster() parses every entry of the cluster as a connection,
        // so a string prefix key becomes a parsed URL that breaks the cluster instead of
        // namespacing its keys. The analyzer must not credit it as a prefix.
        $this->setupCacheConfig($tempDir, [
            'prefix' => 'laravel-cache-',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'connection' => 'orbit',
                ],
            ],
        ], redis: [
            'client' => $client,
            'options' => ['prefix' => 'laravel-database-'],
            'clusters' => [
                'orbit' => [
                    ['host' => '127.0.0.1'],
                    'prefix' => 'acme_cluster_',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining("Cache prefix 'laravel-database-laravel-cache-' is too generic", $result);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function redisClientProvider(): array
    {
        return [
            'predis' => ['predis'],
            'phpredis' => ['phpredis'],
        ];
    }

    public function test_reads_the_prefix_from_a_redis_connection_url(): void
    {
        $tempDir = $this->createTempDirectory([]);

        // RedisManager::parseConnectionConfiguration() merges the URL's query over the connection's keys.
        $this->setupCacheConfig($tempDir, [
            'prefix' => 'laravel-cache-',
        ], redis: [
            'options' => ['prefix' => 'laravel-database-'],
            'cache' => [
                'url' => 'tcp://127.0.0.1:6379?prefix=acme_',
                'prefix' => '',
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_grades_a_redis_connection_whose_url_is_not_a_string(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'laravel-cache-',
        ], redis: [
            'options' => ['prefix' => 'laravel-database-'],
            'cache' => [
                'url' => ['redis://127.0.0.1'],
                'host' => '127.0.0.1',
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining("Cache prefix 'laravel-database-laravel-cache-' is too generic", $result);
    }

    public function test_reads_the_explicit_prefix_of_a_redis_connection_with_a_malformed_url(): void
    {
        $tempDir = $this->createTempDirectory([]);

        // parse_url() rejects this URL, so ConfigurationUrlParser throws InvalidArgumentException.
        $this->setupCacheConfig($tempDir, [
            'prefix' => 'laravel-cache-',
        ], redis: [
            'options' => ['prefix' => 'laravel-database-'],
            'cache' => [
                'url' => 'redis://:80',
                'prefix' => 'acme_',
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_the_memcached_client_carries_a_unique_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        // -1002 is Memcached::OPT_PREFIX_KEY, which the client prepends to every key.
        $this->setupCacheConfig($tempDir, [
            'default' => 'memcached',
            'prefix' => 'laravel-cache-',
            'stores' => [
                'memcached' => [
                    'driver' => 'memcached',
                    'options' => [-1002 => 'acme_'],
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @dataProvider weakMemcachedPrefixProvider
     */
    #[DataProvider('weakMemcachedPrefixProvider')]
    public function test_reports_a_weak_memcached_client_prefix_without_a_unique_cache_prefix(string $clientPrefix, string $cachePrefix, string $expected): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'memcached',
            'prefix' => $cachePrefix,
            'stores' => [
                'memcached' => [
                    'driver' => 'memcached',
                    'options' => [-1002 => $clientPrefix],
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining($expected, $result);
        $this->assertOnlySeverity(Severity::Medium, $result);
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: string}>
     */
    public static function weakMemcachedPrefixProvider(): array
    {
        return [
            'generic client prefix, generic cache prefix' => ['laravel_', 'laravel-cache-', "Cache prefix 'laravel_laravel-cache-' is too generic"],
            'empty client prefix, empty cache prefix' => ['', '', 'Cache prefix is empty or not set'],
        ];
    }

    public function test_ignores_the_redis_connection_prefix_for_other_drivers(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'memcached',
            'prefix' => '',
            'stores' => [
                'memcached' => [
                    'driver' => 'memcached',
                ],
            ],
        ], redis: [
            'options' => ['prefix' => 'acme_database_'],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Cache prefix is empty or not set', $result);
    }

    // =========================================================================
    // Failover Store
    // =========================================================================

    public function test_reports_an_empty_prefix_on_a_redis_store_behind_failover(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'failover',
            'prefix' => '',
            'stores' => [
                'failover' => [
                    'driver' => 'failover',
                    'stores' => ['redis', 'array'],
                ],
                'array' => [
                    'driver' => 'array',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("Failover cache store 'failover' uses store 'redis'", $result);
        $this->assertHasIssueContaining('empty or not set', $result);
        $this->assertOnlySeverity(Severity::Medium, $result);
        $this->assertSame('redis', $result->getIssues()[0]->metadata['cache_store'] ?? null);
    }

    public function test_grades_a_database_store_behind_failover_low(): void
    {
        $tempDir = $this->createTempDirectory([]);

        // The Laravel 13 failover store as the framework ships it.
        $this->setupCacheConfig($tempDir, [
            'default' => 'failover',
            'prefix' => 'laravel-cache-',
            'stores' => [
                'failover' => [
                    'driver' => 'failover',
                    'stores' => ['database', 'array'],
                ],
                'database' => [
                    'driver' => 'database',
                    'table' => 'cache',
                ],
                'array' => [
                    'driver' => 'array',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("uses store 'database'", $result);
        $this->assertHasIssueContaining("'laravel-cache-' is too generic", $result);
        $this->assertOnlySeverity(Severity::Low, $result);
    }

    public function test_reports_each_shared_store_behind_failover_with_its_own_severity(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'failover',
            'prefix' => '',
            'stores' => [
                'failover' => [
                    'driver' => 'failover',
                    'stores' => ['redis', 'database'],
                ],
                'database' => [
                    'driver' => 'database',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(2, $result);

        $severities = [];
        foreach ($result->getIssues() as $issue) {
            $store = $issue->metadata['cache_store'] ?? null;
            $this->assertIsString($store);
            $severities[$store] = $issue->severity;
        }

        $this->assertSame(['redis' => Severity::Medium, 'database' => Severity::Low], $severities);
    }

    public function test_passes_a_failover_store_whose_shared_stores_have_unique_prefixes(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'failover',
            'prefix' => 'acme_cache',
            'stores' => [
                'failover' => [
                    'driver' => 'failover',
                    'stores' => ['redis', 'array'],
                ],
                'array' => [
                    'driver' => 'array',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_reports_a_shared_store_behind_a_nested_failover_store(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'outer',
            'prefix' => '',
            'stores' => [
                'outer' => [
                    'driver' => 'failover',
                    'stores' => ['inner', 'array'],
                ],
                'inner' => [
                    'driver' => 'failover',
                    'stores' => ['redis', 'outer'],
                ],
                'array' => [
                    'driver' => 'array',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("Failover cache store 'outer' uses store 'redis'", $result);
    }

    public function test_reports_a_store_listed_twice_behind_failover_once(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'failover',
            'prefix' => '',
            'stores' => [
                'failover' => [
                    'driver' => 'failover',
                    'stores' => ['1', 'orbit'],
                ],
                'orbit' => [
                    'driver' => 'failover',
                    'stores' => ['1'],
                ],
                '1' => [
                    'driver' => 'memcached',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("uses store '1'", $result);
    }

    public function test_skips_a_failover_store_without_a_shared_store(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'failover',
            'prefix' => '',
            'stores' => [
                'failover' => [
                    'driver' => 'failover',
                    'stores' => ['file', 'array', 'failover', 'missing', 42],
                ],
                'file' => [
                    'driver' => 'file',
                ],
                'array' => [
                    'driver' => 'array',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString("Failover cache store 'failover'", $result->getMessage());
    }

    private function assertOnlySeverity(Severity $expected, ResultInterface $result): void
    {
        $this->assertNotEmpty($result->getIssues());

        foreach ($result->getIssues() as $issue) {
            $this->assertSame($expected, $issue->severity);
        }
    }

    /**
     * The Redis config replaces the framework's, so a test only sees the connection prefix it sets.
     *
     * @param  array<string, mixed>  $overrides
     * @param  array<string, mixed>  $redis
     */
    private function setupCacheConfig(string $basePath, array $overrides = [], bool $writeFile = true, array $redis = []): void
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
        $configRepo->set('database.redis', array_replace_recursive([
            'client' => 'phpredis',
            'options' => [],
            'default' => ['host' => '127.0.0.1'],
            'cache' => ['host' => '127.0.0.1'],
        ], $redis));

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
