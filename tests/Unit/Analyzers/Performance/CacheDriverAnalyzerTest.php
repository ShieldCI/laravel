<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\Performance\CacheDriverAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class CacheDriverAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $configValues
     */
    protected function createAnalyzer(array $configValues = []): AnalyzerInterface
    {
        /** @var ConfigRepository&MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        // Set up default config values
        $defaults = [
            'app' => [
                'env' => 'production', // Default to production so tests actually run
            ],
            'cache' => [
                'default' => 'redis',
                'stores' => [
                    'redis' => [
                        'driver' => 'redis',
                    ],
                ],
            ],
        ];

        $configMap = array_replace_recursive($defaults, $configValues);

        $config->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) use ($configMap) {
                // Handle dotted key access (e.g., 'cache.stores.redis.driver')
                $keys = explode('.', $key);
                $value = $configMap;

                foreach ($keys as $segment) {
                    if (is_array($value) && array_key_exists($segment, $value)) {
                        $value = $value[$segment];
                    } else {
                        return $default;
                    }
                }

                return $value ?? $default;
            });

        return new CacheDriverAnalyzer($config);
    }

    public function test_passes_with_redis_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'redis',
                'stores' => [
                    'redis' => [
                        'driver' => 'redis',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_null_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'null',
                'stores' => [
                    'null' => [
                        'driver' => 'null',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('null', $result);
    }

    public function test_passes_with_null_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'cache' => [
                'default' => 'null',
                'stores' => [
                    'null' => [
                        'driver' => 'null',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_file_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'file',
                'stores' => [
                    'file' => [
                        'driver' => 'file',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('File cache driver', $result);
    }

    public function test_passes_with_file_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'cache' => [
                'default' => 'file',
                'stores' => [
                    'file' => [
                        'driver' => 'file',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_array_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'array',
                'stores' => [
                    'array' => [
                        'driver' => 'array',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('array', $result);
    }

    public function test_passes_with_array_driver_in_testing(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'testing',
            ],
            'cache' => [
                'default' => 'array',
                'stores' => [
                    'array' => [
                        'driver' => 'array',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_database_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'database',
                'stores' => [
                    'database' => [
                        'driver' => 'database',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database cache driver', $result);
    }

    public function test_passes_with_database_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'cache' => [
                'default' => 'database',
                'stores' => [
                    'database' => [
                        'driver' => 'database',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_memcached_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'memcached',
                'stores' => [
                    'memcached' => [
                        'driver' => 'memcached',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_with_apc_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'apc',
                'stores' => [
                    'apc' => [
                        'driver' => 'apc',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APC cache driver', $result);
    }

    public function test_passes_with_apc_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'cache' => [
                'default' => 'apc',
                'stores' => [
                    'apc' => [
                        'driver' => 'apc',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_dynamodb_driver_when_configured(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'dynamodb',
                'stores' => [
                    'dynamodb' => [
                        'driver' => 'dynamodb',
                        'table' => 'cache_table',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_dynamodb_driver_without_table(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'dynamodb',
                'stores' => [
                    'dynamodb' => [
                        'driver' => 'dynamodb',
                        'table' => '',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('DynamoDB cache driver', $result);
    }

    public function test_warns_when_octane_driver_without_octane_support(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'octane',
                'stores' => [
                    'octane' => [
                        'driver' => 'octane',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Octane cache driver', $result);
    }

    public function test_warns_for_unknown_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'custom',
                'stores' => [
                    'custom' => [
                        'driver' => 'custom',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('unsupported', $result);
    }

    public function test_skips_when_cache_default_is_null_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'cache' => [
                'default' => null,
            ],
        ]);

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString('not configured', $analyzer->getSkipReason());
    }

    public function test_fails_when_cache_default_is_not_string(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 123,
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('is not a string', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('int', $issues[0]->metadata['type'] ?? '');
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_fails_when_cache_default_is_array(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => ['redis', 'memcached'],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('is not a string', $result);
        $this->assertEquals('array', $result->getIssues()[0]->metadata['type'] ?? '');
    }

    public function test_fails_when_driver_is_not_string(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'redis',
                'stores' => [
                    'redis' => [
                        'driver' => ['redis'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('driver that is not a string', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('redis', $issues[0]->metadata['store'] ?? '');
        $this->assertEquals('array', $issues[0]->metadata['type'] ?? '');
    }

    public function test_fails_when_store_not_defined_with_proper_metadata(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'nonexistent',
                'stores' => [
                    'redis' => [
                        'driver' => 'redis',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not defined', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('nonexistent', $issues[0]->metadata['store'] ?? '');
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_fails_with_dynamodb_driver_with_null_table(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'dynamodb',
                'stores' => [
                    'dynamodb' => [
                        'driver' => 'dynamodb',
                        'table' => null,
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('missing a table', $result);
    }

    public function test_fails_with_dynamodb_driver_with_whitespace_table(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'dynamodb',
                'stores' => [
                    'dynamodb' => [
                        'driver' => 'dynamodb',
                        'table' => '   ',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('missing a table', $result);
    }

    public function test_fails_with_null_driver_in_staging(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'staging',
            ],
            'cache' => [
                'default' => 'null',
                'stores' => [
                    'null' => [
                        'driver' => 'null',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('null', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('staging', $issues[0]->metadata['environment'] ?? '');
    }

    public function test_fails_with_file_driver_in_staging(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'staging',
            ],
            'cache' => [
                'default' => 'file',
                'stores' => [
                    'file' => [
                        'driver' => 'file',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('File cache driver', $result);
    }

    public function test_fails_with_array_driver_in_staging(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'staging',
            ],
            'cache' => [
                'default' => 'array',
                'stores' => [
                    'array' => [
                        'driver' => 'array',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('array', $result);
    }

    public function test_fails_with_database_driver_in_staging(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'staging',
            ],
            'cache' => [
                'default' => 'database',
                'stores' => [
                    'database' => [
                        'driver' => 'database',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database cache driver', $result);
    }

    public function test_fails_with_apc_driver_in_staging(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'staging',
            ],
            'cache' => [
                'default' => 'apc',
                'stores' => [
                    'apc' => [
                        'driver' => 'apc',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APC cache driver', $result);
    }

    public function test_passes_with_null_driver_in_development(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'development',
            ],
            'cache' => [
                'default' => 'null',
                'stores' => [
                    'null' => [
                        'driver' => 'null',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_file_driver_in_development(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'development',
            ],
            'cache' => [
                'default' => 'file',
                'stores' => [
                    'file' => [
                        'driver' => 'file',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_array_driver_in_development(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'development',
            ],
            'cache' => [
                'default' => 'array',
                'stores' => [
                    'array' => [
                        'driver' => 'array',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_database_driver_in_development(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'development',
            ],
            'cache' => [
                'default' => 'database',
                'stores' => [
                    'database' => [
                        'driver' => 'database',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * Run the analyzer against a base path of our choosing.
     *
     * @param  array<string, mixed>  $configValues
     */
    private function analyzeWithBasePath(string $basePath, array $configValues): ResultInterface
    {
        return $this->withBasePath($basePath, fn () => $this->createAnalyzer($configValues)->analyze());
    }

    public function test_reports_the_driver_when_cache_config_is_not_published(): void
    {
        $result = $this->analyzeWithBasePath($this->createTempDirectory([]), [
            'cache' => [
                'default' => 'file',
                'stores' => [
                    'file' => ['driver' => 'file'],
                ],
            ],
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('File cache driver', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertNull($issues[0]->location);
    }

    public function test_passes_with_redis_when_cache_config_is_not_published(): void
    {
        $result = $this->analyzeWithBasePath($this->createTempDirectory([]), [
            'cache' => [
                'default' => 'redis',
                'stores' => [
                    'redis' => ['driver' => 'redis'],
                ],
            ],
        ]);

        $this->assertPassed($result);
    }

    public function test_fails_when_store_not_defined_and_cache_config_is_not_published(): void
    {
        $result = $this->analyzeWithBasePath($this->createTempDirectory([]), [
            'cache' => [
                'default' => 'nonexistent',
                'stores' => [
                    'redis' => ['driver' => 'redis'],
                ],
            ],
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not defined', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertNull($issues[0]->location);
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_locates_the_driver_in_a_published_cache_config(): void
    {
        $config = <<<'PHP'
<?php

return [
    'default' => env('CACHE_STORE', 'file'),

    'stores' => [
        'file' => [
            'driver' => 'file',
            'path' => storage_path('framework/cache/data'),
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/cache.php' => $config]);

        $result = $this->analyzeWithBasePath($tempDir, [
            'cache' => [
                'default' => 'file',
                'stores' => [
                    'file' => ['driver' => 'file'],
                ],
            ],
        ]);

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $location = $issues[0]->location;
        $this->assertNotNull($location);
        $this->assertSame('config/cache.php', $location->file);
        $this->assertNotNull($location->line);

        $lines = file($tempDir.'/config/cache.php', FILE_IGNORE_NEW_LINES);
        $this->assertIsArray($lines);
        $this->assertStringContainsString("'driver' => 'file'", $lines[$location->line - 1]);
    }

    public function test_is_not_run_in_ci_mode(): void
    {
        $this->assertFalse(CacheDriverAnalyzer::$runInCI);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function productionOrStagingProvider(): array
    {
        return [
            'production' => ['production', 'production'],
            'staging' => ['staging', 'staging'],
        ];
    }

    /**
     * Env::get() turns CACHE_STORE=null into PHP null, which Laravel resolves to the
     * null store, so caching is disabled rather than unconfigured.
     *
     * @dataProvider productionOrStagingProvider
     */
    #[DataProvider('productionOrStagingProvider')]
    public function test_fails_when_cache_default_is_null_in_production_or_staging(string $env, string $expectedEnvironment): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => $env,
            ],
            'cache' => [
                'default' => null,
            ],
        ]);

        $this->assertTrue($analyzer->shouldRun());

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache driver is set to null - caching is disabled', $result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(Severity::Critical, $issues[0]->severity);
        $this->assertStringContainsString('CACHE_STORE', $issues[0]->recommendation);
        $this->assertSame($expectedEnvironment, $issues[0]->metadata['environment'] ?? null);
    }

    /**
     * Controls: the severities the per-driver assessments already emit.
     *
     * @return array<string, array{string, Severity}>
     */
    public static function existingDriverSeverityProvider(): array
    {
        return [
            'array' => ['array', Severity::Critical],
            'file' => ['file', Severity::High],
            'database' => ['database', Severity::High],
            'custom' => ['custom', Severity::Low],
        ];
    }

    /**
     * @dataProvider existingDriverSeverityProvider
     */
    #[DataProvider('existingDriverSeverityProvider')]
    public function test_existing_driver_severities_in_production(string $driver, Severity $severity): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'main',
                'stores' => [
                    'main' => ['driver' => $driver],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame($severity, $issues[0]->severity);
    }

    public function test_custom_driver_is_reported_as_unsupported(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'custom',
                'stores' => [
                    'custom' => ['driver' => 'mongo'],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining("Cache driver 'mongo' is unsupported by ShieldCI", $result);
    }

    /**
     * @return array<string, array{string, Severity|null}>
     */
    public static function sessionDriverProvider(): array
    {
        return [
            'production' => ['production', Severity::High],
            'staging' => ['staging', Severity::High],
            'local' => ['local', null],
            'testing' => ['testing', null],
        ];
    }

    /**
     * The session driver scopes the cache to each user, so rate limiters reset with the
     * cookie and CLI or queue workers get a cache that lives for one process.
     *
     * @dataProvider sessionDriverProvider
     */
    #[DataProvider('sessionDriverProvider')]
    public function test_grades_session_driver_by_environment(string $env, ?Severity $severity): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => $env,
            ],
            'cache' => [
                'default' => 'session',
                'stores' => [
                    'session' => ['driver' => 'session', 'key' => '_cache'],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        if ($severity === null) {
            $this->assertPassed($result);

            return;
        }

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache driver is set to session - cache is scoped to each user session', $result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame($severity, $issues[0]->severity);
        $this->assertSame('session', $issues[0]->metadata['driver'] ?? null);
        $this->assertStringContainsStringIgnoringCase('redis', $issues[0]->recommendation);
    }

    /**
     * @return array<string, array{string, string|null, Severity|null, string|null}>
     */
    public static function failoverPrimaryProvider(): array
    {
        return [
            'database primary' => ['database', 'production', Severity::High, 'Database cache driver in production environment'],
            'file primary' => ['file', 'production', Severity::High, 'File cache driver in production environment'],
            'array primary' => ['array', 'production', Severity::Critical, 'Cache driver is set to array - cache not persisted'],
            'array primary in staging' => ['array', 'staging', Severity::Critical, 'Cache driver is set to array - cache not persisted'],
            'custom primary' => ['mongo', 'production', Severity::Low, "Cache driver 'mongo' is unsupported by ShieldCI"],
            'session primary' => ['session', 'production', Severity::High, 'Cache driver is set to session - cache is scoped to each user session'],
            'session primary in local' => ['session', 'local', null, null],
            'redis primary' => ['redis', 'production', null, null],
            'memcached primary' => ['memcached', 'production', null, null],
            'database primary in local' => ['database', 'local', null, null],
            'array primary in local' => ['array', 'local', null, null],
        ];
    }

    /**
     * @dataProvider failoverPrimaryProvider
     */
    #[DataProvider('failoverPrimaryProvider')]
    public function test_grades_failover_store_by_its_primary_store(string $primaryDriver, string $env, ?Severity $severity, ?string $assessment): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => $env,
            ],
            'cache' => [
                'default' => 'failover',
                'stores' => [
                    'primary' => ['driver' => $primaryDriver],
                    'backup' => ['driver' => 'redis'],
                    'failover' => [
                        'driver' => 'failover',
                        'stores' => ['primary', 'backup'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        if ($severity === null) {
            $this->assertPassed($result);

            return;
        }

        $this->assertNotNull($assessment);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame($severity, $issues[0]->severity);
        $this->assertStringContainsString("Failover cache store 'failover'", $issues[0]->message);
        $this->assertStringContainsString("'primary'", $issues[0]->message);
        $this->assertStringContainsString($assessment, $issues[0]->message);
        $this->assertStringContainsString("'primary'", $issues[0]->recommendation);
        $this->assertSame('failover', $issues[0]->metadata['store'] ?? null);
        $this->assertSame('primary', $issues[0]->metadata['primary_store'] ?? null);
        $this->assertSame($primaryDriver, $issues[0]->metadata['driver'] ?? null);
    }

    public function test_grades_the_framework_failover_store_by_database(): void
    {
        // The shape config/cache.php ships: database first, array as the fallback.
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'failover',
                'stores' => [
                    'database' => ['driver' => 'database', 'table' => 'cache'],
                    'array' => ['driver' => 'array', 'serialize' => false],
                    'failover' => [
                        'driver' => 'failover',
                        'stores' => ['database', 'array'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database cache driver', $result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    public function test_failover_primary_is_the_first_value_of_a_keyed_stores_array(): void
    {
        // FailoverStore iterates the values in order, so the keys are irrelevant.
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'failover',
                'stores' => [
                    'database' => ['driver' => 'database'],
                    'failover' => [
                        'driver' => 'failover',
                        'stores' => ['first' => 'database', 'second' => 'redis'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database cache driver', $result);
    }

    public function test_failover_reads_the_primary_dynamodb_store_table(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'failover',
                'stores' => [
                    'dynamodb' => ['driver' => 'dynamodb', 'table' => 'cache'],
                    'failover' => [
                        'driver' => 'failover',
                        'stores' => ['dynamodb', 'redis'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_grades_nested_failover_store_by_the_innermost_primary(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'outer',
                'stores' => [
                    'array' => ['driver' => 'array'],
                    'inner' => [
                        'driver' => 'failover',
                        'stores' => ['array', 'redis'],
                    ],
                    'outer' => [
                        'driver' => 'failover',
                        'stores' => ['inner', 'redis'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(Severity::Critical, $issues[0]->severity);
        $this->assertStringContainsString("Failover cache store 'outer'", $issues[0]->message);
        $this->assertStringContainsString("'array'", $issues[0]->message);
        $this->assertSame('array', $issues[0]->metadata['primary_store'] ?? null);
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function failoverCycleProvider(): array
    {
        return [
            'self reference' => [[
                'loop' => ['driver' => 'failover', 'stores' => ['loop', 'redis']],
            ]],
            'two-store cycle' => [[
                'loop' => ['driver' => 'failover', 'stores' => ['other', 'redis']],
                'other' => ['driver' => 'failover', 'stores' => ['loop', 'redis']],
            ]],
        ];
    }

    /**
     * @dataProvider failoverCycleProvider
     *
     * @param  array<string, mixed>  $stores
     */
    #[DataProvider('failoverCycleProvider')]
    public function test_fails_when_failover_primary_stores_form_a_cycle(array $stores): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'loop',
                'stores' => $stores,
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining("Failover cache store 'loop' has a cycle in its primary stores", $result);
        $this->assertSame(Severity::Critical, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function failoverWithoutStoresProvider(): array
    {
        return [
            'missing stores' => [['driver' => 'failover']],
            'empty stores' => [['driver' => 'failover', 'stores' => []]],
            'string stores' => [['driver' => 'failover', 'stores' => 'redis']],
        ];
    }

    /**
     * @dataProvider failoverWithoutStoresProvider
     *
     * @param  array<string, mixed>  $failover
     */
    #[DataProvider('failoverWithoutStoresProvider')]
    public function test_fails_when_failover_store_lists_no_stores(array $failover): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'failover',
                'stores' => [
                    'failover' => $failover,
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining("Failover cache store 'failover' does not list any stores", $result);

        // The default store itself: nothing catches the failure, so every operation throws.
        $this->assertSame(Severity::Critical, $result->getIssues()[0]->severity);
        $this->assertStringContainsString('every cache read and write fails at runtime', $result->getIssues()[0]->recommendation);
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function nestedFailoverWithoutStoresProvider(): array
    {
        return [
            'missing stores' => [['driver' => 'failover']],
            'empty stores' => [['driver' => 'failover', 'stores' => []]],
            'string stores' => [['driver' => 'failover', 'stores' => 'redis']],
        ];
    }

    /**
     * The outer FailoverStore catches whatever the empty inner store throws and serves
     * from its next member, so the cache works at the cost of one failed attempt.
     *
     * @dataProvider nestedFailoverWithoutStoresProvider
     *
     * @param  array<string, mixed>  $inner
     */
    #[DataProvider('nestedFailoverWithoutStoresProvider')]
    public function test_nested_failover_primary_without_stores_is_graded_high(array $inner): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'outer',
                'stores' => [
                    'redis' => ['driver' => 'redis'],
                    'inner' => $inner,
                    'outer' => [
                        'driver' => 'failover',
                        'stores' => ['inner', 'redis'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining("Failover cache store 'inner' does not list any stores", $result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(Severity::High, $issues[0]->severity);
        $this->assertStringNotContainsString('every cache read and write fails', $issues[0]->recommendation);
        $this->assertStringContainsString("'outer'", $issues[0]->recommendation);
    }

    /**
     * @param  array<string, mixed>  $stores
     * @param  array<string, mixed>  $filesystems
     */
    private function analyzeFailover(array $stores, array $filesystems = []): ResultInterface
    {
        return $this->createAnalyzer([
            'cache' => [
                'default' => 'f',
                'stores' => $stores,
            ],
            'filesystems' => $filesystems,
        ])->analyze();
    }

    public function test_failover_with_only_an_undefined_member_is_critical(): void
    {
        $result = $this->analyzeFailover([
            'f' => ['driver' => 'failover', 'stores' => ['missing']],
        ]);

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame("Failover cache store 'f' lists primary store 'missing', which is not defined in cache configuration", $issues[0]->message);
        $this->assertSame(Severity::Critical, $issues[0]->severity);
        $this->assertStringContainsString('every cache read and write fails at runtime', $issues[0]->recommendation);
    }

    public function test_failover_led_only_by_an_empty_nested_failover_is_critical(): void
    {
        $result = $this->createAnalyzer([
            'cache' => [
                'default' => 'a',
                'stores' => [
                    'a' => ['driver' => 'failover', 'stores' => ['b']],
                    'b' => ['driver' => 'failover', 'stores' => []],
                ],
            ],
        ])->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame("Failover cache store 'b' does not list any stores", $issues[0]->message);
        $this->assertSame(Severity::Critical, $issues[0]->severity);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function brokenPrimaryFallbackProvider(): array
    {
        return [
            'array fallback' => ['array', 'Cache driver is set to array - cache not persisted'],
            'null fallback' => ['null', 'Cache driver is set to null - caching is disabled'],
        ];
    }

    /**
     * FailoverStore serves every operation from the first member that does not throw,
     * so that member is graded, not just the broken one in front of it.
     *
     * @dataProvider brokenPrimaryFallbackProvider
     */
    #[DataProvider('brokenPrimaryFallbackProvider')]
    public function test_failover_grades_the_member_serving_behind_an_undefined_primary(string $fallback, string $assessment): void
    {
        $result = $this->analyzeFailover([
            $fallback => ['driver' => $fallback],
            'f' => ['driver' => 'failover', 'stores' => ['missing', $fallback]],
        ]);

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(2, $issues);

        $this->assertSame("Failover cache store 'f' lists primary store 'missing', which is not defined in cache configuration", $issues[0]->message);
        $this->assertSame(Severity::High, $issues[0]->severity);
        $this->assertStringNotContainsString('every cache read and write fails', $issues[0]->recommendation);

        $this->assertSame("Failover cache store 'f' falls back to store '{$fallback}' on every operation: {$assessment}", $issues[1]->message);
        $this->assertSame(Severity::Critical, $issues[1]->severity);
        $this->assertSame($fallback, $issues[1]->metadata['primary_store'] ?? null);
    }

    public function test_failover_reports_each_broken_member_before_the_serving_one(): void
    {
        $result = $this->analyzeFailover([
            'f' => ['driver' => 'failover', 'stores' => ['missing', 'gone', 'redis']],
        ]);

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
        $this->assertSame("Failover cache store 'f' lists primary store 'missing', which is not defined in cache configuration", $issues[0]->message);
        $this->assertSame("Failover cache store 'f' lists store 'gone', which is not defined in cache configuration", $issues[1]->message);
        $this->assertSame(Severity::High, $issues[0]->severity);
        $this->assertSame(Severity::High, $issues[1]->severity);
    }

    public function test_failover_does_not_grade_members_after_a_usable_primary(): void
    {
        $result = $this->analyzeFailover([
            'f' => ['driver' => 'failover', 'stores' => ['redis', 'missing']],
        ]);

        $this->assertPassed($result);
    }

    public function test_failover_led_by_a_nested_failover_of_broken_members_falls_back(): void
    {
        $result = $this->createAnalyzer([
            'cache' => [
                'default' => 'outer',
                'stores' => [
                    'inner' => ['driver' => 'failover', 'stores' => ['missing']],
                    'outer' => ['driver' => 'failover', 'stores' => ['inner', 'redis']],
                ],
            ],
        ])->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame("Failover cache store 'inner' lists primary store 'missing', which is not defined in cache configuration", $issues[0]->message);
        $this->assertSame(Severity::High, $issues[0]->severity);
        $this->assertStringContainsString("'outer'", $issues[0]->recommendation);
    }

    public function test_failover_led_by_a_storage_store_with_an_undefined_disk_falls_back(): void
    {
        $result = $this->analyzeFailover(
            [
                's' => ['driver' => 'storage', 'disk' => 'nope'],
                'f' => ['driver' => 'failover', 'stores' => ['s', 'redis']],
            ],
            ['default' => 'local', 'disks' => []]
        );

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame("Storage cache store 's' uses disk 'nope', which is not defined in filesystem configuration", $issues[0]->message);
        $this->assertSame(Severity::High, $issues[0]->severity);
        $this->assertStringNotContainsString('every cache read and write fails', $issues[0]->recommendation);
    }

    public function test_failover_grades_an_array_member_behind_a_broken_storage_store(): void
    {
        $result = $this->analyzeFailover(
            [
                's' => ['driver' => 'storage', 'disk' => 'nope'],
                'array' => ['driver' => 'array'],
                'f' => ['driver' => 'failover', 'stores' => ['s', 'array']],
            ],
            ['default' => 'local', 'disks' => []]
        );

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
        $this->assertSame(Severity::High, $issues[0]->severity);
        $this->assertStringContainsString("Storage cache store 's'", $issues[0]->message);
        $this->assertSame("Failover cache store 'f' falls back to store 'array' on every operation: Cache driver is set to array - cache not persisted", $issues[1]->message);
        $this->assertSame(Severity::Critical, $issues[1]->severity);
    }

    /**
     * CacheManager::build() throws "Driver [] is not supported." for an empty driver,
     * such as one read from an unset environment variable, so it is no driver at all.
     */
    public function test_failover_treats_an_empty_driver_member_as_broken(): void
    {
        $result = $this->createAnalyzer([
            'cache' => [
                'default' => 'a',
                'stores' => [
                    'a' => ['driver' => 'failover', 'stores' => ['blank', 'mem']],
                    'blank' => ['driver' => ''],
                    'mem' => ['driver' => 'array'],
                ],
            ],
        ])->analyze();

        $this->assertFailed($result);

        $severities = array_map(fn ($issue) => $issue->severity, $result->getIssues());
        $this->assertSame([Severity::High, Severity::Critical], $severities);
        $this->assertHasIssueContaining("lists primary store 'blank', which is not defined in cache configuration", $result);
    }

    public function test_fails_when_default_store_has_an_empty_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'blank',
                'stores' => [
                    'blank' => ['driver' => ''],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining("Cache store 'blank' is not defined in cache configuration", $result);

        foreach ($result->getIssues() as $issue) {
            $this->assertStringNotContainsString('unsupported by ShieldCI', $issue->message);
        }
    }

    public function test_fails_when_failover_primary_is_not_a_string(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'failover',
                'stores' => [
                    'failover' => [
                        'driver' => 'failover',
                        'stores' => [['redis'], 'redis'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining("Failover cache store 'failover' lists a primary store that is not a string", $result);

        // FailoverStore catches the TypeError and serves from the next store.
        $issues = $result->getIssues();
        $this->assertSame(Severity::High, $issues[0]->severity);
        $this->assertSame('array', $issues[0]->metadata['type'] ?? null);
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function undefinedFailoverPrimaryProvider(): array
    {
        return [
            'primary not defined' => [[]],
            'primary without a driver' => [['missing' => ['table' => 'cache']]],
        ];
    }

    /**
     * @dataProvider undefinedFailoverPrimaryProvider
     *
     * @param  array<string, mixed>  $extraStores
     */
    #[DataProvider('undefinedFailoverPrimaryProvider')]
    public function test_fails_when_failover_primary_is_not_defined(array $extraStores): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'failover',
                'stores' => array_merge($extraStores, [
                    'failover' => [
                        'driver' => 'failover',
                        'stores' => ['missing', 'redis'],
                    ],
                ]),
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining(
            "Failover cache store 'failover' lists primary store 'missing', which is not defined in cache configuration",
            $result
        );

        // FailoverStore catches the failure and serves from the next store, so the cache
        // works at the cost of one failed attempt per operation.
        $issues = $result->getIssues();
        $this->assertSame(Severity::High, $issues[0]->severity);
        $this->assertSame('missing', $issues[0]->metadata['primary_store'] ?? null);
    }

    public function test_misspelled_failover_primary_is_graded_high(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'failover',
                'stores' => [
                    'redis' => ['driver' => 'redis'],
                    'failover' => [
                        'driver' => 'failover',
                        'stores' => ['rediss', 'redis'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining("lists primary store 'rediss', which is not defined in cache configuration", $result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(Severity::High, $issues[0]->severity);
    }

    public function test_fails_when_failover_primary_driver_is_not_a_string(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'failover',
                'stores' => [
                    'broken' => ['driver' => ['redis']],
                    'failover' => [
                        'driver' => 'failover',
                        'stores' => ['broken', 'redis'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining(
            "Failover cache store 'failover' lists primary store 'broken', which has a driver that is not a string",
            $result
        );
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    public function test_grades_failover_store_led_by_a_local_storage_store(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'failover',
                'stores' => [
                    'storage' => ['driver' => 'storage', 'disk' => null],
                    'failover' => [
                        'driver' => 'failover',
                        'stores' => ['storage', 'redis'],
                    ],
                ],
            ],
            'filesystems' => [
                'default' => 'local',
                'disks' => [
                    'local' => ['driver' => 'local'],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining("Failover cache store 'failover'", $result);
        $this->assertHasIssueContaining("Storage cache driver on local disk 'local'", $result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{mixed, string, string, Severity|null}>
     */
    public static function storageDiskProvider(): array
    {
        return [
            'default disk is local' => [null, 'local', 'production', Severity::High],
            'named local disk' => ['cache', 'local', 'production', Severity::High],
            'named local disk in staging' => ['cache', 'local', 'staging', Severity::High],
            'default disk is local in local env' => [null, 'local', 'local', null],
            's3 disk' => ['cache', 's3', 'production', null],
            'sftp disk' => ['cache', 'sftp', 'production', null],
        ];
    }

    /**
     * @dataProvider storageDiskProvider
     */
    #[DataProvider('storageDiskProvider')]
    public function test_grades_storage_store_by_its_disk_driver(mixed $disk, string $diskDriver, string $env, ?Severity $severity): void
    {
        $diskName = is_string($disk) ? $disk : 'default-disk';

        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => $env,
            ],
            'cache' => [
                'default' => 'storage',
                'stores' => [
                    'storage' => ['driver' => 'storage', 'disk' => $disk, 'path' => 'framework/cache/data'],
                ],
            ],
            'filesystems' => [
                'default' => $diskName,
                'disks' => [
                    $diskName => ['driver' => $diskDriver],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        if ($severity === null) {
            $this->assertPassed($result);

            return;
        }

        $this->assertFailed($result);
        $this->assertHasIssueContaining("Storage cache driver on local disk '{$diskName}' in {$env} environment", $result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame($severity, $issues[0]->severity);
        $this->assertSame('storage', $issues[0]->metadata['driver'] ?? null);
        $this->assertSame($diskName, $issues[0]->metadata['disk'] ?? null);
    }

    /**
     * @return array<string, array{mixed, mixed}>
     */
    public static function storageWithoutDiskProvider(): array
    {
        return [
            'no disk and no default disk' => [null, null],
            'empty disk falls back to a missing default disk' => ['', null],
            'non-string disk' => [['local'], 'local'],
        ];
    }

    /**
     * @dataProvider storageWithoutDiskProvider
     */
    #[DataProvider('storageWithoutDiskProvider')]
    public function test_fails_when_storage_store_names_no_disk(mixed $disk, mixed $defaultDisk): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'storage',
                'stores' => [
                    'storage' => ['driver' => 'storage', 'disk' => $disk],
                ],
            ],
            'filesystems' => [
                'default' => $defaultDisk,
                'disks' => [
                    'local' => ['driver' => 'local'],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining("Storage cache store 'storage' does not name a filesystem disk", $result);
        $this->assertSame(Severity::Critical, $result->getIssues()[0]->severity);
    }

    /**
     * FilesystemManager::disk() falls back on any empty name, and the shipped store reads
     * an unset CACHE_STORAGE_DISK as an empty string.
     */
    public function test_storage_store_with_an_empty_disk_uses_the_default_disk(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'storage',
                'stores' => [
                    'storage' => ['driver' => 'storage', 'disk' => ''],
                ],
            ],
            'filesystems' => [
                'default' => 's3',
                'disks' => [
                    's3' => ['driver' => 's3'],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_failover_led_by_a_storage_store_with_an_empty_disk_uses_the_default_disk(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'failover',
                'stores' => [
                    'storage' => ['driver' => 'storage', 'disk' => ''],
                    'failover' => [
                        'driver' => 'failover',
                        'stores' => ['storage', 'redis'],
                    ],
                ],
            ],
            'filesystems' => [
                'default' => 's3',
                'disks' => [
                    's3' => ['driver' => 's3'],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_storage_store_with_an_empty_disk_grades_a_local_default_disk(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'storage',
                'stores' => [
                    'storage' => ['driver' => 'storage', 'disk' => ''],
                ],
            ],
            'filesystems' => [
                'default' => 'local',
                'disks' => [
                    'local' => ['driver' => 'local'],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining("Storage cache driver on local disk 'local' in production environment", $result);
    }

    /**
     * CacheManager::getConfig() resolves the store name 'null' to the null driver
     * whether or not config/cache.php defines it.
     */
    public function test_undefined_null_store_passes_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'cache' => [
                'default' => 'null',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_undefined_null_store_reports_caching_disabled_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'null',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache driver is set to null - caching is disabled', $result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(Severity::Critical, $issues[0]->severity);
    }

    public function test_failover_led_by_an_undefined_null_store_passes_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'cache' => [
                'default' => 'failover',
                'stores' => [
                    'failover' => [
                        'driver' => 'failover',
                        'stores' => ['null', 'redis'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_failover_led_by_an_undefined_null_store_reports_caching_disabled_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'failover',
                'stores' => [
                    'failover' => [
                        'driver' => 'failover',
                        'stores' => ['null', 'redis'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining("Failover cache store 'failover' uses store 'null' as its primary: Cache driver is set to null - caching is disabled", $result);
        $this->assertSame(Severity::Critical, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function undefinedStorageDiskProvider(): array
    {
        return [
            'disk not defined' => [[]],
            'disk without a driver' => [['cache' => ['root' => '/tmp']]],
            'disk with a non-string driver' => [['cache' => ['driver' => ['local']]]],
        ];
    }

    /**
     * @dataProvider undefinedStorageDiskProvider
     *
     * @param  array<string, mixed>  $disks
     */
    #[DataProvider('undefinedStorageDiskProvider')]
    public function test_fails_when_storage_disk_is_not_defined(array $disks): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'storage',
                'stores' => [
                    'storage' => ['driver' => 'storage', 'disk' => 'cache'],
                ],
            ],
            'filesystems' => [
                'default' => 'local',
                'disks' => $disks,
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining(
            "Storage cache store 'storage' uses disk 'cache', which is not defined in filesystem configuration",
            $result
        );
        $this->assertSame(Severity::Critical, $result->getIssues()[0]->severity);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
