<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Mockery;
use ShieldCI\Analyzers\Performance\CacheDriverAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CacheDriverAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $configValues
     */
    protected function createAnalyzer(array $configValues = []): AnalyzerInterface
    {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
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

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
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

    public function test_skips_when_cache_default_is_null(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => null,
            ],
        ]);

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString('not configured', $analyzer->getSkipReason());
    }

    public function test_errors_when_cache_default_is_not_string(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 123,
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertEquals('error', $result->getStatus()->value);
        $this->assertStringContainsString('not configured properly', $result->getMessage());
    }

    public function test_errors_when_cache_default_is_array(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => ['redis', 'memcached'],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertEquals('error', $result->getStatus()->value);
        $this->assertStringContainsString('not configured properly', $result->getMessage());
    }

    public function test_errors_when_driver_is_not_string(): void
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

        $this->assertEquals('error', $result->getStatus()->value);
        $this->assertStringContainsString('driver is not a string', $result->getMessage());
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
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

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
