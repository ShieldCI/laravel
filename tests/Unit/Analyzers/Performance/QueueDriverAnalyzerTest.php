<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Mockery;
use ShieldCI\Analyzers\Performance\QueueDriverAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class QueueDriverAnalyzerTest extends AnalyzerTestCase
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
            'queue' => [
                'default' => 'redis',
                'connections' => [
                    'redis' => [
                        'driver' => 'redis',
                        'connection' => 'default',
                        'queue' => 'default',
                    ],
                ],
            ],
        ];

        $configMap = array_replace_recursive($defaults, $configValues);

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) use ($configMap) {
                // Handle dotted key access (e.g., 'queue.connections.redis.driver')
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

        return new QueueDriverAnalyzer($config);
    }

    public function test_passes_with_redis_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 'redis',
                'connections' => [
                    'redis' => [
                        'driver' => 'redis',
                        'connection' => 'default',
                        'queue' => 'default',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('redis', $result->getMessage());
        $this->assertStringContainsString('properly configured', $result->getMessage());
    }

    public function test_passes_with_sqs_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 'sqs',
                'connections' => [
                    'sqs' => [
                        'driver' => 'sqs',
                        'key' => 'your-key',
                        'secret' => 'your-secret',
                        'queue' => 'your-queue-url',
                        'region' => 'us-east-1',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('sqs', $result->getMessage());
    }

    public function test_fails_with_null_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 'null',
                'connections' => [
                    'null' => [
                        'driver' => 'null',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('null', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
        $this->assertStringContainsString('silently discards', $issues[0]->recommendation);
    }

    public function test_fails_with_sync_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'production',
            ],
            'queue' => [
                'default' => 'sync',
                'connections' => [
                    'sync' => [
                        'driver' => 'sync',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('sync', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
        $this->assertStringContainsString('synchronous manner', $issues[0]->recommendation);
        $this->assertEquals('production', $issues[0]->metadata['environment'] ?? '');
    }

    public function test_warns_about_sync_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'queue' => [
                'default' => 'sync',
                'connections' => [
                    'sync' => [
                        'driver' => 'sync',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        // Lower severity in local
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $issues[0]->severity);
        $this->assertStringContainsString('acceptable for development', $issues[0]->recommendation);
        $this->assertEquals('local', $issues[0]->metadata['environment'] ?? '');
    }

    public function test_passes_about_sync_driver_in_testing(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'testing',
            ],
            'queue' => [
                'default' => 'sync',
                'connections' => [
                    'sync' => [
                        'driver' => 'sync',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('testing environment', $result->getMessage());
    }

    public function test_warns_about_database_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'production',
            ],
            'queue' => [
                'default' => 'database',
                'connections' => [
                    'database' => [
                        'driver' => 'database',
                        'table' => 'jobs',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('database', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $issues[0]->severity);
        $this->assertStringContainsString('deadlocks', $issues[0]->recommendation);
    }

    public function test_passes_with_database_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'queue' => [
                'default' => 'database',
                'connections' => [
                    'database' => [
                        'driver' => 'database',
                        'table' => 'jobs',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        // Database is acceptable in local, should pass
        $this->assertPassed($result);
    }

    public function test_passes_with_database_driver_in_testing(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'testing',
            ],
            'queue' => [
                'default' => 'database',
                'connections' => [
                    'database' => [
                        'driver' => 'database',
                        'table' => 'jobs',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('database', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $issues[0]->severity);
        $this->assertEquals('testing', $issues[0]->metadata['environment'] ?? '');
    }

    public function test_fails_when_connection_not_defined(): void
    {
        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 'nonexistent',
                'connections' => [
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
        $this->assertEquals('nonexistent', $issues[0]->metadata['connection'] ?? '');
    }

    public function test_fails_when_default_connection_is_not_string(): void
    {
        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 123,
                'connections' => [
                    'redis' => [
                        'driver' => 'redis',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('default connection is not configured', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertSame(123, $issues[0]->metadata['connection'] ?? null);
    }

    public function test_errors_when_driver_is_not_string(): void
    {
        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 'redis',
                'connections' => [
                    'redis' => [
                        'driver' => ['not-a-string'],
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('driver is not a string', $result->getMessage());
    }

    public function test_skips_when_queue_config_not_found(): void
    {
        /** @var QueueDriverAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => null,
            ],
        ]);

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString('not found', $analyzer->getSkipReason());
    }

    public function test_does_not_skip_in_local_without_config(): void
    {
        /** @var QueueDriverAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'shieldci' => [
                'skip_env_specific' => false, // Explicitly disabled
            ],
            'queue' => [
                'default' => 'sync',
                'connections' => [
                    'sync' => [
                        'driver' => 'sync',
                    ],
                ],
            ],
        ]);

        // Should run because skip_env_specific is false
        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('queue-driver', $metadata->id);
        $this->assertEquals('Queue Driver Configuration', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $metadata->severity);
        $this->assertContains('queue', $metadata->tags);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
