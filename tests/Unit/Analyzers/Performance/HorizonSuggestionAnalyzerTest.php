<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Mockery;
use ShieldCI\Analyzers\Performance\HorizonSuggestionAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class HorizonSuggestionAnalyzerTest extends AnalyzerTestCase
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
                'env' => 'production',
            ],
            'queue' => [
                'default' => 'redis',
                'connections' => [
                    'redis' => [
                        'driver' => 'redis',
                        'connection' => 'default',
                        'queue' => 'default',
                        'retry_after' => 90,
                        'block_for' => null,
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

        return new HorizonSuggestionAnalyzer($config);
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('horizon-suggestion', $metadata->id);
        $this->assertEquals('Horizon Suggestion', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $metadata->severity);
        $this->assertContains('queue', $metadata->tags);
        $this->assertContains('horizon', $metadata->tags);
        $this->assertContains('redis', $metadata->tags);
    }

    public function test_skips_when_queue_driver_is_not_redis(): void
    {
        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 'database',
                'connections' => [
                    'database' => [
                        'driver' => 'database',
                        'table' => 'jobs',
                        'queue' => 'default',
                        'retry_after' => 90,
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('database', $analyzer->getSkipReason());
    }

    public function test_skips_when_using_sync_driver(): void
    {
        $analyzer = $this->createAnalyzer([
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

        $this->assertSkipped($result);
        $this->assertStringContainsString('sync', $analyzer->getSkipReason());
    }

    public function test_skips_when_using_sqs_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 'sqs',
                'connections' => [
                    'sqs' => [
                        'driver' => 'sqs',
                        'key' => 'your-public-key',
                        'secret' => 'your-secret-key',
                        'queue' => 'your-queue-url',
                        'region' => 'us-east-1',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('sqs', $analyzer->getSkipReason());
    }

    public function test_skips_when_queue_default_is_not_configured(): void
    {
        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => null,
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('not configured', $analyzer->getSkipReason());
    }

    public function test_warns_when_horizon_not_installed_with_redis_queue(): void
    {
        // This test assumes Horizon is NOT installed in the test environment
        // If Horizon is installed, this test will fail
        if (class_exists(\Laravel\Horizon\Horizon::class)) {
            $this->markTestSkipped('Horizon is installed, skipping test for missing Horizon');
        }

        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 'redis',
                'connections' => [
                    'redis' => [
                        'driver' => 'redis',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Horizon', $result);
        $this->assertHasIssueContaining('not installed', $result);
    }

    public function test_passes_when_horizon_is_installed(): void
    {
        // This test only runs if Horizon IS installed
        if (! class_exists(\Laravel\Horizon\Horizon::class)) {
            $this->markTestSkipped('Horizon is not installed, skipping test for installed Horizon');
        }

        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 'redis',
                'connections' => [
                    'redis' => [
                        'driver' => 'redis',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('Horizon is installed', $result->getMessage());
    }

    public function test_issue_contains_correct_metadata(): void
    {
        if (class_exists(\Laravel\Horizon\Horizon::class)) {
            $this->markTestSkipped('Horizon is installed, skipping test for missing Horizon');
        }

        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 'redis',
                'connections' => [
                    'redis' => [
                        'driver' => 'redis',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $issue->severity);
        $this->assertStringContainsString('queue.php', $issue->location->file);

        $metadata = $issue->metadata;
        $this->assertEquals('redis', $metadata['queue_driver']);
        $this->assertEquals('redis', $metadata['default_connection']);
        $this->assertFalse($metadata['horizon_installed']);
    }

    public function test_issue_contains_installation_instructions(): void
    {
        if (class_exists(\Laravel\Horizon\Horizon::class)) {
            $this->markTestSkipped('Horizon is installed, skipping test for missing Horizon');
        }

        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 'redis',
                'connections' => [
                    'redis' => [
                        'driver' => 'redis',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $issue = $issues[0];

        $this->assertStringContainsString('composer require laravel/horizon', $issue->recommendation);
        $this->assertStringContainsString('php artisan horizon:install', $issue->recommendation);
    }

    public function test_works_with_custom_redis_connection_name(): void
    {
        if (class_exists(\Laravel\Horizon\Horizon::class)) {
            $this->markTestSkipped('Horizon is installed, skipping test for missing Horizon');
        }

        $analyzer = $this->createAnalyzer([
            'queue' => [
                'default' => 'my_custom_redis',
                'connections' => [
                    'my_custom_redis' => [
                        'driver' => 'redis',
                        'connection' => 'cache',
                        'queue' => 'high-priority',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $metadata = $issues[0]->metadata;

        $this->assertEquals('redis', $metadata['queue_driver']);
        $this->assertEquals('my_custom_redis', $metadata['default_connection']);
    }

    public function test_recommendation_mentions_key_features(): void
    {
        if (class_exists(\Laravel\Horizon\Horizon::class)) {
            $this->markTestSkipped('Horizon is installed, skipping test for missing Horizon');
        }

        $analyzer = $this->createAnalyzer();
        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $recommendation = $issues[0]->recommendation;

        $this->assertStringContainsString('dashboard', $recommendation);
        $this->assertStringContainsString('monitoring', $recommendation);
    }
}
