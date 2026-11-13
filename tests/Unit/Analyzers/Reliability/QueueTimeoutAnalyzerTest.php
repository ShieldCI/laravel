<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\Reliability\QueueTimeoutAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class QueueTimeoutAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new QueueTimeoutAnalyzer;
    }

    /** @test */
    #[Test]
    public function test_returns_warning_when_no_config_file(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('Unable to read queue configuration', $result->getMessage());
    }

    /** @test */
    #[Test]
    public function test_passes_with_proper_configuration(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'default',
            'retry_after' => 150,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('Queue timeout configurations are correct', $result->getMessage());
    }

    /** @test */
    #[Test]
    public function test_fails_when_timeout_equals_retry_after(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'default',
            'retry_after' => 60,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Timeout is 60 (default) and retry_after is 60, so it should fail
        $this->assertFailed($result);
        $this->assertStringContainsString('Found 1 queue configuration issue', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertSame("Queue connection 'redis' has improper timeout configuration", $issue->message);
        $this->assertSame(Severity::High, $issue->severity);
    }

    /** @test */
    #[Test]
    public function test_fails_when_timeout_exceeds_retry_after(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'default',
            'retry_after' => 45,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertStringContainsString('timeout', $issue->recommendation);
        $this->assertStringContainsString('retry_after', $issue->recommendation);
    }

    /** @test */
    #[Test]
    public function test_skips_sync_driver(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'sync',
    'connections' => [
        'sync' => [
            'driver' => 'sync',
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_skips_sqs_driver(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'sqs',
    'connections' => [
        'sqs' => [
            'driver' => 'sqs',
            'key' => 'your-public-key',
            'secret' => 'your-secret-key',
            'prefix' => 'https://sqs.us-east-1.amazonaws.com/your-account-id',
            'queue' => 'your-queue-name',
            'region' => 'us-east-1',
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_checks_database_driver(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'database',
    'connections' => [
        'database' => [
            'driver' => 'database',
            'table' => 'jobs',
            'queue' => 'default',
            'retry_after' => 60,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because timeout (60) >= retry_after (60)
        $this->assertFailed($result);
    }

    /** @test */
    #[Test]
    public function test_checks_beanstalkd_driver(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'beanstalkd',
    'connections' => [
        'beanstalkd' => [
            'driver' => 'beanstalkd',
            'host' => 'localhost',
            'queue' => 'default',
            'retry_after' => 90,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass because retry_after (90) > timeout (60)
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_handles_multiple_connections(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'default',
            'retry_after' => 150,
        ],
        'database' => [
            'driver' => 'database',
            'table' => 'jobs',
            'queue' => 'default',
            'retry_after' => 50,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because database connection has retry_after (50) < timeout (60)
        $this->assertFailed($result);
        $this->assertStringContainsString('Found 1 queue configuration issue', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $metadata = $issue->metadata;
        $this->assertSame('database', $metadata['connection']);
        $this->assertSame('database', $metadata['driver']);
    }

    /** @test */
    #[Test]
    public function test_includes_proper_metadata(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'default',
            'retry_after' => 55,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $issue = $issues[0];
        $metadata = $issue->metadata;

        $this->assertArrayHasKey('connection', $metadata);
        $this->assertArrayHasKey('driver', $metadata);
        $this->assertArrayHasKey('timeout', $metadata);
        $this->assertArrayHasKey('retry_after', $metadata);

        $this->assertSame('redis', $metadata['connection']);
        $this->assertSame('redis', $metadata['driver']);
        $this->assertSame(60, $metadata['timeout']);
        $this->assertSame(55, $metadata['retry_after']);
    }

    /** @test */
    #[Test]
    public function test_recommendation_message_format(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'default',
            'retry_after' => 60,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $issue = $issues[0];
        $recommendation = $issue->recommendation;

        $this->assertStringContainsString('retry_after', $recommendation);
        $this->assertStringContainsString('timeout', $recommendation);
        $this->assertStringContainsString('redis', $recommendation);
        $this->assertStringContainsString('60 seconds', $recommendation);
        $this->assertStringContainsString('processed twice', $recommendation);
    }

    /** @test */
    #[Test]
    public function test_uses_default_retry_after_when_not_specified(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'default',
            // No retry_after: RedisConnector falls back to 60
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // retry_after (60) equals the default worker timeout (60)
        $this->assertFailed($result);
        $this->assertSame(60, $result->getIssues()[0]->metadata['retry_after']);
    }

    /** @test */
    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('queue-timeout-configuration', $metadata->id);
        $this->assertSame('Queue Timeout Configuration Analyzer', $metadata->name);
        $this->assertSame(Severity::High, $metadata->severity);
        $this->assertSame(10, $metadata->timeToFix);
        $this->assertContains('queue', $metadata->tags);
        $this->assertContains('configuration', $metadata->tags);
        $this->assertContains('reliability', $metadata->tags);
        $this->assertContains('jobs', $metadata->tags);
    }

    /** @test */
    #[Test]
    public function test_handles_invalid_connections_gracefully(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'retry_after' => 150,
        ],
        'invalid' => 'not-an-array',
        123 => [
            'driver' => 'database',
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - only valid connections are checked
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_handles_malformed_config_file(): void
    {
        $queueConfig = <<<'PHP'
<?php

return 'not-an-array';
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
    }

    /** @test */
    #[Test]
    public function test_handles_missing_driver_field(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'custom',
    'connections' => [
        'custom' => [
            // Missing driver field
            'connection' => 'default',
            'queue' => 'default',
            'retry_after' => 30,
        ],
        'blank' => [
            'driver' => '',
            'queue' => 'default',
            'retry_after' => 30,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Laravel cannot build a connection without a driver, so neither is graded
        // (retry_after 30 would fail against the 60s timeout if it were).
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_enforces_minimum_buffer_requirement(): void
    {
        // timeout=60 (default), retry_after=65, buffer=10
        // 60 + 10 = 70, which is >= 65, so should fail
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'default',
            'retry_after' => 65,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because buffer is only 5 seconds (less than 10 second minimum)
        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $metadata = $issue->metadata;

        // Verify buffer information is in metadata
        $this->assertArrayHasKey('minimum_buffer', $metadata);
        $this->assertSame(10, $metadata['minimum_buffer']);
        $this->assertArrayHasKey('actual_buffer', $metadata);
        $this->assertSame(5, $metadata['actual_buffer']); // 65 - 60 = 5

        // Verify recommendation mentions the buffer
        $this->assertStringContainsString('at least 70 seconds', $issue->recommendation);
        $this->assertStringContainsString('buffer: 5 seconds', $issue->recommendation);
    }

    /** @test */
    #[Test]
    public function test_passes_with_sufficient_buffer(): void
    {
        // timeout=60 (default), retry_after=71, buffer=10
        // 60 + 10 = 70, which is < 71, so should pass
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'default',
            'retry_after' => 71,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass because buffer is 11 seconds (more than 10 second minimum)
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_extracts_queue_name_from_connection(): void
    {
        // Test that analyzer correctly extracts queue name from connection config
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'fast',  // Specific queue name
            'retry_after' => 65,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail due to insufficient buffer
        $this->assertFailed($result);

        $issues = $result->getIssues();
        $metadata = $issues[0]->metadata;

        // Should include queue_name in metadata
        $this->assertArrayHasKey('queue_name', $metadata);
        $this->assertSame('fast', $metadata['queue_name']);
    }

    /** @test */
    #[Test]
    public function test_redis_without_horizon_config_uses_the_default_assumption(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'default',
            'retry_after' => 65,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $metadata = $result->getIssues()[0]->metadata;

        $this->assertSame(60, $metadata['timeout']);
        $this->assertSame('default_assumption', $metadata['timeout_source']);
        $this->assertArrayHasKey('detection_warning', $metadata);
        $this->assertArrayNotHasKey('horizon_detection', $metadata);
    }

    /** @test */
    #[Test]
    public function test_database_driver_includes_detection_warning(): void
    {
        // Database drivers should include warning about default timeout assumption
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'database',
    'connections' => [
        'database' => [
            'driver' => 'database',
            'table' => 'jobs',
            'queue' => 'default',
            'retry_after' => 65, // Will fail with default timeout=60
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $metadata = $issues[0]->metadata;

        // Should include detection warning
        $this->assertArrayHasKey('detection_warning', $metadata);
        $detectionWarning = $metadata['detection_warning'];
        $this->assertIsString($detectionWarning);
        $this->assertStringContainsString('default timeout (60s)', $detectionWarning);
        $this->assertStringContainsString('CLI (--timeout)', $detectionWarning);
        $this->assertSame('default_assumption', $metadata['timeout_source']);
    }

    /** @test */
    #[Test]
    public function test_beanstalkd_driver_includes_detection_warning(): void
    {
        // Beanstalkd drivers should also include warning
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'beanstalkd',
    'connections' => [
        'beanstalkd' => [
            'driver' => 'beanstalkd',
            'host' => 'localhost',
            'queue' => 'default',
            'retry_after' => 65,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $metadata = $issues[0]->metadata;

        // Should include detection warning
        $this->assertArrayHasKey('detection_warning', $metadata);
        $this->assertSame('default_assumption', $metadata['timeout_source']);
    }

    /** @test */
    #[Test]
    public function test_timeout_source_included_in_metadata(): void
    {
        // Verify timeout_source is always included in metadata
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'queue' => 'default',
            'retry_after' => 65,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $metadata = $issues[0]->metadata;

        // Should have timeout_source
        $this->assertArrayHasKey('timeout_source', $metadata);
        $this->assertIsString($metadata['timeout_source']);
        $this->assertContains($metadata['timeout_source'], [
            'horizon_config',
            'shieldci_config',
            'default_assumption',
        ]);
    }

    /** @test */
    #[Test]
    public function test_locates_the_connection_in_the_queue_config(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'sync' => [
            'driver' => 'sync',
        ],

        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'default',
            'retry_after' => 60,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $location = $result->getIssues()[0]->location;

        $this->assertNotNull($location);
        $this->assertSame('config/queue.php', $location->file);
        $this->assertNotNull($location->line);

        // The reported connection, not the first one in the array and not the file's
        // opening line, which is what a missing-file fallback used to answer.
        $lines = file($tempDir.'/config/queue.php', FILE_IGNORE_NEW_LINES);
        $this->assertIsArray($lines);
        $this->assertStringContainsString("'redis' =>", $lines[$location->line - 1]);
    }

    /**
     * @dataProvider coreDriverWithRetryAfterProvider
     */
    #[DataProvider('coreDriverWithRetryAfterProvider')]
    public function test_core_driver_without_retry_after_uses_the_connector_default_of_60(string $driver): void
    {
        $queueConfig = <<<PHP
<?php

return [
    'connections' => [
        'jobs' => [
            'driver' => '{$driver}',
            'queue' => 'default',
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertSame(60, $result->getIssues()[0]->metadata['retry_after']);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function coreDriverWithRetryAfterProvider(): array
    {
        return [
            'database' => ['database'],
            'beanstalkd' => ['beanstalkd'],
        ];
    }

    /**
     * @dataProvider driverWithoutRetryAfterProvider
     */
    #[DataProvider('driverWithoutRetryAfterProvider')]
    public function test_skips_core_drivers_that_never_read_retry_after(string $driver): void
    {
        // The connector ignores retry_after, so even a value below the timeout changes nothing.
        $queueConfig = <<<PHP
<?php

return [
    'connections' => [
        'jobs' => [
            'driver' => '{$driver}',
            'retry_after' => 30,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function driverWithoutRetryAfterProvider(): array
    {
        return [
            'sync' => ['sync'],
            'sqs' => ['sqs'],
            'null' => ['null'],
            'deferred' => ['deferred'],
            'background' => ['background'],
            'failover' => ['failover'],
        ];
    }

    /** @test */
    #[Test]
    public function test_passes_a_stock_laravel_12_queue_config(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'database',
    'connections' => [
        'sync' => [
            'driver' => 'sync',
        ],
        'database' => [
            'driver' => 'database',
            'connection' => null,
            'table' => 'jobs',
            'queue' => 'default',
            'retry_after' => 90,
            'after_commit' => false,
        ],
        'beanstalkd' => [
            'driver' => 'beanstalkd',
            'host' => 'localhost',
            'queue' => 'default',
            'retry_after' => 90,
            'block_for' => 0,
            'after_commit' => false,
        ],
        'sqs' => [
            'driver' => 'sqs',
            'queue' => 'default',
            'region' => 'us-east-1',
        ],
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'default',
            'retry_after' => 90,
            'block_for' => null,
            'after_commit' => false,
        ],
        'deferred' => [
            'driver' => 'deferred',
        ],
        'background' => [
            'driver' => 'background',
        ],
        'failover' => [
            'driver' => 'failover',
            'connections' => [
                'database',
                'deferred',
            ],
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_skips_custom_driver_without_retry_after(): void
    {
        // A third-party connector's retry_after default is unknown, so there is nothing to grade,
        // even against a worker timeout that no assumed default could clear.
        config(['shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts' => ['custom' => 120]]);

        $queueConfig = <<<'PHP'
<?php

return [
    'connections' => [
        'custom' => [
            'driver' => 'custom-driver',
            'queue' => 'default',
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_grades_custom_driver_with_explicit_retry_after(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'connections' => [
        'custom' => [
            'driver' => 'custom-driver',
            'queue' => 'default',
            'retry_after' => 60,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertSame(60, $result->getIssues()[0]->metadata['retry_after']);
    }

    /** @test */
    #[Test]
    public function test_skips_connection_with_non_numeric_retry_after(): void
    {
        // The queue passes a non-numeric retry_after on unconverted, so there is no runtime value to compare.
        config(['shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts' => ['database' => 85]]);

        $queueConfig = <<<'PHP'
<?php

return [
    'connections' => [
        'database' => [
            'driver' => 'database',
            'queue' => 'default',
            'retry_after' => 'ninety',
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_grades_the_connection_against_every_supervisor_on_it_whatever_queue_it_works(): void
    {
        // retry_after belongs to the connection, so the imports supervisor's 600s jobs on it are re-released too.
        $result = $this->analyzeAgainstHorizon([], [
            'production' => [
                'main' => ['connection' => 'redis', 'queue' => ['default'], 'timeout' => 60],
                'imports' => ['connection' => 'redis', 'queue' => ['imports'], 'timeout' => 600],
            ],
        ]);

        $this->assertFailed($result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame(600, $metadata['timeout']);
        $this->assertSame('matched', $metadata['horizon_detection']);
        $this->assertSame('horizon_config', $metadata['timeout_source']);
    }

    /** @test */
    #[Test]
    public function test_ignores_supervisors_on_another_connection(): void
    {
        $result = $this->analyzeAgainstHorizon([], [
            'production' => [
                'main' => ['connection' => 'redis', 'timeout' => 60],
                'long' => ['connection' => 'redis-long', 'queue' => ['imports'], 'timeout' => 600],
            ],
        ], self::TWO_REDIS_CONNECTIONS);

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_ignores_a_supervisor_on_another_connection_that_works_the_same_queue_name(): void
    {
        $result = $this->analyzeAgainstHorizon([], [
            'production' => [
                'short' => ['connection' => 'redis', 'queue' => ['default'], 'timeout' => 60],
                'long' => ['connection' => 'redis-long', 'queue' => ['default'], 'timeout' => 600],
            ],
        ], [
            'redis' => ['driver' => 'redis', 'queue' => 'default', 'retry_after' => 90],
            'redis-long' => ['driver' => 'redis', 'queue' => 'default', 'retry_after' => 700],
        ]);

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_a_supervisor_without_a_timeout_runs_at_horizons_default_of_60(): void
    {
        // Pins the default rather than "no supervisor": the 200s driver override must not be reached.
        config(['shieldci.analyzers.reliability.queue-timeout-configuration.driver_timeouts' => ['redis' => 200]]);

        $result = $this->analyzeAgainstHorizon([], [
            'production' => [
                'main' => ['connection' => 'redis', 'queue' => ['default']],
                'long' => ['connection' => 'redis-long', 'queue' => ['imports'], 'timeout' => 600],
            ],
        ], [
            'redis' => ['driver' => 'redis', 'queue' => 'default', 'retry_after' => 65],
            'redis-long' => ['driver' => 'redis', 'queue' => 'imports', 'retry_after' => 700],
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame('redis', $metadata['connection']);
        $this->assertSame(60, $metadata['timeout']);
        $this->assertSame('horizon_config', $metadata['timeout_source']);
    }

    /** @test */
    #[Test]
    public function test_falls_through_to_the_default_assumption_when_no_supervisor_is_on_the_connection(): void
    {
        $result = $this->analyzeAgainstHorizon([], [
            'production' => [
                'long' => ['connection' => 'redis-long', 'queue' => ['default'], 'timeout' => 600],
            ],
        ], [
            'redis' => ['driver' => 'redis', 'queue' => 'default', 'retry_after' => 65],
        ]);

        $this->assertFailed($result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame(60, $metadata['timeout']);
        $this->assertSame('default_assumption', $metadata['timeout_source']);
        $this->assertArrayNotHasKey('horizon_detection', $metadata);
    }

    /** @test */
    #[Test]
    public function test_horizon_runs_a_defaults_supervisor_in_an_environment_that_does_not_name_it(): void
    {
        $result = $this->analyzeAgainstHorizon([
            'importer' => ['connection' => 'redis', 'queue' => ['imports'], 'timeout' => 600],
        ], [
            'production' => [],
        ]);

        $this->assertFailed($result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame(600, $metadata['timeout']);
        $this->assertSame('matched', $metadata['horizon_detection']);
    }

    /** @test */
    #[Test]
    public function test_ignores_supervisors_of_other_environments_when_the_current_one_matches(): void
    {
        $result = $this->analyzeAgainstHorizon([], [
            'production' => [
                'mail' => ['connection' => 'redis', 'queue' => ['emails'], 'timeout' => 60],
            ],
            'local' => [
                'importer' => ['connection' => 'redis', 'queue' => ['imports'], 'timeout' => 3600],
            ],
        ]);

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_environment_timeout_overrides_the_defaults_supervisor_of_the_same_name(): void
    {
        $result = $this->analyzeAgainstHorizon([
            'supervisor-1' => ['connection' => 'redis', 'queue' => ['default'], 'timeout' => 60],
        ], [
            'production' => [
                'supervisor-1' => ['timeout' => 300],
            ],
        ]);

        $this->assertFailed($result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame(300, $metadata['timeout']);
        $this->assertSame('matched', $metadata['horizon_detection']);
    }

    /** @test */
    #[Test]
    public function test_defaults_timeout_is_replaced_by_the_environment_timeout(): void
    {
        $result = $this->analyzeAgainstHorizon([
            'supervisor-1' => ['connection' => 'redis', 'queue' => ['default'], 'timeout' => 600],
        ], [
            'production' => [
                'supervisor-1' => ['timeout' => 60],
            ],
        ]);

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_grades_every_environment_when_none_matches_the_current_one(): void
    {
        // CI usually runs as 'testing', which names no Horizon environment, so the
        // deployed one is unknown: every environment's plan is graded, largest timeout wins.
        $result = $this->analyzeAgainstHorizon([
            'supervisor-1' => ['connection' => 'redis', 'queue' => ['default'], 'timeout' => 600],
        ], [
            'production' => [
                'supervisor-1' => ['maxProcesses' => 10],
            ],
            'local' => [
                'supervisor-1' => ['maxProcesses' => 3],
            ],
        ], environment: 'testing');

        $this->assertFailed($result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame(600, $metadata['timeout']);
        $this->assertSame('matched', $metadata['horizon_detection']);
        $this->assertArrayHasKey('detection_warning', $metadata);
    }

    /** @test */
    #[Test]
    public function test_matches_a_wildcard_horizon_environment(): void
    {
        $result = $this->analyzeAgainstHorizon([], [
            '*' => [
                'supervisor-1' => ['connection' => 'redis', 'queue' => ['default'], 'timeout' => 300],
            ],
        ]);

        $this->assertFailed($result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame(300, $metadata['timeout']);
        $this->assertSame('matched', $metadata['horizon_detection']);
        $this->assertArrayNotHasKey('detection_warning', $metadata);
    }

    /** @test */
    #[Test]
    public function test_horizon_env_takes_precedence_over_app_env(): void
    {
        config(['horizon.env' => 'staging']);

        $result = $this->analyzeAgainstHorizon([], [
            'production' => [
                'supervisor-1' => ['connection' => 'redis', 'queue' => ['default'], 'timeout' => 60],
            ],
            'staging' => [
                'supervisor-1' => ['connection' => 'redis', 'queue' => ['default'], 'timeout' => 300],
            ],
        ]);

        $this->assertFailed($result);
        $this->assertSame(300, $result->getIssues()[0]->metadata['timeout']);
    }

    /** @test */
    #[Test]
    public function test_reads_connection_timeouts_by_the_queue_connection_name(): void
    {
        // `queue:work database --timeout=120` names the queue connection, not its inner database connection.
        config(['shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts' => ['database' => 120]]);

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => '<?php return '.var_export(['connections' => [
                'database' => ['driver' => 'database', 'connection' => null, 'queue' => 'default', 'retry_after' => 90],
            ]], true).';',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame(120, $metadata['timeout']);
        $this->assertSame('shieldci_config', $metadata['timeout_source']);
    }

    /** @test */
    #[Test]
    public function test_connection_timeouts_tell_apart_connections_sharing_an_inner_connection(): void
    {
        config(['shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts' => ['redis-long' => 600]]);

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => '<?php return '.var_export(['connections' => [
                'redis' => ['driver' => 'redis', 'connection' => 'default', 'queue' => 'default', 'retry_after' => 90],
                'redis-long' => ['driver' => 'redis', 'connection' => 'default', 'queue' => 'long', 'retry_after' => 300],
            ]], true).';',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame('redis-long', $metadata['connection']);
        $this->assertSame(600, $metadata['timeout']);
    }

    /** @test */
    #[Test]
    public function test_connection_timeouts_still_read_an_entry_keyed_by_the_inner_connection_name(): void
    {
        // Configs written when the lookup used the inner `connection` name keep working.
        config(['shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts' => ['default' => 120]]);

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => '<?php return '.var_export(['connections' => [
                'redis' => ['driver' => 'redis', 'connection' => 'default', 'queue' => 'default', 'retry_after' => 90],
            ]], true).';',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame(120, $metadata['timeout']);
        $this->assertSame('shieldci_config', $metadata['timeout_source']);
    }

    /** @test */
    #[Test]
    public function test_connection_timeouts_prefer_the_queue_connection_name_over_the_inner_name(): void
    {
        config(['shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts' => [
            'redis' => 60,
            'default' => 600,
        ]]);

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => '<?php return '.var_export(['connections' => [
                'redis' => ['driver' => 'redis', 'connection' => 'default', 'queue' => 'default', 'retry_after' => 90],
            ]], true).';',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_connection_timeouts_inner_name_fallback_skips_a_connection_without_an_inner_name(): void
    {
        // The legacy 'default' entry belongs to redis; a database connection with a null
        // inner connection (the default DB connection) must not inherit it.
        config(['shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts' => ['default' => 300]]);

        $tempDir = $this->createTempDirectory([
            'config/queue.php' => '<?php return '.var_export(['connections' => [
                'redis' => ['driver' => 'redis', 'connection' => 'default', 'queue' => 'default', 'retry_after' => 310],
                'database' => ['driver' => 'database', 'connection' => null, 'queue' => 'default', 'retry_after' => 90],
            ]], true).';',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_skips_a_connection_with_a_non_string_driver(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/queue.php' => '<?php return '.var_export(['connections' => [
                'numeric' => ['driver' => 123, 'queue' => 'default', 'retry_after' => 30],
            ]], true).';',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // retry_after 30 would fail against the 60s timeout if it were graded.
        $this->assertPassed($result);
    }

    /**
     * @dataProvider connectionLevelTimeoutKeyProvider
     *
     * @param  array<string, mixed>  $connection
     */
    #[DataProvider('connectionLevelTimeoutKeyProvider')]
    public function test_ignores_a_timeout_key_on_the_queue_connection(array $connection): void
    {
        // No worker reads this key: Redis and Database connectors ignore it, and Beanstalkd
        // passes it to Pheanstalk as the socket timeout. The worker still runs at 60s.
        $tempDir = $this->createTempDirectory([
            'config/queue.php' => '<?php return '.var_export(['connections' => ['c' => $connection]], true).';',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame(60, $metadata['timeout']);
        $this->assertSame('default_assumption', $metadata['timeout_source']);
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function connectionLevelTimeoutKeyProvider(): array
    {
        return [
            'beanstalkd socket timeout' => [
                ['driver' => 'beanstalkd', 'host' => 'localhost', 'queue' => 'default', 'retry_after' => 60, 'timeout' => 5],
            ],
            'redis' => [
                ['driver' => 'redis', 'connection' => 'default', 'queue' => 'default', 'retry_after' => 60, 'timeout' => 45],
            ],
            'database' => [
                ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 60, 'timeout' => 45],
            ],
        ];
    }

    /** @test */
    #[Test]
    public function test_passes_when_retry_after_clears_the_worker_timeout_whatever_the_connection_timeout_key_says(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/queue.php' => '<?php return '.var_export(['connections' => [
                'redis' => ['driver' => 'redis', 'connection' => 'default', 'queue' => 'default', 'retry_after' => 90, 'timeout' => 300],
            ]], true).';',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_recommendation_points_at_where_the_worker_timeout_is_set(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/queue.php' => '<?php return '.var_export(['connections' => [
                'redis' => ['driver' => 'redis', 'connection' => 'default', 'queue' => 'default', 'retry_after' => 60],
            ]], true).';',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $recommendation = $result->getIssues()[0]->recommendation;
        $this->assertStringContainsString('queue:work --timeout', $recommendation);
        $this->assertStringContainsString('Horizon supervisor', $recommendation);
        $this->assertStringNotContainsString('decrease the timeout', $recommendation);
    }

    /** @test */
    #[Test]
    public function test_recommendation_says_an_assumed_timeout_is_an_assumption(): void
    {
        $result = $this->analyzeConnections([
            'database' => ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 65],
        ]);

        $this->assertFailed($result);
        $recommendation = $result->getIssues()[0]->recommendation;
        $this->assertStringStartsWith('The queue retry_after value must be at least 70 seconds', $recommendation);
        $this->assertStringContainsString("assumed to be Laravel's default of 60 seconds", $recommendation);
        $this->assertStringContainsString(
            'shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts in config/shieldci.php',
            $recommendation
        );
        $this->assertStringContainsString('queue:work --timeout', $recommendation);
        $this->assertStringNotContainsString('Horizon', $recommendation);
    }

    /** @test */
    #[Test]
    public function test_recommendation_offers_exactly_two_alternatives_with_a_concrete_timeout(): void
    {
        $result = $this->analyzeConnections([
            'redis' => ['driver' => 'redis', 'queue' => 'default', 'retry_after' => 65],
        ]);

        $this->assertFailed($result);
        $recommendation = $result->getIssues()[0]->recommendation;
        // The whole span from Solution to Recommended, so a third alternative anywhere in it fails.
        $this->assertStringContainsString(
            'Solution: Either increase retry_after to at least 70 seconds, or lower the worker timeout to at most 55 seconds. '.
            "The worker timeout is the queue:work --timeout option, or the Horizon supervisors' timeouts when Horizon runs the workers. ".
            'Recommended: retry_after = timeout + 10 seconds (buffer).',
            $recommendation
        );
    }

    /** @test */
    #[Test]
    public function test_recommendation_omits_lowering_the_timeout_when_no_positive_timeout_would_fit(): void
    {
        // retry_after 5 minus the 10s buffer leaves no positive timeout, and 0 would mean unlimited.
        $result = $this->analyzeConnections([
            'database' => ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 5],
        ]);

        $this->assertFailed($result);
        $recommendation = $result->getIssues()[0]->recommendation;
        $this->assertStringContainsString('Solution: Increase retry_after to at least 70 seconds.', $recommendation);
        $this->assertStringNotContainsString('at most', $recommendation);
        $this->assertStringNotContainsString('lower', $recommendation);
    }

    /** @test */
    #[Test]
    public function test_recommendation_says_a_shieldci_timeout_comes_from_the_shieldci_config(): void
    {
        config(['shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts' => ['database' => 120]]);

        $result = $this->analyzeConnections([
            'database' => ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90],
        ]);

        $this->assertFailed($result);
        $recommendation = $result->getIssues()[0]->recommendation;
        $this->assertStringContainsString('comes from the ShieldCI connection_timeouts or driver_timeouts config', $recommendation);
        $this->assertStringContainsString('or lower the worker timeout to at most 80 seconds.', $recommendation);
        $this->assertStringContainsString('queue:work --timeout', $recommendation);
        $this->assertStringNotContainsString('assumed', $recommendation);
    }

    /** @test */
    #[Test]
    public function test_recommendation_names_the_horizon_supervisor_timeout_for_a_horizon_timeout(): void
    {
        $result = $this->analyzeAgainstHorizon([], [
            'production' => [
                's' => ['connection' => 'redis', 'queue' => ['default'], 'timeout' => 120],
            ],
        ]);

        $this->assertFailed($result);
        $recommendation = $result->getIssues()[0]->recommendation;
        $this->assertStringContainsString("or lower the Horizon supervisors' timeouts to at most 80 seconds.", $recommendation);
        $this->assertStringNotContainsString('queue:work', $recommendation);
        $this->assertStringNotContainsString('assumed', $recommendation);
    }

    /**
     * @dataProvider unlimitedSupervisorTimeoutProvider
     *
     * @param  array<string, array<string, mixed>>  $supervisors
     */
    #[DataProvider('unlimitedSupervisorTimeoutProvider')]
    public function test_fails_a_horizon_supervisor_with_no_timeout_limit(array $supervisors): void
    {
        // Horizon passes the supervisor's timeout to the worker as --timeout, and the
        // worker arms pcntl_alarm(max($timeout, 0)): an alarm of 0 never fires, so no
        // retry_after can outlast a job on this supervisor.
        $result = $this->analyzeAgainstHorizon([], [
            'production' => $supervisors,
        ], ['redis' => ['driver' => 'redis', 'queue' => 'default', 'retry_after' => 9999]]);

        $this->assertFailed($result);
        $issue = $result->getIssues()[0];
        $this->assertSame("Queue connection 'redis' has improper timeout configuration", $issue->message);
        $this->assertSame(0, $issue->metadata['timeout']);
        $this->assertTrue($issue->metadata['timeout_unlimited']);
        $this->assertArrayNotHasKey('actual_buffer', $issue->metadata);
        $this->assertArrayNotHasKey('buffer_deficit', $issue->metadata);
        $this->assertStringContainsString('has no timeout limit (a timeout of 0 or less, or an empty value)', $issue->recommendation);
        $this->assertStringContainsString('never time out', $issue->recommendation);
        $this->assertStringNotContainsString('must be at least', $issue->recommendation);
    }

    /**
     * @return array<string, array{array<string, array<string, mixed>>}>
     */
    public static function unlimitedSupervisorTimeoutProvider(): array
    {
        return [
            'zero' => [['s' => ['connection' => 'redis', 'timeout' => 0]]],
            'zero beside 600' => [[
                'a' => ['connection' => 'redis', 'timeout' => 0],
                'b' => ['connection' => 'redis', 'timeout' => 600],
            ]],
            '600 beside zero' => [[
                'a' => ['connection' => 'redis', 'timeout' => 600],
                'b' => ['connection' => 'redis', 'timeout' => 0],
            ]],
            'negative' => [['s' => ['connection' => 'redis', 'timeout' => -5]]],
            'zero string' => [['s' => ['connection' => 'redis', 'timeout' => '0']]],
            // An unset env() leaves null: Horizon writes --timeout= and the worker reads it as 0.
            'null' => [['s' => ['connection' => 'redis', 'timeout' => null]]],
            // HORIZON_TIMEOUT= gives '', also written as --timeout=; false prints the same way.
            'empty string' => [['s' => ['connection' => 'redis', 'timeout' => '']]],
            'false' => [['s' => ['connection' => 'redis', 'timeout' => false]]],
        ];
    }

    /** @test */
    #[Test]
    public function test_unmatched_environment_warning_holds_for_an_unlimited_timeout(): void
    {
        $result = $this->analyzeAgainstHorizon([], [
            'production' => [
                's' => ['connection' => 'redis', 'timeout' => 0],
            ],
        ], environment: 'testing');

        $this->assertFailed($result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertTrue($metadata['timeout_unlimited']);
        $this->assertIsString($metadata['detection_warning']);
        $this->assertStringContainsString("No Horizon environment matches 'testing'", $metadata['detection_warning']);
        $this->assertStringNotContainsString('largest timeout', $metadata['detection_warning']);
    }

    /** @test */
    #[Test]
    public function test_recommendation_omits_lowering_the_timeout_when_retry_after_equals_the_buffer(): void
    {
        $result = $this->analyzeConnections([
            'database' => ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 10],
        ]);

        $this->assertFailed($result);
        $recommendation = $result->getIssues()[0]->recommendation;
        $this->assertStringContainsString('Solution: Increase retry_after to at least 70 seconds. Recommended:', $recommendation);
        $this->assertStringNotContainsString('at most', $recommendation);
    }

    /** @test */
    #[Test]
    public function test_recommendation_offers_a_one_second_timeout_when_retry_after_is_one_past_the_buffer(): void
    {
        $result = $this->analyzeConnections([
            'database' => ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 11],
        ]);

        $this->assertFailed($result);
        $this->assertStringContainsString(
            'Solution: Either increase retry_after to at least 70 seconds, or lower the worker timeout to at most 1 second. ',
            $result->getIssues()[0]->recommendation
        );
    }

    /** @test */
    #[Test]
    public function test_recommendation_writes_one_second_in_the_singular(): void
    {
        config([
            'shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts' => ['database' => 1],
            'shieldci.analyzers.reliability.queue-timeout-configuration.minimum_buffer' => 1,
        ]);

        $result = $this->analyzeConnections([
            'database' => ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 1],
        ]);

        $this->assertFailed($result);
        $recommendation = $result->getIssues()[0]->recommendation;
        $this->assertStringContainsString('has a worker timeout of 1 second and retry_after=1 second (buffer: 0 seconds)', $recommendation);
        $this->assertStringContainsString('Recommended: retry_after = timeout + 1 second (buffer).', $recommendation);
        $this->assertStringNotContainsString('1 seconds', $recommendation);
    }

    /** @test */
    #[Test]
    public function test_unlimited_recommendation_writes_one_second_in_the_singular(): void
    {
        config(['shieldci.analyzers.reliability.queue-timeout-configuration.minimum_buffer' => 1]);

        $result = $this->analyzeAgainstHorizon([], [
            'production' => [
                's' => ['connection' => 'redis', 'timeout' => 0],
            ],
        ], ['redis' => ['driver' => 'redis', 'queue' => 'default', 'retry_after' => 1]]);

        $this->assertFailed($result);
        $recommendation = $result->getIssues()[0]->recommendation;
        $this->assertStringContainsString('(currently 1 second)', $recommendation);
        $this->assertStringContainsString('plus 1 second (buffer)', $recommendation);
    }

    /** @test */
    #[Test]
    public function test_ignores_a_shieldci_connection_timeout_of_zero(): void
    {
        config(['shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts' => ['database' => 0]]);

        $result = $this->analyzeConnections([
            'database' => ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 65],
        ]);

        $this->assertFailed($result);
        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame(60, $metadata['timeout']);
        $this->assertSame('default_assumption', $metadata['timeout_source']);
    }

    /** @test */
    #[Test]
    public function test_a_null_defaults_timeout_survives_an_environment_plan_that_omits_it(): void
    {
        // array_replace_recursive keeps the defaults' null, so the merged supervisor still has no limit.
        $result = $this->analyzeAgainstHorizon([
            's' => ['connection' => 'redis', 'timeout' => null],
        ], [
            'production' => [
                's' => ['maxProcesses' => 3],
            ],
        ], ['redis' => ['driver' => 'redis', 'queue' => 'default', 'retry_after' => 9999]]);

        $this->assertFailed($result);
        $this->assertTrue($result->getIssues()[0]->metadata['timeout_unlimited']);
    }

    /**
     * @param  array<string, array<string, mixed>>  $connections
     */
    private function analyzeConnections(array $connections): ResultInterface
    {
        $tempDir = $this->createTempDirectory([
            'config/queue.php' => '<?php return '.var_export(['connections' => $connections], true).';',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        return $analyzer->analyze();
    }

    private const TWO_REDIS_CONNECTIONS = [
        'redis' => ['driver' => 'redis', 'queue' => 'default', 'retry_after' => 90],
        'redis-long' => ['driver' => 'redis', 'queue' => 'imports', 'retry_after' => 700],
    ];

    /**
     * @param  array<string, mixed>  $defaults
     * @param  array<string, mixed>  $environments
     * @param  array<string, array<string, mixed>>  $connections
     */
    private function analyzeAgainstHorizon(
        array $defaults,
        array $environments,
        array $connections = ['redis' => ['driver' => 'redis', 'queue' => 'default', 'retry_after' => 90]],
        string $environment = 'production',
    ): ResultInterface {
        $tempDir = $this->createTempDirectory([
            'config/queue.php' => '<?php return '.var_export(['connections' => $connections], true).';',
        ]);

        config(['app.env' => $environment]);
        config(['horizon.defaults' => $defaults]);
        config(['horizon.environments' => $environments]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        return $analyzer->analyze();
    }
}
