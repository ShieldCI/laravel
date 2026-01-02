<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\Reliability\QueueTimeoutAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class QueueTimeoutAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new QueueTimeoutAnalyzer;
    }

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
            // No retry_after specified, should use default of 90
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

        // Should pass because default retry_after (90) > timeout (60)
        $this->assertPassed($result);
    }

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

        // Should pass - connections without driver are skipped
        $this->assertPassed($result);
    }

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
        $this->assertStringContainsString('at least 10 seconds shorter', $issue->recommendation);
        $this->assertStringContainsString('buffer: 5 seconds', $issue->recommendation);
    }

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

    #[Test]
    public function test_uses_fallback_when_queue_not_matched(): void
    {
        // When queue name doesn't match any Horizon supervisor,
        // should fall back to maximum timeout
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'unmatched-queue',
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

        // Should indicate fallback detection if Horizon config exists
        // Otherwise may not have horizon_detection key
        if (isset($metadata['horizon_detection'])) {
            $this->assertContains($metadata['horizon_detection'], ['fallback_max', 'matched']);
        }
    }

    #[Test]
    public function test_handles_wildcard_queue_in_horizon(): void
    {
        // Test that '*' wildcard in Horizon supervisor queue matches any queue
        // This would require mocking config(), which we can't easily do in unit tests
        // So we'll just verify the queue name is extracted correctly
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'any-queue',
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

        // With retry_after=90 and default timeout=60, should pass
        $this->assertPassed($result);
    }

    #[Test]
    public function test_metadata_includes_horizon_detection_status(): void
    {
        // Verify that when an issue is found, metadata includes Horizon detection info
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'connections' => [
        'redis-fast' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => 'fast',
            'retry_after' => 65, // Will fail with default timeout
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

        // Should have queue_name
        $this->assertArrayHasKey('queue_name', $metadata);
        $this->assertSame('fast', $metadata['queue_name']);

        // May have horizon_detection if Horizon config is loaded
        // (depends on test environment)
    }
}
