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
        $this->assertSame(Severity::Critical, $issue->severity);
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
        $this->assertSame(Severity::Critical, $metadata->severity);
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
}
