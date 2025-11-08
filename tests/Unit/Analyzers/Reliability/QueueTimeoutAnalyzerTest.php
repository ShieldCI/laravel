<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\QueueTimeoutAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class QueueTimeoutAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new QueueTimeoutAnalyzer;
    }

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
        $this->assertHasIssueContaining('timeout', $result);
    }

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
    }
}
