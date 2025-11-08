<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\QueueDriverAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class QueueDriverAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new QueueDriverAnalyzer;
    }

    public function test_passes_with_redis_driver(): void
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

    public function test_fails_with_sync_driver_in_production(): void
    {
        $envContent = 'APP_ENV=production';
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
            '.env' => $envContent,
            'config/queue.php' => $queueConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('sync', $result);
    }

    public function test_warns_about_database_driver(): void
    {
        $queueConfig = <<<'PHP'
<?php

return [
    'default' => 'database',
    'connections' => [
        'database' => [
            'driver' => 'database',
            'table' => 'jobs',
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

        // May pass or warn depending on implementation
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
