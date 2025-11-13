<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Analyzes queue driver configuration for performance and reliability.
 *
 * Checks for:
 * - Sync queue driver in production (not recommended)
 * - Database queue driver performance considerations
 * - Recommends Redis/SQS for production
 */
class QueueDriverAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'queue-driver',
            name: 'Queue Driver Configuration',
            description: 'Ensures a proper queue driver is configured for optimal performance and reliability',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['queue', 'performance', 'configuration', 'redis', 'sqs'],
            docsUrl: 'https://laravel.com/docs/queues#driver-prerequisites'
        );
    }

    public function shouldRun(): bool
    {
        return file_exists($this->getConfigPath('queue.php'));
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $queueConfig = $this->getQueueConfig();
        $defaultConnection = $queueConfig['default'] ?? 'sync';
        $environment = $this->getEnvironment();

        $connection = $queueConfig['connections'][$defaultConnection] ?? null;

        if ($connection === null) {
            $issues[] = $this->createIssue(
                message: "Queue connection '{$defaultConnection}' is not defined in queue configuration",
                location: new Location($this->getConfigPath('queue.php'), 1),
                severity: Severity::High,
                recommendation: 'Define the queue connection in config/queue.php or change the default connection'
            );

            return $this->failed('Queue configuration is invalid', $issues);
        }

        $driver = $connection['driver'] ?? 'sync';

        // Check for problematic drivers in non-local environments
        if ($driver === 'sync' && $environment !== 'local') {
            $issues[] = $this->createIssue(
                message: "Queue driver is set to 'sync' in {$environment} environment",
                location: new Location($this->getConfigPath('queue.php'), $this->findLineInConfig('queue', 'default')),
                severity: Severity::High,
                recommendation: 'Sync driver executes queued jobs immediately and synchronously, defeating the purpose of queuing. Use redis, sqs, or database for production. This can severely impact response times and user experience.',
                metadata: ['driver' => 'sync', 'environment' => $environment]
            );
        } elseif ($driver === 'database' && $environment !== 'local') {
            $issues[] = $this->createIssue(
                message: "Queue driver is set to 'database' in {$environment} environment",
                location: new Location($this->getConfigPath('queue.php'), $this->findLineInConfig('queue', 'default')),
                severity: Severity::Low,
                recommendation: 'While database queue driver works, Redis or SQS provide better performance and reliability. Database queues can create additional load on your primary database. Consider using Redis for better throughput.',
                metadata: ['driver' => 'database', 'environment' => $environment]
            );
        }

        if (empty($issues)) {
            return $this->passed("Queue driver '{$driver}' is properly configured for {$environment} environment");
        }

        return $this->failed(
            sprintf('Found %d queue driver configuration issues', count($issues)),
            $issues
        );
    }

    private function getQueueConfig(): array
    {
        $configFile = $this->getConfigPath('queue.php');

        if (! file_exists($configFile)) {
            return [];
        }

        return include $configFile;
    }

    private function getConfigPath(string $file): string
    {
        return $this->basePath.'/config/'.$file;
    }

    private function findLineInConfig(string $file, string $key): int
    {
        $configFile = $this->getConfigPath($file.'.php');

        if (! file_exists($configFile)) {
            return 1;
        }

        $lines = file($configFile);

        foreach ($lines as $lineNumber => $line) {
            if (str_contains($line, "'{$key}'") || str_contains($line, "\"{$key}\"")) {
                return $lineNumber + 1;
            }
        }

        return 1;
    }
}
