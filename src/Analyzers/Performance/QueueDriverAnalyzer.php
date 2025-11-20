<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Analyzes queue driver configuration for performance and reliability.
 *
 * Checks for:
 * - Null queue driver (silently discards jobs)
 * - Sync queue driver in production (blocks requests)
 * - Database queue driver performance considerations
 * - Recommends Redis/SQS for production
 *
 * Uses Laravel's ConfigRepository for proper configuration access.
 */
class QueueDriverAnalyzer extends AbstractAnalyzer
{
    public function __construct(
        private ConfigRepository $config
    ) {
        $this->configRepository = $config;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'queue-driver',
            name: 'Queue Driver Configuration',
            description: 'Ensures a proper queue driver is configured for optimal performance and reliability',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['queue', 'performance', 'configuration', 'redis', 'sqs'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/queue-driver'
        );
    }

    public function shouldRun(): bool
    {
        $defaultConnection = $this->config->get('queue.default');

        return $defaultConnection !== null;
    }

    public function getSkipReason(): string
    {
        return 'Queue configuration not found (queue.default is not set)';
    }

    protected function runAnalysis(): ResultInterface
    {
        $defaultConnection = $this->config->get('queue.default');

        // Validate default connection is configured and is a string
        if ($defaultConnection === null || ! is_string($defaultConnection)) {
            $basePath = $this->getBasePath();
            $configFile = ConfigFileHelper::getConfigPath($basePath, 'queue.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

            return $this->failed(
                'Queue configuration is invalid',
                [
                    $this->createIssue(
                        message: 'Queue default connection is not configured',
                        location: new Location($configFile, ConfigFileHelper::findKeyLine($configFile, 'default')),
                        severity: Severity::High,
                        recommendation: 'Set QUEUE_CONNECTION in your .env file or define queue.default in config/queue.php',
                        metadata: [
                            'connection' => $defaultConnection ?? 'null',
                        ]
                    ),
                ]
            );
        }

        $driver = $this->config->get("queue.connections.{$defaultConnection}.driver");

        $basePath = $this->getBasePath();
        $configFile = ConfigFileHelper::getConfigPath($basePath, 'queue.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        if ($driver === null) {
            $lineNumber = ConfigFileHelper::findKeyLine($configFile, $defaultConnection, 'connections');

            return $this->failed(
                'Queue configuration is invalid',
                [
                    $this->createIssue(
                        message: "Queue connection '{$defaultConnection}' is not defined in queue configuration",
                        location: new Location($configFile, $lineNumber),
                        severity: Severity::High,
                        recommendation: 'Define the queue connection in config/queue.php or change the default connection to a valid queue connection.',
                        metadata: [
                            'connection' => $defaultConnection,
                        ]
                    ),
                ]
            );
        }

        // Ensure driver is a string for PHPStan
        if (! is_string($driver)) {
            return $this->error('Queue driver configuration is invalid (driver is not a string)');
        }

        $issues = [];

        // Use match expression for better type safety and clarity
        match ($driver) {
            'null' => $this->assessNullDriver($driver, $issues, $configFile, $defaultConnection),
            'sync' => $this->assessSyncDriver($driver, $issues, $configFile, $defaultConnection),
            'database' => $this->assessDatabaseDriver($driver, $issues, $configFile, $defaultConnection),
            default => $this->assessOtherDriver($driver, $issues, $configFile, $defaultConnection),
        };

        if (empty($issues)) {
            $environment = $this->getEnvironment();

            return $this->passed("Queue driver '{$driver}' is properly configured for {$environment} environment");
        }

        return $this->warning(
            sprintf('Found %d queue driver configuration issue%s', count($issues), count($issues) === 1 ? '' : 's'),
            $issues
        );
    }

    /**
     * Assess the 'null' queue driver.
     * The null driver silently discards all queued jobs, which is dangerous.
     */
    private function assessNullDriver(string $driver, array &$issues, string $configFile, string $defaultConnection): void
    {
        $lineNumber = ConfigFileHelper::findNestedKeyLine($configFile, 'connections', 'driver', $defaultConnection);
        $environment = $this->getEnvironment();

        $issues[] = $this->createIssue(
            message: "Queue driver is set to 'null'",
            location: new Location($configFile, $lineNumber),
            severity: Severity::Critical,
            recommendation: "The 'null' queue driver silently discards all jobs, mails, notifications, and events sent to the queue without processing them. This can be very dangerous and cause data loss. It is only suitable for specific testing scenarios. Use 'redis', 'sqs', or 'database' for production environments.",
            metadata: [
                'driver' => $driver,
                'connection' => $defaultConnection,
                'environment' => $environment,
            ]
        );
    }

    /**
     * Assess the 'sync' queue driver.
     * The sync driver processes jobs immediately, blocking the request.
     */
    private function assessSyncDriver(string $driver, array &$issues, string $configFile, string $defaultConnection): void
    {
        $environment = $this->getEnvironment();
        $lineNumber = ConfigFileHelper::findNestedKeyLine($configFile, 'connections', 'driver', $defaultConnection);

        // Sync is acceptable in local development (though not ideal)
        if ($environment === 'local') {
            $issues[] = $this->createIssue(
                message: "Queue driver is set to 'sync' in local environment",
                location: new Location($configFile, $lineNumber),
                severity: Severity::Low,
                recommendation: "The 'sync' driver processes all jobs, mails, notifications, and event listeners immediately in a synchronous manner. While acceptable for local development, consider using 'redis' or 'database' to accurately simulate production behavior and test queue functionality properly.",
                metadata: [
                    'driver' => $driver,
                    'connection' => $defaultConnection,
                    'environment' => $environment,
                ]
            );

            return;
        }

        $issues[] = $this->createIssue(
            message: "Queue driver is set to 'sync' in {$environment} environment",
            location: new Location($configFile, $lineNumber),
            severity: Severity::High,
            recommendation: "The 'sync' driver processes all jobs, mails, notifications, and event listeners immediately in a synchronous manner, defeating the purpose of queuing. These time-consuming tasks will slow down web requests and severely impact response times and user experience. This driver is not suitable for production environments. Use 'redis', 'sqs', or 'database' instead.",
            metadata: [
                'driver' => $driver,
                'connection' => $defaultConnection,
                'environment' => $environment,
            ]
        );
    }

    /**
     * Assess the 'database' queue driver.
     * The database driver works but has performance issues in production.
     */
    private function assessDatabaseDriver(string $driver, array &$issues, string $configFile, string $defaultConnection): void
    {
        $environment = $this->getEnvironment();

        // Database queue driver is acceptable for local development
        if ($environment === 'local') {
            return;
        }

        $lineNumber = ConfigFileHelper::findNestedKeyLine($configFile, 'connections', 'driver', $defaultConnection);

        $issues[] = $this->createIssue(
            message: "Queue driver is set to 'database' in {$environment} environment",
            location: new Location($configFile, $lineNumber),
            severity: Severity::Low,
            recommendation: "The 'database' queue driver is not suitable for production environments and is known to have issues such as deadlocks and slowing down your database during peak queue backlogs. While it works, Redis or SQS provide significantly better performance, reliability, and throughput. It is strongly recommended to shift to 'redis', 'sqs', or 'beanstalkd' for production use.",
            metadata: [
                'driver' => $driver,
                'connection' => $defaultConnection,
                'environment' => $environment,
            ]
        );
    }

    /**
     * Assess other queue drivers (redis, sqs, beanstalkd, etc.).
     * These are generally acceptable, but we can add specific checks if needed.
     */
    private function assessOtherDriver(string $driver, array &$issues, string $configFile, string $defaultConnection): void
    {
        // Other drivers (redis, sqs, beanstalkd, etc.) are generally acceptable
        // No issues to report for these drivers
    }
}
