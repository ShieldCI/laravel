<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as Config;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
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
 * Uses Laravel's Config for proper configuration access.
 */
class QueueDriverAnalyzer extends AbstractAnalyzer
{
    public static bool $runInCI = false;

    public function __construct(
        private Config $config
    ) {
        $this->configRepository = $config;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'queue-driver',
            name: 'Queue Driver Configuration Analyzer',
            description: 'Ensures a proper queue driver is configured for optimal performance and reliability',
            category: Category::Performance,
            severity: Severity::Critical,
            tags: ['queue', 'performance', 'configuration', 'redis', 'sqs'],
            timeToFix: 30
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

        // The connection and driver come from the config repository, which merges the
        // framework's own config/queue.php, so they are correct whether or not the app
        // published the file - and Laravel 11+ invites deleting config files you do not
        // customise. Only the line reference is lost, so an unpublished file yields no
        // location instead of naming a file the reader cannot open.
        $basePath = $this->getBasePath();

        // Validate default connection is configured and is a string
        if ($defaultConnection === null || ! is_string($defaultConnection)) {
            return $this->failed(
                'Queue configuration is invalid',
                [
                    $this->createIssue(
                        message: 'Queue default connection is not configured',
                        location: ConfigFileHelper::locateConfigKey($basePath, 'queue.php', 'default'),
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

        if ($driver === null) {
            return $this->failed(
                'Queue configuration is invalid',
                [
                    $this->createIssue(
                        message: "Queue connection '{$defaultConnection}' is not defined in queue configuration",
                        location: ConfigFileHelper::locateConfigKey($basePath, 'queue.php', $defaultConnection, 'connections'),
                        severity: Severity::High,
                        recommendation: 'Define the queue connection in config/queue.php or change the default connection to a valid queue connection.',
                        metadata: [
                            'connection' => $defaultConnection,
                        ]
                    ),
                ]
            );
        }

        // A malformed driver is a fact about the user's configuration, not a failure of
        // this analyzer, so it is reported as a located finding like the non-string
        // connection above. As an errored result it carried no issue, which left it
        // unbaselineable and unsuppressible.
        if (! is_string($driver)) {
            return $this->failed(
                'Queue configuration is invalid',
                [
                    $this->createIssue(
                        message: "Queue connection '{$defaultConnection}' has a driver that is not a string",
                        location: ConfigFileHelper::locateNestedConfigKey($basePath, 'queue.php', 'connections', 'driver', $defaultConnection),
                        severity: Severity::High,
                        recommendation: 'Set the connection driver to one of the queue drivers Laravel supports. Laravel cannot build a queue connection from a non-string driver, so every dispatched job fails at runtime.',
                        metadata: [
                            'connection' => $defaultConnection,
                            'type' => get_debug_type($driver),
                        ]
                    ),
                ]
            );
        }

        $issues = [];

        // Resolve the location once so every driver check reports the same one.
        $location = ConfigFileHelper::locateNestedConfigKey($basePath, 'queue.php', 'connections', 'driver', $defaultConnection);

        // Use match expression for better type safety and clarity
        match ($driver) {
            'null' => $this->assessNullDriver($driver, $issues, $location, $defaultConnection),
            'sync' => $this->assessSyncDriver($driver, $issues, $location, $defaultConnection),
            'database' => $this->assessDatabaseDriver($driver, $issues, $location, $defaultConnection),
            default => $this->assessOtherDriver($driver, $issues, $location, $defaultConnection),
        };

        $environment = $this->getEnvironment();

        $summary = empty($issues)
            ? "Queue driver '{$driver}' is properly configured for {$environment} environment"
            : sprintf('Found %d queue driver configuration issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Assess the 'null' queue driver.
     * The null driver silently discards all queued jobs, which is dangerous.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessNullDriver(string $driver, array &$issues, ?Location $location, string $defaultConnection): void
    {
        $environment = $this->getEnvironment();

        $issues[] = $this->createIssue(
            message: "Queue driver is set to 'null'",
            location: $location,
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
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessSyncDriver(string $driver, array &$issues, ?Location $location, string $defaultConnection): void
    {
        $environment = $this->getEnvironment();

        // Sync is acceptable in local development (though not ideal)
        if ($this->isTestingEnvironment($environment)) {
            return;
        }

        if ($this->isLocalEnvironment($environment)) {
            $issues[] = $this->createIssue(
                message: "Queue driver is set to 'sync' in {$environment} environment",
                location: $location,
                severity: Severity::Low,
                recommendation: "The 'sync' driver processes all jobs, mails, notifications, and event listeners immediately in a synchronous manner. While acceptable for development, consider using 'redis' or 'database' to accurately simulate production behavior.",
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
            location: $location,
            severity: Severity::High,
            recommendation: "The 'sync' driver processes all jobs, mails, notifications, and event listeners immediately in a synchronous manner, defeating the purpose of queuing. This severely impacts response times and user experience. Use 'redis', 'sqs', or 'database' instead.",
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
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessDatabaseDriver(string $driver, array &$issues, ?Location $location, string $defaultConnection): void
    {
        $environment = $this->getEnvironment();

        // Database queue driver is acceptable for local development and testing
        if ($this->isLocalEnvironment($environment) || $this->isTestingEnvironment($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: "Queue driver is set to 'database' in {$environment} environment",
            location: $location,
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
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessOtherDriver(string $driver, array &$issues, ?Location $location, string $defaultConnection): void
    {
        // Other drivers (redis, sqs, beanstalkd, etc.) are generally acceptable
        // Parameters are kept for consistency with other assess methods
        // No issues to report for these drivers
    }

    private function isLocalEnvironment(string $environment): bool
    {
        return in_array($environment, ['local', 'development'], true);
    }

    private function isTestingEnvironment(string $environment): bool
    {
        return $environment === 'testing';
    }
}
