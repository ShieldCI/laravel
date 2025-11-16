<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
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
    ) {}

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
        $defaultConnection = $this->config->get('queue.default');

        return $defaultConnection !== null;
    }

    public function getSkipReason(): string
    {
        return 'Queue configuration not found (queue.default is not set)';
    }

    protected function runAnalysis(): ResultInterface
    {
        $defaultConnection = $this->config->get('queue.default', 'sync');
        $driver = $this->config->get("queue.connections.{$defaultConnection}.driver");

        if ($driver === null) {
            return $this->failed(
                'Queue configuration is invalid',
                [
                    $this->createIssue(
                        message: "Queue connection '{$defaultConnection}' is not defined in queue configuration",
                        location: new Location('config/queue.php', 1),
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
            return $this->passed('Queue driver configuration could not be determined');
        }

        $issues = [];

        // Use dynamic method dispatch pattern for extensibility
        $assessMethod = 'assess'.ucfirst($driver).'Driver';

        if (method_exists($this, $assessMethod)) {
            $this->$assessMethod($driver, $issues);
        }

        // @phpstan-ignore-next-line $issues is modified by reference in assess methods
        if (empty($issues)) {
            $environment = $this->config->get('app.env', 'production');

            return $this->passed("Queue driver '{$driver}' is properly configured for {$environment} environment");
        }

        // @phpstan-ignore-next-line $issues is populated by assess methods
        return $this->warning(
            sprintf('Found %d queue driver configuration issue%s', count($issues), count($issues) === 1 ? '' : 's'),
            $issues
        );
    }

    /**
     * Assess the 'null' queue driver.
     * The null driver silently discards all queued jobs, which is dangerous.
     */
    private function assessNullDriver(string $driver, array &$issues): void
    {
        $issues[] = $this->createIssue(
            message: "Queue driver is set to 'null'",
            location: new Location('config/queue.php', 1),
            severity: Severity::Critical,
            recommendation: "The 'null' queue driver silently discards all jobs, mails, notifications, and events sent to the queue without processing them. This can be very dangerous and cause data loss. It is only suitable for specific testing scenarios. Use 'redis', 'sqs', or 'database' for production environments.",
            metadata: [
                'driver' => $driver,
                'environment' => $this->config->get('app.env', 'production'),
            ]
        );
    }

    /**
     * Assess the 'sync' queue driver.
     * The sync driver processes jobs immediately, blocking the request.
     */
    private function assessSyncDriver(string $driver, array &$issues): void
    {
        $environment = $this->config->get('app.env', 'production');

        // Sync is acceptable in local development (though not ideal)
        if ($environment === 'local') {
            $issues[] = $this->createIssue(
                message: "Queue driver is set to 'sync' in local environment",
                location: new Location('config/queue.php', 1),
                severity: Severity::Low,
                recommendation: "The 'sync' driver processes all jobs, mails, notifications, and event listeners immediately in a synchronous manner. While acceptable for local development, consider using 'redis' or 'database' to accurately simulate production behavior and test queue functionality properly.",
                metadata: [
                    'driver' => $driver,
                    'environment' => $environment,
                ]
            );

            return;
        }

        $issues[] = $this->createIssue(
            message: "Queue driver is set to 'sync' in {$environment} environment",
            location: new Location('config/queue.php', 1),
            severity: Severity::High,
            recommendation: "The 'sync' driver processes all jobs, mails, notifications, and event listeners immediately in a synchronous manner, defeating the purpose of queuing. These time-consuming tasks will slow down web requests and severely impact response times and user experience. This driver is not suitable for production environments. Use 'redis', 'sqs', or 'database' instead.",
            metadata: [
                'driver' => $driver,
                'environment' => $environment,
            ]
        );
    }

    /**
     * Assess the 'database' queue driver.
     * The database driver works but has performance issues in production.
     */
    private function assessDatabaseDriver(string $driver, array &$issues): void
    {
        $environment = $this->config->get('app.env', 'production');

        // Database queue driver is acceptable for local development
        if ($environment === 'local') {
            return;
        }

        $issues[] = $this->createIssue(
            message: "Queue driver is set to 'database' in {$environment} environment",
            location: new Location('config/queue.php', 1),
            severity: Severity::Low,
            recommendation: "The 'database' queue driver is not suitable for production environments and is known to have issues such as deadlocks and slowing down your database during peak queue backlogs. While it works, Redis or SQS provide significantly better performance, reliability, and throughput. It is strongly recommended to shift to 'redis', 'sqs', or 'beanstalkd' for production use.",
            metadata: [
                'driver' => $driver,
                'environment' => $environment,
            ]
        );
    }

    /**
     * Override getEnvironment to use ConfigRepository.
     *
     * ConfigRepository-based analyzers get environment directly from
     * injected config instead of using the config() helper.
     *
     * @return string The environment name (e.g., 'local', 'production', 'staging')
     */
    protected function getEnvironment(): string
    {
        $env = $this->config->get('app.env');

        return is_string($env) && $env !== '' ? $env : 'production';
    }

    /**
     * Override isLocalAndShouldSkip to use ConfigRepository.
     *
     * ConfigRepository-based analyzers need to use their injected config
     * for both environment and skip_env_specific checks.
     *
     * @return bool True if analyzer should be skipped in local environment
     */
    protected function isLocalAndShouldSkip(): bool
    {
        // Check if environment is local
        $isLocal = $this->getEnvironment() === 'local';

        // Check if user has enabled skipping (default: false = don't skip)
        $skipEnabled = $this->config->get('shieldci.skip_env_specific', false);
        $skipEnabled = is_bool($skipEnabled) ? $skipEnabled : false;

        return $isLocal && $skipEnabled;
    }
}
