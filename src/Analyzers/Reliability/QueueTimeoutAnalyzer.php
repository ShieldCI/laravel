<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Support\Str;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Checks queue timeout and retry_after configuration.
 *
 * Checks for:
 * - retry_after is greater than timeout with sufficient buffer
 * - Proper timeout configuration for queue workers
 * - Prevents jobs from being processed twice
 */
class QueueTimeoutAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Minimum buffer (in seconds) between timeout and retry_after.
     *
     * This ensures jobs have enough time to complete before being retried,
     * preventing duplicate processing.
     */
    private const MINIMUM_RETRY_AFTER_BUFFER_SECONDS = 10;

    /**
     * Core drivers whose connectors read retry_after.
     */
    private const RETRY_AFTER_DRIVERS = ['redis', 'database', 'beanstalkd'];

    /**
     * Core drivers whose connectors never read retry_after.
     */
    private const DRIVERS_WITHOUT_RETRY_AFTER = ['sync', 'sqs', 'null', 'deferred', 'background', 'failover'];

    /**
     * retry_after when a core connection omits it.
     *
     * RedisConnector and DatabaseConnector fall back to 60, BeanstalkdConnector to
     * Pheanstalk::DEFAULT_TTR, which is also 60.
     */
    private const DEFAULT_RETRY_AFTER_SECONDS = 60;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'queue-timeout-configuration',
            name: 'Queue Timeout Configuration Analyzer',
            description: 'Ensures queue timeout and retry_after values are properly configured to prevent job duplication',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['queue', 'configuration', 'reliability', 'jobs'],
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $queueConfig = $this->getQueueConfig();

        if (empty($queueConfig)) {
            return $this->warning('Unable to read queue configuration');
        }

        $connections = $queueConfig['connections'] ?? [];

        if (! is_array($connections)) {
            return $this->warning('Unable to read queue connections');
        }

        foreach ($connections as $name => $connection) {
            if (! is_string($name) || ! is_array($connection)) {
                continue;
            }

            $driver = $connection['driver'] ?? '';

            // Laravel cannot build a connection without a driver.
            if (! is_string($driver) || $driver === '') {
                continue;
            }

            if (in_array($driver, self::DRIVERS_WITHOUT_RETRY_AFTER, true)) {
                continue;
            }

            $retryAfter = $this->getRetryAfter($connection, $driver);

            if ($retryAfter === null) {
                continue;
            }

            $timeoutInfo = $this->getTimeout($name, $connection, $driver);
            $timeout = $timeoutInfo['timeout'];
            $minimumBuffer = $this->getMinimumBuffer();

            // retry_after must be at least (timeout + buffer)
            if ($retryAfter < $timeout + $minimumBuffer) {
                $location = $this->getConnectionLocation($name);

                $metadata = [
                    'connection' => $name,
                    'driver' => $driver,
                    'timeout' => $timeout,
                    'retry_after' => $retryAfter,
                    'minimum_buffer' => $minimumBuffer,
                    'actual_buffer' => max(0, $retryAfter - $timeout),
                    'buffer_deficit' => max(0, ($timeout + $minimumBuffer) - $retryAfter),
                ];

                // Add queue name
                if (isset($timeoutInfo['queue_name'])) {
                    $metadata['queue_name'] = $timeoutInfo['queue_name'];
                }

                // Add timeout source
                if (isset($timeoutInfo['source'])) {
                    $metadata['timeout_source'] = $timeoutInfo['source'];
                }

                // Add Horizon-specific metadata if applicable
                if (isset($timeoutInfo['horizon_detection'])) {
                    $metadata['horizon_detection'] = $timeoutInfo['horizon_detection'];
                }

                // Add detection warning if present
                if (isset($timeoutInfo['detection_warning'])) {
                    $metadata['detection_warning'] = $timeoutInfo['detection_warning'];
                }

                $issues[] = $this->createIssue(
                    message: "Queue connection '{$name}' has improper timeout configuration",
                    location: $location,
                    severity: $this->metadata()->severity,
                    recommendation: $this->getRecommendation($name, $timeout, $retryAfter, $minimumBuffer),
                    metadata: $metadata
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('Queue timeout configurations are correct');
        }

        return $this->resultBySeverity(
            sprintf('Found %d queue configuration issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Get retry_after value from connection config.
     *
     * Returns null when there is no number to grade: a third-party driver that omits
     * retry_after (its default is unknown), or a non-numeric value, which the queue
     * passes to Carbon or Pheanstalk unconverted, so no single runtime value exists.
     *
     * @param  array<string, mixed>  $connection
     */
    private function getRetryAfter(array $connection, string $driver): ?int
    {
        $retryAfter = $connection['retry_after'] ?? null;

        if ($retryAfter === null) {
            return in_array($driver, self::RETRY_AFTER_DRIVERS, true)
                ? self::DEFAULT_RETRY_AFTER_SECONDS
                : null;
        }

        return is_numeric($retryAfter) ? (int) $retryAfter : null;
    }

    /**
     * Get timeout value using tiered detection approach.
     *
     * Detection order:
     * 1. Connection-specific timeout in queue config
     * 2. For Redis: Horizon supervisors on this connection
     * 3. ShieldCI config override
     * 4. Fallback to 60 with warning
     *
     * @param  array<string, mixed>  $connection
     * @return array{timeout: int, source?: string, horizon_detection?: string, queue_name?: string, detection_warning?: string}
     */
    private function getTimeout(string $name, array $connection, string $driver): array
    {
        $queueName = $this->getQueueName($connection);

        // 1. Check connection-specific timeout (non-standard but possible)
        if (isset($connection['timeout']) && is_numeric($connection['timeout'])) {
            return [
                'timeout' => (int) $connection['timeout'],
                'source' => 'connection_config',
                'queue_name' => $queueName,
            ];
        }

        // 2. For Redis, check Horizon config
        if ($driver === 'redis') {
            $horizonTimeout = $this->getRedisHorizonTimeout($name, $queueName);
            if ($horizonTimeout !== null) {
                return $horizonTimeout;
            }
        }

        // 3. Check ShieldCI config override
        $configuredTimeout = $this->getConfiguredTimeout($driver, $name, $connection);
        if ($configuredTimeout !== null) {
            return [
                'timeout' => $configuredTimeout,
                'source' => 'shieldci_config',
                'queue_name' => $queueName,
            ];
        }

        // 4. Fallback with warning
        return [
            'timeout' => 60,
            'source' => 'default_assumption',
            'queue_name' => $queueName,
            'detection_warning' => 'Using default timeout (60s). Actual worker timeout may differ if configured via CLI (--timeout) or process manager. Configure actual timeout in config/shieldci.php if different.',
        ];
    }

    /**
     * Get the largest timeout of the Horizon supervisors on a queue connection.
     *
     * retry_after belongs to the connection, so every supervisor on it counts,
     * whatever queues it works.
     *
     * @return array{timeout: int, horizon_detection: string, source: string, queue_name: string, detection_warning?: string}|null
     */
    private function getRedisHorizonTimeout(string $name, string $queueName): ?array
    {
        if (! function_exists('config')) {
            return null;
        }

        try {
            $plan = $this->getHorizonSupervisors();
            $timeouts = [];

            foreach ($plan['supervisors'] as $supervisor) {
                if (! is_array($supervisor) || ($supervisor['connection'] ?? null) !== $name) {
                    continue;
                }

                // Horizon's SupervisorOptions defaults an unset timeout to 60.
                $timeout = $supervisor['timeout'] ?? 60;

                if (is_numeric($timeout)) {
                    $timeouts[] = (int) $timeout;
                }
            }

            if (empty($timeouts)) {
                return null;
            }

            $result = [
                'timeout' => max($timeouts),
                'horizon_detection' => 'matched',
                'source' => 'horizon_config',
                'queue_name' => $queueName,
            ];

            if ($plan['unmatched_environment'] !== null) {
                $result['detection_warning'] = "No Horizon environment matches '{$plan['unmatched_environment']}', so the largest timeout across all Horizon environments was used.";
            }

            return $result;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Get configured timeout from ShieldCI config.
     *
     * connection_timeouts is keyed by the queue connection name, the one `queue:work`
     * takes. An entry under the inner `connection` name is still read when the queue
     * connection name has none, so configs keyed that way keep working; a connection
     * without an inner name (database's null, beanstalkd) has no such fallback.
     *
     * @param  array<string, mixed>  $connection
     */
    private function getConfiguredTimeout(string $driver, string $name, array $connection): ?int
    {
        if (! function_exists('config')) {
            return null;
        }

        try {
            // Check connection-specific timeout
            $connectionTimeouts = config('shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts', []);

            $innerName = $connection['connection'] ?? null;
            $key = is_array($connectionTimeouts) && array_key_exists($name, $connectionTimeouts) ? $name : $innerName;

            if (is_array($connectionTimeouts) && is_string($key) && $key !== '' && isset($connectionTimeouts[$key])) {
                $timeout = $connectionTimeouts[$key];
                if (is_numeric($timeout) && $timeout > 0) {
                    return (int) $timeout;
                }
            }

            // Check driver-specific timeout
            $driverTimeouts = config('shieldci.analyzers.reliability.queue-timeout-configuration.driver_timeouts', []);

            if (is_array($driverTimeouts) && isset($driverTimeouts[$driver])) {
                $timeout = $driverTimeouts[$driver];
                if (is_numeric($timeout) && $timeout > 0) {
                    return (int) $timeout;
                }
            }

            return null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Get queue name from connection configuration.
     *
     * @param  array<string, mixed>  $connection
     */
    private function getQueueName(array $connection): string
    {
        $queue = $connection['queue'] ?? 'default';

        return is_string($queue) ? $queue : 'default';
    }

    /**
     * Get the supervisors Horizon deploys in the current environment.
     *
     * Mirrors Horizon's ProvisioningPlan: every environment's plan is
     * array_replace_recursive($defaults, $plan), and deploy() runs only the first
     * environment whose key matches the environment name as a Str::is() pattern.
     * HorizonCommand takes the name from horizon.env, then app.env (its --environment
     * option is not visible here). When no environment matches, as when CI runs as
     * 'testing', the deployed one is unknown, so every environment's plan is returned.
     *
     * @return array{supervisors: array<mixed>, unmatched_environment: string|null}
     */
    private function getHorizonSupervisors(): array
    {
        $defaults = config('horizon.defaults', []);
        $environments = config('horizon.environments', []);

        if (! is_array($defaults) || ! is_array($environments)) {
            return ['supervisors' => [], 'unmatched_environment' => null];
        }

        $environmentValue = config('horizon.env') ?? config('app.env', 'production');
        $environment = is_string($environmentValue) ? $environmentValue : 'production';

        foreach ($environments as $name => $plan) {
            if (Str::is((string) $name, $environment)) {
                return [
                    'supervisors' => is_array($plan) ? array_replace_recursive($defaults, $plan) : [],
                    'unmatched_environment' => null,
                ];
            }
        }

        $supervisors = [];

        foreach ($environments as $plan) {
            if (is_array($plan)) {
                $supervisors = array_merge($supervisors, array_values(array_replace_recursive($defaults, $plan)));
            }
        }

        return ['supervisors' => $supervisors, 'unmatched_environment' => $environment];
    }

    /**
     * Get the minimum buffer requirement from config or use default.
     */
    private function getMinimumBuffer(): int
    {
        if (! function_exists('config')) {
            return self::MINIMUM_RETRY_AFTER_BUFFER_SECONDS;
        }

        try {
            $buffer = config('shieldci.analyzers.reliability.queue-timeout-configuration.minimum_buffer');

            return is_numeric($buffer) && $buffer > 0
                ? (int) $buffer
                : self::MINIMUM_RETRY_AFTER_BUFFER_SECONDS;
        } catch (\Throwable $e) {
            return self::MINIMUM_RETRY_AFTER_BUFFER_SECONDS;
        }
    }

    /**
     * Get recommendation message for timeout configuration issue.
     */
    private function getRecommendation(string $connection, int $timeout, int $retryAfter, int $minimumBuffer): string
    {
        $suggestedRetryAfter = $timeout + $minimumBuffer;
        $actualBuffer = $retryAfter - $timeout;

        return sprintf(
            'The queue retry_after value must be at least %d seconds to prevent duplicate job processing. '.
            "Your '%s' queue connection has timeout=%d seconds and retry_after=%d seconds (buffer: %d seconds). ".
            'This configuration can cause jobs to be processed twice or the queue worker to crash. '.
            'Solution: Either increase retry_after to at least %d seconds, or decrease the timeout to at most %d seconds. '.
            'Recommended: retry_after = timeout + %d seconds (buffer).',
            $suggestedRetryAfter,
            $connection,
            $timeout,
            $retryAfter,
            $actualBuffer,
            $suggestedRetryAfter,
            $retryAfter - $minimumBuffer,
            $minimumBuffer
        );
    }

    /**
     * Get the queue configuration array.
     *
     * @return array<string, mixed>
     */
    private function getQueueConfig(): array
    {
        $basePath = $this->getBasePath();

        if ($basePath === '') {
            return [];
        }

        $configFile = $this->getQueueConfigPath($basePath);

        if (! file_exists($configFile)) {
            return [];
        }

        try {
            $config = include $configFile;

            return is_array($config) ? $config : [];
        } catch (\Throwable $e) {
            // Config file may have syntax errors or other issues
            return [];
        }
    }

    /**
     * Get the path to the queue configuration file.
     */
    private function getQueueConfigPath(string $basePath): string
    {
        return ConfigFileHelper::getConfigPath(
            $basePath,
            'queue.php',
            fn ($file) => function_exists('config_path') ? config_path($file) : null
        );
    }

    /**
     * Get the location for a queue connection in the config file.
     *
     * Unlike the other config analyzers this one reads its values out of the file itself,
     * so runAnalysis() has already returned 'Unable to read queue configuration' when the
     * file is absent. By the time a connection is reported the file is guaranteed to exist,
     * so the helper's unpublished-file answer cannot come back null here.
     */
    private function getConnectionLocation(string $connectionName): ?Location
    {
        return ConfigFileHelper::locateConfigKey(
            $this->getBasePath(),
            'queue.php',
            $connectionName,
            'connections'
        );
    }
}
