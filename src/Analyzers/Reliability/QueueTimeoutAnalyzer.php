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
            $unlimited = $timeoutInfo['unlimited'] ?? false;
            $minimumBuffer = $this->getMinimumBuffer();

            // retry_after must be at least (timeout + buffer); no retry_after outlasts an unlimited timeout
            if ($unlimited || $retryAfter < $timeout + $minimumBuffer) {
                $location = $this->getConnectionLocation($name);

                $metadata = [
                    'connection' => $name,
                    'driver' => $driver,
                    'timeout' => $timeout,
                    'retry_after' => $retryAfter,
                    'minimum_buffer' => $minimumBuffer,
                ];

                // An unlimited timeout has no buffer to measure
                if ($unlimited) {
                    $metadata['timeout_unlimited'] = true;
                } else {
                    $metadata['actual_buffer'] = max(0, $retryAfter - $timeout);
                    $metadata['buffer_deficit'] = max(0, ($timeout + $minimumBuffer) - $retryAfter);
                }

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
                    recommendation: $this->getRecommendation(
                        $name,
                        $driver,
                        $timeoutInfo['source'] ?? 'default_assumption',
                        $unlimited,
                        $timeout,
                        $retryAfter,
                        $minimumBuffer
                    ),
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
     * 1. For Redis: Horizon supervisors on this connection
     * 2. ShieldCI config override
     * 3. Fallback to 60 with warning
     *
     * @param  array<string, mixed>  $connection
     * @return array{timeout: int, unlimited?: bool, source?: string, horizon_detection?: string, queue_name?: string, detection_warning?: string}
     */
    private function getTimeout(string $name, array $connection, string $driver): array
    {
        $queueName = $this->getQueueName($connection);

        // 1. For Redis, check Horizon config
        if ($driver === 'redis') {
            $horizonTimeout = $this->getRedisHorizonTimeout($name, $queueName);
            if ($horizonTimeout !== null) {
                return $horizonTimeout;
            }
        }

        // 2. Check ShieldCI config override
        $configuredTimeout = $this->getConfiguredTimeout($driver, $name, $connection);
        if ($configuredTimeout !== null) {
            return [
                'timeout' => $configuredTimeout,
                'source' => 'shieldci_config',
                'queue_name' => $queueName,
            ];
        }

        // 3. Fallback with warning
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
     * whatever queues it works. Horizon hands the supervisor's timeout to the worker as
     * --timeout, and the worker arms pcntl_alarm(max($timeout, 0)): an alarm of 0 never
     * fires, so a timeout of 0 or less is unlimited and reported as timeout 0.
     *
     * @return array{timeout: int, unlimited?: bool, horizon_detection: string, source: string, queue_name: string, detection_warning?: string}|null
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

                // Horizon's SupervisorOptions defaults an unset timeout to 60, but a null, '' or
                // false one (an unset or empty env()) is written as --timeout=, which the worker
                // reads as 0.
                $timeout = array_key_exists('timeout', $supervisor) ? $supervisor['timeout'] : 60;

                if (in_array($timeout, [null, '', false], true)) {
                    $timeouts[] = 0;
                } elseif (is_numeric($timeout)) {
                    $timeouts[] = (int) $timeout;
                }
            }

            if (empty($timeouts)) {
                return null;
            }

            $unlimited = min($timeouts) <= 0;

            $result = [
                'timeout' => $unlimited ? 0 : max($timeouts),
                'horizon_detection' => 'matched',
                'source' => 'horizon_config',
                'queue_name' => $queueName,
            ];

            if ($unlimited) {
                $result['unlimited'] = true;
            }

            if ($plan['unmatched_environment'] !== null) {
                $result['detection_warning'] = "No Horizon environment matches '{$plan['unmatched_environment']}', so the supervisors of every Horizon environment were graded.";
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
     *
     * The advice names where the timeout came from, so a user can tell an assumed
     * 60 seconds from a value the workers really run with.
     */
    private function getRecommendation(
        string $connection,
        string $driver,
        string $source,
        bool $unlimited,
        int $timeout,
        int $retryAfter,
        int $minimumBuffer
    ): string {
        if ($unlimited) {
            return sprintf(
                "A Horizon supervisor on the '%s' queue connection has no timeout limit (a timeout of 0 or less, or an empty value), so its jobs never time out and no retry_after (currently %s) can outlast them. ".
                'A job still running when retry_after expires is handed to another worker and processed twice. '.
                "Solution: Set the Horizon supervisor's timeout to the longest time a job may run, then make retry_after at least that timeout plus %s (buffer).",
                $connection,
                $this->seconds($retryAfter),
                $this->seconds($minimumBuffer)
            );
        }

        $suggestedRetryAfter = $timeout + $minimumBuffer;
        $actualBuffer = $retryAfter - $timeout;

        // A lower timeout must stay positive: 0 would mean no limit at all.
        $maximumTimeout = $retryAfter - $minimumBuffer;

        $timeoutSource = match ($source) {
            'horizon_config' => 'This worker timeout is the longest timeout among the Horizon supervisors that work this connection. ',
            'shieldci_config' => 'This worker timeout comes from the ShieldCI connection_timeouts or driver_timeouts config, not from the workers themselves. ',
            default => "This worker timeout is assumed to be Laravel's default of 60 seconds, because the configuration does not say what the workers use; ".
                'if they run with a different queue:work --timeout, set it in shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts '.
                'in config/shieldci.php so this check uses the real value. ',
        };

        if ($maximumTimeout <= 0) {
            $solution = sprintf('Solution: Increase retry_after to at least %d seconds. ', $suggestedRetryAfter);
        } elseif ($source === 'horizon_config') {
            $solution = sprintf(
                "Solution: Either increase retry_after to at least %d seconds, or lower the Horizon supervisors' timeouts to at most %s. ",
                $suggestedRetryAfter,
                $this->seconds($maximumTimeout)
            );
        } else {
            $solution = sprintf(
                'Solution: Either increase retry_after to at least %d seconds, or lower the worker timeout to at most %s. ',
                $suggestedRetryAfter,
                $this->seconds($maximumTimeout)
            );

            $solution .= $driver === 'redis'
                ? "The worker timeout is the queue:work --timeout option, or the Horizon supervisors' timeouts when Horizon runs the workers. "
                : 'The worker timeout is the queue:work --timeout option. ';

            if ($source === 'shieldci_config') {
                $solution .= 'After lowering it, update the ShieldCI value to match. ';
            }
        }

        return sprintf(
            'The queue retry_after value must be at least %d seconds to prevent duplicate job processing. '.
            "Your '%s' queue connection has a worker timeout of %s and retry_after=%s (buffer: %d seconds). ".
            'This configuration can cause jobs to be processed twice or the queue worker to crash. '.
            '%s%s'.
            'Recommended: retry_after = timeout + %s (buffer).',
            $suggestedRetryAfter,
            $connection,
            $this->seconds($timeout),
            $this->seconds($retryAfter),
            $actualBuffer,
            $timeoutSource,
            $solution,
            $this->seconds($minimumBuffer)
        );
    }

    /**
     * Format a duration for the recommendation, in the singular for one second.
     *
     * The "at least" figures are timeout plus buffer, both positive, so never 1.
     */
    private function seconds(int $count): string
    {
        return $count.' '.Str::plural('second', $count);
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
