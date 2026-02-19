<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

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
        $basePath = $this->getBasePath();

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

            if (! is_string($driver)) {
                continue;
            }

            // Skip sync and sqs drivers as they don't have retry_after
            if (in_array($driver, ['sync', 'sqs'])) {
                continue;
            }

            $retryAfter = $this->getRetryAfter($connection);
            $timeoutInfo = $this->getTimeout($connection, $driver);
            $timeout = $timeoutInfo['timeout'];
            $minimumBuffer = $this->getMinimumBuffer();

            // retry_after must be at least (timeout + buffer)
            if ($retryAfter < $timeout + $minimumBuffer) {
                $configFile = $this->getQueueConfigPath($basePath);
                $location = $this->getConnectionLocation($configFile, $name);

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
                    severity: Severity::High,
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
     * @param  array<string, mixed>  $connection
     */
    private function getRetryAfter(array $connection): int
    {
        $retryAfter = $connection['retry_after'] ?? 90;

        return is_numeric($retryAfter) ? (int) $retryAfter : 90;
    }

    /**
     * Get timeout value using tiered detection approach.
     *
     * Detection order:
     * 1. Connection-specific timeout in queue config
     * 2. For Redis: Horizon config
     * 3. ShieldCI config override
     * 4. Fallback to 60 with warning
     *
     * @param  array<string, mixed>  $connection
     * @return array{timeout: int, source?: string, horizon_detection?: string, queue_name?: string, detection_warning?: string}
     */
    private function getTimeout(array $connection, string $driver): array
    {
        $queueName = $this->getQueueName($connection);
        $connectionName = is_string($connection['connection'] ?? null) ? $connection['connection'] : 'default';

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
            $horizonTimeout = $this->getRedisHorizonTimeout($queueName);
            if ($horizonTimeout !== null) {
                return $horizonTimeout;
            }
        }

        // 3. Check ShieldCI config override
        $configuredTimeout = $this->getConfiguredTimeout($driver, $connectionName);
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
     * Get timeout from Horizon configuration for Redis drivers.
     *
     * @return array{timeout: int, horizon_detection: string, queue_name: string}|null
     */
    private function getRedisHorizonTimeout(string $queueName): ?array
    {
        if (! function_exists('config')) {
            return null;
        }

        try {
            // Try to find timeout for this specific queue
            $matchedTimeout = $this->findHorizonTimeoutForQueue($queueName);

            if ($matchedTimeout !== null) {
                return [
                    'timeout' => $matchedTimeout,
                    'horizon_detection' => 'matched',
                    'source' => 'horizon_config',
                    'queue_name' => $queueName,
                ];
            }

            // Fallback: use maximum timeout from all supervisors
            $defaultTimeouts = $this->getArrayValues(config('horizon.defaults', []), 'timeout');
            $envTimeouts = $this->getArrayValues(config('horizon.environments', []), 'timeout');
            $allTimeouts = array_merge($defaultTimeouts, $envTimeouts);

            if (! empty($allTimeouts)) {
                return [
                    'timeout' => max($allTimeouts),
                    'horizon_detection' => 'fallback_max',
                    'source' => 'horizon_config',
                    'queue_name' => $queueName,
                ];
            }

            return null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Get configured timeout from ShieldCI config.
     */
    private function getConfiguredTimeout(string $driver, string $connectionName): ?int
    {
        if (! function_exists('config')) {
            return null;
        }

        try {
            // Check connection-specific timeout
            $connectionTimeouts = config('shieldci.analyzers.reliability.queue-timeout-configuration.connection_timeouts', []);

            if (is_array($connectionTimeouts) && isset($connectionTimeouts[$connectionName])) {
                $timeout = $connectionTimeouts[$connectionName];
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
     * Find Horizon timeout for a specific queue by matching supervisors.
     *
     * Searches both defaults and current environment supervisors.
     *
     * @return int|null Timeout in seconds if found, null otherwise
     */
    private function findHorizonTimeoutForQueue(string $queueName): ?int
    {
        if (! function_exists('config')) {
            return null;
        }

        try {
            $timeouts = [];

            // Check defaults
            $defaults = config('horizon.defaults', []);
            if (is_array($defaults)) {
                $timeouts = array_merge($timeouts, $this->extractTimeoutsForQueue($defaults, $queueName));
            }

            // Check current environment
            $currentEnv = config('app.env', 'production');
            $envConfig = config("horizon.environments.{$currentEnv}", []);
            if (is_array($envConfig)) {
                $timeouts = array_merge($timeouts, $this->extractTimeoutsForQueue($envConfig, $queueName));
            }

            // Return maximum timeout from matching supervisors
            return ! empty($timeouts) ? max($timeouts) : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Extract timeouts from supervisors that handle the specified queue.
     *
     * @param  array<string, mixed>  $supervisors
     * @return array<int>
     */
    private function extractTimeoutsForQueue(array $supervisors, string $queueName): array
    {
        $timeouts = [];

        foreach ($supervisors as $supervisor) {
            if (! is_array($supervisor)) {
                continue;
            }

            // Check if this supervisor handles the queue
            $supervisorQueues = $supervisor['queue'] ?? [];

            if (is_string($supervisorQueues)) {
                $supervisorQueues = array_map('trim', explode(',', $supervisorQueues));
            }

            if (! is_array($supervisorQueues)) {
                continue;
            }

            // Match queue name (exact or pattern)
            if (in_array($queueName, $supervisorQueues, true) || in_array('*', $supervisorQueues, true)) {
                $timeout = $supervisor['timeout'] ?? null;

                if (is_numeric($timeout)) {
                    $timeouts[] = (int) $timeout;
                }
            }
        }

        return $timeouts;
    }

    /**
     * Recursively extract numeric values for a specific key from nested arrays.
     *
     * @param  mixed  $data
     * @return array<int>
     */
    private function getArrayValues($data, string $key): array
    {
        $values = [];

        if (! is_array($data)) {
            return $values;
        }

        foreach ($data as $item) {
            if (! is_array($item)) {
                continue;
            }

            if (isset($item[$key]) && is_numeric($item[$key])) {
                $values[] = (int) $item[$key];
            }

            foreach ($item as $child) {
                if (is_array($child)) {
                    $values = array_merge($values, $this->getArrayValues($child, $key));
                }
            }
        }

        return $values;
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
     */
    private function getConnectionLocation(string $configFile, string $connectionName): Location
    {
        if (! file_exists($configFile)) {
            return new Location($this->getRelativePath($configFile));
        }

        $lineNumber = ConfigFileHelper::findKeyLine($configFile, $connectionName, 'connections');

        return new Location($this->getRelativePath($configFile), $lineNumber < 1 ? null : $lineNumber);
    }
}
