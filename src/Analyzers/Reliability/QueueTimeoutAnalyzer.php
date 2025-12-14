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
 * - retry_after is greater than timeout
 * - Proper timeout configuration for queue workers
 * - Prevents jobs from being processed twice
 */
class QueueTimeoutAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'queue-timeout-configuration',
            name: 'Queue Timeout Configuration Analyzer',
            description: 'Ensures queue timeout and retry_after values are properly configured to prevent job duplication',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['queue', 'configuration', 'reliability', 'jobs'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/queue-timeout-configuration',
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
            $timeout = $this->getTimeout($connection, $driver);

            // Timeout should be at least several seconds shorter than retry_after
            if ($timeout >= $retryAfter) {
                $configFile = $this->getQueueConfigPath($basePath);
                $location = $this->getConnectionLocation($configFile, $name);

                $issues[] = $this->createIssue(
                    message: "Queue connection '{$name}' has improper timeout configuration",
                    location: $location,
                    severity: Severity::Critical,
                    recommendation: $this->getRecommendation($name, $timeout, $retryAfter),
                    metadata: [
                        'connection' => $name,
                        'driver' => $driver,
                        'timeout' => $timeout,
                        'retry_after' => $retryAfter,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('Queue timeout configurations are correct');
        }

        return $this->failed(
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
     * Get timeout value from connection config or Horizon config.
     *
     * @param  array<string, mixed>  $connection
     */
    private function getTimeout(array $connection, string $driver): int
    {
        // For non-Redis drivers, use default timeout
        if ($driver !== 'redis') {
            return 60;
        }

        // For Redis with Horizon, check Horizon config
        if (! function_exists('config')) {
            return 60;
        }

        try {
            // Get all timeout values from Horizon configuration
            $defaultTimeouts = $this->getArrayValues(config('horizon.defaults', []), 'timeout');
            $envTimeouts = $this->getArrayValues(config('horizon.environments', []), 'timeout');

            $allTimeouts = array_merge($defaultTimeouts, $envTimeouts);

            // Use maximum timeout from Horizon config, fallback to 60
            return ! empty($allTimeouts) ? max($allTimeouts) : 60;
        } catch (\Throwable $e) {
            return 60;
        }
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
            if (is_array($item)) {
                if (isset($item[$key]) && is_numeric($item[$key])) {
                    $values[] = (int) $item[$key];
                }
                // Recursively search nested arrays
                $values = array_merge($values, $this->getArrayValues($item, $key));
            }
        }

        return $values;
    }

    /**
     * Get recommendation message for timeout configuration issue.
     */
    private function getRecommendation(string $connection, int $timeout, int $retryAfter): string
    {
        $suggestedRetryAfter = $timeout + 30;

        return sprintf(
            'The queue timeout value must be at least several seconds shorter than the retry_after value. '.
            "Your '%s' queue connection's retry_after is set to %d seconds while ".
            'your timeout is %d seconds. This can cause jobs to be processed twice or the queue worker to crash. '.
            'Solution: Either increase retry_after to at least %d seconds, or decrease the timeout to less than %d seconds. '.
            'The retry_after should be: max(timeout) + buffer (e.g., %d seconds).',
            $connection,
            $retryAfter,
            $timeout,
            $suggestedRetryAfter,
            $retryAfter,
            30
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
