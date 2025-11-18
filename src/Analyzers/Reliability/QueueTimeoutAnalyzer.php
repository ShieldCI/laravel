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
            name: 'Queue Timeout Configuration',
            description: 'Ensures queue timeout and retry_after values are properly configured to prevent job duplication',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['queue', 'configuration', 'reliability', 'jobs'],
            docsUrl: 'https://laravel.com/docs/queues#timeout'
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
                $configFile = ConfigFileHelper::getConfigPath($this->basePath, 'queue.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);
                $issues[] = $this->createIssue(
                    message: "Queue connection '{$name}' has improper timeout configuration",
                    location: new Location($configFile, ConfigFileHelper::findKeyLine($configFile, $name, 'connections')),
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
     * @param  array<string, mixed>  $connection
     */
    private function getRetryAfter(array $connection): int
    {
        $retryAfter = $connection['retry_after'] ?? 90;

        return is_numeric($retryAfter) ? (int) $retryAfter : 90;
    }

    /**
     * @param  array<string, mixed>  $connection
     */
    private function getTimeout(array $connection, string $driver): int
    {
        // For Redis with Horizon, check Horizon config
        if ($driver === 'redis' && config('horizon')) {
            $horizonDefaults = config('horizon.defaults', []);
            $horizonEnvironments = config('horizon.environments', []);

            /** @var array<int> $timeouts */
            $timeouts = [];

            // Get timeouts from defaults
            if (is_array($horizonDefaults)) {
                foreach ($horizonDefaults as $key => $value) {
                    if (is_array($value) && isset($value['timeout']) && is_numeric($value['timeout'])) {
                        $timeouts[] = (int) $value['timeout'];
                    }
                }
            }

            // Get timeouts from environments
            if (is_array($horizonEnvironments)) {
                foreach ($horizonEnvironments as $env => $supervisors) {
                    if (is_array($supervisors)) {
                        foreach ($supervisors as $supervisor => $config) {
                            if (is_array($config) && isset($config['timeout']) && is_numeric($config['timeout'])) {
                                $timeouts[] = (int) $config['timeout'];
                            }
                        }
                    }
                }
            }

            if (! empty($timeouts)) {
                return max($timeouts);
            }
        }

        // Default queue worker timeout
        return 60;
    }

    private function getRecommendation(string $connection, int $timeout, int $retryAfter): string
    {
        $suggestedRetryAfter = $timeout + 30;

        return 'The queue timeout value must be at least several seconds shorter than the retry_after value. '.
               "Your '{$connection}' queue connection's retry_after is set to {$retryAfter} seconds while ".
               "your timeout is {$timeout} seconds. This can cause jobs to be processed twice or the queue worker to crash. ".
               "Solution: Either increase retry_after to at least {$suggestedRetryAfter} seconds, or decrease the timeout to less than {$retryAfter} seconds. ".
               'The retry_after should be: max(timeout) + buffer (e.g., 30 seconds).';
    }

    /**
     * @return array<string, mixed>
     */
    private function getQueueConfig(): array
    {
        $configFile = ConfigFileHelper::getConfigPath($this->basePath, 'queue.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        if (! file_exists($configFile)) {
            return [];
        }

        $config = include $configFile;

        return is_array($config) ? $config : [];
    }
}
