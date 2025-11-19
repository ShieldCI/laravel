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
 * Analyzes log level configuration for performance issues.
 *
 * Checks for debug-level logging in non-local environments which can:
 * - Significantly impact application performance
 * - Generate excessive log files
 * - Expose sensitive debugging information
 *
 * Skips local/development/testing environments where debug logging is acceptable for development.
 * Uses Laravel's ConfigRepository for proper configuration checking.
 */
class DebugLogAnalyzer extends AbstractAnalyzer
{
    /**
     * Log level checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

    public function __construct(
        private ConfigRepository $config
    ) {
        $this->configRepository = $config;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'debug-log-level',
            name: 'Debug Log Level',
            description: 'Ensures log level is not set to debug in production for optimal performance',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['logging', 'performance', 'configuration'],
            docsUrl: 'https://laravel.com/docs/logging#log-levels'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $environment = $this->getEnvironment();

        // Check if debug logging is detected
        $hasDebugLogging = $this->hasDebugLogging();

        // Debug logging is acceptable in local, development, and testing environments
        if ($hasDebugLogging && in_array($environment, ['local', 'development', 'testing'])) {
            return $this->passed("Debug logging is acceptable in {$environment} environment");
        }

        // For production/staging, check for issues
        $issues = [];

        // Check default log channel
        $defaultChannel = $this->config->get('logging.default');
        if ($defaultChannel && is_string($defaultChannel)) {
            $this->checkChannelLogLevel($defaultChannel, $issues);
        }

        // Check if using stack driver with multiple channels
        if ($defaultChannel === 'stack') {
            /** @var array<int, mixed> $stackChannels */
            $stackChannels = $this->config->get('logging.channels.stack.channels', []);
            foreach ($stackChannels as $channel) {
                if (is_string($channel)) {
                    $this->checkChannelLogLevel($channel, $issues);
                }
            }
        }

        if (! empty($issues)) {
            return $this->failed(
                "Debug log level detected in {$environment} environment",
                $issues
            );
        }

        return $this->passed("Log level is properly configured for {$environment} environment");
    }

    /**
     * Check if any log channel has debug level configured.
     */
    private function hasDebugLogging(): bool
    {
        $defaultChannel = $this->config->get('logging.default');

        if ($defaultChannel && is_string($defaultChannel)) {
            $level = $this->config->get("logging.channels.{$defaultChannel}.level");
            if ($level === 'debug') {
                return true;
            }
        }

        // Check stack channels
        if ($defaultChannel === 'stack') {
            /** @var array<int, mixed> $stackChannels */
            $stackChannels = $this->config->get('logging.channels.stack.channels', []);
            foreach ($stackChannels as $channel) {
                if (is_string($channel)) {
                    $level = $this->config->get("logging.channels.{$channel}.level");
                    if ($level === 'debug') {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check if a specific log channel is configured with debug level.
     *
     * @param  array<int, mixed>  $issues
     */
    private function checkChannelLogLevel(string $channel, array &$issues): void
    {
        $level = $this->config->get("logging.channels.{$channel}.level");

        if ($level === 'debug') {
            $environment = $this->getEnvironment();

            $issues[] = $this->createIssue(
                message: "Log channel '{$channel}' is set to debug level in {$environment} environment",
                location: new Location('config/logging.php', 1),
                severity: Severity::Medium,
                recommendation: "Change the log level to 'info' or higher in production. Debug logging can significantly impact performance and generate excessive log files. Update your logging configuration or set LOG_LEVEL environment variable to 'info', 'warning', or 'error'.",
                metadata: [
                    'environment' => $environment,
                    'channel' => $channel,
                    'level' => $level,
                    'detection_method' => 'config_repository',
                ]
            );
        }
    }
}
