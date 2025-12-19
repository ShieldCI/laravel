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

    /**
     * Only check debug logging in production and staging environments.
     * Debug logging is acceptable in local, development, and testing environments.
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    public function __construct(
        private ConfigRepository $config
    ) {
        $this->configRepository = $config;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'debug-log-level',
            name: 'Debug Log Level Analyzer',
            description: 'Ensures log level is not set to debug in production for optimal performance',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['logging', 'performance', 'configuration'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/debug-log-level',
            timeToFix: 5
        );
    }

    public function shouldRun(): bool
    {
        return $this->isRelevantForCurrentEnvironment();
    }

    public function getSkipReason(): string
    {
        if (! $this->isRelevantForCurrentEnvironment()) {
            $currentEnv = $this->getEnvironment();
            $relevantEnvs = implode(', ', $this->relevantEnvironments ?? []);

            return "Not relevant in '{$currentEnv}' environment (only relevant in: {$relevantEnvs})";
        }

        return 'Analyzer is not applicable in current context';
    }

    protected function runAnalysis(): ResultInterface
    {
        $environment = $this->getEnvironment();

        // Check for debug logging issues in production/staging
        $issues = [];
        $channels = $this->getChannelsToCheck();

        foreach ($channels as $channel) {
            $this->checkChannelLogLevel($channel, $issues);
        }

        if (count($issues) === 0) {
            return $this->passed("Log level is properly configured for {$environment} environment");
        }

        return $this->resultBySeverity(
            sprintf('Debug log level detected in %s environment', $environment),
            $issues
        );
    }

    /**
     * Get all channels to check (default channel + stack channels if applicable).
     *
     * @return array<string>
     */
    private function getChannelsToCheck(): array
    {
        $channels = [];
        $defaultChannel = $this->config->get('logging.default');

        if ($defaultChannel && is_string($defaultChannel)) {
            $channels[] = $defaultChannel;

            // If using stack, add all stack channels
            if ($defaultChannel === 'stack') {
                /** @var mixed $stackChannels */
                $stackChannels = $this->config->get('logging.channels.stack.channels', []);

                // Ensure stackChannels is actually an array before iterating
                if (is_array($stackChannels)) {
                    foreach ($stackChannels as $channel) {
                        if (is_string($channel)) {
                            $channels[] = $channel;
                        }
                    }
                }
            }
        }

        return $channels;
    }

    /**
     * Check if a specific log channel is configured with debug level.
     *
     * @param  array<int, mixed>  $issues
     */
    private function checkChannelLogLevel(string $channel, array &$issues): void
    {
        $level = $this->config->get("logging.channels.{$channel}.level");
        $normalizedLevel = is_string($level) ? strtolower($level) : null;

        if ($normalizedLevel === 'debug') {
            $environment = $this->getEnvironment();
            $basePath = $this->getBasePath();
            $configPath = ConfigFileHelper::getConfigPath(
                $basePath,
                'logging.php',
                fn ($file) => function_exists('config_path') ? config_path($file) : null
            );

            // Fallback to buildPath if ConfigFileHelper returns empty string
            if ($configPath === '' || ! file_exists($configPath)) {
                $configPath = $this->buildPath('config', 'logging.php');
            }

            $lineNumber = ConfigFileHelper::findNestedKeyLine($configPath, 'channels', 'level', $channel);

            $issues[] = $this->createIssueWithSnippet(
                message: "Log channel '{$channel}' is set to debug level in {$environment} environment",
                filePath: $configPath,
                lineNumber: $lineNumber,
                severity: Severity::High,
                recommendation: "Change the log level to 'info' or higher in production. Debug logging causes 50-300% performance degradation, generates massive log files that can exhaust disk space, and exposes sensitive data in logs. This is a critical production misconfiguration. Update your logging configuration or set LOG_LEVEL environment variable to 'info', 'warning', or 'error'.",
                code: 'debug-log-level',
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
