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

/**
 * Analyzes log level configuration for performance issues.
 *
 * Checks for debug-level logging in non-local environments which can:
 * - Significantly impact application performance
 * - Generate excessive log files
 * - Expose sensitive debugging information
 *
 * Skips local/development/testing environments where debug logging is acceptable for development.
 * Uses Laravel's Config for proper configuration checking.
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
        private Config $config
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

        /** @var array<Issue> $issues */
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

        return array_values(array_unique($channels));
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

            // Determine whether the channel is actually authored in config/logging.php.
            // Channels injected at runtime by a package/framework (e.g. laravel-cloud-socket)
            // are not present in the file, so reporting a file/line location and a
            // "update config/logging.php" recommendation would be misleading.
            // "Injected" only when the channel is absent AND the file genuinely parsed.
            // parseConfigArray() returns [] for a missing/unreadable/unparseable file, in
            // which case we cannot tell — fall back to the legacy behaviour rather than
            // mislabel. The second parse only runs when the channel was not found (&& short-circuits).
            $authoredLine = ConfigFileHelper::findNestedArrayKeyLine($configPath, 'channels', $channel);
            $isInjected = $authoredLine === null
                && ConfigFileHelper::parseConfigArray($configPath) !== [];

            $lineNumber = $isInjected
                ? null
                : ConfigFileHelper::findNestedKeyLine($configPath, 'channels', 'level', $channel);

            $issues[] = $this->createIssueWithSnippet(
                message: "Log channel '{$channel}' is set to debug level in {$environment} environment",
                filePath: $configPath,
                lineNumber: $lineNumber,
                severity: $this->metadata()->severity,
                recommendation: $isInjected
                    ? $this->injectedChannelRecommendation($channel)
                    : "Set the log level to 'info' or higher in production by updating your logging configuration or setting the LOG_LEVEL environment variable. Debug logging causes significant performance degradation, generates excessive log files that can exhaust disk space, and exposes sensitive data.",
                metadata: [
                    'environment' => $environment,
                    'channel' => $channel,
                    'level' => $level,
                    'detection_method' => $isInjected ? 'runtime_injected' : 'config_repository',
                    'injected' => $isInjected,
                    'code' => 'debug-log-level',
                ]
            );
        }
    }

    /**
     * Build a recommendation for a channel that is injected at runtime rather than
     * authored in config/logging.php. Such channels cannot be fixed by editing that
     * file (the framework/package overwrites the entry after config load), so the
     * guidance must name the real lever per known channel, with a generic fallback.
     */
    private function injectedChannelRecommendation(string $channel): string
    {
        $known = [
            'laravel-cloud-socket' => "Channel '{$channel}' is injected at runtime by Laravel "
                .'(Illuminate\\Foundation\\Cloud::configureCloudLogging) and reads LOG_LEVEL from the '
                .'process environment, not config/logging.php. Under config:cache a .env value is not '
                .'enough — set LOG_LEVEL as a real platform environment variable, or re-assert the level '
                ."in a service provider boot() (e.g. config(['logging.channels.{$channel}.level' => 'info'])). "
                .'Debug logging causes performance degradation, excessive log volume, and can expose sensitive data.',
            'nightwatch' => "Channel '{$channel}' is injected at runtime by Laravel Nightwatch. Set "
                .'NIGHTWATCH_LOG_LEVEL (or nightwatch.filtering.log_level) to info or higher; it inherits '
                .'LOG_LEVEL by default. Debug logging causes performance degradation, excessive log volume, '
                .'and can expose sensitive data.',
        ];

        return $known[$channel] ?? "Channel '{$channel}' is not defined in config/logging.php; it is "
            .'registered at runtime by a package or the framework. Configure its level via that package\'s '
            .'documented environment variable/config, or override it to info or higher in a service provider '
            ."boot() (e.g. config(['logging.channels.{$channel}.level' => 'info'])). Debug logging causes "
            .'performance degradation, excessive log volume, and can expose sensitive data.';
    }
}
