<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Analyzes configuration caching setup using Laravel's proper API.
 *
 * Uses Laravel's configurationIsCached() method to check:
 * - Config cached in local/dev environment (not recommended)
 * - Config not cached in production (performance issue)
 *
 * This approach is superior to file-based checking because it uses
 * Laravel's official API and properly checks the CachesConfiguration interface.
 */
class ConfigCachingAnalyzer extends AbstractAnalyzer
{
    /**
     * Config caching checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

    public function __construct(
        private Application $app,
        ConfigRepository $config
    ) {
        $this->configRepository = $config;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'config-caching',
            name: 'Configuration Caching',
            description: 'Ensures configuration caching is properly configured for each environment',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['cache', 'configuration', 'performance', 'optimization'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/config-caching',
            timeToFix: 5
        );
    }

    public function shouldRun(): bool
    {
        // Skip if application does not implement CachesConfiguration interface
        if (! interface_exists(CachesConfiguration::class)) {
            return false;
        }

        if (! ($this->app instanceof CachesConfiguration)) {
            return false;
        }

        return true;
    }

    public function getSkipReason(): string
    {
        if (! interface_exists(CachesConfiguration::class)) {
            return 'CachesConfiguration interface not available (requires Laravel 7+)';
        }

        if (! ($this->app instanceof CachesConfiguration)) {
            return 'Application does not implement CachesConfiguration interface';
        }

        return 'Analyzer is not applicable in current context';
    }

    protected function runAnalysis(): ResultInterface
    {
        $environment = $this->getEnvironment();

        // Type assertion for PHPStan
        if (! ($this->app instanceof CachesConfiguration)) {
            return $this->error('Application does not implement CachesConfiguration interface');
        }

        try {
            $configIsCached = $this->app->configurationIsCached();
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('Failed to check configuration cache status: %s', $e->getMessage())
            );
        }

        $issues = [];

        // Config cached in local/development environment - not recommended
        if ($this->isDevelopmentEnvironment($environment) && $configIsCached) {
            $configPath = $this->getCachedConfigPath();

            $issues[] = $this->createIssue(
                message: "Configuration is cached in {$environment} environment",
                location: new Location($configPath, 1),
                severity: Severity::Medium,
                recommendation: 'Configuration caching is not recommended for '.$environment.'. Run "php artisan config:clear" to clear the cache. As you change your config files, the changes will not be reflected unless you clear the cache.',
                metadata: [
                    'environment' => $environment,
                    'cached' => true,
                    'detection_method' => 'configurationIsCached()',
                ]
            );
        }

        // Config not cached in production/staging - performance issue
        if ($this->shouldCacheConfig($environment) && ! $configIsCached) {
            $configPath = $this->getAppConfigPath();

            $issues[] = $this->createIssue(
                message: "Configuration is not cached in {$environment} environment",
                location: new Location($configPath, 1),
                severity: Severity::High,
                recommendation: 'Configuration caching is critical for production performance - it improves bootstrap time by up to 50% on every request. Add "php artisan config:cache" to your deployment script. Without caching, Laravel must load and parse all config files on every request, causing significant performance degradation.',
                metadata: [
                    'environment' => $environment,
                    'cached' => false,
                    'detection_method' => 'configurationIsCached()',
                ]
            );
        }

        if (count($issues) === 0) {
            return $this->passed("Configuration caching is properly configured for {$environment} environment");
        }

        return $this->resultBySeverity(
            sprintf('Configuration caching is not properly configured in %s environment', $environment),
            $issues
        );
    }

    /**
     * Check if the environment is a development environment.
     */
    private function isDevelopmentEnvironment(string $environment): bool
    {
        return in_array(strtolower($environment), ['local', 'development', 'testing'], true);
    }

    /**
     * Check if configuration should be cached in this environment.
     */
    private function shouldCacheConfig(string $environment): bool
    {
        return in_array(strtolower($environment), ['production', 'staging'], true);
    }

    /**
     * Get the path to the cached config file.
     */
    private function getCachedConfigPath(): string
    {
        return $this->buildPath('bootstrap', 'cache', 'config.php');
    }

    /**
     * Get the path to the app config file.
     */
    private function getAppConfigPath(): string
    {
        $basePath = $this->getBasePath();

        $configPath = ConfigFileHelper::getConfigPath(
            $basePath,
            'app.php',
            fn ($file) => function_exists('config_path') ? config_path($file) : null
        );

        // Fallback if ConfigFileHelper returns empty string
        if ($configPath === '' || ! file_exists($configPath)) {
            return $this->buildPath('config', 'app.php');
        }

        return $configPath;
    }
}
