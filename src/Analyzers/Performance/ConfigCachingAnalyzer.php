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
            docsUrl: 'https://laravel.com/docs/configuration#configuration-caching'
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

        /** @var Application&CachesConfiguration $app */
        $app = $this->app;
        $configIsCached = $app->configurationIsCached();

        // Config cached in local environment - not recommended
        if ($environment === 'local' && $configIsCached) {
            return $this->failed(
                'Configuration is cached in local environment',
                [$this->createIssue(
                    message: 'Configuration is cached in local environment',
                    location: new Location('bootstrap/cache/config.php', 1),
                    severity: Severity::Medium,
                    recommendation: 'Configuration caching is not recommended for development. Run "php artisan config:clear" to clear the cache. As you change your config files, the changes will not be reflected unless you clear the cache.',
                    metadata: [
                        'environment' => $environment,
                        'cached' => true,
                        'detection_method' => 'configurationIsCached()',
                    ]
                )]
            );
        }

        // Config not cached in non-local environment - performance issue
        if ($environment !== 'local' && ! $configIsCached) {
            return $this->failed(
                "Configuration is not cached in {$environment} environment",
                [$this->createIssue(
                    message: "Configuration is not cached in {$environment} environment",
                    location: new Location('config', 1),
                    severity: Severity::Medium,
                    recommendation: 'Configuration caching provides significant performance improvements. Add "php artisan config:cache" to your deployment script. This enables a performance improvement by reducing the number of files that need to be loaded and can improve bootstrap time by up to 50%.',
                    metadata: [
                        'environment' => $environment,
                        'cached' => false,
                        'detection_method' => 'configurationIsCached()',
                    ]
                )]
            );
        }

        return $this->passed("Configuration caching is properly configured for {$environment} environment");
    }
}
