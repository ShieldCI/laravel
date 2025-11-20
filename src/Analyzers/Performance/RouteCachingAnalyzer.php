<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesRoutes;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Analyzes route caching setup using Laravel's official API.
 *
 * Checks for:
 * - Routes cached in local/dev environment (not recommended)
 * - Routes not cached in production (major performance issue)
 * - Proper use of php artisan route:cache
 *
 * This analyzer uses Laravel's CachesRoutes interface to accurately detect
 * route caching status across all Laravel versions.
 */
class RouteCachingAnalyzer extends AbstractAnalyzer
{
    /**
     * Route caching checks are not applicable in CI environments.
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
            id: 'route-caching',
            name: 'Route Caching',
            description: 'Ensures route caching is properly configured for optimal performance',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['cache', 'routes', 'performance', 'optimization'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/route-caching',
            timeToFix: 5
        );
    }

    public function shouldRun(): bool
    {
        // Check if the application implements CachesRoutes interface
        return $this->app instanceof CachesRoutes;
    }

    public function getSkipReason(): string
    {
        return 'Application does not implement CachesRoutes interface';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $environment = $this->getEnvironment();

        /** @var Application&CachesRoutes $app */
        $app = $this->app;
        $routesAreCached = $app->routesAreCached();

        if ($environment === 'local' && $routesAreCached) {
            $issues[] = $this->createIssue(
                message: 'Routes are cached in local environment',
                location: new Location($this->getCachedRoutesPath(), 1),
                severity: Severity::Low,
                recommendation: 'Route caching is not recommended for development. Run "php artisan route:clear" to clear the cache. Route changes won\'t be reflected until you clear the cache.',
                metadata: [
                    'environment' => 'local',
                    'cached' => true,
                    'detection_method' => 'routesAreCached()',
                ]
            );
        } elseif ($environment !== 'local' && ! $routesAreCached) {
            $issues[] = $this->createIssue(
                message: "Routes are not cached in {$environment} environment",
                location: new Location($this->getRoutesDirectory(), 1),
                severity: Severity::High,
                recommendation: 'Route caching provides significant performance improvements (up to 5x faster). Add "php artisan route:cache" to your deployment script. Remember to regenerate the cache every time you deploy.',
                metadata: [
                    'environment' => $environment,
                    'cached' => false,
                    'detection_method' => 'routesAreCached()',
                ]
            );
        }

        if (empty($issues)) {
            return $this->passed("Route caching is properly configured for {$environment} environment");
        }

        return $this->failed(
            sprintf('Found %d route caching issues', count($issues)),
            $issues
        );
    }

    /**
     * Get the path to the cached routes file.
     * Tries multiple locations for different Laravel versions.
     */
    private function getCachedRoutesPath(): string
    {
        $basePath = function_exists('base_path') ? base_path() : getcwd();

        $paths = [
            $basePath.'/bootstrap/cache/routes-v7.php', // Laravel 10+
            $basePath.'/bootstrap/cache/routes.php',     // Older versions
        ];

        foreach ($paths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        return $basePath.'/bootstrap/cache/routes-v7.php';
    }

    /**
     * Get the routes directory path.
     */
    private function getRoutesDirectory(): string
    {
        $basePath = function_exists('base_path') ? base_path() : getcwd();

        return $basePath.'/routes';
    }
}
