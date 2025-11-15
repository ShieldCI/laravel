<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Analyzes route caching setup.
 *
 * Checks for:
 * - Routes cached in local/dev environment (not recommended)
 * - Routes not cached in production (major performance issue)
 * - Proper use of php artisan route:cache
 */
class RouteCachingAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Route caching checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'route-caching',
            name: 'Route Caching',
            description: 'Ensures route caching is properly configured for optimal performance',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['cache', 'routes', 'performance', 'optimization'],
            docsUrl: 'https://laravel.com/docs/routing#route-caching'
        );
    }

    public function shouldRun(): bool
    {
        return file_exists($this->basePath.'/bootstrap/cache');
    }

    public function getSkipReason(): string
    {
        return 'Bootstrap cache directory (bootstrap/cache) not found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $environment = $this->getEnvironment();
        $routesAreCached = $this->routesAreCached();

        if ($environment === 'local' && $routesAreCached) {
            $issues[] = $this->createIssue(
                message: 'Routes are cached in local environment',
                location: new Location($this->basePath.'/bootstrap/cache/routes-v7.php', 1),
                severity: Severity::Low,
                recommendation: 'Route caching is not recommended for development. Run "php artisan route:clear" to clear the cache. Route changes won\'t be reflected until you clear the cache.',
                metadata: ['environment' => 'local', 'cached' => true]
            );
        } elseif ($environment !== 'local' && ! $routesAreCached) {
            $issues[] = $this->createIssue(
                message: "Routes are not cached in {$environment} environment",
                location: new Location($this->basePath.'/routes', 1),
                severity: Severity::High,
                recommendation: 'Route caching provides significant performance improvements (up to 5x faster). Add "php artisan route:cache" to your deployment script. Remember to regenerate the cache every time you deploy.',
                metadata: ['environment' => $environment, 'cached' => false]
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

    private function routesAreCached(): bool
    {
        // Laravel stores cached routes in bootstrap/cache/routes-v7.php (or routes.php in older versions)
        return file_exists($this->basePath.'/bootstrap/cache/routes-v7.php')
            || file_exists($this->basePath.'/bootstrap/cache/routes.php');
    }
}
