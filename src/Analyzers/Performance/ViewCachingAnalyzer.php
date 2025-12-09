<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Filesystem\Filesystem;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use Symfony\Component\Finder\Finder;

/**
 * Analyzes view caching configuration using runtime analysis.
 *
 * Uses runtime analysis to accurately detect view caching status by:
 * - Counting actual blade files using Laravel's view finder
 * - Comparing blade file count with compiled view count
 * - Detecting partial caching scenarios
 * - Supporting custom view paths and package views
 *
 * Checks:
 * - Whether all views are compiled in non-local environments
 * - Whether compiled view count matches blade file count
 *
 * View caching improves performance by pre-compiling blade templates.
 */
class ViewCachingAnalyzer extends AbstractAnalyzer
{
    /**
     * View caching checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

    /**
     * This analyzer is only relevant in production and staging environments.
     *
     * In local/development, views are automatically compiled on-demand,
     * which is fine for development purposes.
     *
     * @var array<string>
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    public function __construct(
        private Filesystem $files,
        private ConfigRepository $config
    ) {
        $this->configRepository = $config;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'view-caching',
            name: 'View Caching Analyzer',
            description: 'Ensures Blade views are properly compiled and cached for optimal performance',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['cache', 'views', 'blade', 'performance', 'optimization'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/view-caching',
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

        if (! is_string($environment)) {
            return $this->error('Invalid environment configuration');
        }

        // Count blade files in all view paths
        $viewCount = 0;

        $this->getViewPaths()->each(function ($path) use (&$viewCount) {
            if (is_dir($path)) {
                $viewCount += $this->countBladeFilesIn($path);
            }
        });

        // Count compiled views
        $compiledPath = $this->config->get('view.compiled');

        if (! is_string($compiledPath)) {
            return $this->error('Invalid view.compiled configuration');
        }

        $compiledViewCount = $this->getCompiledViewCount($compiledPath);

        if ($viewCount > $compiledViewCount) {
            $cachedPercentage = $this->calculateCachedPercentage($compiledViewCount, $viewCount);
            $configLocation = $this->getViewConfigLocation();

            $issues = [
                $this->createIssue(
                    message: sprintf(
                        'Only %d out of %d blade views are compiled (%.1f%% cached)',
                        $compiledViewCount,
                        $viewCount,
                        $cachedPercentage
                    ),
                    location: $configLocation,
                    severity: Severity::Medium,
                    recommendation: 'View caching improves performance by pre-compiling all Blade templates. Add "php artisan view:cache" to your deployment script. This eliminates the need to compile views on each request and is especially important in production environments where view caching can significantly reduce response times.',
                    code: FileParser::getCodeSnippet($configLocation->file, $configLocation->line),
                    metadata: [
                        'environment' => $environment,
                        'total_views' => $viewCount,
                        'compiled_views' => $compiledViewCount,
                        'cached_percentage' => $cachedPercentage,
                        'missing_views' => $viewCount - $compiledViewCount,
                    ]
                ),
            ];

            $summary = sprintf(
                'Views are not fully cached (%d/%d views cached, %.1f%%)',
                $compiledViewCount,
                $viewCount,
                $cachedPercentage
            );

            return $this->resultBySeverity($summary, $issues);
        }

        return $this->passed(sprintf(
            'All %d views are properly cached in %s environment',
            $viewCount,
            $environment
        ));
    }

    /**
     * Get all view paths from Laravel's view finder.
     *
     * @return \Illuminate\Support\Collection<int, string>
     */
    private function getViewPaths(): \Illuminate\Support\Collection
    {
        try {
            /** @var \Illuminate\View\Factory $viewFactory */
            $viewFactory = app('view');
            $finder = $viewFactory->getFinder();

            // Get regular paths and hint paths (package views)
            /** @var \Illuminate\View\FileViewFinder $finder */
            return collect($finder->getPaths())->merge(
                collect($finder->getHints())->flatten()
            )->unique();
        } catch (\Throwable $e) {
            // Fallback to default resource/views path if view factory not available
            return collect([resource_path('views')]);
        }
    }

    /**
     * Count blade files in the given path.
     */
    private function countBladeFilesIn(string $path): int
    {
        if (! is_string($path) || empty(trim($path))) {
            return 0;
        }

        try {
            return collect(
                Finder::create()
                    ->in($path)
                    ->exclude('vendor')
                    ->name('*.blade.php')
                    ->files()
            )->count();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /**
     * Get the count of compiled views in the compiled path.
     */
    private function getCompiledViewCount(string $compiledPath): int
    {
        $globResult = $this->files->glob("{$compiledPath}/*.php");

        // Filesystem::glob() can return false on error
        if ($globResult === false) {
            return 0;
        }

        return is_array($globResult) ? count($globResult) : 0;
    }

    /**
     * Calculate the cached percentage, protecting against division by zero.
     */
    private function calculateCachedPercentage(int $compiledCount, int $totalCount): float
    {
        if ($totalCount === 0) {
            return 0.0;
        }

        return round(($compiledCount / $totalCount) * 100, 1);
    }

    /**
     * Get the location of the view configuration file.
     * Falls back to artisan file if config file not found.
     */
    private function getViewConfigLocation(): Location
    {
        $basePath = $this->getBasePath();
        $configPath = ConfigFileHelper::getConfigPath(
            $basePath,
            'view.php',
            fn ($file) => function_exists('config_path') ? config_path($file) : null
        );

        if (file_exists($configPath)) {
            $lineNumber = ConfigFileHelper::findKeyLine($configPath, 'compiled');

            if ($lineNumber < 1) {
                $lineNumber = 1;
            }

            return new Location($this->getRelativePath($configPath), $lineNumber);
        }

        // Fallback to artisan file if config not found
        $artisanPath = $basePath.DIRECTORY_SEPARATOR.'artisan';

        return new Location($this->getRelativePath($artisanPath), 1);
    }
}
