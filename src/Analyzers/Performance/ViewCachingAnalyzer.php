<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Filesystem\Filesystem;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use Symfony\Component\Finder\Finder;

/**
 * Analyzes view caching freshness using timestamp comparison.
 *
 * Uses timestamp-based analysis to detect view caching status by:
 * - Finding the newest blade file modification time
 * - Finding the newest compiled view modification time
 * - Comparing timestamps to determine if cache is fresh
 *
 * Checks:
 * - Whether compiled views exist
 * - Whether compiled views are newer than all blade files
 *
 * This approach avoids the complexity of hash verification and handles
 * Laravel's inlining of includes, components, and slots.
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

        $compiledPath = $this->config->get('view.compiled');

        if (! is_string($compiledPath)) {
            return $this->error('Invalid view.compiled configuration');
        }

        $newestBladeMtime = $this->getNewestBladeTimestamp();

        // No blade files found = passed (nothing to cache)
        if ($newestBladeMtime === null) {
            return $this->passed('No Blade templates found to cache');
        }

        if (! is_dir($compiledPath)) {
            $issues = [
                $this->createIssue(
                    message: 'Compiled views directory does not exist - view cache has not been generated',
                    location: null,
                    severity: Severity::Medium,
                    recommendation: 'Run "php artisan view:cache" as part of your deployment process to generate compiled views.',
                    metadata: [
                        'environment' => $environment,
                        'compiled_path' => $compiledPath,
                        'newest_blade_mtime' => date('Y-m-d H:i:s', $newestBladeMtime),
                    ]
                ),
            ];

            return $this->resultBySeverity('View cache has not been generated', $issues);
        }

        $newestCompiledMtime = $this->getNewestCompiledTimestamp($compiledPath);

        // Blade files exist but no compiled views = not cached at all
        if ($newestCompiledMtime === null) {
            $issues = [
                $this->createIssue(
                    message: 'No compiled views found - view cache has not been generated',
                    location: null,
                    severity: Severity::Medium,
                    recommendation: 'Run "php artisan view:cache" as part of your deployment process to pre-compile all Blade templates. This eliminates on-demand compilation overhead in production.',
                    metadata: [
                        'environment' => $environment,
                        'compiled_path' => $compiledPath,
                        'newest_blade_mtime' => date('Y-m-d H:i:s', $newestBladeMtime),
                    ]
                ),
            ];

            return $this->resultBySeverity('View cache has not been generated', $issues);
        }

        // Blade files newer than newest compiled = stale cache
        if ($newestBladeMtime > $newestCompiledMtime) {
            $staleDuration = max(0, $newestBladeMtime - $newestCompiledMtime);

            $issues = [
                $this->createIssue(
                    message: sprintf(
                        'View cache is stale - Blade templates were modified %s after cache was generated',
                        $this->humanDuration($staleDuration)
                    ),
                    location: null,
                    severity: Severity::Medium,
                    recommendation: 'Run "php artisan view:cache" to regenerate the view cache. Add this command to your deployment script after any code changes.',
                    metadata: [
                        'environment' => $environment,
                        'newest_blade_mtime' => date('Y-m-d H:i:s', $newestBladeMtime),
                        'newest_compiled_mtime' => date('Y-m-d H:i:s', $newestCompiledMtime),
                        'stale_by_seconds' => $staleDuration,
                        'cache_age_seconds' => max(0, time() - $newestCompiledMtime),
                    ]
                ),
            ];

            return $this->resultBySeverity('View cache is stale', $issues);
        }

        $cacheAge = max(0, time() - $newestCompiledMtime);

        return $this->passed(sprintf(
            'View cache is fresh in %s environment (cached %s ago)',
            $environment,
            $this->humanDuration($cacheAge)
        ));
    }

    /**
     * Get view paths to check for freshness.
     *
     * By default, only returns application view paths (e.g., resources/views).
     * Package views (from hints) are excluded by default to avoid false positives
     * when composer install/update changes vendor file timestamps.
     *
     * Set 'shieldci.analyzers.performance.view-caching.include_package_views' to true to include them.
     *
     * @return \Illuminate\Support\Collection<int, string>
     */
    private function getViewPaths(): \Illuminate\Support\Collection
    {
        try {
            /** @var \Illuminate\View\Factory $viewFactory */
            $viewFactory = app('view');
            $finder = $viewFactory->getFinder();

            /** @var \Illuminate\View\FileViewFinder $finder */
            $paths = collect($finder->getPaths());

            // Only include package views if explicitly configured
            $includePackageViews = $this->config->get('shieldci.analyzers.performance.view-caching.include_package_views', false);

            if ($includePackageViews) {
                $paths = $paths->merge(
                    collect($finder->getHints())->flatten()
                );
            }

            return $paths->unique();
        } catch (\Throwable $e) {
            // Fallback to default resource/views path if view factory not available
            return collect([resource_path('views')]);
        }
    }

    /**
     * Get the newest modification timestamp across all blade files.
     */
    private function getNewestBladeTimestamp(): ?int
    {
        $newest = 0;

        $this->getViewPaths()->each(function ($path) use (&$newest) {
            if (! is_string($path) || empty(trim($path)) || ! is_dir($path)) {
                return;
            }

            try {
                $finder = Finder::create()
                    ->in($path)
                    ->ignoreUnreadableDirs()
                    ->name('*.blade.php')
                    ->files();

                foreach ($finder as $file) {
                    $mtime = $file->getMTime();
                    if ($mtime > $newest) {
                        $newest = $mtime;
                    }
                }
            } catch (\Throwable $e) {
                // Skip paths that cause errors
            }
        });

        return $newest > 0 ? $newest : null;
    }

    /**
     * Get the newest modification timestamp from compiled views.
     *
     * When view:cache runs, all compiled views get similar timestamps.
     * The newest compiled file represents when the cache was last generated.
     * If any blade file is newer than this, the cache is stale.
     */
    private function getNewestCompiledTimestamp(string $compiledPath): ?int
    {
        $globResult = $this->files->glob("{$compiledPath}/*.php");

        if ($globResult === false || empty($globResult)) {
            return null;
        }

        $newest = 0;

        foreach ($globResult as $file) {
            $mtime = @filemtime($file);
            if ($mtime !== false && $mtime > $newest) {
                $newest = $mtime;
            }
        }

        return $newest > 0 ? $newest : null;
    }

    /**
     * Format a duration in seconds to a human-readable string.
     */
    private function humanDuration(int $seconds): string
    {
        if ($seconds < 60) {
            return $seconds === 1 ? '1 second' : "{$seconds} seconds";
        }

        if ($seconds < 3600) {
            $minutes = (int) floor($seconds / 60);

            return $minutes === 1 ? '1 minute' : "{$minutes} minutes";
        }

        if ($seconds < 86400) {
            $hours = (int) floor($seconds / 3600);

            return $hours === 1 ? '1 hour' : "{$hours} hours";
        }

        $days = (int) floor($seconds / 86400);

        return $days === 1 ? '1 day' : "{$days} days";
    }
}
