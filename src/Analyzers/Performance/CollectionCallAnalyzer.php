<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Concerns\ParsesPHPStanAnalysis;
use ShieldCI\Support\PHPStan;

/**
 * Detects inefficient collection operations using PHPStan/Larastan.
 *
 * Uses Larastan's built-in noUnnecessaryCollectionCall rule to detect:
 * - Model::all()->count() instead of Model::count()
 * - Model::all()->sum() instead of Model::sum()
 * - get()->count() instead of count()
 * - Other collection aggregations that could be database queries
 *
 * This approach leverages Larastan's battle-tested detection logic
 * instead of custom AST parsing.
 */
class CollectionCallAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanAnalysis;

    /**
     * PHPStan will not run in CI mode by default (can be slow).
     */
    public static bool $runInCI = false;

    private PHPStan $phpStan;

    public function __construct(PHPStan $phpStan)
    {
        $this->phpStan = $phpStan;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'collection-call-optimization',
            name: 'Collection Call Optimization Analyzer',
            description: 'Detects inefficient collection operations that should be performed at the database query level',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['database', 'collection', 'performance', 'n+1', 'optimization', 'phpstan'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/collection-call-optimization',
            timeToFix: 45
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Set root path for PHPStan
        $basePath = $this->getBasePath();

        if (is_string($basePath) && $basePath !== '') {
            $this->phpStan->setRootPath($basePath);
        }

        // Run PHPStan on configured paths
        $paths = $this->paths;
        if (! is_array($paths) || empty($paths)) {
            // Use paths from config, filtering to code directories only
            // PHPStan should analyze code, not configs/views/migrations
            $configPaths = config('shieldci.paths.analyze', ['app']);

            if (is_array($configPaths)) {
                $paths = array_values(array_filter($configPaths, function ($path) {
                    // Only analyze code directories, not configs, views, migrations, etc.
                    if (! is_string($path)) {
                        return false;
                    }

                    return ! str_starts_with($path, 'config')
                        && ! str_starts_with($path, 'database')
                        && ! str_starts_with($path, 'resources')
                        && ! str_starts_with($path, 'routes');
                }));
            } else {
                $paths = ['app'];
            }

            // Fallback to 'app' if filtering removed everything
            if (empty($paths)) {
                $paths = ['app'];
            }
        }

        try {
            $this->phpStan->start($paths);

            // Parse results for collection call issues
            // Use regex pattern for flexibility across Larastan versions
            // Matches variations of "could have been retrieved as a query"
            // or "Called X on collection" patterns
            $this->pregMatchPHPStanAnalysis(
                $this->phpStan,
                '/could\s+have\s+been\s+retrieved\s+as\s+a\s+query|called\s+.*\s+on\s+.*collection/i',
                $issues
            );
        } catch (\Throwable $e) {
            // If PHPStan fails, return error but don't crash
            return $this->error(
                sprintf(
                    'PHPStan analysis failed: %s. Ensure PHPStan and Larastan are properly configured.',
                    $e->getMessage()
                ),
                []
            );
        }

        if (count($issues) === 0) {
            return $this->passed('No inefficient collection calls detected');
        }

        return $this->resultBySeverity(
            sprintf('Found %d inefficient collection operation(s) that should be database queries', count($issues)),
            $issues
        );
    }
}
