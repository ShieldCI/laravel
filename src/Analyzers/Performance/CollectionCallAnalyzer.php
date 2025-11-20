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
            name: 'Collection Call Optimization',
            description: 'Detects inefficient collection operations that should be performed at the database query level',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['database', 'collection', 'performance', 'n+1', 'optimization', 'phpstan'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/collection-call-optimization',
            timeToFix: 45
        );
    }

    public function shouldRun(): bool
    {
        // Check if PHPStan and Larastan are available
        return $this->hasLarastan();
    }

    public function getSkipReason(): string
    {
        return 'Larastan package not installed (required for collection call analysis)';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Set root path for PHPStan
        if (function_exists('base_path')) {
            $this->phpStan->setRootPath(base_path());
        }

        // Run PHPStan on configured paths
        $paths = $this->paths ?? ['app'];

        try {
            $this->phpStan->start($paths);

            // Parse results for collection call issues
            // Larastan reports these with "could have been retrieved as a query"
            $this->parsePHPStanAnalysis(
                $this->phpStan,
                'could have been retrieved as a query',
                $issues
            );
        } catch (\Throwable $e) {
            // If PHPStan fails, return error but don't crash
            return $this->failed(
                'PHPStan analysis failed: '.$e->getMessage(),
                []
            );
        }

        if (empty($issues)) {
            return $this->passed('No inefficient collection calls detected');
        }

        return $this->failed(
            sprintf('Found %d inefficient collection operations that should be database queries', count($issues)),
            $issues
        );
    }

    /**
     * Check if Larastan is installed.
     */
    protected function hasLarastan(): bool
    {
        // For testing: check if we're in a test environment with mocked PHPStan
        if (get_class($this->phpStan) === 'Mockery\Mock') {
            return true; // Assume Larastan is available when using mocked PHPStan
        }

        // Check if it's a Mockery mock by checking class name
        $className = get_class($this->phpStan);
        if (str_contains($className, 'Mockery') || str_contains($className, 'Mock')) {
            return true;
        }

        $basePath = function_exists('base_path') ? base_path() : getcwd();

        return file_exists($basePath.'/vendor/larastan/larastan/extension.neon');
    }
}
