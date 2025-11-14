<?php

declare(strict_types=1);

namespace ShieldCI;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Results\AnalysisResult;

/**
 * Manages and runs analyzers.
 */
class AnalyzerManager
{
    /**
     * @param  array<class-string<AnalyzerInterface>>  $analyzerClasses
     */
    public function __construct(
        protected Config $config,
        protected array $analyzerClasses,
        protected Container $container,
    ) {}

    /**
     * Get all registered analyzers.
     *
     * @return Collection<int, AnalyzerInterface>
     */
    public function getAnalyzers(): Collection
    {
        $disabledAnalyzersConfig = $this->config->get('shieldci.disabled_analyzers', []);
        /** @var array<string> $disabledAnalyzers */
        $disabledAnalyzers = is_array($disabledAnalyzersConfig) ? $disabledAnalyzersConfig : [];

        $analyzersConfigRaw = $this->config->get('shieldci.analyzers', []);
        /** @var array<string, bool> $analyzersConfig */
        $analyzersConfig = is_array($analyzersConfigRaw) ? $analyzersConfigRaw : [];
        $enabledCategories = collect($analyzersConfig)
            ->filter(fn ($enabled) => $enabled === true)
            ->keys()
            ->toArray();

        // CI mode configuration
        $isCiMode = $this->config->get('shieldci.ci_mode', false);

        // Tier 1: Whitelist (if specified, ONLY these run)
        $ciAnalyzersConfig = $this->config->get('shieldci.ci_mode_analyzers', []);
        /** @var array<string> $ciAnalyzers */
        $ciAnalyzers = is_array($ciAnalyzersConfig) ? $ciAnalyzersConfig : [];

        // Tier 2: Blacklist (additionally exclude these)
        $ciExcludeAnalyzersConfig = $this->config->get('shieldci.ci_mode_exclude_analyzers', []);
        /** @var array<string> $ciExcludeAnalyzers */
        $ciExcludeAnalyzers = is_array($ciExcludeAnalyzersConfig) ? $ciExcludeAnalyzersConfig : [];

        return collect($this->analyzerClasses)
            ->map(function (string $class): ?AnalyzerInterface {
                try {
                    /** @var AnalyzerInterface $analyzer */
                    $analyzer = $this->container->make($class);

                    // Set base path for file analyzers
                    if (method_exists($analyzer, 'setBasePath')) {
                        $analyzer->setBasePath(base_path());
                    }

                    // Set paths to analyze (from config)
                    if (method_exists($analyzer, 'setPaths')) {
                        $paths = $this->config->get('shieldci.paths.analyze', []);
                        if (is_array($paths) && ! empty($paths)) {
                            $analyzer->setPaths($paths);
                        }
                    }

                    // Set excluded patterns (from config)
                    if (method_exists($analyzer, 'setExcludePatterns')) {
                        $excludedPaths = $this->config->get('shieldci.excluded_paths', []);
                        if (is_array($excludedPaths)) {
                            $analyzer->setExcludePatterns($excludedPaths);
                        }
                    }

                    return $analyzer;
                } catch (\Throwable $e) {
                    // If analyzer fails to instantiate, return null (will be filtered out)
                    // It will be handled in getSkippedAnalyzers()
                    return null;
                }
            })
            ->filter(function (?AnalyzerInterface $analyzer): bool {
                return $analyzer !== null;
            })
            ->map(function (?AnalyzerInterface $analyzer): AnalyzerInterface {
                /** @var AnalyzerInterface $analyzer */
                return $analyzer;
            })
            ->filter(function (AnalyzerInterface $analyzer) use ($disabledAnalyzers, $enabledCategories, $isCiMode, $ciAnalyzers, $ciExcludeAnalyzers): bool {
                // Filter by disabled analyzers
                if (in_array($analyzer->getId(), $disabledAnalyzers, true)) {
                    return false;
                }

                // CI Mode: 3-tier filtering
                if ($isCiMode) {
                    // Priority 1: If whitelist exists, ONLY run those
                    if (! empty($ciAnalyzers)) {
                        if (! in_array($analyzer->getId(), $ciAnalyzers, true)) {
                            return false;
                        }
                    } else {
                        // Priority 2: Check analyzer's $runInCI property
                        $analyzerClass = get_class($analyzer);
                        if (property_exists($analyzerClass, 'runInCI') && ! $analyzerClass::$runInCI) {
                            return false;
                        }

                        // Priority 3: Check blacklist (overrides $runInCI)
                        if (in_array($analyzer->getId(), $ciExcludeAnalyzers, true)) {
                            return false;
                        }
                    }
                }

                // Filter by enabled categories
                $category = $analyzer->getMetadata()->category->value;
                if (! empty($enabledCategories) && ! in_array($category, $enabledCategories, true)) {
                    return false;
                }

                return $analyzer->shouldRun();
            })
            ->values();
    }

    /**
     * Get analyzers by category.
     *
     * @return Collection<int, AnalyzerInterface>
     */
    public function getByCategory(string $category): Collection
    {
        return $this->getAnalyzers()
            ->filter(fn (AnalyzerInterface $analyzer) => $analyzer->getMetadata()->category->value === $category
            );
    }

    /**
     * Run all analyzers.
     *
     * @return Collection<int, ResultInterface>
     */
    public function runAll(): Collection
    {
        $results = $this->getAnalyzers()
            ->map(function (AnalyzerInterface $analyzer) {
                $result = $analyzer->analyze();
                $metadata = $analyzer->getMetadata();

                // Enrich result with analyzer metadata
                return new AnalysisResult(
                    analyzerId: $result->getAnalyzerId(),
                    status: $result->getStatus(),
                    message: $result->getMessage(),
                    issues: $result->getIssues(),
                    executionTime: $result->getExecutionTime(),
                    metadata: [
                        'id' => $metadata->id,
                        'name' => $metadata->name,
                        'description' => $metadata->description,
                        'category' => $metadata->category,
                        'severity' => $metadata->severity,
                        'docsUrl' => $metadata->docsUrl,
                    ],
                );
            });

        // Add skipped analyzers to results
        $skippedResults = $this->getSkippedAnalyzers();

        // Convert both to arrays and merge, then convert back to collection
        /** @var Collection<int, ResultInterface> $allResults */
        $allResults = collect(array_merge($results->all(), $skippedResults->all()));

        return $allResults;
    }

    /**
     * Get skipped analyzers as results with "Not Applicable" status.
     *
     * @return Collection<int, ResultInterface>
     */
    public function getSkippedAnalyzers(): Collection
    {
        // Get IDs of analyzers that are actually running (to exclude from skipped list)
        $runningAnalyzerIds = $this->getAnalyzers()
            ->map(fn (AnalyzerInterface $analyzer) => $analyzer->getId())
            ->toArray();

        $disabledAnalyzersConfig = $this->config->get('shieldci.disabled_analyzers', []);
        /** @var array<string> $disabledAnalyzers */
        $disabledAnalyzers = is_array($disabledAnalyzersConfig) ? $disabledAnalyzersConfig : [];

        $analyzersConfigRaw = $this->config->get('shieldci.analyzers', []);
        /** @var array<string, bool> $analyzersConfig */
        $analyzersConfig = is_array($analyzersConfigRaw) ? $analyzersConfigRaw : [];
        $enabledCategories = collect($analyzersConfig)
            ->filter(fn ($enabled) => $enabled === true)
            ->keys()
            ->toArray();

        // CI mode configuration
        $isCiMode = $this->config->get('shieldci.ci_mode', false);

        // Tier 1: Whitelist (if specified, ONLY these run)
        $ciAnalyzersConfig = $this->config->get('shieldci.ci_mode_analyzers', []);
        /** @var array<string> $ciAnalyzers */
        $ciAnalyzers = is_array($ciAnalyzersConfig) ? $ciAnalyzersConfig : [];

        // Tier 2: Blacklist (additionally exclude these)
        $ciExcludeAnalyzersConfig = $this->config->get('shieldci.ci_mode_exclude_analyzers', []);
        /** @var array<string> $ciExcludeAnalyzers */
        $ciExcludeAnalyzers = is_array($ciExcludeAnalyzersConfig) ? $ciExcludeAnalyzersConfig : [];

        $skipped = collect($this->analyzerClasses)
            ->map(function (string $class): ?AnalyzerInterface {
                try {
                    /** @var AnalyzerInterface $analyzer */
                    $analyzer = $this->container->make($class);

                    // Set base path for file analyzers
                    if (method_exists($analyzer, 'setBasePath')) {
                        $analyzer->setBasePath(base_path());
                    }

                    // Set paths to analyze (from config)
                    if (method_exists($analyzer, 'setPaths')) {
                        $paths = $this->config->get('shieldci.paths.analyze', []);
                        if (is_array($paths) && ! empty($paths)) {
                            $analyzer->setPaths($paths);
                        }
                    }

                    // Set excluded patterns (from config)
                    if (method_exists($analyzer, 'setExcludePatterns')) {
                        $excludedPaths = $this->config->get('shieldci.excluded_paths', []);
                        if (is_array($excludedPaths)) {
                            $analyzer->setExcludePatterns($excludedPaths);
                        }
                    }

                    return $analyzer;
                } catch (\Throwable $e) {
                    return null;
                }
            })
            ->filter(function (?AnalyzerInterface $analyzer) use ($runningAnalyzerIds, $disabledAnalyzers, $enabledCategories, $isCiMode, $ciAnalyzers, $ciExcludeAnalyzers): bool {
                if ($analyzer === null) {
                    return false;
                }

                // Exclude analyzers that are already running
                if (in_array($analyzer->getId(), $runningAnalyzerIds, true)) {
                    return false; // This analyzer is running, not skipped
                }

                // Filter by disabled analyzers
                if (in_array($analyzer->getId(), $disabledAnalyzers, true)) {
                    return true; // This analyzer was skipped
                }

                // CI Mode: 3-tier filtering
                if ($isCiMode) {
                    // Priority 1: If whitelist exists, ONLY run those
                    if (! empty($ciAnalyzers)) {
                        if (! in_array($analyzer->getId(), $ciAnalyzers, true)) {
                            return true; // This analyzer was skipped
                        }
                    } else {
                        // Priority 2: Check analyzer's $runInCI property
                        $analyzerClass = get_class($analyzer);
                        if (property_exists($analyzerClass, 'runInCI') && ! $analyzerClass::$runInCI) {
                            return true; // This analyzer was skipped
                        }

                        // Priority 3: Check blacklist (overrides $runInCI)
                        if (in_array($analyzer->getId(), $ciExcludeAnalyzers, true)) {
                            return true; // This analyzer was skipped
                        }
                    }
                }

                // Filter by enabled categories
                $category = $analyzer->getMetadata()->category->value;
                if (! empty($enabledCategories) && ! in_array($category, $enabledCategories, true)) {
                    return true; // This analyzer was skipped
                }

                // Check if analyzer should run
                if (! $analyzer->shouldRun()) {
                    return true; // This analyzer was skipped
                }

                return false; // This analyzer was not skipped
            })
            ->map(function (?AnalyzerInterface $analyzer): ?ResultInterface {
                if ($analyzer === null) {
                    return null;
                }
                $metadata = $analyzer->getMetadata();

                // Determine skip reason
                $skipReason = $this->getSkipReason($analyzer);

                return AnalysisResult::skipped(
                    analyzerId: $analyzer->getId(),
                    message: $skipReason,
                    executionTime: 0.0,
                    metadata: [
                        'id' => $metadata->id,
                        'name' => $metadata->name,
                        'description' => $metadata->description,
                        'category' => $metadata->category,
                        'severity' => $metadata->severity,
                        'docsUrl' => $metadata->docsUrl,
                        'skipReason' => $skipReason,
                    ],
                );
            })
            ->filter()
            ->values();

        /** @var Collection<int, ResultInterface> $skipped */
        return $skipped;
    }

    /**
     * Get the reason why an analyzer was skipped.
     */
    private function getSkipReason(AnalyzerInterface $analyzer): string
    {
        $disabledAnalyzersConfig = $this->config->get('shieldci.disabled_analyzers', []);
        /** @var array<string> $disabledAnalyzers */
        $disabledAnalyzers = is_array($disabledAnalyzersConfig) ? $disabledAnalyzersConfig : [];

        $analyzersConfigRaw = $this->config->get('shieldci.analyzers', []);
        /** @var array<string, bool> $analyzersConfig */
        $analyzersConfig = is_array($analyzersConfigRaw) ? $analyzersConfigRaw : [];
        $enabledCategories = collect($analyzersConfig)
            ->filter(fn ($enabled) => $enabled === true)
            ->keys()
            ->toArray();

        $isCiMode = $this->config->get('shieldci.ci_mode', false);
        $ciAnalyzersConfig = $this->config->get('shieldci.ci_mode_analyzers', []);
        /** @var array<string> $ciAnalyzers */
        $ciAnalyzers = is_array($ciAnalyzersConfig) ? $ciAnalyzersConfig : [];
        $ciExcludeAnalyzersConfig = $this->config->get('shieldci.ci_mode_exclude_analyzers', []);
        /** @var array<string> $ciExcludeAnalyzers */
        $ciExcludeAnalyzers = is_array($ciExcludeAnalyzersConfig) ? $ciExcludeAnalyzersConfig : [];

        // Check disabled analyzers
        if (in_array($analyzer->getId(), $disabledAnalyzers, true)) {
            return 'Disabled in configuration';
        }

        // Check CI mode
        if ($isCiMode) {
            if (! empty($ciAnalyzers)) {
                if (! in_array($analyzer->getId(), $ciAnalyzers, true)) {
                    return 'Not in CI mode whitelist';
                }
            } else {
                $analyzerClass = get_class($analyzer);
                if (property_exists($analyzerClass, 'runInCI') && ! $analyzerClass::$runInCI) {
                    return 'Not applicable in CI environment';
                }
                if (in_array($analyzer->getId(), $ciExcludeAnalyzers, true)) {
                    return 'Excluded from CI mode';
                }
            }
        }

        // Check enabled categories
        $category = $analyzer->getMetadata()->category->value;
        if (! empty($enabledCategories) && ! in_array($category, $enabledCategories, true)) {
            return 'Category not enabled';
        }

        // Check shouldRun - use analyzer's custom skip reason
        if (! $analyzer->shouldRun()) {
            return method_exists($analyzer, 'getSkipReason')
                ? $analyzer->getSkipReason()
                : 'Analyzer conditions not met';
        }

        return 'Unknown reason';
    }

    /**
     * Run specific analyzer by ID.
     */
    public function run(string $analyzerId): ?ResultInterface
    {
        $analyzer = $this->getAnalyzers()
            ->first(fn (AnalyzerInterface $a) => $a->getId() === $analyzerId);

        if ($analyzer === null) {
            return null;
        }

        $result = $analyzer->analyze();
        $metadata = $analyzer->getMetadata();

        // Enrich result with analyzer metadata (same as runAll)
        return new AnalysisResult(
            analyzerId: $result->getAnalyzerId(),
            status: $result->getStatus(),
            message: $result->getMessage(),
            issues: $result->getIssues(),
            executionTime: $result->getExecutionTime(),
            metadata: [
                'id' => $metadata->id,
                'name' => $metadata->name,
                'description' => $metadata->description,
                'category' => $metadata->category,
                'severity' => $metadata->severity,
                'docsUrl' => $metadata->docsUrl,
            ],
        );
    }

    /**
     * Get total count of registered analyzers.
     */
    public function count(): int
    {
        return count($this->analyzerClasses);
    }

    /**
     * Get total count of enabled analyzers.
     */
    public function enabledCount(): int
    {
        return $this->getAnalyzers()->count();
    }
}
