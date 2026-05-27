<?php

declare(strict_types=1);

namespace ShieldCI;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
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

    /** @var Collection<int, AnalyzerInterface>|null */
    private ?Collection $cachedAllInstances = null;

    /** @var Collection<int, AnalyzerInterface>|null */
    private ?Collection $cachedAnalyzers = null;

    /** @var Collection<int, ResultInterface>|null */
    private ?Collection $cachedSkippedAnalyzers = null;

    private bool $configCacheInitialized = false;

    /** @var array<string> */
    private array $cachedDisabledAnalyzers = [];

    /** @var array<string, array<string, mixed>> */
    private array $cachedAnalyzersConfig = [];

    /** @var array<string> */
    private array $cachedEnabledCategories = [];

    private bool $cachedIsCiMode = false;

    /** @var array<string> */
    private array $cachedCiAnalyzers = [];

    /** @var array<string> */
    private array $cachedCiExcludeAnalyzers = [];

    /** @var array<string> */
    private array $cachedPathsToAnalyze = [];

    /** @var array<string> */
    private array $cachedExcludedPaths = [];

    public function invalidateCache(): void
    {
        $this->cachedAllInstances = null;
        $this->cachedAnalyzers = null;
        $this->cachedSkippedAnalyzers = null;
        $this->configCacheInitialized = false;
    }

    /**
     * Clear the singleton AstParser's file cache to prevent unbounded heap growth
     * when 73 analyzers each call parseFile() across the same project.
     * Called after every analyze() invocation in runAll() and run().
     */
    public function clearParserCache(): void
    {
        try {
            $parser = $this->container->make(ParserInterface::class);
            if (method_exists($parser, 'clearCache')) {
                $parser->clearCache();
            }
        } catch (\Throwable) {
            // Parser not bound or doesn't support clearing — silently skip
        }
    }

    private function initConfigCache(): void
    {
        if ($this->configCacheInitialized) {
            return;
        }

        $disabledAnalyzersConfig = $this->config->get('shieldci.disabled_analyzers', []);
        /** @var array<string> $disabledAnalyzers */
        $disabledAnalyzers = is_array($disabledAnalyzersConfig) ? $disabledAnalyzersConfig : [];
        $this->cachedDisabledAnalyzers = $disabledAnalyzers;

        $analyzersConfigRaw = $this->config->get('shieldci.analyzers', []);
        /** @var array<string, array<string, mixed>> $analyzersConfig */
        $analyzersConfig = is_array($analyzersConfigRaw) ? $analyzersConfigRaw : [];
        $this->cachedAnalyzersConfig = $analyzersConfig;
        $this->cachedEnabledCategories = $this->getEnabledCategories($this->cachedAnalyzersConfig);

        $this->cachedIsCiMode = (bool) $this->config->get('shieldci.ci_mode', false);

        $ciAnalyzersConfig = $this->config->get('shieldci.ci_mode_analyzers', []);
        /** @var array<string> $ciAnalyzers */
        $ciAnalyzers = is_array($ciAnalyzersConfig) ? $ciAnalyzersConfig : [];
        $this->cachedCiAnalyzers = $ciAnalyzers;

        $ciExcludeAnalyzersConfig = $this->config->get('shieldci.ci_mode_exclude_analyzers', []);
        /** @var array<string> $ciExcludeAnalyzers */
        $ciExcludeAnalyzers = is_array($ciExcludeAnalyzersConfig) ? $ciExcludeAnalyzersConfig : [];
        $this->cachedCiExcludeAnalyzers = $ciExcludeAnalyzers;

        $pathsConfig = $this->config->get('shieldci.paths.analyze', []);
        /** @var array<string> $pathsToAnalyze */
        $pathsToAnalyze = is_array($pathsConfig) && ! empty($pathsConfig) ? $pathsConfig : [];
        $this->cachedPathsToAnalyze = $pathsToAnalyze;

        $excludedPathsConfig = $this->config->get('shieldci.excluded_paths', []);
        /** @var array<string> $excludedPaths */
        $excludedPaths = is_array($excludedPathsConfig) ? $excludedPathsConfig : [];
        $this->cachedExcludedPaths = $excludedPaths;

        $this->configCacheInitialized = true;
    }

    /**
     * Instantiate all analyzer classes exactly once, applying base-path and config.
     * Both getAnalyzers() and getSkippedAnalyzers() filter from this shared pool.
     *
     * @return Collection<int, AnalyzerInterface>
     */
    private function getAllInstances(): Collection
    {
        if ($this->cachedAllInstances !== null) {
            return $this->cachedAllInstances;
        }

        $this->initConfigCache();

        /** @var Collection<int, AnalyzerInterface> $instances */
        $instances = collect($this->analyzerClasses)
            ->map(function (string $class): ?AnalyzerInterface {
                try {
                    /** @var AnalyzerInterface $analyzer */
                    $analyzer = $this->container->make($class);

                    if (method_exists($analyzer, 'setBasePath')) {
                        $analyzer->setBasePath(base_path());
                    }

                    if (method_exists($analyzer, 'setPaths') && ! empty($this->cachedPathsToAnalyze)) {
                        $analyzer->setPaths($this->cachedPathsToAnalyze);
                    }

                    if (method_exists($analyzer, 'setExcludePatterns')) {
                        $analyzer->setExcludePatterns($this->cachedExcludedPaths);
                    }

                    return $analyzer;
                } catch (\Throwable $e) {
                    return null;
                }
            })
            ->filter()
            ->values();

        $this->cachedAllInstances = $instances;

        return $this->cachedAllInstances;
    }

    /**
     * Get all registered analyzers.
     *
     * @return Collection<int, AnalyzerInterface>
     */
    public function getAnalyzers(): Collection
    {
        if ($this->cachedAnalyzers !== null) {
            return $this->cachedAnalyzers;
        }

        $this->initConfigCache();

        $this->cachedAnalyzers = $this->getAllInstances()
            ->filter(function (AnalyzerInterface $analyzer): bool {
                if (in_array($analyzer->getId(), $this->cachedDisabledAnalyzers, true)) {
                    return false;
                }

                // CI Mode: 3-tier filtering
                if ($this->cachedIsCiMode) {
                    // Priority 1: If whitelist exists, ONLY run those
                    if (! empty($this->cachedCiAnalyzers)) {
                        if (! in_array($analyzer->getId(), $this->cachedCiAnalyzers, true)) {
                            return false;
                        }
                    } else {
                        // Priority 2: Check analyzer's $runInCI property
                        $analyzerClass = get_class($analyzer);
                        if (property_exists($analyzerClass, 'runInCI') && ! $analyzerClass::$runInCI) {
                            return false;
                        }

                        // Priority 3: Check blacklist (overrides $runInCI)
                        if (in_array($analyzer->getId(), $this->cachedCiExcludeAnalyzers, true)) {
                            return false;
                        }
                    }
                }

                // Filter by enabled categories
                if (! empty($this->cachedAnalyzersConfig)) {
                    $category = $analyzer->getMetadata()->category->value;
                    if (empty($this->cachedEnabledCategories)) {
                        return false;
                    }
                    if (! in_array($category, $this->cachedEnabledCategories, true)) {
                        return false;
                    }
                }

                return $analyzer->shouldRun();
            })
            ->values();

        return $this->cachedAnalyzers;
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
     * Get analyzers by multiple categories.
     *
     * @param  array<string>  $categories
     * @return Collection<int, AnalyzerInterface>
     */
    public function getByCategories(array $categories): Collection
    {
        return $this->getAnalyzers()
            ->filter(fn (AnalyzerInterface $analyzer) => in_array($analyzer->getMetadata()->category->value, $categories, true)
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
                if (method_exists($analyzer, 'clearAstParserCache')) {
                    $analyzer->clearAstParserCache();
                }
                $this->clearParserCache();
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
                        'docsUrl' => $metadata->getDocsUrl(),
                        'timeToFix' => $metadata->timeToFix,
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
        if ($this->cachedSkippedAnalyzers !== null) {
            return $this->cachedSkippedAnalyzers;
        }

        $this->initConfigCache();

        $runningAnalyzerIds = $this->getAnalyzers()
            ->map(fn (AnalyzerInterface $analyzer) => $analyzer->getId())
            ->toArray();

        /** @var Collection<int, ResultInterface> $skipped */
        $skipped = $this->getAllInstances()
            ->filter(function (AnalyzerInterface $analyzer) use ($runningAnalyzerIds): bool {
                // Exclude analyzers that are already running
                if (in_array($analyzer->getId(), $runningAnalyzerIds, true)) {
                    return false;
                }

                // Filter by disabled analyzers
                if (in_array($analyzer->getId(), $this->cachedDisabledAnalyzers, true)) {
                    return true; // This analyzer was skipped
                }

                // CI Mode: 3-tier filtering
                if ($this->cachedIsCiMode) {
                    // Priority 1: If whitelist exists, ONLY run those
                    if (! empty($this->cachedCiAnalyzers)) {
                        if (! in_array($analyzer->getId(), $this->cachedCiAnalyzers, true)) {
                            return true; // This analyzer was skipped
                        }
                    } else {
                        // Priority 2: Check analyzer's $runInCI property
                        $analyzerClass = get_class($analyzer);
                        if (property_exists($analyzerClass, 'runInCI') && ! $analyzerClass::$runInCI) {
                            return true; // This analyzer was skipped
                        }

                        // Priority 3: Check blacklist (overrides $runInCI)
                        if (in_array($analyzer->getId(), $this->cachedCiExcludeAnalyzers, true)) {
                            return true; // This analyzer was skipped
                        }
                    }
                }

                // Filter by enabled categories
                $category = $analyzer->getMetadata()->category->value;
                if (! empty($this->cachedEnabledCategories) && ! in_array($category, $this->cachedEnabledCategories, true)) {
                    return true; // This analyzer was skipped
                }

                // Check if analyzer should run
                if (! $analyzer->shouldRun()) {
                    return true; // This analyzer was skipped
                }

                return false; // This analyzer was not skipped
            })
            ->map(function (AnalyzerInterface $analyzer): ResultInterface {
                $metadata = $analyzer->getMetadata();
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
                        'docsUrl' => $metadata->getDocsUrl(),
                        'timeToFix' => $metadata->timeToFix,
                        'skipReason' => $skipReason,
                    ],
                );
            })
            ->values();

        $this->cachedSkippedAnalyzers = $skipped;

        return $this->cachedSkippedAnalyzers;
    }

    /**
     * Get the reason why an analyzer was skipped.
     */
    private function getSkipReason(AnalyzerInterface $analyzer): string
    {
        $this->initConfigCache();

        if (in_array($analyzer->getId(), $this->cachedDisabledAnalyzers, true)) {
            return 'Disabled in configuration';
        }

        if ($this->cachedIsCiMode) {
            if (! empty($this->cachedCiAnalyzers)) {
                if (! in_array($analyzer->getId(), $this->cachedCiAnalyzers, true)) {
                    return 'Not in CI mode whitelist';
                }
            } else {
                $analyzerClass = get_class($analyzer);
                if (property_exists($analyzerClass, 'runInCI') && ! $analyzerClass::$runInCI) {
                    return 'Not applicable in CI environment';
                }
                if (in_array($analyzer->getId(), $this->cachedCiExcludeAnalyzers, true)) {
                    return 'Excluded from CI mode';
                }
            }
        }

        $category = $analyzer->getMetadata()->category->value;
        if (! empty($this->cachedEnabledCategories) && ! in_array($category, $this->cachedEnabledCategories, true)) {
            return 'Category not enabled';
        }

        if (! $analyzer->shouldRun()) {
            return $analyzer->getSkipReason();
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
        if (method_exists($analyzer, 'clearAstParserCache')) {
            $analyzer->clearAstParserCache();
        }
        $this->clearParserCache();
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
                'docsUrl' => $metadata->getDocsUrl(),
                'timeToFix' => $metadata->timeToFix,
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

    /**
     * Extract enabled categories from analyzer configuration.
     *
     * @param  array<string, array<string, mixed>>  $analyzersConfig
     * @return array<string>
     */
    private function getEnabledCategories(array $analyzersConfig): array
    {
        $enabled = [];

        foreach ($analyzersConfig as $category => $config) {
            if (is_array($config) && ($config['enabled'] ?? true) === true) {
                $enabled[] = $category;
            }
        }

        return $enabled;
    }

    /**
     * Get analyzer-specific configuration for a category.
     *
     * @param  array<string, mixed>  $defaults
     * @return array<string, mixed>
     */
    public function getAnalyzerConfig(string $category, string $analyzerId, array $defaults = []): array
    {
        $analyzersConfigRaw = $this->config->get('shieldci.analyzers', []);
        /** @var array<string, array<string, mixed>> $analyzersConfig */
        $analyzersConfig = is_array($analyzersConfigRaw) ? $analyzersConfigRaw : [];

        $categoryConfig = $analyzersConfig[$category] ?? [];

        if (! is_array($categoryConfig)) {
            return $defaults;
        }

        // Get analyzer-specific config from category config
        $analyzerConfig = $categoryConfig[$analyzerId] ?? [];

        if (! is_array($analyzerConfig)) {
            return $defaults;
        }

        // Merge with defaults
        return array_merge($defaults, $analyzerConfig);
    }
}
