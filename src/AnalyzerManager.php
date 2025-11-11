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

        return collect($this->analyzerClasses)
            ->map(function (string $class): AnalyzerInterface {
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
            })
            ->filter(function (AnalyzerInterface $analyzer) use ($disabledAnalyzers, $enabledCategories): bool {
                // Filter by disabled analyzers
                if (in_array($analyzer->getId(), $disabledAnalyzers, true)) {
                    return false;
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
        return $this->getAnalyzers()
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
    }

    /**
     * Run specific analyzer by ID.
     */
    public function run(string $analyzerId): ?ResultInterface
    {
        $analyzer = $this->getAnalyzers()
            ->first(fn (AnalyzerInterface $a) => $a->getId() === $analyzerId);

        return $analyzer?->analyze();
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
