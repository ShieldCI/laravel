<?php

declare(strict_types=1);

namespace ShieldCI;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;

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
        /** @var array<string> $disabledAnalyzers */
        $disabledAnalyzers = $this->config->get('shieldci.disabled_analyzers', []);

        /** @var array<string, bool> $analyzersConfig */
        $analyzersConfig = $this->config->get('shieldci.analyzers', []);
        $enabledCategories = collect($analyzersConfig)
            ->filter(fn ($enabled) => $enabled === true)
            ->keys()
            ->toArray();

        return collect($this->analyzerClasses)
            ->map(function (string $class): AnalyzerInterface {
                /** @var AnalyzerInterface $analyzer */
                $analyzer = $this->container->make($class);

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
            ->map(fn (AnalyzerInterface $analyzer) => $analyzer->analyze());
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
