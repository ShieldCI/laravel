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
        protected ?Container $container = null,
    ) {
        $this->container = $container ?? app();
    }

    /**
     * Get all registered analyzers.
     *
     * @return Collection<int, AnalyzerInterface>
     */
    public function getAnalyzers(): Collection
    {
        return collect($this->analyzerClasses)
            ->map(fn (string $class) => $this->container->make($class))
            ->filter(fn (AnalyzerInterface $analyzer) => $analyzer->shouldRun());
    }

    /**
     * Get analyzers by category.
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
