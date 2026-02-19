<?php

declare(strict_types=1);

namespace ShieldCI\ValueObjects;

use DateTimeImmutable;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Status;

/**
 * Complete analysis report
 */
final class AnalysisReport
{
    /**
     * @param  Collection<int, ResultInterface>  $results
     */
    public function __construct(
        public readonly string $projectId,
        public readonly string $laravelVersion,
        public readonly string $packageVersion,
        public readonly Collection $results,
        public readonly float $totalExecutionTime,
        public readonly DateTimeImmutable $analyzedAt,
        public readonly array $metadata = [],
    ) {}

    public function score(): int
    {
        $total = $this->results->count();
        $passed = $this->results->filter(
            fn (ResultInterface $result) => $result->getStatus() === Status::Passed
        )->count();

        if ($total === 0) {
            return 100;
        }

        return (int) round(($passed / $total) * 100);
    }

    public function passed(): Collection
    {
        return $this->results->filter(
            fn (ResultInterface $result) => $result->getStatus() === Status::Passed
        );
    }

    public function failed(): Collection
    {
        return $this->results->filter(
            fn (ResultInterface $result) => $result->getStatus() === Status::Failed
        );
    }

    public function warnings(): Collection
    {
        return $this->results->filter(
            fn (ResultInterface $result) => $result->getStatus() === Status::Warning
        );
    }

    public function skipped(): Collection
    {
        return $this->results->filter(
            fn (ResultInterface $result) => $result->getStatus() === Status::Skipped
        );
    }

    public function errors(): Collection
    {
        return $this->results->filter(
            fn (ResultInterface $result) => $result->getStatus() === Status::Error
        );
    }

    public function summary(): array
    {
        return [
            'total' => $this->results->count(),
            'passed' => $this->passed()->count(),
            'failed' => $this->failed()->count(),
            'warnings' => $this->warnings()->count(),
            'skipped' => $this->skipped()->count(),
            'errors' => $this->errors()->count(),
            'score' => $this->score(),
        ];
    }

    public function toArray(): array
    {
        return [
            'project_id' => $this->projectId,
            'laravel_version' => $this->laravelVersion,
            'package_version' => $this->packageVersion,
            'analyzed_at' => $this->analyzedAt->format('c'),
            'total_execution_time' => $this->totalExecutionTime,
            'summary' => $this->summary(),
            'results' => $this->results->map(fn (ResultInterface $result) => $result->toArray())->all(),
            'metadata' => $this->metadata,
        ];
    }
}
