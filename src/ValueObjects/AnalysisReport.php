<?php

declare(strict_types=1);

namespace ShieldCI\ValueObjects;

use DateTimeImmutable;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\Enums\TriggerSource;

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
        public readonly TriggerSource $triggeredBy = TriggerSource::Manual,
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

    public function totalIssues(): int
    {
        $total = 0;

        foreach ($this->results as $result) {
            $total += count($result->getIssues());
        }

        return $total;
    }

    /**
     * @return array{critical: int, high: int, medium: int, low: int, info: int}
     */
    public function issuesBySeverity(): array
    {
        $counts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'info' => 0,
        ];

        foreach ($this->results as $result) {
            foreach ($result->getIssues() as $issue) {
                $counts[$issue->severity->value]++;
            }
        }

        return $counts;
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
            'total_issues' => $this->totalIssues(),
            'issues_by_severity' => $this->issuesBySeverity(),
            'score' => $this->score(),
        ];
    }

    public function toArray(): array
    {
        return [
            'project_id' => $this->projectId,
            'laravel_version' => $this->laravelVersion,
            'package_version' => $this->packageVersion,
            'triggered_by' => $this->triggeredBy->value,
            'analyzed_at' => $this->analyzedAt->format('c'),
            'total_execution_time' => $this->totalExecutionTime,
            'summary' => $this->summary(),
            'results' => $this->results->map(fn (ResultInterface $result) => $result->toArray())->all(),
            'metadata' => $this->metadata,
        ];
    }
}
