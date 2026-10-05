<?php

declare(strict_types=1);

namespace ShieldCI\ValueObjects;

use DateTimeImmutable;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\AnalyzersCore\ValueObjects\ParseFailure;
use ShieldCI\AnalyzersCore\ValueObjects\ParserCompatibility;
use ShieldCI\Enums\SuppressionType;
use ShieldCI\Enums\TriggerSource;

/**
 * Complete analysis report
 */
final class AnalysisReport
{
    /**
     * @param  Collection<int, ResultInterface>  $results
     * @param  array<string, string>  $metadata
     * @param  array<string, list<SuppressionRecord>>  $suppressedIssues
     * @param  array<string, mixed>  $configuration
     * @param  ParserCompatibility|null  $parserCompatibility  Whether the installed php-parser
     *                                                         understands the running PHP. Null
     *                                                         when the report was not built by
     *                                                         Reporter::generate().
     * @param  list<ParseFailure>  $parseFailures  Files no analyzer could read, paths relative
     *                                             to the base path. Each analyzer reads an empty
     *                                             AST as "nothing to report", so without this a
     *                                             file that never parsed reads as a clean one.
     * @param  list<string>  $parseRecoveries  The subset of those paths some analyzer recovered
     *                                         partial syntax from.
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
        public readonly array $suppressedIssues = [],
        public readonly array $configuration = [],
        public readonly ?string $proPackageVersion = null,
        public readonly ?ParserCompatibility $parserCompatibility = null,
        public readonly array $parseFailures = [],
        public readonly array $parseRecoveries = [],
    ) {}

    /**
     * A copy with different results and every other field kept.
     *
     * The filters in AnalyzeCommand rebuild the report after analysis. Spelling the
     * constructor out at each of them dropped any field the call site did not list, so the
     * field list lives here, once.
     *
     * @param  Collection<int, ResultInterface>  $results
     */
    public function withResults(Collection $results): self
    {
        return $this->copy(results: $results);
    }

    /**
     * A copy with different suppression records and every other field kept.
     *
     * @param  array<string, list<SuppressionRecord>>  $suppressedIssues
     */
    public function withSuppressedIssues(array $suppressedIssues): self
    {
        return $this->copy(suppressedIssues: $suppressedIssues);
    }

    /**
     * @param  Collection<int, ResultInterface>|null  $results
     * @param  array<string, list<SuppressionRecord>>|null  $suppressedIssues
     */
    private function copy(?Collection $results = null, ?array $suppressedIssues = null): self
    {
        return new self(
            projectId: $this->projectId,
            laravelVersion: $this->laravelVersion,
            packageVersion: $this->packageVersion,
            results: $results ?? $this->results,
            totalExecutionTime: $this->totalExecutionTime,
            analyzedAt: $this->analyzedAt,
            triggeredBy: $this->triggeredBy,
            metadata: $this->metadata,
            suppressedIssues: $suppressedIssues ?? $this->suppressedIssues,
            configuration: $this->configuration,
            proPackageVersion: $this->proPackageVersion,
            parserCompatibility: $this->parserCompatibility,
            parseFailures: $this->parseFailures,
            parseRecoveries: $this->parseRecoveries,
        );
    }

    public function score(): int
    {
        $skipped = $this->skipped()->count();
        $denominator = $this->results->count() - $skipped;
        $passed = $this->passed()->count();

        if ($denominator === 0) {
            return 100;
        }

        return (int) round(($passed / $denominator) * 100);
    }

    /**
     * @return Collection<int, ResultInterface>
     */
    public function passed(): Collection
    {
        return $this->results->filter(
            fn (ResultInterface $result) => $result->getStatus() === Status::Passed
        );
    }

    /**
     * @return Collection<int, ResultInterface>
     */
    public function failed(): Collection
    {
        return $this->results->filter(
            fn (ResultInterface $result) => $result->getStatus() === Status::Failed
        );
    }

    /**
     * @return Collection<int, ResultInterface>
     */
    public function warnings(): Collection
    {
        return $this->results->filter(
            fn (ResultInterface $result) => $result->getStatus() === Status::Warning
        );
    }

    /**
     * @return Collection<int, ResultInterface>
     */
    public function skipped(): Collection
    {
        return $this->results->filter(
            fn (ResultInterface $result) => $result->getStatus() === Status::Skipped
        );
    }

    /**
     * @return Collection<int, ResultInterface>
     */
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

    /**
     * @return array{inline: int, config: int, baseline: int, total: int}
     */
    public function suppressedSummary(): array
    {
        $counts = [
            'inline' => 0,
            'config' => 0,
            'baseline' => 0,
            'total' => 0,
        ];

        foreach ($this->suppressedIssues as $records) {
            foreach ($records as $record) {
                $key = match ($record->type) {
                    SuppressionType::Inline => 'inline',
                    SuppressionType::Config => 'config',
                    SuppressionType::Baseline => 'baseline',
                };
                $counts[$key]++;
                $counts['total']++;
            }
        }

        return $counts;
    }

    /**
     * @return array<string, mixed>
     */
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
            'suppressed_issues' => $this->suppressedSummary(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'project_id' => $this->projectId,
            'laravel_version' => $this->laravelVersion,
            'package_version' => $this->packageVersion,
            'pro_package_version' => $this->proPackageVersion,
            'triggered_by' => $this->triggeredBy->value,
            'analyzed_at' => $this->analyzedAt->format('c'),
            'total_execution_time' => $this->totalExecutionTime,
            'summary' => $this->summary(),
            'results' => $this->results->map(function (ResultInterface $result) {
                $arr = $result->toArray();
                $arr['suppressed_issues'] = array_map(
                    fn (SuppressionRecord $r) => $r->toArray(),
                    $this->suppressedIssues[$result->getAnalyzerId()] ?? []
                );

                return $arr;
            })->all(),
            'metadata' => $this->metadata,
            'configuration' => $this->configuration,
            'parser_compatibility' => $this->parserCompatibility?->toArray(),
            'parse_failures' => array_map(
                fn (ParseFailure $failure) => $failure->toArray() + [
                    'recovered' => $failure->path !== null && in_array($failure->path, $this->parseRecoveries, true),
                ],
                $this->parseFailures,
            ),
        ];
    }
}
