<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\ValueObjects;

use DateTimeImmutable;
use Illuminate\Support\Collection;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Results\AnalysisResult;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Enums\TriggerSource;
use ShieldCI\Tests\TestCase;
use ShieldCI\ValueObjects\AnalysisReport;

class AnalysisReportTest extends TestCase
{
    #[Test]
    public function it_defaults_triggered_by_to_manual(): void
    {
        $report = $this->createReport(collect());

        $this->assertEquals(TriggerSource::Manual, $report->triggeredBy);
    }

    #[Test]
    public function it_accepts_custom_triggered_by(): void
    {
        $report = new AnalysisReport(
            projectId: 'test-project-id',
            laravelVersion: '10.0.0',
            packageVersion: '1.0.0',
            results: collect(),
            totalExecutionTime: 1.0,
            analyzedAt: new DateTimeImmutable,
            triggeredBy: TriggerSource::CiCd,
        );

        $this->assertEquals(TriggerSource::CiCd, $report->triggeredBy);
    }

    #[Test]
    public function it_includes_triggered_by_in_to_array(): void
    {
        $report = new AnalysisReport(
            projectId: 'test-project-id',
            laravelVersion: '10.0.0',
            packageVersion: '1.0.0',
            results: collect(),
            totalExecutionTime: 1.0,
            analyzedAt: new DateTimeImmutable,
            triggeredBy: TriggerSource::Scheduled,
        );

        $array = $report->toArray();

        $this->assertArrayHasKey('triggered_by', $array);
        $this->assertEquals('scheduled', $array['triggered_by']);
    }

    #[Test]
    public function it_calculates_score_correctly(): void
    {
        $results = collect([
            AnalysisResult::passed('analyzer-1', 'Passed'),
            AnalysisResult::passed('analyzer-2', 'Passed'),
            AnalysisResult::failed('analyzer-3', 'Failed', []),
            AnalysisResult::failed('analyzer-4', 'Failed', []),
        ]);

        $report = $this->createReport($results);

        // 2 passed out of 4 = 50%
        $this->assertEquals(50, $report->score());
    }

    #[Test]
    public function it_returns_100_for_empty_results(): void
    {
        $report = $this->createReport(collect());

        $this->assertEquals(100, $report->score());
    }

    #[Test]
    public function it_returns_100_when_all_pass(): void
    {
        $results = collect([
            AnalysisResult::passed('analyzer-1', 'Passed'),
            AnalysisResult::passed('analyzer-2', 'Passed'),
        ]);

        $report = $this->createReport($results);

        $this->assertEquals(100, $report->score());
    }

    #[Test]
    public function it_returns_0_when_all_fail(): void
    {
        $results = collect([
            AnalysisResult::failed('analyzer-1', 'Failed', []),
            AnalysisResult::failed('analyzer-2', 'Failed', []),
        ]);

        $report = $this->createReport($results);

        $this->assertEquals(0, $report->score());
    }

    #[Test]
    public function it_filters_passed_results(): void
    {
        $results = collect([
            AnalysisResult::passed('analyzer-1', 'Passed'),
            AnalysisResult::failed('analyzer-2', 'Failed', []),
            AnalysisResult::passed('analyzer-3', 'Passed'),
        ]);

        $report = $this->createReport($results);
        $passed = $report->passed();

        $this->assertCount(2, $passed);
    }

    #[Test]
    public function it_filters_failed_results(): void
    {
        $results = collect([
            AnalysisResult::passed('analyzer-1', 'Passed'),
            AnalysisResult::failed('analyzer-2', 'Failed', []),
            AnalysisResult::failed('analyzer-3', 'Failed', []),
        ]);

        $report = $this->createReport($results);
        $failed = $report->failed();

        $this->assertCount(2, $failed);
    }

    #[Test]
    public function it_filters_warning_results(): void
    {
        $results = collect([
            AnalysisResult::passed('analyzer-1', 'Passed'),
            AnalysisResult::warning('analyzer-2', 'Warning', []),
        ]);

        $report = $this->createReport($results);
        $warnings = $report->warnings();

        $this->assertCount(1, $warnings);
    }

    #[Test]
    public function it_filters_skipped_results(): void
    {
        $results = collect([
            AnalysisResult::passed('analyzer-1', 'Passed'),
            AnalysisResult::skipped('analyzer-2', 'Skipped'),
        ]);

        $report = $this->createReport($results);
        $skipped = $report->skipped();

        $this->assertCount(1, $skipped);
    }

    #[Test]
    public function it_filters_error_results(): void
    {
        $results = collect([
            AnalysisResult::passed('analyzer-1', 'Passed'),
            AnalysisResult::error('analyzer-2', 'Error'),
        ]);

        $report = $this->createReport($results);
        $errors = $report->errors();

        $this->assertCount(1, $errors);
    }

    #[Test]
    public function it_generates_summary(): void
    {
        $results = collect([
            AnalysisResult::passed('analyzer-1', 'Passed'),
            AnalysisResult::passed('analyzer-2', 'Passed'),
            AnalysisResult::failed('analyzer-3', 'Failed', []),
            AnalysisResult::warning('analyzer-4', 'Warning', []),
            AnalysisResult::skipped('analyzer-5', 'Skipped'),
            AnalysisResult::error('analyzer-6', 'Error'),
        ]);

        $report = $this->createReport($results);
        $summary = $report->summary();

        $this->assertEquals(6, $summary['total']);
        $this->assertEquals(2, $summary['passed']);
        $this->assertEquals(1, $summary['failed']);
        $this->assertEquals(1, $summary['warnings']);
        $this->assertEquals(1, $summary['skipped']);
        $this->assertEquals(1, $summary['errors']);
        $this->assertEquals(33, $summary['score']); // 2 passed out of 6
    }

    #[Test]
    public function it_converts_to_array(): void
    {
        $results = collect([
            AnalysisResult::passed('test-analyzer', 'Test passed'),
        ]);

        $report = $this->createReport($results);
        $array = $report->toArray();

        $this->assertArrayHasKey('laravel_version', $array);
        $this->assertArrayHasKey('package_version', $array);
        $this->assertArrayHasKey('triggered_by', $array);
        $this->assertArrayHasKey('analyzed_at', $array);
        $this->assertArrayHasKey('total_execution_time', $array);
        $this->assertArrayHasKey('summary', $array);
        $this->assertArrayHasKey('results', $array);
        $this->assertArrayHasKey('metadata', $array);
    }

    #[Test]
    public function it_includes_version_info_in_array(): void
    {
        $report = new AnalysisReport(
            projectId: 'test-project-id',
            laravelVersion: '10.0.0',
            packageVersion: '1.0.0',
            results: collect(),
            totalExecutionTime: 1.5,
            analyzedAt: new DateTimeImmutable,
        );

        $array = $report->toArray();

        $this->assertEquals('10.0.0', $array['laravel_version']);
        $this->assertEquals('1.0.0', $array['package_version']);
    }

    #[Test]
    public function it_formats_analyzed_at_as_iso_8601(): void
    {
        $datetime = new DateTimeImmutable('2024-06-15T10:30:00+00:00');

        $report = new AnalysisReport(
            projectId: 'test-project-id',
            laravelVersion: '10.0.0',
            packageVersion: '1.0.0',
            results: collect(),
            totalExecutionTime: 1.0,
            analyzedAt: $datetime,
        );

        $array = $report->toArray();

        $this->assertEquals('2024-06-15T10:30:00+00:00', $array['analyzed_at']);
    }

    #[Test]
    public function it_includes_metadata_in_array(): void
    {
        $report = new AnalysisReport(
            projectId: 'test-project-id',
            laravelVersion: '10.0.0',
            packageVersion: '1.0.0',
            results: collect(),
            totalExecutionTime: 1.0,
            analyzedAt: new DateTimeImmutable,
            metadata: ['custom_key' => 'custom_value'],
        );

        $array = $report->toArray();

        $this->assertEquals(['custom_key' => 'custom_value'], $array['metadata']);
    }

    #[Test]
    public function it_includes_all_results_in_array(): void
    {
        $results = collect([
            AnalysisResult::passed('analyzer-1', 'Passed'),
            AnalysisResult::failed('analyzer-2', 'Failed', [
                new Issue(
                    message: 'Test issue',
                    location: new Location('/test.php', 10),
                    severity: Severity::High,
                    recommendation: 'Fix it',
                ),
            ]),
        ]);

        $report = $this->createReport($results);
        $array = $report->toArray();

        $this->assertCount(2, $array['results']);
    }

    #[Test]
    public function it_preserves_readonly_properties(): void
    {
        $datetime = new DateTimeImmutable;

        $report = new AnalysisReport(
            projectId: 'test-project-id',
            laravelVersion: '10.0.0',
            packageVersion: '1.0.0',
            results: collect(),
            totalExecutionTime: 2.5,
            analyzedAt: $datetime,
        );

        $this->assertEquals('10.0.0', $report->laravelVersion);
        $this->assertEquals('1.0.0', $report->packageVersion);
        $this->assertEquals(2.5, $report->totalExecutionTime);
        $this->assertSame($datetime, $report->analyzedAt);
    }

    private function createReport(Collection $results): AnalysisReport
    {
        return new AnalysisReport(
            projectId: 'test-project-id',
            laravelVersion: app()->version(),
            packageVersion: '1.0.0',
            results: $results,
            totalExecutionTime: 1.0,
            analyzedAt: new DateTimeImmutable,
        );
    }
}
