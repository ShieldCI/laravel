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
use ShieldCI\Enums\SuppressionType;
use ShieldCI\Enums\TriggerSource;
use ShieldCI\Tests\TestCase;
use ShieldCI\ValueObjects\AnalysisReport;
use ShieldCI\ValueObjects\SuppressionRecord;

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
    public function it_excludes_skipped_from_score_denominator_when_all_applicable_pass(): void
    {
        $results = collect([
            AnalysisResult::passed('analyzer-1', 'Passed'),
            AnalysisResult::passed('analyzer-2', 'Passed'),
            AnalysisResult::passed('analyzer-3', 'Passed'),
            AnalysisResult::passed('analyzer-4', 'Passed'),
            AnalysisResult::passed('analyzer-5', 'Passed'),
            AnalysisResult::passed('analyzer-6', 'Passed'),
            AnalysisResult::passed('analyzer-7', 'Passed'),
            AnalysisResult::passed('analyzer-8', 'Passed'),
            AnalysisResult::passed('analyzer-9', 'Passed'),
            AnalysisResult::passed('analyzer-10', 'Passed'),
            AnalysisResult::skipped('analyzer-11', 'Skipped'),
            AnalysisResult::skipped('analyzer-12', 'Skipped'),
        ]);

        $report = $this->createReport($results);

        // 10 passed, 2 skipped → denominator = 10, score = 100 (not 83)
        $this->assertEquals(100, $report->score());
    }

    #[Test]
    public function it_excludes_skipped_from_score_denominator_with_failures(): void
    {
        $results = collect([
            AnalysisResult::passed('analyzer-1', 'Passed'),
            AnalysisResult::passed('analyzer-2', 'Passed'),
            AnalysisResult::passed('analyzer-3', 'Passed'),
            AnalysisResult::passed('analyzer-4', 'Passed'),
            AnalysisResult::passed('analyzer-5', 'Passed'),
            AnalysisResult::passed('analyzer-6', 'Passed'),
            AnalysisResult::passed('analyzer-7', 'Passed'),
            AnalysisResult::passed('analyzer-8', 'Passed'),
            AnalysisResult::failed('analyzer-9', 'Failed', []),
            AnalysisResult::failed('analyzer-10', 'Failed', []),
            AnalysisResult::skipped('analyzer-11', 'Skipped'),
            AnalysisResult::skipped('analyzer-12', 'Skipped'),
        ]);

        $report = $this->createReport($results);

        // 8 passed, 2 failed, 2 skipped → denominator = 10, score = 80 (not 67)
        $this->assertEquals(80, $report->score());
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
        $issue = new Issue(
            message: 'Test issue',
            location: new Location('/test.php', 1),
            severity: Severity::High,
            recommendation: 'Fix it',
        );

        $results = collect([
            AnalysisResult::passed('analyzer-1', 'Passed'),
            AnalysisResult::passed('analyzer-2', 'Passed'),
            AnalysisResult::failed('analyzer-3', 'Failed', [$issue, $issue]),
            AnalysisResult::warning('analyzer-4', 'Warning', [$issue]),
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
        $this->assertEquals(3, $summary['total_issues']);
        $this->assertEquals([
            'critical' => 0,
            'high' => 3,
            'medium' => 0,
            'low' => 0,
            'info' => 0,
        ], $summary['issues_by_severity']);
        $this->assertEquals(40, $summary['score']); // 2 passed out of 5 applicable (1 skipped excluded)
    }

    #[Test]
    public function it_counts_total_issues_across_all_results(): void
    {
        $issue = new Issue(
            message: 'Found a problem',
            location: new Location('/app/Http/Controller.php', 42),
            severity: Severity::High,
            recommendation: 'Fix the problem',
        );

        $results = collect([
            AnalysisResult::passed('analyzer-1', 'All good'),
            AnalysisResult::failed('analyzer-2', 'Found issues', [$issue, $issue, $issue]),
            AnalysisResult::warning('analyzer-3', 'Some warnings', [$issue, $issue]),
            AnalysisResult::failed('analyzer-4', 'More issues', [$issue]),
        ]);

        $report = $this->createReport($results);

        // 0 + 3 + 2 + 1 = 6 total issues
        $this->assertEquals(6, $report->totalIssues());
    }

    #[Test]
    public function it_breaks_down_issues_by_severity(): void
    {
        $critical = new Issue(
            message: 'Critical issue',
            location: new Location('/app/Http/Controller.php', 10),
            severity: Severity::Critical,
            recommendation: 'Fix immediately',
        );

        $high = new Issue(
            message: 'High issue',
            location: new Location('/app/Http/Controller.php', 20),
            severity: Severity::High,
            recommendation: 'Fix soon',
        );

        $medium = new Issue(
            message: 'Medium issue',
            location: new Location('/app/Http/Controller.php', 30),
            severity: Severity::Medium,
            recommendation: 'Consider fixing',
        );

        $low = new Issue(
            message: 'Low issue',
            location: new Location('/app/Http/Controller.php', 40),
            severity: Severity::Low,
            recommendation: 'Nice to fix',
        );

        $info = new Issue(
            message: 'Info issue',
            location: new Location('/app/Http/Controller.php', 50),
            severity: Severity::Info,
            recommendation: 'Informational',
        );

        $results = collect([
            AnalysisResult::failed('analyzer-1', 'Issues', [$critical, $critical, $high]),
            AnalysisResult::warning('analyzer-2', 'Warnings', [$medium, $low]),
            AnalysisResult::failed('analyzer-3', 'More issues', [$info, $high, $critical]),
        ]);

        $report = $this->createReport($results);

        $this->assertEquals([
            'critical' => 3,
            'high' => 2,
            'medium' => 1,
            'low' => 1,
            'info' => 1,
        ], $report->issuesBySeverity());
    }

    #[Test]
    public function it_returns_zero_counts_when_no_issues(): void
    {
        $results = collect([
            AnalysisResult::passed('analyzer-1', 'All good'),
            AnalysisResult::skipped('analyzer-2', 'Skipped'),
        ]);

        $report = $this->createReport($results);

        $this->assertEquals([
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'info' => 0,
        ], $report->issuesBySeverity());
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

    #[Test]
    public function it_defaults_suppressed_issues_to_empty_array(): void
    {
        $report = $this->createReport(collect());

        $this->assertSame([], $report->suppressedIssues);
    }

    #[Test]
    public function suppressed_summary_counts_by_type_correctly(): void
    {
        $issue = new Issue(
            message: 'Test',
            location: new Location('/test.php', 1),
            severity: Severity::High,
            recommendation: 'Fix it',
        );

        $report = new AnalysisReport(
            projectId: 'test-project-id',
            laravelVersion: app()->version(),
            packageVersion: '1.0.0',
            results: collect([AnalysisResult::passed('analyzer-1', 'Passed')]),
            totalExecutionTime: 1.0,
            analyzedAt: new DateTimeImmutable,
            suppressedIssues: [
                'analyzer-1' => [
                    new SuppressionRecord($issue, SuppressionType::Inline, '@shieldci-ignore'),
                    new SuppressionRecord($issue, SuppressionType::Config, 'path: test.php'),
                    new SuppressionRecord($issue, SuppressionType::Config, 'path: other.php'),
                    new SuppressionRecord($issue, SuppressionType::Baseline, 'baseline hash: abc123...'),
                ],
            ],
        );

        $summary = $report->suppressedSummary();

        $this->assertSame(1, $summary['inline']);
        $this->assertSame(2, $summary['config']);
        $this->assertSame(1, $summary['baseline']);
        $this->assertSame(4, $summary['total']);
    }

    #[Test]
    public function suppressed_summary_returns_zeros_when_no_suppressions(): void
    {
        $report = $this->createReport(collect());

        $summary = $report->suppressedSummary();

        $this->assertSame(0, $summary['inline']);
        $this->assertSame(0, $summary['config']);
        $this->assertSame(0, $summary['baseline']);
        $this->assertSame(0, $summary['total']);
    }

    #[Test]
    public function summary_includes_suppressed_issues_counts(): void
    {
        $issue = new Issue(
            message: 'Test',
            location: new Location('/test.php', 1),
            severity: Severity::High,
            recommendation: 'Fix it',
        );

        $report = new AnalysisReport(
            projectId: 'test-project-id',
            laravelVersion: app()->version(),
            packageVersion: '1.0.0',
            results: collect([AnalysisResult::passed('analyzer-1', 'Passed')]),
            totalExecutionTime: 1.0,
            analyzedAt: new DateTimeImmutable,
            suppressedIssues: [
                'analyzer-1' => [
                    new SuppressionRecord($issue, SuppressionType::Config, 'path: test.php'),
                ],
            ],
        );

        $summary = $report->summary();

        $this->assertArrayHasKey('suppressed_issues', $summary);
        $this->assertSame(1, $summary['suppressed_issues']['config']);
        $this->assertSame(1, $summary['suppressed_issues']['total']);
    }

    #[Test]
    public function to_array_includes_suppressed_issues_per_result(): void
    {
        $issue = new Issue(
            message: 'SQL Injection',
            location: new Location('/app/Vulnerable.php', 42),
            severity: Severity::Critical,
            recommendation: 'Use prepared statements',
        );

        $results = collect([AnalysisResult::passed('xss-detection', 'Passed')]);
        $report = new AnalysisReport(
            projectId: 'test-project-id',
            laravelVersion: app()->version(),
            packageVersion: '1.0.0',
            results: $results,
            totalExecutionTime: 1.0,
            analyzedAt: new DateTimeImmutable,
            suppressedIssues: [
                'xss-detection' => [
                    new SuppressionRecord($issue, SuppressionType::Config, 'path_pattern: app/Legacy/*.php'),
                ],
            ],
        );

        $arr = $report->toArray();
        $resultArr = $arr['results'][0];

        $this->assertArrayHasKey('suppressed_issues', $resultArr);
        $this->assertCount(1, $resultArr['suppressed_issues']);
        $suppressed = $resultArr['suppressed_issues'][0];
        $this->assertSame('SQL Injection', $suppressed['message']);
        $this->assertSame('config', $suppressed['suppression']['type']);
        $this->assertSame('path_pattern: app/Legacy/*.php', $suppressed['suppression']['description']);
    }

    #[Test]
    public function to_array_includes_empty_suppressed_issues_when_none_for_result(): void
    {
        $results = collect([AnalysisResult::passed('xss-detection', 'Passed')]);
        $report = $this->createReport($results);

        $arr = $report->toArray();
        $resultArr = $arr['results'][0];

        $this->assertArrayHasKey('suppressed_issues', $resultArr);
        $this->assertSame([], $resultArr['suppressed_issues']);
    }

    #[Test]
    public function it_includes_configuration_in_to_array(): void
    {
        $configuration = [
            'paths' => ['app', 'routes'],
            'excluded_paths' => ['vendor/*'],
            'categories' => ['security' => true, 'performance' => false],
            'disabled_analyzers' => ['sql-injection'],
            'ci_mode' => true,
            'fail_on' => 'high',
            'fail_threshold' => 80,
        ];

        $report = new AnalysisReport(
            projectId: 'test-project-id',
            laravelVersion: '10.0.0',
            packageVersion: '1.0.0',
            results: collect(),
            totalExecutionTime: 1.0,
            analyzedAt: new DateTimeImmutable,
            configuration: $configuration,
        );

        $array = $report->toArray();

        $this->assertArrayHasKey('configuration', $array);
        $this->assertEquals($configuration, $array['configuration']);
    }

    #[Test]
    public function it_defaults_configuration_to_empty_array(): void
    {
        $report = $this->createReport(collect());

        $this->assertEquals([], $report->configuration);
        $this->assertArrayHasKey('configuration', $report->toArray());
        $this->assertEquals([], $report->toArray()['configuration']);
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
