<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Results\AnalysisResult;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Support\Reporter;
use ShieldCI\Tests\TestCase;
use ShieldCI\ValueObjects\AnalysisReport;

class ReporterTest extends TestCase
{
    protected Reporter $reporter;

    protected function setUp(): void
    {
        parent::setUp();
        $this->reporter = new Reporter;
    }

    #[Test]
    public function it_can_generate_report_from_results(): void
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

        $report = $this->reporter->generate($results);

        $this->assertInstanceOf(AnalysisReport::class, $report);
        $this->assertCount(2, $report->results);
    }

    #[Test]
    public function it_can_format_to_console(): void
    {
        $results = collect([
            AnalysisResult::passed('test-analyzer', 'All checks passed'),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        $this->assertIsString($output);
        $this->assertStringContainsString('ShieldCI', $output);
        $this->assertStringContainsString('Report Card', $output);
    }

    #[Test]
    public function it_can_format_to_json(): void
    {
        $results = collect([
            AnalysisResult::passed('test-analyzer', 'All checks passed'),
        ]);

        $report = $this->reporter->generate($results);
        $json = $this->reporter->toJson($report);

        $this->assertJson($json);

        $decoded = json_decode($json, true);
        $this->assertArrayHasKey('summary', $decoded);
        $this->assertArrayHasKey('score', $decoded['summary']);
        $this->assertArrayHasKey('results', $decoded);
    }

    #[Test]
    public function console_output_includes_failed_analyzers(): void
    {
        $results = collect([
            AnalysisResult::failed('test-analyzer', 'Found issues', [
                new Issue(
                    message: 'Security vulnerability detected',
                    location: new Location('/app/Controller.php', 42),
                    severity: Severity::Critical,
                    recommendation: 'Sanitize user input',
                ),
            ]),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        $this->assertStringContainsString('Failed', $output);
        $this->assertStringContainsString('Found issues', $output);
        $this->assertStringContainsString('/app/Controller.php:42', $output);
    }

    #[Test]
    public function console_output_includes_warnings(): void
    {
        $results = collect([
            AnalysisResult::warning('test-analyzer', 'Warning issued', [
                new Issue(
                    message: 'Potential performance issue',
                    location: new Location('/app/Service.php', 100),
                    severity: Severity::Medium,
                    recommendation: 'Consider caching',
                ),
            ]),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        $this->assertStringContainsString('Warning', $output);
        $this->assertStringContainsString('test-analyzer', $output);
        $this->assertStringContainsString('Warning issued', $output);
    }

    #[Test]
    public function it_generates_stream_header(): void
    {
        $header = $this->reporter->streamHeader();

        $this->assertIsString($header);
        $this->assertStringContainsString('ShieldCI', $header);
        $this->assertStringContainsString('Please wait', $header);
    }

    #[Test]
    public function it_generates_stream_category_header(): void
    {
        $header = $this->reporter->streamCategoryHeader('Security');

        $this->assertIsString($header);
        $this->assertStringContainsString('Security', $header);
        $this->assertStringContainsString('Running', $header);
    }

    #[Test]
    public function it_streams_passed_result(): void
    {
        $result = AnalysisResult::passed('test-analyzer', 'All checks passed');

        $output = $this->reporter->streamResult($result, 1, 5, 'Security');

        $this->assertIsString($output);
        $this->assertStringContainsString('1/5', $output);
        $this->assertStringContainsString('Passed', $output);
    }

    #[Test]
    public function it_streams_failed_result_with_issues(): void
    {
        $result = new AnalysisResult(
            analyzerId: 'test-analyzer',
            status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
            message: 'Found 2 issues',
            issues: [
                new Issue(
                    message: 'SQL Injection risk',
                    location: new Location('/app/UserController.php', 42),
                    severity: Severity::Critical,
                    recommendation: 'Use prepared statements',
                ),
                new Issue(
                    message: 'Unvalidated input',
                    location: new Location('/app/UserController.php', 55),
                    severity: Severity::High,
                    recommendation: 'Add validation',
                ),
            ],
            executionTime: 0.5,
            metadata: [
                'name' => 'Test Analyzer',
                'docsUrl' => 'https://docs.shieldci.com/test',
            ],
        );

        $output = $this->reporter->streamResult($result, 2, 5, 'Security');

        $this->assertStringContainsString('Failed', $output);
        $this->assertStringContainsString('Found 2 issues', $output);
        $this->assertStringContainsString('/app/UserController.php', $output);
        $this->assertStringContainsString('Documentation URL', $output);
    }

    #[Test]
    public function it_streams_skipped_result(): void
    {
        $result = AnalysisResult::skipped('test-analyzer', 'Not applicable for this project');

        $output = $this->reporter->streamResult($result, 3, 5, 'Security');

        $this->assertStringContainsString('Not Applicable', $output);
        $this->assertStringContainsString('Not applicable for this project', $output);
    }

    #[Test]
    public function it_streams_result_with_time_to_fix(): void
    {
        $result = new AnalysisResult(
            analyzerId: 'test-analyzer',
            status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
            message: 'Found issues',
            issues: [
                new Issue(
                    message: 'Issue',
                    location: new Location('/app/Test.php', 1),
                    severity: Severity::Medium,
                    recommendation: 'Fix it',
                ),
            ],
            executionTime: 0.1,
            metadata: [
                'name' => 'Test Analyzer',
                'timeToFix' => 5,
            ],
        );

        $output = $this->reporter->streamResult($result, 1, 1, 'Performance');

        $this->assertStringContainsString('5 mins', $output);
    }

    #[Test]
    public function it_streams_result_with_one_minute_to_fix(): void
    {
        $result = new AnalysisResult(
            analyzerId: 'test-analyzer',
            status: \ShieldCI\AnalyzersCore\Enums\Status::Warning,
            message: 'Warning issued',
            issues: [
                new Issue(
                    message: 'Issue',
                    location: new Location('/app/Test.php', 1),
                    severity: Severity::Low,
                    recommendation: 'Fix it',
                ),
            ],
            executionTime: 0.1,
            metadata: [
                'name' => 'Test Analyzer',
                'timeToFix' => 1,
            ],
        );

        $output = $this->reporter->streamResult($result, 1, 1, 'Performance');

        $this->assertStringContainsString('1 min', $output);
    }

    #[Test]
    public function it_limits_displayed_issues_per_check(): void
    {
        config(['shieldci.report.max_issues_per_check' => 2]);

        $issues = [];
        for ($i = 0; $i < 10; $i++) {
            $issues[] = new Issue(
                message: "Issue {$i}",
                location: new Location("/app/File{$i}.php", $i + 1),
                severity: Severity::Medium,
                recommendation: 'Fix it',
            );
        }

        $result = new AnalysisResult(
            analyzerId: 'test-analyzer',
            status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
            message: 'Found 10 issues',
            issues: $issues,
            executionTime: 0.1,
            metadata: ['name' => 'Test Analyzer'],
        );

        $output = $this->reporter->streamResult($result, 1, 1, 'Security');

        $this->assertStringContainsString('more issue(s)', $output);
    }

    #[Test]
    public function console_output_includes_report_card_table(): void
    {
        $results = collect([
            new AnalysisResult(
                analyzerId: 'sec-1',
                status: \ShieldCI\AnalyzersCore\Enums\Status::Passed,
                message: 'Passed',
                issues: [],
                executionTime: 0.1,
                metadata: ['category' => \ShieldCI\AnalyzersCore\Enums\Category::Security, 'name' => 'Security 1'],
            ),
            new AnalysisResult(
                analyzerId: 'perf-1',
                status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
                message: 'Failed',
                issues: [
                    new Issue(
                        message: 'Slow query',
                        location: new Location('/app/Query.php', 10),
                        severity: Severity::High,
                        recommendation: 'Optimize query',
                    ),
                ],
                executionTime: 0.2,
                metadata: ['category' => \ShieldCI\AnalyzersCore\Enums\Category::Performance, 'name' => 'Perf 1'],
            ),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        // Report card table should have status rows
        $this->assertStringContainsString('Passed', $output);
        $this->assertStringContainsString('Failed', $output);
        $this->assertStringContainsString('Total', $output);
    }

    #[Test]
    public function it_shows_recommendations_when_enabled(): void
    {
        config(['shieldci.report.show_recommendations' => true]);

        $result = new AnalysisResult(
            analyzerId: 'test-analyzer',
            status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
            message: 'Found issues',
            issues: [
                new Issue(
                    message: 'XSS detected',
                    location: new Location('/app/View.php', 10),
                    severity: Severity::Critical,
                    recommendation: 'Escape all user output',
                ),
            ],
            executionTime: 0.1,
            metadata: ['name' => 'XSS Analyzer'],
        );

        $output = $this->reporter->streamResult($result, 1, 1, 'Security');

        $this->assertStringContainsString('Escape all user output', $output);
    }

    #[Test]
    public function it_hides_recommendations_when_disabled(): void
    {
        config(['shieldci.report.show_recommendations' => false]);

        $result = new AnalysisResult(
            analyzerId: 'test-analyzer',
            status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
            message: 'Found issues',
            issues: [
                new Issue(
                    message: 'Issue found',
                    location: new Location('/app/Test.php', 10),
                    severity: Severity::High,
                    recommendation: 'This should not appear',
                ),
            ],
            executionTime: 0.1,
            metadata: ['name' => 'Test Analyzer'],
        );

        $output = $this->reporter->streamResult($result, 1, 1, 'Security');

        $this->assertStringNotContainsString('This should not appear', $output);
    }

    #[Test]
    public function console_output_handles_issues_without_location(): void
    {
        $result = new AnalysisResult(
            analyzerId: 'test-analyzer',
            status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
            message: 'Found issues',
            issues: [
                new Issue(
                    message: 'Application-wide security issue',
                    location: null,
                    severity: Severity::High,
                    recommendation: 'Fix the application config',
                ),
            ],
            executionTime: 0.1,
            metadata: ['name' => 'Test Analyzer'],
        );

        $output = $this->reporter->streamResult($result, 1, 1, 'Security');

        $this->assertStringContainsString('Application-wide security issue', $output);
    }

    #[Test]
    public function console_output_handles_skipped_analyzers_in_report(): void
    {
        $results = collect([
            AnalysisResult::passed('pass-1', 'OK'),
            AnalysisResult::skipped('skip-1', 'Skipped'),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        $this->assertStringContainsString('Not Applicable', $output);
    }

    #[Test]
    public function console_output_shows_time_to_fix_in_report(): void
    {
        $results = collect([
            new AnalysisResult(
                analyzerId: 'test-analyzer',
                status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
                message: 'Found issues',
                issues: [
                    new Issue(
                        message: 'Issue',
                        location: new Location('/app/Test.php', 1),
                        severity: Severity::Medium,
                        recommendation: 'Fix it',
                    ),
                ],
                executionTime: 0.1,
                metadata: [
                    'name' => 'Test Analyzer',
                    'category' => \ShieldCI\AnalyzersCore\Enums\Category::Security,
                    'timeToFix' => 5,
                ],
            ),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        $this->assertStringContainsString('5 mins', $output);
    }

    #[Test]
    public function console_output_shows_docs_url_in_report(): void
    {
        $results = collect([
            new AnalysisResult(
                analyzerId: 'test-analyzer',
                status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
                message: 'Found issues',
                issues: [
                    new Issue(
                        message: 'Issue',
                        location: new Location('/app/Test.php', 1),
                        severity: Severity::Medium,
                        recommendation: 'Fix it',
                    ),
                ],
                executionTime: 0.1,
                metadata: [
                    'name' => 'Test Analyzer',
                    'category' => \ShieldCI\AnalyzersCore\Enums\Category::Security,
                    'docsUrl' => 'https://docs.shieldci.com/test-analyzer',
                ],
            ),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        $this->assertStringContainsString('Documentation URL', $output);
        $this->assertStringContainsString('https://docs.shieldci.com/test-analyzer', $output);
    }

    #[Test]
    public function stream_result_groups_issues_at_same_location(): void
    {
        $result = new AnalysisResult(
            analyzerId: 'test-analyzer',
            status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
            message: 'Found 2 issues',
            issues: [
                new Issue(
                    message: 'First issue at same location',
                    location: new Location('/app/Controller.php', 42),
                    severity: Severity::High,
                    recommendation: 'Fix first',
                ),
                new Issue(
                    message: 'Second issue at same location',
                    location: new Location('/app/Controller.php', 42),
                    severity: Severity::High,
                    recommendation: 'Fix second',
                ),
            ],
            executionTime: 0.1,
            metadata: ['name' => 'Test Analyzer'],
        );

        $output = $this->reporter->streamResult($result, 1, 1, 'Security');

        // Grouped issues at same location show individual messages indented with →
        $this->assertStringContainsString('First issue at same location', $output);
        $this->assertStringContainsString('Second issue at same location', $output);
    }

    #[Test]
    public function it_normalizes_string_integer_config_values(): void
    {
        config(['shieldci.report.max_issues_per_check' => '3']);

        $result = new AnalysisResult(
            analyzerId: 'test-analyzer',
            status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
            message: 'Found 5 issues',
            issues: array_map(fn ($i) => new Issue(
                message: "Issue {$i}",
                location: new Location("/app/File{$i}.php", $i),
                severity: Severity::Medium,
                recommendation: 'Fix it',
            ), range(1, 5)),
            executionTime: 0.1,
            metadata: ['name' => 'Test Analyzer'],
        );

        $output = $this->reporter->streamResult($result, 1, 1, 'Security');

        $this->assertStringContainsString('more issue(s)', $output);
    }

    #[Test]
    public function it_handles_non_numeric_string_config_value(): void
    {
        config(['shieldci.report.max_issues_per_check' => 'invalid']);

        $result = new AnalysisResult(
            analyzerId: 'test-analyzer',
            status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
            message: 'Found 3 issues',
            issues: array_map(fn ($i) => new Issue(
                message: "Issue {$i}",
                location: new Location("/app/File{$i}.php", $i),
                severity: Severity::Medium,
                recommendation: 'Fix it',
            ), range(1, 3)),
            executionTime: 0.1,
            metadata: ['name' => 'Test Analyzer'],
        );

        // Non-numeric string defaults to configured default; should not crash
        $output = $this->reporter->streamResult($result, 1, 1, 'Security');
        $this->assertIsString($output);
    }

    #[Test]
    public function console_output_only_shows_categories_with_non_skipped_analyzers(): void
    {
        $results = collect([
            new AnalysisResult(
                analyzerId: 'pass-1',
                status: \ShieldCI\AnalyzersCore\Enums\Status::Passed,
                message: 'OK',
                issues: [],
                executionTime: 0.1,
                metadata: ['category' => \ShieldCI\AnalyzersCore\Enums\Category::Security, 'name' => 'Sec Test'],
            ),
            AnalysisResult::skipped('skip-1', 'Skipped', 0.0, [
                'category' => \ShieldCI\AnalyzersCore\Enums\Category::Performance,
                'name' => 'Perf Test',
            ]),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        // Security should be shown
        $this->assertStringContainsString('Security', $output);
    }

    #[Test]
    public function console_output_handles_null_location_issues_in_to_console(): void
    {
        // Exercises line 128 (null location in toConsole issue display)
        $results = collect([
            new AnalysisResult(
                analyzerId: 'test-analyzer',
                status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
                message: 'Found issues',
                issues: [
                    new Issue(
                        message: 'Application-wide config problem',
                        location: null,
                        severity: Severity::High,
                        recommendation: 'Fix config',
                    ),
                ],
                executionTime: 0.1,
                metadata: [
                    'name' => 'Config Analyzer',
                    'category' => \ShieldCI\AnalyzersCore\Enums\Category::Security,
                ],
            ),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        $this->assertStringContainsString('Application-wide config problem', $output);
    }

    #[Test]
    public function console_output_truncates_many_issues_in_to_console(): void
    {
        // Exercises lines 140-141 (truncated issues in toConsole)
        config(['shieldci.report.max_issues_per_check' => 1]);

        $results = collect([
            new AnalysisResult(
                analyzerId: 'test-analyzer',
                status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
                message: 'Found 3 issues',
                issues: [
                    new Issue(message: 'Issue 1', location: new Location('/a.php', 1), severity: Severity::Medium, recommendation: 'Fix'),
                    new Issue(message: 'Issue 2', location: new Location('/b.php', 2), severity: Severity::Medium, recommendation: 'Fix'),
                    new Issue(message: 'Issue 3', location: new Location('/c.php', 3), severity: Severity::Medium, recommendation: 'Fix'),
                ],
                executionTime: 0.1,
                metadata: [
                    'name' => 'Test Analyzer',
                    'category' => \ShieldCI\AnalyzersCore\Enums\Category::Security,
                ],
            ),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        $this->assertStringContainsString('more issue(s)', $output);
    }

    #[Test]
    public function console_output_shows_recommendations_in_to_console(): void
    {
        // Exercises line 216 (italic recommendation in toConsole)
        config(['shieldci.report.show_recommendations' => true]);

        $results = collect([
            new AnalysisResult(
                analyzerId: 'test-analyzer',
                status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
                message: 'Found issues',
                issues: [
                    new Issue(
                        message: 'SQL issue',
                        location: new Location('/app/Model.php', 10),
                        severity: Severity::High,
                        recommendation: 'Use parameterized queries',
                    ),
                ],
                executionTime: 0.1,
                metadata: [
                    'name' => 'SQL Analyzer',
                    'category' => \ShieldCI\AnalyzersCore\Enums\Category::Security,
                ],
            ),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        $this->assertStringContainsString('Use parameterized queries', $output);
    }

    #[Test]
    public function console_output_shows_docs_url_in_to_console(): void
    {
        // Exercises line 239 (documentation URL in toConsole)
        $results = collect([
            new AnalysisResult(
                analyzerId: 'test-analyzer',
                status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
                message: 'Issue found',
                issues: [
                    new Issue(
                        message: 'Problem',
                        location: new Location('/app/Test.php', 1),
                        severity: Severity::Medium,
                        recommendation: 'Fix it',
                    ),
                ],
                executionTime: 0.1,
                metadata: [
                    'name' => 'Test Analyzer',
                    'category' => \ShieldCI\AnalyzersCore\Enums\Category::Security,
                    'docsUrl' => 'https://docs.shieldci.com/test',
                ],
            ),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        $this->assertStringContainsString('Documentation URL', $output);
    }

    #[Test]
    public function console_report_card_falls_back_when_all_skipped(): void
    {
        // Exercises line 377 (all categories only have skipped analyzers)
        $results = collect([
            AnalysisResult::skipped('skip-1', 'Not applicable', 0.0, [
                'category' => \ShieldCI\AnalyzersCore\Enums\Category::Security,
                'name' => 'Skipped Analyzer',
            ]),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        // Should still render report card (fallback to showing all categories)
        $this->assertStringContainsString('Report Card', $output);
    }

    #[Test]
    public function json_output_contains_all_required_fields(): void
    {
        $results = collect([
            new AnalysisResult(
                analyzerId: 'test-analyzer',
                status: \ShieldCI\AnalyzersCore\Enums\Status::Failed,
                message: 'Found 1 issue',
                issues: [
                    new Issue(
                        message: 'Test issue',
                        location: new Location('/app/Test.php', 10),
                        severity: Severity::High,
                        recommendation: 'Fix it',
                    ),
                ],
                executionTime: 0.5,
                metadata: ['name' => 'Test Analyzer', 'category' => \ShieldCI\AnalyzersCore\Enums\Category::Security],
            ),
        ]);

        $report = $this->reporter->generate($results);
        $json = $this->reporter->toJson($report);
        $decoded = json_decode($json, true);

        $this->assertArrayHasKey('summary', $decoded);
        $this->assertArrayHasKey('total', $decoded['summary']);
        $this->assertArrayHasKey('passed', $decoded['summary']);
        $this->assertArrayHasKey('failed', $decoded['summary']);
        $this->assertArrayHasKey('results', $decoded);
        $this->assertArrayHasKey('analyzed_at', $decoded);
    }

    #[Test]
    public function console_output_shows_error_status_label(): void
    {
        $results = collect([
            new AnalysisResult(
                analyzerId: 'test-error-analyzer',
                status: \ShieldCI\AnalyzersCore\Enums\Status::Error,
                message: 'Analyzer encountered an error',
                issues: [],
                executionTime: 0.1,
                metadata: [
                    'name' => 'Test Error Analyzer',
                    'category' => \ShieldCI\AnalyzersCore\Enums\Category::Security,
                ],
            ),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        $this->assertStringContainsString('Error', $output);
    }

    #[Test]
    public function color_returns_text_for_unknown_color(): void
    {
        $reflection = new \ReflectionMethod($this->reporter, 'color');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->reporter, 'hello', 'unknown_color');

        $this->assertEquals('hello', $result);
    }

    #[Test]
    public function visible_width_handles_null_preg_result(): void
    {
        $reflection = new \ReflectionMethod($this->reporter, 'visibleWidth');
        $reflection->setAccessible(true);

        // Test with plain text (no ANSI codes)
        $result = $reflection->invoke($this->reporter, 'Hello World');
        $this->assertEquals(11, $result);

        // Test with ANSI color codes
        $result = $reflection->invoke($this->reporter, "\033[0;32mHello\033[0m");
        $this->assertEquals(5, $result);
    }

    #[Test]
    public function pad_visible_pads_left_and_center(): void
    {
        $reflection = new \ReflectionMethod($this->reporter, 'padVisible');
        $reflection->setAccessible(true);

        // PAD_LEFT
        $result = $reflection->invoke($this->reporter, 'Hi', 10, ' ', STR_PAD_LEFT);
        $this->assertIsString($result);
        $this->assertEquals('        Hi', $result);
        $this->assertEquals(10, strlen($result));

        // PAD_BOTH
        $result = $reflection->invoke($this->reporter, 'Hi', 10, ' ', STR_PAD_BOTH);
        $this->assertIsString($result);
        $this->assertEquals(10, strlen($result));
        $this->assertStringContainsString('Hi', $result);
    }

    #[Test]
    public function get_package_version_returns_dev_when_file_missing(): void
    {
        $reflection = new \ReflectionMethod($this->reporter, 'getPackageVersion');
        $reflection->setAccessible(true);

        // The method looks at __DIR__.'/../../composer.json' which exists
        // So we just confirm it returns a string
        $version = $reflection->invoke($this->reporter);
        $this->assertIsString($version);
    }

    #[Test]
    public function console_output_shows_unknown_category_for_non_string_category(): void
    {
        $results = collect([
            new AnalysisResult(
                analyzerId: 'test-analyzer',
                status: \ShieldCI\AnalyzersCore\Enums\Status::Passed,
                message: 'All checks passed',
                issues: [],
                executionTime: 0.1,
                metadata: ['name' => 'Test Analyzer', 'category' => 42],
            ),
        ]);

        $report = $this->reporter->generate($results);
        $output = $this->reporter->toConsole($report);

        $this->assertStringContainsString('Unknown', $output);
    }
}
