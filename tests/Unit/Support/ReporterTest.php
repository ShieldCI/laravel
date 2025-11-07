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
        $this->assertStringContainsString('ShieldCI Security Analysis', $output);
        $this->assertStringContainsString('Score:', $output);
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
        $this->assertArrayHasKey('project_id', $decoded);
        $this->assertArrayHasKey('summary', $decoded);
        $this->assertArrayHasKey('score', $decoded['summary']);
        $this->assertArrayHasKey('results', $decoded);
    }

    #[Test]
    public function it_can_format_to_api(): void
    {
        $results = collect([
            AnalysisResult::passed('test-analyzer', 'All checks passed'),
        ]);

        $report = $this->reporter->generate($results);
        $payload = $this->reporter->toApi($report);

        $this->assertIsArray($payload);
        $this->assertArrayHasKey('project_id', $payload);
        $this->assertArrayHasKey('results', $payload);
        $this->assertArrayHasKey('metadata', $payload);
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

        $this->assertStringContainsString('FAILED ANALYZERS', $output);
        $this->assertStringContainsString('Security vulnerability detected', $output);
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

        $this->assertStringContainsString('WARNINGS', $output);
        $this->assertStringContainsString('test-analyzer', $output);
        $this->assertStringContainsString('Warning issued', $output);
    }
}
