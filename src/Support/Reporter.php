<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use DateTimeImmutable;
use Illuminate\Support\Collection;
use ShieldCI\Contracts\ReporterInterface;
use ShieldCI\ValueObjects\AnalysisReport;

/**
 * Report generator for analysis results.
 */
class Reporter implements ReporterInterface
{
    public function generate(Collection $results): AnalysisReport
    {
        return new AnalysisReport(
            projectId: config('shieldci.project_id', 'unknown'),
            laravelVersion: app()->version(),
            packageVersion: $this->getPackageVersion(),
            results: $results,
            totalExecutionTime: $results->sum('executionTime'),
            analyzedAt: new DateTimeImmutable,
        );
    }

    public function toConsole(AnalysisReport $report): string
    {
        $output = [];

        // Header
        $output[] = '';
        $output[] = '╔══════════════════════════════════════════════════╗';
        $output[] = '║          ShieldCI Security Analysis              ║';
        $output[] = '╚══════════════════════════════════════════════════╝';
        $output[] = '';

        // Summary
        $summary = $report->summary();
        $output[] = "Score: {$report->score()}/100";
        $output[] = '';
        $output[] = "Total Analyzers: {$summary['total']}";
        $output[] = "✓ Passed: {$summary['passed']}";
        $output[] = "✗ Failed: {$summary['failed']}";
        $output[] = "⚠ Warnings: {$summary['warnings']}";
        $output[] = "⊝ Skipped: {$summary['skipped']}";

        if ($summary['errors'] > 0) {
            $output[] = "⊗ Errors: {$summary['errors']}";
        }

        $output[] = '';
        $output[] = "Execution Time: {$report->totalExecutionTime}s";
        $output[] = '';

        // Failed analyzers
        if ($report->failed()->isNotEmpty()) {
            $output[] = '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';
            $output[] = 'FAILED ANALYZERS';
            $output[] = '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';
            $output[] = '';

            foreach ($report->failed() as $result) {
                $output[] = "✗ {$result->getAnalyzerId()}";
                $output[] = "  {$result->getMessage()}";

                $issues = $result->getIssues();
                if (! empty($issues)) {
                    $issueCount = count($issues);
                    $output[] = "  Issues found: {$issueCount}";

                    foreach (array_slice($issues, 0, 3) as $issue) {
                        $output[] = "    - {$issue->location}: {$issue->message}";
                    }

                    if ($issueCount > 3) {
                        $remaining = $issueCount - 3;
                        $output[] = "    ... and {$remaining} more";
                    }
                }

                $output[] = '';
            }
        }

        // Warnings
        if ($report->warnings()->isNotEmpty()) {
            $output[] = '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';
            $output[] = 'WARNINGS';
            $output[] = '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';
            $output[] = '';

            foreach ($report->warnings() as $result) {
                $output[] = "⚠ {$result->getAnalyzerId()}";
                $output[] = "  {$result->getMessage()}";
                $output[] = '';
            }
        }

        // Footer
        $output[] = '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';

        if ($report->score() >= 80) {
            $output[] = '✓ Analysis completed successfully!';
        } elseif ($report->score() >= 60) {
            $output[] = '⚠ Analysis completed with warnings.';
        } else {
            $output[] = '✗ Analysis completed with failures.';
        }

        $output[] = '';

        return implode(PHP_EOL, $output);
    }

    public function toJson(AnalysisReport $report): string
    {
        return json_encode($report->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    public function toApi(AnalysisReport $report): array
    {
        return $report->toArray();
    }

    protected function getPackageVersion(): string
    {
        $composerPath = __DIR__.'/../../composer.json';

        if (file_exists($composerPath)) {
            $composer = json_decode(file_get_contents($composerPath), true);

            return $composer['version'] ?? 'dev';
        }

        return 'dev';
    }
}
