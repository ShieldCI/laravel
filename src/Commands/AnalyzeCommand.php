<?php

declare(strict_types=1);

namespace ShieldCI\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzerManager;
use ShieldCI\Contracts\ReporterInterface;
use ShieldCI\ValueObjects\AnalysisReport;

class AnalyzeCommand extends Command
{
    protected $signature = 'shield:analyze
                            {--analyzer= : Run specific analyzer}
                            {--category= : Run analyzers in category}
                            {--format=console : Output format (console|json)}
                            {--output= : Save report to file}
                            {--baseline : Compare against baseline and only report new issues}';

    protected $description = 'Run ShieldCI security and code quality analysis';

    public function handle(
        AnalyzerManager $manager,
        ReporterInterface $reporter,
    ): int {
        // Apply memory limit
        $memoryLimit = config('shieldci.memory_limit');
        if ($memoryLimit !== null && is_string($memoryLimit)) {
            ini_set('memory_limit', $memoryLimit);
        }

        // Set timeout
        $timeout = config('shieldci.timeout');
        if ($timeout !== null && is_int($timeout)) {
            set_time_limit($timeout);
        }

        $this->info('🛡️  ShieldCI Analysis Starting...');
        $this->newLine();

        // Check if enabled
        if (! config('shieldci.enabled')) {
            $this->warn('ShieldCI is disabled in configuration.');

            return self::SUCCESS;
        }

        // Run analysis
        $results = $this->runAnalysis($manager);

        if ($results->isEmpty()) {
            $this->error('No analyzers were run.');

            return self::FAILURE;
        }

        // Generate report
        $report = $reporter->generate($results);

        // Filter against baseline if requested
        if ($this->option('baseline')) {
            $report = $this->filterAgainstBaseline($report);
        }

        // Output report
        $this->outputReport($report, $reporter);

        // Save to file if requested (CLI option or config default)
        $output = $this->option('output');
        if (! $output) {
            $configOutput = config('shieldci.report.output_file');
            $output = is_string($configOutput) ? $configOutput : null;
        }

        if ($output && is_string($output)) {
            $this->saveReport($report, $reporter, $output);
        }

        // Determine exit code
        return $this->determineExitCode($report);
    }

    protected function runAnalysis(AnalyzerManager $manager): Collection
    {
        if ($analyzerId = $this->option('analyzer')) {
            $this->line("Running analyzer: {$analyzerId}");
            $result = $manager->run($analyzerId);

            return collect($result ? [$result] : []);
        }

        if ($category = $this->option('category')) {
            $this->line("Running {$category} analyzers...");
            $analyzers = $manager->getByCategory($category);
        } else {
            $this->line('Running all analyzers...');
            $analyzers = $manager->getAnalyzers();
        }

        $this->withProgressBar($analyzers, function ($analyzer) {
            return $analyzer->analyze();
        });

        $this->newLine(2);

        return $manager->runAll();
    }

    protected function outputReport(AnalysisReport $report, ReporterInterface $reporter): void
    {
        // Use CLI option or fall back to config
        $format = $this->option('format') ?: config('shieldci.report.format', 'console');

        if ($format === 'json') {
            $this->line($reporter->toJson($report));
        } else {
            $this->line($reporter->toConsole($report));
        }
    }

    protected function saveReport(AnalysisReport $report, ReporterInterface $reporter, string $path): void
    {
        $content = $this->option('format') === 'json'
            ? $reporter->toJson($report)
            : $reporter->toConsole($report);

        file_put_contents($path, $content);

        $this->info("Report saved to: {$path}");
    }

    protected function determineExitCode(AnalysisReport $report): int
    {
        $failOn = config('shieldci.fail_on', 'critical');

        if ($failOn === 'never') {
            return self::SUCCESS;
        }

        // Get don't report analyzers
        $dontReportConfig = config('shieldci.dont_report', []);
        $dontReport = is_array($dontReportConfig) ? $dontReportConfig : [];

        // Filter out analyzers in dont_report list
        $criticalResults = $report->failed()->filter(function ($result) use ($dontReport) {
            return ! in_array($result->getAnalyzerId(), $dontReport, true);
        });

        // Check threshold if configured
        if ($threshold = config('shieldci.fail_threshold')) {
            if ($report->score() < $threshold) {
                return self::FAILURE;
            }
        }

        // Check severity levels
        $hasCritical = $criticalResults->some(function ($result) {
            $issues = $result->getIssues();
            foreach ($issues as $issue) {
                if ($issue->severity->value === 'critical') {
                    return true;
                }
            }

            return false;
        });

        if ($hasCritical && in_array($failOn, ['critical', 'high', 'medium', 'low'])) {
            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    /**
     * Filter report against baseline to show only new issues.
     */
    protected function filterAgainstBaseline(AnalysisReport $report): AnalysisReport
    {
        $baselineFileRaw = config('shieldci.baseline_file');
        $baselineFile = is_string($baselineFileRaw) ? $baselineFileRaw : null;

        if (! $baselineFile || ! file_exists($baselineFile)) {
            $this->warn('⚠️  No baseline file found. Run "php artisan shield:baseline" to create one.');

            return $report;
        }

        $baseline = json_decode(file_get_contents($baselineFile), true);
        $baselineErrors = $baseline['errors'] ?? [];

        $this->info('📋 Filtering against baseline...');

        // Filter results
        $filteredResults = $report->results->map(function ($result) use ($baselineErrors) {
            $analyzerId = $result->getAnalyzerId();

            // If no baseline for this analyzer, return as-is
            if (! isset($baselineErrors[$analyzerId])) {
                return $result;
            }

            $baselineIssues = $baselineErrors[$analyzerId];
            $currentIssues = $result->getIssues();

            // Filter out issues that exist in baseline
            $newIssues = collect($currentIssues)->filter(function ($issue) use ($baselineIssues) {
                $issueHash = $this->generateIssueHash($issue);

                foreach ($baselineIssues as $baselineIssue) {
                    if (isset($baselineIssue['hash']) && $baselineIssue['hash'] === $issueHash) {
                        return false; // Issue exists in baseline, filter it out
                    }
                }

                return true; // New issue
            });

            // Create new result with filtered issues
            $status = $newIssues->isEmpty()
                ? \ShieldCI\AnalyzersCore\Enums\Status::Passed
                : $result->getStatus();

            return new \ShieldCI\AnalyzersCore\Results\AnalysisResult(
                analyzerId: $result->getAnalyzerId(),
                status: $status,
                message: $newIssues->isEmpty() ? 'All issues are in baseline' : $result->getMessage(),
                issues: $newIssues->all(),
                executionTime: $result->getExecutionTime(),
                metadata: $result->getMetadata(),
            );
        });

        // Return new report with filtered results
        return new AnalysisReport(
            laravelVersion: $report->laravelVersion,
            packageVersion: $report->packageVersion,
            results: $filteredResults,
            totalExecutionTime: $report->totalExecutionTime,
            analyzedAt: $report->analyzedAt,
        );
    }

    /**
     * Generate a unique hash for an issue.
     */
    private function generateIssueHash(\ShieldCI\AnalyzersCore\ValueObjects\Issue $issue): string
    {
        $data = [
            'file' => $issue->location->file ?? 'unknown',
            'line' => $issue->location->line,
            'message' => $issue->message,
        ];

        $json = json_encode($data);

        return hash('sha256', $json !== false ? $json : '');
    }
}
