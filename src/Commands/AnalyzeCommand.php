<?php

declare(strict_types=1);

namespace ShieldCI\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzerManager;
use ShieldCI\Contracts\ClientInterface;
use ShieldCI\Contracts\ReporterInterface;
use ShieldCI\ValueObjects\AnalysisReport;

class AnalyzeCommand extends Command
{
    protected $signature = 'shield:analyze
                            {--analyzer= : Run specific analyzer}
                            {--category= : Run analyzers in category}
                            {--format=console : Output format (console|json)}
                            {--output= : Save report to file}
                            {--no-send : Do not send results to ShieldCI API}';

    protected $description = 'Run ShieldCI security and code quality analysis';

    public function handle(
        AnalyzerManager $manager,
        ReporterInterface $reporter,
        ClientInterface $client,
    ): int {
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

        // Output report
        $this->outputReport($report, $reporter);

        // Save to file if requested
        if ($output = $this->option('output')) {
            $this->saveReport($report, $reporter, $output);
        }

        // Send to API if enabled
        if ($this->shouldSendToApi()) {
            $this->sendToApi($report, $client);
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
        $format = $this->option('format');

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

    protected function shouldSendToApi(): bool
    {
        if ($this->option('no-send')) {
            return false;
        }

        if (! config('shieldci.report.send_to_api')) {
            return false;
        }

        if (! config('shieldci.token')) {
            $this->warn('ShieldCI token not configured. Skipping API upload.');

            return false;
        }

        return true;
    }

    protected function sendToApi(AnalysisReport $report, ClientInterface $client): void
    {
        $this->info('Sending results to ShieldCI...');

        try {
            $success = $client->sendReport($report);

            if ($success) {
                $this->info('✓ Results sent successfully!');
            } else {
                $this->error('✗ Failed to send results.');
            }
        } catch (\Exception $e) {
            $this->error("✗ Error sending results: {$e->getMessage()}");
        }
    }

    protected function determineExitCode(AnalysisReport $report): int
    {
        $failOn = config('shieldci.fail_on', 'critical');

        if ($failOn === 'never') {
            return self::SUCCESS;
        }

        // Check threshold if configured
        if ($threshold = config('shieldci.fail_threshold')) {
            if ($report->score() < $threshold) {
                return self::FAILURE;
            }
        }

        // Check severity levels
        $hasCritical = $report->failed()->some(fn ($result) => $result->issues->some(fn ($issue) => $issue->severity->value === 'critical'
        )
        );

        if ($hasCritical && in_array($failOn, ['critical', 'high', 'medium', 'low'])) {
            return self::FAILURE;
        }

        return self::SUCCESS;
    }
}
