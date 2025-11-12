<?php

declare(strict_types=1);

namespace ShieldCI\Commands;

use Illuminate\Console\Command;
use ShieldCI\AnalyzerManager;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;

class BaselineCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'shield:baseline
                            {--output= : Custom output path for baseline file}
                            {--merge : Merge with existing baseline instead of overwriting}
                            {--ci : Generate baseline for CI mode (only CI-compatible analyzers)}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate a baseline file to suppress existing issues';

    /**
     * Execute the console command.
     */
    public function handle(AnalyzerManager $manager): int
    {
        // If --ci flag is used, temporarily enable CI mode for baseline generation
        $wasCiMode = config('shieldci.ci_mode', false);
        if ($this->option('ci')) {
            config()->set('shieldci.ci_mode', true);
            $this->info('🔍 Running analysis to generate baseline (CI mode)...');
        } else {
            $this->info('🔍 Running analysis to generate baseline...');
        }
        $this->newLine();

        // Run all analyzers (respects CI mode from config or --ci flag)
        $results = $manager->runAll();

        // Restore original CI mode setting
        if ($this->option('ci')) {
            config()->set('shieldci.ci_mode', $wasCiMode);
        }

        // Determine output path
        $outputPathRaw = $this->option('output') ?? config('shieldci.baseline_file');
        $outputPath = is_string($outputPathRaw) ? $outputPathRaw : base_path('.shieldci-baseline.json');

        // Load existing baseline if merging
        $existingBaseline = [];
        $existingDontReport = [];
        if ($this->option('merge') && file_exists($outputPath)) {
            $decoded = json_decode(file_get_contents($outputPath), true);
            $existingBaseline = is_array($decoded) && isset($decoded['errors']) && is_array($decoded['errors'])
                ? $decoded['errors']
                : [];
            $existingDontReport = is_array($decoded) && isset($decoded['dont_report']) && is_array($decoded['dont_report'])
                ? $decoded['dont_report']
                : [];
            $this->info("📋 Merging with existing baseline at: {$outputPath}");
        }

        // Extract all issues and detect analyzers with no specific issues
        $baseline = $existingBaseline;
        $dontReport = $existingDontReport;
        $newIssuesCount = 0;

        foreach ($results as $result) {
            $analyzerId = $result->getAnalyzerId();

            // Skip if analyzer passed or was skipped
            if (in_array($result->getStatus(), [Status::Passed, Status::Skipped])) {
                continue;
            }

            // Get metadata for display
            $metadata = $result->getMetadata();
            $analyzerName = is_array($metadata) && isset($metadata['name'])
                ? $metadata['name']
                : $analyzerId;

            $issues = $result->getIssues();

            // If analyzer failed but has no specific issues, add to dont_report
            if (count($issues) === 0) {
                if (! in_array($analyzerId, $dontReport, true)) {
                    $dontReport[] = $analyzerId;
                    $this->line("  ⚠️  {$analyzerName}: No specific issues (added to dont_report)");
                }

                continue;
            }

            $this->line("  📌 {$analyzerName}: ".count($issues).' issue(s)');

            // Initialize analyzer entry if not exists
            if (! isset($baseline[$analyzerId])) {
                $baseline[$analyzerId] = [];
            }

            foreach ($issues as $issue) {
                $issueData = [
                    'type' => 'hash',
                    'path' => $issue->location->file ?? 'unknown',
                    'line' => $issue->location->line,
                    'message' => $issue->message,
                    'hash' => $this->generateHash($issue),
                ];

                // Check if this exact issue already exists
                $exists = false;
                foreach ($baseline[$analyzerId] as $existingIssue) {
                    if (is_array($existingIssue) && isset($existingIssue['hash']) && $existingIssue['hash'] === $issueData['hash']) {
                        $exists = true;
                        break;
                    }
                }

                if (! $exists) {
                    $baseline[$analyzerId][] = $issueData;
                    $newIssuesCount++;
                }
            }
        }

        // Prepare final baseline data
        $baselineData = [
            'generated_at' => date('c'),
            'generator' => 'ShieldCI Baseline Command',
            'version' => '1.0.0',
            'total_issues' => array_sum(array_map('count', $baseline)),
            'dont_report' => array_values(array_unique($dontReport)),
            'errors' => $baseline,
        ];

        // Save baseline file
        $json = json_encode($baselineData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        file_put_contents($outputPath, $json);

        $this->newLine();
        $this->info('✅ Baseline file generated successfully!');
        $this->line("   📁 Location: {$outputPath}");
        $this->line("   📊 Total issues: {$baselineData['total_issues']}");
        if (count($baselineData['dont_report']) > 0) {
            $this->line('   ⚠️  Analyzers in dont_report: '.count($baselineData['dont_report']));
        }

        if ($this->option('merge')) {
            $this->line("   🆕 New issues added: {$newIssuesCount}");
        }

        $this->newLine();
        $this->comment('💡 These issues will be ignored in future analyses when using --baseline flag.');
        $this->comment('💡 To analyze against baseline: php artisan shield:analyze --baseline');

        return self::SUCCESS;
    }

    /**
     * Generate a unique hash for an issue.
     */
    private function generateHash(Issue $issue): string
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
