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
                            {--merge : Merge with existing baseline instead of overwriting}';

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
        $this->info('🔍 Running analysis to generate baseline...');
        $this->newLine();

        // Run all analyzers
        $results = $manager->runAll();

        // Determine output path
        $outputPathRaw = $this->option('output') ?? config('shieldci.baseline_file');
        $outputPath = is_string($outputPathRaw) ? $outputPathRaw : base_path('.shieldci-baseline.json');

        // Load existing baseline if merging
        $existingBaseline = [];
        if ($this->option('merge') && file_exists($outputPath)) {
            $decoded = json_decode(file_get_contents($outputPath), true);
            $existingBaseline = is_array($decoded) && isset($decoded['errors']) && is_array($decoded['errors'])
                ? $decoded['errors']
                : [];
            $this->info("📋 Merging with existing baseline at: {$outputPath}");
        }

        // Extract all issues
        $baseline = $existingBaseline;
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
            if (count($issues) === 0) {
                continue;
            }

            $this->line("  📌 {$analyzerName}: ".count($issues).' issue(s)');

            // Initialize analyzer entry if not exists
            if (! isset($baseline[$analyzerId])) {
                $baseline[$analyzerId] = [];
            }

            foreach ($issues as $issue) {
                $issueData = [
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
            'errors' => $baseline,
        ];

        // Save baseline file
        $json = json_encode($baselineData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        file_put_contents($outputPath, $json);

        $this->newLine();
        $this->info('✅ Baseline file generated successfully!');
        $this->line("   📁 Location: {$outputPath}");
        $this->line("   📊 Total issues: {$baselineData['total_issues']}");

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
