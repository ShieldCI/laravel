<?php

declare(strict_types=1);

namespace ShieldCI\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzerManager;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
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
        // Validate options
        if (! $this->validateOptions($manager)) {
            return self::FAILURE;
        }

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

        // Filter against ignore_errors config (always applied)
        $report = $this->filterAgainstIgnoreErrors($report);

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
            $analyzers = $manager->getByCategory($category);
            $totalCount = $manager->count(); // Total registered analyzers
            $enabledCount = $analyzers->count();
            // Get actual skipped count (may differ from calculated due to instantiation failures)
            $skippedCount = $manager->getSkippedAnalyzers()
                ->filter(function (ResultInterface $result) use ($category): bool {
                    $metadata = $result->getMetadata();
                    $resultCategory = $metadata['category'] ?? 'Unknown';
                    if (is_object($resultCategory) && isset($resultCategory->value)) {
                        $resultCategory = $resultCategory->value;
                    }

                    return is_string($resultCategory) && strtolower($resultCategory) === strtolower($category);
                })
                ->count();
            if ($skippedCount > 0) {
                $this->line("Running {$category} analyzers... ({$enabledCount} running, {$skippedCount} skipped, {$totalCount} total)");
            } else {
                $this->line("Running {$category} analyzers... ({$enabledCount}/{$totalCount})");
            }
        } else {
            $analyzers = $manager->getAnalyzers();
            $totalCount = $manager->count(); // Total registered analyzers
            $enabledCount = $analyzers->count();

            // Get actual skipped count (may differ from calculated due to instantiation failures)
            // Note: The final Report Card may show more "Not Applicable" than this count because
            // some analyzers may return Status::Skipped at runtime (via shouldRun() or conditional logic).
            // This count only reflects analyzers pre-filtered before execution.
            $skippedCount = $manager->getSkippedAnalyzers()->count();

            if ($skippedCount > 0) {
                $this->line("Running {$enabledCount} of {$totalCount} analyzers ({$skippedCount} pre-filtered)...");
            } else {
                $this->line("Running all {$enabledCount} analyzers...");
            }
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

        // Get don't report analyzers (from config and baseline if using baseline)
        $dontReportConfig = config('shieldci.dont_report', []);
        $dontReport = is_array($dontReportConfig) ? $dontReportConfig : [];

        // If baseline was used, merge with baseline's dont_report
        if ($this->option('baseline')) {
            $baselineFileRaw = config('shieldci.baseline_file');
            $baselineFile = is_string($baselineFileRaw) ? $baselineFileRaw : null;

            if ($baselineFile && file_exists($baselineFile)) {
                $baseline = json_decode(file_get_contents($baselineFile), true);
                if (is_array($baseline) && isset($baseline['dont_report']) && is_array($baseline['dont_report'])) {
                    $dontReport = array_values(array_unique(array_merge($dontReport, $baseline['dont_report'])));
                }
            }
        }

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
     * Filter report against ignore_errors config.
     */
    protected function filterAgainstIgnoreErrors(AnalysisReport $report): AnalysisReport
    {
        $configIgnoreErrors = config('shieldci.ignore_errors', []);
        $configIgnoreErrors = is_array($configIgnoreErrors) ? $configIgnoreErrors : [];

        if (empty($configIgnoreErrors)) {
            return $report;
        }

        // Filter results
        $filteredResults = $report->results->map(function ($result) use ($configIgnoreErrors) {
            $analyzerId = $result->getAnalyzerId();

            // If no ignore_errors for this analyzer, return as-is
            if (! isset($configIgnoreErrors[$analyzerId])) {
                return $result;
            }

            $currentIssues = $result->getIssues();

            // Filter out issues that match ignore_errors config
            $newIssues = collect($currentIssues)->filter(function ($issue) use ($configIgnoreErrors, $analyzerId) {
                if ($this->matchesIgnoreError($issue, $configIgnoreErrors[$analyzerId])) {
                    return false; // Issue matches ignore_errors, filter it out
                }

                return true; // Keep issue
            });

            // Create new result with filtered issues
            $status = $newIssues->isEmpty()
                ? \ShieldCI\AnalyzersCore\Enums\Status::Passed
                : $result->getStatus();

            return new \ShieldCI\AnalyzersCore\Results\AnalysisResult(
                analyzerId: $result->getAnalyzerId(),
                status: $status,
                message: $newIssues->isEmpty() ? 'All issues are ignored via config' : $result->getMessage(),
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

        $baselineRaw = json_decode(file_get_contents($baselineFile), true);
        /** @var array<string, mixed>|null $baseline */
        $baseline = is_array($baselineRaw) ? $baselineRaw : null;

        // Validate baseline structure
        if (! $this->validateBaseline($baseline)) {
            return $report;
        }

        /** @var array<string, array<int, array<string, mixed>>> $baselineErrors */
        $baselineErrors = is_array($baseline) && isset($baseline['errors']) && is_array($baseline['errors'])
            ? $baseline['errors']
            : [];

        /** @var array<int, string> $baselineDontReport */
        $baselineDontReport = is_array($baseline) && isset($baseline['dont_report']) && is_array($baseline['dont_report'])
            ? $baseline['dont_report']
            : [];

        // Merge baseline dont_report with config dont_report
        $configDontReport = config('shieldci.dont_report', []);
        $configDontReport = is_array($configDontReport) ? $configDontReport : [];
        $allDontReport = array_values(array_unique(array_merge($baselineDontReport, $configDontReport)));

        $this->info('📋 Filtering against baseline...');
        if (count($baselineDontReport) > 0) {
            $this->line('   ⚠️  Using '.count($baselineDontReport).' analyzer(s) from baseline dont_report');
        }

        // Filter results (ignore_errors already filtered in filterAgainstIgnoreErrors)
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
                /** @var array<int, array<string, mixed>> $baselineIssues */
                foreach ($baselineIssues as $baselineIssue) {
                    if (is_array($baselineIssue) && $this->matchesBaselineIssue($issue, $baselineIssue)) {
                        return false; // Issue matches baseline, filter it out
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
     * Check if an issue matches an ignore_errors config entry.
     *
     * @param  array<int, array<string, mixed>>  $ignoreErrors
     */
    private function matchesIgnoreError(\ShieldCI\AnalyzersCore\ValueObjects\Issue $issue, array $ignoreErrors): bool
    {
        if (! is_array($ignoreErrors)) {
            return false;
        }

        $issuePath = $issue->location->file ?? 'unknown';
        $issueMessage = $issue->message;

        foreach ($ignoreErrors as $ignoreError) {
            if (! is_array($ignoreError)) {
                continue;
            }

            $pathMatches = true;
            $messageMatches = true;

            // Check path (supports exact match or pattern)
            if (isset($ignoreError['path']) && is_string($ignoreError['path'])) {
                $ignorePath = $ignoreError['path'];
                $normalizedIssuePath = str_replace('\\', '/', $issuePath);
                $normalizedIgnorePath = str_replace('\\', '/', $ignorePath);

                // Try exact match first
                if ($ignorePath === $issuePath || $normalizedIgnorePath === $normalizedIssuePath) {
                    $pathMatches = true;
                } elseif ((isset($ignoreError['path_pattern']) && is_string($ignoreError['path_pattern'])) || str_contains($ignorePath, '*')) {
                    // Pattern matching (glob or Str::is)
                    $pattern = (isset($ignoreError['path_pattern']) && is_string($ignoreError['path_pattern']))
                        ? $ignoreError['path_pattern']
                        : $ignorePath;
                    if (is_string($pattern)) {
                        $pathMatches = fnmatch($pattern, $issuePath) ||
                                     fnmatch($pattern, $normalizedIssuePath) ||
                                     \Illuminate\Support\Str::is($pattern, $issuePath);
                    } else {
                        $pathMatches = false;
                    }
                } else {
                    $pathMatches = false;
                }
            }

            // Check message (supports exact match or pattern)
            if (isset($ignoreError['message']) && is_string($ignoreError['message'])) {
                $ignoreMessage = $ignoreError['message'];
                if ($ignoreMessage === $issueMessage) {
                    $messageMatches = true;
                } elseif ((isset($ignoreError['message_pattern']) && is_string($ignoreError['message_pattern'])) || str_contains($ignoreMessage, '*')) {
                    // Pattern matching (Laravel Str::is)
                    $pattern = (isset($ignoreError['message_pattern']) && is_string($ignoreError['message_pattern']))
                        ? $ignoreError['message_pattern']
                        : $ignoreMessage;
                    if (is_string($pattern)) {
                        $messageMatches = \Illuminate\Support\Str::is($pattern, $issueMessage);
                    } else {
                        $messageMatches = false;
                    }
                } else {
                    $messageMatches = false;
                }
            }

            // Both path and message must match (if both are specified)
            if ($pathMatches && $messageMatches) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an issue matches a baseline entry.
     *
     * @param  array<string, mixed>  $baselineIssue
     */
    private function matchesBaselineIssue(\ShieldCI\AnalyzersCore\ValueObjects\Issue $issue, array $baselineIssue): bool
    {
        if (! is_array($baselineIssue)) {
            return false;
        }

        $issuePath = $issue->location->file ?? 'unknown';
        $issueMessage = $issue->message;

        // Type 1: Hash-based matching (exact, most precise)
        if (isset($baselineIssue['hash'])) {
            $issueHash = $this->generateIssueHash($issue);
            if ($baselineIssue['hash'] === $issueHash) {
                return true;
            }
        }

        // Type 2: Pattern-based matching (flexible)
        if (isset($baselineIssue['type']) && $baselineIssue['type'] === 'pattern') {
            $pathMatches = true;
            $messageMatches = true;

            // Check path pattern
            if (isset($baselineIssue['path_pattern']) && is_string($baselineIssue['path_pattern'])) {
                $normalizedIssuePath = str_replace('\\', '/', $issuePath);
                $pathPattern = $baselineIssue['path_pattern'];
                $pathMatches = fnmatch($pathPattern, $issuePath) ||
                              fnmatch($pathPattern, $normalizedIssuePath);
            } elseif (isset($baselineIssue['path']) && is_string($baselineIssue['path'])) {
                $pathMatches = $baselineIssue['path'] === $issuePath;
            }

            // Check message pattern
            if (isset($baselineIssue['message_pattern']) && is_string($baselineIssue['message_pattern'])) {
                $messagePattern = $baselineIssue['message_pattern'];
                $messageMatches = \Illuminate\Support\Str::is($messagePattern, $issueMessage);
            } elseif (isset($baselineIssue['message']) && is_string($baselineIssue['message'])) {
                $messageMatches = $baselineIssue['message'] === $issueMessage;
            }

            return $pathMatches && $messageMatches;
        }

        // Type 3: Legacy format (backward compatibility - hash only)
        // This is handled by the hash check above

        return false;
    }

    /**
     * Validate baseline file structure.
     *
     * @param  array<string, mixed>|null  $baseline
     */
    private function validateBaseline(?array $baseline): bool
    {
        if (! is_array($baseline)) {
            $this->error('❌ Invalid baseline: file is not valid JSON or is empty');

            return false;
        }

        $required = ['generated_at', 'version', 'errors'];

        foreach ($required as $key) {
            if (! isset($baseline[$key])) {
                $this->error("❌ Invalid baseline: missing '{$key}' field");

                return false;
            }
        }

        if (! is_array($baseline['errors'])) {
            $this->error("❌ Invalid baseline: 'errors' must be an array");

            return false;
        }

        return true;
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

    /**
     * Validate command options.
     */
    protected function validateOptions(AnalyzerManager $manager): bool
    {
        // Validate analyzer option
        $analyzerId = $this->option('analyzer');
        if ($analyzerId !== null) {
            if (! is_string($analyzerId) || $analyzerId === '') {
                $this->error('❌ Invalid analyzer ID provided.');

                return false;
            }

            // Check if analyzer exists
            $allAnalyzers = $manager->getAnalyzers();
            $analyzerExists = $allAnalyzers->contains(function ($analyzer) use ($analyzerId) {
                return $analyzer->getId() === $analyzerId;
            });

            if (! $analyzerExists) {
                $this->error("❌ Analyzer '{$analyzerId}' not found.");
                $this->line('');
                $this->line('Available analyzers:');
                $allAnalyzers->each(function ($analyzer) {
                    $metadata = $analyzer->getMetadata();
                    $this->line("  - {$analyzer->getId()}: {$metadata->name}");
                });

                return false;
            }
        }

        // Validate category option
        $category = $this->option('category');
        if ($category !== null) {
            if (! is_string($category) || $category === '') {
                $this->error('❌ Invalid category provided.');

                return false;
            }

            // Get valid categories from Category enum
            $validCategories = array_map(
                fn ($case) => $case->value,
                \ShieldCI\AnalyzersCore\Enums\Category::cases()
            );

            $normalizedCategory = strtolower($category);
            $categoryExists = in_array($normalizedCategory, array_map('strtolower', $validCategories), true);

            if (! $categoryExists) {
                $this->error("❌ Category '{$category}' is not valid.");
                $this->line('');
                $this->line('Valid categories:');
                foreach ($validCategories as $validCategory) {
                    $this->line("  - {$validCategory}");
                }

                return false;
            }

            // Check if category has any analyzers
            $analyzersInCategory = $manager->getByCategory($normalizedCategory);
            if ($analyzersInCategory->isEmpty()) {
                $this->warn("⚠️  No analyzers found for category '{$category}'.");

                return false;
            }
        }

        // Validate format option
        $format = $this->option('format');
        if ($format !== null) {
            if (! is_string($format)) {
                $this->error('❌ Invalid format provided.');

                return false;
            }

            $validFormats = ['console', 'json'];
            if (! in_array(strtolower($format), $validFormats, true)) {
                $this->error("❌ Format '{$format}' is not valid. Must be one of: ".implode(', ', $validFormats));

                return false;
            }
        }

        // Validate output option (if provided)
        $output = $this->option('output');
        if ($output !== null) {
            if (! is_string($output) || $output === '') {
                $this->error('❌ Invalid output path provided.');

                return false;
            }

            // Security: Prevent path traversal attacks
            // Normalize path separators
            $normalizedPath = str_replace('\\', '/', $output);

            // Check for path traversal sequences
            if (str_contains($normalizedPath, '../') ||
                str_contains($normalizedPath, '..\\') ||
                str_starts_with($normalizedPath, '/') ||
                str_starts_with($normalizedPath, '..')) {
                $this->error('❌ Output path cannot contain path traversal sequences (../) or absolute paths.');
                $this->line('   Paths must be relative to the application base directory.');

                return false;
            }

            // Security: Enforce JSON file extension
            $filename = basename($normalizedPath);
            $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

            if ($extension !== 'json') {
                $this->error('❌ Output file must have a .json extension.');
                $this->line("   Provided: {$filename}");
                $this->line('   Example: shieldci-report.json or reports/shieldci-report.json');

                return false;
            }

            // Security: Prevent overwriting critical dependency files
            $normalizedFilename = strtolower($filename);
            $protectedFiles = ['composer.json', 'package.json', 'package-lock.json'];

            if (in_array($normalizedFilename, $protectedFiles, true)) {
                $this->error("❌ Cannot write to protected file: {$filename}");
                $this->line('   This file is protected to prevent accidental overwrites.');
                $this->line('   Please use a different filename (e.g., "shieldci-report.json" or "reports/shieldci-report.json").');

                return false;
            }

            // Resolve the final path relative to base path
            $basePath = base_path();
            $resolvedPath = $basePath.'/'.ltrim($normalizedPath, '/');

            // Normalize the resolved path (removes redundant separators, etc.)
            $resolvedPath = str_replace(['\\', '/'], DIRECTORY_SEPARATOR, $resolvedPath);
            $resolvedPathNormalized = preg_replace('#'.preg_quote(DIRECTORY_SEPARATOR, '#').'{2,}#', DIRECTORY_SEPARATOR, $resolvedPath);

            // Ensure resolved path is a string
            if (! is_string($resolvedPathNormalized) || $resolvedPathNormalized === '') {
                $this->error('❌ Invalid output path after normalization.');

                return false;
            }

            $resolvedPath = $resolvedPathNormalized;

            // Use realpath to resolve symlinks and ensure we're within base path
            $realBasePath = realpath($basePath);
            if ($realBasePath === false) {
                $this->error("❌ Cannot resolve base path: {$basePath}");

                return false;
            }

            $resolvedDir = dirname($resolvedPath);
            $realResolvedPath = realpath($resolvedDir);
            if ($realResolvedPath === false) {
                // Directory doesn't exist yet, check if parent is within base path
                $parentPath = dirname($resolvedDir);
                $realParentPath = realpath($parentPath);

                if ($realParentPath === false) {
                    // Try to create the directory structure
                    if (! @mkdir($resolvedDir, 0755, true)) {
                        $this->error("❌ Cannot create output directory: {$resolvedDir}");

                        return false;
                    }
                    $realResolvedPath = realpath($resolvedDir);
                    if ($realResolvedPath === false) {
                        $this->error('❌ Cannot resolve output directory path.');

                        return false;
                    }
                } else {
                    $realResolvedPath = $realParentPath;
                }
            }

            // Security check: Ensure resolved path is within base path
            $realBasePathNormalized = str_replace('\\', '/', $realBasePath);
            $realResolvedPathNormalized = str_replace('\\', '/', $realResolvedPath);

            if (! str_starts_with($realResolvedPathNormalized, $realBasePathNormalized.'/') &&
                $realResolvedPathNormalized !== $realBasePathNormalized) {
                $this->error('❌ Output path is outside the application base directory.');
                $this->line("   Base path: {$realBasePathNormalized}");
                $this->line("   Resolved path: {$realResolvedPathNormalized}");

                return false;
            }

            // Check if directory is writable
            if (! is_writable($realResolvedPath)) {
                $this->error("❌ Output directory is not writable: {$realResolvedPath}");

                return false;
            }
        }

        return true;
    }
}
