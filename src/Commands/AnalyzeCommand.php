<?php

declare(strict_types=1);

namespace ShieldCI\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzerManager;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\Contracts\ReporterInterface;
use ShieldCI\Support\InlineSuppressionParser;
use ShieldCI\ValueObjects\AnalysisReport;

class AnalyzeCommand extends Command
{
    protected $signature = 'shield:analyze
                            {--analyzer= : Run specific analyzer(s). Comma-separated for multiple (e.g., sql-injection,xss-detection)}
                            {--category= : Run analyzers in category}
                            {--format=console : Output format (console|json)}
                            {--output= : Save report to file}
                            {--baseline : Compare against baseline and only report new issues}
                            {--report : Send report to ShieldCI platform}
                            {--triggered-by= : Override trigger source (manual|ci_cd|scheduled)}
                            {--git-branch= : Git branch name for report metadata}
                            {--git-commit= : Git commit SHA for report metadata}';

    protected $description = 'Run ShieldCI security and code quality analysis';

    private InlineSuppressionParser $suppressionParser;

    public function handle(
        AnalyzerManager $manager,
        ReporterInterface $reporter,
        \ShieldCI\Contracts\ClientInterface $client,
    ): int {
        $this->suppressionParser = new InlineSuppressionParser;
        // Validate options
        if (! $this->validateOptions($manager)) {
            return self::FAILURE;
        }

        // Resolve trigger source
        $triggeredBy = $this->resolveTriggerSource();

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

        // Check if enabled
        if (! config('shieldci.enabled')) {
            $this->warn('ShieldCI is disabled in configuration.');

            return self::SUCCESS;
        }

        // Determine if we should use streaming output (console format only)
        $format = $this->option('format') ?: config('shieldci.report.format', 'console');
        $useStreaming = $format === 'console';

        // Validate ignore_errors config early (before analysis starts)
        $this->validateIgnoreErrorsConfig($manager);

        // Check if any categories are enabled
        $analyzersConfig = config('shieldci.analyzers', []);
        $analyzersConfig = is_array($analyzersConfig) ? $analyzersConfig : [];

        if (! empty($analyzersConfig)) {
            $enabledCategories = [];
            foreach ($analyzersConfig as $category => $config) {
                if (is_array($config) && ($config['enabled'] ?? true) === true) {
                    $enabledCategories[] = $category;
                }
            }

            if (empty($enabledCategories)) {
                $this->error('❌ All analyzer categories are disabled in configuration.');
                $this->line('');
                $this->line('To enable categories, set their "enabled" flag to true in config/shieldci.php');
                $this->line('or set the corresponding environment variables (e.g., SHIELDCI_SECURITY_ANALYZERS=true).');

                return self::FAILURE;
            }
        }

        // Run analysis (with optional streaming)
        $results = $useStreaming
            ? $this->runAnalysisWithStreaming($manager, $reporter)
            : $this->runAnalysis($manager);

        if ($results->isEmpty()) {
            $this->error('No analyzers were run.');

            return self::FAILURE;
        }

        // Build git context from CLI flags
        $gitContext = $this->buildGitContext();

        // Generate report
        $report = $reporter->generate($results, $triggeredBy, $gitContext);

        // Filter against ignore_errors config (already applied in streaming, but needed for non-streaming)
        $report = $this->filterAgainstIgnoreErrors($report);

        // Filter against inline @shieldci-ignore comments (already applied in streaming, but needed for non-streaming)
        $report = $this->filterAgainstInlineSuppressions($report);

        // Filter against baseline if requested
        if ($this->option('baseline')) {
            $report = $this->filterAgainstBaseline($report);
        }

        // Output report (skip if already streamed)
        if (! $useStreaming) {
            $this->outputReport($report, $reporter);
        } else {
            // For streaming mode, just output the report card
            $this->newLine();
            $this->line($this->color('Report Card', 'bright_yellow'));
            $this->line($this->color('===========', 'bright_yellow'));
            $this->newLine();
            $this->outputReportCard($report);
            $this->newLine();
        }

        // Save to file if requested (CLI option or config default)
        $output = $this->option('output');
        if (! $output) {
            $configOutput = config('shieldci.report.output_file');
            $output = is_string($configOutput) ? $configOutput : null;
        }

        if ($output && is_string($output)) {
            $this->saveReport($report, $reporter, $output);
        }

        // Send to API if configured
        if ($this->shouldSendToApi()) {
            $this->sendToApi($client, $reporter, $report);
        }

        // Determine exit code
        return $this->determineExitCode($report);
    }

    /**
     * Run analysis with streaming output (results displayed as they complete).
     */
    protected function runAnalysisWithStreaming(AnalyzerManager $manager, ReporterInterface $reporter): Collection
    {
        // Output header
        $this->line($reporter->streamHeader());

        $results = collect();
        $category = $this->option('category');
        $analyzerOption = $this->option('analyzer');

        if ($analyzerOption) {
            // Support comma-separated analyzer IDs
            $analyzerIds = array_map('trim', explode(',', $analyzerOption));
            $analyzerIds = array_filter($analyzerIds, fn (string $id) => $id !== '');

            $displayName = $this->resolveAnalyzerDisplayName($manager, $analyzerIds);
            $label = count($analyzerIds) === 1 ? 'Running analyzer' : 'Running analyzers';
            $this->line("{$label}: {$displayName}");
            $this->newLine();

            $current = 0;
            $total = count($analyzerIds);

            foreach ($analyzerIds as $analyzerId) {
                $analyzer = $manager->getAnalyzers()->first(fn ($a) => $a->getId() === $analyzerId);
                if ($analyzer === null) {
                    continue;
                }

                $current++;

                // Run analyzer
                $result = $analyzer->analyze();
                $metadata = $analyzer->getMetadata();

                // Enrich result with metadata
                $enrichedResult = new \ShieldCI\AnalyzersCore\Results\AnalysisResult(
                    analyzerId: $result->getAnalyzerId(),
                    status: $result->getStatus(),
                    message: $result->getMessage(),
                    issues: $result->getIssues(),
                    executionTime: $result->getExecutionTime(),
                    metadata: [
                        'id' => $metadata->id,
                        'name' => $metadata->name,
                        'description' => $metadata->description,
                        'category' => $metadata->category,
                        'severity' => $metadata->severity,
                        'docsUrl' => $metadata->docsUrl,
                        'timeToFix' => $metadata->timeToFix,
                    ],
                );

                // Apply ignore_errors and inline suppression filtering before streaming
                $filteredResult = $this->filterSingleResultAgainstIgnoreErrors($enrichedResult);
                $filteredResult = $this->filterSingleResultAgainstInlineSuppressions($filteredResult);

                $results->push($filteredResult);

                // Stream output immediately
                $categoryLabel = $metadata->category->label();
                $this->line($reporter->streamResult($filteredResult, $current, $total, $categoryLabel));
            }

            return $results;
        }

        // Get analyzers (by category or all)
        $normalizedCategory = null;
        if ($category) {
            $normalizedCategory = strtolower($category);
            $analyzers = $manager->getByCategory($normalizedCategory);
        } else {
            $analyzers = $manager->getAnalyzers();
        }

        $enabledCount = $analyzers->count();

        // Calculate skipped count
        $skippedCount = 0;
        if ($normalizedCategory) {
            $skippedCount = $manager->getSkippedAnalyzers()
                ->filter(function (\ShieldCI\AnalyzersCore\Contracts\ResultInterface $result) use ($normalizedCategory): bool {
                    $metadata = $result->getMetadata();
                    $resultCategory = $metadata['category'] ?? 'Unknown';
                    if (is_object($resultCategory) && isset($resultCategory->value)) {
                        $resultCategory = $resultCategory->value;
                    }

                    return is_string($resultCategory) && strtolower($resultCategory) === $normalizedCategory;
                })
                ->count();
        } else {
            // Get enabled categories to filter skipped analyzers
            $analyzersConfig = config('shieldci.analyzers', []);
            $analyzersConfig = is_array($analyzersConfig) ? $analyzersConfig : [];
            $enabledCategories = [];
            foreach ($analyzersConfig as $cat => $config) {
                if (is_array($config) && ($config['enabled'] ?? true) === true) {
                    $enabledCategories[] = $cat;
                }
            }

            $allSkipped = $manager->getSkippedAnalyzers();
            if (! empty($enabledCategories)) {
                $skippedCount = $allSkipped
                    ->filter(function (\ShieldCI\AnalyzersCore\Contracts\ResultInterface $result) use ($enabledCategories): bool {
                        $metadata = $result->getMetadata();
                        $resultCategory = $metadata['category'] ?? 'Unknown';
                        if (is_object($resultCategory) && isset($resultCategory->value)) {
                            $resultCategory = $resultCategory->value;
                        }

                        return is_string($resultCategory) && in_array($resultCategory, $enabledCategories, true);
                    })
                    ->count();
            } else {
                $skippedCount = $allSkipped->count();
            }
        }

        $totalCount = $enabledCount + $skippedCount;

        if ($skippedCount > 0) {
            $this->line("Running {$enabledCount} of {$totalCount} analyzers ({$skippedCount} skipped)...");
        } else {
            $this->line("Running all {$enabledCount} analyzers...");
        }
        $this->newLine(2);

        // Group analyzers by category for organized output
        $byCategory = [];
        foreach ($analyzers as $analyzer) {
            $metadata = $analyzer->getMetadata();
            $cat = $metadata->category->value;
            if (! isset($byCategory[$cat])) {
                $byCategory[$cat] = [];
            }
            $byCategory[$cat][] = $analyzer;
        }

        $current = 0;
        $total = $totalCount;

        // Run analyzers by category
        foreach ($byCategory as $cat => $categoryAnalyzers) {
            $categoryLabel = Category::from($cat)->label();

            // Output category header
            $this->line($reporter->streamCategoryHeader($categoryLabel));

            foreach ($categoryAnalyzers as $analyzer) {
                $current++;

                // Run analyzer
                $result = $analyzer->analyze();
                $metadata = $analyzer->getMetadata();

                // Enrich result with metadata
                $enrichedResult = new \ShieldCI\AnalyzersCore\Results\AnalysisResult(
                    analyzerId: $result->getAnalyzerId(),
                    status: $result->getStatus(),
                    message: $result->getMessage(),
                    issues: $result->getIssues(),
                    executionTime: $result->getExecutionTime(),
                    metadata: [
                        'id' => $metadata->id,
                        'name' => $metadata->name,
                        'description' => $metadata->description,
                        'category' => $metadata->category,
                        'severity' => $metadata->severity,
                        'docsUrl' => $metadata->docsUrl,
                        'timeToFix' => $metadata->timeToFix,
                    ],
                );

                // Apply ignore_errors and inline suppression filtering before streaming
                $filteredResult = $this->filterSingleResultAgainstIgnoreErrors($enrichedResult);
                $filteredResult = $this->filterSingleResultAgainstInlineSuppressions($filteredResult);

                $results->push($filteredResult);

                // Stream output immediately
                $this->line($reporter->streamResult($filteredResult, $current, $total, $categoryLabel));
            }
        }

        // Add skipped analyzers to results and stream them
        if ($normalizedCategory) {
            $skippedResults = $manager->getSkippedAnalyzers()
                ->filter(function (\ShieldCI\AnalyzersCore\Contracts\ResultInterface $result) use ($normalizedCategory): bool {
                    $metadata = $result->getMetadata();
                    $resultCategory = $metadata['category'] ?? 'Unknown';
                    if (is_object($resultCategory) && isset($resultCategory->value)) {
                        $resultCategory = $resultCategory->value;
                    }

                    return is_string($resultCategory) && strtolower($resultCategory) === $normalizedCategory;
                });
        } else {
            $skippedResults = $manager->getSkippedAnalyzers();
        }

        // Stream skipped analyzers
        foreach ($skippedResults as $skippedResult) {
            $current++;
            $metadata = $skippedResult->getMetadata();

            // Get category label
            $resultCategory = $metadata['category'] ?? 'Unknown';
            if (is_object($resultCategory) && isset($resultCategory->value)) {
                $categoryLabel = Category::from($resultCategory->value)->label();
            } else {
                $categoryLabel = 'Unknown';
            }

            // Stream output immediately
            $this->line($reporter->streamResult($skippedResult, $current, $total, $categoryLabel));
        }

        // Merge results
        $allResults = collect(array_merge($results->all(), $skippedResults->all()));

        return $allResults;
    }

    protected function runAnalysis(AnalyzerManager $manager): Collection
    {
        if ($analyzerOption = $this->option('analyzer')) {
            // Support comma-separated analyzer IDs
            $analyzerIds = array_map('trim', explode(',', $analyzerOption));
            $analyzerIds = array_filter($analyzerIds, fn (string $id) => $id !== '');

            $displayName = $this->resolveAnalyzerDisplayName($manager, $analyzerIds);
            $label = count($analyzerIds) === 1 ? 'Running analyzer' : 'Running analyzers';
            $this->line("{$label}: {$displayName}");

            $results = [];
            foreach ($analyzerIds as $analyzerId) {
                $result = $manager->run($analyzerId);
                if ($result !== null) {
                    $results[] = $result;
                }
            }

            return collect($results);
        }

        // Get category option (if specified)
        $category = $this->option('category');
        $normalizedCategory = null;

        if ($category) {
            $normalizedCategory = strtolower($category);
            $categoryLabel = Category::from($normalizedCategory)->label();

            $analyzers = $manager->getByCategory($normalizedCategory);
            $enabledCount = $analyzers->count();
            // Get actual skipped count (may differ from calculated due to instantiation failures)
            $skippedCount = $manager->getSkippedAnalyzers()
                ->filter(function (ResultInterface $result) use ($normalizedCategory): bool {
                    $metadata = $result->getMetadata();
                    $resultCategory = $metadata['category'] ?? 'Unknown';
                    if (is_object($resultCategory) && isset($resultCategory->value)) {
                        $resultCategory = $resultCategory->value;
                    }

                    return is_string($resultCategory) && strtolower($resultCategory) === $normalizedCategory;
                })
                ->count();
            // Total count for this specific category (enabled + skipped)
            $totalCount = $enabledCount + $skippedCount;

            if ($skippedCount > 0) {
                $this->line("Running {$categoryLabel} analyzers... ({$enabledCount} running, {$skippedCount} skipped, {$totalCount} total)");
            } else {
                $this->line("Running {$categoryLabel} analyzers... ({$enabledCount}/{$totalCount})");
            }
        } else {
            $analyzers = $manager->getAnalyzers();
            $enabledCount = $analyzers->count();

            // Get enabled categories to filter skipped analyzers
            $analyzersConfig = config('shieldci.analyzers', []);
            $analyzersConfig = is_array($analyzersConfig) ? $analyzersConfig : [];
            $enabledCategories = [];
            foreach ($analyzersConfig as $category => $config) {
                if (is_array($config) && ($config['enabled'] ?? true) === true) {
                    $enabledCategories[] = $category;
                }
            }

            // Get skipped analyzers only from enabled categories
            $allSkipped = $manager->getSkippedAnalyzers();
            $skippedCount = 0;
            if (! empty($enabledCategories)) {
                $skippedCount = $allSkipped
                    ->filter(function (ResultInterface $result) use ($enabledCategories): bool {
                        $metadata = $result->getMetadata();
                        $resultCategory = $metadata['category'] ?? 'Unknown';
                        if (is_object($resultCategory) && isset($resultCategory->value)) {
                            $resultCategory = $resultCategory->value;
                        }

                        return is_string($resultCategory) && in_array($resultCategory, $enabledCategories, true);
                    })
                    ->count();
            } else {
                // If no categories are configured, count all skipped
                $skippedCount = $allSkipped->count();
            }

            // Total count for enabled categories only (enabled + skipped from enabled categories)
            $totalCount = $enabledCount + $skippedCount;

            if ($skippedCount > 0) {
                $this->line("Running {$enabledCount} of {$totalCount} analyzers ({$skippedCount} skipped)...");
            } else {
                $this->line("Running all {$enabledCount} analyzers...");
            }
        }

        // Run analyzers and collect results
        $results = $analyzers->map(function ($analyzer) {
            $result = $analyzer->analyze();
            $metadata = $analyzer->getMetadata();

            // Enrich result with analyzer metadata (same as runAll)
            return new \ShieldCI\AnalyzersCore\Results\AnalysisResult(
                analyzerId: $result->getAnalyzerId(),
                status: $result->getStatus(),
                message: $result->getMessage(),
                issues: $result->getIssues(),
                executionTime: $result->getExecutionTime(),
                metadata: [
                    'id' => $metadata->id,
                    'name' => $metadata->name,
                    'description' => $metadata->description,
                    'category' => $metadata->category,
                    'severity' => $metadata->severity,
                    'docsUrl' => $metadata->docsUrl,
                ],
            );
        });

        // Add skipped analyzers
        if ($normalizedCategory) {
            // Add skipped analyzers for the specified category only
            $skippedResults = $manager->getSkippedAnalyzers()
                ->filter(function (ResultInterface $result) use ($normalizedCategory): bool {
                    $metadata = $result->getMetadata();
                    $resultCategory = $metadata['category'] ?? 'Unknown';
                    if (is_object($resultCategory) && isset($resultCategory->value)) {
                        $resultCategory = $resultCategory->value;
                    }

                    return is_string($resultCategory) && strtolower($resultCategory) === $normalizedCategory;
                });
        } else {
            // Add all skipped analyzers when running all
            $skippedResults = $manager->getSkippedAnalyzers();
        }

        // Convert both to arrays and merge, then convert back to collection (same approach as runAll)
        /** @var Collection<int, ResultInterface> $allResults */
        $allResults = collect(array_merge($results->all(), $skippedResults->all()));
        $results = $allResults;

        $this->newLine(2);

        return $results;
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

    /**
     * Output just the report card (used in streaming mode).
     */
    protected function outputReportCard(AnalysisReport $report): void
    {
        // Group results by category
        $byCategory = [];
        foreach ($report->results as $result) {
            $metadata = $result->getMetadata();
            $category = $metadata['category'] ?? 'Unknown';

            // Extract category value
            $categoryValue = null;
            if (is_object($category) && isset($category->value)) {
                $categoryValue = $category->value;
            } elseif (is_string($category)) {
                $categoryValue = $category;
            }

            // Use Category enum label for human-readable name
            if ($categoryValue !== null) {
                try {
                    $category = Category::from($categoryValue)->label();
                } catch (\ValueError $e) {
                    $category = ucfirst(str_replace('_', ' ', $categoryValue));
                }
            } else {
                $category = 'Unknown';
            }

            if (! isset($byCategory[$category])) {
                $byCategory[$category] = [];
            }

            $byCategory[$category][] = $result;
        }

        // Filter out categories that only have skipped analyzers
        $filteredCategories = [];
        foreach ($byCategory as $category => $results) {
            $hasNonSkipped = false;
            foreach ($results as $result) {
                if ($result->getStatus()->value !== 'skipped') {
                    $hasNonSkipped = true;
                    break;
                }
            }
            if ($hasNonSkipped) {
                $filteredCategories[$category] = $results;
            }
        }

        if (empty($filteredCategories)) {
            $filteredCategories = $byCategory;
        }

        // Calculate stats per category
        $stats = [];
        foreach ($filteredCategories as $category => $results) {
            $stats[$category] = [
                'passed' => 0,
                'failed' => 0,
                'warning' => 0,
                'skipped' => 0,
                'error' => 0,
                'total' => count($results),
            ];

            foreach ($results as $result) {
                $status = $result->getStatus()->value;
                if ($status === 'skipped') {
                    $stats[$category]['skipped']++;
                } else {
                    $stats[$category][$status]++;
                }
            }
        }

        // Calculate total
        $totalAll = 0;
        foreach ($filteredCategories as $results) {
            $totalAll += count($results);
        }

        $categories = array_keys($filteredCategories);
        $table = [];

        // Header
        $table[] = '+----------------+'.str_repeat('----------------+', count($categories)).'------------+';

        // Build header row with green color
        $statusCell = $this->color(str_pad(' Status', 16), 'bright_green');
        $categoryCells = array_map(fn ($c) => $this->color(str_pad(' '.$c, 16), 'bright_green'), $categories);
        $totalCell = $this->color(str_pad('     Total', 12), 'bright_green');

        $table[] = '|'.$statusCell.'|'.implode('|', $categoryCells).'|'.$totalCell.'|';
        $table[] = '+----------------+'.str_repeat('----------------+', count($categories)).'------------+';

        // Passed row with green color
        $passedRow = '| '.$this->color('Passed        ', 'green').' |';
        $totalPassed = 0;
        foreach ($categories as $category) {
            $passed = $stats[$category]['passed'];
            $total = $stats[$category]['total'];
            $pct = $total > 0 ? round(($passed / $total) * 100) : 0;
            $passedRow .= str_pad("   {$passed}  ({$pct}%)", 16).'|';
            $totalPassed += $passed;
        }
        $totalPct = $totalAll > 0 ? round(($totalPassed / $totalAll) * 100) : 0;
        $passedRow .= str_pad(" {$totalPassed}  ({$totalPct}%)", 12).'|';
        $table[] = $passedRow;

        // Failed row with red color
        $failedRow = '| '.$this->color('Failed        ', 'red').' |';
        $totalFailed = 0;
        foreach ($categories as $category) {
            $failed = $stats[$category]['failed'];
            $total = $stats[$category]['total'];
            $pct = $total > 0 ? round(($failed / $total) * 100) : 0;
            $failedRow .= str_pad("    {$failed}   ({$pct}%)", 16).'|';
            $totalFailed += $failed;
        }
        $totalPct = $totalAll > 0 ? round(($totalFailed / $totalAll) * 100) : 0;
        $failedRow .= str_pad("  {$totalFailed}  ({$totalPct}%)", 12).'|';
        $table[] = $failedRow;

        // Warning row with yellow color
        $warningRow = '| '.$this->color('Warning       ', 'yellow').' |';
        $totalWarnings = 0;
        foreach ($categories as $category) {
            $warnings = $stats[$category]['warning'];
            $total = $stats[$category]['total'];
            $pct = $total > 0 ? round(($warnings / $total) * 100) : 0;
            $warningRow .= str_pad("    {$warnings}   ({$pct}%)", 16).'|';
            $totalWarnings += $warnings;
        }
        $totalPct = $totalAll > 0 ? round(($totalWarnings / $totalAll) * 100) : 0;
        $warningRow .= str_pad("  {$totalWarnings}  ({$totalPct}%)", 12).'|';
        $table[] = $warningRow;

        // Not Applicable row with gray color
        $skippedRow = '| '.$this->color('Not Applicable', 'gray').' |';
        $totalSkipped = 0;
        foreach ($categories as $category) {
            $skipped = $stats[$category]['skipped'];
            $total = $stats[$category]['total'];
            $pct = $total > 0 ? round(($skipped / $total) * 100) : 0;
            $skippedRow .= str_pad("    {$skipped}   ({$pct}%)", 16).'|';
            $totalSkipped += $skipped;
        }
        $totalPct = $totalAll > 0 ? round(($totalSkipped / $totalAll) * 100) : 0;
        $skippedRow .= str_pad("  {$totalSkipped}   ({$totalPct}%)", 12).'|';
        $table[] = $skippedRow;

        // Error row with bright red color
        $errorRow = '| '.$this->color('Error         ', 'bright_red').' |';
        $totalErrors = 0;
        foreach ($categories as $category) {
            $errors = $stats[$category]['error'];
            $total = $stats[$category]['total'];
            $pct = $total > 0 ? round(($errors / $total) * 100) : 0;
            $errorRow .= str_pad("    {$errors}   ({$pct}%)", 16).'|';
            $totalErrors += $errors;
        }
        $totalPct = $totalAll > 0 ? round(($totalErrors / $totalAll) * 100) : 0;
        $errorRow .= str_pad("  {$totalErrors}   ({$totalPct}%)", 12).'|';
        $table[] = $errorRow;

        // Footer
        $table[] = '+----------------+'.str_repeat('----------------+', count($categories)).'------------+';

        $this->line(implode(PHP_EOL, $table));
    }

    /**
     * Apply ANSI color to text.
     */
    protected function color(string $text, string $color): string
    {
        $colors = [
            'bright_yellow' => '1;33',
            'green' => '0;32',
            'bright_green' => '1;32',
            'red' => '0;31',
            'bright_red' => '1;31',
            'yellow' => '0;33',
            'gray' => '0;37',
            'dim' => '2',
        ];

        if (! isset($colors[$color])) {
            return $text;
        }

        $code = $colors[$color];

        return "\033[{$code}m{$text}\033[0m";
    }

    protected function saveReport(AnalysisReport $report, ReporterInterface $reporter, string $path): void
    {
        $content = $this->option('format') === 'json'
            ? $reporter->toJson($report)
            : $reporter->toConsole($report);

        file_put_contents($path, $content);

        $this->info("Report saved to: {$path}");
    }

    /**
     * Check if the report should be sent to the ShieldCI API.
     */
    protected function shouldSendToApi(): bool
    {
        if ($this->option('report')) {
            return true;
        }

        return (bool) config('shieldci.report.send_to_api', false);
    }

    /**
     * Send the analysis report to the ShieldCI platform API.
     */
    protected function sendToApi(\ShieldCI\Contracts\ClientInterface $client, ReporterInterface $reporter, AnalysisReport $report): void
    {
        $this->info('Sending report to ShieldCI platform...');

        try {
            $payload = $reporter->toApi($report);
            $response = $client->sendReport($payload);

            if (isset($response['success']) && $response['success'] === true) {
                $this->info('Report sent successfully.');
            } else {
                $message = isset($response['message']) && is_string($response['message'])
                    ? $response['message']
                    : 'Unknown error';
                $this->warn("Failed to send report: {$message}");
            }
        } catch (\Exception $e) {
            $this->warn("Failed to send report to API: {$e->getMessage()}");
        }
    }

    protected function determineExitCode(AnalysisReport $report): int
    {
        $failOn = config('shieldci.fail_on', 'high');

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
                $baselineContent = FileParser::readFile($baselineFile);
                $baseline = $baselineContent !== null ? json_decode($baselineContent, true) : null;
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

        // Check severity levels based on fail_on configuration
        $shouldFail = $criticalResults->some(function ($result) use ($failOn) {
            $issues = $result->getIssues();
            foreach ($issues as $issue) {
                $severity = $issue->severity->value;

                // Fail based on configured threshold
                switch ($failOn) {
                    case 'low':
                        // Fail on any severity (low, medium, high, critical)
                        return true;
                    case 'medium':
                        // Fail on medium, high, or critical
                        if (in_array($severity, ['medium', 'high', 'critical'], true)) {
                            return true;
                        }
                        break;
                    case 'high':
                        // Fail on high or critical
                        if (in_array($severity, ['high', 'critical'], true)) {
                            return true;
                        }
                        break;
                    case 'critical':
                        // Fail only on critical
                        if ($severity === 'critical') {
                            return true;
                        }
                        break;
                }
            }

            return false;
        });

        // Also check warnings if fail_on includes lower severities
        if (in_array($failOn, ['low', 'medium'], true)) {
            $warningResults = $report->warnings()->filter(function ($result) use ($dontReport) {
                return ! in_array($result->getAnalyzerId(), $dontReport, true);
            });

            $shouldFailOnWarnings = $warningResults->some(function ($result) use ($failOn) {
                $issues = $result->getIssues();
                foreach ($issues as $issue) {
                    $severity = $issue->severity->value;

                    if ($failOn === 'low') {
                        // Fail on any severity (including low in warnings)
                        return true;
                    }
                    if ($failOn === 'medium' && $severity === 'medium') {
                        // Fail on medium severity in warnings
                        return true;
                    }
                }

                return false;
            });

            if ($shouldFailOnWarnings) {
                return self::FAILURE;
            }
        }

        if ($shouldFail) {
            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    /**
     * Validate ignore_errors configuration.
     */
    protected function validateIgnoreErrorsConfig(AnalyzerManager $manager): void
    {
        $configIgnoreErrors = config('shieldci.ignore_errors', []);

        if (! is_array($configIgnoreErrors) || empty($configIgnoreErrors)) {
            return;
        }

        $warnings = [];

        // Get all registered analyzer IDs
        $allAnalyzers = $manager->getAnalyzers();
        $allAnalyzerIds = [];
        foreach ($allAnalyzers as $analyzer) {
            $metadata = $analyzer->getMetadata();
            $allAnalyzerIds[] = $metadata->id;
        }

        foreach ($configIgnoreErrors as $analyzerId => $rules) {
            // Check if analyzer exists
            if (! in_array($analyzerId, $allAnalyzerIds, true)) {
                $warnings[] = "Unknown analyzer ID in ignore_errors: '{$analyzerId}'";
            }

            if (! is_array($rules)) {
                $warnings[] = "Invalid rules for analyzer '{$analyzerId}': expected array";

                continue;
            }

            // Warn if rules array is empty (has no effect)
            if (empty($rules)) {
                $warnings[] = "Empty rules array for analyzer '{$analyzerId}': specify at least one rule or remove this entry";

                continue;
            }

            foreach ($rules as $index => $rule) {
                if (! is_array($rule)) {
                    $warnings[] = "Invalid rule #{$index} for analyzer '{$analyzerId}': expected array";

                    continue;
                }

                // Validate rule structure
                $validKeys = ['path', 'path_pattern', 'message', 'message_pattern'];
                $ruleKeys = array_keys($rule);
                $invalidKeys = array_diff($ruleKeys, $validKeys);

                if (! empty($invalidKeys)) {
                    $warnings[] = "Invalid keys in rule #{$index} for analyzer '{$analyzerId}': ".implode(', ', $invalidKeys);
                }

                // Check if rule has at least one matching criterion
                if (empty($rule['path']) && empty($rule['path_pattern']) &&
                    empty($rule['message']) && empty($rule['message_pattern'])) {
                    $warnings[] = "Empty rule #{$index} for analyzer '{$analyzerId}': must specify at least one matching criterion";
                }

                // Validate that path and path_pattern are not both specified
                if (isset($rule['path']) && isset($rule['path_pattern'])) {
                    $warnings[] = "Conflicting keys in rule #{$index} for analyzer '{$analyzerId}': use either 'path' (exact match) or 'path_pattern' (glob), not both";
                }

                // Validate that message and message_pattern are not both specified
                if (isset($rule['message']) && isset($rule['message_pattern'])) {
                    $warnings[] = "Conflicting keys in rule #{$index} for analyzer '{$analyzerId}': use either 'message' (exact match) or 'message_pattern' (wildcard), not both";
                }

                // Validate glob patterns
                if (isset($rule['path_pattern']) && is_string($rule['path_pattern'])) {
                    $pattern = $rule['path_pattern'];

                    // Check for invalid double-star usage (e.g., '**test' instead of '**/test')
                    if (preg_match('/\*\*[^\/]/', $pattern) || preg_match('/[^\/]\*\*/', $pattern)) {
                        $warnings[] = "Invalid glob pattern in rule #{$index} for analyzer '{$analyzerId}': '**' must be used as '**/' or '/**' (e.g., 'src/**/test' or 'tests/**/*.php')";
                    }
                }
            }
        }

        // Display warnings
        if (! empty($warnings)) {
            $this->warn('⚠️  Configuration Warnings:');
            foreach ($warnings as $warning) {
                $this->line("   • {$warning}");
            }
            $this->newLine();
        }
    }

    /**
     * Filter a single result against ignore_errors config.
     * Used in streaming mode to filter results before displaying them.
     */
    protected function filterSingleResultAgainstIgnoreErrors(\ShieldCI\AnalyzersCore\Results\AnalysisResult $result): \ShieldCI\AnalyzersCore\Results\AnalysisResult
    {
        $configIgnoreErrors = config('shieldci.ignore_errors', []);
        $configIgnoreErrors = is_array($configIgnoreErrors) ? $configIgnoreErrors : [];

        if (empty($configIgnoreErrors)) {
            return $result;
        }

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

        // Update message to reflect filtered count
        $message = $result->getMessage();
        if ($newIssues->isEmpty()) {
            $message = 'All issues are ignored via config';
        } elseif ($newIssues->count() !== count($currentIssues)) {
            // Some (but not all) issues were filtered - update the count in the message
            $originalCount = count($currentIssues);
            $filteredCount = $newIssues->count();

            // Update numeric counts in the message
            $updatedMessage = preg_replace('/\b'.$originalCount.'\b/', (string) $filteredCount, $message, 1);
            $message = is_string($updatedMessage) ? $updatedMessage : $message;

            // Fix singular/plural grammar
            if ($filteredCount === 1) {
                $message = preg_replace_callback('/\b(issues|errors|warnings|problems|vulnerabilities)\b/', function ($matches) {
                    $singular = [
                        'issues' => 'issue',
                        'errors' => 'error',
                        'warnings' => 'warning',
                        'problems' => 'problem',
                        'vulnerabilities' => 'vulnerability',
                    ];

                    return $singular[strtolower($matches[1])] ?? $matches[1];
                }, $message, 1) ?? $message;
            }
        }

        return new \ShieldCI\AnalyzersCore\Results\AnalysisResult(
            analyzerId: $result->getAnalyzerId(),
            status: $status,
            message: $message,
            issues: $newIssues->all(),
            executionTime: $result->getExecutionTime(),
            metadata: $result->getMetadata(),
        );
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

            // Update message to reflect filtered count
            $message = $result->getMessage();
            if ($newIssues->isEmpty()) {
                $message = 'All issues are ignored via config';
            } elseif ($newIssues->count() !== count($currentIssues)) {
                // Some (but not all) issues were filtered - update the count in the message
                $originalCount = count($currentIssues);
                $filteredCount = $newIssues->count();

                // Update numeric counts in the message
                $updatedMessage = preg_replace('/\b'.$originalCount.'\b/', (string) $filteredCount, $message, 1);
                $message = is_string($updatedMessage) ? $updatedMessage : $message;

                // Fix singular/plural grammar (e.g., "1 dependency stability issues" -> "1 dependency stability issue")
                if ($filteredCount === 1) {
                    $message = preg_replace_callback('/\b(issues|errors|warnings|problems|vulnerabilities)\b/', function ($matches) {
                        $singular = [
                            'issues' => 'issue',
                            'errors' => 'error',
                            'warnings' => 'warning',
                            'problems' => 'problem',
                            'vulnerabilities' => 'vulnerability',
                        ];

                        return $singular[strtolower($matches[1])] ?? $matches[1];
                    }, $message, 1) ?? $message;
                }
            }

            return new \ShieldCI\AnalyzersCore\Results\AnalysisResult(
                analyzerId: $result->getAnalyzerId(),
                status: $status,
                message: $message,
                issues: $newIssues->all(),
                executionTime: $result->getExecutionTime(),
                metadata: $result->getMetadata(),
            );
        });

        // Return new report with filtered results
        return new AnalysisReport(
            projectId: $report->projectId,
            laravelVersion: $report->laravelVersion,
            packageVersion: $report->packageVersion,
            results: $filteredResults,
            totalExecutionTime: $report->totalExecutionTime,
            analyzedAt: $report->analyzedAt,
            triggeredBy: $report->triggeredBy,
            metadata: $report->metadata,
        );
    }

    /**
     * Filter a single result against inline @shieldci-ignore comments.
     * Used in streaming mode to filter results before displaying them.
     */
    protected function filterSingleResultAgainstInlineSuppressions(\ShieldCI\AnalyzersCore\Results\AnalysisResult $result): \ShieldCI\AnalyzersCore\Results\AnalysisResult
    {
        $currentIssues = $result->getIssues();

        if ($currentIssues === []) {
            return $result;
        }

        $analyzerId = $result->getAnalyzerId();

        $newIssues = array_filter($currentIssues, function ($issue) use ($analyzerId) {
            $location = $issue->location;

            if ($location === null || $location->line === null || $location->line < 1) {
                return true; // Keep issues without a location — can't suppress inline
            }

            return ! $this->suppressionParser->isLineSuppressed($location->file, $location->line, $analyzerId);
        });

        if (count($newIssues) === count($currentIssues)) {
            return $result; // Nothing was suppressed
        }

        $status = $newIssues === []
            ? \ShieldCI\AnalyzersCore\Enums\Status::Passed
            : $result->getStatus();

        $message = $this->adjustFilteredMessage($result->getMessage(), count($currentIssues), count($newIssues));

        return new \ShieldCI\AnalyzersCore\Results\AnalysisResult(
            analyzerId: $result->getAnalyzerId(),
            status: $status,
            message: $message,
            issues: array_values($newIssues),
            executionTime: $result->getExecutionTime(),
            metadata: $result->getMetadata(),
        );
    }

    /**
     * Filter report against inline @shieldci-ignore comments in source files.
     */
    protected function filterAgainstInlineSuppressions(AnalysisReport $report): AnalysisReport
    {
        $filteredResults = $report->results->map(function (ResultInterface $result) {
            if (! $result instanceof \ShieldCI\AnalyzersCore\Results\AnalysisResult) {
                return $result;
            }

            return $this->filterSingleResultAgainstInlineSuppressions($result);
        });

        return new AnalysisReport(
            projectId: $report->projectId,
            laravelVersion: $report->laravelVersion,
            packageVersion: $report->packageVersion,
            results: $filteredResults,
            totalExecutionTime: $report->totalExecutionTime,
            analyzedAt: $report->analyzedAt,
            triggeredBy: $report->triggeredBy,
            metadata: $report->metadata,
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

        $baselineContent = FileParser::readFile($baselineFile);
        $baselineRaw = $baselineContent !== null ? json_decode($baselineContent, true) : null;
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

            // Update message to reflect filtered count
            $message = $result->getMessage();
            if ($newIssues->isEmpty()) {
                $message = 'All issues are in baseline';
            } elseif ($newIssues->count() !== count($currentIssues)) {
                // Some (but not all) issues were filtered - update the count in the message
                $originalCount = count($currentIssues);
                $filteredCount = $newIssues->count();

                // Update numeric counts in the message
                $updatedMessage = preg_replace('/\b'.$originalCount.'\b/', (string) $filteredCount, $message, 1);
                $message = is_string($updatedMessage) ? $updatedMessage : $message;

                // Fix singular/plural grammar (e.g., "1 dependency stability issues" -> "1 dependency stability issue")
                if ($filteredCount === 1) {
                    $message = preg_replace_callback('/\b(issues|errors|warnings|problems|vulnerabilities)\b/', function ($matches) {
                        $singular = [
                            'issues' => 'issue',
                            'errors' => 'error',
                            'warnings' => 'warning',
                            'problems' => 'problem',
                            'vulnerabilities' => 'vulnerability',
                        ];

                        return $singular[strtolower($matches[1])] ?? $matches[1];
                    }, $message, 1) ?? $message;
                }
            }

            return new \ShieldCI\AnalyzersCore\Results\AnalysisResult(
                analyzerId: $result->getAnalyzerId(),
                status: $status,
                message: $message,
                issues: $newIssues->all(),
                executionTime: $result->getExecutionTime(),
                metadata: $result->getMetadata(),
            );
        });

        // Return new report with filtered results
        return new AnalysisReport(
            projectId: $report->projectId,
            laravelVersion: $report->laravelVersion,
            packageVersion: $report->packageVersion,
            results: $filteredResults,
            totalExecutionTime: $report->totalExecutionTime,
            analyzedAt: $report->analyzedAt,
            triggeredBy: $report->triggeredBy,
            metadata: $report->metadata,
        );
    }

    /**
     * Check if an issue matches an ignore_errors config entry.
     *
     * Matching logic:
     * - If rule specifies 'path': exact path match required
     * - If rule specifies 'path_pattern': glob pattern match required
     * - If rule specifies 'message': exact message match required
     * - If rule specifies 'message_pattern': wildcard pattern match required
     *   (also matches against recommendation field for analyzers like PHPStan)
     * - If rule specifies only path criteria: matches ANY message
     * - If rule specifies only message criteria: matches ANY path
     * - If rule specifies both: BOTH must match
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

            // Skip empty rules - they should not match anything
            $hasAtLeastOneCriterion = isset($ignoreError['path']) ||
                                     isset($ignoreError['path_pattern']) ||
                                     isset($ignoreError['message']) ||
                                     isset($ignoreError['message_pattern']);

            if (! $hasAtLeastOneCriterion) {
                continue; // Empty rule, skip it
            }

            // Default to true - if a criterion is not specified, it matches everything
            // This allows rules like { "path": "foo.php" } to match any message in that file
            $pathMatches = true;
            $messageMatches = true;

            // Check path (exact match only)
            if (isset($ignoreError['path']) && is_string($ignoreError['path'])) {
                $ignorePath = $ignoreError['path'];
                $normalizedIssuePath = str_replace('\\', '/', $issuePath);
                $normalizedIgnorePath = str_replace('\\', '/', $ignorePath);

                // Exact match only (normalized for cross-platform compatibility)
                $pathMatches = $ignorePath === $issuePath || $normalizedIgnorePath === $normalizedIssuePath;
            }

            // Check path_pattern (glob pattern match)
            if (isset($ignoreError['path_pattern']) && is_string($ignoreError['path_pattern'])) {
                $pattern = $ignoreError['path_pattern'];
                $normalizedIssuePath = str_replace('\\', '/', $issuePath);

                // Use fnmatch for glob patterns (cross-platform)
                $pathMatches = fnmatch($pattern, $issuePath) ||
                              fnmatch($pattern, $normalizedIssuePath) ||
                              \Illuminate\Support\Str::is($pattern, $issuePath);
            }

            // Check message (exact match only)
            if (isset($ignoreError['message']) && is_string($ignoreError['message'])) {
                $ignoreMessage = $ignoreError['message'];

                // Exact match only
                $messageMatches = $ignoreMessage === $issueMessage;
            }

            // Check message_pattern (wildcard pattern match)
            if (isset($ignoreError['message_pattern']) && is_string($ignoreError['message_pattern'])) {
                $pattern = $ignoreError['message_pattern'];

                // Use Laravel Str::is for wildcard matching
                // Match against both message AND recommendation (PHPStan errors include details in recommendation)
                $issueRecommendation = $issue->recommendation ?? '';
                $messageMatches = \Illuminate\Support\Str::is($pattern, $issueMessage) ||
                                 \Illuminate\Support\Str::is($pattern, $issueRecommendation);
            }

            // Both path and message criteria must match
            // (if a criterion is not specified, it defaults to true)
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
            'file' => $issue->location?->file ?? 'unknown',
            'line' => $issue->location?->line ?? 0,
            'message' => $issue->message,
        ];

        $json = json_encode($data);

        return hash('sha256', $json !== false ? $json : '');
    }

    /**
     * Adjust result message when issues have been filtered out.
     *
     * Updates count in the message and fixes singular/plural grammar.
     */
    private function adjustFilteredMessage(string $message, int $originalCount, int $filteredCount): string
    {
        if ($filteredCount === 0) {
            return 'All issues are suppressed via @shieldci-ignore';
        }

        if ($filteredCount === $originalCount) {
            return $message;
        }

        // Update numeric counts in the message
        $updatedMessage = preg_replace('/\b'.$originalCount.'\b/', (string) $filteredCount, $message, 1);
        $message = is_string($updatedMessage) ? $updatedMessage : $message;

        // Fix singular/plural grammar
        if ($filteredCount === 1) {
            $message = preg_replace_callback('/\b(issues|errors|warnings|problems|vulnerabilities)\b/', function ($matches) {
                $singular = [
                    'issues' => 'issue',
                    'errors' => 'error',
                    'warnings' => 'warning',
                    'problems' => 'problem',
                    'vulnerabilities' => 'vulnerability',
                ];

                return $singular[strtolower($matches[1])] ?? $matches[1];
            }, $message, 1) ?? $message;
        }

        return $message;
    }

    /**
     * Resolve analyzer IDs to a human-readable display string.
     *
     * Single: "SQL Injection Analyzer"
     * Multiple: "SQL Injection, XSS Vulnerabilities and PHPStan Static Analyzers"
     *
     * @param  array<int, string>  $analyzerIds
     */
    private function resolveAnalyzerDisplayName(AnalyzerManager $manager, array $analyzerIds): string
    {
        $names = array_map(function (string $id) use ($manager) {
            $analyzer = $manager->getAnalyzers()->first(fn ($a) => $a->getId() === $id);

            return $analyzer ? $analyzer->getMetadata()->name : $id;
        }, $analyzerIds);

        if (count($names) === 1) {
            return $names[0];
        }

        // Strip " Analyzer" suffix from each name, join naturally, append "Analyzers"
        $shortNames = array_map(
            fn (string $name) => str_ends_with($name, ' Analyzer') ? substr($name, 0, -9) : $name,
            $names
        );

        $last = array_pop($shortNames);

        return implode(', ', $shortNames).' and '.$last.' Analyzers';
    }

    /**
     * Validate command options.
     */
    protected function validateOptions(AnalyzerManager $manager): bool
    {
        // Validate analyzer option
        $analyzerOption = $this->option('analyzer');
        if ($analyzerOption !== null) {
            if (! is_string($analyzerOption) || $analyzerOption === '') {
                $this->error('❌ Invalid analyzer ID provided.');

                return false;
            }

            // Support comma-separated analyzer IDs
            $analyzerIds = array_map('trim', explode(',', $analyzerOption));
            $analyzerIds = array_filter($analyzerIds, fn (string $id) => $id !== '');

            if (empty($analyzerIds)) {
                $this->error('❌ No valid analyzer IDs provided.');

                return false;
            }

            // Check if all analyzers exist
            $allAnalyzers = $manager->getAnalyzers();
            $allAnalyzerIds = $allAnalyzers->map(fn ($analyzer) => $analyzer->getId())->toArray();

            $invalidIds = [];
            foreach ($analyzerIds as $analyzerId) {
                if (! in_array($analyzerId, $allAnalyzerIds, true)) {
                    $invalidIds[] = $analyzerId;
                }
            }

            if (! empty($invalidIds)) {
                $invalidList = implode(', ', $invalidIds);
                $this->error("❌ Analyzer(s) not found: {$invalidList}");
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

            // Check if category is enabled in config
            $analyzersConfig = config('shieldci.analyzers', []);
            $analyzersConfig = is_array($analyzersConfig) ? $analyzersConfig : [];

            if (isset($analyzersConfig[$normalizedCategory])) {
                $categoryConfig = $analyzersConfig[$normalizedCategory];
                if (is_array($categoryConfig) && ($categoryConfig['enabled'] ?? true) === false) {
                    $this->error("❌ Category '{$category}' is disabled in configuration.");
                    $this->line('');
                    $this->line("To enable it, set 'analyzers.{$normalizedCategory}.enabled' to true in config/shieldci.php");
                    $envKey = 'SHIELDCI_'.strtoupper(str_replace('_', '_', $normalizedCategory)).'_ANALYZERS';
                    $this->line("or set {$envKey}=true in your .env file.");

                    return false;
                }
            }

            // Check if category has any analyzers (after filtering by enabled categories)
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

        // Validate triggered-by option
        $triggeredBy = $this->option('triggered-by');
        if ($triggeredBy !== null) {
            if (! is_string($triggeredBy) || $triggeredBy === '') {
                $this->error('❌ Invalid triggered-by value provided.');

                return false;
            }

            $validValues = array_map(fn ($case) => $case->value, \ShieldCI\Enums\TriggerSource::cases());
            if (! in_array($triggeredBy, $validValues, true)) {
                $this->error("❌ Trigger source '{$triggeredBy}' is not valid. Must be one of: ".implode(', ', $validValues));

                return false;
            }
        }

        return true;
    }

    /**
     * Resolve the trigger source from CLI option, config, or default.
     */
    protected function resolveTriggerSource(): \ShieldCI\Enums\TriggerSource
    {
        // 1. Explicit CLI flag takes priority
        $option = $this->option('triggered-by');
        if (is_string($option) && $option !== '') {
            $source = \ShieldCI\Enums\TriggerSource::tryFrom($option);
            if ($source !== null) {
                return $source;
            }
        }

        // 2. CI mode config implies ci_cd
        if (config('shieldci.ci_mode')) {
            return \ShieldCI\Enums\TriggerSource::CiCd;
        }

        // 3. Default to manual
        return \ShieldCI\Enums\TriggerSource::Manual;
    }

    /**
     * Build git context array from CLI flags.
     *
     * @return array<string, string>
     */
    protected function buildGitContext(): array
    {
        $context = [];

        $branch = $this->option('git-branch');
        if (is_string($branch) && $branch !== '') {
            $context['branch'] = $branch;
        }

        $commit = $this->option('git-commit');
        if (is_string($commit) && $commit !== '') {
            $context['commit'] = $commit;
        }

        return $context;
    }
}
