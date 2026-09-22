<?php

declare(strict_types=1);

namespace ShieldCI\Commands;

use Composer\InstalledVersions;
use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use ShieldCI\AnalyzerManager;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\AnalyzersCore\Results\AnalysisResult;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\Support\InlineSuppressionParser;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Concerns\EnrichesResultMetadata;
use ShieldCI\Concerns\SanitizesErrorMessages;
use ShieldCI\Contracts\ClientInterface;
use ShieldCI\Contracts\ReporterInterface;
use ShieldCI\Enums\AnalysisFailureReason;
use ShieldCI\Enums\FailOn;
use ShieldCI\Enums\SuppressionType;
use ShieldCI\Enums\TriggerSource;
use ShieldCI\Support\CiEnvironmentDetector;
use ShieldCI\Support\MemoryLimit;
use ShieldCI\Support\Reporter;
use ShieldCI\ValueObjects\AnalysisReport;
use ShieldCI\ValueObjects\FailureNotification;
use ShieldCI\ValueObjects\FilterResult;
use ShieldCI\ValueObjects\SuppressionRecord;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Output\StreamOutput;

class AnalyzeCommand extends Command
{
    use EnrichesResultMetadata;
    use SanitizesErrorMessages;

    protected $signature = 'shield:analyze
                            {--analyzer= : Run specific analyzer(s). Comma-separated for multiple (e.g., sql-injection,xss-detection)}
                            {--category= : Run analyzers in category. Comma-separated for multiple (e.g., security,performance)}
                            {--format= : Output format (console|json); defaults to shieldci.report.format}
                            {--output= : Save report to file}
                            {--baseline : Compare against baseline and only report new issues}
                            {--report : Send report to ShieldCI platform}
                            {--ci : Run in CI mode (only CI-compatible analyzers)}
                            {--triggered-by= : Override trigger source (manual|ci_cd|scheduled)}
                            {--git-branch= : Git branch name for report metadata}
                            {--git-commit= : Git commit SHA for report metadata}
                            {--git-pr-number= : Pull request number for report metadata}
                            {--git-repository= : Repository owner/repo for report metadata}
                            {--git-base-branch= : PR target branch for report metadata}';

    protected $description = 'Run ShieldCI security and code quality analysis';

    private InlineSuppressionParser $suppressionParser;

    /** @var array<string, list<SuppressionRecord>> */
    private array $suppressedIssues = [];

    public function handle(
        AnalyzerManager $manager,
        ReporterInterface $reporter,
        ClientInterface $client,
    ): int {
        $this->suppressionParser = new InlineSuppressionParser;
        $this->suppressedIssues = [];

        // A command invocation is one run; the shared parser's failure log outlives it.
        $manager->resetParseFailures();

        // Activate CI mode for this run if --ci flag is passed
        if ($this->option('ci')) {
            config(['shieldci.ci_mode' => true]);
        }

        // Resolve trigger source early (needed for failure notifications)
        $triggeredBy = $this->resolveTriggerSource();

        // Validate options
        if (! $this->validateOptions($manager)) {
            $this->notifyFailure($client, AnalysisFailureReason::InvalidOptions, 'Command validation failed: invalid options provided', $triggeredBy);

            return self::FAILURE;
        }

        try {
            return $this->executeAnalysis($manager, $reporter, $client, $triggeredBy);
        } catch (\Throwable $e) {
            $this->error("Analysis failed with error: {$e->getMessage()}");
            $this->notifyFailure($client, AnalysisFailureReason::UncaughtException, $e->getMessage(), $triggeredBy);

            return self::FAILURE;
        }
    }

    /**
     * Execute the main analysis flow.
     */
    private function executeAnalysis(
        AnalyzerManager $manager,
        ReporterInterface $reporter,
        ClientInterface $client,
        TriggerSource $triggeredBy,
    ): int {
        // The Reporter builds strings and never sees the stream they land on, so it cannot
        // decide this for itself. Guarded by the concrete type rather than added to
        // ReporterInterface, which would break any third-party implementation.
        if ($reporter instanceof Reporter) {
            $reporter->setDecorated($this->outputIsDecorated());
        }

        // Apply memory limit as a floor: raise a lower ambient limit, but never lower a
        // higher one (e.g. Vapor's 2048M runtime default or an unlimited CLI). Best-effort:
        // @-suppress the E_WARNING PHP 8.1+ raises when the current memory usage already
        // exceeds the requested limit.
        $memoryLimit = config('shieldci.memory_limit');
        if ($memoryLimit !== null && is_string($memoryLimit)) {
            $currentLimit = ini_get('memory_limit');
            if ($currentLimit === false || MemoryLimit::shouldRaise($currentLimit, $memoryLimit)) {
                @ini_set('memory_limit', $memoryLimit);
            }
        }

        // Set timeout (no-op on Lambda — warn instead)
        if (getenv('AWS_LAMBDA_FUNCTION_NAME') !== false || getenv('VAPOR_SSM_PATH') !== false) {
            $this->warn('Running on Lambda/Vapor: set_time_limit() has no effect. Configure the Lambda function timeout directly, or use --ci to limit analyzer scope.');
        } else {
            $timeout = config('shieldci.timeout');
            if ($timeout !== null && (is_int($timeout) || is_numeric($timeout))) {
                set_time_limit((int) $timeout);
            }
        }

        // Check if enabled
        if (! config('shieldci.enabled')) {
            $this->warn('ShieldCI is disabled in configuration.');

            return self::SUCCESS;
        }

        // Determine if we should use streaming output (console format only)
        $format = $this->resolveFormat();
        $useStreaming = $format === 'console';

        // Validate ignore_errors config early (before analysis starts)
        $this->validateIgnoreErrorsConfig($manager);
        $this->warnIfUnrecognizedEnvironment();
        $this->warnIfUnrecognizedFailOn();
        $this->warnIfConsoleFormatIsWrittenToFile();
        $this->warnIfAnalyzePathsUnusable();

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
                $this->notifyFailure($client, AnalysisFailureReason::AllCategoriesDisabled, 'All analyzer categories are disabled in configuration', $triggeredBy);

                return self::FAILURE;
            }
        }

        // Run analysis (with optional streaming)
        $results = $useStreaming
            ? $this->runAnalysisWithStreaming($manager, $reporter)
            : $this->runAnalysis($manager);

        if ($results->isEmpty()) {
            $this->error('No analyzers were run.');
            $this->notifyFailure($client, AnalysisFailureReason::NoAnalyzersRan, 'Analysis completed but no analyzers produced results', $triggeredBy);

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

        // Inject all accumulated suppression records into the final report
        $report = new AnalysisReport(
            projectId: $report->projectId,
            laravelVersion: $report->laravelVersion,
            packageVersion: $report->packageVersion,
            results: $report->results,
            totalExecutionTime: $report->totalExecutionTime,
            analyzedAt: $report->analyzedAt,
            triggeredBy: $report->triggeredBy,
            metadata: $report->metadata,
            suppressedIssues: $this->suppressedIssues,
            configuration: $report->configuration,
            proPackageVersion: $report->proPackageVersion,
        );

        // Save to file if requested (CLI option or config default)
        $output = $this->resolveOutputPath();

        if ($output !== null && ! $this->saveReport($report, $reporter, $output)) {
            return self::FAILURE;
        }

        // Output report to STDOUT (skip if saved to file or already streamed)
        if (! $output && ! $useStreaming) {
            $this->outputReport($report, $reporter);
        } elseif (! $output && $useStreaming && ! $this->isSingleAnalyzerRun()) {
            // For streaming mode, output the report card — but skip it for a single-analyzer
            // run, where the percentage table degenerates to a meaningless 100%/0% summary
            // already conveyed by the streamed result line.
            // Guarded by the concrete type rather than added to ReporterInterface, which
            // would break any third-party implementation. One that cannot render a card on
            // its own simply does not get one here; toConsole() still includes it.
            if ($reporter instanceof Reporter) {
                $this->newLine();
                $this->line($this->color('Report Card', 'bright_yellow'));
                $this->line($this->color('===========', 'bright_yellow'));
                $this->newLine();
                $this->line($reporter->reportCard($report));
                $this->newLine();
            }
        }

        // Send to API if configured
        if ($this->shouldSendToApi()) {
            if ($this->isScopedRun()) {
                $this->warnOnStderr('⚠️  Skipping platform upload: --analyzer/--category produces a partial '
                    .'report that would skew your project score and history. Run a full scan '
                    .'(php artisan shield:analyze --report) to upload.');
            } else {
                $this->sendToApi($client, $reporter, $report);
            }
        }

        // Determine exit code
        return $this->determineExitCode($report);
    }

    /**
     * Run analysis with streaming output (results displayed as they complete).
     *
     * @return Collection<int, ResultInterface>
     */
    protected function runAnalysisWithStreaming(AnalyzerManager $manager, ReporterInterface $reporter): Collection
    {
        // Output header
        $this->line($reporter->streamHeader());

        $results = collect();
        $category = $this->option('category');
        $analyzerOption = $this->option('analyzer');

        if (is_string($analyzerOption) && $analyzerOption !== '') {
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
                    // Check if it's a skipped analyzer and stream its pre-built result
                    $skippedResult = $manager->getSkippedAnalyzers()->first(fn ($r) => $r->getAnalyzerId() === $analyzerId);
                    if ($skippedResult !== null) {
                        $current++;
                        $skippedMeta = $skippedResult->getMetadata();
                        $skippedCategory = $skippedMeta['category'] ?? 'Unknown';
                        $skippedCategoryLabel = is_object($skippedCategory) && isset($skippedCategory->value)
                            ? Category::from($skippedCategory->value)->label()
                            : 'Unknown';
                        $results->push($skippedResult);
                        $this->line($reporter->streamResult($skippedResult, $current, $total, $skippedCategoryLabel));
                    }

                    continue;
                }

                $current++;

                // Run analyzer
                $result = $analyzer->analyze();
                if (method_exists($analyzer, 'clearAstParserCache')) {
                    $analyzer->clearAstParserCache();
                }
                $manager->clearParserCache();
                $metadata = $analyzer->getMetadata();

                $enrichedResult = $this->enrichResult($result, $metadata);

                // Apply ignore_errors and inline suppression filtering before streaming
                $fr1 = $this->filterSingleResultAgainstIgnoreErrors($enrichedResult);
                $fr2 = $this->filterSingleResultAgainstInlineSuppressions($fr1->result);
                $analyzerId = $enrichedResult->getAnalyzerId();
                $this->accumulateSuppressed($fr1->suppressedRecords, $analyzerId);
                $this->accumulateSuppressed($fr2->suppressedRecords, $analyzerId);

                $results->push($fr2->result);

                // Stream output immediately
                $categoryLabel = $metadata->category->label();
                $allSuppressed = array_merge($fr1->suppressedRecords, $fr2->suppressedRecords);
                $streamOutput = $reporter->streamResult($fr2->result, $current, $total, $categoryLabel);
                if ($allSuppressed !== []) {
                    $count = count($allSuppressed);
                    $suppressedNote = '('.$count.' '.($count === 1 ? 'issue' : 'issues').' suppressed — use --format=json to see details)';
                    $streamOutput = rtrim($streamOutput, PHP_EOL).PHP_EOL.$suppressedNote.PHP_EOL;
                }
                $this->line($streamOutput);
            }

            return $results;
        }

        // Get analyzers (by category/categories or all)
        $normalizedCategories = null;
        if (is_string($category) && $category !== '') {
            $normalizedCategories = array_values(array_filter(
                array_map(fn (string $c) => strtolower(trim($c)), explode(',', $category)),
                fn (string $c) => $c !== ''
            ));
            $analyzers = $manager->getByCategories($normalizedCategories);
        } else {
            $analyzers = $manager->getAnalyzers();
        }

        $enabledCount = $analyzers->count();

        // Calculate skipped count
        $skippedCount = 0;
        if ($normalizedCategories) {
            $skippedCount = $manager->getSkippedAnalyzers()
                ->filter(function (ResultInterface $result) use ($normalizedCategories): bool {
                    $metadata = $result->getMetadata();
                    $resultCategory = $metadata['category'] ?? 'Unknown';
                    if (is_object($resultCategory) && isset($resultCategory->value)) {
                        $resultCategory = $resultCategory->value;
                    }

                    return is_string($resultCategory) && in_array(strtolower($resultCategory), $normalizedCategories, true);
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
                if (method_exists($analyzer, 'clearAstParserCache')) {
                    $analyzer->clearAstParserCache();
                }
                $manager->clearParserCache();
                $metadata = $analyzer->getMetadata();

                $enrichedResult = $this->enrichResult($result, $metadata);

                // Apply ignore_errors and inline suppression filtering before streaming
                $fr1 = $this->filterSingleResultAgainstIgnoreErrors($enrichedResult);
                $fr2 = $this->filterSingleResultAgainstInlineSuppressions($fr1->result);
                $analyzerId = $enrichedResult->getAnalyzerId();
                $this->accumulateSuppressed($fr1->suppressedRecords, $analyzerId);
                $this->accumulateSuppressed($fr2->suppressedRecords, $analyzerId);

                $results->push($fr2->result);

                // Stream output immediately
                $allSuppressed = array_merge($fr1->suppressedRecords, $fr2->suppressedRecords);
                $streamOutput = $reporter->streamResult($fr2->result, $current, $total, $categoryLabel);
                if ($allSuppressed !== []) {
                    $count = count($allSuppressed);
                    $suppressedNote = '('.$count.' '.($count === 1 ? 'issue' : 'issues').' suppressed — use --format=json to see details)';
                    $streamOutput = rtrim($streamOutput, PHP_EOL).PHP_EOL.$suppressedNote.PHP_EOL;
                }
                $this->line($streamOutput);
            }
        }

        // Add skipped analyzers to results and stream them
        if ($normalizedCategories) {
            $skippedResults = $manager->getSkippedAnalyzers()
                ->filter(function (ResultInterface $result) use ($normalizedCategories): bool {
                    $metadata = $result->getMetadata();
                    $resultCategory = $metadata['category'] ?? 'Unknown';
                    if (is_object($resultCategory) && isset($resultCategory->value)) {
                        $resultCategory = $resultCategory->value;
                    }

                    return is_string($resultCategory) && in_array(strtolower($resultCategory), $normalizedCategories, true);
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

    /**
     * @param  resource  $stderrStream
     */
    protected function isProgressEnabled(mixed $stderrStream): bool
    {
        return stream_isatty($stderrStream);
    }

    /**
     * @return Collection<int, ResultInterface>
     */
    protected function runAnalysis(AnalyzerManager $manager): Collection
    {
        /** @var resource $stderrStream */
        $stderrStream = fopen('php://stderr', 'w');
        $showProgress = $this->isProgressEnabled($stderrStream);
        $stderrOutput = new StreamOutput(
            $stderrStream,
            $this->getOutput()->getVerbosity(),
            $showProgress,
        );

        $analyzerOption = $this->option('analyzer');
        if (is_string($analyzerOption) && $analyzerOption !== '') {
            // Support comma-separated analyzer IDs
            $analyzerIds = array_map('trim', explode(',', $analyzerOption));
            $analyzerIds = array_filter($analyzerIds, fn (string $id) => $id !== '');

            $displayName = $this->resolveAnalyzerDisplayName($manager, $analyzerIds);
            $label = count($analyzerIds) === 1 ? 'Running analyzer' : 'Running analyzers';
            $stderrOutput->writeln("{$label}: {$displayName}");

            $progressBar = null;
            if ($showProgress && count($analyzerIds) > 1) {
                $progressBar = new ProgressBar($stderrOutput, count($analyzerIds));
                $progressBar->setFormat(' %current%/%max% [%bar%] %percent:3s%% — %message%');
                $progressBar->setMessage('Starting...');
                $progressBar->start();
            }

            $results = [];
            foreach ($analyzerIds as $analyzerId) {
                if ($progressBar !== null) {
                    $progressBar->setMessage($analyzerId);
                }
                $result = $manager->run($analyzerId);
                if ($progressBar !== null) {
                    $progressBar->advance();
                }
                if ($result !== null) {
                    $results[] = $result;
                } else {
                    // Check if it's a skipped analyzer and include its pre-built result
                    $skippedResult = $manager->getSkippedAnalyzers()->first(fn ($r) => $r->getAnalyzerId() === $analyzerId);
                    if ($skippedResult !== null) {
                        $results[] = $skippedResult;
                    }
                }
            }

            if ($progressBar !== null) {
                $progressBar->finish();
                $stderrOutput->writeln('');
            }

            return collect($results);
        }

        // Get category option (if specified)
        $category = $this->option('category');
        $normalizedCategories = null;

        if (is_string($category) && $category !== '') {
            $normalizedCategories = array_values(array_filter(
                array_map(fn (string $c) => strtolower(trim($c)), explode(',', $category)),
                fn (string $c) => $c !== ''
            ));
            $categoryLabels = array_map(fn (string $c) => Category::from($c)->label(), $normalizedCategories);
            $categoryLabel = implode(', ', $categoryLabels);

            $analyzers = $manager->getByCategories($normalizedCategories);
            $enabledCount = $analyzers->count();
            // Get actual skipped count (may differ from calculated due to instantiation failures)
            $skippedCount = $manager->getSkippedAnalyzers()
                ->filter(function (ResultInterface $result) use ($normalizedCategories): bool {
                    $metadata = $result->getMetadata();
                    $resultCategory = $metadata['category'] ?? 'Unknown';
                    if (is_object($resultCategory) && isset($resultCategory->value)) {
                        $resultCategory = $resultCategory->value;
                    }

                    return is_string($resultCategory) && in_array(strtolower($resultCategory), $normalizedCategories, true);
                })
                ->count();
            // Total count for these categories (enabled + skipped)
            $totalCount = $enabledCount + $skippedCount;

            if ($skippedCount > 0) {
                $stderrOutput->writeln("Running {$categoryLabel} analyzers... ({$enabledCount} running, {$skippedCount} skipped, {$totalCount} total)");
            } else {
                $stderrOutput->writeln("Running {$categoryLabel} analyzers... ({$enabledCount}/{$totalCount})");
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
                $stderrOutput->writeln("Running {$enabledCount} of {$totalCount} analyzers ({$skippedCount} skipped)...");
            } else {
                $stderrOutput->writeln("Running all {$enabledCount} analyzers...");
            }
        }

        // Run analyzers and collect results
        $progressBar = null;
        if ($showProgress) {
            $progressBar = new ProgressBar($stderrOutput, $enabledCount);
            $progressBar->setFormat(' %current%/%max% [%bar%] %percent:3s%% — %message%');
            $progressBar->setMessage('Starting...');
            $progressBar->start();
        }

        $resultsList = [];
        foreach ($analyzers as $analyzer) {
            $metadata = $analyzer->getMetadata();
            if ($progressBar !== null) {
                $progressBar->setMessage($metadata->name);
            }
            $result = $analyzer->analyze();
            if (method_exists($analyzer, 'clearAstParserCache')) {
                $analyzer->clearAstParserCache();
            }
            $manager->clearParserCache();
            if ($progressBar !== null) {
                $progressBar->advance();
            }
            $resultsList[] = $this->enrichResult($result, $metadata);
        }

        if ($progressBar !== null) {
            $progressBar->finish();
            $stderrOutput->writeln('');
        }

        $results = collect($resultsList);

        // Add skipped analyzers
        if ($normalizedCategories) {
            // Add skipped analyzers for the specified categories only
            $skippedResults = $manager->getSkippedAnalyzers()
                ->filter(function (ResultInterface $result) use ($normalizedCategories): bool {
                    $metadata = $result->getMetadata();
                    $resultCategory = $metadata['category'] ?? 'Unknown';
                    if (is_object($resultCategory) && isset($resultCategory->value)) {
                        $resultCategory = $resultCategory->value;
                    }

                    return is_string($resultCategory) && in_array(strtolower($resultCategory), $normalizedCategories, true);
                });
        } else {
            // Add all skipped analyzers when running all
            $skippedResults = $manager->getSkippedAnalyzers();
        }

        // Convert both to arrays and merge, then convert back to collection (same approach as runAll)
        /** @var Collection<int, ResultInterface> $allResults */
        $allResults = collect(array_merge($results->all(), $skippedResults->all()));

        return $allResults;
    }

    protected function outputReport(AnalysisReport $report, ReporterInterface $reporter): void
    {
        // Use CLI option or fall back to config
        $format = $this->resolveFormat();

        if ($format === 'json') {
            $this->line($reporter->toJson($report));
        } else {
            $this->line($reporter->toConsole($report));
        }
    }

    /**
     * Apply ANSI color to text.
     */
    protected function color(string $text, string $color): string
    {
        // Only what this command still renders itself: the Report Card heading and the two
        // exit-code verdicts. Everything else moved to the Reporter with the table. Trimming
        // this also retires a 'gray' that was 0;37 here and 0;90 there, so the two maps no
        // longer define the same name differently.
        $colors = [
            'bright_yellow' => '1;33',
            'bright_red' => '1;31',
            'dim' => '2',
        ];

        if (! $this->outputIsDecorated() || ! isset($colors[$color])) {
            return $text;
        }

        $code = $colors[$color];

        return "\033[{$code}m{$text}\033[0m";
    }

    /**
     * Whether the destination renders escape sequences.
     *
     * Symfony already answers this, and answers it better than anything written here would:
     * isDecorated() accounts for --no-ansi and --ansi, and the stream behind it follows
     * NO_COLOR and FORCE_COLOR and checks that the stream is a terminal. Everything this
     * command and the Reporter emit was written unconditionally, so a redirected run wrote
     * raw escapes into the file, and --no-ansi changed only the handful of messages that go
     * through Laravel's own info/warn/error helpers.
     */
    protected function outputIsDecorated(): bool
    {
        return $this->getOutput()->isDecorated();
    }

    /**
     * Send a failure notification to the ShieldCI platform API.
     */
    private function notifyFailure(
        ClientInterface $client,
        AnalysisFailureReason $reason,
        string $errorMessage,
        TriggerSource $triggeredBy,
    ): void {
        if (! $this->shouldSendToApi()) {
            return;
        }

        try {
            $projectIdConfig = config('shieldci.project_id', 'unknown');
            $projectId = is_string($projectIdConfig) ? $projectIdConfig : 'unknown';

            $notification = new FailureNotification(
                projectId: $projectId,
                laravelVersion: app()->version(),
                packageVersion: $this->resolvePackageVersion(),
                reason: $reason,
                // Sanitized here rather than in FailureNotification, which stays a plain value
                // object. Of the four callers only the uncaught-exception one carries free-form
                // text; doing it here rather than at that call site makes it the contract every
                // caller gets, including any added later.
                errorMessage: $this->sanitizedErrorMessage($errorMessage),
                triggeredBy: $triggeredBy,
                occurredAt: new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
                metadata: $this->buildFailureMetadata(),
            );

            $client->sendFailureNotification($notification->toArray());
        } catch (\Exception $e) {
            // Silently fail — failure notifications should never interrupt the command flow
        }
    }

    /**
     * Build metadata array for failure notifications.
     *
     * @return array<string, string>
     */
    private function buildFailureMetadata(): array
    {
        $appName = config('app.name');
        $appUrl = config('app.url');

        $metadata = [
            'php_version' => PHP_VERSION,
            'environment' => $this->resolveEnvironment(),
            'app_name' => is_string($appName) ? $appName : '',
            'app_url' => is_string($appUrl) ? $appUrl : '',
            'os' => PHP_OS_FAMILY,
        ];

        $gitContext = $this->buildGitContext();
        if (isset($gitContext['branch']) && $gitContext['branch'] !== '') {
            $metadata['git_branch'] = $gitContext['branch'];
        }
        if (isset($gitContext['commit']) && $gitContext['commit'] !== '') {
            $metadata['git_commit'] = $gitContext['commit'];
        }
        if (isset($gitContext['ci_provider']) && $gitContext['ci_provider'] !== '') {
            $metadata['ci_provider'] = $gitContext['ci_provider'];
        }
        foreach (['pr_number', 'repository', 'base_branch'] as $key) {
            if (isset($gitContext[$key]) && $gitContext[$key] !== '') {
                $metadata[$key] = $gitContext[$key];
            }
        }

        return $metadata;
    }

    /**
     * Resolve the package version from Composer.
     */
    private function resolvePackageVersion(): string
    {
        if (class_exists(InstalledVersions::class)) {
            try {
                $version = InstalledVersions::getVersion('shieldci/laravel');

                return is_string($version) ? $version : 'unknown';
            } catch (\Exception $e) {
                return 'unknown';
            }
        }

        return 'unknown';
    }

    /**
     * Resolve the current environment name.
     */
    private function resolveEnvironment(): string
    {
        $env = app()->environment();

        return is_string($env) ? $env : 'unknown';
    }

    /**
     * Write the report to disk, answering whether it landed.
     *
     * The file is always JSON. validateOptions() requires the name to end in .json, while the
     * format branch that used to live here wrote the ASCII banner and ANSI escapes into it
     * whenever --format was absent, which is the default. --format governs stdout instead,
     * and a redirected run already writes a plain console report: #372 gated every escape on
     * isDecorated(), so `shield:analyze > report.txt` needs nothing from this option.
     *
     * The write itself is checked. file_put_contents() answers false for a missing directory
     * or a permission failure, and the confirmation below used to print regardless, so a run
     * whose only report went to a file it could not write reported success and exited 0.
     */
    protected function saveReport(AnalysisReport $report, ReporterInterface $reporter, string $path): bool
    {
        $content = $reporter->toJson($report);

        $directory = dirname($path);

        if (! is_dir($directory) && ! @mkdir($directory, 0755, true) && ! is_dir($directory)) {
            $this->errorOnStderr("❌ Could not create the report directory: {$directory}");

            return false;
        }

        if (@file_put_contents($path, $content) === false) {
            $this->errorOnStderr("❌ Could not write the report to: {$path}");

            return false;
        }

        $this->lineOnStderr("<info>Report saved to: {$path}</info>");

        return true;
    }

    /**
     * Determine whether this run is scoped to a subset of analyzers via --analyzer or --category.
     *
     * Scoped runs produce a partial report whose score/summary reflect only the requested
     * subset, so they must not be uploaded as a full project snapshot.
     */
    protected function isScopedRun(): bool
    {
        $analyzer = $this->option('analyzer');
        $category = $this->option('category');

        return (is_string($analyzer) && $analyzer !== '')
            || (is_string($category) && $category !== '');
    }

    /**
     * Determine whether this run targets exactly one analyzer via --analyzer.
     */
    protected function isSingleAnalyzerRun(): bool
    {
        $analyzer = $this->option('analyzer');

        if (! is_string($analyzer) || $analyzer === '') {
            return false;
        }

        $ids = array_filter(
            array_map('trim', explode(',', $analyzer)),
            fn (string $id) => $id !== ''
        );

        return count($ids) === 1;
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
    protected function sendToApi(ClientInterface $client, ReporterInterface $reporter, AnalysisReport $report): void
    {
        $this->lineOnStderr('<info>Sending report to ShieldCI platform...</info>');

        try {
            $payload = $reporter->toApi($report);
            $response = $client->sendReport($payload);

            if (isset($response['success']) && $response['success'] === true) {
                $this->lineOnStderr('<info>Report sent successfully.</info>');
            } else {
                $message = isset($response['message']) && is_string($response['message'])
                    ? $response['message']
                    : 'Unknown error';
                $this->warnOnStderr("Failed to send report: {$message}");
            }
        } catch (\Exception $e) {
            $this->warnOnStderr("Failed to send report to API: {$e->getMessage()}");
        }
    }

    protected function determineExitCode(AnalysisReport $report): int
    {
        $failOn = FailOn::fromConfig(config('shieldci.fail_on', 'high'));

        if ($failOn === FailOn::Never) {
            return self::SUCCESS;
        }

        // Get don't report analyzers (from config and baseline if using baseline)
        $dontReportConfig = config('shieldci.dont_report', []);
        $dontReport = is_array($dontReportConfig) ? array_values(array_filter($dontReportConfig, 'is_string')) : [];

        // An incomplete analysis is only ever waived by a human. Findings keep using the
        // merged list; errors use the config list only.
        //
        // BaselineCommand no longer writes an errored analyzer into the baseline's
        // dont_report, so this no longer guards against a baseline generated today. It stays
        // because baselines generated before that change are still on disk and still carry
        // those entries, and nothing rewrites a baseline the user already has. Reading one
        // would otherwise reopen the same permanent, invisible hole in the check below.
        $configDontReport = $dontReport;

        // If baseline was used, merge with baseline's dont_report
        if ($this->option('baseline')) {
            $baselineFileRaw = config('shieldci.baseline_file');
            $baselineFile = is_string($baselineFileRaw) ? $baselineFileRaw : null;

            if ($baselineFile && file_exists($baselineFile)) {
                $baselineContent = FileParser::readFile($baselineFile);
                $baseline = $baselineContent !== null ? json_decode($baselineContent, true) : null;
                if (is_array($baseline) && isset($baseline['dont_report']) && is_array($baseline['dont_report'])) {
                    $dontReportMerged = array_merge($dontReport, array_values(array_filter($baseline['dont_report'], 'is_string')));
                    $dontReport = array_values(array_unique($dontReportMerged));
                }
            }
        }

        // Filter out analyzers in dont_report list
        $criticalResults = $report->failed()->filter(function ($result) use ($dontReport) {
            return ! in_array($result->getAnalyzerId(), $dontReport, true);
        });

        // A result that is not passing but names no issue cannot be graded by the severity
        // loops below, which decide by reading $issue->severity and so have nothing to read.
        // An errored analyzer produced no verdict at all; a failed or warning one produced a
        // verdict whose detail it could not enumerate. Reporting success for either is the
        // defect this check exists to prevent. Checked before fail_threshold so the reason
        // the user is told is "phpstan never ran" rather than a score that it depressed.
        $blockingErrors = $report->errors()->filter(function ($result) use ($configDontReport) {
            return ! in_array($result->getAnalyzerId(), $configDontReport, true);
        });

        $ungraded = $criticalResults->filter(fn (ResultInterface $result) => $result->getIssues() === []);

        // A warning only reaches the exit code at the two lowest thresholds, so an ungradable
        // one must not block above them either.
        if ($failOn->gradesWarnings()) {
            $ungraded = $ungraded->merge(
                $this->gradableWarnings($report, $dontReport)
                    ->filter(fn (ResultInterface $result) => $result->getIssues() === [])
            );
        }

        if ($blockingErrors->isNotEmpty() || $ungraded->isNotEmpty()) {
            $this->reportUngradableResults($blockingErrors, $ungraded);

            return self::FAILURE;
        }

        // Check threshold if configured. The score compared here excludes dont_report
        // analyzers, because dont_report is documented as "runs but does not affect the exit
        // code" and AnalysisReport::score() has no knowledge of it, so a waived analyzer
        // still dragged the score under the threshold. The reported score is deliberately
        // left alone: it is uploaded to the platform, so it must not vary with one
        // developer's local config.
        $threshold = config('shieldci.fail_threshold');

        if (is_numeric($threshold)) {
            $score = $this->gatingScore($report, $dontReport);

            if ($score < (float) $threshold) {
                $this->reportThresholdFailure($score, (float) $threshold);

                return self::FAILURE;
            }
        }

        // Failures and warnings are graded by the same rule, so both consult FailOn::fails().
        // They used to be separate switch statements, and the warning one had fallen a level
        // behind: it matched only 'medium', letting a warning that carried a High or Critical
        // issue through a threshold that a Medium one would have tripped.
        $gradable = $criticalResults;

        if ($failOn->gradesWarnings()) {
            $gradable = $gradable->merge($this->gradableWarnings($report, $dontReport));
        }

        $shouldFail = $gradable->some(
            fn (ResultInterface $result) => collect($result->getIssues())
                ->contains(fn (Issue $issue) => $failOn->fails($issue->severity))
        );

        if ($shouldFail) {
            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    /**
     * Warning results that dont_report has not waived.
     *
     * @param  array<int, string>  $dontReport
     * @return Collection<int, ResultInterface>
     */
    private function gradableWarnings(AnalysisReport $report, array $dontReport): Collection
    {
        return $report->warnings()->filter(
            fn (ResultInterface $result) => ! in_array($result->getAnalyzerId(), $dontReport, true)
        );
    }

    /**
     * The score fail_threshold is compared against.
     *
     * Differs from AnalysisReport::score() in one way: analyzers the user waived through
     * dont_report are dropped from both sides of the ratio rather than counted as failures.
     * dont_report is documented as "runs but does not affect the exit code", and score()
     * knows nothing about it, so waiving an analyzer still sank the score and failed the
     * build through this gate. Kept separate from score() so the number shown to the user
     * and uploaded to the platform stays independent of local configuration.
     *
     * @param  array<int, string>  $dontReport
     */
    private function gatingScore(AnalysisReport $report, array $dontReport): int
    {
        $graded = $report->results->filter(
            fn (ResultInterface $result) => $result->getStatus() !== Status::Skipped
                && ! in_array($result->getAnalyzerId(), $dontReport, true)
        );

        if ($graded->isEmpty()) {
            return 100;
        }

        $passed = $graded->filter(
            fn (ResultInterface $result) => $result->getStatus() === Status::Passed
        )->count();

        return (int) round(($passed / $graded->count()) * 100);
    }

    /**
     * Name the analyzers that could not complete as the reason for the non-zero exit code.
     *
     * Runs after the whole report body, so this is the last thing on screen. The per-analyzer
     * reason is already printed by the Reporter, so this names the analyzers rather than
     * repeating their messages.
     *
     * Skipped only when the JSON report is itself going to stdout, which appending prose
     * would stop `shield:analyze --format=json | jq` from parsing. Such a consumer already
     * has summary.errors and each result's "status": "error". When the report is written to
     * a file instead, stdout is free and the verdict is the only thing telling an operator
     * why the command exited non-zero, so it is printed.
     *
     * The two groups are named separately because they are not the same failure: an errored
     * analyzer never produced a verdict, while an ungradable one reported a problem it could
     * not attribute to a specific issue.
     *
     * @param  Collection<int, ResultInterface>  $erroredResults
     * @param  Collection<int, ResultInterface>  $ungradedResults
     */
    private function reportUngradableResults(Collection $erroredResults, Collection $ungradedResults): void
    {
        if (! $this->prosePermitted()) {
            return;
        }

        $this->newLine();

        if ($erroredResults->isNotEmpty()) {
            $count = $erroredResults->count();
            $noun = $count === 1 ? 'analyzer' : 'analyzers';
            $ids = $erroredResults->map(fn (ResultInterface $result) => $result->getAnalyzerId())->implode(', ');

            $this->line($this->color("✗ Analysis incomplete: {$count} {$noun} could not run ({$ids}).", 'bright_red'));
        }

        if ($ungradedResults->isNotEmpty()) {
            $count = $ungradedResults->count();
            $noun = $count === 1 ? 'analyzer' : 'analyzers';
            $ids = $ungradedResults->map(fn (ResultInterface $result) => $result->getAnalyzerId())->implode(', ');

            $this->line($this->color(
                "✗ {$count} {$noun} reported a problem without naming an issue ({$ids}).",
                'bright_red'
            ));
        }

        $this->line($this->color(
            "  Add an analyzer id to 'dont_report' in config/shieldci.php to stop it affecting the exit code.",
            'dim'
        ));
    }

    /**
     * Name the score that failed the build, since the threshold branch is otherwise silent.
     */
    private function reportThresholdFailure(int $score, float $threshold): void
    {
        if (! $this->prosePermitted()) {
            return;
        }

        $this->newLine();
        $this->line($this->color(
            sprintf('✗ Score %d%% is below the configured fail_threshold of %s%%.', $score, rtrim(rtrim(number_format($threshold, 2, '.', ''), '0'), '.')),
            'bright_red'
        ));
        $this->line($this->color(
            '  Analyzers listed in \'dont_report\' are excluded from this score.',
            'dim'
        ));
    }

    /**
     * Whether a human-readable line may be written to stdout.
     *
     * False only when the JSON report is itself going to stdout, which appending prose would
     * stop `shield:analyze --format=json | jq` from parsing. Such a consumer already has
     * summary.errors and each result's status. When the report is written to a file instead,
     * stdout is free and these lines are the only thing telling an operator why the command
     * exited non-zero.
     */
    private function prosePermitted(): bool
    {
        return $this->resolveFormat() !== 'json' || $this->resolveOutputPath() !== null;
    }

    /**
     * The stream for anything that is not the report itself.
     *
     * Advisory lines used to go to stdout alongside the report, so
     * `shield:analyze --format=json | jq` failed to parse whenever the run had anything to
     * say: an unmapped APP_ENV, a malformed ignore_errors glob, a scoped upload, a baseline
     * being applied. Diagnostics belong on stderr, which keeps them visible without putting
     * them in the document.
     *
     * Falls back to the same stream when the output is not a console, which is what Symfony's
     * own OutputStyle::getErrorOutput() does. That is also what keeps this testable: the test
     * harness buffers a single stream, so a message written here is still observable there.
     */
    private function errorOutput(): OutputInterface
    {
        $output = $this->getOutput()->getOutput();

        return $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
    }

    /**
     * Write an advisory line to stderr, styled the way Command::warn() would style it.
     */
    private function warnOnStderr(string $message): void
    {
        $this->errorOutput()->writeln("<comment>{$message}</comment>");
    }

    /**
     * Write a failure line to stderr, styled the way Command::error() would style it.
     */
    private function errorOnStderr(string $message): void
    {
        $this->errorOutput()->writeln("<error>{$message}</error>");
    }

    /**
     * Write a plain line to stderr.
     */
    private function lineOnStderr(string $message = ''): void
    {
        $this->errorOutput()->writeln($message);
    }

    /**
     * The report format, from --format or the configured default.
     *
     * The option used to declare console as its own default, which meant it was never
     * empty, so the `?:` fallback below never ran and shieldci.report.format and
     * SHIELDCI_REPORT_FORMAT could not be reached from anywhere. validateOptions() still
     * guards `$format !== null`, which only makes sense for an option that can be absent.
     */
    private function resolveFormat(): string
    {
        $option = $this->option('format');

        if (is_string($option) && $option !== '') {
            return strtolower($option);
        }

        $configured = config('shieldci.report.format', 'console');

        return is_string($configured) && $configured !== '' ? strtolower($configured) : 'console';
    }

    /**
     * Where the report is written, from --output or the configured default, or null for stdout.
     *
     * Always absolute. validateOptions() resolves --output against base_path(), creates the
     * directory there and checks it is writable, but saveReport() used to hand the raw
     * relative string to file_put_contents(), which resolves against the process working
     * directory. The command validated one file and wrote another; the two coincide only
     * because artisan is normally run from the project root.
     */
    private function resolveOutputPath(): ?string
    {
        $option = $this->option('output');

        if (is_string($option) && $option !== '') {
            return $this->absoluteReportPath($option);
        }

        $configured = config('shieldci.report.output_file');

        return is_string($configured) && $configured !== ''
            ? $this->absoluteReportPath($configured)
            : null;
    }

    /**
     * Resolve a report path against the application base directory.
     *
     * An already absolute path is answered unchanged. shieldci.report.output_file is not
     * validated at all and may legitimately point outside base_path(), which is what makes a
     * temp directory a usable destination for it.
     */
    private function absoluteReportPath(string $path): string
    {
        $normalized = str_replace('\\', '/', $path);

        if (str_starts_with($normalized, '/') || preg_match('#^[A-Za-z]:/#', $normalized) === 1) {
            return $path;
        }

        return base_path($path);
    }

    /**
     * Warn when an explicit --format=console is paired with a file destination.
     *
     * The file is always JSON, so a console format applies to stdout only. Gated on the
     * option rather than resolveFormat() because console is the default: the ordinary
     * `--output=report.json` never asked for console and has nothing to be told.
     */
    private function warnIfConsoleFormatIsWrittenToFile(): void
    {
        if ($this->option('format') !== 'console' || $this->resolveOutputPath() === null) {
            return;
        }

        $this->warnOnStderr('⚠️  --format=console applies to stdout. The report file is always JSON.');
        $this->lineOnStderr();
    }

    /**
     * Warn if fail_on is set to a value this command does not understand.
     *
     * Reported before the analysis rather than from determineExitCode(), which runs after
     * the report body has already gone to stdout. Advisory only: resolveFailOn() falls back
     * to the default so the run still gates on something.
     */
    private function warnIfUnrecognizedFailOn(): void
    {
        $failOn = config('shieldci.fail_on', 'high');

        if (is_string($failOn) && FailOn::tryFrom($failOn) !== null) {
            return;
        }

        $this->warnOnStderr(sprintf(
            "⚠️  fail_on '%s' is not one of %s. Falling back to '%s'.",
            is_scalar($failOn) ? (string) $failOn : get_debug_type($failOn),
            implode(', ', FailOn::values()),
            FailOn::fromConfig($failOn)->value
        ));
        $this->lineOnStderr();
    }

    /**
     * Warn if APP_ENV is non-standard and has no environment_mapping entry.
     */
    private function warnIfUnrecognizedEnvironment(): void
    {
        $standardEnvs = ['local', 'development', 'staging', 'production', 'testing'];
        $rawEnv = config('app.env');

        if (! is_string($rawEnv) || $rawEnv === '' || in_array($rawEnv, $standardEnvs, true)) {
            return;
        }

        $mapping = config('shieldci.environment_mapping', []);
        if (is_array($mapping) && isset($mapping[$rawEnv])) {
            return;
        }

        $this->warnOnStderr("⚠️  APP_ENV '{$rawEnv}' is not a recognized standard environment. Environment-scoped analyzers may be skipped. Add a mapping in config/shieldci.php.");
        $this->lineOnStderr();
    }

    /**
     * Warn if paths.analyze holds nothing analysis can use.
     *
     * Reported before the analysis rather than alongside the report, which is already on
     * stdout by the time the scan has happened against directories the user did not write.
     * Advisory only: AnalyzerManager substitutes the shipped defaults so the run still walks
     * something. Without the substitution an unusable value left every file analyzer on its
     * base path, which is either the whole application root or, on analyzers-core 2.3.0 and
     * earlier, nothing at all reported as a pass.
     */
    private function warnIfAnalyzePathsUnusable(): void
    {
        $configured = config('shieldci.paths.analyze', []);
        $paths = is_array($configured) ? array_values(array_filter($configured, 'is_string')) : [];

        if ($paths !== []) {
            return;
        }

        if (! is_array($configured)) {
            $reason = sprintf('is a %s, not a list of directories', get_debug_type($configured));
        } elseif ($configured === []) {
            $reason = 'is empty';
        } else {
            $reason = 'holds no directory names';
        }

        $this->warnOnStderr(sprintf(
            '⚠️  paths.analyze %s. Falling back to %s.',
            $reason,
            implode(', ', AnalyzerManager::DEFAULT_ANALYZE_PATHS)
        ));
        $this->lineOnStderr();
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
            $this->warnOnStderr('⚠️  Configuration Warnings:');
            foreach ($warnings as $warning) {
                $this->lineOnStderr("   • {$warning}");
            }
            $this->lineOnStderr();
        }
    }

    /**
     * Filter a single result against ignore_errors config.
     * Used in streaming mode to filter results before displaying them.
     */
    protected function filterSingleResultAgainstIgnoreErrors(AnalysisResult $result): FilterResult
    {
        $configIgnoreErrors = config('shieldci.ignore_errors', []);
        $configIgnoreErrors = is_array($configIgnoreErrors) ? $configIgnoreErrors : [];

        if (empty($configIgnoreErrors)) {
            return new FilterResult($result, []);
        }

        $analyzerId = $result->getAnalyzerId();

        // If no ignore_errors for this analyzer, return as-is
        if (! isset($configIgnoreErrors[$analyzerId])) {
            return new FilterResult($result, []);
        }

        $currentIssues = $result->getIssues();

        // Nothing to filter. Without this, a result that never had issues falls into the
        // "no issues remain" branch below: deriveSuppressedStatus() rewrites it to Passed
        // and the message becomes 'All issues are ignored via config', which turns an
        // errored analyzer into a clean pass and destroys the only record of why it could
        // not run. Mirrors the guard in filterSingleResultAgainstInlineSuppressions().
        if ($currentIssues === []) {
            return new FilterResult($result, []);
        }

        $suppressedRecords = [];

        /** @var array<int, array<string, mixed>> $analyzerIgnoreErrors */
        $analyzerIgnoreErrors = is_array($configIgnoreErrors[$analyzerId]) ? $configIgnoreErrors[$analyzerId] : [];

        // Filter out issues that match ignore_errors config
        $newIssues = collect($currentIssues)->filter(function ($issue) use ($analyzerIgnoreErrors, &$suppressedRecords) {
            $matchingRule = $this->findMatchingIgnoreRule($issue, $analyzerIgnoreErrors);
            if ($matchingRule !== null) {
                $suppressedRecords[] = new SuppressionRecord(
                    $issue,
                    SuppressionType::Config,
                    $this->describeIgnoreRule($matchingRule)
                );

                return false; // Issue matches ignore_errors, filter it out
            }

            return true; // Keep issue
        });

        // Create new result with filtered issues
        $status = $this->deriveSuppressedStatus($result->getStatus(), $newIssues->all());

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

        return new FilterResult(
            new AnalysisResult(
                analyzerId: $result->getAnalyzerId(),
                status: $status,
                message: $message,
                issues: $newIssues->all(),
                executionTime: $result->getExecutionTime(),
                metadata: $result->getMetadata(),
            ),
            $suppressedRecords
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

        // Filter results, accumulating suppression records via the single-result method
        $filteredResults = $report->results->map(function ($result) {
            if (! $result instanceof AnalysisResult) {
                return $result;
            }

            $fr = $this->filterSingleResultAgainstIgnoreErrors($result);
            $this->accumulateSuppressed($fr->suppressedRecords, $result->getAnalyzerId());

            return $fr->result;
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
            configuration: $report->configuration,
            proPackageVersion: $report->proPackageVersion,
        );
    }

    /**
     * Filter a single result against inline @shieldci-ignore comments.
     * Used in streaming mode to filter results before displaying them.
     */
    protected function filterSingleResultAgainstInlineSuppressions(AnalysisResult $result): FilterResult
    {
        $currentIssues = $result->getIssues();

        if ($currentIssues === []) {
            return new FilterResult($result, []);
        }

        $analyzerId = $result->getAnalyzerId();
        $suppressedRecords = [];

        $newIssues = array_filter($currentIssues, function ($issue) use ($analyzerId, &$suppressedRecords) {
            $location = $issue->location;

            if ($location === null || $location->line === null || $location->line < 1) {
                return true; // Keep issues without a location — can't suppress inline
            }

            if ($this->suppressionParser->isLineSuppressed($location->file, $location->line, $analyzerId)) {
                $suppressedRecords[] = new SuppressionRecord(
                    $issue,
                    SuppressionType::Inline,
                    '@shieldci-ignore at '.$location->file.':'.$location->line
                );

                return false;
            }

            return true;
        });

        if (count($newIssues) === count($currentIssues)) {
            return new FilterResult($result, []); // Nothing was suppressed
        }

        $status = $this->deriveSuppressedStatus($result->getStatus(), $newIssues);

        $message = $this->adjustFilteredMessage($result->getMessage(), count($currentIssues), count($newIssues));

        return new FilterResult(
            new AnalysisResult(
                analyzerId: $result->getAnalyzerId(),
                status: $status,
                message: $message,
                issues: array_values($newIssues),
                executionTime: $result->getExecutionTime(),
                metadata: $result->getMetadata(),
            ),
            $suppressedRecords
        );
    }

    /**
     * Filter report against inline @shieldci-ignore comments in source files.
     */
    protected function filterAgainstInlineSuppressions(AnalysisReport $report): AnalysisReport
    {
        $filteredResults = $report->results->map(function (ResultInterface $result) {
            if (! $result instanceof AnalysisResult) {
                return $result;
            }

            $fr = $this->filterSingleResultAgainstInlineSuppressions($result);
            $this->accumulateSuppressed($fr->suppressedRecords, $result->getAnalyzerId());

            return $fr->result;
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
            configuration: $report->configuration,
            proPackageVersion: $report->proPackageVersion,
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
            $this->warnOnStderr('⚠️  No baseline file found. Run "php artisan shield:baseline" to create one.');

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

        $baselineDontReportRaw = is_array($baseline) && isset($baseline['dont_report']) && is_array($baseline['dont_report'])
            ? $baseline['dont_report']
            : [];
        $baselineDontReport = array_values(array_filter($baselineDontReportRaw, 'is_string'));

        // dont_report is deliberately not applied here. It is documented as "runs and shows
        // in the report, but does not affect the exit code", so it belongs in
        // determineExitCode() and nowhere else; filtering issues out of the report would
        // hide them instead. A merged list used to be built here and never read.
        $this->lineOnStderr('<info>📋 Filtering against baseline...</info>');
        if (count($baselineDontReport) > 0) {
            $this->lineOnStderr('   ⚠️  Using '.count($baselineDontReport).' analyzer(s) from baseline dont_report');
        }

        // Filter results (ignore_errors already filtered in filterAgainstIgnoreErrors)
        $filteredResults = $report->results->map(function ($result) use ($baselineErrors) {
            $analyzerId = $result->getAnalyzerId();

            // If no baseline for this analyzer, return as-is
            if (! isset($baselineErrors[$analyzerId])) {
                return $result;
            }

            $currentIssues = $result->getIssues();

            // Same guard as ignore_errors: a result with no issues has nothing to match
            // against the baseline, and must not be rewritten to Passed / 'All issues are
            // in baseline' just because the analyzer had issues on the run that generated
            // the baseline.
            if ($currentIssues === []) {
                return $result;
            }

            $baselineIssues = $baselineErrors[$analyzerId];

            $suppressedRecords = [];

            // Filter out issues that exist in baseline
            $newIssues = collect($currentIssues)->filter(function ($issue) use ($baselineIssues, &$suppressedRecords) {
                /** @var array<int, array<string, mixed>> $baselineIssues */
                foreach ($baselineIssues as $baselineIssue) {
                    if (is_array($baselineIssue) && $this->matchesBaselineIssue($issue, $baselineIssue)) {
                        $suppressedRecords[] = new SuppressionRecord(
                            $issue,
                            SuppressionType::Baseline,
                            $this->describeBaselineMatch($baselineIssue)
                        );

                        return false; // Issue matches baseline, filter it out
                    }
                }

                return true; // New issue
            });

            $this->accumulateSuppressed($suppressedRecords, $analyzerId);

            // Create new result with filtered issues
            $status = $this->deriveSuppressedStatus($result->getStatus(), $newIssues->all());

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

            return new AnalysisResult(
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
            configuration: $report->configuration,
            proPackageVersion: $report->proPackageVersion,
        );
    }

    /**
     * Push suppression records into the instance accumulator for a given analyzer.
     *
     * @param  list<SuppressionRecord>  $records
     */
    private function accumulateSuppressed(array $records, string $analyzerId): void
    {
        if ($records === []) {
            return;
        }

        if (! isset($this->suppressedIssues[$analyzerId])) {
            $this->suppressedIssues[$analyzerId] = [];
        }

        foreach ($records as $record) {
            $this->suppressedIssues[$analyzerId][] = $record;
        }
    }

    /**
     * Derive a result's status after suppression has removed some issues.
     *
     * Suppression only ever removes issues, so a result's status can only
     * improve or stay the same — never worsen:
     *   - no issues remain                              → Passed
     *   - issues remain, none High/Critical, was Failed → Warning (downgrade)
     *   - otherwise                                     → unchanged
     *
     * @param  array<Issue>  $remainingIssues
     */
    private function deriveSuppressedStatus(Status $original, array $remainingIssues): Status
    {
        if ($remainingIssues === []) {
            return Status::Passed;
        }

        if ($original !== Status::Failed) {
            return $original;
        }

        foreach ($remainingIssues as $issue) {
            if ($issue->severity->level() >= Severity::High->level()) {
                return Status::Failed; // a High/Critical issue survived
            }
        }

        return Status::Warning; // only Low/Medium remain → downgrade
    }

    /**
     * Build a human-readable description of an ignore_errors rule.
     *
     * @param  array<string, mixed>  $rule
     */
    private function describeIgnoreRule(array $rule): string
    {
        if (isset($rule['path_pattern']) && is_string($rule['path_pattern'])) {
            return 'path_pattern: '.$rule['path_pattern'];
        }

        if (isset($rule['path']) && is_string($rule['path'])) {
            return 'path: '.$rule['path'];
        }

        if (isset($rule['message_pattern']) && is_string($rule['message_pattern'])) {
            return 'message_pattern: '.$rule['message_pattern'];
        }

        if (isset($rule['message']) && is_string($rule['message'])) {
            return 'message: '.$rule['message'];
        }

        return 'config rule';
    }

    /**
     * Build a human-readable description of a baseline match.
     *
     * @param  array<string, mixed>  $baselineIssue
     */
    private function describeBaselineMatch(array $baselineIssue): string
    {
        if (isset($baselineIssue['hash']) && is_string($baselineIssue['hash'])) {
            return 'baseline hash: '.substr($baselineIssue['hash'], 0, 8).'...';
        }

        if (isset($baselineIssue['path']) && is_string($baselineIssue['path'])) {
            return 'baseline match: '.$baselineIssue['path'];
        }

        if (isset($baselineIssue['path_pattern']) && is_string($baselineIssue['path_pattern'])) {
            return 'baseline pattern: '.$baselineIssue['path_pattern'];
        }

        return 'baseline match';
    }

    /**
     * Find the first ignore_errors rule that matches an issue and return it, or null if none match.
     *
     * @param  array<int, array<string, mixed>>  $ignoreErrors
     * @return array<string, mixed>|null
     */
    private function findMatchingIgnoreRule(Issue $issue, array $ignoreErrors): ?array
    {
        $issuePath = $issue->location->file ?? 'unknown';
        $issueMessage = $issue->message;

        foreach ($ignoreErrors as $ignoreError) {
            if (! is_array($ignoreError)) {
                continue;
            }

            $hasAtLeastOneCriterion = isset($ignoreError['path']) ||
                                     isset($ignoreError['path_pattern']) ||
                                     isset($ignoreError['message']) ||
                                     isset($ignoreError['message_pattern']);

            if (! $hasAtLeastOneCriterion) {
                continue;
            }

            $pathMatches = true;
            $messageMatches = true;

            if (isset($ignoreError['path']) && is_string($ignoreError['path'])) {
                $ignorePath = $ignoreError['path'];
                $normalizedIssuePath = str_replace('\\', '/', $issuePath);
                $normalizedIgnorePath = str_replace('\\', '/', $ignorePath);
                $pathMatches = $ignorePath === $issuePath || $normalizedIgnorePath === $normalizedIssuePath;
            }

            if (isset($ignoreError['path_pattern']) && is_string($ignoreError['path_pattern'])) {
                $pattern = $ignoreError['path_pattern'];
                $normalizedIssuePath = str_replace('\\', '/', $issuePath);
                $pathMatches = fnmatch($pattern, $issuePath) ||
                              fnmatch($pattern, $normalizedIssuePath) ||
                              Str::is($pattern, $issuePath);
            }

            if (isset($ignoreError['message']) && is_string($ignoreError['message'])) {
                $messageMatches = $ignoreError['message'] === $issueMessage;
            }

            if (isset($ignoreError['message_pattern']) && is_string($ignoreError['message_pattern'])) {
                $pattern = $ignoreError['message_pattern'];
                $issueRecommendation = $issue->recommendation;
                $messageMatches = Str::is($pattern, $issueMessage) ||
                                 Str::is($pattern, $issueRecommendation);
            }

            if ($pathMatches && $messageMatches) {
                return $ignoreError;
            }
        }

        return null;
    }

    /**
     * Check if an issue matches a baseline entry.
     *
     * @param  array<string, mixed>  $baselineIssue
     */
    private function matchesBaselineIssue(Issue $issue, array $baselineIssue): bool
    {
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
                $messageMatches = Str::is($messagePattern, $issueMessage);
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
    private function generateIssueHash(Issue $issue): string
    {
        $data = [
            'file' => $issue->location !== null ? $issue->location->file : 'unknown',
            'line' => $issue->location !== null ? $issue->location->line : 0,
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
            if ($analyzer !== null) {
                return $analyzer->getMetadata()->name;
            }

            $skipped = $manager->getSkippedAnalyzers()->first(fn ($r) => $r->getAnalyzerId() === $id);
            $skippedName = $skipped !== null ? ($skipped->getMetadata()['name'] ?? null) : null;

            return is_string($skippedName) ? $skippedName : $id;
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

            // Check if all analyzers exist (active or skipped)
            $allAnalyzers = $manager->getAnalyzers();
            $allAnalyzerIds = $allAnalyzers->map(fn ($analyzer) => $analyzer->getId())->toArray();
            $skippedAnalyzerIds = $manager->getSkippedAnalyzers()
                ->map(fn ($result) => $result->getAnalyzerId())
                ->toArray();

            $invalidIds = [];
            $warnSkippedIds = [];
            foreach ($analyzerIds as $analyzerId) {
                if (in_array($analyzerId, $allAnalyzerIds, true)) {
                    // Active — fine
                } elseif (in_array($analyzerId, $skippedAnalyzerIds, true)) {
                    $warnSkippedIds[] = $analyzerId;
                } else {
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

            if (! empty($warnSkippedIds)) {
                $skippedList = implode(', ', $warnSkippedIds);
                $this->line("<fg=yellow>⚠ Analyzer(s) are skipped: {$skippedList}</>");
            }
        }

        // Validate category option
        $category = $this->option('category');
        if ($category !== null) {
            if (! is_string($category) || $category === '') {
                $this->error('❌ Invalid category provided.');

                return false;
            }

            // Parse comma-separated category IDs
            $categoryIds = array_values(array_filter(
                array_map('trim', explode(',', $category)),
                fn (string $c) => $c !== ''
            ));

            if (empty($categoryIds)) {
                $this->error('❌ No valid category provided.');

                return false;
            }

            // Get valid categories from Category enum
            $validCategories = array_map(
                fn ($case) => $case->value,
                Category::cases()
            );

            $analyzersConfig = config('shieldci.analyzers', []);
            $analyzersConfig = is_array($analyzersConfig) ? $analyzersConfig : [];

            $invalidCategories = [];
            $disabledCategories = [];
            $emptyCategories = [];

            foreach ($categoryIds as $cat) {
                $normalized = strtolower($cat);
                if (! in_array($normalized, array_map('strtolower', $validCategories), true)) {
                    $invalidCategories[] = $cat;

                    continue;
                }

                // Check if disabled in config
                if (isset($analyzersConfig[$normalized])) {
                    $cfg = $analyzersConfig[$normalized];
                    if (is_array($cfg) && ($cfg['enabled'] ?? true) === false) {
                        $disabledCategories[] = $cat;

                        continue;
                    }
                }

                // Check if any analyzers exist for this category
                if ($manager->getByCategory($normalized)->isEmpty()) {
                    $emptyCategories[] = $cat;
                }
            }

            if (! empty($invalidCategories)) {
                $invalidList = implode(', ', $invalidCategories);
                $this->error("❌ Category '{$invalidList}' is not valid.");
                $this->line('');
                $this->line('Valid categories:');
                foreach ($validCategories as $validCategory) {
                    $this->line("  - {$validCategory}");
                }

                return false;
            }

            if (! empty($disabledCategories)) {
                $disabledList = implode(', ', $disabledCategories);
                $this->error("❌ Category '{$disabledList}' is disabled in configuration.");

                return false;
            }

            if (! empty($emptyCategories)) {
                $emptyList = implode(', ', $emptyCategories);
                $this->warn("⚠️  No analyzers found for category '{$emptyList}'.");

                return false;
            }

            // Warn if both --analyzer and --category are provided (--category will be ignored)
            if ($this->option('analyzer') !== null) {
                $this->warn('⚠️  Both --analyzer and --category were provided. --category will be ignored.');
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

            // Resolve the final path the same way saveReport() will, so the file this block
            // validates and the file that gets written cannot drift apart again.
            $basePath = base_path();
            $resolvedPath = $this->absoluteReportPath($normalizedPath);

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

            $validValues = array_map(fn ($case) => $case->value, TriggerSource::cases());
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
    protected function resolveTriggerSource(): TriggerSource
    {
        // 1. Explicit CLI flag takes priority
        $option = $this->option('triggered-by');
        if (is_string($option) && $option !== '') {
            $source = TriggerSource::tryFrom($option);
            if ($source !== null) {
                return $source;
            }
        }

        // 2. --ci flag or CI mode config implies ci_cd
        if ($this->option('ci') || config('shieldci.ci_mode')) {
            return TriggerSource::CiCd;
        }

        // 3. Default to manual
        return TriggerSource::Manual;
    }

    /**
     * Build git context array from CLI flags, CI env vars, or git shell commands.
     *
     * Priority: CLI flags → CI env vars → git shell fallback.
     *
     * @return array<string, string>
     */
    protected function buildGitContext(): array
    {
        $detector = $this->makeCiDetector();
        $provider = $detector->detectProvider();

        $context = [];
        if ($provider !== null) {
            $context['ci_provider'] = $provider;
        }

        $branch = $this->option('git-branch');
        if (! is_string($branch) || $branch === '') {
            $branch = $detector->resolveBranch($provider);
        }
        if (is_string($branch)) {
            $context['branch'] = $branch;
        }

        $commit = $this->option('git-commit');
        if (! is_string($commit) || $commit === '') {
            $commit = $detector->resolveCommit($provider);
        }
        if (is_string($commit) && $commit !== '') {
            $context['commit'] = $commit;
        }

        $prNumber = $this->option('git-pr-number');
        if (! is_string($prNumber) || $prNumber === '') {
            $resolved = $detector->resolvePrNumber($provider);
            $prNumber = $resolved !== null ? (string) $resolved : null;
        }
        if (is_string($prNumber)) {
            $context['pr_number'] = $prNumber;
        }

        $repository = $this->option('git-repository');
        if (! is_string($repository) || $repository === '') {
            $repository = $detector->resolveRepository($provider);
        }
        if (is_string($repository)) {
            $context['repository'] = $repository;
        }

        $baseBranch = $this->option('git-base-branch');
        if (! is_string($baseBranch) || $baseBranch === '') {
            $baseBranch = $detector->resolveBaseBranch($provider);
        }
        if (is_string($baseBranch) && $baseBranch !== '') {
            $context['base_branch'] = $baseBranch;
        }

        return $context;
    }

    protected function makeCiDetector(): CiEnvironmentDetector
    {
        return app(CiEnvironmentDetector::class);
    }
}
