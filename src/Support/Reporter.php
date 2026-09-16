<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Composer\InstalledVersions;
use DateTimeImmutable;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzerManager;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\AnalyzersCore\ValueObjects\CodeSnippet;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Contracts\ReporterInterface;
use ShieldCI\Enums\TriggerSource;
use ShieldCI\ValueObjects\AnalysisReport;

/**
 * Report generator for analysis results.
 */
class Reporter implements ReporterInterface
{
    /**
     * Whether escape sequences may be written.
     *
     * This class builds strings and never sees the stream they end up on, so it cannot work
     * this out for itself: only the command knows whether --no-ansi was passed or where
     * stdout is pointing. Defaults to true so the plain string builders used outside a
     * command keep their existing output.
     */
    private bool $decorated = true;

    /**
     * Token ids rendered as keywords.
     *
     * Listed rather than derived: PHP exposes no "is this id a keyword" predicate, and
     * inferring it from the token name or from the text would put a heuristic back where
     * the tokeniser has already given a definite answer.
     *
     * @var list<int>
     */
    private const KEYWORD_TOKENS = [
        T_ABSTRACT, T_ARRAY, T_AS, T_BREAK, T_CALLABLE, T_CASE, T_CATCH, T_CLASS,
        T_CLONE, T_CONST, T_CONTINUE, T_DECLARE, T_DEFAULT, T_DO, T_ECHO, T_ELSE,
        T_ELSEIF, T_EMPTY, T_ENDDECLARE, T_ENDFOR, T_ENDFOREACH, T_ENDIF, T_ENDSWITCH,
        T_ENDWHILE, T_ENUM, T_EVAL, T_EXIT, T_EXTENDS, T_FINAL, T_FINALLY, T_FN, T_FOR,
        T_FOREACH, T_FUNCTION, T_GLOBAL, T_GOTO, T_IF, T_IMPLEMENTS, T_INCLUDE,
        T_INCLUDE_ONCE, T_INSTANCEOF, T_INSTEADOF, T_INTERFACE, T_ISSET, T_LIST,
        T_LOGICAL_AND, T_LOGICAL_OR, T_LOGICAL_XOR, T_MATCH, T_NAMESPACE, T_NEW,
        T_PRINT, T_PRIVATE, T_PROTECTED, T_PUBLIC, T_READONLY, T_REQUIRE,
        T_REQUIRE_ONCE, T_RETURN, T_STATIC, T_SWITCH, T_THROW, T_TRAIT, T_TRY,
        T_UNSET, T_USE, T_VAR, T_WHILE, T_YIELD, T_YIELD_FROM,
    ];

    /**
     * Declare whether the destination renders escape sequences.
     *
     * Not on ReporterInterface, so a third-party implementation stays valid.
     */
    public function setDecorated(bool $decorated): void
    {
        $this->decorated = $decorated;
    }

    /**
     * @param  Collection<int, ResultInterface>  $results
     * @param  array<string, string>  $gitContext
     */
    public function generate(Collection $results, TriggerSource $triggeredBy = TriggerSource::Manual, array $gitContext = []): AnalysisReport
    {
        $projectIdConfig = config('shieldci.project_id', 'unknown');

        return new AnalysisReport(
            projectId: is_string($projectIdConfig) ? $projectIdConfig : 'unknown',
            laravelVersion: app()->version(),
            packageVersion: $this->getPackageVersion(),
            results: $results,
            totalExecutionTime: $results->sum(fn (ResultInterface $result) => $result->getExecutionTime()),
            analyzedAt: new DateTimeImmutable('now', new \DateTimeZone('UTC')),
            triggeredBy: $triggeredBy,
            metadata: $this->buildMetadata($gitContext),
            configuration: $this->buildConfiguration(),
            proPackageVersion: $this->getProPackageVersion(),
        );
    }

    public function toConsole(AnalysisReport $report): string
    {
        $showRecommendations = config('shieldci.report.show_recommendations', true);
        $showCodeSnippets = config('shieldci.report.show_code_snippets', true);
        $maxIssuesPerCheckRaw = config('shieldci.report.max_issues_per_check', 5);
        $maxIssuesPerCheck = $this->normalizeIntegerConfig($maxIssuesPerCheckRaw, 5);

        $output = [];

        // ASCII Header with color
        $output[] = '';
        $output[] = $this->color('   _____ __    _      __    __________', 'green');
        $output[] = $this->color('  / ___// /_  (_)__  / /___/ / ____/  _/', 'green');
        $output[] = $this->color('  \__ \/ __ \/ / _ \/ / __  / /    / /  ', 'green');
        $output[] = $this->color(' ___/ / / / / /  __/ / /_/ / /____/ /   ', 'green');
        $output[] = $this->color('/____/_/ /_/_/\___/_/\__,_/\____/___/   ', 'green');
        $output[] = '';
        $output[] = '';

        $output[] = 'Please wait while ShieldCI scans your code base...';
        $output[] = '';

        // Group results by category
        $byCategory = $this->groupByCategory($report->results);

        // Filter out categories that only have skipped analyzers (disabled categories)
        // Only show categories that have at least one analyzer that actually ran
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

        // Calculate total from filtered categories only
        $total = 0;
        foreach ($filteredCategories as $results) {
            $total += count($results);
        }

        $current = 0;

        foreach ($filteredCategories as $category => $results) {
            $output[] = '|------------------------------------------';
            $output[] = "| Running {$category} Analyzers";
            $output[] = '|------------------------------------------';
            $output[] = '';

            foreach ($results as $result) {
                $current++;
                $status = $this->getColoredStatusLabel($result->getStatus());
                $metadata = $result->getMetadata();

                // Get name from metadata
                $nameValue = $metadata['name'] ?? null;
                $name = is_string($nameValue) ? $nameValue : $result->getAnalyzerId();

                // Build status line with optional timeToFix
                $statusLine = "{$name}. {$status}";
                $timeToFix = $metadata['timeToFix'] ?? null;
                if ($timeToFix !== null && is_int($timeToFix) && ($result->getStatus()->value === 'failed' || $result->getStatus()->value === 'warning')) {
                    $timeLabel = $timeToFix === 1 ? '1 min' : "{$timeToFix} mins";
                    $statusLine .= ' '.$this->color("({$timeLabel} to fix)", 'gray');
                }

                $suppressedForThis = $report->suppressedIssues[$result->getAnalyzerId()] ?? [];
                if ($suppressedForThis !== []) {
                    $count = count($suppressedForThis);
                    $statusLine .= $this->color(' ('.$count.' '.($count === 1 ? 'issue' : 'issues').' suppressed)', 'gray');
                }

                $output[] = $this->color("Analyzer {$current}/{$total}: ", 'yellow').$statusLine;

                // Show skip reason for skipped analyzers
                if ($result->getStatus()->value === 'skipped') {
                    $output[] = $this->color("  ⊝ {$result->getMessage()}", 'gray');
                    $output[] = '';

                    continue;
                }

                // Show the reason an analyzer could not complete. An errored result
                // carries no issues, so its message is the only place the reason exists.
                if ($result->getStatus()->value === 'error') {
                    $output[] = $this->color("  ⚡ {$result->getMessage()}", 'magenta');
                    $output[] = '';

                    continue;
                }

                // Show detailed info for failed/warning analyzers
                if ($result->getStatus()->value === 'failed' || $result->getStatus()->value === 'warning') {
                    // Use bold for critical failures
                    $isCritical = $result->getStatus()->value === 'failed';
                    $message = $isCritical
                        ? $this->bold($this->color($result->getMessage(), 'red'))
                        : $this->color($result->getMessage(), 'red');

                    $output[] = $message;

                    $issues = $result->getIssues();
                    if (! empty($issues)) {
                        $displayCount = $maxIssuesPerCheck;
                        $previewed = [];

                        // Show issue locations
                        foreach (array_slice($issues, 0, $displayCount) as $issue) {
                            // Show message for application-wide issues without location
                            $displayText = $issue->location === null
                                ? $issue->message
                                : "At {$issue->location}";

                            // Highlight critical issues with background color
                            if ($issue->severity->value === 'critical') {
                                $output[] = $this->color($displayText, 'white', 'bg_red');
                            } else {
                                $output[] = $this->color($displayText, 'magenta');
                            }

                            // One preview per location. This loop walks issues, not the
                            // location groups streamResult() builds, so several issues on the
                            // same line would otherwise repeat the same block.
                            $key = $issue->location === null ? null : (string) $issue->location;

                            if ($showCodeSnippets && $issue->codeSnippet !== null && $key !== null
                                && ! in_array($key, $previewed, true)) {
                                $previewed[] = $key;
                                $output[] = $this->formatCodeSnippet($issue->codeSnippet);
                            }
                        }

                        if (count($issues) > $displayCount) {
                            $remaining = count($issues) - $displayCount;
                            $output[] = $this->color("... and {$remaining} more issue(s).", 'magenta');
                        }

                        // Show all unique recommendations from displayed issues (if recommendations are enabled)
                        if ($showRecommendations) {
                            // Collect all unique recommendations from the displayed issues only
                            $recommendations = [];
                            foreach (array_slice($issues, 0, $displayCount) as $issue) {
                                if (! empty($issue->recommendation) && ! in_array($issue->recommendation, $recommendations, true)) {
                                    $recommendations[] = $issue->recommendation;
                                }
                            }

                            foreach ($recommendations as $recommendation) {
                                // Use italic for recommendations
                                $output[] = $this->italic($recommendation);
                            }
                        }
                    }

                    // Documentation URL if available (with hyperlink support)
                    $docsUrl = $metadata['docsUrl'] ?? null;
                    if (! empty($docsUrl) && is_string($docsUrl)) {
                        $linkText = $this->hyperlink($docsUrl, $docsUrl);
                        $output[] = $this->color('Documentation URL: ', 'cyan').$this->color($linkText, 'cyan');
                    }
                }

                $output[] = '';
            }
        }

        // Report Card
        $output[] = $this->color('Report Card', 'bright_yellow');
        $output[] = $this->color('===========', 'bright_yellow');
        $output[] = '';
        // Passes the unfiltered grouping: generateReportCard() applies the same
        // skipped-category filter itself, and running it twice on the same data was a
        // no-op that read as though the two filters might differ.
        $output[] = $this->generateReportCard($report, $byCategory);
        $output[] = '';

        return implode(PHP_EOL, $output);
    }

    /**
     * Group results by category.
     *
     * @param  Collection<int, ResultInterface>  $results
     * @return array<string, array<int, ResultInterface>>
     */
    private function groupByCategory(Collection $results): array
    {
        $grouped = [];

        foreach ($results as $result) {
            $metadata = $result->getMetadata();

            // Extract category from metadata
            $category = $metadata['category'] ?? 'Unknown';

            // If category is an enum, get its value
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
                    // If category value doesn't match any enum case, fall back to formatted string
                    $category = ucfirst(str_replace('_', ' ', $categoryValue));
                }
            } else {
                $category = 'Unknown';
            }

            if (! isset($grouped[$category])) {
                $grouped[$category] = [];
            }

            $grouped[$category][] = $result;
        }

        return $grouped;
    }

    /**
     * Get colored status label for display.
     */
    private function getColoredStatusLabel(Status $status): string
    {
        return match ($status->value) {
            'passed' => $this->color('Passed', 'green'),
            'failed' => $this->color('Failed', 'red'),
            'warning' => $this->color('Warning', 'yellow'),
            'skipped' => $this->color('Not Applicable', 'cyan'),
            'error' => $this->color('Error', 'magenta'),
            default => 'Unknown',
        };
    }

    /**
     * Apply ANSI color to text.
     */
    private function color(string $text, string $color, ?string $background = null): string
    {
        $colors = [
            'black' => '0;30',
            'red' => '0;31',
            'green' => '0;32',
            'yellow' => '0;33',
            'blue' => '0;34',
            'magenta' => '0;35',
            'cyan' => '0;36',
            'white' => '0;37',
            'gray' => '0;90',
            'bright_red' => '1;31',
            'bright_green' => '1;32',
            'bright_yellow' => '1;33',
        ];

        $backgrounds = [
            'bg_black' => '40',
            'bg_red' => '41',
            'bg_green' => '42',
            'bg_yellow' => '43',
            'bg_blue' => '44',
            'bg_magenta' => '45',
            'bg_cyan' => '46',
            'bg_white' => '47',
        ];

        if (! $this->decorated || ! isset($colors[$color])) {
            return $text;
        }

        $code = $colors[$color];

        // Add background color if specified
        if ($background !== null && isset($backgrounds[$background])) {
            $code .= ';'.$backgrounds[$background];
        }

        return "\033[{$code}m{$text}\033[0m";
    }

    /**
     * Make text bold.
     */
    private function bold(string $text): string
    {
        return $this->decorated ? "\033[1m{$text}\033[0m" : $text;
    }

    /**
     * Get visible width of a string (strips ANSI color codes).
     */
    private function visibleWidth(string $text): int
    {
        // Remove ANSI escape sequences
        $stripped = preg_replace('/\033\[[0-9;]*m/', '', $text);
        if (! is_string($stripped)) {
            $stripped = '';
        }

        return mb_strwidth($stripped, 'UTF-8');
    }

    /**
     * Pad a string to a specific visible width (accounts for ANSI codes).
     */
    private function padVisible(string $text, int $width, string $padString = ' ', int $padType = STR_PAD_RIGHT): string
    {
        $visibleLen = $this->visibleWidth($text);
        $paddingNeeded = max(0, $width - $visibleLen);

        if ($padType === STR_PAD_LEFT) {
            return str_repeat($padString, $paddingNeeded).$text;
        } elseif ($padType === STR_PAD_BOTH) {
            $left = (int) floor($paddingNeeded / 2);
            $right = $paddingNeeded - $left;

            return str_repeat($padString, $left).$text.str_repeat($padString, $right);
        }

        return $text.str_repeat($padString, $paddingNeeded);
    }

    /**
     * Make text italic.
     */
    private function italic(string $text): string
    {
        return $this->decorated ? "\033[3m{$text}\033[0m" : $text;
    }

    /**
     * Create a clickable hyperlink (OSC 8).
     * Supported in: iTerm2, GNOME Terminal, Konsole, Windows Terminal, VS Code terminal
     * Falls back to plain text in CI environments and unsupported terminals.
     */
    private function hyperlink(string $url, ?string $text = null): string
    {
        $displayText = $text ?? $url;

        if (! $this->supportsHyperlinks()) {
            return $displayText;
        }

        return "\033]8;;{$url}\033\\{$displayText}\033]8;;\033\\";
    }

    /**
     * Detect whether the current terminal supports OSC 8 hyperlinks.
     */
    private function supportsHyperlinks(): bool
    {
        // CI environments don't support OSC 8 hyperlinks
        if (getenv('CI') !== false) {
            return false;
        }

        // Known terminals that support OSC 8
        $termProgram = (string) (getenv('TERM_PROGRAM') ?: '');
        if (in_array($termProgram, ['iTerm.app', 'WezTerm', 'vscode'], true)) {
            return true;
        }

        // VTE-based terminals (GNOME Terminal, Tilix, etc.)
        if (getenv('VTE_VERSION') !== false) {
            return true;
        }

        // Windows Terminal
        if (getenv('WT_SESSION') !== false) {
            return true;
        }

        return false;
    }

    /**
     * Render the report card on its own.
     *
     * The streaming path prints only this table, having already streamed each result, so it
     * needs an entry point that does its own grouping. AnalyzeCommand used to carry a second
     * copy of the whole table for that. The two agreed on every number and disagreed on
     * colour, so the same run rendered differently depending on which path produced it.
     *
     * Not on ReporterInterface, so a third-party implementation stays valid.
     */
    public function reportCard(AnalysisReport $report): string
    {
        return $this->generateReportCard($report, $this->groupByCategory($report->results));
    }

    /**
     * Generate report card table.
     *
     * @param  array<string, array<int, ResultInterface>>  $byCategory
     */
    private function generateReportCard(AnalysisReport $report, array $byCategory): string
    {
        $table = [];

        // Filter out categories that only have skipped analyzers (disabled categories)
        // Only show categories that have at least one analyzer that actually ran
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

        // If no categories have non-skipped analyzers, show all categories (edge case)
        if (empty($filteredCategories)) {
            $filteredCategories = $byCategory;
        }

        // Header
        $categories = array_keys($filteredCategories);
        $table[] = '+----------------+'.str_repeat('----------------+', count($categories)).'------------+';

        // Build header row with colored labels
        $statusCell = $this->padVisible(' '.$this->color('Status', 'green'), 16);
        $categoryCells = array_map(function ($c) {
            return $this->padVisible(' '.$this->color($c, 'green'), 16);
        }, $categories);
        $totalCell = $this->padVisible('     '.$this->color('Total', 'green'), 12);

        $table[] = '|'.$statusCell.'|'.implode('|', $categoryCells).'|'.$totalCell.'|';
        $table[] = '+----------------+'.str_repeat('----------------+', count($categories)).'------------+';

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

        // Calculate total from filtered categories only
        $totalAll = 0;
        foreach ($filteredCategories as $results) {
            $totalAll += count($results);
        }

        // Pre-compute totalSkipped so other rows can exclude it from their denominators
        $totalSkipped = 0;
        foreach ($categories as $category) {
            $totalSkipped += $stats[$category]['skipped'];
        }

        // Passed row
        $passedRow = '| '.$this->padVisible($this->color('Passed', 'green'), 14).' |';
        $totalPassed = 0;
        foreach ($categories as $category) {
            $passed = $stats[$category]['passed'];
            $denominator = $stats[$category]['total'] - $stats[$category]['skipped'];
            $pct = $denominator > 0 ? round(($passed / $denominator) * 100) : 0;
            $passedRow .= str_pad("   {$passed}  ({$pct}%)", 16).'|';
            $totalPassed += $passed;
        }
        $totalDenominator = $totalAll - $totalSkipped;
        $totalPct = $totalDenominator > 0 ? round(($totalPassed / $totalDenominator) * 100) : 0;
        $passedRow .= str_pad(" {$totalPassed}  ({$totalPct}%)", 12).'|';
        $table[] = $passedRow;

        // Failed row
        $failedRow = '| '.$this->padVisible($this->color('Failed', 'red'), 14).' |';
        $totalFailed = 0;
        foreach ($categories as $category) {
            $failed = $stats[$category]['failed'];
            $denominator = $stats[$category]['total'] - $stats[$category]['skipped'];
            $pct = $denominator > 0 ? round(($failed / $denominator) * 100) : 0;
            $failedRow .= str_pad("    {$failed}   ({$pct}%)", 16).'|';
            $totalFailed += $failed;
        }
        $totalPct = $totalDenominator > 0 ? round(($totalFailed / $totalDenominator) * 100) : 0;
        $failedRow .= str_pad("  {$totalFailed}  ({$totalPct}%)", 12).'|';
        $table[] = $failedRow;

        // Warning row
        $warningRow = '| '.$this->padVisible($this->color('Warning', 'yellow'), 14).' |';
        $totalWarnings = 0;
        foreach ($categories as $category) {
            $warnings = $stats[$category]['warning'];
            $denominator = $stats[$category]['total'] - $stats[$category]['skipped'];
            $pct = $denominator > 0 ? round(($warnings / $denominator) * 100) : 0;
            $warningRow .= str_pad("    {$warnings}   ({$pct}%)", 16).'|';
            $totalWarnings += $warnings;
        }
        $totalPct = $totalDenominator > 0 ? round(($totalWarnings / $totalDenominator) * 100) : 0;
        $warningRow .= str_pad("  {$totalWarnings}  ({$totalPct}%)", 12).'|';
        $table[] = $warningRow;

        // Error row
        $errorRow = '| '.$this->padVisible($this->color('Error', 'bright_red'), 14).' |';
        $totalErrors = 0;
        foreach ($categories as $category) {
            $errors = $stats[$category]['error'];
            $denominator = $stats[$category]['total'] - $stats[$category]['skipped'];
            $pct = $denominator > 0 ? round(($errors / $denominator) * 100) : 0;
            $errorRow .= str_pad("    {$errors}   ({$pct}%)", 16).'|';
            $totalErrors += $errors;
        }
        $totalPct = $totalDenominator > 0 ? round(($totalErrors / $totalDenominator) * 100) : 0;
        $errorRow .= str_pad("  {$totalErrors}   ({$totalPct}%)", 12).'|';
        $table[] = $errorRow;

        // Not Applicable row last, no percentages
        $skippedRow = '| '.$this->padVisible($this->color('Not Applicable', 'gray'), 14).' |';
        foreach ($categories as $category) {
            $skipped = $stats[$category]['skipped'];
            $skippedRow .= str_pad("    {$skipped}      ", 16).'|';
        }
        $skippedRow .= str_pad("  {$totalSkipped}      ", 12).'|';
        $table[] = $skippedRow;

        // Footer
        $table[] = '+----------------+'.str_repeat('----------------+', count($categories)).'------------+';

        return implode(PHP_EOL, $table);
    }

    public function toJson(AnalysisReport $report): string
    {
        return json_encode($report->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) ?: '';
    }

    public function toApi(AnalysisReport $report): array
    {
        return $report->toArray();
    }

    protected function getPackageVersion(): string
    {
        if (class_exists(InstalledVersions::class)) {
            $version = InstalledVersions::getPrettyVersion('shieldci/laravel');
            if ($version !== null) {
                return $version;
            }
        }

        return 'dev';
    }

    protected function getProPackageVersion(): ?string
    {
        if (class_exists(InstalledVersions::class) && InstalledVersions::isInstalled('shieldci/laravel-pro')) {
            return InstalledVersions::getPrettyVersion('shieldci/laravel-pro');
        }

        return null;
    }

    /**
     * Build the effective configuration snapshot for the report payload.
     *
     * Captured inside generate() so runtime mutations (e.g. --ci sets shieldci.ci_mode)
     * are reflected accurately.
     *
     * @return array<string, mixed>
     */
    private function buildConfiguration(): array
    {
        // Effective, not configured: AnalyzerManager substitutes the shipped defaults for an
        // unusable paths.analyze, so reporting the raw [] would name directories the run did
        // not walk and omit the ones it did.
        $rawPaths = config('shieldci.paths.analyze', []);
        $configuredPaths = is_array($rawPaths) ? array_values(array_filter($rawPaths, 'is_string')) : [];
        $paths = $configuredPaths === [] ? AnalyzerManager::DEFAULT_ANALYZE_PATHS : $configuredPaths;

        $rawExcluded = config('shieldci.excluded_paths', []);
        $excludedPaths = is_array($rawExcluded) ? array_values(array_filter($rawExcluded, 'is_string')) : [];

        $rawAnalyzers = config('shieldci.analyzers', []);
        $categories = [];
        if (is_array($rawAnalyzers)) {
            foreach ($rawAnalyzers as $category => $settings) {
                if (is_string($category) && is_array($settings)) {
                    $enabled = $settings['enabled'] ?? true;
                    $categories[$category] = (bool) $enabled;
                }
            }
        }

        $rawDisabled = config('shieldci.disabled_analyzers', []);
        $disabledAnalyzers = is_array($rawDisabled) ? array_values(array_filter($rawDisabled, 'is_string')) : [];

        $rawDontReport = config('shieldci.dont_report', []);
        $dontReport = is_array($rawDontReport) ? array_values(array_filter($rawDontReport, 'is_string')) : [];

        $rawIgnoreErrors = config('shieldci.ignore_errors', []);
        $ignoreErrors = is_array($rawIgnoreErrors) ? $rawIgnoreErrors : [];

        $rawEnvMapping = config('shieldci.environment_mapping', []);
        $environmentMapping = is_array($rawEnvMapping) ? $rawEnvMapping : [];

        $rawCiMode = config('shieldci.ci_mode', false);
        $ciMode = (bool) $rawCiMode;

        $rawCiAnalyzers = config('shieldci.ci_mode_analyzers', []);
        $ciModeAnalyzers = is_array($rawCiAnalyzers) ? array_values(array_filter($rawCiAnalyzers, 'is_string')) : [];

        $rawCiExclude = config('shieldci.ci_mode_exclude_analyzers', []);
        $ciModeExcludeAnalyzers = is_array($rawCiExclude) ? array_values(array_filter($rawCiExclude, 'is_string')) : [];

        $rawTimeout = config('shieldci.timeout', 300);
        $timeout = is_int($rawTimeout) ? $rawTimeout : (is_numeric($rawTimeout) ? (int) $rawTimeout : 300);

        $rawMemoryLimit = config('shieldci.memory_limit', '512M');
        $memoryLimit = is_string($rawMemoryLimit) ? $rawMemoryLimit : '512M';

        $rawFailOn = config('shieldci.fail_on', 'high');
        $failOn = is_string($rawFailOn) ? $rawFailOn : 'high';

        $rawThreshold = config('shieldci.fail_threshold', null);
        $failThreshold = is_int($rawThreshold) ? $rawThreshold : (is_numeric($rawThreshold) ? (int) $rawThreshold : null);

        return [
            'paths' => $paths,
            'excluded_paths' => $excludedPaths,
            'categories' => $categories,
            'disabled_analyzers' => $disabledAnalyzers,
            'dont_report' => $dontReport,
            'ignore_errors' => $ignoreErrors,
            'environment_mapping' => $environmentMapping,
            'ci_mode' => $ciMode,
            'ci_mode_analyzers' => $ciModeAnalyzers,
            'ci_mode_exclude_analyzers' => $ciModeExcludeAnalyzers,
            'timeout' => $timeout,
            'memory_limit' => $memoryLimit,
            'fail_on' => $failOn,
            'fail_threshold' => $failThreshold,
        ];
    }

    /**
     * Build the metadata array for the report payload.
     *
     * @param  array<string, string>  $gitContext
     * @return array<string, string>
     */
    private function buildMetadata(array $gitContext): array
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
     * Resolve the current environment, applying shieldci.environment_mapping if configured.
     *
     * Mirrors the logic in analyzers-core AbstractAnalyzer::getEnvironment().
     */
    private function resolveEnvironment(): string
    {
        $rawEnv = config('app.env');
        if (! is_string($rawEnv) || $rawEnv === '') {
            $rawEnv = 'production';
        }

        $mapping = config('shieldci.environment_mapping', []);
        if (is_array($mapping) && isset($mapping[$rawEnv]) && is_string($mapping[$rawEnv])) {
            return $mapping[$rawEnv];
        }

        return $rawEnv;
    }

    /**
     * Output the header for streaming mode.
     */
    public function streamHeader(): string
    {
        $output = [];

        // ASCII Header with color
        $output[] = '';
        $output[] = $this->color('   _____ __    _      __    __________', 'green');
        $output[] = $this->color('  / ___// /_  (_)__  / /___/ / ____/  _/', 'green');
        $output[] = $this->color('  \__ \/ __ \/ / _ \/ / __  / /    / /  ', 'green');
        $output[] = $this->color(' ___/ / / / / /  __/ / /_/ / /____/ /   ', 'green');
        $output[] = $this->color('/____/_/ /_/_/\___/_/\__,_/\____/___/   ', 'green');
        $output[] = '';
        $output[] = '';
        $output[] = 'Please wait while ShieldCI scans your code base...';
        $output[] = '';

        return implode(PHP_EOL, $output);
    }

    /**
     * Output a category header for streaming mode.
     */
    public function streamCategoryHeader(string $category): string
    {
        $output = [];
        $output[] = '|------------------------------------------';
        $output[] = "| Running {$category} Analyzers";
        $output[] = '|------------------------------------------';
        $output[] = '';

        return implode(PHP_EOL, $output);
    }

    /**
     * Stream a single result to console as it completes.
     */
    public function streamResult(
        ResultInterface $result,
        int $current,
        int $total,
        string $category
    ): string {
        $showRecommendations = config('shieldci.report.show_recommendations', true);
        $showCodeSnippets = config('shieldci.report.show_code_snippets', true);
        $maxIssuesPerCheckRaw = config('shieldci.report.max_issues_per_check', 5);
        $maxIssuesPerCheck = $this->normalizeIntegerConfig($maxIssuesPerCheckRaw, 5);

        $output = [];

        $status = $this->getColoredStatusLabel($result->getStatus());
        $metadata = $result->getMetadata();

        // Get name from metadata
        $nameValue = $metadata['name'] ?? null;
        $name = is_string($nameValue) ? $nameValue : $result->getAnalyzerId();

        // Build status line with optional timeToFix
        $statusLine = "{$name}. {$status}";
        $timeToFix = $metadata['timeToFix'] ?? null;
        if ($timeToFix !== null && is_int($timeToFix) && ($result->getStatus()->value === 'failed' || $result->getStatus()->value === 'warning')) {
            $timeLabel = $timeToFix === 1 ? '1 min' : "{$timeToFix} mins";
            $statusLine .= ' '.$this->color("({$timeLabel} to fix)", 'gray');
        }

        $output[] = $this->color("Analyzer {$current}/{$total}: ", 'yellow').$statusLine;

        // Show skip reason for skipped analyzers
        if ($result->getStatus()->value === 'skipped') {
            $output[] = $this->color("  ⊝ {$result->getMessage()}", 'gray');
            $output[] = '';

            return implode(PHP_EOL, $output);
        }

        // Show the reason an analyzer could not complete. An errored result carries no
        // issues, so its message is the only place the reason exists.
        if ($result->getStatus()->value === 'error') {
            $output[] = $this->color("  ⚡ {$result->getMessage()}", 'magenta');
            $output[] = '';

            return implode(PHP_EOL, $output);
        }

        // Show detailed info for failed/warning analyzers
        if ($result->getStatus()->value === 'failed' || $result->getStatus()->value === 'warning') {
            // Use bold for critical failures
            $isCritical = $result->getStatus()->value === 'failed';
            $message = $isCritical
                ? $this->bold($this->color($result->getMessage(), 'red'))
                : $this->color($result->getMessage(), 'red');

            $output[] = $message;

            $issues = $result->getIssues();
            if (! empty($issues)) {
                $displayCount = $maxIssuesPerCheck;

                // Group issues by location to avoid duplicate location lines
                $issuesByLocation = $this->groupIssuesByLocation(array_slice($issues, 0, $displayCount));

                // Show issues grouped by location
                foreach ($issuesByLocation as $locationKey => $locationIssues) {
                    $firstIssue = $locationIssues[0];

                    // Show location line (or message for application-wide issues)
                    if ($firstIssue->location === null) {
                        $locationText = $firstIssue->message;
                    } else {
                        $locationText = "At {$firstIssue->location}";
                    }

                    // Highlight critical issues with background color
                    $hasCritical = false;
                    foreach ($locationIssues as $issue) {
                        if ($issue->severity->value === 'critical') {
                            $hasCritical = true;
                            break;
                        }
                    }

                    if ($hasCritical) {
                        $output[] = $this->color($locationText, 'white', 'bg_red');
                    } else {
                        $output[] = $this->color($locationText, 'magenta');
                    }

                    if ($showCodeSnippets && $firstIssue->codeSnippet !== null) {
                        $output[] = $this->formatCodeSnippet($firstIssue->codeSnippet);
                    }

                    // Show individual messages when grouped (multiple at same location) or
                    // when the location has no line number (e.g. package-lock.json) and
                    // the message carries the only meaningful detail
                    if ($firstIssue->location !== null &&
                        (count($locationIssues) > 1 || $firstIssue->location->line === null)) {
                        foreach ($locationIssues as $issue) {
                            $output[] = $this->color("  → {$issue->message}", 'gray');
                        }
                    }
                }

                if (count($issues) > $displayCount) {
                    $remaining = count($issues) - $displayCount;
                    $output[] = $this->color("... and {$remaining} more issue(s).", 'magenta');
                }

                // Show all unique recommendations from displayed issues (if recommendations are enabled)
                if ($showRecommendations) {
                    // Collect all unique recommendations from the displayed issues only
                    $recommendations = [];
                    foreach (array_slice($issues, 0, $displayCount) as $issue) {
                        if (! empty($issue->recommendation) && ! in_array($issue->recommendation, $recommendations, true)) {
                            $recommendations[] = $issue->recommendation;
                        }
                    }

                    foreach ($recommendations as $recommendation) {
                        // Use italic for recommendations
                        $output[] = $this->italic($recommendation);
                    }
                }
            }

            // Documentation URL if available (with hyperlink support)
            $docsUrl = $metadata['docsUrl'] ?? null;
            if (! empty($docsUrl) && is_string($docsUrl)) {
                $linkText = $this->hyperlink($docsUrl, $docsUrl);
                $output[] = $this->color('Documentation URL: ', 'cyan').$this->color($linkText, 'cyan');
            }
        }

        $output[] = '';

        return implode(PHP_EOL, $output);
    }

    /**
     * Render the code around an issue.
     *
     * Three things can turn the colour off, and they are not the same question. The
     * destination may not render escape sequences at all, which isDecorated() answers for
     * the whole run and which this class receives through setDecorated(); that one is not
     * negotiable. snippet_plain_mode is a preference for a plain block even on a terminal,
     * so the lines survive a copy into an issue tracker. snippet_syntax_highlighting turns
     * off per token colour only, leaving the gutter and the target marker to do their job.
     */
    private function formatCodeSnippet(CodeSnippet $snippet): string
    {
        $lines = $snippet->getLines();

        if ($lines === []) {
            return '';
        }

        $plain = ! $this->decorated || (bool) config('shieldci.report.snippet_plain_mode', false);
        $highlight = ! $plain && (bool) config('shieldci.report.snippet_syntax_highlighting', true);
        $highlighted = $highlight ? $this->highlightPhpLines($lines) : [];

        $targetLine = $snippet->getTargetLine();

        $output = [''];
        $output[] = $plain ? '  Code Preview:' : $this->color('  Code Preview:', 'gray');

        foreach ($lines as $lineNumber => $lineContent) {
            $isTarget = $lineNumber === $targetLine;

            if ($plain) {
                $output[] = '  '.sprintf('%4d', $lineNumber).($isTarget ? ' → ' : '   ').$lineContent;

                continue;
            }

            $gutter = $this->color(sprintf('%4d', $lineNumber), $isTarget ? 'red' : 'gray');
            $marker = $isTarget ? $this->color(' → ', 'red') : '   ';

            if ($isTarget) {
                // The target line carries the background, so it is never token coloured:
                // two schemes on one line reads as damage rather than emphasis.
                $content = $this->color($lineContent, 'white', 'bg_red');
            } elseif ($highlight) {
                $content = $highlighted[$lineNumber] ?? $lineContent;
            } else {
                $content = $this->color($lineContent, 'gray');
            }

            $output[] = "  {$gutter}{$marker}{$content}";
        }

        $output[] = '';

        return implode(PHP_EOL, $output);
    }

    /**
     * Token colour a block of source, answering the same line numbers it was given.
     *
     * The block is tokenised in one pass rather than line by line, because a string or a
     * comment spanning several lines only tokenises correctly when the tokeniser can see
     * all of it. A snippet is a fragment, so it can begin or end mid construct and
     * CodeSnippet truncates at 250 characters; token_get_all() is lenient about both
     * without TOKEN_PARSE, and anything it cannot place comes back uncoloured.
     *
     * This replaces a regex implementation that ran five passes in sequence, each matching
     * inside the escape sequences its predecessors had written: the number pass rewrote the
     * 0 inside every "\033[0;32m", so the terminal printed a literal ";32m", and the
     * keyword pass recoloured keywords inside already yellow strings. Partitioning the
     * input once retires the whole class of bug rather than reordering it.
     *
     * @param  non-empty-array<int, string>  $lines
     * @return array<int, string>
     */
    private function highlightPhpLines(array $lines): array
    {
        $firstLine = array_key_first($lines);

        // token_get_all() needs an open tag, and counts it as line 1, so the first line of
        // the block is line 2 of what the tokeniser sees.
        $tokens = @token_get_all("<?php\n".implode("\n", $lines));
        $offset = $firstLine - 2;

        $rendered = [];
        $line = 1;

        foreach ($tokens as $token) {
            if (is_array($token)) {
                $id = $token[0];
                $text = $token[1];
                $line = $token[2];
            } else {
                $id = null;
                $text = $token;
            }

            $color = $this->tokenColor($id, $text);

            foreach (explode("\n", $text) as $index => $part) {
                $number = $line + $index + $offset;
                $rendered[$number] = ($rendered[$number] ?? '')
                    .($part === '' || $color === null ? $part : $this->color($part, $color));
            }

            // An array token reports where it starts; a single character token has no line
            // of its own and continues from wherever the last one ended.
            $line += substr_count($text, "\n");
        }

        return array_intersect_key($rendered, $lines);
    }

    /**
     * The colour the docs promise for a token, or null to leave it alone.
     *
     * Keywords are matched by token id rather than by word, which is the whole point of
     * asking the tokeniser: `class` inside a string arrives as T_CONSTANT_ENCAPSED_STRING
     * and a method named `list` arrives as T_STRING, so neither can be mistaken for the
     * keyword it spells.
     */
    private function tokenColor(?int $id, string $text): ?string
    {
        if ($id === null || trim($text) === '') {
            return null;
        }

        return match (true) {
            $id === T_VARIABLE => 'green',
            $id === T_CONSTANT_ENCAPSED_STRING, $id === T_ENCAPSED_AND_WHITESPACE => 'yellow',
            $id === T_LNUMBER, $id === T_DNUMBER => 'magenta',
            $id === T_COMMENT, $id === T_DOC_COMMENT => 'gray',
            in_array($id, self::KEYWORD_TOKENS, true) => 'cyan',
            default => null,
        };
    }

    /**
     * Normalize config value to integer, handling both int and string values from .env.
     *
     * @param  mixed  $value
     */
    private function normalizeIntegerConfig($value, int $default): int
    {
        if (is_int($value)) {
            return $value;
        }

        if (is_string($value)) {
            // Handle string integers (including negative numbers)
            // ctype_digit only works for positive numbers, so we use filter_var for full support
            $filtered = filter_var($value, FILTER_VALIDATE_INT);
            if ($filtered !== false) {
                return $filtered;
            }
        }

        return $default;
    }

    /**
     * Group issues by their location to avoid duplicate location lines in output.
     *
     * When multiple issues occur on the same line (e.g., multiple PHPStan errors),
     * this groups them so we show the location once, with individual messages underneath.
     *
     * @param  array<Issue>  $issues
     * @return array<string, array<Issue>>
     */
    private function groupIssuesByLocation(array $issues): array
    {
        $grouped = [];

        foreach ($issues as $issue) {
            // Create a unique key for the location
            $locationKey = $issue->location === null
                ? 'no-location-'.$issue->message
                : (string) $issue->location;

            if (! isset($grouped[$locationKey])) {
                $grouped[$locationKey] = [];
            }

            $grouped[$locationKey][] = $issue;
        }

        return $grouped;
    }
}
