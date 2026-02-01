<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use DateTimeImmutable;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Support\FileParser;
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
            laravelVersion: app()->version(),
            packageVersion: $this->getPackageVersion(),
            results: $results,
            totalExecutionTime: $results->sum('executionTime'),
            analyzedAt: new DateTimeImmutable,
        );
    }

    public function toConsole(AnalysisReport $report): string
    {
        $showRecommendations = config('shieldci.report.show_recommendations', true);
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
                $name = $metadata['name'] ?? $result->getAnalyzerId();

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

                        // Show issue locations
                        foreach (array_slice($issues, 0, $displayCount) as $issue) {
                            // Show message for application-wide issues without location
                            $displayText = $issue->location === null
                                ? $issue->message
                                : "At {$issue->location}";

                            // Highlight critical issues with background color
                            if (isset($issue->severity) && $issue->severity->value === 'critical') {
                                $output[] = $this->color($displayText, 'white', 'bg_red');
                            } else {
                                $output[] = $this->color($displayText, 'magenta');
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
        $output[] = $this->generateReportCard($report, $filteredCategories);
        $output[] = '';

        return implode(PHP_EOL, $output);
    }

    /**
     * Group results by category.
     *
     * @param  Collection<int, \ShieldCI\AnalyzersCore\Contracts\ResultInterface>  $results
     * @return array<string, array<int, \ShieldCI\AnalyzersCore\Contracts\ResultInterface>>
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
    private function getColoredStatusLabel(\ShieldCI\AnalyzersCore\Enums\Status $status): string
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

        if (! isset($colors[$color])) {
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
        return "\033[1m{$text}\033[0m";
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
        return "\033[3m{$text}\033[0m";
    }

    /**
     * Create a clickable hyperlink (OSC 8).
     * Supported in: iTerm2, GNOME Terminal, Konsole, Windows Terminal, VS Code terminal
     */
    private function hyperlink(string $url, ?string $text = null): string
    {
        $displayText = $text ?? $url;

        return "\033]8;;{$url}\033\\{$displayText}\033]8;;\033\\";
    }

    /**
     * Generate report card table.
     *
     * @param  array<string, array<int, \ShieldCI\AnalyzersCore\Contracts\ResultInterface>>  $byCategory
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

        // Passed row
        $passedRow = '| Passed         |';
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

        // Failed row
        $failedRow = '| Failed         |';
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

        // Warning row
        $warningRow = '| Warning        |';
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

        // Not Applicable row
        $skippedRow = '| Not Applicable |';
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

        // Error row
        $errorRow = '| Error          |';
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

        return implode(PHP_EOL, $table);
    }

    public function toJson(AnalysisReport $report): string
    {
        return json_encode($report->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    protected function getPackageVersion(): string
    {
        $composerPath = __DIR__.'/../../composer.json';

        if (file_exists($composerPath)) {
            $content = FileParser::readFile($composerPath);
            if ($content !== null) {
                $composer = json_decode($content, true);

                return is_array($composer) && isset($composer['version']) ? $composer['version'] : 'dev';
            }
        }

        return 'dev';
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
        \ShieldCI\AnalyzersCore\Contracts\ResultInterface $result,
        int $current,
        int $total,
        string $category
    ): string {
        $showRecommendations = config('shieldci.report.show_recommendations', true);
        $maxIssuesPerCheckRaw = config('shieldci.report.max_issues_per_check', 5);
        $maxIssuesPerCheck = $this->normalizeIntegerConfig($maxIssuesPerCheckRaw, 5);

        $output = [];

        $status = $this->getColoredStatusLabel($result->getStatus());
        $metadata = $result->getMetadata();

        // Get name from metadata
        $name = $metadata['name'] ?? $result->getAnalyzerId();

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

                // Show issue locations
                foreach (array_slice($issues, 0, $displayCount) as $issue) {
                    // Show message for application-wide issues without location
                    $displayText = $issue->location === null
                        ? $issue->message
                        : "At {$issue->location}";

                    // Highlight critical issues with background color
                    if (isset($issue->severity) && $issue->severity->value === 'critical') {
                        $output[] = $this->color($displayText, 'white', 'bg_red');
                    } else {
                        $output[] = $this->color($displayText, 'magenta');
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
}
