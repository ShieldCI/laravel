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
        $showCodeSnippets = config('shieldci.report.show_code_snippets', true);

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
        $total = $report->results->count();
        $current = 0;

        foreach ($byCategory as $category => $results) {
            $output[] = '|------------------------------------------';
            $output[] = "| Running {$category} Checks";
            $output[] = '|------------------------------------------';
            $output[] = '';

            foreach ($results as $result) {
                $current++;
                $status = $this->getColoredStatusLabel($result->getStatus());
                $metadata = $result->getMetadata();

                // Get name from metadata
                $name = $metadata['name'] ?? $result->getAnalyzerId();

                $output[] = $this->color("Check {$current}/{$total}: ", 'yellow')."{$name}. {$status}";

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
                        $displayCount = $showCodeSnippets ? 3 : 5;

                        // Show issue locations
                        foreach (array_slice($issues, 0, $displayCount) as $issue) {
                            // Highlight critical issues with background color
                            if (isset($issue->severity) && $issue->severity->value === 'critical') {
                                $output[] = $this->color("At {$issue->location}.", 'white', 'bg_red');
                            } else {
                                $output[] = $this->color("At {$issue->location}.", 'magenta');
                            }
                        }

                        if (count($issues) > $displayCount) {
                            $remaining = count($issues) - $displayCount;
                            $output[] = $this->color("... and {$remaining} more issue(s).", 'magenta');
                        }

                        // Show one recommendation for all issues (if recommendations are enabled)
                        if ($showRecommendations) {
                            // Get the first non-empty recommendation
                            $recommendation = null;
                            foreach ($issues as $issue) {
                                if (! empty($issue->recommendation)) {
                                    $recommendation = $issue->recommendation;
                                    break;
                                }
                            }

                            if ($recommendation !== null) {
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
        $output[] = 'Report Card';
        $output[] = '===========';
        $output[] = '';
        $output[] = $this->generateReportCard($report, $byCategory);
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
            if (is_object($category) && method_exists($category, '__toString')) {
                $category = (string) $category;
            } elseif (is_object($category) && isset($category->value)) {
                $category = $category->value;
            }

            // Ensure category is a string before formatting
            if (! is_string($category)) {
                $category = 'Unknown';
            }

            // Format category name
            $category = ucfirst($category);
            $category = str_replace('_', ' ', $category);

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

        // Header
        $categories = array_keys($byCategory);
        $table[] = '+----------------+'.str_repeat('-------------+', count($categories)).'-----------+';
        $table[] = '| Status         |'.implode('|', array_map(fn ($c) => str_pad(' '.$c, 13), $categories)).'|     Total |';
        $table[] = '+----------------+'.str_repeat('-------------+', count($categories)).'-----------+';

        // Calculate stats per category
        $stats = [];
        foreach ($byCategory as $category => $results) {
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

        // Passed row
        $passedRow = '| Passed         |';
        $totalPassed = 0;
        foreach ($categories as $category) {
            $passed = $stats[$category]['passed'];
            $total = $stats[$category]['total'];
            $pct = $total > 0 ? round(($passed / $total) * 100) : 0;
            $passedRow .= str_pad("   {$passed}  ({$pct}%)", 13).'|';
            $totalPassed += $passed;
        }
        $totalAll = $report->results->count();
        $totalPct = $totalAll > 0 ? round(($totalPassed / $totalAll) * 100) : 0;
        $passedRow .= str_pad(" {$totalPassed}  ({$totalPct}%)", 11).'|';
        $table[] = $passedRow;

        // Failed row
        $failedRow = '| Failed         |';
        $totalFailed = 0;
        foreach ($categories as $category) {
            $failed = $stats[$category]['failed'];
            $total = $stats[$category]['total'];
            $pct = $total > 0 ? round(($failed / $total) * 100) : 0;
            $failedRow .= str_pad("    {$failed}   ({$pct}%)", 13).'|';
            $totalFailed += $failed;
        }
        $totalPct = $totalAll > 0 ? round(($totalFailed / $totalAll) * 100) : 0;
        $failedRow .= str_pad("  {$totalFailed}  ({$totalPct}%)", 11).'|';
        $table[] = $failedRow;

        // Not Applicable row
        $skippedRow = '| Not Applicable |';
        $totalSkipped = 0;
        foreach ($categories as $category) {
            $skipped = $stats[$category]['skipped'];
            $total = $stats[$category]['total'];
            $pct = $total > 0 ? round(($skipped / $total) * 100) : 0;
            $skippedRow .= str_pad("    {$skipped}   ({$pct}%)", 13).'|';
            $totalSkipped += $skipped;
        }
        $totalPct = $totalAll > 0 ? round(($totalSkipped / $totalAll) * 100) : 0;
        $skippedRow .= str_pad("  {$totalSkipped}   ({$totalPct}%)", 11).'|';
        $table[] = $skippedRow;

        // Error row
        $errorRow = '| Error          |';
        $totalErrors = 0;
        foreach ($categories as $category) {
            $errors = $stats[$category]['error'];
            $total = $stats[$category]['total'];
            $pct = $total > 0 ? round(($errors / $total) * 100) : 0;
            $errorRow .= str_pad("    {$errors}   ({$pct}%)", 13).'|';
            $totalErrors += $errors;
        }
        $totalPct = $totalAll > 0 ? round(($totalErrors / $totalAll) * 100) : 0;
        $errorRow .= str_pad("  {$totalErrors}   ({$totalPct}%)", 11).'|';
        $table[] = $errorRow;

        // Footer
        $table[] = '+----------------+'.str_repeat('-------------+', count($categories)).'-----------+';

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
            $composer = json_decode(file_get_contents($composerPath), true);

            return $composer['version'] ?? 'dev';
        }

        return 'dev';
    }
}
