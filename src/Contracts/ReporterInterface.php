<?php

declare(strict_types=1);

namespace ShieldCI\Contracts;

use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\ValueObjects\AnalysisReport;

/**
 * Interface for reporting analysis results.
 */
interface ReporterInterface
{
    /**
     * Generate a report from analysis results.
     *
     * @param  Collection<int, ResultInterface>  $results
     */
    public function generate(Collection $results): AnalysisReport;

    /**
     * Format the report for console output.
     */
    public function toConsole(AnalysisReport $report): string;

    /**
     * Format the report for JSON output.
     */
    public function toJson(AnalysisReport $report): string;

    /**
     * Stream a single result to console as it completes.
     *
     * @param  int  $current  Current analyzer number
     * @param  int  $total  Total number of analyzers
     * @param  string  $category  Category label
     */
    public function streamResult(ResultInterface $result, int $current, int $total, string $category): string;

    /**
     * Output the header for streaming mode.
     */
    public function streamHeader(): string;

    /**
     * Output a category header for streaming mode.
     */
    public function streamCategoryHeader(string $category): string;
}
