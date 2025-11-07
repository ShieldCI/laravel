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
     * Format the report for sending to ShieldCI API.
     */
    public function toApi(AnalysisReport $report): array;
}
