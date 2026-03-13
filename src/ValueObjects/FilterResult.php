<?php

declare(strict_types=1);

namespace ShieldCI\ValueObjects;

use ShieldCI\AnalyzersCore\Results\AnalysisResult;

/**
 * Internal envelope returned by single-result filter methods.
 * Carries the filtered result together with any records that were suppressed.
 */
final class FilterResult
{
    /**
     * @param  list<SuppressionRecord>  $suppressedRecords
     */
    public function __construct(
        public readonly AnalysisResult $result,
        public readonly array $suppressedRecords,
    ) {}
}
