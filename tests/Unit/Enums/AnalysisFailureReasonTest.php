<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Enums\AnalysisFailureReason;
use ShieldCI\Tests\TestCase;

class AnalysisFailureReasonTest extends TestCase
{
    #[Test]
    public function all_cases_have_non_empty_values(): void
    {
        foreach (AnalysisFailureReason::cases() as $case) {
            $this->assertNotEmpty($case->value, "Case {$case->name} has empty value");
        }
    }

    #[Test]
    public function all_cases_have_non_empty_labels(): void
    {
        foreach (AnalysisFailureReason::cases() as $case) {
            $this->assertNotEmpty($case->label(), "Case {$case->name} has empty label");
        }
    }

    #[Test]
    public function try_from_returns_case_for_valid_values(): void
    {
        $this->assertSame(AnalysisFailureReason::InvalidOptions, AnalysisFailureReason::tryFrom('invalid_options'));
        $this->assertSame(AnalysisFailureReason::AllCategoriesDisabled, AnalysisFailureReason::tryFrom('all_categories_disabled'));
        $this->assertSame(AnalysisFailureReason::NoAnalyzersRan, AnalysisFailureReason::tryFrom('no_analyzers_ran'));
        $this->assertSame(AnalysisFailureReason::UncaughtException, AnalysisFailureReason::tryFrom('uncaught_exception'));
    }

    #[Test]
    public function try_from_returns_null_for_invalid_values(): void
    {
        $this->assertNull(AnalysisFailureReason::tryFrom('nonexistent'));
        $this->assertNull(AnalysisFailureReason::tryFrom(''));
    }

    #[Test]
    public function labels_are_human_readable(): void
    {
        $this->assertSame('Invalid command options', AnalysisFailureReason::InvalidOptions->label());
        $this->assertSame('All analyzer categories are disabled', AnalysisFailureReason::AllCategoriesDisabled->label());
        $this->assertSame('No analyzers were executed', AnalysisFailureReason::NoAnalyzersRan->label());
        $this->assertSame('Uncaught exception during analysis', AnalysisFailureReason::UncaughtException->label());
    }
}
