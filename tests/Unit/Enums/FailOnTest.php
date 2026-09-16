<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Enums\FailOn;
use ShieldCI\Tests\TestCase;

class FailOnTest extends TestCase
{
    /** @test */
    #[Test]
    public function it_has_the_values_the_config_documents(): void
    {
        $this->assertEquals(['never', 'critical', 'high', 'medium', 'low'], FailOn::values());
    }

    /** @test */
    #[Test]
    public function it_falls_back_to_high_for_a_value_it_does_not_recognize(): void
    {
        // A typo used to leave the gate half on: no finding of any severity could fail the
        // build, while errored analyzers and fail_threshold still could.
        $this->assertSame(FailOn::High, FailOn::fromConfig('hgh'));
        $this->assertSame(FailOn::High, FailOn::fromConfig(''));
        $this->assertSame(FailOn::High, FailOn::fromConfig(null));
        $this->assertSame(FailOn::High, FailOn::fromConfig(5));
        $this->assertSame(FailOn::High, FailOn::fromConfig(['high']));
    }

    /** @test */
    #[Test]
    public function it_resolves_every_documented_value(): void
    {
        foreach (FailOn::cases() as $case) {
            $this->assertSame($case, FailOn::fromConfig($case->value));
        }
    }

    /** @test */
    #[Test]
    public function never_fails_on_nothing(): void
    {
        foreach (Severity::cases() as $severity) {
            $this->assertFalse(FailOn::Never->fails($severity), $severity->value);
        }
    }

    /** @test */
    #[Test]
    public function low_fails_on_any_severity_including_info(): void
    {
        // 'low' is documented as "fail on any issues", so it reaches the bottom of the scale.
        foreach (Severity::cases() as $severity) {
            $this->assertTrue(FailOn::Low->fails($severity), $severity->value);
        }
    }

    /**
     * @return array<string, array{FailOn, Severity, bool}>
     */
    public static function gradingProvider(): array
    {
        return [
            'critical passes a high issue' => [FailOn::Critical, Severity::High, false],
            'critical fails a critical issue' => [FailOn::Critical, Severity::Critical, true],
            'high passes a medium issue' => [FailOn::High, Severity::Medium, false],
            'high fails a high issue' => [FailOn::High, Severity::High, true],
            'high fails a critical issue' => [FailOn::High, Severity::Critical, true],
            'medium passes a low issue' => [FailOn::Medium, Severity::Low, false],
            'medium fails a medium issue' => [FailOn::Medium, Severity::Medium, true],
            // The warning gate used to match only 'medium', so these two slipped through a
            // threshold that a Medium issue would have tripped.
            'medium fails a high issue' => [FailOn::Medium, Severity::High, true],
            'medium fails a critical issue' => [FailOn::Medium, Severity::Critical, true],
        ];
    }

    /**
     * @test
     *
     * @dataProvider gradingProvider
     */
    #[Test]
    #[DataProvider('gradingProvider')]
    public function it_grades_an_issue_against_the_threshold(FailOn $failOn, Severity $severity, bool $expected): void
    {
        $this->assertSame($expected, $failOn->fails($severity));
    }

    /** @test */
    #[Test]
    public function only_the_two_lowest_thresholds_grade_warnings(): void
    {
        $this->assertTrue(FailOn::Low->gradesWarnings());
        $this->assertTrue(FailOn::Medium->gradesWarnings());
        $this->assertFalse(FailOn::High->gradesWarnings());
        $this->assertFalse(FailOn::Critical->gradesWarnings());
        $this->assertFalse(FailOn::Never->gradesWarnings());
    }
}
