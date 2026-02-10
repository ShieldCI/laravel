<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support\SecurityAdvisories;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Support\SecurityAdvisories\VersionConstraintMatcher;
use ShieldCI\Tests\TestCase;

class VersionConstraintMatcherTest extends TestCase
{
    private VersionConstraintMatcher $matcher;

    protected function setUp(): void
    {
        parent::setUp();
        $this->matcher = new VersionConstraintMatcher;
    }

    #[Test]
    public function it_matches_exact_version(): void
    {
        $this->assertTrue($this->matcher->matches('1.0.0', '1.0.0'));
        $this->assertTrue($this->matcher->matches('2.5.3', '==2.5.3'));
        $this->assertTrue($this->matcher->matches('1.0.0', '=1.0.0'));
    }

    #[Test]
    public function it_matches_wildcard_constraint(): void
    {
        $this->assertTrue($this->matcher->matches('1.0.0', '*'));
        $this->assertTrue($this->matcher->matches('2.5.3', '*'));
    }

    #[Test]
    public function it_matches_empty_constraint(): void
    {
        $this->assertTrue($this->matcher->matches('1.0.0', ''));
        $this->assertTrue($this->matcher->matches('2.5.3', '  '));
    }

    #[Test]
    public function it_matches_greater_than_constraint(): void
    {
        $this->assertTrue($this->matcher->matches('2.0.0', '>1.0.0'));
        $this->assertFalse($this->matcher->matches('1.0.0', '>1.0.0'));
        $this->assertFalse($this->matcher->matches('0.5.0', '>1.0.0'));
    }

    #[Test]
    public function it_matches_greater_than_or_equal_constraint(): void
    {
        $this->assertTrue($this->matcher->matches('2.0.0', '>=1.0.0'));
        $this->assertTrue($this->matcher->matches('1.0.0', '>=1.0.0'));
        $this->assertFalse($this->matcher->matches('0.5.0', '>=1.0.0'));
    }

    #[Test]
    public function it_matches_less_than_constraint(): void
    {
        $this->assertTrue($this->matcher->matches('0.5.0', '<1.0.0'));
        $this->assertFalse($this->matcher->matches('1.0.0', '<1.0.0'));
        $this->assertFalse($this->matcher->matches('2.0.0', '<1.0.0'));
    }

    #[Test]
    public function it_matches_less_than_or_equal_constraint(): void
    {
        $this->assertTrue($this->matcher->matches('0.5.0', '<=1.0.0'));
        $this->assertTrue($this->matcher->matches('1.0.0', '<=1.0.0'));
        $this->assertFalse($this->matcher->matches('2.0.0', '<=1.0.0'));
    }

    #[Test]
    public function it_matches_caret_constraint(): void
    {
        // ^1.2.3 means >=1.2.3 and <2.0.0
        $this->assertTrue($this->matcher->matches('1.2.3', '^1.2.3'));
        $this->assertTrue($this->matcher->matches('1.5.0', '^1.2.3'));
        $this->assertTrue($this->matcher->matches('1.9.9', '^1.2.3'));
        $this->assertFalse($this->matcher->matches('2.0.0', '^1.2.3'));
        $this->assertFalse($this->matcher->matches('1.2.2', '^1.2.3'));
    }

    #[Test]
    public function it_matches_tilde_constraint(): void
    {
        // ~1.2.3 means >=1.2.3 and <1.3.0
        $this->assertTrue($this->matcher->matches('1.2.3', '~1.2.3'));
        $this->assertTrue($this->matcher->matches('1.2.9', '~1.2.3'));
        $this->assertFalse($this->matcher->matches('1.3.0', '~1.2.3'));
        $this->assertFalse($this->matcher->matches('1.2.2', '~1.2.3'));
    }

    #[Test]
    public function it_matches_tilde_constraint_with_single_part(): void
    {
        // ~1 means >=1.0.0 and <2.0.0
        $this->assertTrue($this->matcher->matches('1.0.0', '~1'));
        $this->assertTrue($this->matcher->matches('1.9.9', '~1'));
        $this->assertFalse($this->matcher->matches('2.0.0', '~1'));
    }

    #[Test]
    public function it_matches_wildcard_in_version(): void
    {
        $this->assertTrue($this->matcher->matches('1.0.0', '1.*'));
        $this->assertTrue($this->matcher->matches('1.5.3', '1.*'));
        $this->assertFalse($this->matcher->matches('2.0.0', '1.*'));
    }

    #[Test]
    public function it_matches_x_notation(): void
    {
        $this->assertTrue($this->matcher->matches('1.0.0', '1.x'));
        $this->assertTrue($this->matcher->matches('1.5.3', '1.x'));
        $this->assertFalse($this->matcher->matches('2.0.0', '1.x'));
    }

    #[Test]
    public function it_matches_array_of_constraints(): void
    {
        // Should match if ANY constraint matches
        $this->assertTrue($this->matcher->matches('1.5.0', ['^1.0', '^2.0']));
        $this->assertTrue($this->matcher->matches('2.5.0', ['^1.0', '^2.0']));
        $this->assertFalse($this->matcher->matches('3.0.0', ['^1.0', '^2.0']));
    }

    #[Test]
    public function it_handles_version_with_v_prefix(): void
    {
        $this->assertTrue($this->matcher->matches('1.0.0', 'v1.0.0'));
        $this->assertTrue($this->matcher->matches('1.0.0', '>=v1.0.0'));
    }

    #[Test]
    #[DataProvider('constraintMatchProvider')]
    public function it_matches_various_constraint_formats(string $version, string $constraint, bool $expected): void
    {
        $this->assertEquals($expected, $this->matcher->matches($version, $constraint));
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: bool}>
     */
    public static function constraintMatchProvider(): array
    {
        return [
            'exact_match' => ['1.0.0', '1.0.0', true],
            'exact_with_double_equal' => ['1.0.0', '==1.0.0', true],
            'exact_with_single_equal' => ['1.0.0', '=1.0.0', true],
            'greater_than_true' => ['1.1.0', '>1.0.0', true],
            'greater_than_false' => ['1.0.0', '>1.0.0', false],
            'less_than_true' => ['0.9.0', '<1.0.0', true],
            'less_than_false' => ['1.0.0', '<1.0.0', false],
            'caret_within_range' => ['1.5.0', '^1.0.0', true],
            'caret_below_range' => ['0.9.0', '^1.0.0', false],
            'caret_above_range' => ['2.0.0', '^1.0.0', false],
            'tilde_within_range' => ['1.0.5', '~1.0.0', true],
            'tilde_above_minor' => ['1.1.0', '~1.0.0', false],
            'wildcard_asterisk' => ['1.5.9', '1.*', true],
            'wildcard_x' => ['2.3.4', '2.x', true],
            'prerelease_version' => ['1.0.0-alpha', '>=1.0.0-alpha', true],
            'complex_version' => ['1.2.3-beta.1', '>=1.2.3-beta.1', true],
        ];
    }

    #[Test]
    public function it_returns_false_for_no_matching_constraints_in_array(): void
    {
        $this->assertFalse($this->matcher->matches('5.0.0', ['^1.0', '^2.0', '^3.0']));
    }

    #[Test]
    public function it_handles_empty_caret_constraint(): void
    {
        // ^<empty> should not match
        $this->assertFalse($this->matcher->matches('1.0.0', '^'));
    }

    #[Test]
    public function it_handles_empty_tilde_constraint(): void
    {
        // ~<empty> should not match
        $this->assertFalse($this->matcher->matches('1.0.0', '~'));
    }

    #[Test]
    public function it_handles_whitespace_in_constraints(): void
    {
        $this->assertTrue($this->matcher->matches('1.0.0', '  >= 1.0.0  '));
        $this->assertTrue($this->matcher->matches('1.0.0', '>= 1.0.0'));
    }
}
