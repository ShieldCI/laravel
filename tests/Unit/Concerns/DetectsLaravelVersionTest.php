<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Concerns\DetectsLaravelVersion;
use ShieldCI\Tests\TestCase;

class DetectsLaravelVersionTest extends TestCase
{
    private ConcreteDetectsLaravelVersion $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->subject = new ConcreteDetectsLaravelVersion;
    }

    /** @test */
    #[Test]
    public function it_returns_a_boolean(): void
    {
        $this->assertIsBool($this->subject->check());
    }

    /** @test */
    #[Test]
    public function it_matches_the_running_laravel_version(): void
    {
        $expected = version_compare(app()->version(), '11.0.0', '>=');

        $this->assertSame($expected, $this->subject->check());
    }

    /** @test */
    #[Test]
    public function it_returns_true_on_laravel_11_or_higher(): void
    {
        if (version_compare(app()->version(), '11.0.0', '<')) {
            $this->markTestSkipped('Running on Laravel '.app()->version().' — skipping L11+ assertion.');
        }

        $this->assertTrue($this->subject->check());
    }

    /** @test */
    #[Test]
    public function it_returns_false_on_laravel_10_or_lower(): void
    {
        if (version_compare(app()->version(), '11.0.0', '>=')) {
            $this->markTestSkipped('Running on Laravel '.app()->version().' — skipping L10 assertion.');
        }

        $this->assertFalse($this->subject->check());
    }
}

class ConcreteDetectsLaravelVersion
{
    use DetectsLaravelVersion;

    public function check(): bool
    {
        return $this->isLaravel11OrNewer();
    }
}
