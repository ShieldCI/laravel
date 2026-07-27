<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Support\MemoryLimit;
use ShieldCI\Tests\TestCase;

class MemoryLimitTest extends TestCase
{
    /** @test */
    #[Test]
    public function it_converts_ini_style_limits_to_bytes(): void
    {
        $this->assertSame(536870912.0, MemoryLimit::toBytes('512M'));
        $this->assertSame(1073741824.0, MemoryLimit::toBytes('1G'));
        $this->assertSame(131072.0, MemoryLimit::toBytes('128k'));
        $this->assertSame(1024.0, MemoryLimit::toBytes('1K'));
        $this->assertSame(262144.0, MemoryLimit::toBytes('262144'));
        $this->assertSame(INF, MemoryLimit::toBytes('-1'));
    }

    /** @test */
    #[Test]
    public function it_returns_null_for_unparseable_limits(): void
    {
        $this->assertNull(MemoryLimit::toBytes(''));
        $this->assertNull(MemoryLimit::toBytes('abc'));
        $this->assertNull(MemoryLimit::toBytes('12MB'));
        $this->assertNull(MemoryLimit::toBytes('1.5G'));
        $this->assertNull(MemoryLimit::toBytes('-2'));
    }

    /** @test */
    #[Test]
    public function it_raises_only_when_configured_limit_is_higher(): void
    {
        $this->assertTrue(MemoryLimit::shouldRaise('128M', '512M'));
        $this->assertTrue(MemoryLimit::shouldRaise('1G', '2048M'));

        $this->assertFalse(MemoryLimit::shouldRaise('2048M', '512M'));
        $this->assertFalse(MemoryLimit::shouldRaise('512M', '512M'));
    }

    /** @test */
    #[Test]
    public function it_never_lowers_an_unlimited_current_limit(): void
    {
        $this->assertFalse(MemoryLimit::shouldRaise('-1', '512M'));
        $this->assertFalse(MemoryLimit::shouldRaise('-1', '-1'));
    }

    /** @test */
    #[Test]
    public function it_raises_a_finite_limit_to_unlimited(): void
    {
        $this->assertTrue(MemoryLimit::shouldRaise('512M', '-1'));
    }

    /** @test */
    #[Test]
    public function it_handles_unparseable_values_conservatively(): void
    {
        // Unparseable configured value: never apply it.
        $this->assertFalse(MemoryLimit::shouldRaise('512M', 'nonsense'));

        // Unparseable current value: trust the configured limit.
        $this->assertTrue(MemoryLimit::shouldRaise('nonsense', '512M'));
    }
}
