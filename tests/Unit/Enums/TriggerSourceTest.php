<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Enums\TriggerSource;
use ShieldCI\Tests\TestCase;

class TriggerSourceTest extends TestCase
{
    #[Test]
    public function it_has_correct_string_values(): void
    {
        $this->assertEquals('manual', TriggerSource::Manual->value);
        $this->assertEquals('ci_cd', TriggerSource::CiCd->value);
        $this->assertEquals('scheduled', TriggerSource::Scheduled->value);
    }

    #[Test]
    public function it_has_human_readable_labels(): void
    {
        $this->assertEquals('Manual', TriggerSource::Manual->label());
        $this->assertEquals('CI/CD', TriggerSource::CiCd->label());
        $this->assertEquals('Scheduled', TriggerSource::Scheduled->label());
    }

    #[Test]
    public function it_can_be_created_from_valid_string(): void
    {
        $this->assertEquals(TriggerSource::Manual, TriggerSource::from('manual'));
        $this->assertEquals(TriggerSource::CiCd, TriggerSource::from('ci_cd'));
        $this->assertEquals(TriggerSource::Scheduled, TriggerSource::from('scheduled'));
    }

    #[Test]
    public function try_from_returns_null_for_invalid_string(): void
    {
        $this->assertNull(TriggerSource::tryFrom('invalid'));
        $this->assertNull(TriggerSource::tryFrom(''));
        $this->assertNull(TriggerSource::tryFrom('MANUAL'));
    }

    #[Test]
    public function it_enumerates_all_cases(): void
    {
        $cases = TriggerSource::cases();

        $this->assertCount(3, $cases);
        $this->assertContains(TriggerSource::Manual, $cases);
        $this->assertContains(TriggerSource::CiCd, $cases);
        $this->assertContains(TriggerSource::Scheduled, $cases);
    }
}
