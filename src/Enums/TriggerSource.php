<?php

declare(strict_types=1);

namespace ShieldCI\Enums;

enum TriggerSource: string
{
    case Manual = 'manual';
    case CiCd = 'ci_cd';
    case Scheduled = 'scheduled';

    public function label(): string
    {
        return match ($this) {
            self::Manual => 'Manual',
            self::CiCd => 'CI/CD',
            self::Scheduled => 'Scheduled',
        };
    }
}
