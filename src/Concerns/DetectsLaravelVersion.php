<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

trait DetectsLaravelVersion
{
    private function isLaravel11OrNewer(): bool
    {
        return version_compare(app()->version(), '11.0.0', '>=');
    }
}
