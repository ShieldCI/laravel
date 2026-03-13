<?php

declare(strict_types=1);

namespace ShieldCI\Enums;

enum SuppressionType: string
{
    case Inline = 'inline';
    case Config = 'config';
    case Baseline = 'baseline';
}
