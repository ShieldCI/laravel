<?php

declare(strict_types=1);

namespace ShieldCI\Support;

final class ComposerValidatorResult
{
    public function __construct(
        public readonly bool $successful,
        public readonly string $output,
    ) {}
}
