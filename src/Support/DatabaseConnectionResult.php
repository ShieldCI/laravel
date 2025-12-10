<?php

declare(strict_types=1);

namespace ShieldCI\Support;

final class DatabaseConnectionResult
{
    public function __construct(
        public readonly bool $successful,
        public readonly ?string $message = null,
        public readonly ?string $exceptionClass = null,
    ) {
    }
}
