<?php

declare(strict_types=1);

namespace ShieldCI\Support;

final class ViewBinding
{
    /** @param list<string> $eagerLoads */
    public function __construct(
        public readonly ?string $type,
        public readonly array $eagerLoads,
        public readonly string $source,
    ) {}
}
