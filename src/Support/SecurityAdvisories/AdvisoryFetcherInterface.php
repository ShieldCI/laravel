<?php

declare(strict_types=1);

namespace ShieldCI\Support\SecurityAdvisories;

/**
 * Provides security advisory metadata.
 */
interface AdvisoryFetcherInterface
{
    /**
     * Fetch security advisories for the given dependencies.
     *
     * @param  array<string, array{version: string, time: string|null}>  $dependencies
     * @return array<string, array<int, array<string, mixed>>>
     */
    public function fetch(array $dependencies): array;
}
