<?php

declare(strict_types=1);

namespace ShieldCI\Support\SecurityAdvisories;

interface AdvisoryAnalyzerInterface
{
    /**
     * @param  array<string, array{version: string, time: string|null}>  $dependencies
     * @param  array<string, array<int, array<string, mixed>>>  $advisories
     * @return array<string, array{version: string, advisories: array<int, array<string, mixed>>}>
     */
    public function analyze(array $dependencies, array $advisories): array;
}
