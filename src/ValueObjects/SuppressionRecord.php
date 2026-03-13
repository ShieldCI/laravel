<?php

declare(strict_types=1);

namespace ShieldCI\ValueObjects;

use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Enums\SuppressionType;

/**
 * Records a single issue that was suppressed during analysis.
 */
final class SuppressionRecord
{
    public function __construct(
        public readonly Issue $issue,
        public readonly SuppressionType $type,
        public readonly string $description,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $arr = $this->issue->toArray();
        $arr['suppression'] = [
            'type' => $this->type->value,
            'description' => $this->description,
        ];

        return $arr;
    }
}
