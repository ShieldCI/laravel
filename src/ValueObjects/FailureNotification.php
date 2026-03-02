<?php

declare(strict_types=1);

namespace ShieldCI\ValueObjects;

use DateTimeImmutable;
use ShieldCI\Enums\AnalysisFailureReason;
use ShieldCI\Enums\TriggerSource;

final class FailureNotification
{
    /**
     * @param  array<string, string>  $metadata
     */
    public function __construct(
        public readonly string $projectId,
        public readonly string $laravelVersion,
        public readonly string $packageVersion,
        public readonly AnalysisFailureReason $reason,
        public readonly string $errorMessage,
        public readonly TriggerSource $triggeredBy,
        public readonly DateTimeImmutable $occurredAt,
        public readonly array $metadata = [],
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'project_id' => $this->projectId,
            'laravel_version' => $this->laravelVersion,
            'package_version' => $this->packageVersion,
            'status' => 'failed',
            'failure_reason' => $this->reason->value,
            'failure_label' => $this->reason->label(),
            'error_message' => $this->errorMessage,
            'triggered_by' => $this->triggeredBy->value,
            'occurred_at' => $this->occurredAt->format('c'),
            'metadata' => $this->metadata,
        ];
    }
}
