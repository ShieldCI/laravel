<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\ValueObjects;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Enums\AnalysisFailureReason;
use ShieldCI\Enums\TriggerSource;
use ShieldCI\Tests\TestCase;
use ShieldCI\ValueObjects\FailureNotification;

class FailureNotificationTest extends TestCase
{
    #[Test]
    public function it_constructs_with_all_parameters(): void
    {
        $occurredAt = new DateTimeImmutable('2026-02-28T14:30:00+00:00');

        $notification = new FailureNotification(
            projectId: 'proj-123',
            laravelVersion: '11.40.0',
            packageVersion: '1.2.0',
            reason: AnalysisFailureReason::InvalidOptions,
            errorMessage: 'Invalid analyzer ID',
            triggeredBy: TriggerSource::Manual,
            occurredAt: $occurredAt,
            metadata: ['php_version' => '8.3.2'],
        );

        $this->assertSame('proj-123', $notification->projectId);
        $this->assertSame('11.40.0', $notification->laravelVersion);
        $this->assertSame('1.2.0', $notification->packageVersion);
        $this->assertSame(AnalysisFailureReason::InvalidOptions, $notification->reason);
        $this->assertSame('Invalid analyzer ID', $notification->errorMessage);
        $this->assertSame(TriggerSource::Manual, $notification->triggeredBy);
        $this->assertSame($occurredAt, $notification->occurredAt);
        $this->assertSame(['php_version' => '8.3.2'], $notification->metadata);
    }

    #[Test]
    public function it_defaults_metadata_to_empty_array(): void
    {
        $notification = new FailureNotification(
            projectId: 'proj-123',
            laravelVersion: '11.0.0',
            packageVersion: '1.0.0',
            reason: AnalysisFailureReason::NoAnalyzersRan,
            errorMessage: 'No analyzers ran',
            triggeredBy: TriggerSource::CiCd,
            occurredAt: new DateTimeImmutable('now', new DateTimeZone('UTC')),
        );

        $this->assertSame([], $notification->metadata);
    }

    #[Test]
    public function to_array_produces_correct_structure(): void
    {
        $occurredAt = new DateTimeImmutable('2026-02-28T14:30:00+00:00');

        $notification = new FailureNotification(
            projectId: 'proj-456',
            laravelVersion: '10.48.29',
            packageVersion: '1.5.0',
            reason: AnalysisFailureReason::AllCategoriesDisabled,
            errorMessage: 'All categories disabled',
            triggeredBy: TriggerSource::Scheduled,
            occurredAt: $occurredAt,
            metadata: ['os' => 'Linux', 'php_version' => '8.2.0'],
        );

        $array = $notification->toArray();

        $this->assertSame('proj-456', $array['project_id']);
        $this->assertSame('10.48.29', $array['laravel_version']);
        $this->assertSame('1.5.0', $array['package_version']);
        $this->assertSame('failed', $array['status']);
        $this->assertSame('all_categories_disabled', $array['failure_reason']);
        $this->assertSame('All analyzer categories are disabled', $array['failure_label']);
        $this->assertSame('All categories disabled', $array['error_message']);
        $this->assertSame('scheduled', $array['triggered_by']);
        $this->assertSame($occurredAt->format('c'), $array['occurred_at']);
        $this->assertSame(['os' => 'Linux', 'php_version' => '8.2.0'], $array['metadata']);
    }

    #[Test]
    public function status_is_always_failed(): void
    {
        foreach (AnalysisFailureReason::cases() as $reason) {
            $notification = new FailureNotification(
                projectId: 'proj-test',
                laravelVersion: '11.0.0',
                packageVersion: '1.0.0',
                reason: $reason,
                errorMessage: 'test',
                triggeredBy: TriggerSource::Manual,
                occurredAt: new DateTimeImmutable('now', new DateTimeZone('UTC')),
            );

            $this->assertSame('failed', $notification->toArray()['status'], "Status should be 'failed' for reason {$reason->value}");
        }
    }

    #[Test]
    public function occurred_at_is_iso_8601_format(): void
    {
        $occurredAt = new DateTimeImmutable('2026-01-15T09:45:30+03:00');

        $notification = new FailureNotification(
            projectId: 'proj-test',
            laravelVersion: '11.0.0',
            packageVersion: '1.0.0',
            reason: AnalysisFailureReason::UncaughtException,
            errorMessage: 'Something broke',
            triggeredBy: TriggerSource::Manual,
            occurredAt: $occurredAt,
        );

        $array = $notification->toArray();

        // Verify it's a valid ISO 8601 datetime
        $occurredAtValue = $array['occurred_at'];
        $this->assertIsString($occurredAtValue);
        $parsed = new DateTimeImmutable($occurredAtValue);
        $this->assertSame('2026-01-15', $parsed->format('Y-m-d'));
    }

    #[Test]
    public function failure_reason_matches_enum_value(): void
    {
        foreach (AnalysisFailureReason::cases() as $reason) {
            $notification = new FailureNotification(
                projectId: 'proj-test',
                laravelVersion: '11.0.0',
                packageVersion: '1.0.0',
                reason: $reason,
                errorMessage: 'test',
                triggeredBy: TriggerSource::Manual,
                occurredAt: new DateTimeImmutable('now', new DateTimeZone('UTC')),
            );

            $array = $notification->toArray();
            $this->assertSame($reason->value, $array['failure_reason']);
            $this->assertSame($reason->label(), $array['failure_label']);
        }
    }

    #[Test]
    public function laravel_and_package_versions_are_top_level_fields(): void
    {
        $notification = new FailureNotification(
            projectId: 'proj-test',
            laravelVersion: '12.0.0',
            packageVersion: '2.0.0',
            reason: AnalysisFailureReason::InvalidOptions,
            errorMessage: 'test',
            triggeredBy: TriggerSource::Manual,
            occurredAt: new DateTimeImmutable('now', new DateTimeZone('UTC')),
        );

        $array = $notification->toArray();

        // These must be top-level, not inside metadata
        $this->assertArrayHasKey('laravel_version', $array);
        $this->assertArrayHasKey('package_version', $array);
        $this->assertSame('12.0.0', $array['laravel_version']);
        $this->assertSame('2.0.0', $array['package_version']);
        $this->assertArrayNotHasKey('laravel_version', $array['metadata']);
        $this->assertArrayNotHasKey('package_version', $array['metadata']);
    }
}
