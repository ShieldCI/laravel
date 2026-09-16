<?php

declare(strict_types=1);

namespace ShieldCI\Enums;

use ShieldCI\AnalyzersCore\Enums\Severity;

/**
 * The severity threshold at which findings fail the build.
 *
 * Configured as shieldci.fail_on. Owning the comparison here keeps the two gates in
 * AnalyzeCommand from drifting: they previously spelled the same rule out as separate
 * switch statements, and the warning one was a level behind.
 */
enum FailOn: string
{
    case Never = 'never';
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';

    /**
     * Resolve the configured value, falling back to the documented default.
     *
     * An unrecognized value used to leave the gate half on: the switch this replaces
     * matched no case, so no finding of any severity could fail the build, while errored
     * analyzers and fail_threshold still could.
     */
    public static function fromConfig(mixed $value): self
    {
        return is_string($value) ? self::tryFrom($value) ?? self::High : self::High;
    }

    /**
     * Whether an issue of this severity fails the build at this threshold.
     *
     * The three graded cases are named after the severity they gate on, so the threshold is
     * derived from this enum's own value rather than naming a Severity. That keeps the
     * severity a finding carries chosen in one place, the analyzer that emits it, which is
     * the invariant MetadataSeverityConsistencyTest exists to hold.
     */
    public function fails(Severity $severity): bool
    {
        return match ($this) {
            self::Never => false,
            // Documented as "fail on any issues", so it reaches the bottom of the scale.
            self::Low => true,
            self::Medium, self::High, self::Critical => $severity->level() >= Severity::from($this->value)->level(),
        };
    }

    /**
     * Whether warning results reach the exit code at this threshold.
     *
     * A warning is a softer verdict than a failure, so it only gates at the two lowest
     * thresholds. This also decides whether a warning that names no issue can block.
     */
    public function gradesWarnings(): bool
    {
        return $this === self::Low || $this === self::Medium;
    }

    /**
     * The accepted values, for error messages.
     *
     * @return array<int, string>
     */
    public static function values(): array
    {
        return array_map(fn (self $case) => $case->value, self::cases());
    }
}
