<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use ShieldCI\AnalyzersCore\Enums\Status;

/**
 * The part of a check that an analyzer could not complete, recorded on its result.
 *
 * A few analyzers find issues and also fail to finish part of the check, such as an origin
 * probe that timed out or a PHPStan run that stopped early. They name the unfinished part in
 * the result summary, but the summary is replaced when every issue is suppressed through
 * ignore_errors, the baseline or an inline comment. The same text is kept in the result
 * metadata, with the status the analyzer gives the same run when it finds no issues, so the
 * command can report a fully suppressed result with that status instead of a pass.
 */
final class ResultCaveat
{
    public const METADATA_KEY = 'caveat';

    public const STATUS_KEY = 'caveat_status';

    private function __construct(
        public readonly string $text,
        public readonly Status $status,
    ) {}

    /**
     * Result metadata carrying the caveat text and the status of the issue-less result.
     *
     * @return array<string, string>
     */
    public static function metadata(string $caveat, Status $status = Status::Warning): array
    {
        return [
            self::METADATA_KEY => $caveat,
            self::STATUS_KEY => $status->value,
        ];
    }

    /**
     * The caveat recorded in a result's metadata, or null when there is none.
     *
     * The status falls back to Warning when it is missing or unusable. A caveat means part
     * of the check was not done, so it never yields a pass or a skip.
     *
     * @param  array<string, mixed>  $metadata
     */
    public static function from(array $metadata): ?self
    {
        $text = $metadata[self::METADATA_KEY] ?? null;

        if (! is_string($text) || $text === '') {
            return null;
        }

        $stored = $metadata[self::STATUS_KEY] ?? null;
        $status = match (is_string($stored) ? Status::tryFrom($stored) : null) {
            Status::Failed => Status::Failed,
            Status::Error => Status::Error,
            default => Status::Warning,
        };

        return new self($text, $status);
    }
}
