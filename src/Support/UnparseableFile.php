<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use ShieldCI\Enums\ParseFailureCause;

/**
 * One file the analyzer suite reads but cannot parse.
 *
 * The point of recording it is the consequence, not the file: an unparseable file
 * is skipped by every AST-based analyzer, and a run that skips it still reports a
 * clean bill of health for it.
 *
 * @internal No analyzer consumes this yet. It is published only so a consumer can be
 * built against it, and the failure channel may move to analyzers-core's AstParser,
 * which records what the suite actually parsed rather than predicting it. Do not
 * depend on it from outside this package.
 */
final class UnparseableFile
{
    /**
     * @param  string  $path  Path relative to the application root, forward-slashed.
     * @param  int  $line  1-indexed line the parser stopped on (the Blade line for a template).
     * @param  string  $parserMessage  The parser's own message, unaltered.
     */
    public function __construct(
        public readonly string $path,
        public readonly int $line,
        public readonly string $parserMessage,
        public readonly ParseFailureCause $cause,
    ) {}

    /**
     * What the suite silently did with this file.
     */
    public function consequence(): string
    {
        return sprintf(
            'every AST-based analyzer silently skipped %s, so their checks did not run on it',
            $this->path
        );
    }

    /**
     * A one-line summary: where it failed, what the parser said, and why.
     */
    public function describe(): string
    {
        return sprintf(
            '%s:%d — %s: %s',
            $this->path,
            $this->line,
            $this->cause->label(),
            $this->parserMessage
        );
    }
}
