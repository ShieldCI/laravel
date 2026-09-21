<?php

declare(strict_types=1);

namespace ShieldCI\Enums;

/**
 * Why the pinned parser could not read a source file.
 *
 * The two cases need different fixes, so they are never collapsed into one:
 * broken code is the author's to repair, while syntax the pinned parser does
 * not implement yet is the toolchain's.
 */
enum ParseFailureCause: string
{
    /** No PHP runtime would accept this file either: the code itself is broken. */
    case SyntaxError = 'syntax_error';

    /** The running PHP accepts this file; the pinned parser is the one that cannot read it. */
    case UnsupportedSyntax = 'unsupported_syntax';

    public function label(): string
    {
        return match ($this) {
            self::SyntaxError => 'Syntax error',
            self::UnsupportedSyntax => 'Unsupported by the pinned parser',
        };
    }

    public function recommendation(): string
    {
        return match ($this) {
            self::SyntaxError => 'Fix the syntax error so the file can be analyzed. Until then the file is invisible to every AST-based check.',
            self::UnsupportedSyntax => 'The running PHP accepts this file but the pinned nikic/php-parser does not, so the file uses a language feature newer than the parser. Upgrade nikic/php-parser so the analyzers can read it.',
        };
    }
}
