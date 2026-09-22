<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

/**
 * Reads where a Blade source's @php blocks begin and end.
 *
 * Two callers need this and used to answer it separately, each with its own line-by-line test
 * for the substring "@php": BladeCompilerFactory, to choose a line marker form, and
 * LogicInBladeAnalyzer, to size a block and to report an unclosed one. A substring is not a
 * directive, so "@@php", a "@php" written in a sentence and a "@php" inside an HTML comment
 * each opened a block that nothing ever closed (#411). The two spellings had already drifted,
 * one guarding a block opened and closed on a single line and the other not. Sharing one
 * answer is what leaves nothing to drift.
 *
 * The spans mirror BladeCompiler::storePhpBlocks(), which compileString() runs before anything
 * else and which is therefore the authority on what a block is. Reading its pattern over the
 * whole source rather than line by line is what fixes the three cases above, and it also
 * settles the two questions a line-by-line reading cannot answer at all: which @endphp closes
 * which @php, and whether an opener is paired with one in the first place.
 *
 * Tradeoff, accepted: the spans are read from the raw source, while Laravel reads them from a
 * source storeVerbatimBlocks() has already emptied. A @php block written inside @verbatim is
 * therefore counted here as a block where Laravel renders it as text. That direction is
 * harmless for both callers, because a marker lands in text Blade discards and a body is
 * measured that never runs. The opposite direction, a finding raised against a template that
 * renders correctly, is what the literal regions below guard.
 */
trait ReadsBladePhpBlocks
{
    /**
     * Every @php block of a Blade source, and every opener that never got an @endphp.
     *
     * "insideBlock" keys the 1-indexed lines from the line after an opener through its @endphp
     * line. The @endphp line counts as inside: the raw block Blade lifts out runs up to and
     * including it, so anything injected there is still inside PHP.
     *
     * "size" counts the lines strictly between opener and closer, which is the length an
     * author reads off the template. A block opened and closed on one line has none.
     *
     * @return array{
     *     insideBlock: array<int, true>,
     *     blocks: list<array{open: int, close: int, size: int}>,
     *     unpairedOpeners: list<int>
     * }
     */
    protected static function readBladePhpBlocks(string $bladeSource): array
    {
        // Non-greedy and DOTALL, so the first @php pairs with the nearest following @endphp.
        // (?<!@) is what excludes the escape "@@php", which Blade unescapes to literal text.
        $spans = self::bladeRangesOf('/(?<!@)@php(.*?)@endphp/s', $bladeSource);

        $insideBlock = [];
        $blocks = [];

        foreach ($spans as [$start, $end]) {
            $open = self::bladeLineAt($bladeSource, $start);
            $close = self::bladeLineAt($bladeSource, $end);

            $blocks[] = ['open' => $open, 'close' => $close, 'size' => max(0, $close - $open - 1)];

            for ($line = $open + 1; $line <= $close; $line++) {
                $insideBlock[$line] = true;
            }
        }

        return [
            'insideBlock' => $insideBlock,
            'blocks' => $blocks,
            'unpairedOpeners' => self::bladeUnpairedOpeners($bladeSource, $spans),
        ];
    }

    /**
     * Lines holding a @php that opens a block no @endphp ever closes.
     *
     * Deliberately narrower than Blade's own reading. An unpaired @php is not a fatal error:
     * compilePhp('') returns the literal string '@php', so the directive and the PHP after it
     * simply render as text. That is worth reporting, because the text is the author's own
     * code shown to a browser, but it is also why the test has to be conservative. Blade would
     * call a "@php" mentioned mid-sentence a directive too, and that sentence compiles back to
     * itself, so there is nothing there for anyone to fix.
     *
     * The gate is directive position: the @php must open its line. "^[ \t]*" rejects the
     * escape "@@php", whose leading "@" is neither horizontal space nor the start of "@php",
     * and rejects a mention in prose or in an HTML comment. "\b" rejects a longer directive
     * name such as "@phpunit". The lookahead rejects the self-closing call form, and spells
     * its separator "[ \t]*" rather than "\s*" because that is what Blade's own statement
     * pattern allows before the parenthesis.
     *
     * Accepted miss: an unclosed opener that is not first on its line. A miss costs far less
     * than a finding raised against a template that renders exactly as written, and the paired
     * form of that shape still produces a span.
     *
     * @param  list<array{int, int}>  $spans
     * @return list<int>
     */
    private static function bladeUnpairedOpeners(string $bladeSource, array $spans): array
    {
        // storeVerbatimBlocks() empties a @verbatim region before storePhpBlocks() ever sees
        // it, and compileComments() strips a Blade comment after it. Neither renders anything
        // an author can act on, and both are where a template documenting Blade puts a bare
        // @php. This gate belongs to the unclosed reading alone, so that the spans above stay
        // a faithful mirror of the compiler.
        $literal = array_merge(
            self::bladeRangesOf('/(?<!@)@verbatim(.*?)@endverbatim/s', $bladeSource),
            self::bladeRangesOf('/\{\{--(.*?)--\}\}/s', $bladeSource),
        );

        $unpaired = [];

        foreach (self::bladeRangesOf('/^[ \t]*@php\b(?![ \t]*\()/m', $bladeSource) as [$start]) {
            // The pattern consumes the indent, so the directive starts where that space ends.
            $offset = $start + strspn($bladeSource, " \t", $start);

            if (self::bladeOffsetCovered($spans, $offset) || self::bladeOffsetCovered($literal, $offset)) {
                continue;
            }

            $unpaired[] = self::bladeLineAt($bladeSource, $offset);
        }

        return $unpaired;
    }

    /**
     * Byte ranges of every whole-pattern match, as [start, end) offsets.
     *
     * A pattern that fails outright, which PCRE can do on its own limits, leaves $matches
     * empty and yields no ranges. Both callers then read the source as plain markup, which is
     * the same answer they give a template with no @php in it at all.
     *
     * @return list<array{int, int}>
     */
    private static function bladeRangesOf(string $pattern, string $bladeSource): array
    {
        /** @var array<int, array<int, array{string, int}>> $matches */
        $matches = [];

        preg_match_all($pattern, $bladeSource, $matches, PREG_OFFSET_CAPTURE);

        $ranges = [];

        foreach ($matches[0] ?? [] as [$text, $offset]) {
            $ranges[] = [$offset, $offset + strlen($text)];
        }

        return $ranges;
    }

    /**
     * @param  list<array{int, int}>  $ranges
     */
    private static function bladeOffsetCovered(array $ranges, int $offset): bool
    {
        foreach ($ranges as [$start, $end]) {
            if ($offset >= $start && $offset < $end) {
                return true;
            }
        }

        return false;
    }

    /**
     * The 1-indexed line holding a byte offset.
     */
    private static function bladeLineAt(string $bladeSource, int $offset): int
    {
        return substr_count($bladeSource, "\n", 0, $offset) + 1;
    }
}
