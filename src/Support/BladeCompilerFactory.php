<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Illuminate\Filesystem\Filesystem;
use Illuminate\View\Compilers\BladeCompiler;

/**
 * Standalone Blade-to-PHP compiler with original line number tracking.
 *
 * Injects __BLADE_LINE_N__ markers before each source line so that after
 * BladeCompiler::compileString() transforms Blade syntax to PHP, we can
 * map compiled-PHP line numbers back to original Blade line numbers.
 */
class BladeCompilerFactory
{
    /**
     * Compile Blade source to PHP with line-number tracking.
     *
     * @return array{compiledPhp: string, lineMap: array<int, int>}|null
     */
    public static function compile(string $bladeSource): ?array
    {
        try {
            $markedSource = self::injectLineMarkers($bladeSource);
            $compiler = new BladeCompiler(new Filesystem, sys_get_temp_dir());
            $compiler->withoutComponentTags();
            $compiledPhp = $compiler->compileString($markedSource);
            $lineMap = self::buildLineMap($compiledPhp);

            return ['compiledPhp' => $compiledPhp, 'lineMap' => $lineMap];
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Inject __BLADE_LINE_N__ markers before each source line.
     *
     * Outside @php blocks: a self-contained PHP open/close tag wrapping a marker.
     * Inside  @php blocks: a single-line // comment on its own line.
     *
     * Why dual-mode: @php compiles to a PHP open tag. Injecting another open tag
     * inside would close the PHP mode prematurely, producing invalid PHP.
     * Why // not block comments: block comments cannot nest in PHP, so user's own
     * block comments would conflict with marker block comments.
     *
     * Why some lines get no marker: a directive expression or an echo may span lines
     * ("@include('v', [\n 'k' => 1,\n])"). A marker on a continuation line lands inside
     * the expression, so the compiled PHP does not parse and every caller skips the
     * template silently. Continuation lines therefore inherit the opening line's marker,
     * which is also the line an author would want a failure reported against.
     */
    private static function injectLineMarkers(string $bladeSource): string
    {
        $lines = explode("\n", $bladeSource);
        $inPhpBlock = false;
        $openBrackets = 0;
        $openEcho = null;
        $marked = [];

        foreach ($lines as $index => $line) {
            $lineNum = $index + 1;
            $trimmed = trim($line);

            if (! $inPhpBlock && preg_match('/@php\b/', $trimmed)
                && ! str_contains($trimmed, '@endphp')) {
                $inPhpBlock = true;
                $marked[] = "<?php /* __BLADE_LINE_{$lineNum}__ */ ?>".$line;

                continue;
            }

            if ($inPhpBlock) {
                $marked[] = "// __BLADE_LINE_{$lineNum}__";
                $marked[] = $line;

                if (str_contains($trimmed, '@endphp')) {
                    $inPhpBlock = false;
                }

                continue;
            }

            $marked[] = $openBrackets > 0 || $openEcho !== null
                ? $line
                : "<?php /* __BLADE_LINE_{$lineNum}__ */ ?>".$line;

            [$openBrackets, $openEcho] = self::carryOver($line, $openBrackets, $openEcho);
        }

        return implode("\n", $marked);
    }

    /**
     * How much of an expression this line leaves open for the next one.
     *
     * Walks the line once, entering a directive expression at "@name(" and an echo at
     * "{{" or "{!!", and tracking quotes so a bracket inside a string literal does not
     * count. What comes back is the state the next line starts in.
     *
     * @param  int  $openBrackets  Unclosed brackets carried in from earlier lines.
     * @param  string|null  $openEcho  Closing token of an echo still open, or null.
     * @return array{int, string|null}
     */
    private static function carryOver(string $line, int $openBrackets, ?string $openEcho): array
    {
        $quote = null;
        $length = strlen($line);
        $i = 0;

        while ($i < $length) {
            $char = $line[$i];

            if ($quote !== null) {
                if ($char === '\\') {
                    $i += 2;

                    continue;
                }

                if ($char === $quote) {
                    $quote = null;
                }

                $i++;

                continue;
            }

            if ($openEcho !== null) {
                if (substr($line, $i, strlen($openEcho)) === $openEcho) {
                    $i += strlen($openEcho);
                    $openEcho = null;

                    continue;
                }

                $i++;

                continue;
            }

            if ($char === "'" || $char === '"') {
                $quote = $char;
                $i++;

                continue;
            }

            if ($openBrackets > 0) {
                if ($char === '(' || $char === '[') {
                    $openBrackets++;
                } elseif ($char === ')' || $char === ']') {
                    $openBrackets--;
                }

                $i++;

                continue;
            }

            if (substr($line, $i, 3) === '{!!') {
                $openEcho = '!!}';
                $i += 3;

                continue;
            }

            if (substr($line, $i, 2) === '{{') {
                $openEcho = '}}';
                $i += 2;

                continue;
            }

            if ($char === '@' && preg_match('/\G@[a-zA-Z]\w*\s*\(/', $line, $m, 0, $i) === 1) {
                $openBrackets = 1;
                $i += strlen($m[0]);

                continue;
            }

            $i++;
        }

        return [$openBrackets, $openEcho];
    }

    /**
     * Build compiled-line → original-blade-line mapping.
     *
     * Scans compiled PHP for __BLADE_LINE_N__ markers. Each compiled line
     * maps to the most recently seen marker's original line number.
     *
     * @return array<int, int> Keys = compiled PHP line (1-indexed), values = original Blade line
     */
    private static function buildLineMap(string $compiledPhp): array
    {
        $map = [];
        $lines = explode("\n", $compiledPhp);
        $currentBladeLine = 1;

        foreach ($lines as $compiledIdx => $line) {
            if (preg_match('/__BLADE_LINE_(\d+)__/', $line, $m)) {
                $currentBladeLine = (int) $m[1];
            }
            $map[$compiledIdx + 1] = $currentBladeLine;
        }

        return $map;
    }
}
