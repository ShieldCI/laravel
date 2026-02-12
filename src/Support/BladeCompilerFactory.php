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
     */
    private static function injectLineMarkers(string $bladeSource): string
    {
        $lines = explode("\n", $bladeSource);
        $inPhpBlock = false;
        $marked = [];

        foreach ($lines as $index => $line) {
            $lineNum = $index + 1;
            $trimmed = trim($line);

            if (! $inPhpBlock && preg_match('/@php\b/', $trimmed)
                && ! str_contains($trimmed, '@endphp')) {
                $inPhpBlock = true;
                $marked[] = "<?php /* __BLADE_LINE_{$lineNum}__ */ ?>".$line;
            } elseif ($inPhpBlock && str_contains($trimmed, '@endphp')) {
                $marked[] = "// __BLADE_LINE_{$lineNum}__";
                $marked[] = $line;
                $inPhpBlock = false;
            } elseif ($inPhpBlock) {
                $marked[] = "// __BLADE_LINE_{$lineNum}__";
                $marked[] = $line;
            } else {
                $marked[] = "<?php /* __BLADE_LINE_{$lineNum}__ */ ?>".$line;
            }
        }

        return implode("\n", $marked);
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
