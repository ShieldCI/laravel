<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Support\BladeCompilerFactory;

class BladeCompilerFactoryTest extends TestCase
{
    public function test_compiles_simple_blade_to_php(): void
    {
        $result = BladeCompilerFactory::compile('<div>{{ $name }}</div>');

        $this->assertNotNull($result);
        $this->assertArrayHasKey('compiledPhp', $result);
        $this->assertArrayHasKey('lineMap', $result);
        $this->assertStringContainsString('<?php echo', $result['compiledPhp']);
    }

    public function test_line_map_maps_back_to_original_lines(): void
    {
        $blade = "<div>\n    {{ \$name }}\n</div>";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);
        $lineMap = $result['lineMap'];

        // Line map should be 1-indexed
        $this->assertArrayHasKey(1, $lineMap);

        // Should contain mappings back to original blade lines (1, 2, 3)
        $this->assertContains(1, $lineMap);
        $this->assertContains(2, $lineMap);
        $this->assertContains(3, $lineMap);
    }

    public function test_compiles_php_block_with_line_tracking(): void
    {
        $blade = "<div>\n    @php\n        \$x = 1;\n    @endphp\n</div>";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);

        // Compiled PHP should be parseable
        $ast = (new AstParser)->parseCode($result['compiledPhp']);
        $this->assertNotEmpty($ast);
    }

    public function test_handles_block_comments_inside_php_blocks(): void
    {
        $blade = "<div>\n    @php\n        /*\n         * A comment\n         */\n        \$users = User::all();\n    @endphp\n</div>";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);

        // Compiled PHP should be parseable even with block comments
        $ast = (new AstParser)->parseCode($result['compiledPhp']);
        $this->assertNotEmpty($ast);
    }

    public function test_markers_use_line_comments_inside_php_blocks(): void
    {
        $blade = "<div>\n    @php\n        \$x = 1;\n    @endphp\n</div>";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);
        // Inside @php blocks, markers should use // comments (not /* */ which would conflict)
        $this->assertStringContainsString('// __BLADE_LINE_', $result['compiledPhp']);
    }

    public function test_markers_use_php_tags_outside_php_blocks(): void
    {
        $result = BladeCompilerFactory::compile('<div>{{ $name }}</div>');

        $this->assertNotNull($result);
        $this->assertStringContainsString('__BLADE_LINE_1__', $result['compiledPhp']);
    }

    public function test_line_map_is_monotonically_non_decreasing(): void
    {
        $blade = "<h1>Title</h1>\n<p>{{ \$body }}</p>\n<footer>End</footer>";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);

        $prev = 0;
        foreach ($result['lineMap'] as $originalLine) {
            $this->assertGreaterThanOrEqual($prev, $originalLine);
            $prev = $originalLine;
        }
    }

    public function test_empty_blade_returns_result(): void
    {
        $result = BladeCompilerFactory::compile('');

        $this->assertNotNull($result);
        $this->assertArrayHasKey('compiledPhp', $result);
        $this->assertArrayHasKey('lineMap', $result);
    }

    public function test_blade_directives_compile_correctly(): void
    {
        $blade = "@if(\$show)\n    <p>Hello</p>\n@endif";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);
        $this->assertStringContainsString('<?php if', $result['compiledPhp']);
    }

    public function test_foreach_compiles_with_loop_data(): void
    {
        $blade = "@foreach(\$items as \$item)\n    <p>{{ \$item }}</p>\n@endforeach";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);
        // Blade compiles @foreach to $__currentLoopData assignment
        $this->assertStringContainsString('__currentLoopData', $result['compiledPhp']);
    }

    public function test_multiline_php_block_preserves_line_mapping(): void
    {
        $blade = "<div>\n    @php\n        \$a = 1;\n        \$b = 2;\n        \$c = \$a + \$b;\n    @endphp\n</div>";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);

        $lineMap = $result['lineMap'];

        // The line map should contain references to lines 3, 4, 5 (inside @php block)
        $this->assertContains(3, $lineMap);
        $this->assertContains(4, $lineMap);
        $this->assertContains(5, $lineMap);
    }

    /**
     * A directive whose expression spans several lines must still compile to valid PHP.
     *
     * Markers used to be injected on every line, which dropped a self-contained PHP tag
     * into the middle of the expression and made the compiled output unparseable. Callers
     * skip such a template silently, so a healthy view became invisible to analysis.
     */
    #[DataProvider('multiLineDirectiveProvider')]
    public function test_a_directive_split_across_lines_still_compiles_to_parseable_php(string $blade): void
    {
        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result, 'Blade could not compile a template that is valid.');

        $this->assertNotEmpty(
            (new AstParser)->parseCode($result['compiledPhp']),
            'Compiled PHP did not parse, so every AST-based analyzer would skip this template.'
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function multiLineDirectiveProvider(): array
    {
        return [
            'include with an array argument' => ["<div>\n@include('partials.nav', [\n    'active' => true,\n])\n</div>\n"],
            // The escaped quote must not end the string early, or the unbalanced bracket
            // inside it would be counted and the tracking would never recover.
            'include whose argument hides a bracket' => ["<div>\n@include('it\\'s (here', [\n    'a' => 1,\n])\n</div>\n"],
            'if with a split condition' => ["<div>\n@if (\$a\n    && \$b)\n    yes\n@endif\n</div>\n"],
            'escaped echo split across lines' => ["<div>\n{!! \$a\n    . \$b !!}\n</div>\n"],
            'echo split across lines' => ["<div>\n{{ \$a\n    + \$b }}\n</div>\n"],
            'foreach with a split expression' => ["<div>\n@foreach (\$items\n    as \$item)\n    {{ \$item }}\n@endforeach\n</div>\n"],
            'forelse with a split expression' => ["<div>\n@forelse (\$items\n    as \$item)\n    {{ \$item }}\n@empty\n    none\n@endforelse\n</div>\n"],
        ];
    }

    public function test_a_split_directive_maps_to_its_opening_line_and_does_not_shift_what_follows(): void
    {
        // @if opens on Blade line 2 and closes on line 3; its body is line 4.
        $blade = "<div>\n@if (\$a\n    && \$b)\n    {{ \$a }}\n@endif\n</div>\n";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);

        $condition = $this->compiledLineContaining($result['compiledPhp'], 'if(');
        $body = $this->compiledLineContaining($result['compiledPhp'], 'echo e(');

        // The condition is reported against the line the author opened the directive on,
        // and the body keeps its own line rather than being dragged back to the opening.
        $this->assertSame(2, $result['lineMap'][$condition] ?? null);
        $this->assertSame(4, $result['lineMap'][$body] ?? null);
    }

    /**
     * The 1-indexed compiled line holding $needle.
     */
    private function compiledLineContaining(string $compiledPhp, string $needle): int
    {
        foreach (explode("\n", $compiledPhp) as $index => $line) {
            if (str_contains($line, $needle)) {
                return $index + 1;
            }
        }

        $this->fail(sprintf('No compiled line contains "%s".', $needle));
    }
}
