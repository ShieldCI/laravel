<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
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
        $ast = (new \ShieldCI\AnalyzersCore\Support\AstParser)->parseCode($result['compiledPhp']);
        $this->assertNotEmpty($ast);
    }

    public function test_handles_block_comments_inside_php_blocks(): void
    {
        $blade = "<div>\n    @php\n        /*\n         * A comment\n         */\n        \$users = User::all();\n    @endphp\n</div>";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);

        // Compiled PHP should be parseable even with block comments
        $ast = (new \ShieldCI\AnalyzersCore\Support\AstParser)->parseCode($result['compiledPhp']);
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
}
