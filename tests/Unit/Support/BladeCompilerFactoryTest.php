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
     *
     * The annotation is not redundant with the attribute: composer allows phpunit ^9
     * through ^13, and the CI matrix resolves 9 on Laravel 9, which reads only the
     * annotation, while 12 dropped annotations and reads only the attribute.
     *
     * @dataProvider multiLineDirectiveProvider
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
            // An inline @php(...) is self-closing, so the tracking above must stay live for
            // the rest of the file. Blade re-flows a foreach header onto one line, so if the
            // marker had switched to the comment form it would swallow the rest of that
            // header and leave @endforeach orphaned.
            'foreach split after an inline @php call' => ["<div>\n@php(\$x = 1)\n@foreach (\$items\n    as \$item)\n    {{ \$item }}\n@endforeach\n</div>\n"],
            'forelse split after an inline @php call' => ["<div>\n@php(\$x = 1)\n@forelse (\$items\n    as \$item)\n    {{ \$item }}\n@empty\n    none\n@endforelse\n</div>\n"],
            'inline @php call split across lines' => ["<div>\n@php(\$x = [\n    1,\n    2,\n])\n{{ count(\$x) }}\n</div>\n"],
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
     * An inline @php(...) compiles to a self-contained <?php ... ?> and has no @endphp,
     * so the lines after it are still markup and must keep the markup marker form.
     */
    public function test_an_inline_php_call_does_not_switch_the_rest_of_the_file_to_the_block_marker_form(): void
    {
        $blade = "<div>\n@php(\$x = 1)\n{{ \$x }}\n<p>after</p>\n</div>\n";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);

        $this->assertStringNotContainsString(
            '// __BLADE_LINE_',
            $result['compiledPhp'],
            'The comment marker form is only safe inside a @php block, where Blade copies the body verbatim.'
        );

        // The echo opens on Blade line 3 and the paragraph on line 4; neither may shift.
        $echo = $this->compiledLineContaining($result['compiledPhp'], 'echo e(');
        $tail = $this->compiledLineContaining($result['compiledPhp'], '<p>after</p>');

        $this->assertSame(3, $result['lineMap'][$echo] ?? null);
        $this->assertSame(4, $result['lineMap'][$tail] ?? null);
    }

    /**
     * Only a bare @php opens a block that runs until @endphp. Reading the call form as an
     * opening latches the comment marker for the rest of the file, because no @endphp ever
     * arrives to close it.
     *
     * The annotation is not redundant with the attribute: composer allows phpunit ^9
     * through ^13, and the CI matrix resolves 9 on Laravel 9, which reads only the
     * annotation, while 12 dropped annotations and reads only the attribute.
     *
     * @dataProvider phpDirectiveFormProvider
     */
    #[DataProvider('phpDirectiveFormProvider')]
    public function test_only_a_bare_php_directive_opens_a_block(string $blade, bool $opensBlock): void
    {
        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);

        if ($opensBlock) {
            $this->assertStringContainsString('// __BLADE_LINE_', $result['compiledPhp']);

            return;
        }

        $this->assertStringNotContainsString('// __BLADE_LINE_', $result['compiledPhp']);
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function phpDirectiveFormProvider(): array
    {
        return [
            'bare directive opens a block' => ["<div>\n@php\n    \$x = 1;\n@endphp\n{{ \$x }}\n</div>\n", true],
            'call form is self-closing' => ["<div>\n@php(\$x = 1)\n{{ \$x }}\n</div>\n", false],
            // Blade's own statement matcher allows horizontal space before the parenthesis.
            'call form after a space' => ["<div>\n@php (\$x = 1)\n{{ \$x }}\n</div>\n", false],
            'call form after a tab' => ["<div>\n@php\t(\$x = 1)\n{{ \$x }}\n</div>\n", false],
            'block opened and closed on one line' => ["<div>\n@php \$x = 1; @endphp\n{{ \$x }}\n</div>\n", false],
            // A longer name is a different directive, so the word boundary must hold.
            'a directive whose name merely starts with php' => ["<div>\n@phpunit\n{{ \$x }}\n</div>\n", false],
            // Text that merely reads @php is not a directive. Each of these carries a @foreach
            // whose expression spans lines, because that is what a latched marker destroys:
            // Blade re-flows the header onto one line and the comment swallows its closing
            // parenthesis. A single-line tail would parse either way and prove nothing.
            'an escaped directive' => ["<div>\n<p>@@php</p>\n@foreach (\n    \$users as \$user\n)\n{{ \$user }}\n@endforeach\n</div>\n", false],
            'a mention in prose' => ["<div>\n<p>Use @php blocks here</p>\n@foreach (\n    \$users as \$user\n)\n{{ \$user }}\n@endforeach\n</div>\n", false],
            'a mention in an html comment' => ["<div>\n<!-- @php -->\n@foreach (\n    \$users as \$user\n)\n{{ \$user }}\n@endforeach\n</div>\n", false],
        ];
    }

    /**
     * Reading a mention of @php as a block opening stopped the continuation tracking, so a
     * marker landed inside a @foreach header Blade had re-flowed onto one line and commented
     * out its closing parenthesis. parseCode() then returned [] and both Blade analyzers
     * skipped the whole template without saying so.
     *
     * The annotation is not redundant with the attribute: composer allows phpunit ^9
     * through ^13, and the CI matrix resolves 9 on Laravel 9, which reads only the
     * annotation, while 12 dropped annotations and reads only the attribute.
     *
     * @dataProvider phpDirectiveFormProvider
     */
    #[DataProvider('phpDirectiveFormProvider')]
    public function test_every_php_directive_form_leaves_the_compiled_php_parseable(string $blade, bool $opensBlock): void
    {
        // $opensBlock belongs to the sibling test above; the provider is shared, and PHPUnit
        // warns on a data set with more arguments than the method takes.
        unset($opensBlock);

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);

        $this->assertNotEmpty(
            (new AstParser)->parseCode($result['compiledPhp']),
            'Compiled PHP did not parse, so every AST-based analyzer would skip this template.'
        );
    }

    /**
     * @switch is the only directive that leaves PHP mode open: it compiles to an open tag that
     * the first @case closes. A markup marker in between opens PHP inside PHP, so the compiled
     * output does not parse and both Blade analyzers skip the template without saying so.
     *
     * The annotation is not redundant with the attribute: composer allows phpunit ^9
     * through ^13, and the CI matrix resolves 9 on Laravel 9, which reads only the
     * annotation, while 12 dropped annotations and reads only the attribute.
     *
     * @dataProvider switchTemplateProvider
     */
    #[DataProvider('switchTemplateProvider')]
    public function test_a_switch_still_compiles_to_parseable_php(string $blade): void
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
    public static function switchTemplateProvider(): array
    {
        return [
            'one case' => ["<div>\n@switch (\$a)\n@case(1)\n    one\n@break\n@endswitch\n</div>\n"],
            'several cases and a default' => ["<div>\n@switch (\$a)\n@case(1)\n    one\n@break\n@case(2)\n    two\n@break\n@default\n    other\n@endswitch\n</div>\n"],
            // Blade's own statement matcher allows horizontal space before the parenthesis.
            'no space before the parenthesis' => ["<div>\n@switch(\$a)\n@case(1)\n    one\n@break\n@endswitch\n</div>\n"],
            'switch and case on one line' => ["<div>\n@switch (\$a) @case(1) one @break @endswitch\n</div>\n"],
            'blank lines before the first case' => ["<div>\n@switch (\$a)\n\n\n@case(1)\n    one\n@break\n@endswitch\n</div>\n"],
            'a blade comment before the first case' => ["<div>\n@switch (\$a)\n{{-- pick one --}}\n@case(1)\n    one\n@break\n@endswitch\n</div>\n"],
            'switch with a split expression' => ["<div>\n@switch (\n    \$a\n)\n@case(1)\n    one\n@break\n@endswitch\n</div>\n"],
            'case with a split expression' => ["<div>\n@switch (\$a)\n@case(\n    1\n)\n    one\n@break\n@endswitch\n</div>\n"],
            'a switch nested in a case' => ["<div>\n@switch (\$a)\n@case(1)\n@switch (\$b)\n@case(2)\n    two\n@break\n@endswitch\n@break\n@endswitch\n</div>\n"],
            'a switch inside a foreach' => ["<div>\n@foreach (\$rows as \$row)\n@switch (\$row->type)\n@case(1)\n    {{ \$row->name }}\n@break\n@endswitch\n@endforeach\n</div>\n"],
            'two switches in one template' => ["<div>\n@switch (\$a)\n@case(1)\n    one\n@break\n@endswitch\n@switch (\$b)\n@case(2)\n    two\n@break\n@endswitch\n</div>\n"],
            // The call form is self-closing, so the lines after it are still markup and the
            // switch header that follows has to be recognised from that state.
            'a switch after an inline @php call' => ["<div>\n@php(\$a = 1)\n@switch (\$a)\n@case(1)\n    one\n@break\n@endswitch\n</div>\n"],
        ];
    }

    /**
     * The first @case is a statement of its own rather than a continuation of the @switch line,
     * so it keeps its own number instead of inheriting the one above it.
     */
    public function test_a_case_keeps_its_own_line_and_does_not_shift_what_follows(): void
    {
        // @switch opens on Blade line 2, its first @case is line 3, that case's body line 4,
        // and the second @case line 6.
        $blade = "<div>\n    @switch (\$status)\n        @case('a')\n            {{ \$a }}\n            @break\n        @case('b')\n            {{ \$b }}\n            @break\n    @endswitch\n</div>\n";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);

        $firstCase = $this->compiledLineContaining($result['compiledPhp'], "case ('a')");
        $firstBody = $this->compiledLineContaining($result['compiledPhp'], 'echo e($a)');
        $secondCase = $this->compiledLineContaining($result['compiledPhp'], "case ('b')");

        $this->assertSame(3, $result['lineMap'][$firstCase] ?? null);
        $this->assertSame(4, $result['lineMap'][$firstBody] ?? null);
        $this->assertSame(6, $result['lineMap'][$secondCase] ?? null);
    }

    /**
     * Only the real directive opens a header. An escaped @@switch renders as text, so reading it
     * as one would leave the comment marker form running through the markup after it.
     */
    public function test_an_escaped_switch_does_not_open_a_header(): void
    {
        $blade = "<div>\n<p>@@switch (\$a) is written literally</p>\n{{ \$x }}\n<p>after</p>\n</div>\n";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);

        $this->assertStringNotContainsString('// __BLADE_LINE_', $result['compiledPhp']);
    }

    /**
     * PHP mode can already be open where a marker lands, and the markup form then nests an
     * open tag inside PHP. A @php block and a @switch header were the known cases; a raw
     * "<?php" the author wrote straight into the template is the third (#415), and a heredoc
     * body is a place where neither form is safe.
     *
     * The annotation is not redundant with the attribute: composer allows phpunit ^9
     * through ^13, and the CI matrix resolves 9 on Laravel 9, which reads only the
     * annotation, while 12 dropped annotations and reads only the attribute.
     *
     * @dataProvider phpModeTemplateProvider
     */
    #[DataProvider('phpModeTemplateProvider')]
    public function test_php_already_being_open_still_compiles_to_parseable_php(string $blade): void
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
    public static function phpModeTemplateProvider(): array
    {
        return [
            'a raw tag spanning lines' => ["<div>\n<?php\n    \$c = 'red';\n?>\n<p>{{ \$c }}</p>\n</div>\n"],
            'a raw tag on one line' => ["<div>\n<?php \$c = 'red'; ?>\n<p>{{ \$c }}</p>\n</div>\n"],
            'two raw tags' => ["<div>\n<?php\n\$a = 1;\n?>\n<p>x</p>\n<?php\n\$b = 2;\n?>\n</div>\n"],
            // Only PHP's lexer knows a close token inside a string does not close the mode.
            'a close token inside a string' => ["<div>\n<?php\n    \$s = '?>';\n    \$t = 2;\n?>\n<p>{{ \$t }}</p>\n</div>\n"],
            'a close token inside a block comment' => ["<div>\n<?php\n    /* not a close token */\n    \$t = 2;\n?>\n<p>{{ \$t }}</p>\n</div>\n"],
            'a raw tag with no closer' => ["<div>\n<?php\n    \$t = 2;\n"],
            'the short echo tag' => ["<div>\n<?=\n    \$t\n?>\n<p>after</p>\n</div>\n"],
            // A split @foreach after the raw tag: the continuation tracking has to survive it.
            'a raw tag before a split directive' => ["<div>\n<?php\n\$u = [];\n?>\n@foreach (\n    \$u as \$x\n)\n{{ \$x }}\n@endforeach\n</div>\n"],
            'a heredoc inside a raw tag' => ["<div>\n<?php\n    \$s = <<<EOT\n    hi\n    EOT;\n?>\n<p>{{ \$s }}</p>\n</div>\n"],
            // Indented is the shape that breaks: a marker at column zero becomes the body's
            // least indented line and PHP rejects the closing identifier.
            'an indented heredoc inside a @php block' => ["<div>\n@php\n    \$s = <<<EOT\n    hi\n    EOT;\n@endphp\n<p>{{ \$s }}</p>\n</div>\n"],
            'an indented nowdoc inside a @php block' => ["<div>\n@php\n    \$s = <<<'EOT'\n    hi\n    EOT;\n@endphp\n<p>{{ \$s }}</p>\n</div>\n"],
        ];
    }

    /**
     * A raw tag must not shift what follows it: the markup after the close token keeps its own
     * Blade line, so a finding there is reported where the author wrote it.
     */
    public function test_markup_after_a_raw_tag_keeps_its_own_line(): void
    {
        // The raw tag opens on Blade line 2 and closes on 4; the paragraph is line 5.
        $blade = "<div>\n<?php\n    \$c = 'red';\n?>\n<p>{{ \$c }}</p>\n</div>\n";

        $result = BladeCompilerFactory::compile($blade);

        $this->assertNotNull($result);

        $echo = $this->compiledLineContaining($result['compiledPhp'], 'echo e($c)');

        $this->assertSame(5, $result['lineMap'][$echo] ?? null);
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
