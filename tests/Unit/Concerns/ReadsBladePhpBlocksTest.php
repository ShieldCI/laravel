<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ShieldCI\Concerns\ReadsBladePhpBlocks;

class ReadsBladePhpBlocksTest extends TestCase
{
    public function test_a_bare_directive_and_its_endphp_are_one_block(): void
    {
        $blocks = ConcreteReadsBladePhpBlocks::read("<div>\n    @php\n        \$x = 1;\n    @endphp\n</div>\n");

        $this->assertSame([['open' => 2, 'close' => 4, 'size' => 1]], $blocks['blocks']);
        $this->assertSame([], $blocks['unpairedOpeners']);

        // The body runs from the line after the opener through the @endphp line, because the
        // raw block Blade lifts out includes that line.
        $this->assertSame([3 => true, 4 => true], $blocks['insideBlock']);
    }

    /**
     * Blade turns "@php $x = 1; @endphp" into a self-contained <?php ... ?> on that one line,
     * so nothing is inside it and a marker in front of it is still markup.
     */
    public function test_a_block_opened_and_closed_on_one_line_has_no_body(): void
    {
        $blocks = ConcreteReadsBladePhpBlocks::read("@php \$x = 1; @endphp\n<p>after</p>\n");

        $this->assertSame([['open' => 1, 'close' => 1, 'size' => 0]], $blocks['blocks']);
        $this->assertSame([], $blocks['unpairedOpeners']);
        $this->assertSame([], $blocks['insideBlock']);
    }

    public function test_an_unclosed_directive_is_an_unpaired_opener(): void
    {
        $blocks = ConcreteReadsBladePhpBlocks::read("<div>\n    @php\n        \$x = 1;\n</div>");

        $this->assertSame([], $blocks['blocks']);
        $this->assertSame([2], $blocks['unpairedOpeners']);
    }

    /**
     * Blade's pattern is non-greedy, so each opener pairs with the nearest following @endphp
     * rather than the last one in the file.
     */
    public function test_adjacent_blocks_are_separate_spans(): void
    {
        $blocks = ConcreteReadsBladePhpBlocks::read("@php\n\$a = 1;\n@endphp\n@php\n\$b = 2;\n@endphp\n");

        $this->assertSame([
            ['open' => 1, 'close' => 3, 'size' => 1],
            ['open' => 4, 'close' => 6, 'size' => 1],
        ], $blocks['blocks']);
    }

    /**
     * storePhpBlocks() starts its non-greedy match at the first @php it sees, call form or
     * not, so the call form here is what the later @endphp closes. Laravel compiles that
     * shape to PHP that does not parse, all on its own. Reading it any other way would put
     * this trait out of step with the compiler it exists to mirror.
     */
    public function test_a_call_form_before_a_block_pairs_the_way_laravel_pairs_it(): void
    {
        $blocks = ConcreteReadsBladePhpBlocks::read("@php(\$x = 1)\n@php\n\$y = 2;\n@endphp\n");

        $this->assertSame([['open' => 1, 'close' => 4, 'size' => 2]], $blocks['blocks']);
        $this->assertSame([], $blocks['unpairedOpeners']);
    }

    /**
     * The narrow opener test governs the unclosed report only. A paired block still pairs
     * wherever its opener sits, because the spans are read straight from the source.
     */
    public function test_an_opener_that_does_not_start_its_line_still_pairs(): void
    {
        $blocks = ConcreteReadsBladePhpBlocks::read("<div> @php\n\$x = 1;\n@endphp </div>\n");

        $this->assertSame([['open' => 1, 'close' => 3, 'size' => 1]], $blocks['blocks']);
        $this->assertSame([], $blocks['unpairedOpeners']);
    }

    public function test_an_unpaired_opener_after_a_closed_block_is_still_reported(): void
    {
        $blocks = ConcreteReadsBladePhpBlocks::read("@php \$a = 1; @endphp\n@php\n\$b = 2;\n");

        $this->assertSame([['open' => 1, 'close' => 1, 'size' => 0]], $blocks['blocks']);
        $this->assertSame([2], $blocks['unpairedOpeners']);
    }

    public function test_a_source_with_no_directives_has_nothing(): void
    {
        $blocks = ConcreteReadsBladePhpBlocks::read('');

        $this->assertSame([], $blocks['blocks']);
        $this->assertSame([], $blocks['unpairedOpeners']);
        $this->assertSame([], $blocks['insideBlock']);
    }

    /**
     * Text that merely reads "@php" is not a directive. Each of these compiles back to itself,
     * so calling any of them an unclosed block recommends an @endphp that would change what
     * the template renders.
     *
     * The annotation is not redundant with the attribute: composer allows phpunit ^9
     * through ^13, and the CI matrix resolves 9 on Laravel 9, which reads only the
     * annotation, while 12 dropped annotations and reads only the attribute.
     *
     * @dataProvider mentionProvider
     */
    #[DataProvider('mentionProvider')]
    public function test_a_mention_of_the_directive_is_not_one(string $blade): void
    {
        $blocks = ConcreteReadsBladePhpBlocks::read($blade);

        $this->assertSame([], $blocks['blocks']);
        $this->assertSame([], $blocks['unpairedOpeners']);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function mentionProvider(): array
    {
        return [
            'the escape' => ["<p>@@php</p>\n"],
            'a mention in prose' => ["<p>Use @php blocks here</p>\n"],
            'a mention in an html comment' => ["<!-- @php -->\n"],
            // A longer name is a different directive, so the word boundary must hold.
            'a longer directive name' => ["<div>\n@phpunit\n</div>\n"],
            'a mention with a word in front' => ["<p>foo@php</p>\n"],
            // storeVerbatimBlocks() empties this before storePhpBlocks() ever runs.
            'inside verbatim' => ["@verbatim\n@php\n@endverbatim\n"],
            // compileComments() strips this, so nothing of it reaches the browser.
            'inside a blade comment' => ["{{--\n@php\n--}}\n"],
            // Blade's own statement matcher allows horizontal space before the parenthesis.
            'the call form' => ["@php(\$x = 1)\n"],
            'the call form after a space' => ["@php (\$x = 1)\n"],
            'the call form after a tab' => ["@php\t(\$x = 1)\n"],
        ];
    }
}

class ConcreteReadsBladePhpBlocks
{
    use ReadsBladePhpBlocks;

    /**
     * @return array{
     *     insideBlock: array<int, true>,
     *     blocks: list<array{open: int, close: int, size: int}>,
     *     unpairedOpeners: list<int>
     * }
     */
    public static function read(string $bladeSource): array
    {
        return self::readBladePhpBlocks($bladeSource);
    }
}
