<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PhpParser\ParserFactory;
use PhpParser\PhpVersion;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Enums\ParseFailureCause;
use ShieldCI\Support\SourceParseabilityScanner;
use ShieldCI\Tests\AnalyzerTestCase;

class SourceParseabilityScannerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        throw new \LogicException('No analyzer under test.');
    }

    public function test_reports_nothing_when_every_enumerated_file_parses(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Models/User.php' => "<?php\n\nnamespace App\\Models;\n\nclass User {}\n",
            'config/app.php' => "<?php\n\nreturn ['name' => 'Test'];\n",
            'routes/web.php' => "<?php\n\nRoute::get('/', fn () => 'ok');\n",
            'database/seeders/DatabaseSeeder.php' => "<?php\n\nclass DatabaseSeeder {}\n",
            'bootstrap/app.php' => "<?php\n\nreturn new stdClass;\n",
        ]);

        $this->assertSame([], (new SourceParseabilityScanner)->scan($basePath));
    }

    public function test_reports_a_genuine_syntax_error_with_the_parsers_own_message_and_line(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Http/Controllers/BrokenController.php' => "<?php\n\nclass BrokenController\n{\n    public function index(\n}\n",
        ]);

        $failures = (new SourceParseabilityScanner)->scan($basePath);

        $this->assertCount(1, $failures);
        $this->assertSame('app/Http/Controllers/BrokenController.php', $failures[0]->path);
        $this->assertSame(6, $failures[0]->line);
        $this->assertStringContainsString('Syntax error', $failures[0]->parserMessage);
        $this->assertSame(ParseFailureCause::SyntaxError, $failures[0]->cause);
    }

    public function test_classifies_syntax_the_pinned_parser_cannot_understand_separately(): void
    {
        // An enum is valid PHP on this runtime and invalid to a parser pinned to 8.0,
        // which is exactly the shape of "the pinned parser is older than the runtime".
        $basePath = $this->createTempDirectory([
            'app/Enums/Suit.php' => "<?php\n\nnamespace App\\Enums;\n\nenum Suit: string\n{\n    case Hearts = 'H';\n}\n",
        ]);

        $scanner = new SourceParseabilityScanner(
            (new ParserFactory)->createForVersion(PhpVersion::fromString('8.0'))
        );

        $failures = $scanner->scan($basePath);

        $this->assertCount(1, $failures);
        $this->assertSame('app/Enums/Suit.php', $failures[0]->path);
        $this->assertSame(ParseFailureCause::UnsupportedSyntax, $failures[0]->cause);
    }

    public function test_the_same_file_is_a_genuine_syntax_error_to_every_parser_version(): void
    {
        // Guards the discriminator against simply echoing the pinned parser's opinion:
        // with the same 8.0 parser, code no PHP runtime accepts is still a syntax error.
        $basePath = $this->createTempDirectory([
            'app/Broken.php' => "<?php\n\nclass Broken\n{\n    public function index(\n}\n",
        ]);

        $scanner = new SourceParseabilityScanner(
            (new ParserFactory)->createForVersion(PhpVersion::fromString('8.0'))
        );

        $failures = $scanner->scan($basePath);

        $this->assertCount(1, $failures);
        $this->assertSame(ParseFailureCause::SyntaxError, $failures[0]->cause);
    }

    public function test_states_that_every_ast_based_analyzer_skipped_the_file(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Broken.php' => "<?php\n\nclass Broken\n{\n    public function index(\n}\n",
        ]);

        $consequence = (new SourceParseabilityScanner)->scan($basePath)[0]->consequence();

        $this->assertStringContainsString('app/Broken.php', $consequence);
        $this->assertStringContainsString('every AST-based analyzer', $consequence);
        $this->assertStringContainsString('did not run', $consequence);
    }

    public function test_each_cause_describes_itself_and_carries_its_own_fix(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Broken.php' => "<?php\n\nclass Broken\n{\n    public function index(\n}\n",
        ]);

        $failure = (new SourceParseabilityScanner)->scan($basePath)[0];

        $this->assertStringContainsString('app/Broken.php:6', $failure->describe());
        $this->assertStringContainsString('Syntax error', $failure->describe());
        $this->assertStringContainsString('Fix the syntax error', $failure->cause->recommendation());

        // The other cause is the toolchain's problem, so it must not read as broken code.
        $this->assertStringContainsString(
            'Upgrade nikic/php-parser',
            ParseFailureCause::UnsupportedSyntax->recommendation()
        );
        $this->assertSame('Unsupported by the pinned parser', ParseFailureCause::UnsupportedSyntax->label());
    }

    public function test_enumerates_the_directories_and_blade_templates_the_suite_reads(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Models/User.php' => "<?php\n",
            'config/app.php' => "<?php\n",
            'routes/web.php' => "<?php\n",
            'database/migrations/2024_01_01_000000_create_users_table.php' => "<?php\n",
            'bootstrap/app.php' => "<?php\n",
            'resources/views/welcome.blade.php' => "<div>ok</div>\n",
            'resources/views/partials/nav.blade.php' => "<nav>ok</nav>\n",
        ]);

        $this->assertSame([
            'app/Models/User.php',
            'bootstrap/app.php',
            'config/app.php',
            'database/migrations/2024_01_01_000000_create_users_table.php',
            'resources/views/partials/nav.blade.php',
            'resources/views/welcome.blade.php',
            'routes/web.php',
        ], (new SourceParseabilityScanner)->filesToScan($basePath));
    }

    public function test_leaves_out_paths_the_suite_never_analyzes(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Models/User.php' => "<?php\n",
            'bootstrap/cache/packages.php' => "<?php return [];\n",
            'app/vendor/acme/src/Broken.php' => "<?php class {\n",
            'app/node_modules/pkg/index.php' => "<?php class {\n",
            'resources/views/README.md' => "not php\n",
            'resources/views/app.css' => "body {}\n",
            'database/schema/mysql-schema.sql' => "SELECT 1;\n",
        ]);

        $this->assertSame(
            ['app/Models/User.php'],
            (new SourceParseabilityScanner)->filesToScan($basePath)
        );
    }

    public function test_reports_a_blade_template_whose_compiled_php_cannot_be_parsed(): void
    {
        $basePath = $this->createTempDirectory([
            'resources/views/broken.blade.php' => "<div>\n@php\n    \$x = ;\n@endphp\n</div>\n",
        ]);

        $failures = (new SourceParseabilityScanner)->scan($basePath);

        $this->assertCount(1, $failures);
        $this->assertSame('resources/views/broken.blade.php', $failures[0]->path);
        // The Blade line, not the line of the compiled PHP the parser actually read.
        $this->assertSame(3, $failures[0]->line);
        $this->assertSame(ParseFailureCause::SyntaxError, $failures[0]->cause);
        $this->assertStringContainsString('Syntax error', $failures[0]->parserMessage);
    }

    public function test_a_blade_template_with_valid_php_is_not_reported(): void
    {
        $basePath = $this->createTempDirectory([
            'resources/views/fine.blade.php' => "<div>\n@php\n    \$x = 1;\n@endphp\n{{ \$x }}\n</div>\n",
        ]);

        $this->assertSame([], (new SourceParseabilityScanner)->scan($basePath));
    }

    public function test_returns_nothing_for_an_application_with_none_of_those_directories(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $this->assertSame([], (new SourceParseabilityScanner)->filesToScan($basePath));
        $this->assertSame([], (new SourceParseabilityScanner)->scan($basePath));
    }
}
