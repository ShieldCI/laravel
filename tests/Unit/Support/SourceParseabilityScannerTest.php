<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PhpParser\Parser;
use PhpParser\ParserFactory;
use PhpParser\PhpVersion;
use ShieldCI\AnalyzerManager;
use ShieldCI\Enums\ParseFailureCause;
use ShieldCI\Support\BladeCompilerFactory;
use ShieldCI\Support\PathFilter;
use ShieldCI\Support\SourceParseabilityScanner;
use ShieldCI\Tests\TestCase;

class SourceParseabilityScannerTest extends TestCase
{
    /**
     * A scanner pointed at the same paths and exclusions an installed suite would use.
     *
     * @param  array<string>|null  $paths
     * @param  array<string>|null  $excluded
     */
    private function scanner(?array $paths = null, ?array $excluded = null, ?Parser $parser = null): SourceParseabilityScanner
    {
        return new SourceParseabilityScanner(
            new PathFilter(
                $paths ?? AnalyzerManager::DEFAULT_ANALYZE_PATHS,
                $excluded ?? []
            ),
            $parser
        );
    }

    public function test_reports_nothing_when_every_enumerated_file_parses(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Models/User.php' => "<?php\n\nnamespace App\\Models;\n\nclass User {}\n",
            'config/app.php' => "<?php\n\nreturn ['name' => 'Test'];\n",
            'routes/web.php' => "<?php\n\nRoute::get('/', fn () => 'ok');\n",
            'database/seeders/DatabaseSeeder.php' => "<?php\n\nclass DatabaseSeeder {}\n",
        ]);

        $this->assertSame([], $this->scanner()->scan($basePath));
    }

    public function test_reports_a_genuine_syntax_error_with_the_parsers_own_message_and_line(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Http/Controllers/BrokenController.php' => "<?php\n\nclass BrokenController\n{\n    public function index(\n}\n",
        ]);

        $failures = $this->scanner()->scan($basePath);

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

        $failures = $this->scanner(parser: (new ParserFactory)->createForVersion(PhpVersion::fromString('8.0')))
            ->scan($basePath);

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

        $failures = $this->scanner(parser: (new ParserFactory)->createForVersion(PhpVersion::fromString('8.0')))
            ->scan($basePath);

        $this->assertCount(1, $failures);
        $this->assertSame(ParseFailureCause::SyntaxError, $failures[0]->cause);
    }

    public function test_states_that_every_ast_based_analyzer_skipped_the_file(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Broken.php' => "<?php\n\nclass Broken\n{\n    public function index(\n}\n",
        ]);

        $consequence = $this->scanner()->scan($basePath)[0]->consequence();

        $this->assertStringContainsString('app/Broken.php', $consequence);
        $this->assertStringContainsString('every AST-based analyzer', $consequence);
        $this->assertStringContainsString('did not run', $consequence);
    }

    public function test_each_cause_describes_itself_and_carries_its_own_fix(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Broken.php' => "<?php\n\nclass Broken\n{\n    public function index(\n}\n",
        ]);

        $failure = $this->scanner()->scan($basePath)[0];

        $this->assertStringContainsString('app/Broken.php:6', $failure->describe());
        $this->assertStringContainsString('Syntax error', $failure->describe());
        $this->assertStringContainsString('Fix the syntax error', $failure->cause->recommendation());

        // The other cause is the toolchain's problem, so it must not read as broken code.
        $this->assertStringContainsString(
            'Upgrade nikic/php-parser',
            ParseFailureCause::UnsupportedSyntax->recommendation()
        );
        $this->assertSame('Unsupported by the pinned parser', ParseFailureCause::UnsupportedSyntax->label());

        // A file that never reached a parser is a third situation with a third fix.
        $this->assertSame('Unreadable', ParseFailureCause::Unreadable->label());
        $this->assertStringContainsString('read access', ParseFailureCause::Unreadable->recommendation());
    }

    public function test_enumerates_every_php_file_under_the_configured_paths(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Models/User.php' => "<?php\n",
            'config/app.php' => "<?php\n",
            'routes/web.php' => "<?php\n",
            'database/migrations/2024_01_01_000000_create_users_table.php' => "<?php\n",
            'resources/views/welcome.blade.php' => "<div>ok</div>\n",
            'resources/views/partials/nav.blade.php' => "<nav>ok</nav>\n",
        ]);

        $this->assertSame([
            'app/Models/User.php',
            'config/app.php',
            'database/migrations/2024_01_01_000000_create_users_table.php',
            'resources/views/partials/nav.blade.php',
            'resources/views/welcome.blade.php',
            'routes/web.php',
        ], $this->scanner()->filesToScan($basePath));
    }

    public function test_leaves_out_non_php_files(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Models/User.php' => "<?php\n",
            'resources/views/README.md' => "not php\n",
            'resources/views/app.css' => "body {}\n",
            'database/schema/mysql-schema.sql' => "SELECT 1;\n",
        ]);

        $this->assertSame(['app/Models/User.php'], $this->scanner()->filesToScan($basePath));
    }

    public function test_scans_only_the_paths_the_suite_was_configured_to_analyze(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Models/User.php' => "<?php\n",
            'modules/Billing/Broken.php' => "<?php class {\n",
        ]);

        // bootstrap/ and anything else outside paths.analyze is not the suite's to read,
        // so claiming an analyzer skipped a file there would be false.
        $this->assertSame(['app/Models/User.php'], $this->scanner()->filesToScan($basePath));

        // An application that adds a path gets that path scanned, rather than the silence
        // this helper exists to remove.
        $this->assertSame(
            ['app/Models/User.php', 'modules/Billing/Broken.php'],
            $this->scanner(paths: ['app', 'modules'])->filesToScan($basePath)
        );
    }

    public function test_honours_the_configured_exclusions(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Models/User.php' => "<?php\n",
            'app/Legacy/Broken.php' => "<?php class {\n",
        ]);

        $this->assertSame(
            ['app/Models/User.php'],
            $this->scanner(excluded: ['app/Legacy/*'])->filesToScan($basePath)
        );
    }

    public function test_enumerates_published_vendor_views(): void
    {
        // vendor:publish puts real application source under resources/views/vendor, and
        // the default 'vendor/*' exclusion is anchored so it does not cover it.
        $basePath = $this->createTempDirectory([
            'resources/views/vendor/mail/html/message.blade.php' => "<div>ok</div>\n",
        ]);

        $this->assertSame(
            ['resources/views/vendor/mail/html/message.blade.php'],
            $this->scanner(excluded: ['vendor/*', 'node_modules/*'])->filesToScan($basePath)
        );
    }

    public function test_reports_a_blade_template_whose_compiled_php_cannot_be_parsed(): void
    {
        $basePath = $this->createTempDirectory([
            'resources/views/broken.blade.php' => "<div>\n@php\n    \$x = ;\n@endphp\n</div>\n",
        ]);

        $failures = $this->scanner()->scan($basePath);

        $this->assertCount(1, $failures);
        $this->assertSame('resources/views/broken.blade.php', $failures[0]->path);
        // The Blade line, not the line of the compiled PHP the parser actually read.
        $this->assertSame(3, $failures[0]->line);
        $this->assertSame(ParseFailureCause::SyntaxError, $failures[0]->cause);
        $this->assertStringContainsString('Syntax error', $failures[0]->parserMessage);
    }

    public function test_reports_a_file_it_is_not_allowed_to_read(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Unreadable.php' => "<?php\n\nclass Unreadable {}\n",
        ]);

        $path = $basePath.'/app/Unreadable.php';
        $this->assertTrue(chmod($path, 0000), 'Could not make the fixture unreadable.');

        // Probing beats guessing at the platform: root bypasses the permission bits and
        // Windows ignores them outright, and in both cases the file stays readable.
        if (is_readable($path)) {
            chmod($path, 0644);
            $this->markTestSkipped('This platform does not let chmod revoke read access.');
        }

        try {
            $failures = $this->scanner()->scan($basePath);
        } finally {
            // Restore before the assertions so a failure still leaves a removable fixture.
            chmod($path, 0644);
        }

        // The file is enumerated, so staying silent about it would be the very defect
        // this helper exists to close.
        $this->assertCount(1, $failures);
        $this->assertSame('app/Unreadable.php', $failures[0]->path);
        $this->assertSame(ParseFailureCause::Unreadable, $failures[0]->cause);
        $this->assertStringContainsString('could not be read', $failures[0]->parserMessage);
    }

    public function test_a_directory_it_cannot_read_does_not_abort_the_scan(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Broken.php' => "<?php\n\nclass Broken\n{\n    public function index(\n}\n",
        ]);

        $locked = $basePath.'/app/Locked';
        $this->assertTrue(@mkdir($locked, 0755), 'Could not create the fixture directory.');
        $this->assertTrue(chmod($locked, 0000), 'Could not make the fixture directory unreadable.');

        if (is_readable($locked)) {
            chmod($locked, 0755);
            $this->markTestSkipped('This platform does not let chmod revoke directory access.');
        }

        try {
            $failures = $this->scanner()->scan($basePath);
        } finally {
            chmod($locked, 0755);
        }

        // The unreadable directory must not cost us the findings we already had.
        $this->assertCount(1, $failures);
        $this->assertSame('app/Broken.php', $failures[0]->path);
    }

    public function test_reports_a_blade_template_that_cannot_be_compiled_at_all(): void
    {
        // @classComponentOpening collides with a BladeCompiler method that requires four
        // arguments, so compilation throws before any PHP exists to hand to the parser.
        $template = "<div>\n@classComponentOpening('x')\n</div>\n";

        $this->assertNull(
            BladeCompilerFactory::compile($template),
            'Precondition: this template must be one Blade cannot compile.'
        );

        $basePath = $this->createTempDirectory([
            'resources/views/uncompilable.blade.php' => $template,
        ]);

        $failures = $this->scanner()->scan($basePath);

        $this->assertCount(1, $failures);
        $this->assertSame('resources/views/uncompilable.blade.php', $failures[0]->path);
        // No compiled PHP means no line map, so the report falls back to the file itself.
        $this->assertSame(1, $failures[0]->line);
        $this->assertStringContainsString('could not be compiled', $failures[0]->parserMessage);
        // Nothing was parsed, so this is not evidence that the author's code is broken.
        $this->assertSame(ParseFailureCause::Uncompilable, $failures[0]->cause);
        $this->assertStringContainsString('template', $failures[0]->cause->recommendation());
    }

    public function test_a_blade_template_with_valid_php_is_not_reported(): void
    {
        $basePath = $this->createTempDirectory([
            'resources/views/fine.blade.php' => "<div>\n@php\n    \$x = 1;\n@endphp\n{{ \$x }}\n</div>\n",
        ]);

        $this->assertSame([], $this->scanner()->scan($basePath));
    }

    public function test_a_blade_template_using_multi_line_directives_is_not_reported(): void
    {
        // The shape that used to be reported as broken code: healthy, and extremely common.
        $basePath = $this->createTempDirectory([
            'resources/views/nav.blade.php' => "<div>\n@include('partials.nav', [\n    'active' => true,\n])\n@if (\$a\n    && \$b)\n    yes\n@endif\n</div>\n",
        ]);

        $this->assertSame([], $this->scanner()->scan($basePath));
    }

    public function test_a_configured_path_may_name_a_single_file(): void
    {
        // The suite's own walk yields a configured path that is a file, so a scanner that
        // only understood directories would stay silent about one.
        $basePath = $this->createTempDirectory([
            'routes/web.php' => "<?php\n",
            'artisan' => "#!/usr/bin/env php\n",
            'bootstrap/app.php' => "<?php class {\n",
        ]);

        $this->assertSame(
            ['bootstrap/app.php', 'routes/web.php'],
            $this->scanner(paths: ['routes', 'bootstrap/app.php', 'artisan'])->filesToScan($basePath)
        );
    }

    public function test_returns_nothing_for_an_application_with_none_of_those_directories(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $this->assertSame([], $this->scanner()->filesToScan($basePath));
        $this->assertSame([], $this->scanner()->scan($basePath));
    }
}
