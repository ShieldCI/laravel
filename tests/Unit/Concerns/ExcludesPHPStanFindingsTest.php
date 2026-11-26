<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Concerns\ExcludesPHPStanFindings;
use ShieldCI\Tests\AnalyzerTestCase;

/**
 * The excludePaths entries PHPStan is given once shieldci.excluded_paths has been applied to
 * the analysed paths, and whether anything is left for it to analyse.
 */
class ExcludesPHPStanFindingsTest extends AnalyzerTestCase
{
    /**
     * The patterns config/shieldci.php ships.
     */
    private const SHIPPED_EXCLUDES = ['vendor/*', 'node_modules/*', 'storage/*', 'bootstrap/cache/*', 'tests/*'];

    private string $basePath = '';

    protected function setUp(): void
    {
        parent::setUp();

        $php = "<?php\n";

        $this->basePath = $this->createTempDirectory([
            'app/Services/Ledger.php' => $php,
            'app/Archive/Dormant.php' => $php,
            'app/Archive/Older/Retired.php' => $php,
            'app/Http/Kernel.php' => $php,
            'app/Http/Controllers/LedgerController.php' => $php,
            'app/Http/Middleware/Archive/Gate.php' => $php,
            'app/Http/Middleware/Assets/shield.svg' => "<svg/>\n",
            'app/helpers.php' => $php,
            'app/notes.txt' => "notes\n",
            'bootstrap/app.php' => $php,
            'bootstrap/cache/services.php' => $php,
            'resources/css/ledger.css' => "body {}\n",
            'resources/js/ledger.js' => "export {};\n",
            'resources/lang/en/ledger.php' => $php,
            'resources/views/ledger.blade.php' => $php,
            'routes/web.php' => $php,
            'tests/Feature/LedgerTest.php' => $php,
            'vendor/acme/widgets/Widget.php' => $php,
        ]);
    }

    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ExclusionAnalyzer;
    }

    public function test_excludes_nothing_and_reads_nothing_without_exclude_patterns(): void
    {
        $this->withUnreadableDirectory('app', function (): void {
            $this->assertExclusions([], true, [], ['app', '.', 'routes']);
        });
    }

    public function test_excludes_nothing_when_nothing_beneath_the_paths_is_excluded(): void
    {
        $this->assertExclusions([], true, self::SHIPPED_EXCLUDES, ['app', 'routes']);
    }

    public function test_excludes_a_directory_an_exclude_pattern_covers(): void
    {
        $this->assertExclusions(['app/Archive/*'], true, ['app/Archive/*'], ['app']);
    }

    public function test_excludes_a_nested_directory_an_exclude_pattern_covers(): void
    {
        $this->assertExclusions(['app/Http/Middleware/Archive/*'], true, ['app/Http/Middleware/Archive/*'], ['app']);
    }

    public function test_excludes_a_single_excluded_file_on_its_own(): void
    {
        // A wildcard-free pattern names one file, so its directory is not excluded with it.
        $this->assertExclusions(['app/Archive/Dormant.php'], true, ['app/Archive/Dormant.php'], ['app']);
    }

    public function test_matches_a_pattern_written_against_the_absolute_path(): void
    {
        $this->assertExclusions(['app/Archive/*', 'app/Http/Middleware/Archive/*'], true, ['*/Archive/*'], ['app']);
    }

    public function test_collapses_a_directory_whose_every_file_is_excluded_into_one_entry(): void
    {
        // '*.php' covers no directory, but leaves app/Services and app/Archive with nothing
        // in them, while app/Http/Middleware/Assets keeps a file that is not PHP.
        $this->assertExclusions([
            'app/Archive/*',
            'app/Http/Controllers/*',
            'app/Http/Kernel.php',
            'app/Http/Middleware/Archive/*',
            'app/Services/*',
            'app/helpers.php',
        ], true, ['*.php'], ['app']);
    }

    public function test_does_not_walk_a_covered_directory(): void
    {
        // An unreadable directory would fail the walk, so it can only be excluded unread.
        $this->withUnreadableDirectory('app/Archive', function (): void {
            $this->assertExclusions(['app/Archive/*'], true, ['app/Archive/*'], ['app']);
        });
    }

    public function test_does_not_walk_a_directory_no_pattern_can_reach(): void
    {
        $this->withUnreadableDirectory('app/Http', function (): void {
            $this->assertExclusions([], true, self::SHIPPED_EXCLUDES, ['app']);
        });
    }

    public function test_walks_the_base_path_itself(): void
    {
        $this->assertExclusions(['bootstrap/cache/*', 'tests/*', 'vendor/*'], true, self::SHIPPED_EXCLUDES, ['.']);
    }

    /**
     * @dataProvider appSpellingProvider
     */
    #[DataProvider('appSpellingProvider')]
    public function test_reads_every_spelling_of_a_path_like_its_relative_form(string $path): void
    {
        $this->assertExclusions(['app/Archive/*'], true, ['app/Archive/*'], [str_replace('{base}', $this->basePath, $path)]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function appSpellingProvider(): array
    {
        return [
            'dot-slash with trailing slash' => ['./app/'],
            'backslash' => ['app\\'],
            'absolute' => ['{base}/app'],
            'absolute with trailing slash' => ['{base}/app/'],
        ];
    }

    public function test_a_path_that_does_not_exist_excludes_nothing(): void
    {
        $this->assertExclusions([], true, ['app/Missing/*', 'tests/*'], ['app/Missing', 'tests/Missing']);
    }

    public function test_excludes_a_configured_file_path_that_is_excluded(): void
    {
        // A file that is itself an analysed path is excluded like one found in a directory.
        $this->assertExclusions(['app/Archive/Dormant.php'], false, ['app/Archive/*'], ['app/Archive/Dormant.php']);
    }

    public function test_an_excluded_file_path_beside_a_directory_leaves_the_directory_to_analyse(): void
    {
        $this->assertExclusions(['app/helpers.php'], true, ['app/helpers.php'], ['app/Services', 'app/helpers.php']);
    }

    public function test_an_explicit_file_path_waives_a_pattern_that_covers_it(): void
    {
        $this->assertExclusions([], true, ['app/Archive/*'], ['app/Archive/Dormant.php'], ['app/Archive/Dormant.php']);
    }

    public function test_a_configured_file_path_that_is_not_excluded_excludes_nothing(): void
    {
        $this->assertExclusions([], true, ['app/Archive/*'], ['app/helpers.php']);
    }

    public function test_counts_a_directory_whose_every_file_is_excluded_as_nothing_to_analyse(): void
    {
        $this->assertExclusions(['app/Archive/*'], false, ['app/Archive/*.php', 'app/Archive/Older/*.php'], ['app/Archive']);
    }

    public function test_escapes_glob_characters_in_an_excluded_directory_name(): void
    {
        // PHPStan reads [ as the start of an fnmatch class. Escaped, the entry becomes a
        // pattern, so a directory needs /* to match the files beneath it.
        $this->addFiles(['app/Legacy[1]/Old.php' => "<?php\n", 'app/Old*Star/Old.php' => "<?php\n"]);

        $this->assertExclusions(['app/Legacy[[]1[]]/*', 'app/Old[*]Star/*'], true, ['app/Legacy[1]/*', 'app/Old*Star/*'], ['app']);
    }

    public function test_ends_a_directory_entry_with_a_separator_so_a_sibling_sharing_its_prefix_is_not_excluded(): void
    {
        // PHPStan 1.x matches a literal entry as a string prefix, so app/Models/User would
        // also exclude app/Models/User.php and app/Models/UserProfile/.
        $this->addFiles([
            'app/Models/User/Legacy.php' => "<?php\n",
            'app/Models/User.php' => "<?php\n",
            'app/Models/UserProfile/Profile.php' => "<?php\n",
        ]);

        $this->assertExclusions(['app/Models/User/*'], true, ['app/Models/User/*'], ['app']);
    }

    public function test_escapes_a_closing_bracket_in_an_excluded_directory_name(): void
    {
        // PHPStan reads any of * ? [ ] as a pattern, a lone ] included.
        $this->addFiles(['app/v2]/Old.php' => "<?php\n"]);

        $this->assertExclusions(['app/v2[]]/*'], true, ['app/v2]/*'], ['app']);
    }

    public function test_escapes_glob_characters_in_an_excluded_file_name(): void
    {
        $this->addFiles(['app/Reports/Q[1].php' => "<?php\n", 'app/Reports/Q2.php' => "<?php\n"]);

        $this->assertExclusions(['app/Reports/Q[[]1[]].php'], true, ['app/Reports/Q[1].php'], ['app']);
    }

    public function test_leaves_nothing_to_analyse_when_every_path_is_covered(): void
    {
        $this->assertExclusions(['app/*', 'routes/*'], false, ['app/*', 'routes/*'], ['app', 'routes']);
    }

    public function test_an_explicit_path_waives_a_pattern_that_covers_it(): void
    {
        $this->assertExclusions([], true, self::SHIPPED_EXCLUDES, ['tests'], ['tests']);
    }

    public function test_a_shared_path_does_not_waive_a_pattern_that_covers_it(): void
    {
        $this->assertExclusions(['tests/*'], false, self::SHIPPED_EXCLUDES, ['tests']);
    }

    public function test_an_explicit_path_waives_only_the_patterns_that_cover_it(): void
    {
        $this->assertExclusions(['app/Archive/*'], true, ['app/Archive/*'], ['app'], ['app']);
    }

    public function test_an_explicit_path_below_a_walked_directory_keeps_its_waiver(): void
    {
        // 'tests/*' covers tests/, but the explicit tests path waives it beneath tests/.
        $this->assertExclusions(['bootstrap/cache/*', 'vendor/*'], true, self::SHIPPED_EXCLUDES, ['.', 'tests'], ['.', 'tests']);
    }

    public function test_leaves_php_free_directories_to_phpstan(): void
    {
        // Whether PHPStan finds anything depends on the project's fileExtensions, so only a
        // path that is excluded outright counts as nothing to analyse.
        $this->assertExclusions(['resources/lang/*'], true, ['resources/lang/*'], ['resources']);
    }

    public function test_a_configured_directory_holding_no_php_file_is_left_to_phpstan(): void
    {
        // Nothing is excluded beneath it, so the run goes ahead as it would without patterns.
        $this->assertExclusions([], true, ['app/Archive/*'], ['resources/js']);
    }

    public function test_one_analysable_path_is_enough(): void
    {
        $this->assertExclusions(['app/*'], true, ['app/*'], ['app', 'routes']);
    }

    /**
     * @param  array<int, string>  $expectedRelative  excluded entries, relative to the base path
     * @param  array<int, string>  $patterns
     * @param  array<int, string>  $paths
     * @param  array<int, string>  $explicitPaths
     */
    private function assertExclusions(array $expectedRelative, bool $analysable, array $patterns, array $paths, array $explicitPaths = []): void
    {
        $analyzer = new ExclusionAnalyzer;
        $analyzer->setBasePath($this->basePath);
        $analyzer->setExcludePatterns($patterns);

        $realBase = (string) realpath($this->basePath);

        $this->assertSame([
            // Blade templates are always left out, by extension, after the concrete entries. A
            // directory entry ends in /*, so PHPStan 1.x's prefix match cannot reach a sibling.
            'excludePaths' => [...array_map(static fn (string $path): string => $realBase.'/'.$path, $expectedRelative), '*.blade.php'],
            'analysable' => $analysable,
            'excludesConfigured' => $expectedRelative !== [],
        ], $analyzer->exclusions($paths, $explicitPaths));
    }

    /**
     * @param  array<string, string>  $files  path => contents, relative to the base path
     */
    private function addFiles(array $files): void
    {
        foreach ($files as $path => $contents) {
            @mkdir(dirname($this->basePath.'/'.$path), 0755, true);
            file_put_contents($this->basePath.'/'.$path, $contents);
        }
    }

    private function withUnreadableDirectory(string $path, callable $callback): void
    {
        $directory = $this->basePath.'/'.$path;
        chmod($directory, 0);

        try {
            if (is_readable($directory)) {
                $this->markTestSkipped('Cannot make a directory unreadable here (running as root?)');
            }

            $callback();
        } finally {
            chmod($directory, 0755);
        }
    }
}

/**
 * The smallest analyzer that carries the trait, with its exclusions made public.
 */
class ExclusionAnalyzer extends AbstractFileAnalyzer
{
    use ExcludesPHPStanFindings;

    /**
     * @param  array<int, string>  $paths
     * @param  array<int, string>  $explicitPaths
     * @return array{excludePaths: list<string>, analysable: bool, excludesConfigured: bool}
     */
    public function exclusions(array $paths, array $explicitPaths = []): array
    {
        return $this->phpstanExclusions($paths, $explicitPaths);
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'exclusion-test-double',
            name: 'Exclusion Test Double',
            description: 'Exposes the PHPStan exclusions',
            category: Category::Reliability,
            severity: Severity::Low,
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        return $this->passed('Not used');
    }
}
