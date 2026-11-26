<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\AnalyzerManager;
use ShieldCI\Analyzers\Performance\CollectionCallAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;
use ShieldCI\Tests\Concerns\RunsRealPHPStan;

/**
 * The analyzer drives a real PHPStan process, so these tests stand up a stub at
 * vendor/bin/phpstan that prints a canned report. That runs the real JSON parsing and the
 * real matching, which a mocked support object never did. The runner names the interpreter
 * and hands it the stub as a script, so the stub is PHP rather than shell.
 */
class CollectionCallAnalyzerTest extends AnalyzerTestCase
{
    use RunsRealPHPStan;

    private const COLLECTION_MESSAGE = "Called 'count' on Laravel collection, but could have been retrieved as a query.";

    /**
     * Base path of the last project capturedArgumentsFor() built, for absolute-path assertions.
     */
    private string $lastBasePath = '';

    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CollectionCallAnalyzer;
    }

    public function test_passes_when_no_collection_issues_found(): void
    {
        $result = $this->analyzeIssues([]);

        $this->assertPassed($result);
        $this->assertSame('No inefficient collection calls detected', $result->getMessage());
        $this->assertArrayNotHasKey('analysis_errors', $result->getMetadata());
    }

    public function test_fails_on_a_finding_carrying_the_larastan_identifier(): void
    {
        $result = $this->analyzeIssues([
            ['message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER],
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertStringContainsString('Found 1 inefficient collection operation(s)', $result->getMessage());

        $issue = $result->getIssues()[0];
        $this->assertSame(Severity::Medium, $issue->severity);
        $this->assertSame(self::COLLECTION_MESSAGE, $issue->metadata['phpstan_message']);
        $this->assertSame(CollectionCallAnalyzer::IDENTIFIER, $issue->metadata['phpstan_identifier']);
    }

    public function test_the_identifier_decides_regardless_of_the_message_text(): void
    {
        // PHPStan's identifier is the stable contract; the wording is not.
        $result = $this->analyzeIssues([
            ['message' => 'Wording Larastan has never used.', 'identifier' => CollectionCallAnalyzer::IDENTIFIER],
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_falls_back_to_the_message_when_phpstan_emits_no_identifier(): void
    {
        // PHPStan below 1.11 and Larastan below 2.9 emit none, and composer.json
        // still admits both.
        $result = $this->analyzeIssues([
            ['message' => self::COLLECTION_MESSAGE],
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_ignores_a_near_miss_message_that_carries_no_identifier(): void
    {
        // Guards the loose regex this analyzer used to match on, which accepted
        // anything shaped like "called ... on ... collection".
        $result = $this->analyzeIssues([
            ['message' => 'Called filter on the result collection to narrow it.'],
        ]);

        $this->assertPassed($result);
    }

    public function test_ignores_findings_owned_by_another_rule(): void
    {
        $result = $this->analyzeIssues([
            ['message' => 'Undefined variable: $missing', 'identifier' => 'variable.undefined'],
            ['message' => self::COLLECTION_MESSAGE, 'identifier' => 'larastan.noEnvCallsOutsideOfConfig'],
        ]);

        $this->assertPassed($result);
    }

    public function test_skips_when_larastan_is_not_installed(): void
    {
        // The regression test for #344: Larastan supplies the only rule this analyzer
        // reads, so without it PHPStan completes cleanly and reports nothing. Calling
        // that "passed" claims an analysis that never happened.
        $result = $this->analyzeIssues([], larastan: false);

        $this->assertSkipped($result);
        $this->assertStringContainsString('Larastan is not installed', $result->getMessage());
    }

    public function test_skips_when_phpstan_is_not_installed(): void
    {
        $analyzer = new CollectionCallAnalyzer;
        $analyzer->setBasePath($this->createTempDirectory([]));
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('PHPStan is not installed', $result->getMessage());
    }

    public function test_reports_an_error_when_phpstan_emitted_no_parseable_output(): void
    {
        $result = $this->analyzeAbortedRun('PHPStan\Command\PathNotFoundException: Path /app was not found.', 1);

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan produced no analysable output', $result->getMessage());
        $this->assertStringContainsString('exit code 1', $result->getMessage());
        $this->assertStringContainsString('PathNotFoundException', $result->getMessage());
        $this->assertCount(1, $result->getMetadata()['analysis_errors']);
    }

    public function test_reports_an_error_when_output_is_undecodable_at_exit_zero(): void
    {
        // Undecodable output is a failure on its own, independent of how PHPStan exited.
        $result = $this->analyzeAbortedRun('', 0, 'This is not valid JSON');

        $this->assertError($result);
        $this->assertStringContainsString('exit code 0', $result->getMessage());
    }

    public function test_reports_an_error_when_only_analysis_errors_come_back(): void
    {
        $result = $this->analyzeIssues([], analysisErrors: [
            'Internal error: child process ran out of memory.',
        ]);

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan reported 1 analysis error(s)', $result->getMessage());
        $this->assertStringContainsString('ran out of memory', $result->getMessage());
        $this->assertSame(
            ['Internal error: child process ran out of memory.'],
            $result->getMetadata()['analysis_errors']
        );
    }

    public function test_reports_an_error_when_phpstan_stopped_at_a_file_it_could_not_process(): void
    {
        // PHPStan drops every other file's findings when one file will not parse, so
        // an empty collection-call list here says nothing about the rest of the project.
        $result = $this->analyzeIssues([[
            'message' => 'Syntax error, unexpected \'}\' on line 7',
            'identifier' => 'phpstan.parse',
        ]]);

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan stopped at file(s) it could not process', $result->getMessage());
        $this->assertStringContainsString('app/Services/ExampleService.php:7', $result->getMessage());
        $this->assertSame(['app/Services/ExampleService.php:7'], $result->getMetadata()['stopped_at']);
        $this->assertArrayNotHasKey('analysis_errors', $result->getMetadata());
    }

    public function test_reports_an_error_when_a_reflection_error_stopped_phpstan(): void
    {
        $result = $this->analyzeIssues([[
            'message' => 'Reflection error: Circular reference to class "App\\Services\\ExampleService"',
            'identifier' => 'phpstan.reflection',
            'line' => 0,
        ]]);

        $this->assertError($result);
        $this->assertSame(['app/Services/ExampleService.php'], $result->getMetadata()['stopped_at']);
    }

    public function test_describes_both_a_stopping_file_and_analysis_errors(): void
    {
        $result = $this->analyzeIssues(
            [['message' => 'Syntax error, unexpected EOF on line 7', 'identifier' => 'phpstan.parse']],
            analysisErrors: ['Internal error: child process died.']
        );

        $this->assertError($result);
        $this->assertStringContainsString('could not process', $result->getMessage());
        $this->assertStringContainsString('child process died', $result->getMessage());
        $this->assertSame(['Internal error: child process died.'], $result->getMetadata()['analysis_errors']);
        $this->assertSame(['app/Services/ExampleService.php:7'], $result->getMetadata()['stopped_at']);
    }

    public function test_keeps_the_warning_result_when_analysis_errors_accompany_findings(): void
    {
        // A file finding still drives the status, so a partial run is not downgraded
        // from a warning to error and its findings are not thrown away.
        $result = $this->analyzeIssues(
            [['message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER]],
            analysisErrors: ['Internal error: child process died.']
        );

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertStringContainsString('these findings may be incomplete', $result->getMessage());
        $this->assertSame(
            ['Internal error: child process died.'],
            $result->getMetadata()['analysis_errors']
        );
    }

    public function test_caps_the_quoted_analysis_errors_but_not_the_metadata(): void
    {
        $result = $this->analyzeIssues([], analysisErrors: [
            'Error1', 'Error2', 'Error3', 'Error4', 'Error5',
        ]);

        $this->assertError($result);
        $this->assertStringContainsString('Error3', $result->getMessage());
        $this->assertStringNotContainsString('Error4', $result->getMessage());
        $this->assertStringContainsString('(and 2 more)', $result->getMessage());
        $this->assertCount(5, $result->getMetadata()['analysis_errors']);
    }

    public function test_a_non_zero_exit_with_valid_json_is_not_an_error(): void
    {
        // PHPStan exits 1 whenever it reports anything at all, ordinary type errors
        // included, so a non-zero exit on its own must never read as a failed run.
        $result = $this->analyzeIssues(
            [['message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER]],
            exitCode: 1
        );

        $this->assertWarning($result);
        $this->assertArrayNotHasKey('analysis_errors', $result->getMetadata());
    }

    public function test_truncates_the_rendered_issues_but_reports_the_true_total(): void
    {
        $issues = [];

        for ($i = 1; $i <= 100; $i++) {
            $issues[] = [
                'message' => self::COLLECTION_MESSAGE,
                'line' => $i,
                'identifier' => CollectionCallAnalyzer::IDENTIFIER,
            ];
        }

        $result = $this->analyzeIssues($issues);

        $this->assertWarning($result);
        $this->assertIssueCount(50, $result);
        $this->assertStringContainsString('Found 100 inefficient collection operation(s) (showing first 50)', $result->getMessage());
        $this->assertSame(100, $result->getMetadata()['total_issues']);
        $this->assertSame(50, $result->getMetadata()['displayed_issues']);
        $this->assertTrue($result->getMetadata()['truncated']);
    }

    public function test_names_the_flagged_operation_in_the_recommendation(): void
    {
        $result = $this->analyzeIssues([
            ['message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER],
        ]);

        $this->assertStringContainsString('count', $result->getIssues()[0]->recommendation);
    }

    public function test_falls_back_to_generic_advice_for_an_unfamiliar_message(): void
    {
        $result = $this->analyzeIssues([
            ['message' => 'This value could have been retrieved as a query.'],
        ]);

        $this->assertStringContainsString('database query level', $result->getIssues()[0]->recommendation);
    }

    public function test_analyses_the_app_directory_by_default(): void
    {
        $args = $this->capturedArgumentsFor(null);

        $this->assertStringContainsString("\napp\n", $args);
    }

    public function test_analyses_the_paths_it_was_given(): void
    {
        $args = $this->capturedArgumentsFor(['app', 'src']);

        $this->assertStringContainsString("\napp\n", $args);
        $this->assertStringContainsString("\nsrc\n", $args);
    }

    public function test_analyses_every_default_path_except_the_views_directory(): void
    {
        $args = $this->capturedArgumentsFor(AnalyzerManager::DEFAULT_ANALYZE_PATHS);

        $this->assertStringContainsString("\napp\n", $args);
        $this->assertStringContainsString("\nconfig\n", $args);
        $this->assertStringContainsString("\ndatabase\n", $args);
        $this->assertStringContainsString("\nroutes\n", $args);
        $this->assertNoViewsPathIn($args);
    }

    /**
     * @dataProvider viewsPathSpellingProvider
     */
    #[DataProvider('viewsPathSpellingProvider')]
    public function test_leaves_out_every_spelling_of_the_views_directory(string $viewsPath): void
    {
        $args = $this->capturedArgumentsFor(['app', $viewsPath, 'routes']);

        $this->assertStringContainsString("\napp\n", $args);
        $this->assertStringContainsString("\nroutes\n", $args);
        $this->assertNoViewsPathIn($args);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function viewsPathSpellingProvider(): array
    {
        return [
            'plain' => ['resources/views'],
            'dot-slash with trailing slash' => ['./resources/views/'],
            'backslashes' => ['resources\\views'],
            'a subdirectory' => ['resources/views/admin'],
            'absolute under the base path' => ['{base}/resources/views'],
            'absolute subdirectory with trailing slash' => ['{base}/resources/views/partials/'],
        ];
    }

    /**
     * @dataProvider keptPathProvider
     */
    #[DataProvider('keptPathProvider')]
    public function test_keeps_paths_outside_the_views_directory(string $path): void
    {
        $args = $this->capturedArgumentsFor(['app', $path]);

        $this->assertStringContainsString("\n".str_replace('{base}', $this->lastBasePath, $path)."\n", $args);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function keptPathProvider(): array
    {
        return [
            'route closures' => ['routes'],
            'seeders and migrations' => ['database'],
            'config' => ['config'],
            'a sibling whose name starts with views' => ['resources/views-legacy'],
            'another resources subdirectory' => ['resources/lang'],
            'the broader resources directory' => ['resources'],
            'an absolute path elsewhere under the base path' => ['{base}/routes'],
        ];
    }

    public function test_skips_without_running_phpstan_when_every_path_is_under_the_views_directory(): void
    {
        $tempDir = $this->createStubbedProject();
        $capturePath = $tempDir.'/captured_args.txt';
        $this->writePHPStanStub($tempDir, sprintf(
            "file_put_contents(%s, 'ran');\necho '{\"totals\":{\"errors\":0,\"file_errors\":0},\"files\":{},\"errors\":[]}';\n",
            var_export($capturePath, true)
        ));

        $result = $this->runAnalyzer($tempDir, ['resources/views', './resources/views/admin/']);

        $this->assertSkipped($result);
        $this->assertStringContainsString('resources/views', $result->getMessage());
        $this->assertFileDoesNotExist($capturePath);
    }

    public function test_analyses_app_when_no_paths_were_set_whatever_the_config_says(): void
    {
        config(['shieldci.paths.analyze' => ['src']]);

        $args = $this->capturedArgumentsFor(null);

        $this->assertStringContainsString("\napp\n", $args);
        $this->assertStringNotContainsString("\nsrc\n", $args);
    }

    public function test_skips_when_the_base_path_cannot_be_determined(): void
    {
        $analyzer = new class extends CollectionCallAnalyzer
        {
            protected function getBasePath(): string
            {
                return '';
            }
        };

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('base path could not be determined', $result->getMessage());
    }

    public function test_reports_the_fatal_from_a_child_that_dies_before_writing_a_report(): void
    {
        // Replaces a test that made the stub unlaunchable by dropping its exec bit. The
        // runner names the interpreter now, so neither the exec bit nor the first line
        // decides whether the child starts, and that premise is gone. What is worth
        // pinning is the shape an interpreter mismatch produced: a php that the project
        // was not installed for, Composer's platform_check.php aborting the run, a fatal
        // on stderr, nothing on stdout.
        $result = $this->analyzeAbortedRun(
            'PHP Fatal error:  Uncaught RuntimeException: Composer detected issues in your '
                .'platform: Your Composer dependencies require a PHP version ">= 8.4.0". '
                .'You are running 8.3.21. in /tmp/project/vendor/composer/platform_check.php:22',
            255
        );

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan produced no analysable output', $result->getMessage());
        $this->assertStringContainsString('exit code 255', $result->getMessage());
        $this->assertStringContainsString('Composer detected issues in your platform', $result->getMessage());
    }

    public function test_reports_an_error_when_the_run_exceeds_the_configured_timeout(): void
    {
        // The retired support class set no timeout at all, so a run that hung, hung
        // forever. PHPStanRunner bounds it and lets the exception out, which is the
        // one path the catch arm exists for.
        config(['shieldci.timeout' => 1]);

        $tempDir = $this->createStubbedProject();
        $this->writePHPStanStub($tempDir, "sleep(10);\n");

        $result = $this->runAnalyzer($tempDir, ['app']);

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan analysis failed', $result->getMessage());
    }

    public function test_reports_a_finding_from_a_real_phpstan_run(): void
    {
        // Control for the switches below: the same project with a config that leaves the
        // rule alone, run through the real PHPStan and Larastan.
        $result = $this->analyzeRealProject([
            'phpstan.neon' => "parameters:\n    treatPhpDocTypesAsCertain: false\n",
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame(Severity::Medium, $result->getIssues()[0]->severity);
        $this->assertSame(CollectionCallAnalyzer::IDENTIFIER, $result->getIssues()[0]->metadata['phpstan_identifier']);
    }

    /**
     * @dataProvider projectSwitchProvider
     *
     * @param  array<string, string>  $config
     */
    #[DataProvider('projectSwitchProvider')]
    public function test_reports_the_finding_when_the_projects_config_switches_the_rule_off(array $config): void
    {
        // The generated config includes the project's own, so each of these would otherwise
        // leave a clean run behind and the analyzer would pass.
        $result = $this->analyzeRealProject($config);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame(Severity::Medium, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function projectSwitchProvider(): array
    {
        $ignoreByIdentifier = "parameters:\n    ignoreErrors:\n        - identifier: larastan.noUnnecessaryCollectionCall\n";

        return [
            'boolean switch' => [[
                'phpstan.neon' => "parameters:\n    noUnnecessaryCollectionCall: false\n",
            ]],
            'method excluded' => [[
                'phpstan.neon' => "parameters:\n    noUnnecessaryCollectionCallExcept: [count]\n",
            ]],
            'other methods only' => [[
                'phpstan.neon' => "parameters:\n    noUnnecessaryCollectionCallOnly: [contains]\n",
            ]],
            'ignored by message' => [[
                'phpstan.neon' => "parameters:\n    ignoreErrors:\n        - '#could have been retrieved as a query#'\n",
            ]],
            'ignored by identifier' => [[
                'phpstan.neon' => $ignoreByIdentifier,
            ]],
            'method excluded in phpstan.neon.dist' => [[
                'phpstan.neon.dist' => "parameters:\n    noUnnecessaryCollectionCallExcept: [count]\n",
            ]],
            // No path key: PHPStan matches an ignore's path against the resolved file, and
            // the system temp directory sits behind a symlink on macOS.
            'ignored in an included file' => [[
                'phpstan.neon' => "includes:\n    - phpstan-ignores.neon\n",
                'phpstan-ignores.neon' => $ignoreByIdentifier,
            ]],
        ];
    }

    /**
     * @dataProvider excludePatternProvider
     */
    #[DataProvider('excludePatternProvider')]
    public function test_leaves_out_findings_in_excluded_files(string $pattern): void
    {
        // The regression test for #657: PHPStan analyses the configured paths whole, so
        // excluded_paths has to be applied to what it reports, as every file analyzer does.
        $result = $this->analyzeWithExcludePatterns([$pattern], [
            ['file' => 'app/Legacy/Report.php', 'message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER],
            ['file' => 'app/Services/ExampleService.php', 'message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER],
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame(1, $result->getMetadata()['total_issues']);
        $this->assertStringContainsString('Found 1 inefficient collection operation(s)', $result->getMessage());
        $this->assertStringEndsWith('app/Services/ExampleService.php', (string) $result->getIssues()[0]->location?->file);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function excludePatternProvider(): array
    {
        return [
            'relative wildcard' => ['app/Legacy/*'],
            'exact relative file' => ['app/Legacy/Report.php'],
            'absolute-path wildcard' => ['*/Legacy/*'],
        ];
    }

    public function test_passes_when_every_finding_is_in_an_excluded_file(): void
    {
        $result = $this->analyzeWithExcludePatterns(['app/Legacy/Report.php', 'app/Legacy/*'], [
            ['file' => 'app/Legacy/Report.php', 'message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER],
        ]);

        $this->assertPassed($result);
    }

    public function test_leaves_out_a_trait_finding_reported_in_the_context_of_a_class(): void
    {
        // PHPStan reports an error inside a trait under "<file> (in context of class X)".
        $result = $this->analyzeWithExcludePatterns(['app/Legacy/*'], [[
            'file' => 'app/Legacy/CountsWidgets.php (in context of class App\Services\ExampleService)',
            'message' => self::COLLECTION_MESSAGE,
            'identifier' => CollectionCallAnalyzer::IDENTIFIER,
        ]]);

        $this->assertPassed($result);
    }

    public function test_matches_exclude_patterns_through_a_symlinked_base_path(): void
    {
        // PHPStan runs from the resolved working directory, so a base path reached through
        // a symlink (a release directory, or macOS's /var) comes back under its real path.
        $tempDir = $this->createStubbedProject();

        if (! @symlink($tempDir, $tempDir.'-link')) {
            $this->markTestSkipped('Cannot create symlinks on this system');
        }

        $this->beforeApplicationDestroyed(static function () use ($tempDir): void {
            @unlink($tempDir.'-link');
        });

        $realPath = (string) realpath($tempDir);

        $this->writePHPStanStub($tempDir, $this->reportScript([
            ['file' => $realPath.'/app/Legacy/Report.php', 'line' => 7, 'message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER],
            ['file' => $realPath.'/app/Services/ExampleService.php', 'line' => 7, 'message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER],
        ], [], 1));

        $analyzer = new CollectionCallAnalyzer;
        $analyzer->setBasePath($tempDir.'-link');
        $analyzer->setPaths(['app']);
        $analyzer->setExcludePatterns(['app/Legacy/*']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertStringEndsWith('app/Services/ExampleService.php', (string) $result->getIssues()[0]->location?->file);
    }

    public function test_a_stopping_error_in_an_excluded_file_still_marks_the_run_incomplete(): void
    {
        // The exclusion hides the file's findings, not the fact that PHPStan stopped there
        // and dropped every other file's.
        $result = $this->analyzeWithExcludePatterns(['app/Legacy/*'], [
            ['file' => 'app/Legacy/Report.php', 'message' => 'Syntax error, unexpected \'}\' on line 7', 'identifier' => 'phpstan.parse'],
        ]);

        $this->assertError($result);
        $this->assertSame(['app/Legacy/Report.php:7'], $result->getMetadata()['stopped_at']);
    }

    public function test_leaves_out_a_finding_in_an_excluded_non_php_file(): void
    {
        // Reachable when the project's phpstan.neon adds .inc to fileExtensions.
        $result = $this->analyzeWithExcludePatterns(['app/Legacy/*'], [
            ['file' => 'app/Legacy/widgets.inc', 'message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER],
            ['file' => 'app/Services/ExampleService.php', 'message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER],
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertStringEndsWith('app/Services/ExampleService.php', (string) $result->getIssues()[0]->location?->file);
    }

    public function test_keeps_a_finding_in_a_non_php_file_the_patterns_do_not_exclude(): void
    {
        // A project's own fileExtensions can make PHPStan report a .inc file. Core's
        // matcher declines every non-.php file, so asking it would drop the finding.
        $result = $this->analyzeWithExcludePatterns(['app/Legacy/*'], [
            ['file' => 'app/Services/widgets.inc', 'message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER],
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_an_unparseable_file_in_an_excluded_directory_does_not_stop_a_real_run(): void
    {
        // #659: PHPStan stops at a file it cannot parse and drops every other file's
        // findings, so an excluded file has to be kept out of the run, not just the report.
        $result = $this->analyzeRealProject(
            ['app/Archive/Damaged.php' => "<?php\n\nclass Damaged {\n"],
            ['app'],
            ['app/Archive/*']
        );

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertArrayNotHasKey('stopped_at', $result->getMetadata());
    }

    public function test_a_blade_template_below_an_analysed_resources_directory_does_not_stop_a_real_run(): void
    {
        // #664: resources/views is left out of the run when paths lists a directory above it.
        $result = $this->analyzeRealProject(
            ['resources/views/ledger.blade.php' => "<?php if ( ?>\n"],
            ['app', 'resources']
        );

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertArrayNotHasKey('stopped_at', $result->getMetadata());
    }

    public function test_hands_phpstan_the_project_root_whole_and_excludes_vendor_and_templates_in_the_config(): void
    {
        // Checked on the generated config rather than in a real run: PHPStan still scans the
        // files an analyse-only exclude leaves out, and a real run over a root holding this
        // package's whole vendor tree exceeds PHPStan's default memory limit.
        $tempDir = $this->createStubbedProject();
        $this->createFilesIn($tempDir, ['resources/views/ledger.blade.php' => "<?php if ( ?>\n"]);
        $configPath = $tempDir.'/captured_config.neon';
        $this->writePHPStanStub($tempDir, sprintf(
            <<<'PHP'
            foreach ($argv as $argument) {
                if (str_starts_with($argument, '--configuration=')) {
                    copy(substr($argument, strlen('--configuration=')), %s);
                }
            }

            echo '{"totals":{"errors":0,"file_errors":0},"files":{},"errors":[]}';

            PHP,
            var_export($configPath, true)
        ));

        $analyzer = new CollectionCallAnalyzer;
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);
        $analyzer->setExcludePatterns(['vendor/*']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString(
            "        analyse:\n            - '".realpath($tempDir)."/vendor/*'\n            - '*.blade.php'",
            (string) file_get_contents($configPath)
        );
    }

    public function test_reports_the_finding_from_a_real_run_when_the_views_directory_is_listed_itself(): void
    {
        // Control for #664: the shape that already worked.
        $result = $this->analyzeRealProject(
            ['resources/views/ledger.blade.php' => "<?php if ( ?>\n"],
            ['app', 'resources/views']
        );

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_an_unparseable_file_that_is_not_excluded_still_stops_a_real_run(): void
    {
        // Control: narrowing must not hide a damaged file the project still analyses.
        $result = $this->analyzeRealProject(
            ['app/Archive/Damaged.php' => "<?php\n\nclass Damaged {\n"],
            ['app'],
            ['app/Elsewhere/*']
        );

        $this->assertError($result);
        $this->assertStringContainsString('app/Archive/Damaged.php', $result->getMessage());
    }

    public function test_hands_phpstan_a_resources_directory_whole_and_excludes_its_views_in_the_config(): void
    {
        $tempDir = $this->createStubbedProject();
        $this->createFilesIn($tempDir, [
            'resources/views/ledger.blade.php' => "<?php\n",
            'resources/lang/en/ledger.php' => "<?php\n",
        ]);

        $args = $this->capturedArgumentsIn($tempDir, ['app', 'resources']);
        $realBase = (string) realpath($tempDir);

        // The configured paths go through as given; the templates are left out in the config.
        $this->assertStringContainsString("\napp\nresources\n", $args);
        $this->assertStringContainsString(
            "    excludePaths:\n        analyse:\n            - '*.blade.php'",
            (string) file_get_contents($tempDir.'/captured_config.neon')
        );
    }

    public function test_skips_without_running_phpstan_when_every_analysed_path_is_excluded(): void
    {
        $tempDir = $this->createStubbedProject();
        $this->createFilesIn($tempDir, ['resources/views/ledger.blade.php' => "<?php\n"]);
        $capturePath = $tempDir.'/captured_args.txt';
        $this->writePHPStanStub($tempDir, sprintf(
            "file_put_contents(%s, 'ran');\necho '{\"totals\":{\"errors\":0,\"file_errors\":0},\"files\":{},\"errors\":[]}';\n",
            var_export($capturePath, true)
        ));

        $analyzer = new CollectionCallAnalyzer;
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources/views']);
        $analyzer->setExcludePatterns(['app/*']);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('excluded_paths', $result->getMessage());
        $this->assertFileDoesNotExist($capturePath);
    }

    public function test_skips_when_a_resources_directory_holds_nothing_but_templates_and_assets(): void
    {
        // Left without its templates, PHPStan finds nothing to analyse and aborts, which used
        // to surface as an error.
        $result = $this->analyzeRealProject([
            'resources/views/ledger.blade.php' => "<?php\n",
            'resources/js/ledger.js' => "export {};\n",
        ], ['resources']);

        $this->assertSkipped($result);
        $this->assertStringContainsString('Blade templates', $result->getMessage());
        $this->assertStringNotContainsString('excluded_paths', $result->getMessage());
    }

    public function test_reports_an_error_when_phpstan_finds_no_file_and_nothing_was_excluded(): void
    {
        $result = $this->inRealPHPStanProject(['app/notes.txt' => "notes\n"], function (string $tempDir): ResultInterface {
            return $this->runAnalyzer($tempDir, ['app']);
        });

        // PHPStan's own wording is not asserted: on 1.12 an "old version" banner fills the
        // quoted excerpt before it.
        $this->assertError($result);
        $this->assertStringContainsString('PHPStan produced no analysable output', $result->getMessage());
    }

    public function test_a_blade_template_outside_resources_views_does_not_stop_a_real_run(): void
    {
        // Templates are recognised by extension: a module keeps its own views directory.
        $result = $this->analyzeRealProject(
            ['Modules/Billing/resources/views/index.blade.php' => "<?php if ( ?>\n"],
            ['app', 'Modules']
        );

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertArrayNotHasKey('stopped_at', $result->getMetadata());
    }

    public function test_metadata(): void
    {
        $metadata = (new CollectionCallAnalyzer)->getMetadata();

        $this->assertEquals('collection-call-optimization', $metadata->id);
        $this->assertEquals(Category::Performance, $metadata->category);
        $this->assertEquals(Severity::Medium, $metadata->severity);
        $this->assertContains('phpstan', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(CollectionCallAnalyzer::$runInCI);
    }

    /**
     * Run the analyzer against a stubbed PHPStan report.
     *
     * @param  array<int, array{message: string, line?: int, identifier?: string, tip?: string}>  $issues
     * @param  array<int, string>  $analysisErrors
     */
    private function analyzeIssues(
        array $issues,
        array $analysisErrors = [],
        int $exitCode = 0,
        bool $larastan = true
    ): ResultInterface {
        $tempDir = $this->createStubbedProject($larastan);
        $filePath = $tempDir.'/app/Services/ExampleService.php';

        $prepared = [];

        foreach ($issues as $issue) {
            $issue['file'] = $filePath;
            $issue['line'] = $issue['line'] ?? 7;
            $prepared[] = $issue;
        }

        $this->writePHPStanStub($tempDir, $this->reportScript($prepared, $analysisErrors, $exitCode));

        return $this->runAnalyzer($tempDir, ['app']);
    }

    /**
     * Run the analyzer against a PHPStan that aborts without a parseable report.
     */
    private function analyzeAbortedRun(string $stderr, int $exitCode, string $stdout = ''): ResultInterface
    {
        $tempDir = $this->createStubbedProject();

        $this->writePHPStanStub($tempDir, sprintf(
            "fwrite(STDOUT, %s);\nfwrite(STDERR, %s);\nexit(%d);\n",
            var_export($stdout, true),
            var_export($stderr, true),
            $exitCode
        ));

        return $this->runAnalyzer($tempDir, ['app']);
    }

    /**
     * Run the analyzer against a PHPStan that records the arguments it was given.
     *
     * @param  array<int, string>|null  $paths
     */
    private function capturedArgumentsFor(?array $paths): string
    {
        $tempDir = $this->createStubbedProject();
        $capturePath = $tempDir.'/captured_args.txt';

        // array_slice($argv, 1) drops the stub's own path, exactly as "$@" dropped $0.
        $this->writePHPStanStub($tempDir, sprintf(
            <<<'PHP'
            file_put_contents(%s, implode("\n", array_slice($argv, 1))."\n");

            echo '{"totals":{"errors":0,"file_errors":0},"files":{},"errors":[]}';

            PHP,
            var_export($capturePath, true)
        ));

        $this->lastBasePath = $tempDir;

        if ($paths !== null) {
            $paths = array_map(static fn (string $path): string => str_replace('{base}', $tempDir, $path), $paths);
        }

        $this->runAnalyzer($tempDir, $paths);

        $this->assertFileExists($capturePath);
        $captured = file_get_contents($capturePath);
        $this->assertIsString($captured);

        return "\n".$captured;
    }

    /**
     * Run the analyzer over a small Laravel project through the real PHPStan and Larastan.
     *
     * The run exercises the generated config against the installed rule rather than a
     * canned report.
     *
     * @param  array<string, string>  $config  extra files at the project root, such as its phpstan.neon
     * @param  array<int, string>  $paths
     * @param  array<int, string>  $excludePatterns
     */
    private function analyzeRealProject(array $config, array $paths = ['app'], array $excludePatterns = []): ResultInterface
    {
        return $this->inRealPHPStanProject(array_merge([
            'app/Models/Invoice.php' => <<<'PHP'
            <?php

            namespace App\Models;

            use Illuminate\Database\Eloquent\Model;

            class Invoice extends Model {}
            PHP,
            'app/Reports/InvoiceReport.php' => <<<'PHP'
            <?php

            namespace App\Reports;

            use App\Models\Invoice;

            class InvoiceReport
            {
                public function issued(): int
                {
                    return Invoice::all()->count();
                }
            }
            PHP,
        ], $config), function (string $tempDir) use ($paths, $excludePatterns): ResultInterface {
            $analyzer = new CollectionCallAnalyzer;
            $analyzer->setBasePath($tempDir);
            $analyzer->setPaths($paths);
            $analyzer->setExcludePatterns($excludePatterns);

            return $analyzer->analyze();
        });
    }

    /**
     * @param  array<string, string>  $files  path => contents, relative to $tempDir
     */
    private function createFilesIn(string $tempDir, array $files): void
    {
        foreach ($files as $path => $contents) {
            @mkdir(dirname($tempDir.'/'.$path), 0755, true);
            file_put_contents($tempDir.'/'.$path, $contents);
        }
    }

    /**
     * Run the analyzer over an existing project against a PHPStan that records its arguments.
     *
     * @param  array<int, string>  $paths
     */
    private function capturedArgumentsIn(string $tempDir, array $paths): string
    {
        $capturePath = $tempDir.'/captured_args.txt';

        $this->writePHPStanStub($tempDir, sprintf(
            <<<'PHP'
            file_put_contents(%s, implode("\n", array_slice($argv, 1))."\n");

            foreach ($argv as $argument) {
                if (str_starts_with($argument, '--configuration=')) {
                    copy(substr($argument, strlen('--configuration=')), %s);
                }
            }

            echo '{"totals":{"errors":0,"file_errors":0},"files":{},"errors":[]}';

            PHP,
            var_export($capturePath, true),
            var_export($tempDir.'/captured_config.neon', true)
        ));

        $this->runAnalyzer($tempDir, $paths);

        $this->assertFileExists($capturePath);
        $captured = file_get_contents($capturePath);
        $this->assertIsString($captured);

        return "\n".$captured;
    }

    /**
     * No argument PHPStan received names resources/views or anything below it.
     */
    private function assertNoViewsPathIn(string $args): void
    {
        foreach (explode("\n", $args) as $argument) {
            $this->assertDoesNotMatchRegularExpression('#resources[/\\\\]views($|[/\\\\])#', $argument);
        }
    }

    /**
     * A temp project with an app directory and, by default, a Larastan extension.
     */
    private function createStubbedProject(bool $larastan = true): string
    {
        $code = <<<'PHP'
        <?php

        namespace App\Services;

        class ExampleService
        {
            public function run(): void {}
        }
        PHP;

        $files = ['app/Services/ExampleService.php' => $code];

        if ($larastan) {
            $files['vendor/larastan/larastan/extension.neon'] = "# Larastan extension\n";
        }

        return $this->createTempDirectory($files);
    }

    private function writePHPStanStub(string $tempDir, string $php): void
    {
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', "<?php\n\n".$php);
    }

    /**
     * @param  array<int, string>|null  $paths
     */
    private function runAnalyzer(string $tempDir, ?array $paths): ResultInterface
    {
        $analyzer = new CollectionCallAnalyzer;
        $analyzer->setBasePath($tempDir);

        if ($paths !== null) {
            $analyzer->setPaths($paths);
        }

        return $analyzer->analyze();
    }

    /**
     * Run the analyzer with exclude patterns against a report naming files by relative path.
     *
     * @param  array<int, string>  $patterns
     * @param  array<int, array{file: string, message: string, line?: int, identifier?: string}>  $issues
     */
    private function analyzeWithExcludePatterns(array $patterns, array $issues): ResultInterface
    {
        $tempDir = $this->createStubbedProject();

        $prepared = [];

        foreach ($issues as $issue) {
            $issue['file'] = $tempDir.'/'.$issue['file'];
            $issue['line'] = $issue['line'] ?? 7;
            $prepared[] = $issue;
        }

        $this->writePHPStanStub($tempDir, $this->reportScript($prepared, [], 1));

        $analyzer = new CollectionCallAnalyzer;
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);
        $analyzer->setExcludePatterns($patterns);

        return $analyzer->analyze();
    }

    /**
     * Mirrors PHPStan's JSON error format, which omits 'identifier' and 'tip' entirely
     * rather than emitting them as null, and reports errors it cannot attach to a file
     * in a top-level 'errors' list.
     *
     * The exit code is configurable because PHPStan exits 1 whenever it reports
     * anything at all.
     *
     * @param  array<int, array{file: string, line: int, message: string, identifier?: string, tip?: string}>  $issues
     * @param  array<int, string>  $analysisErrors
     */
    private function reportScript(array $issues, array $analysisErrors, int $exitCode): string
    {
        $files = [];

        foreach ($issues as $issue) {
            $file = $issue['file'];

            if (! isset($files[$file])) {
                $files[$file] = ['messages' => []];
            }

            $entry = [
                'message' => $issue['message'],
                'line' => $issue['line'],
                'ignorable' => true,
            ];

            if (isset($issue['tip'])) {
                $entry['tip'] = $issue['tip'];
            }

            if (isset($issue['identifier'])) {
                $entry['identifier'] = $issue['identifier'];
            }

            $files[$file]['messages'][] = $entry;
        }

        $json = (string) json_encode([
            'totals' => ['errors' => count($analysisErrors), 'file_errors' => count($issues)],
            'files' => $files,
            'errors' => array_values($analysisErrors),
        ], JSON_PRETTY_PRINT);

        return sprintf(
            "echo %s;\nexit(%d);\n",
            var_export($json, true),
            $exitCode
        );
    }
}
