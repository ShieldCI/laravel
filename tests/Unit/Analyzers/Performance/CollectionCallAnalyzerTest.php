<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\CollectionCallAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

/**
 * The analyzer drives a real PHPStan process, so these tests stand up an executable
 * stub at vendor/bin/phpstan that prints a canned report. That runs the real JSON
 * parsing and the real matching, which a mocked support object never did.
 */
class CollectionCallAnalyzerTest extends AnalyzerTestCase
{
    private const COLLECTION_MESSAGE = "Called 'count' on Laravel collection, but could have been retrieved as a query.";

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

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertStringContainsString('Found 1 inefficient collection operation(s)', $result->getMessage());

        $issue = $result->getIssues()[0];
        $this->assertSame(Severity::High, $issue->severity);
        $this->assertSame(self::COLLECTION_MESSAGE, $issue->metadata['phpstan_message']);
        $this->assertSame(CollectionCallAnalyzer::IDENTIFIER, $issue->metadata['phpstan_identifier']);
    }

    public function test_the_identifier_decides_regardless_of_the_message_text(): void
    {
        // PHPStan's identifier is the stable contract; the wording is not.
        $result = $this->analyzeIssues([
            ['message' => 'Wording Larastan has never used.', 'identifier' => CollectionCallAnalyzer::IDENTIFIER],
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_falls_back_to_the_message_when_phpstan_emits_no_identifier(): void
    {
        // PHPStan below 1.11 and Larastan below 2.9 emit none, and composer.json
        // still admits both.
        $result = $this->analyzeIssues([
            ['message' => self::COLLECTION_MESSAGE],
        ]);

        $this->assertFailed($result);
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

    public function test_keeps_the_failed_result_when_analysis_errors_accompany_findings(): void
    {
        // A file finding still drives the status, so a partial run is not downgraded
        // from failed to error and its findings are not thrown away.
        $result = $this->analyzeIssues(
            [['message' => self::COLLECTION_MESSAGE, 'identifier' => CollectionCallAnalyzer::IDENTIFIER]],
            analysisErrors: ['Internal error: child process died.']
        );

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

    public function test_filters_non_code_directories_out_of_the_configured_paths(): void
    {
        config(['shieldci.paths.analyze' => ['app', 'config', 'database', 'resources/views', 'routes']]);

        $args = $this->capturedArgumentsFor(null);

        $this->assertStringContainsString("\napp\n", $args);
        $this->assertStringNotContainsString("\nconfig\n", $args);
        $this->assertStringNotContainsString("\ndatabase\n", $args);
        $this->assertStringNotContainsString("\nresources/views\n", $args);
        $this->assertStringNotContainsString("\nroutes\n", $args);
    }

    public function test_falls_back_to_app_when_the_configured_paths_are_all_filtered_out(): void
    {
        config(['shieldci.paths.analyze' => ['config', 'routes']]);

        $args = $this->capturedArgumentsFor(null);

        $this->assertStringContainsString("\napp\n", $args);
    }

    public function test_reports_an_error_when_the_base_path_cannot_be_determined(): void
    {
        $analyzer = new class extends CollectionCallAnalyzer
        {
            protected function getBasePath(): string
            {
                return '';
            }
        };

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('Unable to determine base path', $result->getMessage());
    }

    public function test_reports_an_error_when_the_phpstan_binary_cannot_be_executed(): void
    {
        $tempDir = $this->createStubbedProject();

        // isAvailable() only proves the file is there. A present but unrunnable binary
        // is launched through sh, which reports the refusal on stderr and exits 126
        // rather than throwing, so this lands on the aborted-run path.
        $this->writePHPStanStub($tempDir, "#!/bin/bash\necho hi\n");
        chmod($tempDir.'/vendor/bin/phpstan', 0644);

        $result = $this->runAnalyzer($tempDir, ['app']);

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan produced no analysable output', $result->getMessage());
        $this->assertStringContainsString('exit code 126', $result->getMessage());
    }

    public function test_reports_an_error_when_the_run_exceeds_the_configured_timeout(): void
    {
        // The retired support class set no timeout at all, so a run that hung, hung
        // forever. PHPStanRunner bounds it and lets the exception out, which is the
        // one path the catch arm exists for.
        config(['shieldci.timeout' => 1]);

        $tempDir = $this->createStubbedProject();
        $this->writePHPStanStub($tempDir, "#!/bin/bash\nsleep 10\n");

        $result = $this->runAnalyzer($tempDir, ['app']);

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan analysis failed', $result->getMessage());
    }

    public function test_metadata(): void
    {
        $metadata = (new CollectionCallAnalyzer)->getMetadata();

        $this->assertEquals('collection-call-optimization', $metadata->id);
        $this->assertEquals(Category::Performance, $metadata->category);
        $this->assertEquals(Severity::High, $metadata->severity);
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
            "#!/bin/bash\nprintf '%%s' %s\nprintf '%%s' %s >&2\nexit %d\n",
            escapeshellarg($stdout),
            escapeshellarg($stderr),
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

        $this->writePHPStanStub($tempDir, sprintf(
            "#!/bin/bash\nprintf '%%s\\n' \"$@\" > %s\necho '{\"totals\":{\"errors\":0,\"file_errors\":0},\"files\":{},\"errors\":[]}'\n",
            escapeshellarg($capturePath)
        ));

        $this->runAnalyzer($tempDir, $paths);

        $this->assertFileExists($capturePath);
        $captured = file_get_contents($capturePath);
        $this->assertIsString($captured);

        return "\n".$captured;
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

    private function writePHPStanStub(string $tempDir, string $script): void
    {
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);
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

        $json = json_encode([
            'totals' => ['errors' => count($analysisErrors), 'file_errors' => count($issues)],
            'files' => $files,
            'errors' => array_values($analysisErrors),
        ], JSON_PRETTY_PRINT);

        return <<<BASH
        #!/bin/bash
        cat <<'EOF'
        {$json}
        EOF
        exit {$exitCode}
        BASH;
    }
}
