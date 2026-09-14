<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ShieldCI\Support\PHPStanRunner;
use Symfony\Component\Process\Exception\ProcessTimedOutException;

class PHPStanRunnerTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tempDir = sys_get_temp_dir().'/phpstan_runner_test_'.uniqid();
        mkdir($this->tempDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $this->recursiveDelete($this->tempDir);
        parent::tearDown();
    }

    private function recursiveDelete(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        $items = scandir($dir);
        if ($items === false) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $path = $dir.'/'.$item;
            if (is_dir($path)) {
                $this->recursiveDelete($path);
            } else {
                unlink($path);
            }
        }

        rmdir($dir);
    }

    public function test_filters_higher_order_proxy_false_positive(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to an undefined method Illuminate\Support\HigherOrderCollectionProxy::something()',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Undefined variable: $realIssue',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        // Should only have the real issue, not the HigherOrderProxy false positive
        $this->assertCount(1, $issues);
        $firstIssue = $issues->first();
        $this->assertNotNull($firstIssue);
        $this->assertStringContainsString('Undefined variable', $firstIssue['message']);
    }

    public function test_filters_higher_order_when_proxy_false_positive(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to an undefined method Illuminate\Support\HigherOrderWhenProxy::doSomething()',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        $this->assertCount(0, $issues);
    }

    public function test_does_not_filter_real_issues(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/Services/PaymentService.php',
                'line' => 20,
                'message' => 'Call to an undefined static method App\Models\Payment::customNonExistentMethod()',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Undefined variable: $realIssue',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        // Both are real issues (not HigherOrderProxy)
        $this->assertCount(2, $issues);
    }

    public function test_filters_faker_generator_unknown_class_false_positive(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to method unique() on an unknown class Faker\Generator.',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Undefined variable: $realIssue',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        $this->assertCount(1, $issues);
        $firstIssue = $issues->first();
        $this->assertNotNull($firstIssue);
        $this->assertStringContainsString('Undefined variable', $firstIssue['message']);
    }

    public function test_filters_faker_undefined_method_false_positive(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to an undefined method Faker\Generator::randomNumber().',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        $this->assertCount(0, $issues);
    }

    public function test_filters_faker_proxy_generators_false_positives(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to method randomNumber() on an unknown class Faker\UniqueGenerator.',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Call to method name() on an unknown class Faker\ValidGenerator.',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 20,
                'message' => 'Call to method boolean() on an unknown class Faker\ChanceGenerator.',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        $this->assertCount(0, $issues);
    }

    public function test_filters_faker_property_access_false_positives(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Access to property $name on an unknown class Faker\Generator.',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Access to an undefined property Faker\Generator::$name.',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        $this->assertCount(0, $issues);
    }

    public function test_does_not_filter_non_faker_namespace_issues(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to an undefined method App\Services\FakerService::generate().',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Call to an undefined method App\Models\User::fake().',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 20,
                'message' => 'Class Faker\Generator not found.',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        // All three are real issues — none should be filtered
        $this->assertCount(3, $issues);
    }

    public function test_filters_faker_false_positives_while_keeping_real_issues(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Call to method unique() on an unknown class Faker\Generator.',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Undefined variable: $faker',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 20,
                'message' => 'Call to an undefined method Faker\Generator::randomNumber().',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 25,
                'message' => 'Method App\Services\UserService::create() has no return type specified.',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->getIssues();

        // 2 Faker FPs removed, 2 real issues kept
        $this->assertCount(2, $issues);

        $messages = $issues->pluck('message')->toArray();
        $this->assertContains('Undefined variable: $faker', $messages);
        $this->assertContains('Method App\Services\UserService::create() has no return type specified.', $messages);
    }

    public function test_generates_config_with_larastan_extension(): void
    {
        // Create mock Larastan extension
        $larastanDir = $this->tempDir.'/vendor/larastan/larastan';
        mkdir($larastanDir, 0755, true);
        file_put_contents($larastanDir.'/extension.neon', "# Larastan extension\n");

        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('includes:', $capturedConfig);
        $this->assertStringContainsString('larastan/larastan/extension.neon', $capturedConfig);
    }

    public function test_generates_config_with_caller_supplied_parameters(): void
    {
        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app'], 5, 300, null, [
            'noUnnecessaryCollectionCall' => true,
            'reportUnmatchedIgnoredErrors' => false,
        ]);

        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('    noUnnecessaryCollectionCall: true', $capturedConfig);
        $this->assertStringContainsString('    reportUnmatchedIgnoredErrors: false', $capturedConfig);
    }

    public function test_generates_the_same_config_as_before_when_no_parameters_are_passed(): void
    {
        // Regression guard for PHPStanAnalyzer, which passes none: the generated config
        // must be byte-identical to what it got before the argument existed.
        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $capturedConfig = $this->getCapturedConfig();

        $this->assertSame(
            "parameters:\n    level: 5\n    tmpDir: ".sys_get_temp_dir().'/phpstan',
            $capturedConfig
        );
    }

    public function test_caller_supplied_parameters_outrank_the_users_phpstan_neon(): void
    {
        // The generated parameters block is written after the includes, and PHPStan lets
        // the including file win, so a user who switched the rule off does not silently
        // disable the analyzer that depends on it.
        file_put_contents($this->tempDir.'/phpstan.neon', "parameters:\n    noUnnecessaryCollectionCall: false\n");

        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app'], 5, 300, null, ['noUnnecessaryCollectionCall' => true]);

        $capturedConfig = $this->getCapturedConfig();

        $includesAt = strpos($capturedConfig, 'phpstan.neon');
        $parameterAt = strpos($capturedConfig, 'noUnnecessaryCollectionCall: true');

        $this->assertIsInt($includesAt);
        $this->assertIsInt($parameterAt);
        $this->assertGreaterThan($includesAt, $parameterAt);
    }

    public function test_generates_config_with_carbon_extension(): void
    {
        // Create mock Carbon extension
        $carbonDir = $this->tempDir.'/vendor/nesbot/carbon';
        mkdir($carbonDir, 0755, true);
        file_put_contents($carbonDir.'/extension.neon', "# Carbon extension\n");

        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('includes:', $capturedConfig);
        $this->assertStringContainsString('nesbot/carbon/extension.neon', $capturedConfig);
    }

    public function test_generates_config_with_user_phpstan_neon(): void
    {
        // Create user's phpstan.neon
        file_put_contents($this->tempDir.'/phpstan.neon', "# User config\n");

        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('includes:', $capturedConfig);
        $this->assertStringContainsString('phpstan.neon', $capturedConfig);
    }

    public function test_generates_config_with_user_phpstan_neon_dist(): void
    {
        // Create user's phpstan.neon.dist (without phpstan.neon)
        file_put_contents($this->tempDir.'/phpstan.neon.dist', "# User config dist\n");

        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('includes:', $capturedConfig);
        $this->assertStringContainsString('phpstan.neon.dist', $capturedConfig);
    }

    public function test_prefers_phpstan_neon_over_dist(): void
    {
        // Create both files
        file_put_contents($this->tempDir.'/phpstan.neon', "# Primary config\n");
        file_put_contents($this->tempDir.'/phpstan.neon.dist', "# Dist config\n");

        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        // Should only include phpstan.neon, not .dist
        $this->assertStringContainsString('phpstan.neon', $capturedConfig);
        $this->assertStringNotContainsString('phpstan.neon.dist', $capturedConfig);
    }

    public function test_generates_config_without_extensions_when_not_available(): void
    {
        // Don't create any extension files
        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        // Should have parameters but no includes
        $this->assertStringContainsString('parameters:', $capturedConfig);
        $this->assertStringContainsString('level:', $capturedConfig);
        $this->assertStringNotContainsString('includes:', $capturedConfig);
    }

    public function test_config_includes_correct_level(): void
    {
        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app'], 9);

        // Read the captured config from the mock script
        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('level: 9', $capturedConfig);
    }

    public function test_cleans_up_temp_config_file(): void
    {
        $this->createMockPHPStan([]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Use reflection to access private property
        $reflection = new ReflectionClass($runner);
        $property = $reflection->getProperty('tempConfigFile');
        $property->setAccessible(true);
        $tempConfigFile = $property->getValue($runner);

        // Temp config file should be null (cleaned up)
        $this->assertNull($tempConfigFile);
    }

    public function test_is_available_returns_true_when_phpstan_exists(): void
    {
        $this->createMockPHPStan([]);

        $runner = new PHPStanRunner($this->tempDir);

        $this->assertTrue($runner->isAvailable());
    }

    public function test_is_available_returns_false_when_phpstan_missing(): void
    {
        // Don't create mock PHPStan
        $runner = new PHPStanRunner($this->tempDir);

        $this->assertFalse($runner->isAvailable());
    }

    public function test_get_issues_returns_empty_collection_without_analysis(): void
    {
        $runner = new PHPStanRunner($this->tempDir);

        $issues = $runner->getIssues();

        $this->assertTrue($issues->isEmpty());
    }

    public function test_get_issues_captures_identifier_and_tip(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Instantiated class App\Nope not found.',
                'identifier' => 'class.notFound',
                'tip' => 'Learn more at https://phpstan.org/user-guide/discovering-symbols',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issue = $runner->getIssues()->first();

        $this->assertNotNull($issue);
        $this->assertArrayHasKey('identifier', $issue);
        $this->assertArrayHasKey('tip', $issue);
        $this->assertSame('class.notFound', $issue['identifier'] ?? null);
        $this->assertSame('Learn more at https://phpstan.org/user-guide/discovering-symbols', $issue['tip'] ?? null);
    }

    public function test_get_issues_defaults_identifier_and_tip_to_null_when_absent(): void
    {
        // PHPStan below 1.11 emits neither key, and that version is still inside the
        // supported range, so both must read as null rather than being missing.
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Undefined variable: $foo',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issue = $runner->getIssues()->first();

        $this->assertNotNull($issue);
        // Present-and-null, not absent: assertArrayHasKey proves the key is there,
        // the null assertion proves its value.
        $this->assertArrayHasKey('identifier', $issue);
        $this->assertArrayHasKey('tip', $issue);
        $this->assertNull($issue['identifier'] ?? null);
        $this->assertNull($issue['tip'] ?? null);
    }

    public function test_get_issues_nulls_non_string_identifier_and_tip(): void
    {
        $runner = new PHPStanRunner($this->tempDir);

        $reflection = new ReflectionClass($runner);
        $property = $reflection->getProperty('result');
        $property->setAccessible(true);
        $property->setValue($runner, [
            'files' => [
                '/app/valid.php' => [
                    'messages' => [
                        ['line' => 10, 'message' => 'Valid issue', 'identifier' => 42, 'tip' => ''],
                    ],
                ],
            ],
        ]);

        $issue = $runner->getIssues()->first();

        $this->assertNotNull($issue);
        $this->assertNull($issue['identifier'] ?? null);
        $this->assertNull($issue['tip'] ?? null);
    }

    public function test_get_analysis_errors_returns_non_file_specific_errors(): void
    {
        $this->createMockPHPStan([], [
            'Ignored error pattern #This pattern will never match anything at all# was not matched in reported errors.',
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $this->assertSame(
            ['Ignored error pattern #This pattern will never match anything at all# was not matched in reported errors.'],
            $runner->getAnalysisErrors()
        );

        // Nothing lands in "files", so getIssues() cannot carry this signal on its own.
        $this->assertTrue($runner->getIssues()->isEmpty());
    }

    public function test_get_analysis_errors_survive_alongside_file_issues(): void
    {
        $this->createMockPHPStan(
            [
                [
                    'file' => $this->tempDir.'/app/test.php',
                    'line' => 10,
                    'message' => 'Undefined variable: $foo',
                ],
            ],
            ['Child process error: Allowed memory size of 134217728 bytes exhausted.']
        );

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $this->assertCount(1, $runner->getIssues());
        $this->assertSame(
            ['Child process error: Allowed memory size of 134217728 bytes exhausted.'],
            $runner->getAnalysisErrors()
        );
    }

    public function test_get_analysis_errors_is_empty_for_a_clean_run(): void
    {
        $this->createMockPHPStan([]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $this->assertSame([], $runner->getAnalysisErrors());
    }

    public function test_get_analysis_errors_returns_empty_array_without_analysis(): void
    {
        $runner = new PHPStanRunner($this->tempDir);

        $this->assertSame([], $runner->getAnalysisErrors());
    }

    public function test_get_analysis_errors_drops_non_string_and_blank_entries(): void
    {
        $runner = new PHPStanRunner($this->tempDir);

        $reflection = new ReflectionClass($runner);
        $property = $reflection->getProperty('result');
        $property->setAccessible(true);
        $property->setValue($runner, [
            'files' => [],
            'errors' => [
                'Internal error: child process died.',
                '',
                '   ',
                42,
                ['nested' => 'array'],
                null,
                '  Padded error.  ',
            ],
        ]);

        // Trimmed, blanks and non-strings dropped, re-indexed as a list so the consumer
        // can count and implode it without holes.
        $this->assertSame(
            ['Internal error: child process died.', 'Padded error.'],
            $runner->getAnalysisErrors()
        );
    }

    public function test_get_analysis_errors_returns_empty_array_when_the_errors_key_is_absent(): void
    {
        $runner = new PHPStanRunner($this->tempDir);

        $reflection = new ReflectionClass($runner);
        $property = $reflection->getProperty('result');
        $property->setAccessible(true);
        $property->setValue($runner, ['files' => []]);

        $this->assertSame([], $runner->getAnalysisErrors());
    }

    public function test_get_analysis_errors_returns_empty_array_when_errors_is_not_an_array(): void
    {
        $runner = new PHPStanRunner($this->tempDir);

        $reflection = new ReflectionClass($runner);
        $property = $reflection->getProperty('result');
        $property->setAccessible(true);
        $property->setValue($runner, ['files' => [], 'errors' => 'boom']);

        $this->assertSame([], $runner->getAnalysisErrors());
    }

    public function test_get_analysis_errors_records_a_run_that_emitted_no_json(): void
    {
        $this->createFailingMockPHPStan('PHPStan\Command\PathNotFoundException: Path /app was not found.');

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $errors = $runner->getAnalysisErrors();

        $this->assertCount(1, $errors);
        $this->assertStringContainsString('PHPStan produced no analysable output', $errors[0]);
        $this->assertStringContainsString('exit code 1', $errors[0]);
        $this->assertStringContainsString('PathNotFoundException', $errors[0]);
        $this->assertTrue($runner->getIssues()->isEmpty());
    }

    public function test_get_analysis_errors_records_a_silent_failure_with_no_output(): void
    {
        // A process killed outright leaves neither stream to quote, so the exit code is
        // all the evidence there is.
        $this->createFailingMockPHPStan('', 137);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $this->assertSame(
            ['PHPStan produced no analysable output (exit code 137)'],
            $runner->getAnalysisErrors()
        );
    }

    public function test_get_analysis_errors_truncates_a_long_output_excerpt(): void
    {
        $this->createFailingMockPHPStan(str_repeat('E', 2000).'TAIL_MARKER');

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $errors = $runner->getAnalysisErrors();

        $this->assertCount(1, $errors);
        $this->assertStringContainsString('EEEE', $errors[0]);
        $this->assertStringNotContainsString('TAIL_MARKER', $errors[0]);
        $this->assertLessThan(700, strlen($errors[0]));
    }

    public function test_get_analysis_errors_stays_empty_when_phpstan_exits_non_zero_with_valid_json(): void
    {
        // PHPStan exits 1 whenever it reports anything at all, so a non-zero exit on its
        // own must never be read as a failed run.
        $this->createMockPHPStan(
            [
                [
                    'file' => $this->tempDir.'/app/test.php',
                    'line' => 10,
                    'message' => 'Undefined variable: $foo',
                ],
            ],
            [],
            1
        );

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $this->assertCount(1, $runner->getIssues());
        $this->assertSame([], $runner->getAnalysisErrors());
    }

    public function test_analyze_clears_a_recorded_failure_from_a_previous_run(): void
    {
        $this->createFailingMockPHPStan('Internal error.');

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $this->assertCount(1, $runner->getAnalysisErrors());

        $this->createMockPHPStan([]);

        $runner->analyze(['app']);

        $this->assertSame([], $runner->getAnalysisErrors());
    }

    public function test_matches_any_pattern_handles_wildcards_and_an_empty_list(): void
    {
        $this->assertTrue(PHPStanRunner::matchesAnyPattern('Undefined variable: $foo', ['*variable*']));
        $this->assertTrue(PHPStanRunner::matchesAnyPattern('Undefined variable: $foo', ['no match', 'Undefined *']));
        $this->assertFalse(PHPStanRunner::matchesAnyPattern('Undefined variable: $foo', ['Method *']));

        // An empty pattern list must claim nothing, otherwise a category without
        // patterns would swallow every message.
        $this->assertFalse(PHPStanRunner::matchesAnyPattern('Undefined variable: $foo', []));
    }

    public function test_filter_by_pattern_works(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Undefined variable: $foo',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Method has no return type',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->filterByPattern('*variable*');

        $this->assertCount(1, $issues);
        $firstIssue = $issues->first();
        $this->assertNotNull($firstIssue);
        $this->assertStringContainsString('variable', $firstIssue['message']);
    }

    public function test_filter_by_regex_works(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Undefined variable: $foo',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Method has no return type',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->filterByRegex('/variable.*\$\w+/');

        $this->assertCount(1, $issues);
    }

    public function test_filter_by_text_works(): void
    {
        $this->createMockPHPStan([
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 10,
                'message' => 'Undefined variable: $foo',
            ],
            [
                'file' => $this->tempDir.'/app/test.php',
                'line' => 15,
                'message' => 'Method has no return type',
            ],
        ]);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $issues = $runner->filterByText('return type');

        $this->assertCount(1, $issues);
        $firstIssue = $issues->first();
        $this->assertNotNull($firstIssue);
        $this->assertStringContainsString('return type', $firstIssue['message']);
    }

    public function test_handles_invalid_json_output_from_phpstan(): void
    {
        $vendorBinDir = $this->tempDir.'/vendor/bin';
        mkdir($vendorBinDir, 0755, true);

        // Create a mock PHPStan that outputs invalid JSON
        $script = <<<'BASH'
#!/bin/bash
echo "This is not valid JSON"
BASH;

        file_put_contents($vendorBinDir.'/phpstan', $script);
        chmod($vendorBinDir.'/phpstan', 0755);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        // Issues still fall back to empty, but the run no longer looks clean: output that
        // cannot be decoded is recorded as an analysis error rather than vanishing. Note
        // the exit code is 0 here, which pins that undecodable output is a failure on its
        // own, independent of how PHPStan exited.
        $this->assertTrue($runner->getIssues()->isEmpty());

        $errors = $runner->getAnalysisErrors();
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('PHPStan produced no analysable output', $errors[0]);
        $this->assertStringContainsString('exit code 0', $errors[0]);
        $this->assertStringContainsString('This is not valid JSON', $errors[0]);
    }

    public function test_get_issues_skips_non_array_file_data(): void
    {
        $runner = new PHPStanRunner($this->tempDir);

        // Use reflection to set result with non-array file data
        $reflection = new ReflectionClass($runner);
        $property = $reflection->getProperty('result');
        $property->setAccessible(true);
        $property->setValue($runner, [
            'files' => [
                '/app/valid.php' => [
                    'messages' => [
                        ['line' => 10, 'message' => 'Valid issue'],
                    ],
                ],
                42 => 'not-an-array', // Non-string key, non-array value
                '/app/missing.php' => 'string-not-array', // String key but non-array value
            ],
        ]);

        $issues = $runner->getIssues();

        // Only the valid file data should produce issues
        $this->assertCount(1, $issues);
        $firstIssue = $issues->first();
        $this->assertNotNull($firstIssue);
        $this->assertEquals('Valid issue', $firstIssue['message']);
    }

    public function test_get_issues_skips_non_array_message_entries(): void
    {
        $runner = new PHPStanRunner($this->tempDir);

        // Use reflection to set result with non-array message entries
        $reflection = new ReflectionClass($runner);
        $property = $reflection->getProperty('result');
        $property->setAccessible(true);
        $property->setValue($runner, [
            'files' => [
                '/app/test.php' => [
                    'messages' => [
                        'string-not-array',
                        ['line' => 10, 'message' => 'Real issue'],
                        42,
                    ],
                ],
            ],
        ]);

        $issues = $runner->getIssues();

        // Only the valid message entry should produce issues
        $this->assertCount(1, $issues);
        $firstIssue = $issues->first();
        $this->assertNotNull($firstIssue);
        $this->assertEquals('Real issue', $firstIssue['message']);
    }

    public function test_config_always_includes_tmpdir(): void
    {
        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('tmpDir:', $capturedConfig);
    }

    public function test_config_includes_parallel_limit_when_running_in_serverless(): void
    {
        $this->createMockPHPStanWithConfigCapture();

        putenv('AWS_LAMBDA_FUNCTION_NAME=test-function');
        try {
            $runner = new PHPStanRunner($this->tempDir);
            $runner->analyze(['app']);
        } finally {
            putenv('AWS_LAMBDA_FUNCTION_NAME');
        }

        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('maximumNumberOfProcesses: 1', $capturedConfig);
    }

    public function test_config_does_not_include_parallel_limit_outside_serverless(): void
    {
        $saved = getenv('AWS_LAMBDA_FUNCTION_NAME');
        putenv('AWS_LAMBDA_FUNCTION_NAME');

        $this->createMockPHPStanWithConfigCapture();

        try {
            $runner = new PHPStanRunner($this->tempDir);
            $runner->analyze(['app']);
        } finally {
            if ($saved !== false) {
                putenv("AWS_LAMBDA_FUNCTION_NAME={$saved}");
            }
        }

        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringNotContainsString('maximumNumberOfProcesses', $capturedConfig);
    }

    public function test_analyze_respects_custom_timeout(): void
    {
        $vendorBinDir = $this->tempDir.'/vendor/bin';
        mkdir($vendorBinDir, 0755, true);

        // Mock that sleeps 3 seconds — longer than our 1s timeout
        file_put_contents($vendorBinDir.'/phpstan', "#!/bin/bash\nsleep 3\n");
        chmod($vendorBinDir.'/phpstan', 0755);

        $this->expectException(ProcessTimedOutException::class);

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app'], 5, 1); // 1-second timeout
    }

    public function test_analyze_passes_memory_limit_to_phpstan(): void
    {
        $this->createMockPHPStanWithArgCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app'], 5, 300, '2048M');

        $this->assertStringContainsString('--memory-limit=2048M', $this->getCapturedArgs());
    }

    public function test_analyze_omits_memory_limit_when_null(): void
    {
        $this->createMockPHPStanWithArgCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app'], 5, 300, null);

        $this->assertStringNotContainsString('--memory-limit', $this->getCapturedArgs());
    }

    public function test_analyze_omits_invalid_memory_limit(): void
    {
        $this->createMockPHPStanWithArgCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app'], 5, 300, 'not-a-size');

        $this->assertStringNotContainsString('--memory-limit', $this->getCapturedArgs());
    }

    public function test_is_valid_memory_limit_accepts_php_ini_formats(): void
    {
        $this->assertTrue(PHPStanRunner::isValidMemoryLimit('512M'));
        $this->assertTrue(PHPStanRunner::isValidMemoryLimit('2048M'));
        $this->assertTrue(PHPStanRunner::isValidMemoryLimit('2G'));
        $this->assertTrue(PHPStanRunner::isValidMemoryLimit('1024k'));
        $this->assertTrue(PHPStanRunner::isValidMemoryLimit('134217728'));
        $this->assertTrue(PHPStanRunner::isValidMemoryLimit('-1'));

        $this->assertFalse(PHPStanRunner::isValidMemoryLimit(''));
        $this->assertFalse(PHPStanRunner::isValidMemoryLimit('not-a-size'));
        $this->assertFalse(PHPStanRunner::isValidMemoryLimit('512MB'));
        $this->assertFalse(PHPStanRunner::isValidMemoryLimit('1.5G'));
    }

    /**
     * Create a mock PHPStan script that returns predefined issues.
     *
     * Mirrors PHPStan's JSON error format, which omits 'identifier' and 'tip'
     * entirely rather than emitting them as null, and which reports errors it cannot
     * attach to a file in a top-level 'errors' list counted by totals.errors.
     *
     * The exit code is configurable because PHPStan exits 1 whenever it reports
     * anything at all, ordinary type errors included.
     *
     * @param  array<array{file: string, line: int, message: string, identifier?: string, tip?: string}>  $issues
     * @param  array<string>  $analysisErrors
     */
    private function createMockPHPStan(array $issues, array $analysisErrors = [], int $exitCode = 0): void
    {
        $vendorBinDir = $this->tempDir.'/vendor/bin';

        if (! is_dir($vendorBinDir)) {
            mkdir($vendorBinDir, 0755, true);
        }

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

        $output = [
            'totals' => [
                'errors' => count($analysisErrors),
                'file_errors' => count($issues),
            ],
            'files' => $files,
            'errors' => array_values($analysisErrors),
        ];

        $json = json_encode($output, JSON_PRETTY_PRINT);

        $script = <<<BASH
#!/bin/bash
cat <<'EOF'
{$json}
EOF
exit {$exitCode}
BASH;

        file_put_contents($vendorBinDir.'/phpstan', $script);
        chmod($vendorBinDir.'/phpstan', 0755);
    }

    /**
     * Create a mock PHPStan script that writes to stderr and emits no JSON at all.
     *
     * Mirrors a crash, an out-of-memory kill or a PathNotFoundException: PHPStan
     * writes the reason to stderr and leaves stdout empty, so there is no report to
     * decode.
     */
    private function createFailingMockPHPStan(string $stderr, int $exitCode = 1): void
    {
        $vendorBinDir = $this->tempDir.'/vendor/bin';

        if (! is_dir($vendorBinDir)) {
            mkdir($vendorBinDir, 0755, true);
        }

        $script = <<<BASH
#!/bin/bash
cat >&2 <<'EOF'
{$stderr}
EOF
exit {$exitCode}
BASH;

        file_put_contents($vendorBinDir.'/phpstan', $script);
        chmod($vendorBinDir.'/phpstan', 0755);
    }

    /**
     * Create a mock PHPStan script that captures the config file content.
     */
    private function createMockPHPStanWithConfigCapture(): void
    {
        $vendorBinDir = $this->tempDir.'/vendor/bin';
        mkdir($vendorBinDir, 0755, true);

        $output = [
            'totals' => [
                'errors' => 0,
                'file_errors' => 0,
            ],
            'files' => [],
            'errors' => [],
        ];

        $json = json_encode($output, JSON_PRETTY_PRINT);
        $capturedConfigPath = $this->tempDir.'/captured_config.neon';

        // Script that captures the config file content before outputting JSON
        $script = <<<BASH
#!/bin/bash

# Parse the --configuration flag to get the config file path
for arg in "\$@"; do
    case \$arg in
        --configuration=*)
            CONFIG_FILE="\${arg#*=}"
            if [ -f "\$CONFIG_FILE" ]; then
                cp "\$CONFIG_FILE" "{$capturedConfigPath}"
            fi
            ;;
    esac
done

cat <<'EOF'
{$json}
EOF
BASH;

        file_put_contents($vendorBinDir.'/phpstan', $script);
        chmod($vendorBinDir.'/phpstan', 0755);
    }

    /**
     * Read the captured config file content.
     */
    private function getCapturedConfig(): string
    {
        $path = $this->tempDir.'/captured_config.neon';
        $this->assertFileExists($path, 'Captured config file should exist');

        $content = file_get_contents($path);
        $this->assertIsString($content, 'Captured config file should be readable');

        return $content;
    }

    /**
     * Create a mock PHPStan script that records every argument it is invoked with.
     */
    private function createMockPHPStanWithArgCapture(): void
    {
        $vendorBinDir = $this->tempDir.'/vendor/bin';
        mkdir($vendorBinDir, 0755, true);

        $output = [
            'totals' => [
                'errors' => 0,
                'file_errors' => 0,
            ],
            'files' => [],
            'errors' => [],
        ];

        $json = json_encode($output, JSON_PRETTY_PRINT);
        $capturedArgsPath = $this->tempDir.'/captured_args.txt';

        // Script that records each argument on its own line, then outputs JSON.
        $script = <<<BASH
#!/bin/bash
printf '%s\\n' "\$@" > "{$capturedArgsPath}"

cat <<'EOF'
{$json}
EOF
BASH;

        file_put_contents($vendorBinDir.'/phpstan', $script);
        chmod($vendorBinDir.'/phpstan', 0755);
    }

    /**
     * Read the captured argument list content.
     */
    private function getCapturedArgs(): string
    {
        $path = $this->tempDir.'/captured_args.txt';
        $this->assertFileExists($path, 'Captured args file should exist');

        $content = file_get_contents($path);
        $this->assertIsString($content, 'Captured args file should be readable');

        return $content;
    }
}
