<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ShieldCI\Support\PHPStanRunner;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;

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

    public function test_generates_a_fixed_config_when_no_parameters_are_passed(): void
    {
        // Regression guard for PHPStanAnalyzer, which passes none. reportUnmatchedIgnoredErrors
        // joined this baseline in #352: the run substitutes its own level for the user's, so
        // it cannot judge whether their ignore patterns are stale.
        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $capturedConfig = $this->getCapturedConfig();

        $this->assertSame(
            "parameters:\n    level: 5\n    tmpDir: ".sys_get_temp_dir()
                .'/phpstan'."\n    reportUnmatchedIgnoredErrors: false",
            $capturedConfig
        );
    }

    public function test_does_not_report_unmatched_ignore_patterns_from_the_users_config(): void
    {
        // #352: the generated config includes the user's phpstan.neon but replaces its level,
        // so patterns tuned for their level go unmatched at ours and land in PHPStan's
        // top-level errors list. That reddened the run for a configuration ShieldCI itself
        // changed the meaning of.
        file_put_contents(
            $this->tempDir.'/phpstan.neon',
            "parameters:\n    level: 8\n    reportUnmatchedIgnoredErrors: true\n"
        );

        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('    reportUnmatchedIgnoredErrors: false', $capturedConfig);

        // The setting has to be written after the includes to outrank the user's own value.
        $includesAt = strpos($capturedConfig, 'phpstan.neon');
        $settingAt = strpos($capturedConfig, 'reportUnmatchedIgnoredErrors: false');

        $this->assertIsInt($includesAt);
        $this->assertIsInt($settingAt);
        $this->assertGreaterThan($includesAt, $settingAt);
    }

    public function test_a_caller_can_re_enable_unmatched_ignore_reporting(): void
    {
        $this->createMockPHPStanWithConfigCapture();

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app'], 5, 300, null, ['reportUnmatchedIgnoredErrors' => true]);

        $capturedConfig = $this->getCapturedConfig();

        $this->assertStringContainsString('    reportUnmatchedIgnoredErrors: true', $capturedConfig);
        $this->assertStringNotContainsString('    reportUnmatchedIgnoredErrors: false', $capturedConfig);
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

    public function test_retries_without_an_extension_the_users_config_already_includes(): void
    {
        // Larastan's own install instructions put this include in the project's phpstan.neon,
        // and PHPStan refuses to start when the generated config includes the file again.
        $larastan = $this->createExtension('vendor/larastan/larastan/extension.neon');
        file_put_contents($this->tempDir.'/phpstan.neon', "includes:\n    - ./vendor/larastan/larastan/extension.neon\n");

        $this->createMockPHPStanRejectingDuplicateIncludes(
            ['larastan/larastan/extension.neon'],
            "This file is included multiple times:\n- {$larastan}"
        );

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $this->assertSame([], $runner->getAnalysisErrors());
        $this->assertCount(1, $runner->getIssues());
        $this->assertSame(2, $this->getInvocationCount());

        $capturedConfig = $this->getCapturedConfig();
        $this->assertStringNotContainsString('larastan/larastan/extension.neon', $capturedConfig);
        $this->assertStringContainsString($this->tempDir.'/phpstan.neon', $capturedConfig);
    }

    public function test_drops_every_extension_reported_as_duplicated(): void
    {
        // phpstan/extension-installer loads both extensions itself, whether or not the
        // project has a phpstan.neon, so PHPStan reports them together.
        $larastan = $this->createExtension('vendor/larastan/larastan/extension.neon');
        $carbon = $this->createExtension('vendor/nesbot/carbon/extension.neon');
        file_put_contents($this->tempDir.'/phpstan.neon', "parameters:\n    level: 9\n");

        $this->createMockPHPStanRejectingDuplicateIncludes(
            ['larastan/larastan/extension.neon', 'nesbot/carbon/extension.neon'],
            "These files are included multiple times:\n- {$larastan}\n- {$carbon}\n\n"
                ."It can lead to unexpected results. If you're using phpstan/extension-installer, "
                .'make sure you have removed corresponding neon files from your project config file.'
        );

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $this->assertSame([], $runner->getAnalysisErrors());
        $this->assertCount(1, $runner->getIssues());
        $this->assertSame(2, $this->getInvocationCount());

        $capturedConfig = $this->getCapturedConfig();
        $this->assertStringNotContainsString('larastan/larastan/extension.neon', $capturedConfig);
        $this->assertStringNotContainsString('nesbot/carbon/extension.neon', $capturedConfig);
        $this->assertStringContainsString($this->tempDir.'/phpstan.neon', $capturedConfig);
    }

    public function test_does_not_retry_when_the_duplicated_file_is_not_one_of_the_runners_includes(): void
    {
        // A project config that includes one of its own files twice is rejected by plain
        // PHPStan too. Dropping the runner's includes cannot repair that, so the run is
        // reported as the failure it is.
        $this->createExtension('vendor/larastan/larastan/extension.neon');
        file_put_contents($this->tempDir.'/phpstan.neon', "parameters:\n    level: 9\n");

        $this->createMockPHPStanRejectingDuplicateIncludes(
            ['includes:'],
            "This file is included multiple times:\n- {$this->tempDir}/config/shared.neon"
        );

        $runner = new PHPStanRunner($this->tempDir);
        $runner->analyze(['app']);

        $errors = $runner->getAnalysisErrors();

        $this->assertSame(1, $this->getInvocationCount());
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('included multiple times', $errors[0]);
        $this->assertStringContainsString('config/shared.neon', $errors[0]);
        $this->assertTrue($runner->getIssues()->isEmpty());
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

    /**
     * A regex engine failure must not cost the caller the whole message.
     *
     * condenseOutput() falls back to an empty excerpt when PCRE gives up, so the exit
     * code still reaches the report. That is the only evidence a run which produced no
     * output leaves behind, and losing it would put us back to reporting a clean pass
     * for an analysis that never happened.
     */
    public function test_describe_aborted_run_survives_a_regex_engine_failure(): void
    {
        // Run the process before lowering the limit: Symfony\Process uses PCRE itself.
        $process = new Process(['sh', '-c', 'echo "crash detail" >&2; exit 3']);
        $process->run();

        $runner = new PHPStanRunner($this->tempDir);

        $reflection = new ReflectionClass($runner);
        $method = $reflection->getMethod('describeAbortedRun');
        $method->setAccessible(true);

        // A match limit of zero makes PCRE abort before it matches anything, which is
        // the only way preg_replace() can fail on a pattern as simple as /\s+/.
        $original = ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '0');

        try {
            if (preg_replace('/\s+/', ' ', 'a b') !== null) {
                $this->markTestSkipped('This PCRE build does not honour a zero match limit.');
            }

            $message = $method->invoke($runner, $process);
        } finally {
            ini_set('pcre.backtrack_limit', $original === false ? '1000000' : $original);
        }

        // The stderr excerpt is dropped, the summary is not.
        $this->assertSame('PHPStan produced no analysable output (exit code 3)', $message);
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
        // Create a mock PHPStan that outputs invalid JSON
        $this->writePHPStanStub("echo \"This is not valid JSON\\n\";\n");

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
        // Mock that sleeps 3 seconds, longer than our 1s timeout
        $this->writePHPStanStub("sleep(3);\n");

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

    /**
     * The subprocess runs under the interpreter that is running this analysis.
     *
     * vendor/bin/phpstan is a Composer proxy whose "#!/usr/bin/env php" shebang resolves
     * against PATH, so executing it directly handed the analysis to whichever php came
     * first there. Against a project installed for a newer PHP, Composer's platform_check.php
     * then killed the child before it analysed anything and the run surfaced only as
     * "produced no analysable output (exit code 255)". Reporting its own PHP_BINARY back
     * through the report is the only way the stub can say which interpreter ran it.
     *
     * The stub carries no shebang and is not executable, so neither its first line nor its
     * mode takes any part in the decision.
     */
    public function test_analyze_runs_phpstan_under_the_interpreter_running_this_process(): void
    {
        $this->writePHPStanStub(<<<'PHP'
        echo json_encode([
            'totals' => ['errors' => 0, 'file_errors' => 1],
            'files' => [
                '/app/Interpreter.php' => [
                    'messages' => [['message' => PHP_BINARY, 'line' => 1, 'ignorable' => true]],
                ],
            ],
            'errors' => [],
        ]);

        PHP);

        $stub = $this->tempDir.'/vendor/bin/phpstan';
        chmod($stub, 0644);
        $this->assertFalse(is_executable($stub), 'The stub must not be executable for this test to mean anything');

        // PhpExecutableFinder answers from the PHP_BINARY environment variable before it
        // looks at the running SAPI, so a shell that exports one would be deciding this
        // assertion instead of the runner. ComposerValidatorTest empties PATH for the same
        // reason. Full paths, not basenames: the reported bug was two binaries both called
        // "php".
        $saved = getenv('PHP_BINARY');
        putenv('PHP_BINARY');

        $runner = new PHPStanRunner($this->tempDir);

        try {
            $runner->analyze(['app']);
        } finally {
            putenv($saved === false ? 'PHP_BINARY' : 'PHP_BINARY='.$saved);
        }

        $issue = $runner->getIssues()->first();

        $this->assertNotNull($issue);
        $this->assertSame(PHP_BINARY, $issue['message']);
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
     * Write the stub PHPStan the runner will launch.
     *
     * The runner names the PHP interpreter and hands it this path as the script to run, so
     * the stub is a PHP file: a shell script would be parsed as PHP and leave a syntax error
     * where the report belongs. Nothing execs the file, so no mode is set. On macOS the first
     * execution of a freshly written executable blocks on a Gatekeeper scan, ~3.9s wall
     * against 0.02s CPU (#364), and this file no longer has a first execution.
     */
    private function writePHPStanStub(string $php): void
    {
        $vendorBinDir = $this->tempDir.'/vendor/bin';

        if (! is_dir($vendorBinDir)) {
            mkdir($vendorBinDir, 0755, true);
        }

        file_put_contents($vendorBinDir.'/phpstan', "<?php\n\n".$php);
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

        $this->writePHPStanStub(sprintf(
            "echo %s;\nexit(%d);\n",
            var_export((string) json_encode($output, JSON_PRETTY_PRINT), true),
            $exitCode
        ));
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
        // The appended newline stands in for the one the heredoc used to add, so what
        // reaches condenseOutput() is byte for byte what it saw before.
        $this->writePHPStanStub(sprintf(
            "fwrite(STDERR, %s);\nexit(%d);\n",
            var_export($stderr."\n", true),
            $exitCode
        ));
    }

    /**
     * Create a mock PHPStan script that captures the config file content.
     */
    private function createMockPHPStanWithConfigCapture(): void
    {
        $output = [
            'totals' => [
                'errors' => 0,
                'file_errors' => 0,
            ],
            'files' => [],
            'errors' => [],
        ];

        // Stub that captures the config file before printing the report. The is_file()
        // guard is load bearing: the CLI SAPI writes warnings to stdout, where one would
        // land in the middle of the JSON and turn a config assertion into an unreadable
        // "no analysable output".
        $this->writePHPStanStub(sprintf(
            <<<'PHP'
            foreach (array_slice($argv, 1) as $arg) {
                if (str_starts_with($arg, '--configuration=')) {
                    $config = substr($arg, strlen('--configuration='));

                    if (is_file($config)) {
                        copy($config, %s);
                    }
                }
            }

            echo %s;

            PHP,
            var_export($this->tempDir.'/captured_config.neon', true),
            var_export((string) json_encode($output, JSON_PRETTY_PRINT), true)
        ));
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
     * Create an empty extension config under the base path and return its path.
     */
    private function createExtension(string $relativePath): string
    {
        $path = $this->tempDir.'/'.$relativePath;

        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0755, true);
        }

        file_put_contents($path, "# Extension\n");

        return $path;
    }

    /**
     * Create a mock PHPStan script that refuses any config containing one of the needles.
     *
     * Mirrors PHPStan's DuplicateIncludedFilesException, which is written to stderr and
     * ends the run with exit code 1 before anything is analysed. A config containing none
     * of the needles gets a report with one issue instead. Every invocation is counted and
     * its config captured, so the capture always belongs to the last run.
     *
     * @param  array<string>  $needles
     */
    private function createMockPHPStanRejectingDuplicateIncludes(array $needles, string $stderr): void
    {
        $json = (string) json_encode([
            'totals' => ['errors' => 0, 'file_errors' => 1],
            'files' => [
                '/app/Services/ReportService.php' => [
                    'messages' => [
                        ['message' => 'Undefined variable: $report', 'line' => 12, 'ignorable' => true],
                    ],
                ],
            ],
            'errors' => [],
        ], JSON_PRETTY_PRINT);

        // str_contains() is what grep -qF was doing: a fixed substring test, not a pattern
        // match. Both arms exit 1, because PHPStan does too whenever it reports anything.
        $this->writePHPStanStub(sprintf(
            <<<'PHP'
            file_put_contents(%s, "run\n", FILE_APPEND);

            $config = '';

            foreach (array_slice($argv, 1) as $arg) {
                if (str_starts_with($arg, '--configuration=')) {
                    $config = substr($arg, strlen('--configuration='));
                }
            }

            $contents = '';

            if (is_file($config)) {
                copy($config, %s);
                $contents = (string) file_get_contents($config);
            }

            foreach (%s as $needle) {
                if (str_contains($contents, $needle)) {
                    fwrite(STDERR, %s);

                    exit(1);
                }
            }

            echo %s;
            exit(1);

            PHP,
            var_export($this->tempDir.'/invocations.txt', true),
            var_export($this->tempDir.'/captured_config.neon', true),
            var_export($needles, true),
            var_export($stderr."\n", true),
            var_export($json, true)
        ));
    }

    /**
     * How many times the mock PHPStan script has been run.
     */
    private function getInvocationCount(): int
    {
        $path = $this->tempDir.'/invocations.txt';

        if (! file_exists($path)) {
            return 0;
        }

        $content = file_get_contents($path);
        $this->assertIsString($content, 'Invocation log should be readable');

        return substr_count($content, "run\n");
    }

    /**
     * Create a mock PHPStan script that records every argument it is invoked with.
     */
    private function createMockPHPStanWithArgCapture(): void
    {
        $output = [
            'totals' => [
                'errors' => 0,
                'file_errors' => 0,
            ],
            'files' => [],
            'errors' => [],
        ];

        // Stub that records each argument on its own line, then prints the report.
        // array_slice($argv, 1) drops the stub's own path, exactly as "$@" dropped $0.
        $this->writePHPStanStub(sprintf(
            <<<'PHP'
            file_put_contents(%s, implode("\n", array_slice($argv, 1))."\n");

            echo %s;

            PHP,
            var_export($this->tempDir.'/captured_args.txt', true),
            var_export((string) json_encode($output, JSON_PRETTY_PRINT), true)
        ));
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
