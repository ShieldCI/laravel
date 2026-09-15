<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\Reliability\PHPStanAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class PHPStanAnalyzerTest extends AnalyzerTestCase
{
    /**
     * Messages Larastan builds from fixed literals, quoted as its rules emit them.
     */
    private const COLLECTION_MESSAGE = "Called 'count' on Laravel collection, but could have been retrieved as a query.";

    private const ENV_MESSAGE = "Called 'env' outside of the config directory which returns null when the config is cached, use 'config'.";

    private const RELATION_MESSAGE = "Relation 'widgets' is not found in App\Models\Team model.";

    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        $reliabilityConfig = [
            'enabled' => true,
            'phpstan' => [
                'level' => $config['level'] ?? 5,
                'paths' => $config['paths'] ?? ['app'],
                'categories' => $config['categories'] ?? [
                    'dead-code',
                    'deprecated-code',
                    'foreach-iterable',
                    'invalid-function-calls',
                    'invalid-imports',
                    'invalid-method-calls',
                    'invalid-method-overrides',
                    'invalid-offset-access',
                    'invalid-property-access',
                    'missing-model-relation',
                    'missing-return-statement',
                    'undefined-constant',
                    'undefined-variable',
                ],
                'disabled_categories' => $config['disabled_categories'] ?? [],
            ],
        ];

        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'reliability' => $reliabilityConfig,
                ],
            ],
        ]);

        return new PHPStanAnalyzer($configRepo);
    }

    public function test_passes_with_valid_code(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ValidService
{
    public function process(string $input): string
    {
        return strtoupper($input);
    }

    public function calculate(int $a, int $b): int
    {
        return $a + $b;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/ValidService.php' => $code]);

        // Create mock PHPStan that returns no issues
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([])
        );
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_undefined_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class InvalidService
{
    public function process()
    {
        return $undefinedVariable;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/InvalidService.php' => $code]);
        $filePath = $tempDir.'/app/Services/InvalidService.php';

        // Create mock PHPStan that returns undefined variable issue
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                [
                    'file' => $filePath,
                    'line' => 9,
                    'message' => 'Undefined variable: $undefinedVariable',
                ],
            ])
        );
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Undefined Variables', $result);
    }

    public function test_detects_undefined_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUser()
    {
        $user = new \stdClass();
        return $user->undefinedMethod();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/UserService.php' => $code]);
        $filePath = $tempDir.'/app/Services/UserService.php';

        // Create mock PHPStan that returns method call issue
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                [
                    'file' => $filePath,
                    'line' => 10,
                    'message' => 'Call to an undefined method stdClass::undefinedMethod().',
                ],
            ])
        );
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid Method Calls', $result);
    }

    public function test_detects_missing_return_statement(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CalculatorService
{
    public function calculate(int $a, int $b): int
    {
        $result = $a + $b;
        // Missing return statement
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/CalculatorService.php' => $code]);
        $filePath = $tempDir.'/app/Services/CalculatorService.php';

        // Create mock PHPStan that returns missing return issue
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                [
                    'file' => $filePath,
                    'line' => 8,
                    'message' => 'Method App\Services\CalculatorService::calculate() should return int but return statement is missing.',
                ],
            ])
        );
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Missing Return Statements', $result);
    }

    public function test_respects_disabled_categories(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ServiceWithIssues
{
    public function process()
    {
        return $undefinedVariable;
    }

    public function calculate(int $a, int $b): int
    {
        $result = $a + $b;
        // Missing return
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/ServiceWithIssues.php' => $code]);
        $filePath = $tempDir.'/app/Services/ServiceWithIssues.php';

        // Create mock PHPStan with both issues
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                [
                    'file' => $filePath,
                    'line' => 9,
                    'message' => 'Undefined variable: $undefinedVariable',
                ],
                [
                    'file' => $filePath,
                    'line' => 13,
                    'message' => 'Method should return int but return statement is missing.',
                ],
            ])
        );
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        // Disable undefined-variable category
        $analyzer = $this->createAnalyzer([
            'disabled_categories' => ['undefined-variable'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should still detect missing return, but not undefined variable
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $messages = array_map(fn ($issue) => $issue->message, $issues);

        // Should not contain undefined variable
        foreach ($messages as $msg) {
            $this->assertStringNotContainsString('Undefined Variables detected', $msg);
        }

        // Should contain missing return
        $this->assertHasIssueContaining('Missing Return Statements', $result);
    }

    public function test_respects_custom_categories(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ServiceWithMultipleIssues
{
    public function process()
    {
        return $undefinedVariable;
    }

    public function getUser()
    {
        $user = new \stdClass();
        return $user->undefinedMethod();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/ServiceWithMultipleIssues.php' => $code]);
        $filePath = $tempDir.'/app/Services/ServiceWithMultipleIssues.php';

        // Create mock PHPStan with both issues
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                [
                    'file' => $filePath,
                    'line' => 9,
                    'message' => 'Undefined variable: $undefinedVariable',
                ],
                [
                    'file' => $filePath,
                    'line' => 15,
                    'message' => 'Call to an undefined method stdClass::undefinedMethod().',
                ],
            ])
        );
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        // Only enable undefined-variable category
        $analyzer = $this->createAnalyzer([
            'categories' => ['undefined-variable'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should only detect undefined variable, not method call
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Undefined Variables', $result);

        $issues = $result->getIssues();
        $messages = array_map(fn ($issue) => $issue->message, $issues);

        // Should not contain method call issues
        foreach ($messages as $msg) {
            $this->assertStringNotContainsString('Invalid Method Calls', $msg);
        }
    }

    public function test_handles_phpstan_not_available(): void
    {
        // Create temp directory without vendor/bin/phpstan
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should return warning, not error or pass
        $this->assertWarning($result);
        $this->assertStringContainsString('PHPStan is not available', $result->getMessage());
    }

    public function test_respects_custom_phpstan_level(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class StrictService
{
    public function process($input)
    {
        return strtoupper($input);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/StrictService.php' => $code]);

        // Create mock PHPStan (no issues for this test - just verify level config)
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([])
        );
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        // Use level 8 (stricter)
        $analyzer = $this->createAnalyzer([
            'level' => 8,
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Verify that the analyzer ran successfully
        $this->assertPassed($result);
    }

    public function test_respects_custom_paths(): void
    {
        $appCode = <<<'PHP'
<?php

namespace App\Services;

class AppService
{
    public function process()
    {
        return $undefinedVariable;
    }
}
PHP;

        $srcCode = <<<'PHP'
<?php

namespace Src\Services;

class SrcService
{
    public function process()
    {
        return $anotherUndefinedVariable;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/AppService.php' => $appCode,
            'src/Services/SrcService.php' => $srcCode,
        ]);

        $appFilePath = $tempDir.'/app/Services/AppService.php';

        // Create mock PHPStan with only app issues (not src issues)
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                [
                    'file' => $appFilePath,
                    'line' => 9,
                    'message' => 'Undefined variable: $undefinedVariable',
                ],
            ])
        );
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        // Only analyze 'app' directory
        $analyzer = $this->createAnalyzer([
            'paths' => ['app'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should detect issues in app, but not src
        $this->assertFailed($result);
        $issues = $result->getIssues();

        foreach ($issues as $issue) {
            // All issues should be from app directory
            $this->assertNotNull($issue->location);
            $this->assertStringContainsString('app', $issue->location->file);
            $this->assertStringNotContainsString('src', $issue->location->file);
        }
    }

    public function test_provides_eloquent_scope_recommendation_for_builder_method_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Deal extends Model
{
    public function scopeSent($query)
    {
        return $query->where('sent', true);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Deal.php' => $code]);
        $filePath = $tempDir.'/app/Models/Deal.php';

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                [
                    'file' => $filePath,
                    'line' => 10,
                    'message' => 'Call to an undefined method Illuminate\Database\Eloquent\Builder<Illuminate\Database\Eloquent\Model>::sent().',
                ],
            ])
        );
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid Method Calls', $result);

        $issues = $result->getIssues();
        $scopeRecommendationFound = false;
        foreach ($issues as $issue) {
            if (str_contains($issue->recommendation, 'local scope')) {
                $scopeRecommendationFound = true;
                $this->assertStringContainsString('@var', $issue->recommendation);
                $this->assertStringContainsString('@method', $issue->recommendation);
                $this->assertStringContainsString('Builder<static>', $issue->recommendation);
                break;
            }
        }
        $this->assertTrue($scopeRecommendationFound, 'Expected Eloquent scope recommendation with @var and @method annotation guidance');
    }

    public function test_metadata_contains_correct_information(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('phpstan', $metadata->id);
        $this->assertSame('PHPStan Static Analyzer', $metadata->name);
        $this->assertStringContainsString('PHPStan', $metadata->description);
        $this->assertStringContainsString('static analysis', $metadata->description);
    }

    public function test_honours_string_timeout_from_config(): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/ValidService.php' => "<?php\nclass ValidService {}"]);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        // Sleeps 2s — exceeds the 1s timeout so the process is killed on time.
        // If string '1' fell back to the hardcoded 300 (the bug), the mock would
        // complete before the timeout and the result would be passed, not error.
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            "#!/bin/bash\nsleep 2\necho '{}'"
        );
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        // env() returns strings, so SHIELDCI_TIMEOUT=600 arrives as '1' here.
        // is_int('1') = false → without the is_numeric fix it falls back to 300.
        $configRepo = new Repository([
            'shieldci' => [
                'timeout' => '1',
                'analyzers' => ['reliability' => ['enabled' => true, 'phpstan' => [
                    'level' => 5, 'paths' => ['app'], 'categories' => ['undefined-variable'], 'disabled_categories' => [],
                ]]],
            ],
        ]);

        $analyzer = new PHPStanAnalyzer($configRepo);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('exceeded the timeout of 1', $result->getMessage());
    }

    public function test_passes_configured_memory_limit_to_phpstan(): void
    {
        $tempDir = $this->createTempDirectory(['app/Services/ValidService.php' => "<?php\nclass ValidService {}"]);
        $argsFile = $tempDir.'/captured_args.txt';

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        // Records the arguments PHPStan was invoked with, then returns empty JSON.
        $script = <<<BASH
#!/bin/bash
printf '%s\\n' "\$@" > "{$argsFile}"
echo '{"files":[]}'
BASH;
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $configRepo = new Repository([
            'shieldci' => [
                'memory_limit' => '2048M',
                'analyzers' => ['reliability' => ['enabled' => true, 'phpstan' => [
                    'level' => 5, 'paths' => ['app'], 'categories' => ['undefined-variable'], 'disabled_categories' => [],
                ]]],
            ],
        ]);

        $analyzer = new PHPStanAnalyzer($configRepo);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $analyzer->analyze();

        $this->assertFileExists($argsFile);
        $captured = file_get_contents($argsFile);
        $this->assertIsString($captured);
        $this->assertStringContainsString('--memory-limit=2048M', $captured);
    }

    public function test_does_not_report_a_cross_category_duplicate_twice(): void
    {
        $result = $this->analyzeIssues([
            ['message' => 'Parameter #1 $id of method App\Services\ExampleService::find() expects int, string given.'],
        ]);

        $this->assertIssueCount(1, $result);
        $this->assertStringContainsString('Found 1 PHPStan issue(s)', $result->getMessage());
    }

    public function test_reports_unmatched_errors_in_the_other_category(): void
    {
        $result = $this->analyzeIssues([
            ['message' => 'If condition is always true.'],
        ]);

        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('Other PHPStan Issues', $result);
    }

    public function test_routes_function_argument_errors_to_invalid_function_calls(): void
    {
        $result = $this->analyzeIssues([
            [
                'identifier' => 'argument.type',
                'message' => 'Parameter #1 $callback of function array_map expects callable, string given.',
            ],
        ]);

        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('Invalid Function Calls', $result);
    }

    public function test_routes_static_method_and_constructor_arguments_to_invalid_method_calls(): void
    {
        $result = $this->analyzeIssues([
            [
                'identifier' => 'argument.type',
                'message' => 'Parameter #1 $id of static method App\Services\ExampleService::locate() expects int, string given.',
            ],
            [
                'identifier' => 'argument.type',
                'message' => 'Parameter #1 $id of class App\Services\ExampleService constructor expects int, string given.',
            ],
        ]);

        $this->assertIssueCount(2, $result);
        $this->assertHasIssueContaining('Invalid Method Calls', $result);

        foreach ($result->getIssues() as $issue) {
            $this->assertStringNotContainsString('Invalid Function Calls', $issue->message);
        }
    }

    public function test_recovers_always_false_comparison_as_dead_code(): void
    {
        $result = $this->analyzeIssues([
            [
                'identifier' => 'equal.alwaysFalse',
                'message' => "Loose comparison using == between int<min, -1>|int<1, max> and '' will always evaluate to false.",
            ],
        ]);

        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('Dead Code', $result);
    }

    public function test_recovers_null_coalesce_errors_into_distinct_categories(): void
    {
        $result = $this->analyzeIssues([
            [
                'identifier' => 'nullCoalesce.variable',
                'message' => 'Variable $selected on left side of ?? always exists and is not nullable.',
            ],
            [
                'identifier' => 'nullCoalesce.expr',
                'message' => 'Expression on left side of ?? is not nullable.',
            ],
            [
                'identifier' => 'nullCoalesce.offset',
                'message' => "Offset 'name' on array{name: string} on left side of ?? always exists and is not nullable.",
            ],
        ]);

        $this->assertIssueCount(3, $result);
        $this->assertHasIssueContaining('Undefined Variables', $result);
        $this->assertHasIssueContaining('Dead Code', $result);
        $this->assertHasIssueContaining('Invalid Offset Access', $result);
    }

    public function test_deprecation_identifier_beats_the_namespace_prefix(): void
    {
        $result = $this->analyzeIssues([
            [
                'identifier' => 'method.deprecated',
                'message' => 'Call to deprecated method find() of class App\Services\ExampleService.',
            ],
            [
                'identifier' => 'class.deprecated',
                'message' => 'Usage of deprecated class App\Services\ExampleService.',
            ],
            [
                'identifier' => 'property.deprecated',
                'message' => 'Access to deprecated property $name of class App\Services\ExampleService.',
            ],
        ]);

        $this->assertIssueCount(3, $result);

        foreach ($result->getIssues() as $issue) {
            $this->assertStringContainsString('Deprecated Code', $issue->message);
        }
    }

    public function test_does_not_treat_a_symbol_named_deprecated_as_deprecated_code(): void
    {
        $result = $this->analyzeIssues([
            ['message' => 'Call to an undefined method App\Deprecated\Legacy::run().'],
        ]);

        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('Invalid Method Calls', $result);
    }

    public function test_missing_model_relation_matches_only_the_larastan_identifier(): void
    {
        $result = $this->analyzeIssues([
            [
                'identifier' => 'larastan.relationExistence',
                'message' => "Relation 'widgets' is not found in App\Models\Team model.",
            ],
            [
                'identifier' => 'method.notFound',
                'message' => 'Call to an undefined method App\Models\Team::widgets().',
            ],
            [
                'identifier' => 'property.notFound',
                'message' => 'Access to an undefined property Illuminate\Database\Eloquent\Model::$owner_id.',
            ],
        ]);

        $this->assertIssueCount(3, $result);

        $relationIssues = array_filter(
            $result->getIssues(),
            static fn ($issue): bool => str_contains($issue->message, 'Missing Model Relations')
        );

        $this->assertCount(1, $relationIssues);
        $this->assertHasIssueContaining('Invalid Method Calls', $result);
        $this->assertHasIssueContaining('Invalid Property Access', $result);
    }

    public function test_other_category_is_active_even_when_categories_are_pinned(): void
    {
        $result = $this->analyzeIssues(
            [['message' => 'If condition is always true.']],
            ['categories' => ['undefined-variable']]
        );

        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('Other PHPStan Issues', $result);
    }

    public function test_other_category_can_be_disabled(): void
    {
        $result = $this->analyzeIssues(
            [['message' => 'If condition is always true.']],
            ['disabled_categories' => ['other']]
        );

        $this->assertPassed($result);
    }

    public function test_disabled_category_issues_do_not_leak_into_other(): void
    {
        $result = $this->analyzeIssues(
            [['identifier' => 'variable.undefined', 'message' => 'Undefined variable: $missing']],
            ['disabled_categories' => ['undefined-variable']]
        );

        $this->assertPassed($result);
        $this->assertStringNotContainsString('Other PHPStan Issues', $result->getMessage());
    }

    public function test_skips_identifiers_owned_by_a_dedicated_analyzer(): void
    {
        $rows = [
            ['larastan.noUnnecessaryCollectionCall', self::COLLECTION_MESSAGE],
            ['larastan.noEnvCallsOutsideOfConfig', self::ENV_MESSAGE],
            // Larastan 2.9.0 published its rule identifiers under a "rules." namespace
            // and renamed them to "larastan." in 2.9.1. composer.json still admits 2.9.0,
            // so both spellings reach us and both belong to env-call-outside-config.
            ['rules.noEnvCallsOutsideOfConfig', self::ENV_MESSAGE],
        ];

        foreach ($rows as [$identifier, $message]) {
            $result = $this->analyzeIssues([
                ['identifier' => $identifier, 'message' => $message],
            ]);

            $this->assertPassed($result);
            $this->assertCount(
                0,
                $result->getIssues(),
                sprintf('%s is owned by another analyzer and must not be reported here', $identifier)
            );
        }
    }

    public function test_skips_a_collection_call_finding_that_carries_no_identifier(): void
    {
        // Larastan's collection rule sets no identifier before 2.9.1, so the message is
        // the only thing distinguishing a finding collection-call-optimization owns.
        $result = $this->analyzeIssues([
            ['message' => self::COLLECTION_MESSAGE],
        ]);

        $this->assertPassed($result);
        $this->assertCount(0, $result->getIssues());
    }

    public function test_reports_an_env_message_whose_identifier_belongs_to_another_rule(): void
    {
        // Ownership is decided by the whole identifier, never by its last segment: a
        // third-party rule that happens to end in the same word is not ours to suppress.
        $result = $this->analyzeIssues([
            ['identifier' => 'acme.noEnvCallsOutsideOfConfig', 'message' => self::ENV_MESSAGE],
        ]);

        $this->assertHasIssueContaining('Other PHPStan Issues', $result);
    }

    public function test_the_legacy_relation_existence_identifier_still_reaches_its_category(): void
    {
        // Unlike the env rule, this one has a message pattern, so the 2.9.0 spelling
        // lands in the right category without an entry of its own. Pinned because the
        // pattern is what carries it: dropping the pattern would silently regress 2.9.0.
        $result = $this->analyzeIssues([
            ['identifier' => 'rules.relationExistence', 'message' => self::RELATION_MESSAGE],
        ]);

        $this->assertHasIssueContaining('Missing Model Relations', $result);
    }

    public function test_owned_identifiers_are_not_also_categorised(): void
    {
        $reflection = new \ReflectionClass(PHPStanAnalyzer::class);

        /** @var array<string> $owned */
        $owned = $reflection->getConstant('IDENTIFIERS_HANDLED_ELSEWHERE');

        /** @var array<string, string> $map */
        $map = $reflection->getConstant('IDENTIFIER_MAP');

        $this->assertNotSame([], $owned);

        foreach ($owned as $identifier) {
            // Categorising an identifier we suppress is a contradiction: whichever
            // check runs first wins and the other declaration becomes dead.
            $this->assertArrayNotHasKey(
                $identifier,
                $map,
                sprintf('"%s" is both owned elsewhere and mapped to a category', $identifier)
            );
        }
    }

    public function test_total_issue_count_matches_the_emitted_issue_count(): void
    {
        $result = $this->analyzeIssues([
            ['identifier' => 'variable.undefined', 'message' => 'Undefined variable: $a'],
            ['identifier' => 'method.notFound', 'message' => 'Call to an undefined method App\Services\ExampleService::b().'],
            ['identifier' => 'class.notFound', 'message' => 'Instantiated class App\Nope not found.'],
            ['identifier' => 'equal.alwaysFalse', 'message' => 'Loose comparison using == between int and string will always evaluate to false.'],
            ['identifier' => 'argument.type', 'message' => 'Parameter #1 $x of function strlen expects string, int given.'],
        ]);

        $metadata = $result->getMetadata();

        $this->assertSame(5, $metadata['total_issues']);
        $this->assertCount(5, $result->getIssues());
        $this->assertFalse($metadata['truncated']);
    }

    public function test_result_metadata_reports_category_breakdown_and_truncation(): void
    {
        $issues = [];

        for ($i = 0; $i < 60; $i++) {
            $issues[] = ['identifier' => 'variable.undefined', 'message' => 'Undefined variable: $v'.$i];
        }

        $result = $this->analyzeIssues($issues);
        $metadata = $result->getMetadata();

        $this->assertSame(60, $metadata['total_issues']);
        $this->assertSame(50, $metadata['displayed_issues']);
        $this->assertTrue($metadata['truncated']);
        $this->assertSame(60, $metadata['issues_by_category']['undefined-variable']);
        $this->assertStringContainsString('Found 60 PHPStan issue(s) (showing first 50)', $result->getMessage());
    }

    public function test_other_category_alone_produces_a_warning_not_a_failure(): void
    {
        $result = $this->analyzeIssues([
            ['message' => 'If condition is always true.'],
        ]);

        $this->assertWarning($result);
    }

    public function test_reports_an_error_when_phpstan_only_returns_analysis_errors(): void
    {
        $result = $this->analyzeIssues([], [], [
            'Ignored error pattern #Never matched# was not matched in reported errors.',
        ]);

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan reported 1 analysis error(s)', $result->getMessage());
        $this->assertStringContainsString('was not matched in reported errors', $result->getMessage());
        $this->assertSame(
            ['Ignored error pattern #Never matched# was not matched in reported errors.'],
            $result->getMetadata()['analysis_errors']
        );
    }

    public function test_analysis_error_message_names_each_error(): void
    {
        $result = $this->analyzeIssues([], [], [
            'Ignored error pattern #First# was not matched in reported errors.',
            'Ignored error pattern #Second# was not matched in reported errors.',
        ]);

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan reported 2 analysis error(s)', $result->getMessage());
        $this->assertStringContainsString('#First#', $result->getMessage());
        $this->assertStringContainsString('#Second#', $result->getMessage());
    }

    public function test_summarizes_analysis_errors_beyond_the_message_cap(): void
    {
        $errors = [];

        for ($i = 1; $i <= 5; $i++) {
            $errors[] = 'Ignored error pattern #Pattern'.$i.'# was not matched in reported errors.';
        }

        $result = $this->analyzeIssues([], [], $errors);

        $this->assertError($result);
        $this->assertStringContainsString('#Pattern3#', $result->getMessage());
        $this->assertStringNotContainsString('#Pattern4#', $result->getMessage());
        $this->assertStringContainsString('(and 2 more)', $result->getMessage());

        // The message is capped, the metadata is not.
        $this->assertCount(5, $result->getMetadata()['analysis_errors']);
    }

    public function test_keeps_the_severity_result_when_analysis_errors_accompany_file_issues(): void
    {
        $result = $this->analyzeIssues(
            [['identifier' => 'variable.undefined', 'message' => 'Undefined variable: $missing']],
            [],
            ['Internal error: child process ran out of memory.']
        );

        // The file issue still drives the status, so a partial run is not downgraded from
        // failed to error and its findings are not thrown away.
        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertStringContainsString('Found 1 PHPStan issue(s)', $result->getMessage());
        $this->assertStringContainsString('1 analysis error(s)', $result->getMessage());
        $this->assertStringContainsString('child process ran out of memory', $result->getMessage());
        $this->assertSame(
            ['Internal error: child process ran out of memory.'],
            $result->getMetadata()['analysis_errors']
        );
    }

    public function test_analysis_errors_do_not_upgrade_a_warning_to_a_failure(): void
    {
        $result = $this->analyzeIssues(
            [['message' => 'If condition is always true.']],
            [],
            ['Ignored error pattern #Never matched# was not matched in reported errors.']
        );

        $this->assertWarning($result);
        $this->assertStringContainsString('1 analysis error(s)', $result->getMessage());
    }

    public function test_passes_and_omits_analysis_error_metadata_when_phpstan_is_clean(): void
    {
        $result = $this->analyzeIssues([]);

        $this->assertPassed($result);
        $this->assertSame('No PHPStan issues detected', $result->getMessage());
        $this->assertArrayNotHasKey('analysis_errors', $result->getMetadata());
    }

    public function test_omits_analysis_error_metadata_when_only_file_issues_are_found(): void
    {
        $result = $this->analyzeIssues([
            ['identifier' => 'variable.undefined', 'message' => 'Undefined variable: $missing'],
        ]);

        $this->assertFailed($result);
        $this->assertSame('Found 1 PHPStan issue(s)', $result->getMessage());
        $this->assertArrayNotHasKey('analysis_errors', $result->getMetadata());
    }

    public function test_reports_an_error_when_phpstan_crashes_without_emitting_json(): void
    {
        $result = $this->analyzeUnparseableOutput(
            '',
            'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted',
            1
        );

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan produced no analysable output', $result->getMessage());
        $this->assertStringContainsString('exit code 1', $result->getMessage());
        $this->assertStringContainsString('Allowed memory size', $result->getMessage());
    }

    public function test_reports_an_error_when_phpstan_prints_something_other_than_json(): void
    {
        $result = $this->analyzeUnparseableOutput('Xdebug: [Step Debug] Could not connect', '', 0);

        $this->assertError($result);
        $this->assertStringContainsString('PHPStan produced no analysable output', $result->getMessage());
        $this->assertStringContainsString('exit code 0', $result->getMessage());
    }

    public function test_appends_the_phpstan_tip_to_the_recommendation(): void
    {
        $result = $this->analyzeIssues([
            [
                'identifier' => 'class.notFound',
                'message' => 'Instantiated class App\Nope not found.',
                'tip' => 'Learn more at https://phpstan.org/user-guide/discovering-symbols',
            ],
        ]);

        $issues = $result->getIssues();

        $this->assertCount(1, $issues);
        $this->assertStringContainsString('PHPStan tip: Learn more at', $issues[0]->recommendation);
        $this->assertSame('class.notFound', $issues[0]->metadata['phpstan_identifier']);
    }

    public function test_identifier_and_pattern_paths_agree(): void
    {
        $rows = [
            ['method.notFound', 'Call to an undefined method App\Services\ExampleService::missing().', 'Invalid Method Calls'],
            ['variable.undefined', 'Undefined variable: $missing', 'Undefined Variables'],
            ['return.missing', 'Method App\Services\ExampleService::run() should return string but return statement is missing.', 'Missing Return Statements'],
            ['class.notFound', 'Instantiated class App\Nope not found.', 'Invalid Imports'],
            ['property.notFound', 'Access to an undefined property App\Services\ExampleService::$name.', 'Invalid Property Access'],
            ['larastan.relationExistence', "Relation 'widgets' is not found in App\Models\Team model.", 'Missing Model Relations'],
        ];

        foreach ($rows as [$identifier, $message, $expectedCategory]) {
            $withIdentifier = $this->analyzeIssues([
                ['identifier' => $identifier, 'message' => $message],
            ]);

            $withoutIdentifier = $this->analyzeIssues([
                ['message' => $message],
            ]);

            $this->assertHasIssueContaining($expectedCategory, $withIdentifier);
            $this->assertHasIssueContaining($expectedCategory, $withoutIdentifier);
        }
    }

    public function test_issue_categories_declaration_is_internally_consistent(): void
    {
        $reflection = new \ReflectionClass(PHPStanAnalyzer::class);

        /** @var array<string, array<string, mixed>> $categories */
        $categories = $reflection->getConstant('ISSUE_CATEGORIES');

        $this->assertSame('other', array_key_last($categories));
        $this->assertSame([], $categories['other']['patterns']);

        foreach (['IDENTIFIER_MAP', 'IDENTIFIER_SUFFIX_MAP', 'IDENTIFIER_PREFIX_MAP'] as $mapName) {
            /** @var array<string, string> $map */
            $map = $reflection->getConstant($mapName);

            foreach ($map as $key => $category) {
                $this->assertArrayHasKey(
                    $category,
                    $categories,
                    sprintf('%s maps "%s" to unknown category "%s"', $mapName, $key, $category)
                );
            }
        }
    }

    /**
     * Run the analyzer over a set of mock PHPStan errors.
     *
     * @param  array<array{message: string, line?: int, identifier?: string, tip?: string}>  $issues
     * @param  array<string, mixed>  $config
     * @param  array<string>  $analysisErrors  Errors PHPStan could not attach to a file
     */
    private function analyzeIssues(array $issues, array $config = [], array $analysisErrors = []): ResultInterface
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ExampleService
{
    public function run(): void {}
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/ExampleService.php' => $code]);
        $filePath = $tempDir.'/app/Services/ExampleService.php';

        $prepared = [];

        foreach ($issues as $issue) {
            $issue['file'] = $filePath;
            $issue['line'] = $issue['line'] ?? 7;
            $prepared[] = $issue;
        }

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript($prepared, $analysisErrors)
        );
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer($config);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        return $analyzer->analyze();
    }

    /**
     * Create a mock PHPStan script that returns predefined issues.
     *
     * Mirrors PHPStan's JSON error format, which omits 'identifier' and 'tip'
     * entirely rather than emitting them as null, and which reports errors it cannot
     * attach to a file in a top-level 'errors' list counted by totals.errors.
     *
     * @param  array<array{file: string, line: int, message: string, identifier?: string, tip?: string}>  $issues
     * @param  array<string>  $analysisErrors
     */
    private function createMockPHPStanScript(array $issues, array $analysisErrors = []): string
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

        $json = json_encode($output, JSON_PRETTY_PRINT);

        return <<<BASH
#!/bin/bash
cat <<'EOF'
{$json}
EOF
BASH;
    }

    /**
     * Run the analyzer against a PHPStan binary whose output cannot be decoded.
     *
     * Covers both shapes of the same failure: a crash that writes only to standard
     * error, and a run that exits cleanly but prints something other than JSON.
     */
    private function analyzeUnparseableOutput(string $stdout, string $stderr, int $exitCode): ResultInterface
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ExampleService
{
    public function run(): void {}
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Services/ExampleService.php' => $code]);

        $script = <<<BASH
#!/bin/bash
cat <<'STDOUT_EOF'
{$stdout}
STDOUT_EOF
cat >&2 <<'STDERR_EOF'
{$stderr}
STDERR_EOF
exit {$exitCode}
BASH;

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        return $analyzer->analyze();
    }
}
