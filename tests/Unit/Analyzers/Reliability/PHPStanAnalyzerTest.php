<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\Reliability\PHPStanAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class PHPStanAnalyzerTest extends AnalyzerTestCase
{
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
        $this->assertSame('PHPStan Static Analysis', $metadata->name);
        $this->assertStringContainsString('PHPStan', $metadata->description);
        $this->assertStringContainsString('static analysis', $metadata->description);
    }

    /**
     * Create a mock PHPStan script that returns predefined issues.
     *
     * @param  array<array{file: string, line: int, message: string}>  $issues
     */
    private function createMockPHPStanScript(array $issues): string
    {
        $files = [];

        foreach ($issues as $issue) {
            $file = $issue['file'];
            if (! isset($files[$file])) {
                $files[$file] = ['messages' => []];
            }

            $files[$file]['messages'][] = [
                'message' => $issue['message'],
                'line' => $issue['line'],
                'ignorable' => true,
            ];
        }

        $output = [
            'totals' => [
                'errors' => 0,
                'file_errors' => count($issues),
            ],
            'files' => $files,
            'errors' => [],
        ];

        $json = json_encode($output, JSON_PRETTY_PRINT);

        return <<<BASH
#!/bin/bash
cat <<'EOF'
{$json}
EOF
BASH;
    }
}
