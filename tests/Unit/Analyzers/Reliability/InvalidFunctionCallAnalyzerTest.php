<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\InvalidFunctionCallAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class InvalidFunctionCallAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new InvalidFunctionCallAnalyzer;
    }

    // =========================================================================
    // PHPStan Availability & Error Handling Tests
    // =========================================================================

    public function test_returns_warning_when_phpstan_not_installed(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('PHPStan binary not found', $result);

        // Check recommendation mentions composer install
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('composer install', $issues[0]->recommendation);
        $this->assertStringNotContainsString('composer require', $issues[0]->recommendation);
    }

    public function test_handles_phpstan_execution_failure(): void
    {
        // Create a temp directory with vendor/bin/phpstan that will fail
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => '#!/bin/bash'."\n".'exit 1',
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should handle the execution failure gracefully
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_handles_invalid_json_output_from_phpstan(): void
    {
        // Create a temp directory with phpstan that returns invalid JSON
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => '#!/bin/bash'."\n".'echo "not json"',
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should handle invalid JSON gracefully
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    // =========================================================================
    // Basic Functionality Tests
    // =========================================================================

    public function test_detects_undefined_function_call(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test() {
        nonExistentFunction();
    }
}
PHP,
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                [
                    'file' => $filePath,
                    'line' => 6,
                    'message' => 'Function nonExistentFunction not found.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid function call detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('function does not exist', $issues[0]->recommendation);
        $this->assertStringContainsString('Check for typos', $issues[0]->recommendation);
    }

    public function test_detects_wrong_parameter_count(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test() {
        substr('hello'); // Missing required parameter
    }
}
PHP,
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                [
                    'file' => $filePath,
                    'line' => 6,
                    'message' => 'Function substr invoked with 1 parameter, 2-3 required.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid function call detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('parameters', $issues[0]->recommendation);
    }

    public function test_detects_wrong_parameter_type(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test() {
        strlen(123); // Expects string, given int
    }
}
PHP,
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                [
                    'file' => $filePath,
                    'line' => 6,
                    'message' => 'Parameter #1 $string of function strlen expects string, int given.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid function call detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('parameter types', $issues[0]->recommendation);
    }

    public function test_detects_void_function_return_usage(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function voidFunc(): void {
        echo "test";
    }

    public function test() {
        $result = $this->voidFunc(); // Void function return used
    }
}
PHP,
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                [
                    'file' => $filePath,
                    'line' => 10,
                    'message' => 'Result of function App\Example::voidFunc (void) is used.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid function call detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('returns void', $issues[0]->recommendation);
        $this->assertStringContainsString('cannot use its return value', $issues[0]->recommendation);
    }

    public function test_detects_multiple_invalid_function_calls(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test() {
        unknownFunc1();
        unknownFunc2();
        unknownFunc3();
    }
}
PHP,
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 6, 'message' => 'Function unknownFunc1 not found.'],
                ['file' => $filePath, 'line' => 7, 'message' => 'Function unknownFunc2 not found.'],
                ['file' => $filePath, 'line' => 8, 'message' => 'Function unknownFunc3 not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('3 invalid function call(s)', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    public function test_passes_when_no_invalid_function_calls(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test(): string {
        return strlen("test") > 0 ? "valid" : "empty";
    }
}
PHP,
        ]);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('No invalid function calls detected', $result->getMessage());
    }

    // =========================================================================
    // Pattern Matching Tests
    // =========================================================================

    public function test_matches_function_not_found_pattern(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Function someFunc not found in this context.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_matches_parameter_mismatch_pattern(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Parameter #1 of function test expects string, int given.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_matches_void_return_pattern(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Result of function test (void) is used.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    // =========================================================================
    // Recommendation Tests
    // =========================================================================

    public function test_recommendation_for_undefined_function(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Function customFunction not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('function does not exist', $issues[0]->recommendation);
        $this->assertStringContainsString('Check for typos', $issues[0]->recommendation);
        $this->assertStringContainsString('extension/library', $issues[0]->recommendation);
    }

    public function test_recommendation_for_parameter_mismatch(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Parameter #1 of function test expects string, int given.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('function parameters', $issues[0]->recommendation);
        $this->assertStringContainsString('do not match', $issues[0]->recommendation);
    }

    public function test_recommendation_for_void_return_usage(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Result of function test (void) is used.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('returns void', $issues[0]->recommendation);
        $this->assertStringContainsString('cannot use its return value', $issues[0]->recommendation);
    }

    // =========================================================================
    // Metadata Tests
    // =========================================================================

    public function test_metadata_includes_phpstan_message(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Function test not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertArrayHasKey('phpstan_message', $issues[0]->metadata);
        $this->assertSame('Function test not found.', $issues[0]->metadata['phpstan_message']);
    }

    public function test_metadata_includes_file_and_line(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 42, 'message' => 'Function test not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertArrayHasKey('file', $issues[0]->metadata);
        $this->assertArrayHasKey('line', $issues[0]->metadata);
        $this->assertSame($filePath, $issues[0]->metadata['file']);
        $this->assertSame(42, $issues[0]->metadata['line']);
    }

    // =========================================================================
    // Result Formatting Tests
    // =========================================================================

    public function test_formats_single_issue_message(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Function test not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertStringContainsString('1 invalid function call(s)', $result->getMessage());
    }

    public function test_formats_multiple_issues_message(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Function test1 not found.'],
                ['file' => $filePath, 'line' => 2, 'message' => 'Function test2 not found.'],
                ['file' => $filePath, 'line' => 3, 'message' => 'Function test3 not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertStringContainsString('3 invalid function call(s)', $result->getMessage());
    }

    public function test_limits_displayed_issues_to_50(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';

        // Create 75 issues
        $issues = [];
        for ($i = 1; $i <= 75; $i++) {
            $issues[] = ['file' => $filePath, 'line' => $i, 'message' => "Function test{$i} not found."];
        }

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript($issues)
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should show "Found 75 invalid function calls (showing first 50)"
        $this->assertStringContainsString('75 invalid function call(s)', $result->getMessage());
        $this->assertStringContainsString('showing first 50', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(50, $issues);
    }

    // =========================================================================
    // Edge Cases Tests
    // =========================================================================

    public function test_handles_empty_basepath(): void
    {
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath('');

        $result = $analyzer->analyze();

        // Should use base_path() as fallback and handle gracefully
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_handles_missing_app_directory(): void
    {
        $tempDir = $this->createTempDirectory([]);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should handle missing app directory gracefully
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_handles_unreadable_file_in_issue(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        // Reference a file that doesn't exist
        $nonExistentFile = $tempDir.'/app/NonExistent.php';

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $nonExistentFile, 'line' => 1, 'message' => 'Function test not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should handle missing file gracefully (no code snippet)
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

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
