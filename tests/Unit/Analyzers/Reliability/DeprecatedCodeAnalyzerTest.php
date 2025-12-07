<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\DeprecatedCodeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class DeprecatedCodeAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new DeprecatedCodeAnalyzer;
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

        // Check recommendation contains install instructions
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('PHPStan is included with ShieldCI', $issues[0]->recommendation);
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

    public function test_handles_empty_basepath(): void
    {
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath('');

        $result = $analyzer->analyze();

        // Should use base_path() as fallback and handle gracefully
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    // =========================================================================
    // Deprecated Code Detection Tests
    // =========================================================================

    public function test_detects_deprecated_method_usage(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test() {
        $this->oldMethod();
    }

    /** @deprecated Use newMethod() instead */
    private function oldMethod() {}
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
                    'message' => 'Call to deprecated method oldMethod() of class App\Example.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Deprecated code usage detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('Replace deprecated method', $issues[0]->recommendation);
    }

    public function test_detects_deprecated_class_usage(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

/** @deprecated Use NewClass instead */
class OldClass {}

class Example {
    public function test() {
        return new OldClass();
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
                    'line' => 9,
                    'message' => 'Instantiation of deprecated class App\OldClass.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Deprecated code usage detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('Replace deprecated class/interface', $issues[0]->recommendation);
    }

    public function test_detects_deprecated_function_usage(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

/** @deprecated Use newFunction() instead */
function oldFunction() {
    return true;
}

class Example {
    public function test() {
        return oldFunction();
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
                    'line' => 11,
                    'message' => 'Call to deprecated function App\oldFunction().',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Deprecated code usage detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('Replace deprecated function', $issues[0]->recommendation);
    }

    public function test_detects_deprecated_constant_usage(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    /** @deprecated Use NEW_CONSTANT instead */
    const OLD_CONSTANT = 'old';

    public function test() {
        return self::OLD_CONSTANT;
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
                    'line' => 9,
                    'message' => 'Access to deprecated constant OLD_CONSTANT.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Deprecated code usage detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('Replace deprecated constant', $issues[0]->recommendation);
    }

    public function test_detects_deprecated_property_access(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    /** @deprecated Use $newProperty instead */
    public $oldProperty = 'old';

    public function test() {
        return $this->oldProperty;
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
                    'line' => 9,
                    'message' => 'Access to deprecated property $oldProperty.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Deprecated code usage detected', $result);
    }

    // =========================================================================
    // Result Formatting & Limiting Tests
    // =========================================================================

    public function test_limits_issues_to_50(): void
    {
        // Create 100 deprecated code issues
        $issues = [];
        for ($i = 1; $i <= 100; $i++) {
            $issues[] = [
                'file' => 'app/Example.php',
                'line' => $i,
                'message' => "Call to deprecated method on line {$i}",
            ];
        }

        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript($issues),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $resultIssues = $result->getIssues();
        $this->assertCount(50, $resultIssues);
    }

    public function test_shows_total_count_when_truncated(): void
    {
        // Create 60 deprecated code issues
        $issues = [];
        for ($i = 1; $i <= 60; $i++) {
            $issues[] = [
                'file' => 'app/Example.php',
                'line' => $i,
                'message' => "Call to deprecated method on line {$i}",
            ];
        }

        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript($issues),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 60 deprecated code usage(s) (showing first 50)', $result->getMessage());
    }

    public function test_pluralization_with_single_usage(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 5,
                    'message' => 'Call to deprecated method',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 1 deprecated code usage(s)', $result->getMessage());
    }

    // =========================================================================
    // Metadata Validation Tests
    // =========================================================================

    public function test_includes_phpstan_message_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 5,
                    'message' => 'Call to deprecated method oldMethod() of class App\Example.',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertArrayHasKey('phpstan_message', $issues[0]->metadata);
        $this->assertArrayHasKey('file', $issues[0]->metadata);
        $this->assertArrayHasKey('line', $issues[0]->metadata);
        $this->assertSame('Call to deprecated method oldMethod() of class App\Example.', $issues[0]->metadata['phpstan_message']);
    }

    public function test_passes_when_no_deprecated_code_found(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('No deprecated code usage detected', $result->getMessage());
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /**
     * Create a mock PHPStan script that returns specified issues.
     *
     * @param  array<int, array{file: string, line: int, message: string}>  $issues
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
