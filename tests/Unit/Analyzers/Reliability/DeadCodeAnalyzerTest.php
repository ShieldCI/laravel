<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\DeadCodeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class DeadCodeAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new DeadCodeAnalyzer;
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
        $this->assertStringContainsString('Install PHPStan', $issues[0]->recommendation);
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
    // Dead Code Detection Tests
    // =========================================================================

    public function test_detects_unreachable_statements(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test() {
        return true;
        $unreachable = 'this is never executed';
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
                    'line' => 7,
                    'message' => 'Unreachable statement - code above always terminates.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Dead code detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('Remove unreachable code', $issues[0]->recommendation);
    }

    public function test_detects_unused_variables(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test() {
        $unused = 'never used';
        return true;
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
                    'message' => 'Variable $unused is unused.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Dead code detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('Remove unused code', $issues[0]->recommendation);
    }

    public function test_detects_statements_with_no_effect(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test() {
        1 + 1;
        return true;
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
                    'message' => 'Expression "1 + 1" does not do anything.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Dead code detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('has no effect', $issues[0]->recommendation);
    }

    public function test_detects_always_true_conditions(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test() {
        if (true && true) {
            return 'always true';
        }
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
                    'message' => 'Result of && is always true.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Dead code detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('Remove redundant condition', $issues[0]->recommendation);
    }

    public function test_detects_dead_catch_blocks(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test() {
        try {
            return true;
        } catch (\InvalidArgumentException $e) {
            // This exception can never be thrown
        }
    }
}
PHP,
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 8,
                    'message' => 'Dead catch - InvalidArgumentException is never thrown in the try block.',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Dead code detected', $result);
    }

    // =========================================================================
    // Result Formatting & Limiting Tests
    // =========================================================================

    public function test_limits_issues_to_50(): void
    {
        // Create 100 dead code issues
        $issues = [];
        for ($i = 1; $i <= 100; $i++) {
            $issues[] = [
                'file' => 'app/Example.php',
                'line' => $i,
                'message' => "Unreachable statement on line {$i}",
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
        // Create 60 dead code issues
        $issues = [];
        for ($i = 1; $i <= 60; $i++) {
            $issues[] = [
                'file' => 'app/Example.php',
                'line' => $i,
                'message' => "Unreachable statement on line {$i}",
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
        $this->assertStringContainsString('Found 60 dead code issues (showing first 50)', $result->getMessage());
    }

    public function test_pluralization_with_single_issue(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 5,
                    'message' => 'Unreachable statement',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 1 dead code issue(s)', $result->getMessage());
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
                    'message' => 'Unreachable statement - code above always terminates.',
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
        $this->assertSame('Unreachable statement - code above always terminates.', $issues[0]->metadata['phpstan_message']);
    }

    public function test_passes_when_no_dead_code_found(): void
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
        $this->assertStringContainsString('No dead code detected', $result->getMessage());
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
