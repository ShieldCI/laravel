<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\ForeachIterableAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ForeachIterableAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ForeachIterableAnalyzer;
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
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => '#!/bin/bash'."\n".'exit 1',
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should handle execution failure gracefully
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
    // Basic Functionality Tests
    // =========================================================================

    public function test_passes_with_no_foreach_issues(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ValidForeachService
{
    public function processArray(): void
    {
        $items = [1, 2, 3, 4, 5];
        foreach ($items as $item) {
            echo $item;
        }
    }

    public function processCollection(): void
    {
        $collection = collect([1, 2, 3]);
        foreach ($collection as $item) {
            echo $item;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ValidForeachService.php' => $code,
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('No invalid foreach usage detected', $result->getMessage());
    }

    public function test_detects_foreach_on_string(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 10,
                    'message' => 'Argument of an invalid type string supplied for foreach, only iterables are supported.',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('invalid foreach usage(s)', $result->getMessage());
        $this->assertHasIssueContaining('Invalid foreach usage detected', $result);
    }

    public function test_detects_foreach_on_integer(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 8,
                    'message' => 'Argument of an invalid type int supplied for foreach, only iterables are supported.',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid foreach usage detected', $result);
    }

    public function test_detects_foreach_on_null(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 9,
                    'message' => 'Argument of an invalid type null supplied for foreach, only iterables are supported.',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid foreach usage detected', $result);
    }

    public function test_detects_foreach_on_non_iterable_object(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 12,
                    'message' => 'Argument of an invalid type App\NonIterable supplied for foreach, only iterables are supported.',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid foreach usage detected', $result);
    }

    public function test_detects_foreach_on_boolean(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 7,
                    'message' => 'Argument of an invalid type bool supplied for foreach, only iterables are supported.',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid foreach usage detected', $result);
    }

    public function test_detects_multiple_foreach_issues_in_single_file(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 8,
                    'message' => 'Argument of an invalid type string supplied for foreach, only iterables are supported.',
                ],
                [
                    'file' => 'app/Example.php',
                    'line' => 14,
                    'message' => 'Argument of an invalid type int supplied for foreach, only iterables are supported.',
                ],
                [
                    'file' => 'app/Example.php',
                    'line' => 20,
                    'message' => 'Argument of an invalid type null supplied for foreach, only iterables are supported.',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
        $this->assertStringContainsString('3 invalid foreach usage(s)', $result->getMessage());
    }

    // =========================================================================
    // Pattern Matching Tests
    // =========================================================================

    public function test_detects_pattern_invalid_type_supplied(): void
    {
        // Pattern: "Argument of an invalid type * supplied for foreach*"
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 6,
                    'message' => 'Argument of an invalid type float supplied for foreach, only iterables are supported.',
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
        $this->assertStringContainsString('invalid type', $issues[0]->recommendation);
    }

    public function test_detects_pattern_cannot_use_in_foreach(): void
    {
        // Pattern: "Cannot use * in a foreach loop*"
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 7,
                    'message' => 'Cannot use stdClass in a foreach loop.',
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
        $this->assertStringContainsString('Cannot use', $issues[0]->recommendation);
    }

    public function test_detects_pattern_iterating_over_non_iterable(): void
    {
        // Pattern: "Iterating over * but * does not specify*"
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 10,
                    'message' => 'Iterating over mixed but it does not specify iterable.',
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
        $this->assertStringContainsString('does not specify', $issues[0]->recommendation);
    }

    // =========================================================================
    // Recommendation Tests
    // =========================================================================

    public function test_recommendation_for_invalid_type(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 5,
                    'message' => 'Argument of an invalid type string supplied for foreach.',
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

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('Fix the foreach loop', $recommendation);
        $this->assertStringContainsString('not of an iterable type', $recommendation);
        $this->assertStringContainsString('array, Traversable, or Iterator', $recommendation);
    }

    public function test_recommendation_for_cannot_use(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 6,
                    'message' => 'Cannot use object in a foreach loop.',
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

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('cannot be used in a foreach loop', $recommendation);
        $this->assertStringContainsString('implements Traversable or is an array', $recommendation);
    }

    public function test_recommendation_for_does_not_specify(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 8,
                    'message' => 'Iterating over mixed but it does not specify iterable.',
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

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('type does not specify that it is iterable', $recommendation);
        $this->assertStringContainsString('Add proper type hints', $recommendation);
    }

    // =========================================================================
    // Metadata Tests
    // =========================================================================

    public function test_metadata_includes_phpstan_message(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 5,
                    'message' => 'Argument of an invalid type string supplied for foreach.',
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
        $this->assertSame('Argument of an invalid type string supplied for foreach.', $issues[0]->metadata['phpstan_message']);
    }

    public function test_metadata_includes_file_location(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Services/TestService.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Services/TestService.php',
                    'line' => 10,
                    'message' => 'Argument of an invalid type int supplied for foreach.',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $issue = $issues[0];
        $this->assertNotNull($issue->location);
        $this->assertStringContainsString('TestService.php', $issue->location->file);
        $this->assertSame(10, $issue->location->line);
    }

    // =========================================================================
    // Result Formatting & Limiting Tests
    // =========================================================================

    public function test_limits_issues_to_50(): void
    {
        // Create 100 foreach issues
        $issues = [];
        for ($i = 1; $i <= 100; $i++) {
            $issues[] = [
                'file' => 'app/Example.php',
                'line' => $i,
                'message' => "Argument of an invalid type string supplied for foreach on line {$i}.",
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
        // Create 60 foreach issues
        $issues = [];
        for ($i = 1; $i <= 60; $i++) {
            $issues[] = [
                'file' => 'app/Example.php',
                'line' => $i,
                'message' => "Argument of an invalid type string supplied for foreach on line {$i}.",
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
        $this->assertStringContainsString('Found 60 invalid foreach usage(s) (showing first 50)', $result->getMessage());
    }

    public function test_pluralization_with_single_issue(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/Example.php',
                    'line' => 5,
                    'message' => 'Argument of an invalid type string supplied for foreach.',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 1 invalid foreach usage(s)', $result->getMessage());
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    public function test_handles_multiple_files_with_mixed_results(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/ValidService.php' => '<?php namespace App; class ValidService { }',
            'app/InvalidService.php' => '<?php namespace App; class InvalidService { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/InvalidService.php',
                    'line' => 8,
                    'message' => 'Argument of an invalid type string supplied for foreach.',
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
    }

    public function test_handles_multiple_issues_across_different_files(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/ServiceA.php' => '<?php namespace App; class ServiceA { }',
            'app/ServiceB.php' => '<?php namespace App; class ServiceB { }',
            'app/ServiceC.php' => '<?php namespace App; class ServiceC { }',
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([
                [
                    'file' => 'app/ServiceA.php',
                    'line' => 5,
                    'message' => 'Argument of an invalid type string supplied for foreach.',
                ],
                [
                    'file' => 'app/ServiceB.php',
                    'line' => 7,
                    'message' => 'Cannot use int in a foreach loop.',
                ],
                [
                    'file' => 'app/ServiceC.php',
                    'line' => 10,
                    'message' => 'Iterating over mixed but it does not specify iterable.',
                ],
            ]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    // =========================================================================
    // Edge Cases Tests
    // =========================================================================

    public function test_handles_empty_codebase(): void
    {
        $tempDir = $this->createTempDirectory([
            'vendor/bin/phpstan' => $this->createMockPHPStanScript([]),
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - no code to analyze
        $this->assertPassed($result);
    }

    public function test_handles_malformed_phpstan_result(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => '#!/bin/bash'."\n".'echo "malformed json {{"',
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should handle malformed JSON gracefully
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_handles_issues_with_missing_line_field(): void
    {
        // Create PHPStan output with issue missing 'line' field
        // PHPStanRunner will default line to 1 in this case
        $output = [
            'totals' => [
                'errors' => 0,
                'file_errors' => 1,
            ],
            'files' => [
                'app/Example.php' => [
                    'messages' => [
                        [
                            'message' => 'Argument of an invalid type string supplied for foreach.',
                            // Missing 'line' field - will default to 1
                            'ignorable' => true,
                        ],
                    ],
                ],
            ],
            'errors' => [],
        ];

        $json = json_encode($output, JSON_PRETTY_PRINT);

        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => <<<BASH
#!/bin/bash
cat <<'EOF'
{$json}
EOF
BASH,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should still report the issue with line defaulted to 1
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(1, $issues[0]->location->line);
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
