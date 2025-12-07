<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\InvalidImportAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class InvalidImportAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new InvalidImportAnalyzer;
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

    public function test_detects_invalid_class_import(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

use App\NonExistentClass;

class Example {
    public function test() {
        return new NonExistentClass();
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
                    'line' => 4,
                    'message' => 'Class App\NonExistentClass not found.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid import detected', $result);

        // Check recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('does not exist', $issues[0]->recommendation);
        $this->assertStringContainsString('composer dump-autoload', $issues[0]->recommendation);
    }

    public function test_detects_invalid_interface_import(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

use App\Contracts\NonExistentInterface;

class Example implements NonExistentInterface {
    // ...
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
                    'line' => 4,
                    'message' => 'Interface App\Contracts\NonExistentInterface not found.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid import detected', $result);

        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('does not exist', $issues[0]->recommendation);
    }

    public function test_detects_invalid_trait_import(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

use App\Traits\NonExistentTrait;

class Example {
    use NonExistentTrait;
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
                    'line' => 4,
                    'message' => 'Trait App\Traits\NonExistentTrait not found.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid import detected', $result);
    }

    public function test_detects_instantiated_class_not_found(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test() {
        return new \App\Services\MissingService();
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
                    'message' => 'Instantiated class App\Services\MissingService not found.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid import detected', $result);
    }

    public function test_detects_reflection_class_not_found(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

class Example {
    public function test() {
        $reflection = new \ReflectionClass('App\\NonExistent');
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
                    'message' => 'Reflection class App\NonExistent does not exist.',
                ],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Invalid import detected', $result);

        // Check reflection-specific recommendation
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('reflection', strtolower($issues[0]->recommendation));
    }

    public function test_detects_multiple_invalid_imports(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

use App\Missing1;
use App\Missing2;
use App\Missing3;

class Example {
    // ...
}
PHP,
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 4, 'message' => 'Class App\Missing1 not found.'],
                ['file' => $filePath, 'line' => 5, 'message' => 'Class App\Missing2 not found.'],
                ['file' => $filePath, 'line' => 6, 'message' => 'Class App\Missing3 not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('3 invalid import(s)', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    public function test_passes_when_no_invalid_imports(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => <<<'PHP'
<?php
namespace App;

use Illuminate\Support\Collection;

class Example {
    public function test(): Collection {
        return new Collection([1, 2, 3]);
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
        $this->assertStringContainsString('No invalid imports detected', $result->getMessage());
    }

    // =========================================================================
    // Pattern Matching Tests
    // =========================================================================

    public function test_matches_class_not_found_pattern(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Class App\SomeClass not found in this file.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_matches_interface_not_found_pattern(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Interface App\SomeInterface not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_matches_trait_not_found_pattern(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Trait App\SomeTrait not found.'],
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

    public function test_recommendation_for_class_not_found(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Class App\MissingClass not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('does not exist', $issues[0]->recommendation);
        $this->assertStringContainsString('Check for typos', $issues[0]->recommendation);
        $this->assertStringContainsString('composer dump-autoload', $issues[0]->recommendation);
    }

    public function test_recommendation_for_reflection_class(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Reflection class App\Missing does not exist.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('reflection', strtolower($issues[0]->recommendation));
        $this->assertStringContainsString('class name is correct', $issues[0]->recommendation);
    }

    public function test_recommendation_for_generic_import_error(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $filePath = $tempDir.'/app/Example.php';
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents(
            $tempDir.'/vendor/bin/phpstan',
            $this->createMockPHPStanScript([
                ['file' => $filePath, 'line' => 1, 'message' => 'Used App\SomeClass not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('does not exist', $issues[0]->recommendation);
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
                ['file' => $filePath, 'line' => 1, 'message' => 'Class App\Test not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertArrayHasKey('phpstan_message', $issues[0]->metadata);
        $this->assertSame('Class App\Test not found.', $issues[0]->metadata['phpstan_message']);
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
                ['file' => $filePath, 'line' => 42, 'message' => 'Class App\Test not found.'],
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
                ['file' => $filePath, 'line' => 1, 'message' => 'Class App\Test not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertStringContainsString('1 invalid import(s)', $result->getMessage());
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
                ['file' => $filePath, 'line' => 1, 'message' => 'Class App\Test1 not found.'],
                ['file' => $filePath, 'line' => 2, 'message' => 'Class App\Test2 not found.'],
                ['file' => $filePath, 'line' => 3, 'message' => 'Class App\Test3 not found.'],
            ])
        );

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertStringContainsString('3 invalid import(s)', $result->getMessage());
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
            $issues[] = ['file' => $filePath, 'line' => $i, 'message' => "Class App\Test{$i} not found."];
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

        // Should show "Found 75 invalid imports (showing first 50)"
        $this->assertStringContainsString('75 invalid import(s)', $result->getMessage());
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
                ['file' => $nonExistentFile, 'line' => 1, 'message' => 'Class App\Test not found.'],
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
        // Code should be null when file doesn't exist
        $this->assertNull($issues[0]->code);
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
