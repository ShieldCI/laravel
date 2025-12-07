<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\Reliability\MissingReturnStatementAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class MissingReturnStatementAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MissingReturnStatementAnalyzer;
    }

    #[Test]
    public function test_returns_warning_when_phpstan_not_installed(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertHasIssueContaining('PHPStan binary not found', $result);
        $this->assertStringContainsString('composer require', $issues[0]->recommendation);
    }

    #[Test]
    public function test_passes_when_no_missing_return_statements_detected(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('No missing return statements detected', $result->getMessage());
    }

    #[Test]
    public function test_detects_missing_return_in_method(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 15,
                'message' => 'Method App\\Example::getData() should return string but return statement is missing',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 1 missing return statement', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertEquals('Missing return statement detected', $issue->message);
        $this->assertEquals(Severity::High, $issue->severity);
        $this->assertEquals(15, $issue->location->line);
        $this->assertStringContainsString('Add a return statement to the method', $issue->recommendation);
    }

    #[Test]
    public function test_detects_missing_return_in_function(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/helpers.php' => '<?php',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/helpers.php',
                'line' => 10,
                'message' => 'Function processData() should return array but return statement is missing',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertStringContainsString('Add a return statement to the function', $issue->recommendation);
    }

    #[Test]
    public function test_detects_generic_missing_return(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 20,
                'message' => 'A return statement is missing',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertStringContainsString('Add missing return statement', $issue->recommendation);
        $this->assertStringContainsString('if/else branches', $issue->recommendation);
    }

    #[Test]
    public function test_detects_multiple_missing_returns(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'app/Helper.php' => '<?php namespace App; class Helper { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 15,
                'message' => 'Method App\\Example::getData() should return string but return statement is missing',
            ],
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 25,
                'message' => 'Method App\\Example::process() should return int but return statement is missing',
            ],
            [
                'file' => $tempDir.'/app/Helper.php',
                'line' => 10,
                'message' => 'Function transform() should return array but return statement is missing',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 3 missing return statement', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    #[Test]
    public function test_recommendation_for_method_return(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 15,
                'message' => 'Method App\\Example::getData() should return string but return statement is missing',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertStringContainsString('Add a return statement to the method', $issue->recommendation);
        $this->assertStringContainsString('return type to void', $issue->recommendation);
        $this->assertStringContainsString('should return string', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_function_return(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/helpers.php' => '<?php',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/helpers.php',
                'line' => 10,
                'message' => 'Function processData() should return array but return statement is missing',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertStringContainsString('Add a return statement to the function', $issue->recommendation);
        $this->assertStringContainsString('every possible execution path', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_generic_missing_return(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 20,
                'message' => 'A return statement is missing',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertStringContainsString('Add missing return statement', $issue->recommendation);
        $this->assertStringContainsString('switch cases', $issue->recommendation);
        $this->assertStringContainsString('exception handling', $issue->recommendation);
    }

    #[Test]
    public function test_includes_phpstan_message_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 15,
                'message' => 'Method App\\Example::getData() should return string but return statement is missing',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];
        $metadata = $issue->metadata;

        $this->assertArrayHasKey('phpstan_message', $metadata);
        $this->assertIsString($metadata['phpstan_message']);
        $this->assertStringContainsString('should return string', $metadata['phpstan_message']);
    }

    #[Test]
    public function test_limits_displayed_issues_to_50(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        // Create 75 issues
        $issues = [];
        for ($i = 1; $i <= 75; $i++) {
            $issues[] = [
                'file' => $tempDir.'/app/Example.php',
                'line' => $i,
                'message' => "Method App\\Example::method{$i}() should return string but return statement is missing",
            ];
        }

        $script = $this->createMockPHPStanScript($issues);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 75 missing return statement(s) (showing first 50)', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(50, $issues);
    }

    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('missing-return-statement', $metadata->id);
        $this->assertSame('Missing Return Statements Analyzer', $metadata->name);
        $this->assertSame(Severity::High, $metadata->severity);
        $this->assertSame(10, $metadata->timeToFix);
        $this->assertContains('phpstan', $metadata->tags);
        $this->assertContains('static-analysis', $metadata->tags);
        $this->assertContains('return-types', $metadata->tags);
        $this->assertContains('type-safety', $metadata->tags);
    }

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
            'totals' => ['errors' => 0, 'file_errors' => count($issues)],
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
