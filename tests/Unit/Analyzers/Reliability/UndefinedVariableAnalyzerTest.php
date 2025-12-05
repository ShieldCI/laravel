<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\Reliability\UndefinedVariableAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class UndefinedVariableAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new UndefinedVariableAnalyzer;
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
        $this->assertStringContainsString('composer install', $issues[0]->recommendation);
    }

    #[Test]
    public function test_passes_when_no_undefined_variables_detected(): void
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
        $this->assertStringContainsString('No undefined variables detected', $result->getMessage());
    }

    #[Test]
    public function test_detects_undefined_variable(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 10,
                'message' => 'Undefined variable: $user',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 1 undefined variable', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertEquals('Undefined variable detected', $issue->message);
        $this->assertEquals(Severity::High, $issue->severity);
        $this->assertEquals(10, $issue->location->line);
        $this->assertStringContainsString('Variable is used before being defined', $issue->recommendation);
    }

    #[Test]
    public function test_detects_variable_might_not_be_defined(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 15,
                'message' => 'Variable $result might not be defined',
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
        $this->assertStringContainsString('might not be defined in all code paths', $issue->recommendation);
        $this->assertStringContainsString('if/else branches', $issue->recommendation);
    }

    #[Test]
    public function test_detects_unnecessary_isset_check(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 20,
                'message' => 'Variable $data in isset() always exists and is not nullable',
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
        $this->assertStringContainsString('Remove unnecessary isset() check', $issue->recommendation);
        $this->assertStringContainsString('redundant', $issue->recommendation);
    }

    #[Test]
    public function test_detects_multiple_undefined_variables(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'app/Helper.php' => '<?php namespace App; class Helper { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 10,
                'message' => 'Undefined variable: $user',
            ],
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 15,
                'message' => 'Variable $result might not be defined',
            ],
            [
                'file' => $tempDir.'/app/Helper.php',
                'line' => 20,
                'message' => 'Undefined variable: $config',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 3 undefined variable', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    #[Test]
    public function test_recommendation_for_undefined_variable(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 10,
                'message' => 'Undefined variable: $username',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertStringContainsString('Variable is used before being defined', $issue->recommendation);
        $this->assertStringContainsString('Initialize the variable', $issue->recommendation);
        $this->assertStringContainsString('check for typos', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_might_not_be_defined(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 15,
                'message' => 'Variable $data might not be defined in all code paths',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertStringContainsString('might not be defined in all code paths', $issue->recommendation);
        $this->assertStringContainsString('initialized before use in all possible execution paths', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_unnecessary_isset(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 20,
                'message' => 'Variable $value in isset() always exists',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertStringContainsString('Remove unnecessary isset() check', $issue->recommendation);
        $this->assertStringContainsString('variable is guaranteed to exist', $issue->recommendation);
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
                'line' => 10,
                'message' => 'Undefined variable: $debugMode',
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
        $this->assertStringContainsString('debugMode', $metadata['phpstan_message']);
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
                'message' => "Undefined variable: \$var{$i}",
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
        $this->assertStringContainsString('Found 75 undefined variable(s) (showing first 50)', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(50, $issues);
    }

    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('undefined-variable', $metadata->id);
        $this->assertSame('Undefined Variable Usage Analyzer', $metadata->name);
        $this->assertSame(Severity::High, $metadata->severity);
        $this->assertSame(10, $metadata->timeToFix);
        $this->assertContains('phpstan', $metadata->tags);
        $this->assertContains('static-analysis', $metadata->tags);
        $this->assertContains('variables', $metadata->tags);
        $this->assertContains('type-safety', $metadata->tags);
    }

    #[Test]
    public function test_generic_recommendation_for_other_variable_error(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 10,
                'message' => 'Undefined variable: $someVar with additional context',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertStringContainsString('Variable is used before being defined', $issue->recommendation);
        $this->assertStringContainsString('PHPStan message:', $issue->recommendation);
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
