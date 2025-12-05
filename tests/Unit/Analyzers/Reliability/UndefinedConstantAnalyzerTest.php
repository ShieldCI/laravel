<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\Reliability\UndefinedConstantAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class UndefinedConstantAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new UndefinedConstantAnalyzer;
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
    public function test_passes_when_no_undefined_constants_detected(): void
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
        $this->assertStringContainsString('No undefined constants detected', $result->getMessage());
    }

    #[Test]
    public function test_detects_undefined_global_constant(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 10,
                'message' => 'Call to undefined constant UNDEFINED_CONSTANT',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 1 undefined constant', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertEquals('Undefined constant detected', $issue->message);
        $this->assertEquals(Severity::High, $issue->severity);
        $this->assertEquals(10, $issue->location->line);
        $this->assertStringContainsString('Constant is not defined', $issue->recommendation);
    }

    #[Test]
    public function test_detects_class_constant_used_outside_scope(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 15,
                'message' => 'Using self::MY_CONSTANT outside of class scope is not allowed',
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
        $this->assertStringContainsString('outside of its scope', $issue->recommendation);
        $this->assertStringContainsString('fully qualified class name', $issue->recommendation);
    }

    #[Test]
    public function test_detects_constant_on_unknown_class(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 20,
                'message' => 'Access to constant STATUS on an unknown class App\\NonExistent',
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
        $this->assertStringContainsString('class that does not exist', $issue->recommendation);
        $this->assertStringContainsString('imported/autoloaded', $issue->recommendation);
    }

    #[Test]
    public function test_detects_constant_does_not_exist(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 25,
                'message' => 'Constant App\\Example::MISSING does not exist',
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
        $this->assertStringContainsString('does not exist on the specified class', $issue->recommendation);
    }

    #[Test]
    public function test_detects_class_constant_not_found(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 30,
                'message' => 'Class constant App\\User::ADMIN_ROLE not found',
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
        $this->assertStringContainsString('does not exist on the specified class', $issue->recommendation);
        $this->assertStringContainsString('not found', $issue->recommendation);
    }

    #[Test]
    public function test_detects_multiple_undefined_constants(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'app/Helper.php' => '<?php namespace App; class Helper { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 10,
                'message' => 'Call to undefined constant DEBUG',
            ],
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 15,
                'message' => 'Using self::VERSION outside of class scope is not allowed',
            ],
            [
                'file' => $tempDir.'/app/Helper.php',
                'line' => 20,
                'message' => 'Access to constant STATUS on an unknown class App\\Config',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 3 undefined constant', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    #[Test]
    public function test_recommendation_for_undefined_constant(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 10,
                'message' => 'Call to undefined constant APP_VERSION',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertStringContainsString('Constant is not defined', $issue->recommendation);
        $this->assertStringContainsString('typos in the constant name', $issue->recommendation);
        $this->assertStringContainsString('define() function', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_outside_scope(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 15,
                'message' => 'Using self::CONSTANT outside of class scope is not allowed',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertStringContainsString('outside of its scope', $issue->recommendation);
        $this->assertStringContainsString('ClassName::CONSTANT_NAME', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_unknown_class(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Example.php',
                'line' => 20,
                'message' => 'Access to constant CONFIG on an unknown class App\\Settings',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertStringContainsString('class that does not exist', $issue->recommendation);
        $this->assertStringContainsString('class name is correct', $issue->recommendation);
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
                'message' => 'Call to undefined constant DEBUG_MODE',
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
        $this->assertStringContainsString('DEBUG_MODE', $metadata['phpstan_message']);
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
                'message' => "Call to undefined constant CONST_{$i}",
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
        $this->assertStringContainsString('Found 75 undefined constant(s) (showing first 50)', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(50, $issues);
    }

    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('undefined-constant', $metadata->id);
        $this->assertSame('Undefined Constant Usage Analyzer', $metadata->name);
        $this->assertSame(Severity::High, $metadata->severity);
        $this->assertSame(10, $metadata->timeToFix);
        $this->assertContains('phpstan', $metadata->tags);
        $this->assertContains('static-analysis', $metadata->tags);
        $this->assertContains('constants', $metadata->tags);
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
