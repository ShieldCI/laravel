<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\Reliability\InvalidOffsetAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class InvalidOffsetAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new InvalidOffsetAnalyzer;
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
        $this->assertStringNotContainsString('composer require', $issues[0]->recommendation);
    }

    #[Test]
    public function test_passes_when_no_invalid_offsets_detected(): void
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
        $this->assertStringContainsString('No invalid offset access detected', $result->getMessage());
    }

    #[Test]
    public function test_detects_access_to_non_existent_offset(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/UserService.php' => '<?php namespace App; class UserService { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/UserService.php',
                'line' => 10,
                'message' => 'Offset \'email\' does not exist on array{name: string}',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 1 invalid offset access', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertEquals('Invalid offset access detected', $issue->message);
        $this->assertEquals(Severity::High, $issue->severity);
        $this->assertEquals(10, $issue->location->line);
        $this->assertStringContainsString('does not exist', $issue->recommendation);
    }

    #[Test]
    public function test_detects_offset_might_not_exist(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/OrderProcessor.php' => '<?php namespace App; class OrderProcessor { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/OrderProcessor.php',
                'line' => 25,
                'message' => 'Offset \'total\' might not exist on array',
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
        $this->assertStringContainsString('might not exist', $issue = $issues[0]->recommendation);
        $this->assertStringContainsString('isset()', $issues[0]->recommendation);
    }

    #[Test]
    public function test_detects_cannot_access_offset_on_non_array(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/DataService.php' => '<?php namespace App; class DataService { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/DataService.php',
                'line' => 15,
                'message' => 'Cannot access offset \'id\' on string',
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
        $this->assertStringContainsString('cannot use array offset syntax', $issues[0]->recommendation);
        $this->assertStringContainsString('ArrayAccess', $issues[0]->recommendation);
    }

    #[Test]
    public function test_detects_cannot_assign_offset(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/ConfigManager.php' => '<?php namespace App; class ConfigManager { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/ConfigManager.php',
                'line' => 30,
                'message' => 'Cannot assign string offset \'key\' to stdClass',
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
        $this->assertStringContainsString('array offset syntax', $issues[0]->recommendation);
    }

    #[Test]
    public function test_detects_offset_does_not_accept_type(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/ArrayHandler.php' => '<?php namespace App; class ArrayHandler { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/ArrayHandler.php',
                'line' => 20,
                'message' => 'Offset int on ArrayAccess does not accept type string',
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
        $this->assertStringContainsString('offset type', $issues[0]->recommendation);
        $this->assertStringContainsString('does not match', $issues[0]->recommendation);
    }

    #[Test]
    public function test_detects_cannot_unset_offset(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/CacheManager.php' => '<?php namespace App; class CacheManager { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/CacheManager.php',
                'line' => 40,
                'message' => 'Cannot unset offset \'cache_key\' on string',
            ],
        ]);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
    }

    #[Test]
    public function test_detects_multiple_invalid_offsets(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/MultiIssue.php' => '<?php namespace App; class MultiIssue { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/MultiIssue.php',
                'line' => 10,
                'message' => 'Offset \'name\' does not exist on array',
            ],
            [
                'file' => $tempDir.'/app/MultiIssue.php',
                'line' => 20,
                'message' => 'Cannot access offset \'id\' on string',
            ],
            [
                'file' => $tempDir.'/app/MultiIssue.php',
                'line' => 30,
                'message' => 'Offset int on ArrayAccess does not accept type string',
            ],
        ]);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 3 invalid offset access', $result->getMessage());
        $this->assertCount(3, $result->getIssues());
    }

    #[Test]
    public function test_matches_cannot_assign_offset_pattern(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Test.php',
                'line' => 5,
                'message' => 'Cannot assign int offset 0 to string',
            ],
        ]);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
    }

    #[Test]
    public function test_matches_offset_does_not_exist_pattern(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Test.php',
                'line' => 5,
                'message' => 'Offset \'key\' does not exist on array{id: int}',
            ],
        ]);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
    }

    #[Test]
    public function test_matches_offset_might_not_exist_pattern(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Test.php',
                'line' => 5,
                'message' => 'Offset \'optional\' might not exist on array',
            ],
        ]);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
    }

    #[Test]
    public function test_recommendation_for_non_existent_offset(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Test.php',
                'line' => 5,
                'message' => 'Offset \'email\' does not exist on array{name: string}',
            ],
        ]);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('Check if the offset exists', $issue->recommendation);
        $this->assertStringContainsString('isset()', $issue->recommendation);
        $this->assertStringContainsString('??', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_cannot_access_offset(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Test.php',
                'line' => 5,
                'message' => 'Cannot access offset int on string',
            ],
        ]);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('array offset syntax', $issue->recommendation);
        $this->assertStringContainsString('ArrayAccess', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_type_mismatch(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Test.php',
                'line' => 5,
                'message' => 'Offset int on ArrayAccess does not accept type string',
            ],
        ]);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('offset type', $issue->recommendation);
        $this->assertStringContainsString('does not match', $issue->recommendation);
    }

    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('invalid-offset-access', $metadata->id);
        $this->assertEquals('Invalid Offset Access', $metadata->name);
        $this->assertEquals(Category::Reliability, $metadata->category);
        $this->assertEquals(Severity::High, $metadata->severity);
        $this->assertStringContainsString('PHPStan', $metadata->description);
        $this->assertEquals(15, $metadata->timeToFix);
    }

    #[Test]
    public function test_has_correct_tags(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertContains('phpstan', $metadata->tags);
        $this->assertContains('static-analysis', $metadata->tags);
        $this->assertContains('arrays', $metadata->tags);
        $this->assertContains('type-safety', $metadata->tags);
    }

    #[Test]
    public function test_formats_message_with_single_issue(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Test.php',
                'line' => 5,
                'message' => 'Offset \'key\' does not exist on array',
            ],
        ]);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertStringContainsString('Found 1 invalid offset access', $result->getMessage());
        $this->assertStringNotContainsString('showing first', $result->getMessage());
    }

    #[Test]
    public function test_formats_message_with_multiple_issues(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $issues = [];
        for ($i = 1; $i <= 5; $i++) {
            $issues[] = [
                'file' => $tempDir.'/app/Test.php',
                'line' => $i * 10,
                'message' => "Offset 'key{$i}' does not exist on array",
            ];
        }

        $script = $this->createMockPHPStanScript($issues);

        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertStringContainsString('Found 5 invalid offset access', $result->getMessage());
    }

    /**
     * Create a mock PHPStan script that returns predefined issues.
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
