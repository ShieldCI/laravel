<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\Reliability\MissingModelRelationAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class MissingModelRelationAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MissingModelRelationAnalyzer;
    }

    #[Test]
    public function test_returns_warning_when_phpstan_not_installed(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; class User { }',
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
    public function test_passes_when_no_missing_relations_detected(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; class User { }',
        ]);

        $script = $this->createMockPHPStanScript([]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('No missing model relations detected', $result->getMessage());
    }

    #[Test]
    public function test_detects_relation_not_found_in_model(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; class User { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Models/User.php',
                'line' => 15,
                'message' => 'Relation posts is not found in App\\Models\\User model',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 1 missing model relation', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertEquals('Missing or invalid model relation detected', $issue->message);
        $this->assertEquals(Severity::High, $issue->severity);
        $this->assertEquals(15, $issue->location->line);
        $this->assertStringContainsString('Define the missing relation method', $issue->recommendation);
        $this->assertStringContainsString('posts is not found', $issue->recommendation);
    }

    #[Test]
    public function test_detects_undefined_method_on_model(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; class User { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Models/User.php',
                'line' => 20,
                'message' => 'Call to an undefined method App\\Models\\User::comments (relation)',
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
        $this->assertStringContainsString('relation method does not exist', $issue->recommendation);
        $this->assertStringContainsString('hasMany, belongsTo', $issue->recommendation);
    }

    #[Test]
    public function test_detects_undefined_property_on_model(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => '<?php namespace App\\Models; class Post { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Models/Post.php',
                'line' => 25,
                'message' => 'Access to an undefined property App\\Models\\Post::$author (relation)',
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
        $this->assertStringContainsString('dynamic relation property', $issue->recommendation);
        $this->assertStringContainsString('relation method exists', $issue->recommendation);
    }

    #[Test]
    public function test_detects_multiple_missing_relations(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; class User { }',
            'app/Models/Post.php' => '<?php namespace App\\Models; class Post { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Models/User.php',
                'line' => 15,
                'message' => 'Relation posts is not found in App\\Models\\User model',
            ],
            [
                'file' => $tempDir.'/app/Models/User.php',
                'line' => 20,
                'message' => 'Relation comments is not found in App\\Models\\User model',
            ],
            [
                'file' => $tempDir.'/app/Models/Post.php',
                'line' => 10,
                'message' => 'Relation author is not found in App\\Models\\Post model',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 3 missing model relation', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    #[Test]
    public function test_recommendation_for_relation_not_found(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; class User { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Models/User.php',
                'line' => 15,
                'message' => 'Relation posts is not found in App\\Models\\User model',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertStringContainsString('Define the missing relation method', $issue->recommendation);
        $this->assertStringContainsString('typo in the relation name', $issue->recommendation);
        $this->assertStringContainsString('missing relationship method', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_undefined_method(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; class User { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Models/User.php',
                'line' => 20,
                'message' => 'Call to an undefined method App\\Models\\User::comments (relation)',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertStringContainsString('relation method does not exist', $issue->recommendation);
        $this->assertStringContainsString('define the relationship method', $issue->recommendation);
        $this->assertStringContainsString('fix the typo', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_undefined_property(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => '<?php namespace App\\Models; class Post { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Models/Post.php',
                'line' => 25,
                'message' => 'Access to an undefined property App\\Models\\Post::$author (relation)',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertStringContainsString('undefined property', $issue->recommendation);
        $this->assertStringContainsString('dynamic relation property', $issue->recommendation);
        $this->assertStringContainsString('relation method exists', $issue->recommendation);
    }

    #[Test]
    public function test_includes_phpstan_message_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; class User { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Models/User.php',
                'line' => 15,
                'message' => 'Relation posts is not found in App\\Models\\User model',
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
        $this->assertStringContainsString('Relation posts is not found', $metadata['phpstan_message']);
    }

    #[Test]
    public function test_limits_displayed_issues_to_50(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; class User { }',
        ]);

        // Create 75 issues
        $issues = [];
        for ($i = 1; $i <= 75; $i++) {
            $issues[] = [
                'file' => $tempDir.'/app/Models/User.php',
                'line' => $i,
                'message' => "Relation relation{$i} is not found in App\\Models\\User model",
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
        $this->assertStringContainsString('Found 75 missing model relation(s) (showing first 50)', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(50, $issues);
    }

    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('missing-model-relation', $metadata->id);
        $this->assertSame('Missing Model Relations', $metadata->name);
        $this->assertSame(Severity::High, $metadata->severity);
        $this->assertSame(20, $metadata->timeToFix);
        $this->assertContains('phpstan', $metadata->tags);
        $this->assertContains('eloquent', $metadata->tags);
        $this->assertContains('relations', $metadata->tags);
        $this->assertContains('models', $metadata->tags);
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
