<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\Reliability\InvalidPropertyAccessAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class InvalidPropertyAccessAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new InvalidPropertyAccessAnalyzer;
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
    public function test_passes_when_no_invalid_property_access_detected(): void
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
        $this->assertStringContainsString('No invalid property access detected', $result->getMessage());
    }

    #[Test]
    public function test_detects_access_to_undefined_property(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/User.php' => '<?php namespace App; class User { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/User.php',
                'line' => 10,
                'message' => 'Access to an undefined property App\User::$email',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 1 invalid property access', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertEquals('Invalid property access detected', $issue->message);
        $this->assertEquals(Severity::High, $issue->severity);
        $this->assertEquals(10, $issue->location->line);
        $this->assertStringContainsString('undefined property', $issue->recommendation);
    }

    #[Test]
    public function test_detects_access_to_private_property(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/UserService.php' => '<?php namespace App; class UserService { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/UserService.php',
                'line' => 25,
                'message' => 'Access to private property App\User::$password',
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
        $this->assertStringContainsString('private/protected property', $issues[0]->recommendation);
        $this->assertStringContainsString('visibility', $issues[0]->recommendation);
    }

    #[Test]
    public function test_detects_access_to_protected_property(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Controller.php' => '<?php namespace App; class Controller { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Controller.php',
                'line' => 15,
                'message' => 'Access to protected property App\BaseController::$middleware',
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
        $this->assertStringContainsString('protected', $issues[0]->recommendation);
    }

    #[Test]
    public function test_detects_property_access_on_non_object(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Service.php' => '<?php namespace App; class Service { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Service.php',
                'line' => 30,
                'message' => 'Cannot access property $name on string',
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
        $this->assertStringContainsString('cannot access properties', $issues[0]->recommendation);
    }

    #[Test]
    public function test_detects_property_type_mismatch(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Model.php' => '<?php namespace App; class Model { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Model.php',
                'line' => 20,
                'message' => 'Property App\Model::$age (int) does not accept string',
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
        $this->assertStringContainsString('does not match', $issues[0]->recommendation);
        $this->assertStringContainsString('property type', $issues[0]->recommendation);
    }

    #[Test]
    public function test_detects_static_property_access_issue(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Config.php' => '<?php namespace App; class Config { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Config.php',
                'line' => 12,
                'message' => 'Static property App\Config::$settings does not exist',
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
    public function test_detects_property_not_readable(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Entity.php' => '<?php namespace App; class Entity { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Entity.php',
                'line' => 18,
                'message' => 'Property App\Entity::$data in isset() is not readable',
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
        $this->assertStringContainsString('not readable', $issues[0]->recommendation);
    }

    #[Test]
    public function test_detects_property_not_writable(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/ReadOnly.php' => '<?php namespace App; class ReadOnly { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/ReadOnly.php',
                'line' => 8,
                'message' => 'Property App\ReadOnly::$value in assign is not writable',
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
        $this->assertStringContainsString('not writable', $issues[0]->recommendation);
    }

    #[Test]
    public function test_detects_multiple_invalid_property_accesses(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/MultiIssue.php' => '<?php namespace App; class MultiIssue { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/MultiIssue.php',
                'line' => 10,
                'message' => 'Access to an undefined property App\MultiIssue::$name',
            ],
            [
                'file' => $tempDir.'/app/MultiIssue.php',
                'line' => 20,
                'message' => 'Access to private property App\MultiIssue::$id',
            ],
            [
                'file' => $tempDir.'/app/MultiIssue.php',
                'line' => 30,
                'message' => 'Cannot access property $email on null',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 3 invalid property access', $result->getMessage());
        $this->assertCount(3, $result->getIssues());
    }

    #[Test]
    public function test_matches_access_to_property_pattern(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Test.php',
                'line' => 5,
                'message' => 'Access to private property App\Test::$secret',
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
    public function test_matches_cannot_access_property_pattern(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Test.php',
                'line' => 5,
                'message' => 'Cannot access property $foo on array',
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
    public function test_matches_undefined_property_pattern(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Test.php',
                'line' => 5,
                'message' => 'Access to undefined property App\Test::$missing',
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
    public function test_recommendation_for_undefined_property(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Test.php',
                'line' => 5,
                'message' => 'Access to an undefined property App\Test::$nonExistent',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('does not exist', $issue->recommendation);
        $this->assertStringContainsString('typos', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_visibility_violation(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
        ]);

        $script = $this->createMockPHPStanScript([
            [
                'file' => $tempDir.'/app/Test.php',
                'line' => 5,
                'message' => 'Access to private property App\User::$secret',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('visibility', $issue->recommendation);
        $this->assertStringContainsString('getter', $issue->recommendation);
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
                'message' => 'Property App\Test::$count (int) does not accept string',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('does not match', $issue->recommendation);
        $this->assertStringContainsString('correct type', $issue->recommendation);
    }

    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('invalid-property-access', $metadata->id);
        $this->assertEquals('Invalid Property Access', $metadata->name);
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
        $this->assertContains('properties', $metadata->tags);
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
                'message' => 'Access to undefined property App\Test::$foo',
            ],
        ]);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertStringContainsString('Found 1 invalid property access', $result->getMessage());
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
                'message' => "Access to undefined property App\Test::\$prop{$i}",
            ];
        }

        $script = $this->createMockPHPStanScript($issues);
        @mkdir($tempDir.'/vendor/bin', 0755, true);
        file_put_contents($tempDir.'/vendor/bin/phpstan', $script);
        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertStringContainsString('Found 5 invalid property access', $result->getMessage());
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
