<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\CodeQuality\ClassLengthAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class ClassLengthAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ClassLengthAnalyzer($this->parser);
    }

    #[Test]
    public function test_passes_with_reasonable_class_size(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    private $repository;

    public function getUser($id) { return User::find($id); }
    public function createUser($data) { return User::create($data); }
    public function updateUser($id, $data) { return User::update($id, $data); }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('within recommended size limits', $result->getMessage());
    }

    #[Test]
    public function test_detects_class_with_too_many_lines(): void
    {
        // Generate class with 350 lines (exceeds 300 limit)
        $lines = str_repeat("    // Comment line\n", 340);

        $code = <<<PHP
<?php

namespace App\Services;

class LargeClass
{
{$lines}
    public function method1() { return true; }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/LargeClass.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('too large', $result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertStringContainsString('lines (max: 300)', $issue->message);
        $this->assertGreaterThan(300, $issue->metadata['lines']);
    }

    #[Test]
    public function test_detects_class_with_too_many_methods(): void
    {
        $methods = '';
        for ($i = 1; $i <= 25; $i++) {
            $methods .= "    public function method{$i}() { return true; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Services;

class MethodHeavyClass
{
{$methods}}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/MethodHeavyClass.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('too large', $result);

        $issues = $result->getIssues();
        $issue = $issues[0];
        $this->assertStringContainsString('methods (max: 20)', $issue->message);
        $this->assertEquals(25, $issue->metadata['methods']);
    }

    #[Test]
    public function test_detects_class_with_too_many_properties(): void
    {
        $properties = '';
        for ($i = 1; $i <= 20; $i++) {
            $properties .= "    private \$property{$i};\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

class PropertyHeavyClass
{
{$properties}
    public function getData() { return []; }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/PropertyHeavyClass.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $issue = $issues[0];
        $this->assertStringContainsString('properties (max: 15)', $issue->message);
        $this->assertEquals(20, $issue->metadata['properties']);
    }

    #[Test]
    public function test_detects_god_object_with_all_violations(): void
    {
        // Create class exceeding all limits
        $methods = '';
        for ($i = 1; $i <= 25; $i++) {
            $methods .= "    public function method{$i}() {\n";
            $methods .= "        // Method body\n";
            $methods .= "        return true;\n";
            $methods .= "    }\n\n";
        }

        $properties = '';
        for ($i = 1; $i <= 20; $i++) {
            $properties .= "    private \$property{$i};\n";
        }

        // Add padding to exceed line limit
        $padding = str_repeat("    // Comment\n", 250);

        $code = <<<PHP
<?php

namespace App\Services;

class GodObject
{
{$properties}
{$padding}
{$methods}}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/GodObject.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $issue = $issues[0];

        // Should have all 3 violation types
        $violations = $issue->metadata['violations'];
        $this->assertIsArray($violations);
        $this->assertCount(3, $violations);
        $this->assertStringContainsString('lines', $issue->message);
        $this->assertStringContainsString('methods', $issue->message);
        $this->assertStringContainsString('properties', $issue->message);
    }

    #[Test]
    public function test_severity_is_low_for_minor_violations(): void
    {
        // 21 methods (barely over 20 limit)
        $methods = '';
        for ($i = 1; $i <= 21; $i++) {
            $methods .= "    public function method{$i}() { return true; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Services;

class SlightlyLargeClass
{
{$methods}}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/SlightlyLargeClass.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $issue = $issues[0];
        $this->assertEquals(Severity::Low, $issue->severity);
    }

    #[Test]
    public function test_severity_is_medium_for_moderate_violations(): void
    {
        // 31 methods (11 over limit) or 2 violations
        $methods = '';
        for ($i = 1; $i <= 31; $i++) {
            $methods .= "    public function method{$i}() { return true; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Services;

class ModerateClass
{
{$methods}}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ModerateClass.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $issue = $issues[0];
        $this->assertEquals(Severity::Medium, $issue->severity);
    }

    #[Test]
    public function test_severity_is_high_for_severe_violations(): void
    {
        // 40 methods (20 over limit = severe)
        $methods = '';
        for ($i = 1; $i <= 40; $i++) {
            $methods .= "    public function method{$i}() { return true; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Services;

class VeryLargeClass
{
{$methods}}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/VeryLargeClass.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $issue = $issues[0];
        $this->assertEquals(Severity::High, $issue->severity);
    }

    #[Test]
    public function test_handles_anonymous_classes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Container
{
    public function create()
    {
        return new class {
            public function method1() {}
            public function method2() {}
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Container.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Both classes are small, should pass
        $this->assertPassed($result);
    }

    #[Test]
    public function test_handles_multiple_classes_in_file(): void
    {
        $methods1 = str_repeat("    public function method() { return 1; }\n", 25);
        $methods2 = str_repeat("    public function method() { return 2; }\n", 10);

        $code = <<<PHP
<?php

namespace App\Services;

class FirstClass
{
{$methods1}}

class SecondClass
{
{$methods2}}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Multiple.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        // Only FirstClass should violate
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('FirstClass', $issues[0]->message);
    }

    #[Test]
    public function test_handles_empty_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

class EmptyModel
{
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/EmptyModel.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_counts_multiple_properties_in_single_declaration(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

class User
{
    private $id, $name, $email, $password;
    private $created_at, $updated_at;
    protected $first, $last, $middle;
    public $prop1, $prop2, $prop3, $prop4, $prop5, $prop6, $prop7;

    public function test() {}
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        // Should count 16 properties total (4+2+3+7=16)
        $issues = $result->getIssues();
        $issue = $issues[0];
        $this->assertEquals(16, $issue->metadata['properties']);
    }

    #[Test]
    public function test_includes_proper_metadata(): void
    {
        $methods = str_repeat("    public function method() { return true; }\n", 25);

        $code = <<<PHP
<?php

namespace App\Services;

class TestClass
{
{$methods}}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/TestClass.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $issue = $issues[0];
        $metadata = $issue->metadata;

        $this->assertArrayHasKey('class', $metadata);
        $this->assertArrayHasKey('lines', $metadata);
        $this->assertArrayHasKey('methods', $metadata);
        $this->assertArrayHasKey('properties', $metadata);
        $this->assertArrayHasKey('violations', $metadata);
        $this->assertArrayHasKey('file', $metadata);

        $this->assertEquals('TestClass', $metadata['class']);
        $this->assertEquals(25, $metadata['methods']);
        $this->assertIsArray($metadata['violations']);
    }

    #[Test]
    public function test_recommendation_includes_refactoring_strategies(): void
    {
        $methods = str_repeat("    public function method() { return true; }\n", 25);

        $code = <<<PHP
<?php

namespace App\Services;

class BigClass
{
{$methods}}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/BigClass.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $issue = $issues[0];

        $this->assertStringContainsString('Single Responsibility Principle', $issue->recommendation);
        $this->assertStringContainsString('Extract related methods', $issue->recommendation);
        $this->assertStringContainsString('Example:', $issue->recommendation);
        $this->assertStringContainsString('UserManager', $issue->recommendation);
        $this->assertStringContainsString('UserRepository', $issue->recommendation);
    }

    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('class-length', $metadata->id);
        $this->assertSame('Class Length', $metadata->name);
        $this->assertSame(Severity::Medium, $metadata->severity);
        $this->assertSame(45, $metadata->timeToFix);
        $this->assertContains('complexity', $metadata->tags);
        $this->assertContains('maintainability', $metadata->tags);
        $this->assertContains('god-object', $metadata->tags);
    }
}
