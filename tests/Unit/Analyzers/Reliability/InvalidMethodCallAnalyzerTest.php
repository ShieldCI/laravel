<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\Reliability\InvalidMethodCallAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class InvalidMethodCallAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new InvalidMethodCallAnalyzer;
    }

    // =========================================================================
    // PHPStan Availability & Error Handling Tests
    // =========================================================================

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
        $this->assertHasIssueContaining('PHPStan binary not found', $result);

        // Check recommendation mentions composer install
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('composer install', $issues[0]->recommendation);
        $this->assertStringNotContainsString('composer require', $issues[0]->recommendation);
    }

    #[Test]
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

    #[Test]
    public function test_passes_when_no_invalid_method_calls_detected(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([]);

        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('No invalid method calls detected', $result->getMessage());
        $this->assertIssueCount(0, $result);
    }

    // =========================================================================
    // Basic Functionality Tests
    // =========================================================================

    #[Test]
    public function test_detects_undefined_method_call(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Services/UserService.php',
                'line' => 42,
                'message' => 'Call to an undefined method App\Models\User::getName().',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => '<?php namespace App\Services; class UserService { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 1 invalid method call(s)', $result->getMessage());
        $this->assertIssueCount(1, $result);

        $issue = $result->getIssues()[0];
        $this->assertEquals(Severity::Critical, $issue->severity);
        $this->assertStringContainsString('Invalid method call detected', $issue->message);
        $this->assertEquals(42, $issue->location->line);
    }

    #[Test]
    public function test_detects_method_with_wrong_parameter_count(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Services/OrderService.php',
                'line' => 15,
                'message' => 'Method App\Services\OrderService::processOrder() invoked with 1 parameter, 2 required.',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderService.php' => '<?php namespace App\Services; class OrderService { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertEquals(Severity::Critical, $issue->severity);
        $this->assertEquals(15, $issue->location->line);
    }

    #[Test]
    public function test_detects_wrong_parameter_types(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Services/PaymentService.php',
                'line' => 28,
                'message' => 'Parameter #1 of method App\Services\PaymentService::charge() expects float, int given.',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Services/PaymentService.php' => '<?php namespace App\Services; class PaymentService { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertEquals(Severity::Critical, $issue->severity);
        $this->assertStringContainsString('Parameter', $issue->recommendation);
    }

    #[Test]
    public function test_detects_private_method_access_violation(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Controllers/UserController.php',
                'line' => 55,
                'message' => 'Call to private method validate() of parent class App\Controllers\BaseController.',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Controllers/UserController.php' => '<?php namespace App\Controllers; class UserController { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertEquals(Severity::Critical, $issue->severity);
        $this->assertStringContainsString('visibility', $issue->recommendation);
    }

    #[Test]
    public function test_detects_static_call_to_instance_method(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Helpers/StringHelper.php',
                'line' => 12,
                'message' => 'Static call to instance method App\Services\UserService::getUser().',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Helpers/StringHelper.php' => '<?php namespace App\Helpers; class StringHelper { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertEquals(Severity::Critical, $issue->severity);
    }

    #[Test]
    public function test_detects_void_method_return_usage(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Services/LogService.php',
                'line' => 33,
                'message' => 'Result of method App\Services\LogService::log() (void) is used.',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Services/LogService.php' => '<?php namespace App\Services; class LogService { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertEquals(Severity::Critical, $issue->severity);
    }

    #[Test]
    public function test_detects_multiple_invalid_method_calls(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Services/UserService.php',
                'line' => 10,
                'message' => 'Call to an undefined method App\Models\User::getName().',
            ],
            [
                'file' => 'app/Services/UserService.php',
                'line' => 15,
                'message' => 'Method App\Services\UserService::processUser() invoked with 1 parameter, 2 required.',
            ],
            [
                'file' => 'app/Controllers/UserController.php',
                'line' => 25,
                'message' => 'Call to private method validate() of class App\Controllers\BaseController.',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => '<?php namespace App\Services; class UserService { }',
            'app/Controllers/UserController.php' => '<?php namespace App\Controllers; class UserController { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Found 3 invalid method call(s)', $result->getMessage());
        $this->assertIssueCount(3, $result);
    }

    // =========================================================================
    // Pattern Matching Tests
    // =========================================================================

    #[Test]
    public function test_matches_undefined_method_pattern(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Call to an undefined method App\Test::foo().',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    #[Test]
    public function test_matches_parameter_mismatch_pattern(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Parameter #2 of method App\Test::bar() expects string, int given.',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    #[Test]
    public function test_matches_static_call_pattern(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Static call to instance method App\Test::instanceMethod().',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    // =========================================================================
    // Recommendation Tests
    // =========================================================================

    #[Test]
    public function test_recommendation_for_undefined_method(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Call to an undefined method App\Test::foo().',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('method does not exist', $issue->recommendation);
        $this->assertStringContainsString('Check for typos', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_parameter_mismatch(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Parameter #1 of method App\Test::bar() expects string, int given.',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('parameters', $issue->recommendation);
        $this->assertStringContainsString('parameter types', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_visibility_violation(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Call to private method validate() of class App\BaseClass.',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('visibility', $issue->recommendation);
        $this->assertStringContainsString('private/protected', $issue->recommendation);
    }

    // =========================================================================
    // Metadata Tests
    // =========================================================================

    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('invalid-method-calls', $metadata->id);
        $this->assertEquals('Invalid Method Calls Analyzer', $metadata->name);
        $this->assertEquals(Category::Reliability, $metadata->category);
        $this->assertEquals(Severity::Critical, $metadata->severity);
        $this->assertEquals(20, $metadata->timeToFix);
    }

    #[Test]
    public function test_has_correct_tags(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertContains('phpstan', $metadata->tags);
        $this->assertContains('static-analysis', $metadata->tags);
        $this->assertContains('methods', $metadata->tags);
        $this->assertContains('type-safety', $metadata->tags);
    }

    // =========================================================================
    // Result Formatting Tests
    // =========================================================================

    #[Test]
    public function test_formats_message_with_single_issue(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Call to an undefined method App\Test::foo().',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertStringContainsString('Found 1 invalid method call(s)', $result->getMessage());
        $this->assertStringNotContainsString('showing first', $result->getMessage());
    }

    #[Test]
    public function test_formats_message_with_multiple_issues(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Call to an undefined method App\Test::foo().',
            ],
            [
                'file' => 'app/Test.php',
                'line' => 2,
                'message' => 'Call to an undefined method App\Test::bar().',
            ],
            [
                'file' => 'app/Test.php',
                'line' => 3,
                'message' => 'Call to an undefined method App\Test::baz().',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertStringContainsString('Found 3 invalid method call(s)', $result->getMessage());
    }

    // =========================================================================
    // Edge Cases Tests
    // =========================================================================

    #[Test]
    public function test_handles_edge_case_with_empty_message(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => '',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Empty messages won't match any pattern, so should pass
        $this->assertPassed($result);
        $this->assertIssueCount(0, $result);
    }

    #[Test]
    public function test_handles_edge_case_with_zero_line_number(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 0,
                'message' => 'Call to an undefined method App\Test::foo().',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Test.php' => '<?php namespace App; class Test { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        // PHPStan treats line 0 as line 1 in the Location value object
        $this->assertEquals(1, $result->getIssues()[0]->location->line);
    }

    #[Test]
    public function test_handles_special_characters_in_file_path(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Services/User Service.php',
                'line' => 1,
                'message' => 'Call to an undefined method App\Test::foo().',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Services/User Service.php' => '<?php namespace App\Services; class UserService { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertStringContainsString('User Service.php', $result->getIssues()[0]->location->file);
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /**
     * Create a mock PHPStan script that returns predefined issues.
     *
     * @param  array<array{file: string, line: int, message: string}>  $issues
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
