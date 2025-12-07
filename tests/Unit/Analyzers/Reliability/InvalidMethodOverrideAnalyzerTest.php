<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\Reliability\InvalidMethodOverrideAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class InvalidMethodOverrideAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new InvalidMethodOverrideAnalyzer;
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
    public function test_passes_when_no_invalid_method_overrides_detected(): void
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
        $this->assertStringContainsString('No invalid method overrides detected', $result->getMessage());
        $this->assertIssueCount(0, $result);
    }

    // =========================================================================
    // Basic Functionality Tests
    // =========================================================================

    #[Test]
    public function test_detects_non_covariant_return_type(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Services/UserService.php',
                'line' => 42,
                'message' => 'Return type App\User of method App\Services\UserService::getUser() is not covariant with return type App\Models\User of method App\Services\BaseService::getUser().',
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
        $this->assertStringContainsString('Found 1 invalid method override(s)', $result->getMessage());
        $this->assertIssueCount(1, $result);

        $issue = $result->getIssues()[0];
        $this->assertEquals(Severity::High, $issue->severity);
        $this->assertStringContainsString('Invalid method override detected', $issue->message);
        $this->assertEquals(42, $issue->location->line);
    }

    #[Test]
    public function test_detects_non_contravariant_parameter_type(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Controllers/UserController.php',
                'line' => 15,
                'message' => 'Parameter #1 $user of method App\Controllers\UserController::store() is not contravariant with parameter #1 $user of method App\Controllers\BaseController::store().',
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
        $this->assertEquals(Severity::High, $issue->severity);
        $this->assertEquals(15, $issue->location->line);
    }

    #[Test]
    public function test_detects_missing_parameter_in_override(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Services/PaymentService.php',
                'line' => 28,
                'message' => 'Method App\Services\PaymentService::processPayment() overrides method App\Services\BaseService::processPayment() but is missing parameter $options.',
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
        $this->assertEquals(Severity::High, $issue->severity);
        $this->assertStringContainsString('missing parameter', $issue->recommendation);
    }

    #[Test]
    public function test_detects_visibility_narrowing(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Models/User.php',
                'line' => 55,
                'message' => 'Method App\Models\User::save() extends method App\Models\Model::save() but changes visibility from public to protected.',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\Models; class User { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertEquals(Severity::High, $issue->severity);
        $this->assertStringContainsString('visibility', $issue->recommendation);
    }

    #[Test]
    public function test_detects_deprecated_method_override(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Services/LegacyService.php',
                'line' => 12,
                'message' => 'Overridden method App\Services\BaseService::legacyMethod() is deprecated: Use newMethod() instead.',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Services/LegacyService.php' => '<?php namespace App\Services; class LegacyService { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertEquals(Severity::High, $issue->severity);
        $this->assertStringContainsString('deprecated', $issue->recommendation);
    }

    #[Test]
    public function test_detects_incompatible_method_signature(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Repositories/UserRepository.php',
                'line' => 33,
                'message' => 'Method App\Repositories\UserRepository::find() is not compatible with App\Repositories\Repository::find().',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'app/Repositories/UserRepository.php' => '<?php namespace App\Repositories; class UserRepository { }',
            'vendor/bin/phpstan' => $phpstanScript,
        ]);

        chmod($tempDir.'/vendor/bin/phpstan', 0755);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertEquals(Severity::High, $issue->severity);
    }

    #[Test]
    public function test_detects_multiple_invalid_overrides(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Services/UserService.php',
                'line' => 10,
                'message' => 'Return type App\User of method App\Services\UserService::getUser() is not covariant with return type App\Models\User.',
            ],
            [
                'file' => 'app/Services/UserService.php',
                'line' => 15,
                'message' => 'Parameter #1 of method App\Services\UserService::update() is not contravariant with parameter #1.',
            ],
            [
                'file' => 'app/Controllers/UserController.php',
                'line' => 25,
                'message' => 'Method App\Controllers\UserController::show() extends method App\Controllers\BaseController::show() but changes visibility from public to protected.',
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
        $this->assertStringContainsString('Found 3 invalid method override(s)', $result->getMessage());
        $this->assertIssueCount(3, $result);
    }

    // =========================================================================
    // Pattern Matching Tests
    // =========================================================================

    #[Test]
    public function test_matches_covariant_return_type_pattern(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Return type string of method App\Test::foo() is not covariant with return type int.',
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
    public function test_matches_contravariant_parameter_pattern(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Parameter #2 $value of method App\Test::bar() is not contravariant with parameter #2.',
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
    public function test_matches_missing_parameter_pattern(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Method App\Test::process() overrides method App\Base::process() but is missing parameter $data.',
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
    public function test_recommendation_for_covariant_return_type(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Return type string of method App\Test::foo() is not covariant with return type int.',
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
        $this->assertStringContainsString('return type', $issue->recommendation);
        $this->assertStringContainsString('covariant', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_contravariant_parameter(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Parameter #1 $user of method App\Test::bar() is not contravariant with parameter #1.',
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
        $this->assertStringContainsString('parameter type', $issue->recommendation);
        $this->assertStringContainsString('contravariant', $issue->recommendation);
    }

    #[Test]
    public function test_recommendation_for_visibility_violation(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Method App\Test::save() extends method App\Base::save() but changes visibility from public to protected.',
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
        $this->assertStringContainsString('narrow', $issue->recommendation);
    }

    // =========================================================================
    // Metadata Tests
    // =========================================================================

    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('invalid-method-overrides', $metadata->id);
        $this->assertEquals('Invalid Method Overrides Analyzer', $metadata->name);
        $this->assertEquals(Category::Reliability, $metadata->category);
        $this->assertEquals(Severity::High, $metadata->severity);
        $this->assertEquals(20, $metadata->timeToFix);
    }

    #[Test]
    public function test_has_correct_tags(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertContains('phpstan', $metadata->tags);
        $this->assertContains('static-analysis', $metadata->tags);
        $this->assertContains('inheritance', $metadata->tags);
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
                'message' => 'Return type string of method App\Test::foo() is not covariant with return type int.',
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

        $this->assertStringContainsString('Found 1 invalid method override(s)', $result->getMessage());
        $this->assertStringNotContainsString('showing first', $result->getMessage());
    }

    #[Test]
    public function test_formats_message_with_multiple_issues(): void
    {
        $phpstanScript = $this->createMockPHPStanScript([
            [
                'file' => 'app/Test.php',
                'line' => 1,
                'message' => 'Return type string of method App\Test::foo() is not covariant with return type int.',
            ],
            [
                'file' => 'app/Test.php',
                'line' => 2,
                'message' => 'Parameter #1 of method App\Test::bar() is not contravariant with parameter #1.',
            ],
            [
                'file' => 'app/Test.php',
                'line' => 3,
                'message' => 'Method App\Test::baz() is not compatible with App\Base::baz().',
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

        $this->assertStringContainsString('Found 3 invalid method override(s)', $result->getMessage());
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
                'message' => 'Return type string of method App\Test::foo() is not covariant with return type int.',
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
                'message' => 'Return type string of method App\Test::foo() is not covariant with return type int.',
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
