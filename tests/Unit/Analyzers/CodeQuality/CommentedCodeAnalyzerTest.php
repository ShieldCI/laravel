<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\CodeQuality\CommentedCodeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class CommentedCodeAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CommentedCodeAnalyzer;
    }

    #[Test]
    public function test_passes_without_commented_code(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Register a new user.
     */
    public function register($data)
    {
        // Validate the input data
        $validated = $this->validate($data);

        return User::create($validated);
    }
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
        $this->assertStringContainsString('No commented-out code', $result->getMessage());
    }

    #[Test]
    public function test_detects_commented_code_with_double_slash(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function register($data)
    {
        $user = User::create($data);

        // Old implementation:
        // $validator = new UserValidator();
        // if (!$validator->validate($data)) {
        //     throw new ValidationException();
        // }
        // $user = new User();
        // $user->name = $data['name'];

        return $user;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('commented-out code', $result);
    }

    #[Test]
    public function test_detects_commented_code_with_hash_comments(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function process()
    {
        $data = [];

        # Old code that we don't need anymore:
        # $user = new User();
        # $user->name = 'Test';
        # $user->save();

        return $data;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('commented-out code', $result);
    }

    #[Test]
    public function test_ignores_todo_comments(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // TODO: Implement caching
        // TODO: Add validation
        // TODO: Send notification email

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_ignores_fixme_comments(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // FIXME: This is broken
        // FIXME: Performance issue here
        // FIXME: Memory leak

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_ignores_prose_comments(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // This method will process the data
        // The result should be cached
        // This can improve performance significantly

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_ignores_prose_at_sentence_boundaries(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // The user registration process
        // This validates input data
        // Should return validated result

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because these are prose comments
        $this->assertPassed($result);
    }

    #[Test]
    public function test_minimum_consecutive_lines_threshold(): void
    {
        // Only 2 lines of commented code (below threshold of 3)
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // $user = new User();
        // $user->save();

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because only 2 lines (below minimum of 3)
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_exactly_three_lines(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // $user = new User();
        // $user->name = 'Test';
        // $user->save();

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('3 consecutive lines', $result);
    }

    #[Test]
    public function test_detects_variable_patterns(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // $userId = 123;
        // $userName = 'John';
        // $userEmail = 'john@example.com';

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    #[Test]
    public function test_detects_function_patterns(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // function oldHelper() {
        //     return true;
        // }

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    #[Test]
    public function test_detects_method_call_patterns(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // $user->getName();
        // $user->getEmail();
        // $user->save();

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    #[Test]
    public function test_detects_static_call_patterns(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // User::find(1);
        // User::create($data);
        // User::all();

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    #[Test]
    public function test_detects_control_structure_patterns(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // if ($condition) {
        //     return true;
        // }

        return false;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    #[Test]
    public function test_detects_multiple_blocks_in_one_file(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function method1()
    {
        // $user = new User();
        // $user->name = 'Test';
        // $user->save();

        return true;
    }

    public function method2()
    {
        // $data = [];
        // $data['key'] = 'value';
        // return $data;

        return false;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
    }

    #[Test]
    public function test_severity_is_low_for_small_blocks(): void
    {
        // 10 lines of commented code (< 20)
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // $a = 1;
        // $b = 2;
        // $c = 3;
        // $d = 4;
        // $e = 5;
        // $f = 6;
        // $g = 7;
        // $h = 8;
        // $i = 9;
        // $j = 10;

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
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
    public function test_severity_is_medium_for_large_blocks(): void
    {
        // 25 lines of commented code (>= 20)
        $lines = '';
        for ($i = 1; $i <= 25; $i++) {
            $lines .= "        // \$var{$i} = {$i};\n";
        }

        $code = <<<PHP
<?php

class Service
{
    public function process()
    {
{$lines}
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
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
    public function test_includes_proper_metadata(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // $user = new User();
        // $user->name = 'Test';
        // $user->email = 'test@example.com';
        // $user->save();

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $issue = $issues[0];
        $metadata = $issue->metadata;

        $this->assertArrayHasKey('startLine', $metadata);
        $this->assertArrayHasKey('endLine', $metadata);
        $this->assertArrayHasKey('lineCount', $metadata);
        $this->assertArrayHasKey('preview', $metadata);
        $this->assertArrayHasKey('file', $metadata);

        $this->assertEquals(4, $metadata['lineCount']);
        $this->assertIsString($metadata['preview']);
    }

    #[Test]
    public function test_preview_shows_first_three_lines(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // $line1 = 1;
        // $line2 = 2;
        // $line3 = 3;
        // $line4 = 4;
        // $line5 = 5;

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $issue = $issues[0];

        $this->assertIsString($issue->metadata['preview']);
        $preview = (string) $issue->metadata['preview'];

        $this->assertStringContainsString('$line1 = 1', $preview);
        $this->assertStringContainsString('$line2 = 2', $preview);
        $this->assertStringContainsString('$line3 = 3', $preview);
        $this->assertStringContainsString('(2 more lines)', $preview);
    }

    #[Test]
    public function test_recommendation_includes_strategies(): void
    {
        $code = <<<'PHP'
<?php

class Service
{
    public function process()
    {
        // $user = new User();
        // $user->name = 'Test';
        // $user->save();

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $issue = $issues[0];

        $this->assertStringContainsString('Delete the commented code', $issue->recommendation);
        $this->assertStringContainsString('version control', $issue->recommendation);
    }

    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('commented-code', $metadata->id);
        $this->assertSame('Commented Code Analyzer', $metadata->name);
        $this->assertSame(Severity::Low, $metadata->severity);
        $this->assertSame(5, $metadata->timeToFix);
        $this->assertContains('maintainability', $metadata->tags);
        $this->assertContains('code-quality', $metadata->tags);
        $this->assertContains('dead-code', $metadata->tags);
    }

    #[Test]
    public function test_handles_empty_files(): void
    {
        $code = <<<'PHP'
<?php

// Empty file with just comment
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Empty.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because no commented code
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_block_commented_code(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class LegacyService
{
    public function activeMethod()
    {
        return "Active code";
    }

    /*
    public function oldMethod()
    {
        $user = User::find(1);
        $user->name = 'John';
        $user->save();

        return $user;
    }
    */

    public function anotherMethod()
    {
        return "More active code";
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/LegacyService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('commented-out code', $result);

        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));

        // Should detect the block comment
        $issue = $issues[0];
        $this->assertArrayHasKey('lineCount', $issue->metadata);
        $this->assertGreaterThanOrEqual(3, $issue->metadata['lineCount']);
    }

    #[Test]
    public function test_ignores_phpdoc_block_comments(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DocumentedService
{
    /**
     * This is a PHPDoc comment
     *
     * @param string $name
     * @param int $age
     * @return User
     */
    public function createUser($name, $age)
    {
        return User::create(['name' => $name, 'age' => $age]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/DocumentedService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because PHPDoc comments are not commented code
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_multiple_block_comments(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class MultipleBlocksService
{
    /*
    public function oldFeature1()
    {
        $data = getData();
        processData($data);
        return $data;
    }
    */

    public function activeMethod()
    {
        return "Active";
    }

    /*
     * Another disabled feature
     *
     * function oldFeature2() {
     *     $result = calculate();
     *     return $result;
     * }
     */
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/MultipleBlocksService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        // Should detect both block comments
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    #[Test]
    public function test_detects_both_single_line_and_block_comments(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class MixedCommentsService
{
    // $oldVar1 = "test";
    // $oldVar2 = 123;
    // return $oldVar1;

    /*
    public function disabledMethod()
    {
        $user = getUser();
        $user->update($data);
        return $user;
    }
    */
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/MixedCommentsService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        // Should detect both single-line and block comments
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    #[Test]
    public function test_allows_neutral_lines_within_threshold(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class NeutralLinesService
{
    // Old implementation with blank comment lines:
    // $foo = 1;
    // $bar = 2;
    //
    // $baz = 3;
    // $qux = 4;
    //
    //
    // $final = 5;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/NeutralLinesService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        // Should detect as ONE block despite blank comment lines (within tolerance)
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        // Should have 5 code lines (excluding the blank comment lines)
        $this->assertEquals(5, $issue->metadata['lineCount']);
        // But should span lines 8-15 (including neutral lines)
        $this->assertEquals(8, $issue->metadata['startLine']);
        $this->assertEquals(15, $issue->metadata['endLine']);
    }

    #[Test]
    public function test_breaks_block_when_exceeding_neutral_line_threshold(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ExceedNeutralService
{
    // First block:
    // $foo = 1;
    // $bar = 2;
    //
    //
    //
    // After 3 blank lines, this starts a new block (exceeds max of 2)
    // $baz = 3;
    // $qux = 4;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ExceedNeutralService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Both blocks are only 2 lines each (below min of 3), so should pass
        $this->assertPassed($result);
    }

    #[Test]
    public function test_ignores_variable_mentions_in_documentation(): void
    {
        $code = <<<'PHP'
<?php

class UserService
{
    // This method accepts a $userId parameter and returns the user
    // Set the $userName variable to the appropriate value
    // The $email should be validated before storing
    public function updateUser()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - these are just documentation mentioning variables (score 1 each)
        $this->assertPassed($result);
    }

    #[Test]
    public function test_ignores_inline_examples_in_documentation(): void
    {
        $code = <<<'PHP'
<?php

class DatabaseService
{
    // You can call $user->save() to persist changes
    // Use DB::table('users') to query the table
    // Try $query->where('active', true) for filtering
    public function queryUsers()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/DatabaseService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - these are inline examples in docs (score 1-2 each)
        $this->assertPassed($result);
    }

    #[Test]
    public function test_ignores_pseudocode_explanations(): void
    {
        $code = <<<'PHP'
<?php

class PaymentProcessor
{
    // First check if $balance > $amount
    // Then update $user->balance accordingly
    // Finally send $notification->email
    public function processPayment()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/PaymentProcessor.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - these are pseudocode explanations (weak indicators only)
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_actual_code_vs_documentation(): void
    {
        $code = <<<'PHP'
<?php

class OrderService
{
    // These are just explanations:
    // Set the $orderId and $status variables
    // Call $order->save() to persist

    // This is actual commented code:
    // $order = Order::find($id);
    // $order->status = 'completed';
    // $order->save();
    public function completeOrder()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/OrderService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should fail - the second block has actual code with assignments and method calls
        $this->assertFailed($result);
        $this->assertHasIssueContaining('3 consecutive lines', $result);
    }

    #[Test]
    public function test_detects_code_with_todo_markers_inverted_logic(): void
    {
        $code = <<<'PHP'
<?php

class PaymentService
{
    // TODO: Remove this old implementation after migration
    // public function oldPaymentMethod()
    // {
    //     $payment = Payment::create($data);
    //     return $payment;
    // }

    // FIXME: This legacy code needs refactoring
    // private function legacyCalculation()
    // {
    //     return $total * $rate;
    // }

    public function newPaymentMethod()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/PaymentService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should FAIL - strong code indicators (public function, private function)
        // should be detected even with TODO/FIXME markers
        // This demonstrates inverted logic: code signals win over documentation markers
        $this->assertFailed($result);
        $this->assertHasIssueContaining('commented-out code', $result);
    }

    #[Test]
    public function test_ignores_todo_with_weak_code_signals(): void
    {
        $code = <<<'PHP'
<?php

class UserService
{
    // TODO: Update the $userId in the next version
    // FIXME: The $userName validation needs improvement
    // NOTE: Consider using $email for login
    public function processUser()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should PASS - weak signals ($variable) + documentation markers = not code
        // Borderline scores (2-3) use documentation check as tiebreaker
        $this->assertPassed($result);
    }
}
