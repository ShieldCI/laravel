<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\CodeQuality\MissingDocBlockAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MissingDocBlockAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MissingDocBlockAnalyzer($this->parser);
    }

    #[Test]
    public function test_detects_missing_docblocks(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function processUser($userId, $action)
    {
        return User::find($userId);
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
        $this->assertHasIssueContaining('PHPDoc', $result);
    }

    #[Test]
    public function test_passes_with_proper_docblocks(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     *
     * @param int $userId
     * @param string $action
     * @return User|null
     */
    public function processUser($userId, $action)
    {
        return User::find($userId);
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
    }

    #[Test]
    public function test_excludes_getter_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    // Getter should be excluded even without docblock
    public function getName($user)
    {
        return $user->name;
    }

    public function getUserId($user)
    {
        return $user->id;
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

        // Should pass because getters are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_excludes_setter_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    // Setter should be excluded even without docblock
    public function setName($user, $name)
    {
        $user->name = $name;
    }

    public function setEmail($user, $email)
    {
        $user->email = $email;
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

        // Should pass because setters are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_excludes_is_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    // is* methods should be excluded
    public function isActive($user)
    {
        return $user->active;
    }

    public function isAdmin($user)
    {
        return $user->role === 'admin';
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

        // Should pass because is* methods are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_excludes_has_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    // has* methods should be excluded
    public function hasPermission($user, $permission)
    {
        return in_array($permission, $user->permissions);
    }

    public function hasRole($user, $role)
    {
        return $user->role === $role;
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

        // Should pass because has* methods are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_excludes_magic_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    // Magic methods should be excluded
    public function __construct($dependency)
    {
        $this->dependency = $dependency;
    }

    public function __toString()
    {
        return 'UserService';
    }

    public function __call($method, $args)
    {
        return null;
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

        // Should pass because magic methods are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_missing_param_tags(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     *
     * @return User|null
     */
    public function processUser($userId, $action)
    {
        return User::find($userId);
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
        $this->assertHasIssueContaining('@param', $result);
    }

    #[Test]
    public function test_detects_partial_param_tags(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     *
     * @param mixed $userId The user ID
     * @return User|null
     */
    public function processUser($userId, $action, $timestamp, $metadata, $options)
    {
        return User::find($userId);
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
        // Should flag that 4 out of 5 parameters are missing @param tags
        $this->assertHasIssueContaining('4 parameter(s) missing @param', $result);
        $this->assertHasIssueContaining('found 1, need 5', $result);
    }

    #[Test]
    public function test_detects_missing_return_tags(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     *
     * @param int $userId
     * @param string $action
     */
    public function processUser($userId, $action): User
    {
        return User::find($userId);
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
    }

    #[Test]
    public function test_detects_missing_throws_tags_with_direct_throw(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     *
     * @param int $userId
     * @param string $action
     * @return User|null
     */
    public function processUser($userId, $action): ?User
    {
        if (!$userId) {
            throw new \InvalidArgumentException('User ID required');
        }
        return User::find($userId);
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
        $this->assertHasIssueContaining('@throws', $result);
    }

    #[Test]
    public function test_detects_throws_in_nested_if_statement(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     *
     * @param int $userId
     * @return User|null
     */
    public function processUser($userId): ?User
    {
        if ($userId > 0) {
            if ($userId > 1000) {
                throw new \Exception('Invalid user ID');
            }
            return User::find($userId);
        }
        return null;
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
        $this->assertHasIssueContaining('@throws', $result);
    }

    #[Test]
    public function test_detects_throws_in_foreach_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process multiple users.
     *
     * @param array $userIds
     * @return void
     */
    public function processUsers($userIds): void
    {
        foreach ($userIds as $userId) {
            if (!$userId) {
                throw new \Exception('Invalid ID');
            }
        }
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
        $this->assertHasIssueContaining('@throws', $result);
    }

    #[Test]
    public function test_detects_throws_in_try_catch_block(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     *
     * @param int $userId
     */
    public function processUser($userId)
    {
        try {
            throw new \Exception('Test exception');
        } catch (\Exception $e) {
            // Re-throw
            throw $e;
        }
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
        $this->assertHasIssueContaining('@throws', $result);
    }

    #[Test]
    public function test_ignores_caught_exceptions_in_try_block(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     *
     * @param int $userId
     * @return User|null
     */
    public function processUser($userId)
    {
        try {
            // These exceptions are caught and handled - no @throws needed
            throw new \InvalidArgumentException('Invalid user');
        } catch (\InvalidArgumentException $e) {
            // Handle exception without re-throwing
            logger()->error($e->getMessage());
            return null;
        }
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

        // Should pass - exception is caught and handled, not propagated
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_throws_in_catch_block_without_rethrow(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     *
     * @param int $userId
     */
    public function processUser($userId)
    {
        try {
            $user = User::find($userId);
        } catch (\Exception $e) {
            // New throw in catch - this DOES need @throws
            throw new \RuntimeException('Failed to process user', 0, $e);
        }
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

        // Should fail - new exception in catch block propagates
        $this->assertFailed($result);
        $this->assertHasIssueContaining('@throws', $result);
    }

    #[Test]
    public function test_ignores_private_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    // Private method without docblock should be ignored
    private function processUser($userId, $action)
    {
        return User::find($userId);
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

        // Should pass because private methods are not checked
        $this->assertPassed($result);
    }

    #[Test]
    public function test_ignores_protected_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    // Protected method without docblock should be ignored
    protected function processUser($userId, $action)
    {
        return User::find($userId);
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

        // Should pass because protected methods are not checked
        $this->assertPassed($result);
    }

    #[Test]
    public function test_method_without_parameters_doesnt_require_param_tags(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Get all users.
     *
     * @return array
     */
    public function getAllUsers(): array
    {
        return User::all();
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

        // Should pass because no parameters means no @param required
        $this->assertPassed($result);
    }

    #[Test]
    public function test_method_without_return_type_requires_return_tag(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     *
     * @param int $userId
     */
    public function processUser($userId)
    {
        return User::find($userId);
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

        // Should fail - methods without return type need @return documentation
        $this->assertFailed($result);
        $this->assertHasIssueContaining('@return', $result);
    }

    #[Test]
    public function test_return_type_requirements(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class UserService
{
    /** Doc */ public function needsReturnMixed(): mixed { return null; }
    /** Doc */ public function needsReturnArray(): array { return []; }
    /** Doc */ public function needsReturnIterable(): iterable { return []; }
    /** Doc */ public function needsReturnCallable(): callable { return fn() => true; }
    /** Doc */ public function needsReturnObject(): object { return new \stdClass; }
    /** Doc */ public function needsReturnUnion(): string|int { return 'test'; }

    /** @return string */ public function scalarString(): string { return 'test'; }
    /** @return int */ public function scalarInt(): int { return 1; }
    /** @return void */ public function scalarVoid(): void { }
    /** @return never @throws \Exception */ public function scalarNever(): never { throw new \Exception; }
    /** @return BelongsToMany */ public function concreteClass(): BelongsToMany { }
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

        // These should be flagged (missing @return)
        $this->assertHasIssueContaining('needsReturnMixed', $result);
        $this->assertHasIssueContaining('needsReturnArray', $result);
        $this->assertHasIssueContaining('needsReturnIterable', $result);
        $this->assertHasIssueContaining('needsReturnCallable', $result);
        $this->assertHasIssueContaining('needsReturnObject', $result);
        $this->assertHasIssueContaining('needsReturnUnion', $result);

        // These should NOT be flagged (have @return or don't need it)
        $issues = $result->getIssues();
        $issueMessages = array_map(fn ($i) => $i->message, $issues);

        $this->assertFalse(
            in_array(true, array_map(fn ($m) => str_contains($m, 'scalarString'), $issueMessages)),
            'scalarString should not be flagged'
        );
        $this->assertFalse(
            in_array(true, array_map(fn ($m) => str_contains($m, 'scalarInt'), $issueMessages)),
            'scalarInt should not be flagged'
        );
        $this->assertFalse(
            in_array(true, array_map(fn ($m) => str_contains($m, 'scalarVoid'), $issueMessages)),
            'scalarVoid should not be flagged'
        );
        $this->assertFalse(
            in_array(true, array_map(fn ($m) => str_contains($m, 'scalarNever'), $issueMessages)),
            'scalarNever should not be flagged'
        );
        $this->assertFalse(
            in_array(true, array_map(fn ($m) => str_contains($m, 'concreteClass'), $issueMessages)),
            'concreteClass should not be flagged'
        );
    }

    #[Test]
    public function test_abstract_methods_can_be_documented(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

abstract class BaseService
{
    /**
     * Process something.
     *
     * @param int $id
     * @return mixed
     */
    abstract public function process($id);
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/BaseService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because abstract method has docblock
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_multiple_issues_in_one_file(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    // No docblock
    public function firstMethod($userId)
    {
        return User::find($userId);
    }

    // No docblock
    public function secondMethod($data)
    {
        return $data;
    }

    /**
     * Has docblock.
     *
     * @param int $id
     * @return User
     */
    public function thirdMethod($id): User
    {
        return User::find($id);
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
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
        $this->assertHasIssueContaining('firstMethod', $result);
        $this->assertHasIssueContaining('secondMethod', $result);
    }

    #[Test]
    public function test_message_counts_issues_and_methods_separately(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     */
    public function processUser($userId, $action)
    {
        throw new \Exception('Error');
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
        $issues = $result->getIssues();

        // This method has 3 issues: missing @param (2 params), missing @throws, and missing @return (no return type)
        $this->assertCount(3, $issues);

        // Message should say "3 issues across 1 method" (not "3 methods")
        $this->assertStringContainsString('3 documentation issues across 1 public method', $result->getMessage());
    }

    #[Test]
    public function test_includes_correct_metadata(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function processUser($userId)
    {
        return User::find($userId);
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
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('method', $metadata);
        $this->assertArrayHasKey('class', $metadata);
        $this->assertArrayHasKey('issue_type', $metadata);
        $this->assertSame('processUser', $metadata['method']);
        $this->assertSame('UserService', $metadata['class']);
        $this->assertSame('missing', $metadata['issue_type']);
    }

    #[Test]
    public function test_has_correct_analyzer_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('missing-docblock', $metadata->id);
        $this->assertSame('Missing DocBlock Analyzer', $metadata->name);
        $this->assertContains('documentation', $metadata->tags);
    }

    #[Test]
    public function test_passes_with_throws_tag_when_exception_thrown(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     *
     * @param int $userId
     * @return User|null
     * @throws \InvalidArgumentException
     */
    public function processUser($userId): ?User
    {
        if (!$userId) {
            throw new \InvalidArgumentException('User ID required');
        }
        return User::find($userId);
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

        // Should pass because @throws tag is present
        $this->assertPassed($result);
    }
}
