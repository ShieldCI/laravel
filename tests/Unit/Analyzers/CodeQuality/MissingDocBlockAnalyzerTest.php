<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\CodeQuality\MissingDocBlockAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MissingDocBlockAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MissingDocBlockAnalyzer($this->parser);
    }

    /** @test */
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('PHPDoc', $result);
    }

    /** @test */
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

    /** @test */
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

    /** @test */
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

    /** @test */
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

    /** @test */
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

    /** @test */
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

    /** @test */
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('@param', $result);
    }

    /** @test */
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

        $this->assertWarning($result);
        // Should flag that 4 out of 5 parameters are missing @param tags
        $this->assertHasIssueContaining('4 parameter(s) missing @param', $result);
        $this->assertHasIssueContaining('found 1, need 5', $result);
    }

    /** @test */
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

    /** @test */
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('@throws', $result);
    }

    /** @test */
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('@throws', $result);
    }

    /** @test */
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('@throws', $result);
    }

    /** @test */
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('@throws', $result);
    }

    /** @test */
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

    /** @test */
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
        $this->assertWarning($result);
        $this->assertHasIssueContaining('@throws', $result);
    }

    /** @test */
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

    /** @test */
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

    /** @test */
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

    /** @test */
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
        $this->assertWarning($result);
        $this->assertHasIssueContaining('@return', $result);
    }

    /** @test */
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
    /** Doc */ public function needsReturnUnion(): string|array { return 'test'; }

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

        $this->assertWarning($result);

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

    /** @test */
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

    /** @test */
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

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
        $this->assertHasIssueContaining('firstMethod', $result);
        $this->assertHasIssueContaining('secondMethod', $result);
    }

    /** @test */
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

        $this->assertWarning($result);
        $issues = $result->getIssues();

        // This method has 3 issues: missing @param (2 params), missing @throws, and missing @return (no return type)
        $this->assertCount(3, $issues);

        // Message should say "3 issues across 1 method" (not "3 methods")
        $this->assertStringContainsString('3 documentation issues across 1 public method', $result->getMessage());
    }

    /** @test */
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

        $this->assertWarning($result);
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

    /** @test */
    #[Test]
    public function test_has_correct_analyzer_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('missing-docblock', $metadata->id);
        $this->assertSame('Missing DocBlock Analyzer', $metadata->name);
        $this->assertContains('documentation', $metadata->tags);
    }

    /** @test */
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

    /** @test */
    #[Test]
    public function test_union_of_concrete_class_types_doesnt_require_return_tag(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;

class ExampleController
{
    /**
     * Handle the request.
     */
    public function handle(): Response|JsonResponse
    {
        return response()->json([]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ExampleController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - both union members are concrete class names, fully self-documenting
        // Adding @return would conflict with Pint which strips redundant type declarations
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_filament_resource_builder_overrides(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Filament\Resources;

use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables\Table;

class ClientResource extends Resource
{
    public static function form(Schema $schema): Schema
    {
        return $schema->components([]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([]);
    }

    public static function infolist(Schema $schema): Schema
    {
        return $schema->components([]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Filament/Resources/ClientResource.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // form/table/infolist are framework overrides with self-explanatory signatures
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_filament_authorization_overrides(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Filament\Resources;

use Filament\Resources\Resource;
use Illuminate\Database\Eloquent\Model;

class AllocationResource extends Resource
{
    public static function canAccess(): bool
    {
        return auth()->user()->can('access', Allocation::class);
    }

    public static function canView(Model $record): bool
    {
        return auth()->user()->can('view', $record);
    }

    public static function canViewAny(): bool
    {
        return auth()->user()->can('viewAny', Allocation::class);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Filament/Resources/AllocationResource.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // can* authorization overrides should not require docblocks
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_filament_panel_provider_override(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Providers\Filament;

use Filament\Panel;
use Filament\PanelProvider;

class AppPanelProvider extends PanelProvider
{
    public function panel(Panel $panel): Panel
    {
        return $panel->default()->id('app');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/Filament/AppPanelProvider.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // panel() is a Filament framework override (class extends Filament\PanelProvider)
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_does_not_exclude_builder_methods_in_non_filament_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ReportBuilder
{
    public function form($data)
    {
        return $data;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ReportBuilder.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // form() in a plain service class is NOT a Filament override and stays flagged
        $this->assertWarning($result);
        $this->assertHasIssueContaining('PHPDoc', $result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_custom_methods_in_filament_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Filament\Resources;

use Filament\Resources\Resource;
use Filament\Schemas\Schema;

class AllocationResource extends Resource
{
    public static function form(Schema $schema): Schema
    {
        return $schema->components([]);
    }

    public function calculateTotals($rows, $modifier)
    {
        return collect($rows)->sum();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Filament/Resources/AllocationResource.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Only known framework overrides are skipped; custom methods stay flagged
        $this->assertWarning($result);
        $this->assertHasIssueContaining('calculateTotals', $result);
    }

    /** @test */
    #[Test]
    public function test_detects_filament_class_via_namespace(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Filament\Resources;

use App\Filament\BaseResource;
use Filament\Schemas\Schema;

class ProductResource extends BaseResource
{
    public static function form(Schema $schema): Schema
    {
        return $schema->components([]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Filament/Resources/ProductResource.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Class extends a project-local base but lives in an App\Filament namespace
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_skips_migration_files(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Database\Migrations\Migration;

class CreatePermissionTables extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        if (empty(config('permission.table_names'))) {
            throw new Exception('config not loaded');
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (empty(config('permission.table_names'))) {
            throw new Exception('config not found');
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'database/migrations/2022_10_14_000000_create_permission_tables.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['database']);

        $result = $analyzer->analyze();

        // Migrations are scaffolding: no @throws noise on up()/down()
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_skips_factory_files(): void
    {
        $code = <<<'PHP'
<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class ClientFactory extends Factory
{
    public function configure()
    {
        return $this->afterCreating(fn ($client) => null);
    }

    public function surveyed(): static
    {
        return $this->state(fn () => ['site_survey_requested' => true]);
    }

    public function forEmployee($employee, $extra): static
    {
        return $this->state(fn () => ['employee_id' => $employee->id]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'database/factories/ClientFactory.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['database']);

        $result = $analyzer->analyze();

        // Factory hooks (configure) and arbitrary state methods are test-support noise
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_skips_seeder_files(): void
    {
        $code = <<<'PHP'
<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    public function run($extra)
    {
        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'database/seeders/DatabaseSeeder.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['database']);

        $result = $analyzer->analyze();

        // Seeders are scaffolding/test-support files
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_mailable_contract_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Mail;

use Illuminate\Mail\Mailable;

class OrderShipped extends Mailable
{
    public function envelope(): Envelope
    {
        return new Envelope(subject: 'Order Shipped');
    }

    public function content(): Content
    {
        return new Content(view: 'emails.orders.shipped');
    }

    public function attachments(): array
    {
        return [];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Mail/OrderShipped.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // envelope/content/attachments are Mailable framework contracts
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_form_request_contract_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StorePostRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return ['title' => 'required'];
    }

    public function prepareForValidation(): void
    {
        $this->merge(['slug' => 'x']);
    }

    public function withValidator($validator): void
    {
        //
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Requests/StorePostRequest.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // authorize/rules/prepareForValidation/withValidator are FormRequest contracts
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_all_public_controller_methods(): void
    {
        // Controllers are exempt wholesale — both REST-named actions (store) and
        // app-specific actions (switch) are route handlers with typed signatures.
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Support\ActiveBusiness;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

class BusinessSwitcherController
{
    public function store(Request $request, ActiveBusiness $active): RedirectResponse
    {
        $business = $this->persist($request);
        $active->set($business->id);

        return redirect()->route('dashboard');
    }

    public function switch(Request $request, ActiveBusiness $active): RedirectResponse
    {
        $data = $request->validate(['business_id' => ['required', 'integer']]);
        abort_unless($request->user() !== null, 403);
        $active->set((int) $data['business_id']);

        return redirect()->back();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/BusinessSwitcherController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // store (REST name) and switch (custom name) are both controller actions
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_job_contract_methods_via_should_queue(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;

class ProcessPodcast implements ShouldQueue
{
    public function handle(): void
    {
        //
    }

    public function failed($exception): void
    {
        //
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Jobs/ProcessPodcast.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // handle/failed are queued-job framework contracts
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_listener_contract_methods_via_namespace(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Listeners;

class SendShipmentNotification
{
    public function handle($event): void
    {
        //
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Listeners/SendShipmentNotification.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // handle is a listener framework contract (gated by namespace/path)
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_store_update_in_repository(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

class PostRepository
{
    public function store($data)
    {
        return $data;
    }

    public function update($id, $data)
    {
        return $id;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Repositories/PostRepository.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // store/update in a repository are NOT controller actions — still flagged
        $this->assertWarning($result);
        $this->assertHasIssueContaining('store', $result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_handle_in_plain_service(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PaymentService
{
    public function handle($payment)
    {
        return $payment;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/PaymentService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // handle() in a plain service is not a job/listener — still flagged
        $this->assertWarning($result);
        $this->assertHasIssueContaining('handle', $result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_rules_in_plain_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Support;

class RuleEngine
{
    public function rules()
    {
        return [];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Support/RuleEngine.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // rules() in a plain class is not a FormRequest — still flagged
        $this->assertWarning($result);
        $this->assertHasIssueContaining('rules', $result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_build_in_non_mailable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Builders;

class QueryBuilder
{
    public function build()
    {
        return [];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Builders/QueryBuilder.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // build() in a non-Mailable class is still flagged
        $this->assertWarning($result);
        $this->assertHasIssueContaining('build', $result);
    }

    /** @test */
    #[Test]
    public function test_excludes_even_helper_methods_in_controller(): void
    {
        // Consequence of the whole-file controller exemption: even a public helper that
        // is not an action is exempt. Public helpers on controllers are an anti-pattern
        // (they should be private/protected, which the analyzer never checks anyway).
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function recalculateStats($rows)
    {
        return $rows;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_store_in_non_controller_path(): void
    {
        // A 'store' method in a class that is NOT a controller (path/filename) stays flagged
        // — the exemption is the controller location, not the method name.
        $code = <<<'PHP'
<?php

namespace App\Repositories;

class PostStore
{
    public function store($data)
    {
        $saved = $this->persist($data);

        return $saved;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Repositories/PostStore.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('store', $result);
    }

    /** @test */
    #[Test]
    public function test_suppresses_trivially_self_documenting_enum_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Enums;

enum FounderBand: string
{
    case Emerging = 'emerging';
    case Strong = 'strong';

    public function label(): string
    {
        return match ($this) {
            self::Emerging => 'Emerging',
            self::Strong => 'Strong',
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Enums/FounderBand.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // label(): string is single-statement, self-documenting return, no params, no throws
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_suppresses_self_documenting_value_object_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Support;

class Plan
{
    public function tier(): PlanTier
    {
        return $this->tier;
    }

    public function id(): ?int
    {
        return $this->id;
    }

    public function clear(): void
    {
        $this->items = [];
    }

    public function can(Capability $capability): bool
    {
        return $this->capabilities->contains($capability);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Support/Plan.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // All four are single-statement, fully-typed, non-throwing — self-documenting
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_self_documenting_signature_with_control_flow(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function process(Order $order): Receipt
    {
        if ($order->isEmpty()) {
            return Receipt::empty();
        }

        return new Receipt($order->total());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // A branching body is not "trivial" even with concrete types — still nudged, but
        // the recommendation should only ask for a summary (no @param/@return/@throws).
        $this->assertWarning($result);
        $recommendation = $this->recommendationFor('process', $result);
        $this->assertStringContainsString('short description', $recommendation);
        $this->assertStringNotContainsString('@param', $recommendation);
        $this->assertStringNotContainsString('@return', $recommendation);
        $this->assertStringNotContainsString('@throws', $recommendation);
    }

    /** @test */
    #[Test]
    public function test_suppresses_assign_then_return_with_self_documenting_signature(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Support;

class ActiveBusiness
{
    public function id(): ?int
    {
        $value = $this->session->get('active_business_id');

        return is_numeric($value) ? (int) $value : null;
    }

    public function owner(): ?User
    {
        $owner = User::query()->where('role', 'owner')->first();

        return $owner;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Support/ActiveBusiness.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Local assignments feeding a single return, with self-documenting signatures
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_assign_then_return_when_variable_does_not_feed_return(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Auditor
{
    public function record(): int
    {
        $logged = $this->writeAuditLog();

        return 42;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Auditor.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // $logged is a side-effecting statement that never feeds the return — not trivial
        $this->assertWarning($result);
        $this->assertHasIssueContaining('record', $result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_when_statement_before_return_is_not_assignment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ReportService
{
    public function assemble(): Report
    {
        $this->prepare();

        return new Report();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ReportService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // A side-effecting call before the return makes the body non-trivial
        $this->assertWarning($result);
        $this->assertHasIssueContaining('assemble', $result);
    }

    /** @test */
    #[Test]
    public function test_missing_docblock_recommendation_includes_only_needed_tags(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Transformer
{
    public function transform($input): array
    {
        $output = (array) $input;

        return $output;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Transformer.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $recommendation = $this->recommendationFor('transform', $result);
        // Untyped param needs @param; generic array return needs @return; nothing thrown.
        $this->assertStringContainsString('@param', $recommendation);
        $this->assertStringContainsString('@return', $recommendation);
        $this->assertStringNotContainsString('@throws', $recommendation);
    }

    /** @test */
    #[Test]
    public function test_enum_method_issue_reports_enum_name_not_unknown(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Enums;

enum Palette: string
{
    case Warm = 'warm';
    case Cool = 'cool';

    public function swatches(): array
    {
        $base = ['#fff'];

        return $base;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Enums/Palette.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // swatches(): array is generic, multi-statement — flagged. Its class context must
        // resolve to the enum name now that Stmt\Enum_ is tracked.
        $this->assertWarning($result);
        $this->assertHasIssueContaining('swatches', $result);

        $issue = $result->getIssues()[0];
        $this->assertSame('Palette', $issue->metadata['class'] ?? null);
    }

    /** @test */
    #[Test]
    public function test_excludes_middleware_contract_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureActiveBusiness
{
    public function handle(Request $request, Closure $next): Response
    {
        if ($request->user() === null) {
            abort(403);
        }

        return $next($request);
    }

    public function terminate(Request $request, Response $response): void
    {
        $this->log($request, $response);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/EnsureActiveBusiness.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // handle/terminate are fixed by the Laravel middleware contract, even with real logic
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_custom_method_in_middleware(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class CheckRole
{
    public function handle(Request $request, Closure $next): Response
    {
        return $next($request);
    }

    public function resolveRole($user)
    {
        return $user->role;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/CheckRole.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // handle is skipped, but a custom middleware method is still flagged
        $this->assertWarning($result);
        $this->assertHasIssueContaining('resolveRole', $result);
    }

    /** @test */
    #[Test]
    public function test_excludes_eloquent_scope_apply_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Scopes;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;

class BusinessScope implements Scope
{
    public function apply(Builder $builder, Model $model): void
    {
        $businessId = app('active')->id();

        $builder->where($model->qualifyColumn('business_id'), $businessId ?? 0);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Scopes/BusinessScope.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // apply() is mandated by the Illuminate\Database\Eloquent\Scope interface
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_apply_method_in_non_scope_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DiscountApplier
{
    public function apply(Order $order): void
    {
        if ($order->isEmpty()) {
            return;
        }

        $order->discount(0.1);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/DiscountApplier.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // apply() in a class that does not implement Scope is not a contract method
        $this->assertWarning($result);
        $this->assertHasIssueContaining('apply', $result);
    }

    /** @test */
    #[Test]
    public function test_excludes_validation_rule_contract_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

class Lowercase implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $normalized = strtolower((string) $value);

        if ($normalized !== $value) {
            $fail('The :attribute must be lowercase.');
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Rules/Lowercase.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // validate() is mandated by the ValidationRule interface
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_legacy_validation_rule_contract_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Rules;

use Illuminate\Contracts\Validation\Rule;

class NonEmpty implements Rule
{
    public function passes($attribute, $value): bool
    {
        $clean = trim((string) $value);

        return $clean !== '';
    }

    public function message(): array
    {
        return ['en' => 'Required', 'es' => 'Requerido'];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Rules/NonEmpty.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // passes/message are the legacy Rule contract
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_responsable_contract_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Responses;

use Illuminate\Contracts\Support\Responsable;
use Symfony\Component\HttpFoundation\Response;

class CheckoutResponse implements Responsable
{
    public function toResponse($request): Response
    {
        if ($this->failed) {
            return response('error', 500);
        }

        return response('ok');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Responses/CheckoutResponse.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // toResponse() is mandated by the Responsable interface
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_console_command_handle(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

class SyncReports extends Command
{
    public function handle(): int
    {
        $this->info('Syncing...');

        return self::SUCCESS;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Console/Commands/SyncReports.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // handle() is the console command framework contract
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_notification_channel_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Notifications;

use Illuminate\Notifications\Notification;

class InvoicePaid extends Notification
{
    public function via($notifiable): array
    {
        return ['mail', 'database'];
    }

    public function toArray($notifiable): array
    {
        $data = ['amount' => 100];

        return $data;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Notifications/InvoicePaid.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // via/toArray are Notification channel contracts
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_excludes_json_resource_to_array(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Resources;

use Illuminate\Http\Resources\Json\JsonResource;

class UserResource extends JsonResource
{
    public function toArray($request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Resources/UserResource.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // toArray() is the JsonResource framework contract
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_to_array_in_plain_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Support;

class Payload
{
    public function toArray($data): array
    {
        $out = (array) $data;

        return $out;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Support/Payload.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // toArray() in a class that is neither a Resource nor a Notification is still flagged
        $this->assertWarning($result);
        $this->assertHasIssueContaining('toArray', $result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_message_on_non_illuminate_rule_interface(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Validation;

use App\Contracts\Rule;

class PricingRule implements Rule
{
    public function message(): array
    {
        return ['price' => 'invalid'];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Validation/PricingRule.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // A non-Illuminate interface ending in \Rule must NOT be suffix-matched (exact-only)
        $this->assertWarning($result);
        $this->assertHasIssueContaining('message', $result);
    }

    /** @test */
    #[Test]
    public function test_excludes_fully_typed_interface_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services\ActionPlan\Contracts;

use App\Support\ActionPlan\ActionPlanContent;
use App\Support\ActionPlan\PlanInput;

interface PlanGenerator
{
    public function generate(PlanInput $input): ActionPlanContent;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ActionPlan/Contracts/PlanGenerator.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // A bodyless declaration with a fully-typed signature is the entire contract
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_interface_method_with_generic_signature(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Contracts;

interface Transformer
{
    public function transform(array $payload): array;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Contracts/Transformer.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // array param and array return are ambiguous — a docblock still adds value
        $this->assertWarning($result);
        $this->assertHasIssueContaining('transform', $result);
    }

    /** @test */
    #[Test]
    public function test_excludes_fully_typed_abstract_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use Illuminate\Database\Eloquent\Model;

abstract class Repository
{
    abstract public function find(int $id): ?Model;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Repositories/Repository.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Fully-typed abstract declaration carries nothing beyond its signature
        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_still_flags_abstract_method_with_ambiguous_return(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

abstract class Aggregator
{
    abstract public function summarize(int $id): array;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Aggregator.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // array return is ambiguous — a @return documenting the shape still adds value
        $this->assertWarning($result);
        $this->assertHasIssueContaining('summarize', $result);
    }

    /**
     * Find the recommendation for the issue raised against the named method.
     */
    private function recommendationFor(string $method, ResultInterface $result): string
    {
        foreach ($result->getIssues() as $issue) {
            if (str_contains($issue->message, "'{$method}'")) {
                return $issue->recommendation;
            }
        }

        $this->fail("No issue found for method '{$method}'");
    }
}
