<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\MissingDatabaseTransactionsAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MissingDatabaseTransactionsAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best_practices' => [
                        'missing-database-transactions' => [
                            'threshold' => 2,
                        ],
                    ],
                ],
            ],
        ]);

        return new MissingDatabaseTransactionsAnalyzer($this->parser, $config);
    }

    public function test_passes_with_single_write_operation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function createUser(array $data)
    {
        return User::create($data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_transaction_wrapper(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Profile;
use Illuminate\Support\Facades\DB;

class UserService
{
    public function createUserWithProfile(array $data)
    {
        return DB::transaction(function () use ($data) {
            $user = User::create($data['user']);
            Profile::create(['user_id' => $user->id, 'bio' => $data['bio']]);
            return $user;
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_begin_transaction(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Profile;
use Illuminate\Support\Facades\DB;

class UserService
{
    public function createUserWithProfile(array $data)
    {
        DB::beginTransaction();

        try {
            $user = User::create($data['user']);
            Profile::create(['user_id' => $user->id]);
            DB::commit();
            return $user;
        } catch (\Exception $e) {
            DB::rollBack();
            throw $e;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_multiple_writes_without_transaction(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Profile;

class UserService
{
    public function createUserWithProfile(array $data)
    {
        $user = User::create($data['user']);
        Profile::create(['user_id' => $user->id, 'bio' => $data['bio']]);
        return $user;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('write operations without transaction protection', $result);
    }

    public function test_detects_multiple_model_saves(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;
use App\Models\OrderItem;

class OrderService
{
    public function createOrder(array $data)
    {
        $order = new Order($data['order']);
        $order->save();

        $item = new OrderItem($data['item']);
        $item->order_id = $order->id;
        $item->save();

        return $order;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('write operations', $result);
    }

    public function test_detects_static_updates_without_transaction(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\ActivityLog;

class UserUpdateService
{
    public function updateUser($id, array $data)
    {
        User::update($data);
        ActivityLog::create(['action' => 'user_updated', 'user_id' => $id]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserUpdateService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_delete_operations_without_transaction(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Profile;

class UserDeletionService
{
    public function deleteUserAndProfile($userId)
    {
        Profile::where('user_id', $userId)->delete();
        User::find($userId)->delete();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserDeletionService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 write operations', $result);
    }

    public function test_detects_relationship_operations_without_transaction(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserRelationService
{
    public function syncRoles($userId, array $roleIds)
    {
        $user = User::find($userId);
        $user->roles()->sync($roleIds);
        $user->permissions()->attach([1, 2, 3]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserRelationService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_ignores_files_with_parse_errors(): void
    {
        $code = '<?php this is invalid PHP code {{{';

        $tempDir = $this->createTempDirectory(['Invalid.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_provides_helpful_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Profile;

class UserService
{
    public function createUserWithProfile(array $data)
    {
        $user = User::create($data['user']);
        Profile::create(['user_id' => $user->id]);
        return $user;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('DB::transaction()', $issues[0]->recommendation);
        $this->assertStringContainsString('data integrity', $issues[0]->recommendation);
    }
}
