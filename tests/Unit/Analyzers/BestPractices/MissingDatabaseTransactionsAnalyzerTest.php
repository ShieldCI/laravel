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
                    'best-practices' => [
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
        $this->assertHasIssueContaining('database write operation(s) outside transaction protection', $result);
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
        $this->assertHasIssueContaining('database write operation', $result);
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
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
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
        $this->assertStringContainsString('atomicity', $issues[0]->recommendation);
    }

    public function test_detects_writes_outside_transaction_scope(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Profile;
use App\Models\Log;
use Illuminate\Support\Facades\DB;

class UserService
{
    public function createUserWithProfile(array $data)
    {
        // These writes are OUTSIDE the transaction - should be detected!
        $user = User::create($data['user']);
        Profile::create(['user_id' => $user->id]);

        // This transaction exists but doesn't protect the writes above
        DB::transaction(function () {
            // Empty or unrelated code
        });

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
        $this->assertHasIssueContaining('database write operation(s) outside transaction protection', $result);
    }

    public function test_detects_db_facade_writes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

class ReportService
{
    public function generateReport(array $data)
    {
        DB::insert('INSERT INTO reports (name) VALUES (?)', [$data['name']]);
        DB::update('UPDATE stats SET count = count + 1');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReportService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operation', $result);
    }

    public function test_detects_increment_decrement_operations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Counter;
use App\Models\Stats;

class CounterService
{
    public function updateCounters($id)
    {
        Counter::find($id)->increment('views');
        Stats::where('type', 'page')->decrement('remaining');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CounterService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_touch_operations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Post;
use App\Models\User;

class TouchService
{
    public function touchRecords($postId, $userId)
    {
        Post::find($postId)->touch();
        User::find($userId)->touch();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/TouchService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_update_or_insert_and_upsert(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Setting;
use Illuminate\Support\Facades\DB;

class SettingService
{
    public function syncSettings(array $settings)
    {
        Setting::updateOrInsert(['key' => 'foo'], ['value' => 'bar']);
        DB::table('configs')->upsert($settings, ['key'], ['value']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/SettingService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_respects_custom_threshold(): void
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'missing-database-transactions' => [
                            'threshold' => 3,
                        ],
                    ],
                ],
            ],
        ]);

        $analyzer = new MissingDatabaseTransactionsAnalyzer($this->parser, $config);

        // This has 2 writes, which is below the threshold of 3
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

        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because we only have 2 writes and threshold is 3
        $this->assertPassed($result);
    }

    public function test_detects_issues_in_multiple_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Profile;
use App\Models\Log;

class UserService
{
    public function createUserWithProfile(array $data)
    {
        $user = User::create($data['user']);
        Profile::create(['user_id' => $user->id]);
        return $user;
    }

    public function deleteUser($userId)
    {
        Profile::where('user_id', $userId)->delete();
        User::find($userId)->delete();
        Log::create(['action' => 'user_deleted', 'user_id' => $userId]);
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

        // Should have 2 issues (one for each method)
        $this->assertCount(2, $issues);
        $this->assertStringContainsString('createUserWithProfile', $issues[0]->message);
        $this->assertStringContainsString('deleteUser', $issues[1]->message);
    }

    public function test_detects_toggle_and_sync_without_detaching(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class RoleService
{
    public function manageRoles($userId, array $roleIds, array $permIds)
    {
        $user = User::find($userId);
        $user->roles()->toggle($roleIds);
        $user->permissions()->syncWithoutDetaching($permIds);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/RoleService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_passes_when_writes_inside_transaction_scope(): void
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
        // Transaction wraps the writes - should pass
        return DB::transaction(function () use ($data) {
            $user = User::create($data['user']);
            Profile::create(['user_id' => $user->id]);
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

    public function test_detects_mixed_protected_and_unprotected_writes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Profile;
use App\Models\Log;
use Illuminate\Support\Facades\DB;

class UserService
{
    public function createUserWithProfile(array $data)
    {
        // These two writes are OUTSIDE transaction
        $user = User::create($data['user']);
        Profile::create(['user_id' => $user->id]);

        // This write is protected
        DB::transaction(function () use ($user) {
            Log::create(['action' => 'user_created', 'user_id' => $user->id]);
        });

        return $user;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should fail because 2 writes are unprotected (even though 1 is protected)
        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operation(s) outside transaction protection', $result);
    }

    public function test_ignores_cache_increment_operations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;

class CounterService
{
    public function incrementCounters()
    {
        Cache::increment('visitors');
        Cache::increment('page_views');
        Cache::decrement('remaining');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CounterService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_redis_operations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Redis;

class RedisService
{
    public function updateCounters()
    {
        Redis::incr('counter');
        Redis::decr('other');
        Redis::set('key', 'value');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/RedisService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_test_files(): void
    {
        $code = <<<'PHP'
<?php

namespace Tests\Unit;

use App\Models\User;
use App\Models\Profile;

class UserTest
{
    public function test_create_user()
    {
        // Multiple writes in test file should be ignored
        $user = User::create(['name' => 'Test']);
        Profile::create(['user_id' => $user->id]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['tests/Unit/UserTest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_seeder_files(): void
    {
        $code = <<<'PHP'
<?php

namespace Database\Seeders;

use App\Models\User;
use App\Models\Role;

class DatabaseSeeder
{
    public function run()
    {
        // Multiple writes in seeder should be ignored
        User::create(['name' => 'Admin']);
        Role::create(['name' => 'admin']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['database/seeders/DatabaseSeeder.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_migration_files(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up()
    {
        // Multiple writes in migration should be ignored
        DB::insert('INSERT INTO settings (key, value) VALUES (?, ?)', ['foo', 'bar']);
        DB::insert('INSERT INTO settings (key, value) VALUES (?, ?)', ['baz', 'qux']);
    }
};
PHP;

        $tempDir = $this->createTempDirectory(['database/migrations/2024_01_01_000000_create_settings.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_factory_files(): void
    {
        $code = <<<'PHP'
<?php

namespace Database\Factories;

use App\Models\User;
use App\Models\Profile;
use Illuminate\Database\Eloquent\Factories\Factory;

class UserFactory extends Factory
{
    public function configure()
    {
        return $this->afterCreating(function (User $user) {
            // Multiple writes in factory should be ignored
            Profile::create(['user_id' => $user->id, 'bio' => 'Test']);
            $user->roles()->attach([1, 2]);
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['database/factories/UserFactory.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_only_direct_transaction_closure_is_protected(): void
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
        // This closure is NOT passed to DB::transaction, so writes here are unprotected
        $callback = function () use ($data) {
            User::create($data['user']);
            Profile::create(['user_id' => 1]);
        };

        // This empty transaction doesn't protect the callback above
        DB::transaction(function () {
            // Empty
        });

        $callback();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should fail because the writes are in an unrelated closure, not the transaction closure
        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operation(s) outside transaction protection', $result);
    }

    public function test_mixed_cache_and_db_operations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\Cache;

class UserService
{
    public function updateUserWithCache(array $data)
    {
        // Only ONE actual DB write
        $user = User::create($data);

        // These are Cache operations, NOT DB writes
        Cache::increment('user_count');
        Cache::put('last_user', $user->id);

        return $user;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because only 1 DB write exists (Cache operations don't count)
        $this->assertPassed($result);
    }

    public function test_ignores_session_operations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Session;

class SessionService
{
    public function updateSession()
    {
        Session::put('key1', 'value1');
        Session::put('key2', 'value2');
        Session::save();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/SessionService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_storage_operations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Storage;

class FileService
{
    public function storeFiles()
    {
        Storage::put('file1.txt', 'content');
        Storage::delete('file2.txt');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/FileService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_queue_operations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Queue;

class QueueService
{
    public function dispatchJobs()
    {
        Queue::push('App\Jobs\Job1');
        Queue::delete('job-id');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/QueueService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_db_writes_mixed_with_ignored_facades(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Profile;
use Illuminate\Support\Facades\Cache;

class UserService
{
    public function createUserWithCaching(array $data)
    {
        // TWO actual DB writes - should be flagged
        $user = User::create($data['user']);
        Profile::create(['user_id' => $user->id]);

        // These don't count as DB writes
        Cache::increment('user_count');

        return $user;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should fail because there are 2 DB writes without transaction
        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    public function test_passes_with_begin_transaction_without_try_catch(): void
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
        $user = User::create($data['user']);
        Profile::create(['user_id' => $user->id]);
        DB::commit();
        return $user;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass - writes are between beginTransaction and commit
        $this->assertPassed($result);
    }

    public function test_detects_writes_after_commit(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Order;
use App\Models\Product;
use Illuminate\Support\Facades\DB;

class OrderService
{
    public function processOrder(array $data)
    {
        DB::beginTransaction();
        User::create($data['user']);  // Protected ✓
        DB::commit();

        // These writes are AFTER commit - NOT protected!
        Order::create($data['order']);
        Product::create($data['product']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should fail because Order::create and Product::create are outside transaction
        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operation(s) outside transaction protection', $result);
    }

    public function test_detects_writes_after_rollback(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Order;
use Illuminate\Support\Facades\DB;

class OrderService
{
    public function processOrder(array $data)
    {
        DB::beginTransaction();
        User::create($data['user']);  // Protected (but rolled back)
        DB::rollBack();

        // These writes are AFTER rollBack - NOT protected!
        Order::create($data['order']);
        User::create($data['fallback']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should fail because writes after rollBack are unprotected
        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operation(s) outside transaction protection', $result);
    }

    public function test_handles_multiple_transaction_blocks(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Order;
use Illuminate\Support\Facades\DB;

class OrderService
{
    public function processOrder(array $data)
    {
        // First transaction block
        DB::beginTransaction();
        User::create($data['user']);
        DB::commit();

        // Second transaction block
        DB::beginTransaction();
        Order::create($data['order']);
        DB::commit();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass - both writes are protected by their respective transactions
        $this->assertPassed($result);
    }

    public function test_detects_unprotected_write_between_transaction_blocks(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Order;
use App\Models\Log;
use Illuminate\Support\Facades\DB;

class OrderService
{
    public function processOrder(array $data)
    {
        // First transaction block
        DB::beginTransaction();
        User::create($data['user']);
        DB::commit();

        // Unprotected write between transactions!
        Log::create(['action' => 'user_created']);
        Order::create($data['order']);

        // Second transaction block (but Log::create above is NOT protected)
        DB::beginTransaction();
        Order::update(['status' => 'processed']);
        DB::commit();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should fail - Log::create and Order::create are unprotected between transactions
        $this->assertFailed($result);
    }

    public function test_handles_writes_in_try_and_catch_blocks(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Log;
use Illuminate\Support\Facades\DB;

class UserService
{
    public function createUser(array $data)
    {
        DB::beginTransaction();
        try {
            User::create($data['user']);
            DB::commit();
        } catch (\Exception $e) {
            DB::rollBack();
            Log::create(['error' => $e->getMessage()]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // The catch block write (Log::create) is outside transaction protection
        // because rollBack() has been called. This should be flagged since:
        // - Total writes = 2 (meets threshold)
        // - Log::create after rollBack is unprotected
        // Note: If this is intentional error logging, consider using a separate
        // try-catch for the Log::create or excluding it via baseline.
        $this->assertFailed($result);
        $this->assertHasIssueContaining('1 database write operation(s)', $result);
    }

    public function test_passes_with_nested_transaction_closures(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Profile;
use App\Models\Log;
use Illuminate\Support\Facades\DB;

class UserService
{
    public function createUserWithProfile(array $data)
    {
        return DB::transaction(function () use ($data) {
            $user = User::create($data['user']);

            // Nested transaction closure
            DB::transaction(function () use ($user) {
                Profile::create(['user_id' => $user->id]);
                Log::create(['action' => 'profile_created']);
            });

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

        // All writes are protected by DB::transaction() closures
        $this->assertPassed($result);
    }

    public function test_passes_with_deeply_nested_transaction_closures(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Profile;
use App\Models\Log;
use App\Models\Audit;
use Illuminate\Support\Facades\DB;

class UserService
{
    public function createUser(array $data)
    {
        return DB::transaction(function () use ($data) {
            $user = User::create($data['user']);

            DB::transaction(function () use ($user) {
                Profile::create(['user_id' => $user->id]);

                DB::transaction(function () use ($user) {
                    Log::create(['user_id' => $user->id]);
                    Audit::create(['action' => 'user_created']);
                });
            });

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

        // All writes are protected by nested DB::transaction() closures
        $this->assertPassed($result);
    }

    public function test_passes_with_nested_manual_transactions(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Profile;
use App\Models\Log;
use Illuminate\Support\Facades\DB;

class UserService
{
    public function createUserWithProfile(array $data)
    {
        DB::beginTransaction();
        $user = User::create($data['user']);

        DB::beginTransaction();  // Nested transaction
        Profile::create(['user_id' => $user->id]);
        DB::commit();  // Close nested

        Log::create(['action' => 'done']);  // Still protected by outer
        DB::commit();  // Close outer

        return $user;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // All writes should be protected by manual transactions
        $this->assertPassed($result);
    }

    public function test_detects_single_unprotected_write_with_partial_transaction(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Order;
use Illuminate\Support\Facades\DB;

class OrderService
{
    public function createOrder(array $data)
    {
        DB::transaction(function () use ($data) {
            User::create($data['user']);  // protected
        });

        Order::create($data['order']);  // unprotected - should be flagged!
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should fail because 1 write is outside transaction when total >= threshold
        $this->assertFailed($result);
        $this->assertHasIssueContaining('1 database write operation', $result);
    }
}
