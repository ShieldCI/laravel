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
        $this->assertHasIssueContaining('write operations without transaction protection', $result);
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
        $this->assertHasIssueContaining('write operations', $result);
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
        $this->assertHasIssueContaining('write operations without transaction protection', $result);
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
        $this->assertHasIssueContaining('write operations without transaction protection', $result);
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
        $this->assertHasIssueContaining('2 write operations', $result);
    }
}
