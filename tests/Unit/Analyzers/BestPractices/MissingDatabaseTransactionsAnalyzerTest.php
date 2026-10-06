<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use PhpParser\Node;
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
        $this->assertStringContainsString('database transaction', $issues[0]->recommendation);
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
        // These two writes are OUTSIDE transaction (lines 16 and 17)
        $user = User::create($data['user']);
        Profile::create(['user_id' => $user->id]);

        // This write is protected (line 21)
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

        // Verify recommendation shows only unprotected lines
        $issues = $result->getIssues();
        $recommendation = $issues[0]->recommendation;

        // Lines 15 and 16 are unprotected (User::create and Profile::create)
        $this->assertStringContainsString('15', $recommendation);
        $this->assertStringContainsString('16', $recommendation);

        // Line 20 is protected (Log::create inside transaction) - should NOT appear
        $this->assertStringNotContainsString('20', $recommendation);
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

    public function test_ignores_external_service_client_method_calls(): void
    {
        // $this->stripe->customers->update() is a Stripe API call, not a DB write.
        // Two or more levels of property access before the method indicates an injected
        // service client (e.g. Stripe, Twilio, SendGrid), not a query builder chain.
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class SubscriptionController
{
    private object $stripe;

    public function subscribe(string $email, string $tokenId): mixed
    {
        $account = $this->stripe->customers->search(['query' => "email:'{$email}'"]);

        if (! isset($account->data) || count($account->data) === 0) {
            $customer = $this->stripe->customers->create(['source' => $tokenId, 'email' => $email]);
        } else {
            $card     = $this->stripe->customers->createSource($account->data[0]->id, ['source' => $tokenId]);
            $customer = $this->stripe->customers->update($account->data[0]->id, ['default_source' => $card->id]);
        }

        // Only this is a real DB write
        DB::table('members')->update(['stripe_id' => $customer->id]);

        return response()->json(['status' => 'ok']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Controllers/SubscriptionController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Stripe calls are not DB writes — only 1 real DB write exists → below threshold
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

    public function test_passes_with_guard_clause_delete_before_transaction(): void
    {
        $code = <<<'PHP'
<?php
namespace App\Http\Controllers;
use App\Models\Team;
use App\Models\Invitation;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
class InvitationController
{
    public function accept(Request $request, string $token): mixed
    {
        $invitation = Invitation::where('token', $token)->first();
        $team = $invitation->team;

        // Guard clause: isolated write, always returns immediately after
        if ($team->hasUser($request->user())) {
            $invitation->delete();
            return redirect()->route('dashboard');
        }

        // Main flow: properly wrapped in transaction
        DB::transaction(function () use ($request, $team, $invitation): void {
            $team->addMember($request->user(), $invitation->role);
            $invitation->delete();
        });

        return redirect()->route('teams.show', $team);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Controllers/InvitationController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_guard_clause_has_else_branch(): void
    {
        $code = <<<'PHP'
<?php
namespace App\Http\Controllers;
use App\Models\Team;
use App\Models\Invitation;
use Illuminate\Http\Request;
class InvitationController
{
    public function accept(Request $request, string $token): mixed
    {
        $invitation = Invitation::where('token', $token)->first();
        $team = $invitation->team;

        // NOT a guard clause: has an else branch, so both paths continue
        if ($team->hasUser($request->user())) {
            $invitation->delete();
            return redirect()->route('dashboard');
        } else {
            $invitation->delete();
        }

        $team->save();

        return redirect()->route('teams.show', $team);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Controllers/InvitationController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_passes_with_plain_if_else_one_write_per_branch_no_returns(): void
    {
        // Neither branch has a return — no guard clause — but they're still mutually exclusive.
        $code = <<<'PHP'
<?php
namespace App\Services;
use Illuminate\Support\Facades\DB;
class MemberService
{
    public function upsertMember(string $email): void
    {
        $exists = DB::table('members')->where('email', $email)->exists();

        if (! $exists) {
            DB::table('members')->insert(['email' => $email]);
        } else {
            DB::table('members')->update(['email' => $email]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MemberService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Each branch has exactly 1 write; they can never co-execute → below threshold
        $this->assertPassed($result);
    }

    public function test_flags_else_branch_multiple_writes_in_plain_if_else(): void
    {
        // if-body has 1 write, else-body has 2 writes that can co-execute
        $code = <<<'PHP'
<?php
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;
class MemberController
{
    public function saveMemberAirport(string $email, int $airportId): void
    {
        $exists = DB::table('members')->where('email', $email)->exists();

        if (! $exists) {
            DB::table('members')->insert(['email' => $email, 'airport_id' => $airportId]);
        } else {
            DB::table('members')->update(['airport_id' => $airportId]);
            DB::table('member_custom_airports')->update(['deleted_at' => now()]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Controllers/MemberController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // else branch has 2 co-executable unprotected writes → should flag
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $recommendation = $issues[0]->recommendation;

        // Recommendation should list the else-branch lines, not the if-branch line
        $this->assertStringNotContainsString('insert', $recommendation);
        // Both else-branch update lines should be present
        $this->assertStringContainsString('database write operation', $issues[0]->message);
    }

    public function test_passes_with_plain_if_else_after_else_writes_wrapped_in_transaction(): void
    {
        // The real false-positive scenario: after wrapping the else-branch writes in a
        // transaction, the lone if-branch write (in a mutually exclusive branch) should
        // not keep the method flagged.
        $code = <<<'PHP'
<?php
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;
class MemberController
{
    public function saveMemberAirport(string $email, int $airportId): void
    {
        $exists = DB::table('members')->where('email', $email)->exists();

        if (! $exists) {
            DB::table('members')->insert(['email' => $email, 'airport_id' => $airportId]);
        } else {
            DB::transaction(function () use ($email, $airportId): void {
                DB::table('members')->update(['airport_id' => $airportId]);
                DB::table('member_custom_airports')->update(['deleted_at' => now()]);
            });
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Controllers/MemberController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // if-branch: 1 unprotected write; else-branch: 2 protected writes.
        // Heavier branch by count is else (2), all protected → effective unprotected = 0
        $this->assertPassed($result);
    }

    public function test_passes_with_writes_in_mutually_exclusive_if_else_branches(): void
    {
        // if-body always returns, else-body always returns — only one branch executes per request
        $code = <<<'PHP'
<?php
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;
class MemberController
{
    public function saveMemberEmail(int $id, string $email): mixed
    {
        $member = DB::table('members')->where('id', $id)->first();

        if (! $member) {
            DB::table('members')->insert(['email' => $email]);
            return response()->json(['status' => 'created']);
        } else {
            DB::table('members')->update(['email' => $email]);
            return response()->json(['status' => 'updated']);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Controllers/MemberController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Branches are mutually exclusive — only one write can execute per request
        $this->assertPassed($result);
    }

    public function test_flags_else_branch_with_multiple_writes_in_mutually_exclusive_if_else(): void
    {
        // if-body returns early (1 isolated write), but else has 2 writes that can co-execute
        $code = <<<'PHP'
<?php
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;
class MemberController
{
    public function saveMemberEmail(int $id, string $email): mixed
    {
        $member = DB::table('members')->where('id', $id)->first();

        if (! $member) {
            DB::table('members')->insert(['email' => $email]);
            return response()->json(['status' => 'created']);
        } else {
            DB::table('members')->update(['email' => $email]);
            DB::table('member_logs')->insert(['member_id' => $id, 'action' => 'updated']);
        }

        return response()->json(['status' => 'ok']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Controllers/MemberController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // The else branch has 2 writes that can co-execute without a transaction
        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operation(s) outside transaction protection', $result);
    }

    public function test_passes_with_guard_clause_throw_before_transaction(): void
    {
        $code = <<<'PHP'
<?php
namespace App\Services;
use App\Models\Order;
use Illuminate\Support\Facades\DB;
class OrderService
{
    public function process(int $id): void
    {
        $order = Order::find($id);

        // Guard clause using throw — isolated write
        if ($order->isPaid()) {
            $order->delete();
            throw new \RuntimeException('Order already paid');
        }

        DB::transaction(function () use ($order): void {
            $order->markPaid();
            $order->save();
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_writes_in_private_method_called_from_transaction_closure(): void
    {
        // Mirrors the UserDeletionService pattern: the orchestrator wraps all
        // writes in DB::transaction() by delegating to private helper methods.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\DB;

class UserDeletionService
{
    public function delete(User $user): void
    {
        DB::transaction(function () use ($user): void {
            $this->revokeTokens($user);
            $this->dissolveOwnedTeams($user);
            $user->delete();
        });
    }

    private function revokeTokens(User $user): void
    {
        $user->tokens()->delete();
    }

    private function dissolveOwnedTeams(User $user): void
    {
        DB::table('team_members')->whereIn('team_id', [1])->delete();
        $user->ownedTeams()->delete();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserDeletionService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_flags_private_method_with_writes_called_outside_transaction(): void
    {
        // When the same helper is called both inside AND outside a transaction,
        // the analyzer must still flag it — the outside call path is unprotected.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\DB;

class UserService
{
    public function withTransaction(User $user): void
    {
        DB::transaction(function () use ($user): void {
            $this->doWrites($user);
        });
    }

    public function withoutTransaction(User $user): void
    {
        $this->doWrites($user);
    }

    private function doWrites(User $user): void
    {
        $user->save();
        $user->tokens()->delete();
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

    public function test_passes_when_multiple_private_helpers_all_delegated(): void
    {
        // All private helpers are exclusively called from within the transaction closure.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\DB;

class UserDeletionService
{
    public function delete(User $user): void
    {
        DB::transaction(function () use ($user): void {
            $this->revokeTokens($user);
            $this->dissolveOwnedTeams($user);
            $this->anonymizePii($user);
            $user->delete();
        });
    }

    private function revokeTokens(User $user): void
    {
        $user->tokens()->delete();
    }

    private function dissolveOwnedTeams(User $user): void
    {
        DB::table('team_members')->whereIn('team_id', [1])->delete();
        $user->ownedTeams()->delete();
    }

    private function anonymizePii(User $user): void
    {
        $user->update(['name' => 'Deleted', 'email' => 'deleted@invalid']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserDeletionService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_writes_in_transitively_delegated_private_helper(): void
    {
        // Two-hop delegation: the public orchestrator opens the transaction and
        // delegates to a private helper, which in turn delegates the actual writes
        // to a second private helper. Every path runs inside the transaction.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Account;
use Illuminate\Support\Facades\DB;

class AccountCloser
{
    public function close(Account $account): void
    {
        DB::transaction(function () use ($account): void {
            $this->settleBalances($account);
            $account->delete();
        });
    }

    private function settleBalances(Account $account): void
    {
        $this->writeOffLedger($account);
    }

    private function writeOffLedger(Account $account): void
    {
        DB::table('ledgers')->where('account_id', $account->id)->update(['written_off' => true]);
        $account->entries()->delete();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/AccountCloser.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_writes_in_three_hop_delegated_chain(): void
    {
        // a -> b -> c, all private; the transaction is opened only at the public
        // entry point. Proves the fixed point converges beyond two levels.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Account;
use Illuminate\Support\Facades\DB;

class AccountCloser
{
    public function close(Account $account): void
    {
        DB::transaction(function () use ($account): void {
            $this->stepA($account);
        });
    }

    private function stepA(Account $account): void
    {
        $this->stepB($account);
    }

    private function stepB(Account $account): void
    {
        $this->stepC($account);
    }

    private function stepC(Account $account): void
    {
        $account->update(['status' => 'closed']);
        $account->entries()->delete();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/AccountCloser.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_flags_transitively_delegated_helper_also_reached_without_transaction(): void
    {
        // The helper is reachable transitively from a transaction AND directly from
        // a second entry point that has no transaction. The unprotected path must
        // still be flagged.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Account;
use Illuminate\Support\Facades\DB;

class AccountService
{
    public function closeWithTransaction(Account $account): void
    {
        DB::transaction(function () use ($account): void {
            $this->settle($account);
        });
    }

    public function purgeWithoutTransaction(Account $account): void
    {
        $this->writeOffLedger($account);
    }

    private function settle(Account $account): void
    {
        $this->writeOffLedger($account);
    }

    private function writeOffLedger(Account $account): void
    {
        $account->update(['written_off' => true]);
        $account->entries()->delete();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/AccountService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operation(s) outside transaction protection', $result);
    }

    public function test_flags_helper_delegated_only_through_public_intermediary(): void
    {
        // The transaction wraps a call to a PUBLIC intermediary. Because that
        // intermediary can be invoked externally without a transaction, protection
        // must not propagate to the private leaf it calls.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Account;
use Illuminate\Support\Facades\DB;

class AccountService
{
    public function entry(Account $account): void
    {
        DB::transaction(function () use ($account): void {
            $this->mid($account);
        });
    }

    public function mid(Account $account): void
    {
        $this->leaf($account);
    }

    private function leaf(Account $account): void
    {
        $account->update(['status' => 'closed']);
        $account->entries()->delete();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/AccountService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operation(s) outside transaction protection', $result);
    }

    public function test_passes_with_third_party_static_create_calls(): void
    {
        // Spatie\Sitemap\Tags\Url and Spatie\Sitemap\Sitemap are not Eloquent models.
        // Multiple ::create() calls on them must not trigger the missing-transaction warning.
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers\Marketing;

use App\Http\Controllers\Controller;
use Illuminate\Http\Response;
use Spatie\Sitemap\Sitemap;
use Spatie\Sitemap\Tags\Url;

class SitemapController extends Controller
{
    public function __invoke(): Response
    {
        $sitemap = Sitemap::create()
            ->add(Url::create('/')->setPriority(1.0)->setChangeFrequency(Url::CHANGE_FREQUENCY_WEEKLY))
            ->add(Url::create('/features')->setPriority(0.9)->setChangeFrequency(Url::CHANGE_FREQUENCY_MONTHLY))
            ->add(Url::create('/pricing')->setPriority(0.9)->setChangeFrequency(Url::CHANGE_FREQUENCY_MONTHLY))
            ->add(Url::create('/changelog')->setPriority(0.7)->setChangeFrequency(Url::CHANGE_FREQUENCY_WEEKLY));

        return response($sitemap->render(), 200, ['Content-Type' => 'application/xml']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Controllers/Marketing/SitemapController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_filament_sibling_action_closures(): void
    {
        // Each Filament action closure fires on a different user action / request, so
        // the writes never co-execute and must not be summed across sibling closures.
        $code = <<<'PHP'
<?php

namespace App\Filament\Resources;

use App\Models\Order;
use Filament\Tables\Actions\Action;
use Filament\Tables\Table;

class OrderResource
{
    public function table(Table $table): Table
    {
        return $table
            ->actions([
                Action::make('approve')
                    ->action(function (Order $record) {
                        $record->update(['status' => 'approved']);
                    }),
                Action::make('reject')
                    ->action(function (Order $record) {
                        $record->delete();
                    }),
            ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Filament/Resources/OrderResource.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // One write per independent callback → below threshold → passes.
        $this->assertPassed($result);
    }

    public function test_fails_when_single_action_closure_has_multiple_writes(): void
    {
        // A single closure that performs two writes is a genuine atomicity risk and
        // must still be flagged (guards against over-relaxing the closure scoping).
        $code = <<<'PHP'
<?php

namespace App\Filament\Resources;

use App\Models\Order;
use App\Models\Log;
use Filament\Tables\Actions\Action;
use Filament\Tables\Table;

class OrderResource
{
    public function table(Table $table): Table
    {
        return $table
            ->actions([
                Action::make('approve')
                    ->action(function (Order $record) {
                        $record->update(['status' => 'approved']);
                        Log::create(['action' => 'approved', 'order_id' => $record->id]);
                    }),
            ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Filament/Resources/OrderResource.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operation(s) outside transaction protection', $result);
    }

    public function test_fails_with_main_flow_write_plus_synchronous_closure_write(): void
    {
        // A main-flow write co-executes with a write inside a synchronous closure
        // (each()), so together they exceed the threshold and must be flagged.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;
use App\Models\OrderItem;

class OrderService
{
    public function createOrder(array $data, array $items)
    {
        $order = Order::create($data);

        collect($items)->each(function (array $item) use ($order) {
            OrderItem::create(['order_id' => $order->id] + $item);
        });

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
        $this->assertHasIssueContaining('database write operation(s) outside transaction protection', $result);
    }

    public function test_passes_with_synchronous_closure_inside_transaction(): void
    {
        // Writes inside a synchronous closure that is itself inside DB::transaction()
        // are protected — the closure inherits the enclosing transaction.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;
use App\Models\OrderItem;
use App\Models\Log;
use Illuminate\Support\Facades\DB;

class OrderService
{
    public function createOrder(array $data, array $items)
    {
        return DB::transaction(function () use ($data, $items) {
            $order = Order::create($data);

            collect($items)->each(function (array $item) use ($order) {
                OrderItem::create(['order_id' => $order->id] + $item);
                Log::create(['order_id' => $order->id]);
            });

            return $order;
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_closure_driven_issue_is_located_at_the_closure_not_the_method(): void
    {
        // Mirrors a Filament table() resource: the writes live in an ->action() callback
        // far below the (long) method declaration. The issue must point at the closure,
        // not at the method's signature line.
        $code = <<<'PHP'
<?php

namespace App\Filament\Resources;

use App\Models\Order;
use Filament\Tables\Actions\Action;
use Filament\Tables\Table;

class OrderResource
{
    public function table(Table $table): Table
    {
        return $table
            ->recordActions([
                Action::make('approve')
                    ->action(function (Order $record): void {
                        $record->status = 'approved';
                        $record->save();
                        $record->touch();
                    }),
            ]);
    }
}
PHP;

        // Resolve the expected line dynamically so the assertion is not brittle.
        $closureLine = null;
        $methodLine = null;
        foreach (explode("\n", $code) as $index => $lineText) {
            if (str_contains($lineText, '->action(function')) {
                $closureLine = $index + 1;
            }
            if (str_contains($lineText, 'public function table')) {
                $methodLine = $index + 1;
            }
        }
        $this->assertNotNull($closureLine);
        $this->assertNotNull($methodLine);

        $tempDir = $this->createTempDirectory(['Filament/Resources/OrderResource.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        // The issue points at the closure, not the method signature.
        $this->assertNotNull($issues[0]->location);
        $this->assertSame($closureLine, $issues[0]->location->line);
        $this->assertNotSame($methodLine, $issues[0]->location->line);
        $this->assertStringContainsString('Closure in', $issues[0]->message);
    }

    public function test_passes_with_protected_sibling_and_single_write_sibling(): void
    {
        // One action wraps two writes in a transaction (protected); a sibling action
        // performs a single write. Neither closure is a problem on its own, and they
        // never co-execute, so the method must not be flagged. Guards against mixing
        // the write count of one sibling with the unprotected count of another.
        $code = <<<'PHP'
<?php

namespace App\Filament\Resources;

use App\Models\Quotation;
use App\Models\WorkOrder;
use Filament\Tables\Actions\Action;
use Filament\Tables\Table;
use Illuminate\Support\Facades\DB;

class QuotationResource
{
    public function table(Table $table): Table
    {
        return $table
            ->recordActions([
                Action::make('approve')
                    ->action(function (Quotation $record): void {
                        DB::transaction(function () use ($record): void {
                            $record->update(['client_approved' => 1]);
                            $record->touch();
                        });
                    }),
                Action::make('work_order')
                    ->action(function (Quotation $record, array $data): void {
                        WorkOrder::create($data);
                    }),
            ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Filament/Resources/QuotationResource.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_filament_filter_toggle_as_write(): void
    {
        // Filament's Filter::make('x')->...->toggle() configures a UI toggle filter;
        // it is not an Eloquent relationship toggle and must not count as a DB write.
        $code = <<<'PHP'
<?php

namespace App\Filament\Resources;

use App\Models\WorkOrder;
use Filament\Tables\Actions\Action;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class QuotationResource
{
    public function table(Table $table): Table
    {
        return $table
            ->filters([
                Filter::make('approved')
                    ->query(fn (Builder $query): Builder => $query->where('approved', 1))
                    ->toggle(),
            ])
            ->recordActions([
                Action::make('work_order')
                    ->action(function (array $data): void {
                        WorkOrder::create($data);
                    }),
            ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Filament/Resources/QuotationResource.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_detects_real_relationship_toggle_on_model(): void
    {
        // A genuine Eloquent relationship toggle/attach (rooted on a model instance,
        // not a ::make() builder) must still be flagged.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class RoleService
{
    public function manageRoles(User $user, array $roleIds, array $permIds): void
    {
        $user->roles()->toggle($roleIds);
        $user->permissions()->attach($permIds);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/RoleService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operation(s) outside transaction protection', $result);
    }

    public function test_recognises_connection_scoped_transaction(): void
    {
        $code = <<<'PHP'
<?php
namespace App\Services;
use App\Models\Order;
use Illuminate\Support\Facades\DB;
class Svc {
    public function place(array $data) {
        return DB::connection('tenant')->transaction(function () use ($data) {
            $order = Order::create($data);
            $order->items()->create(['sku' => 'x']);
            $order->save();
            return $order;
        });
    }
}
PHP;
        $tempDir = $this->createTempDirectory(['Svc.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);
        $this->assertPassed($analyzer->analyze());
    }

    public function test_ignores_storage_disk_held_in_a_variable(): void
    {
        $code = <<<'PHP'
<?php
namespace App\Services;
use Illuminate\Support\Facades\Storage;
class A {
    public function purge(array $paths) {
        $disk = Storage::disk('s3');
        $disk->delete($paths[0]);
        $disk->delete($paths[1]);
    }
}
PHP;
        $tempDir = $this->createTempDirectory(['A.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);
        $this->assertPassed($analyzer->analyze());
    }

    public function test_ignores_injected_cache_client(): void
    {
        $code = <<<'PHP'
<?php
namespace App\Services;
class B {
    public function __construct(private \Psr\SimpleCache\CacheInterface $cache) {}
    public function forget(string $a, string $b) {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP;
        $tempDir = $this->createTempDirectory(['B.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);
        $this->assertPassed($analyzer->analyze());
    }

    public function test_recognises_connection_scoped_manual_transaction(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;
use Illuminate\Support\Facades\DB;

class LedgerService
{
    public function settle(array $data)
    {
        DB::connection('tenant')->beginTransaction();

        try {
            Order::create($data);
            Order::where('id', $data['id'])->update(['settled' => true]);

            DB::connection('tenant')->commit();
        } catch (\Throwable $e) {
            DB::connection('tenant')->rollBack();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LedgerService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_recognises_connection_scoped_transaction_for_delegated_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;
use Illuminate\Support\Facades\DB;

class ShipmentService
{
    public function ship(array $data)
    {
        return DB::connection('tenant')->transaction(function () use ($data) {
            return $this->persist($data);
        });
    }

    private function persist(array $data)
    {
        $order = Order::create($data);
        $order->save();

        return $order;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ShipmentService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_still_flags_connection_scoped_writes_outside_a_transaction(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

class TenantProvisioner
{
    public function provision(array $data)
    {
        DB::connection('tenant')->table('accounts')->insert($data);
        DB::connection('tenant')->table('audit_log')->insert(['event' => 'provisioned']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/TenantProvisioner.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    public function test_still_flags_model_held_in_a_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class AccountCloser
{
    public function close(int $id)
    {
        $user = User::find($id);
        $user->save();
        $user->tokens()->delete();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/AccountCloser.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    public function test_still_flags_injected_model_property(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class ProfileSyncer
{
    private User $model;

    public function sync()
    {
        $this->model->save();
        $this->model->touch();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProfileSyncer.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    public function test_still_flags_model_whose_name_matches_a_non_db_facade(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Session;

class SessionReaper
{
    public function expire(int $id, string $ip)
    {
        $session = Session::find($id);
        $session->update(['ip' => $ip]);
        $session->delete();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/SessionReaper.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    public function test_ignores_cache_client_after_an_anonymous_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

class Handler
{
    public function __construct(private Repository $cache) {}

    public function run(string $a, string $b)
    {
        $rule = new class
        {
            public function passes(): bool
            {
                return true;
            }
        };

        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Handler.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_ignores_imported_cache_client_declared_as_a_property(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

class TagFlusher
{
    private Repository $cache;

    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/TagFlusher.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_ignores_cache_client_injected_into_a_trait(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Concerns;

use Illuminate\Contracts\Cache\Repository;

trait ManagesCache
{
    private Repository $cache;

    public function flushBoth(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Concerns/ManagesCache.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_still_flags_connection_scoped_raw_statements(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

class TenantPurger
{
    public function purge()
    {
        DB::connection('tenant')->statement('DELETE FROM sessions WHERE expired = 1');
        DB::connection('tenant')->statement('UPDATE accounts SET purged_at = NOW()');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/TenantPurger.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    public function test_still_flags_model_writes_on_a_closure_parameter_shadowing_a_disk(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Storage;

class Syncer
{
    public function sync(array $models)
    {
        $disk = Storage::disk('s3');
        $disk->delete('tmp');

        collect($models)->each(function ($disk) {
            $disk->save();
            $disk->delete();
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Syncer.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    /**
     * A property the class inherits is declared in another node, usually in another file,
     * so the map built from the node being entered has no entry for it. Before #422 the
     * receiver check found no declared type and the cache write was reported.
     */
    public function test_ignores_cache_client_declared_on_a_parent_class(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

abstract class BaseService
{
    protected Repository $cache;
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

class TagService extends BaseService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_ignores_cache_client_declared_two_levels_up(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

abstract class BaseService
{
    protected Repository $cache;
}
PHP,
            'Services/MidService.php' => <<<'PHP'
<?php

namespace App\Services;

abstract class MidService extends BaseService {}
PHP,
            'Services/DeepService.php' => <<<'PHP'
<?php

namespace App\Services;

class DeepService extends MidService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_ignores_filesystem_promoted_on_a_parent_constructor(): void
    {
        $tempDir = $this->createTempDirectory([
            'Jobs/BaseJob.php' => <<<'PHP'
<?php

namespace App\Jobs;

use Illuminate\Contracts\Filesystem\Filesystem;

abstract class BaseJob
{
    public function __construct(protected Filesystem $disk) {}
}
PHP,
            'Jobs/PurgeJob.php' => <<<'PHP'
<?php

namespace App\Jobs;

class PurgeJob extends BaseJob
{
    public function purge(string $a, string $b)
    {
        $this->disk->delete($a);
        $this->disk->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The trait half of the same blind spot. #421 covered a trait that declares the
     * property and does the writing; here the writing happens in the class that uses it.
     */
    public function test_ignores_cache_client_declared_in_a_used_trait(): void
    {
        $tempDir = $this->createTempDirectory([
            'Support/CachesThings.php' => <<<'PHP'
<?php

namespace App\Support;

use Illuminate\Contracts\Cache\Repository;

trait CachesThings
{
    protected Repository $store;
}
PHP,
            'Http/TagController.php' => <<<'PHP'
<?php

namespace App\Http;

use App\Support\CachesThings;

class TagController
{
    use CachesThings;

    public function clear(string $a, string $b)
    {
        $this->store->delete($a);
        $this->store->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_ignores_cache_client_declared_in_a_trait_used_by_a_trait(): void
    {
        $tempDir = $this->createTempDirectory([
            'Support/HoldsCache.php' => <<<'PHP'
<?php

namespace App\Support;

use Illuminate\Contracts\Cache\Repository;

trait HoldsCache
{
    protected Repository $store;
}
PHP,
            'Support/CachesThings.php' => <<<'PHP'
<?php

namespace App\Support;

trait CachesThings
{
    use HoldsCache;
}
PHP,
            'Http/TagController.php' => <<<'PHP'
<?php

namespace App\Http;

use App\Support\CachesThings;

class TagController
{
    use CachesThings;

    public function clear(string $a, string $b)
    {
        $this->store->delete($a);
        $this->store->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_still_flags_model_property_declared_on_a_parent_class(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseSyncer.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

abstract class BaseSyncer
{
    protected User $model;
}
PHP,
            'Services/ProfileSyncer.php' => <<<'PHP'
<?php

namespace App\Services;

class ProfileSyncer extends BaseSyncer
{
    public function sync()
    {
        $this->model->save();
        $this->model->touch();
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    public function test_still_flags_when_a_child_redeclares_an_inherited_cache_property_as_a_model(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

abstract class BaseService
{
    protected Repository $cache;
}
PHP,
            'Services/OverrideService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Models\Post;

class OverrideService extends BaseService
{
    protected Post $cache;

    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    /**
     * Ancestors are looked up by fully qualified name only. Two parents sharing a short
     * name are two different declarations, and the one this child extends holds a model,
     * not a cache client. This pins the lookup against ever falling back to a short-name
     * match, which would hand this child the other BaseService's exemption.
     */
    public function test_still_flags_child_of_a_same_named_parent_in_another_namespace(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

abstract class BaseService
{
    protected Repository $cache;
}
PHP,
            'Billing/BaseService.php' => <<<'PHP'
<?php

namespace App\Billing;

use App\Models\Invoice;

abstract class BaseService
{
    protected Invoice $cache;
}
PHP,
            'Billing/InvoiceService.php' => <<<'PHP'
<?php

namespace App\Billing;

class InvoiceService extends BaseService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    /**
     * PHP could not load this pair, but an AST can express it, and the walk has to
     * terminate rather than follow the parent link back and forth forever.
     */
    public function test_terminates_on_a_class_hierarchy_that_refers_back_to_itself(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/Looping.php' => <<<'PHP'
<?php

namespace App\Services;

class Alpha extends Beta
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}

class Beta extends Alpha {}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    /**
     * A child cannot see what its parent declared private, so the parent's client is not
     * the child's and the writes it makes stay flaggable.
     */
    public function test_a_private_client_on_a_parent_does_not_exempt_the_child(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

abstract class BaseService
{
    private Repository $cache;
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

class TagService extends BaseService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    /**
     * The visibility rule must not swallow the case the fix exists for: a protected
     * client on a parent is visible to the child and still exempts it.
     */
    public function test_a_protected_client_on_a_parent_still_exempts_the_child(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

abstract class BaseService
{
    protected Repository $cache;
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

class TagService extends BaseService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * An anonymous class has no name to be filed under, but its extends clause is on the
     * node, so the ancestors it draws a client from are knowable without a registry key.
     */
    public function test_an_anonymous_class_inherits_the_client_its_parent_declares(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

abstract class BaseService
{
    protected Repository $cache;
}
PHP,
            'Services/Builder.php' => <<<'PHP'
<?php

namespace App\Services;

class Builder
{
    public function build()
    {
        return new class extends BaseService
        {
            public function flush(string $a, string $b)
            {
                $this->cache->delete($a);
                $this->cache->delete($b);
            }
        };
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * PHP resolves a class name without regard to case, so a parent named in a different
     * case than it was declared is the same parent and supplies the same client.
     */
    public function test_a_parent_referenced_with_different_casing_still_supplies_its_client(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

abstract class BaseService
{
    protected Repository $cache;
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

class TagService extends BASESERVICE
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * Two `use` statements on one alias stop name resolution for the whole file, so the
     * classes it declares have no fully qualified name. Filing one under its short name
     * would let an unrelated global-namespace class of that name inherit its client.
     */
    public function test_a_class_whose_imports_collide_is_not_filed_under_its_short_name(): void
    {
        $tempDir = $this->createTempDirectory([
            'Deep/Vault.php' => <<<'PHP'
<?php

namespace App\Deep;

use App\First\Duplicate;
use App\Second\Duplicate;

class Vault
{
    protected \Illuminate\Contracts\Cache\Repository $cache;
}
PHP,
            'Consumer.php' => <<<'PHP'
<?php

class Consumer extends Vault
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    /**
     * Pins the AST tier of the model check, which the namespacedName repair made
     * reachable for a namespaced class for the first time. A model outside App\Models is
     * recognised through its parent chain rather than through the namespace heuristic.
     */
    public function test_a_namespaced_model_is_recognised_through_its_parent_chain(): void
    {
        $tempDir = $this->createTempDirectory([
            'Domain/Order.php' => <<<'PHP'
<?php

namespace App\Domain;

use Illuminate\Database\Eloquent\Model;

class Order extends Model {}
PHP,
            'Domain/OrderService.php' => <<<'PHP'
<?php

namespace App\Domain;

class OrderService
{
    public function handle(array $a, array $b)
    {
        Order::create($a);
        Order::create($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    /**
     * The other half of the same tier: a namespaced class whose parent chain does not
     * reach Model is not a database class, so writes through it are not counted.
     */
    public function test_a_namespaced_non_model_is_not_taken_for_a_database_class(): void
    {
        $tempDir = $this->createTempDirectory([
            'Domain/Ledger.php' => <<<'PHP'
<?php

namespace App\Domain;

class Ledger extends Journal {}

class Journal {}
PHP,
            'Domain/LedgerService.php' => <<<'PHP'
<?php

namespace App\Domain;

class LedgerService
{
    public function handle(array $a, array $b)
    {
        Ledger::create($a);
        Ledger::create($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_an_anonymous_class_method_is_not_folded_into_the_enclosing_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class Svc
{
    public function outer(array $d)
    {
        $x = new class
        {
            public function inner()
            {
                User::create([]);
                User::create([]);
            }
        };

        User::create($d);

        return $x;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Svc.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();

        // The anonymous class's own method is reported; the enclosing method performs one
        // write and must not inherit the two the anonymous class performs.
        $this->assertFailed($result);
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('Svc@anonymous::inner()', $issues[0]->message);
        $this->assertStringContainsString('2 database write', $issues[0]->message);

        // Reported after the class it sits in, not as one of that class's own methods.
        foreach ($issues as $issue) {
            $this->assertStringNotContainsString('"Svc::', $issue->message);
        }
    }

    /**
     * PHP names an anonymous class after its parent as it resolves it, so an imported parent
     * contributes its full name, which is what a stack trace shows for the same class.
     */
    public function test_an_anonymous_class_is_named_after_its_imported_parent(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Invoice;
use App\Support\Handler;

class Billing
{
    public function handler(): object
    {
        return new class extends Handler
        {
            public function close(): void
            {
                Invoice::create([]);
                Invoice::create([]);
            }
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Billing.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        // Asserted from the opening quote, because the short spelling is a substring of the
        // full one.
        $this->assertStringContainsString('Method "App\\Support\\Handler@anonymous::close()"', $issues[0]->message);
    }

    /**
     * A parent the file does not import resolves against the file's namespace, as PHP
     * resolves it.
     */
    public function test_an_anonymous_class_is_named_after_a_parent_in_its_own_namespace(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Invoice;

class Billing
{
    public function handler(): object
    {
        return new class extends BaseHandler
        {
            public function close(): void
            {
                Invoice::create([]);
                Invoice::create([]);
            }
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Billing.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('Method "App\\Services\\BaseHandler@anonymous::close()"', $issues[0]->message);
    }

    /**
     * With no parent, PHP borrows the first interface, resolved the same way: a qualified
     * name is relative to the file's namespace.
     */
    public function test_an_anonymous_class_is_named_after_the_interface_it_implements(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Invoice;

class Billing
{
    public function closer(): object
    {
        return new class implements Contracts\Closer
        {
            public function close(): void
            {
                Invoice::create([]);
                Invoice::create([]);
            }
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Billing.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('Method "App\\Services\\Contracts\\Closer@anonymous::close()"', $issues[0]->message);
    }

    /**
     * A finding attributed to a callback closure names its class the same way.
     */
    public function test_a_closure_in_an_anonymous_class_names_the_resolved_parent(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Invoice;
use App\Support\Handler;

class Billing
{
    public function handler(): object
    {
        return new class extends Handler
        {
            public function table($table)
            {
                return $table->actions([
                    Action::make('close')->action(function () {
                        Invoice::create([]);
                        Invoice::create([]);
                    }),
                ]);
            }
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Billing.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('Closure in "App\\Support\\Handler@anonymous::table()"', $issues[0]->message);
    }

    /**
     * A fully qualified parent is spelled without its leading backslash, as PHP spells it.
     */
    public function test_an_anonymous_class_is_named_after_a_fully_qualified_parent(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Invoice;

class Billing
{
    public function handler(): object
    {
        return new class extends \App\Support\Handler
        {
            public function close(): void
            {
                Invoice::create([]);
                Invoice::create([]);
            }
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Billing.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('Method "App\\Support\\Handler@anonymous::close()"', $issues[0]->message);
    }

    /**
     * In a file with no namespace, an imported parent still contributes its full name and one
     * that is not imported keeps the name as written.
     */
    public function test_an_anonymous_class_in_a_file_without_a_namespace_is_named_after_its_parent(): void
    {
        $code = <<<'PHP'
<?php

use App\Models\Invoice;
use App\Support\Handler;

class Billing
{
    public function handler(): object
    {
        return new class extends Handler
        {
            public function close(): void
            {
                Invoice::create([]);
                Invoice::create([]);
            }
        };
    }

    public function fallback(): object
    {
        return new class extends BaseHandler
        {
            public function close(): void
            {
                Invoice::create([]);
                Invoice::create([]);
            }
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Billing.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
        $messages = implode("\n", array_map(fn ($issue) => $issue->message, $issues));
        $this->assertStringContainsString('Method "App\\Support\\Handler@anonymous::close()"', $messages);
        $this->assertStringContainsString('Method "BaseHandler@anonymous::close()"', $messages);
    }

    public function test_writes_on_both_sides_of_an_anonymous_class_are_still_counted(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class Svc
{
    public function outer(array $d)
    {
        User::create($d);

        $x = new class
        {
            public function inner()
            {
            }
        };

        User::create($d);

        return $x;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Svc.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('Method "Svc::outer()"', $issues[0]->message);
        $this->assertStringContainsString('2 database write', $issues[0]->message);
    }

    public function test_an_anonymous_class_does_not_break_the_enclosing_transaction_closure(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;
use Illuminate\Support\Facades\DB;

class Svc
{
    public function place(array $d)
    {
        return DB::transaction(function () use ($d) {
            $rule = new class
            {
                public function passes(): bool
                {
                    return true;
                }
            };

            Order::create($d);
            Order::create($d);

            return $rule;
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Svc.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_a_delegated_helper_stays_delegated_after_an_anonymous_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;
use Illuminate\Support\Facades\DB;

class Svc
{
    public function place(array $d)
    {
        return DB::transaction(function () use ($d) {
            return $this->build($d);
        });
    }

    private function build(array $d)
    {
        $rule = new class
        {
            public function passes(): bool
            {
                return true;
            }
        };

        $this->persist($d);

        return $rule;
    }

    private function persist(array $d): void
    {
        Order::create($d);
        Order::create($d);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Svc.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * Declaring a class inside a transaction closure does not run its methods there. The
     * object is handed out of the closure, so a helper reached only through one of its methods
     * has no transaction around it.
     */
    public function test_a_helper_called_from_a_class_declared_inside_a_transaction_is_not_delegated(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Invoice;
use Illuminate\Support\Facades\DB;

class Ledger
{
    public function opener(): object
    {
        return DB::transaction(function () {
            return new class
            {
                public function close(): void
                {
                    $this->settle();
                }

                private function settle(): void
                {
                    Invoice::create([]);
                    Invoice::create([]);
                    Invoice::create([]);
                }
            };
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Ledger.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('Method "Ledger@anonymous::settle()"', $issues[0]->message);
    }

    public function test_a_call_after_a_class_declared_inside_a_transaction_is_still_protected(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Invoice;
use Illuminate\Support\Facades\DB;

class Ledger
{
    public function post(): object
    {
        return DB::transaction(function () {
            $receipt = new class
            {
                public function number(): string
                {
                    return 'R-1';
                }
            };

            $this->settle();

            return $receipt;
        });
    }

    private function settle(): void
    {
        Invoice::create([]);
        Invoice::create([]);
        Invoice::create([]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Ledger.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_an_anonymous_class_does_not_detach_a_callback_closure_from_its_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Filament\Resources;

use App\Models\Order;
use Filament\Tables\Actions\Action;
use Filament\Tables\Table;

class OrderResource
{
    public function table(Table $table): Table
    {
        return $table
            ->recordActions([
                Action::make('approve')
                    ->action(function (Order $record): void {
                        $stamp = new class
                        {
                            public function at(): string
                            {
                                return 'now';
                            }
                        };

                        $record->status = $stamp->at();
                        $record->save();
                        $record->touch();
                    }),
            ]);
    }
}
PHP;

        // Resolve the expected line dynamically so the assertion is not brittle.
        $closureLine = null;
        foreach (explode("\n", $code) as $index => $lineText) {
            if (str_contains($lineText, '->action(function')) {
                $closureLine = $index + 1;
            }
        }
        $this->assertNotNull($closureLine);

        $tempDir = $this->createTempDirectory(['Filament/Resources/OrderResource.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('Closure in "OrderResource::table()"', $issues[0]->message);
        $this->assertNotNull($issues[0]->location);
        $this->assertSame($closureLine, $issues[0]->location->line);
    }

    /**
     * A method is one declaration's, not every same-named method's in the file. The outer
     * class's helper is only reached inside a transaction; the anonymous class's own helper of
     * the same name is reached outside one, and only that one is reported.
     */
    public function test_a_helper_stays_delegated_when_another_class_in_the_file_shares_its_name(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Payout;
use Illuminate\Support\Facades\DB;

class PayoutRunner
{
    public function run(): void
    {
        DB::transaction(function () {
            $this->reconcile();
        });
    }

    public function preview(): object
    {
        return new class
        {
            public function show(): void
            {
                $this->reconcile();
            }

            private function reconcile(): void
            {
                Payout::create([]);
                Payout::create([]);
            }
        };
    }

    private function reconcile(): void
    {
        Payout::create([]);
        Payout::create([]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PayoutRunner.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('"PayoutRunner@anonymous::reconcile()"', $issues[0]->message);
    }

    /**
     * The reverse of the above: a call inside a transaction protects the method it reaches,
     * not a same-named public method of another class that nothing in the file calls.
     */
    public function test_a_call_inside_a_transaction_does_not_protect_a_same_named_method_of_another_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Shipment;
use Illuminate\Support\Facades\DB;

class ShipmentBooker
{
    public function book(): void
    {
        DB::transaction(function () {
            $this->reconcile();
        });
    }

    private function reconcile(): void
    {
        Shipment::create([]);
    }
}

class ShipmentAuditor
{
    public function reconcile(): void
    {
        Shipment::create([]);
        Shipment::create([]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ShipmentBooker.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('"ShipmentAuditor::reconcile()"', $issues[0]->message);
    }

    public function test_two_named_classes_in_one_file_keep_separate_verdicts(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Shipment;
use Illuminate\Support\Facades\DB;

class ShipmentBooker
{
    public function book(): void
    {
        DB::transaction(fn () => $this->reconcile());
    }

    private function reconcile(): void
    {
        Shipment::create([]);
        Shipment::create([]);
    }
}

class ShipmentAuditor
{
    public function audit(): void
    {
        $this->reconcile();
    }

    private function reconcile(): void
    {
        Shipment::create([]);
        Shipment::create([]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ShipmentBooker.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('"ShipmentAuditor::reconcile()"', $issues[0]->message);
    }

    /**
     * Both anonymous classes report under the same name, so the name cannot be what tells
     * their methods apart.
     */
    public function test_two_anonymous_classes_in_one_method_keep_separate_verdicts(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Shipment;
use Illuminate\Support\Facades\DB;

class Handlers
{
    public function all(): array
    {
        return [
            new class
            {
                public function handle(): void
                {
                    DB::transaction(fn () => $this->reconcile());
                }

                private function reconcile(): void
                {
                    Shipment::create([]);
                    Shipment::create([]);
                }
            },
            new class
            {
                public function handle(): void
                {
                    $this->reconcile();
                }

                private function reconcile(): void
                {
                    Shipment::create([]);
                    Shipment::create([]);
                }
            },
        ];
    }
}
PHP;

        $line = null;
        foreach (explode("\n", $code) as $index => $lineText) {
            if (str_contains($lineText, 'private function reconcile')) {
                $line = $index + 1;
            }
        }

        $tempDir = $this->createTempDirectory(['Services/Handlers.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertNotNull($issues[0]->location);
        $this->assertSame($line, $issues[0]->location->line);
    }

    /**
     * Two classes of one short name in two namespaces of one file are two classes.
     */
    public function test_same_named_classes_in_two_namespaces_keep_separate_verdicts(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Billing {
    use App\Models\Shipment;
    use Illuminate\Support\Facades\DB;

    class Reconciler
    {
        public function run(): void
        {
            DB::transaction(fn () => $this->reconcile());
        }

        private function reconcile(): void
        {
            Shipment::create([]);
            Shipment::create([]);
        }
    }
}

namespace App\Shipping {
    use App\Models\Shipment;

    class Reconciler
    {
        public function run(): void
        {
            $this->reconcile();
        }

        private function reconcile(): void
        {
            Shipment::create([]);
            Shipment::create([]);
        }
    }
}
PHP;

        $line = null;
        foreach (explode("\n", $code) as $index => $lineText) {
            if (str_contains($lineText, 'private function reconcile')) {
                $line = $index + 1;
            }
        }

        $tempDir = $this->createTempDirectory(['Services/Reconciler.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertNotNull($issues[0]->location);
        $this->assertSame($line, $issues[0]->location->line);
    }

    /**
     * PHP resolves a method name without regard to case.
     */
    public function test_a_call_spelled_in_another_case_still_reaches_the_helper(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Shipment;
use Illuminate\Support\Facades\DB;

class ShipmentBooker
{
    public function book(): void
    {
        DB::transaction(fn () => $this->Reconcile());
    }

    private function reconcile(): void
    {
        Shipment::create([]);
        Shipment::create([]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ShipmentBooker.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * A call reaches a helper the class takes from a trait declared in the same file.
     */
    public function test_a_helper_from_a_trait_in_the_same_file_stays_delegated(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Shipment;
use Illuminate\Support\Facades\DB;

trait Reconciles
{
    private function reconcile(): void
    {
        Shipment::create([]);
        Shipment::create([]);
    }
}

class ShipmentBooker
{
    use Reconciles;

    public function book(): void
    {
        DB::transaction(fn () => $this->reconcile());
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ShipmentBooker.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * A call reaches a helper the class inherits from a parent declared in the same file.
     */
    public function test_a_helper_from_a_parent_in_the_same_file_stays_delegated(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Shipment;
use Illuminate\Support\Facades\DB;

abstract class BaseBooker
{
    protected function reconcile(): void
    {
        Shipment::create([]);
        Shipment::create([]);
    }
}

class ShipmentBooker extends BaseBooker
{
    public function book(): void
    {
        DB::transaction(fn () => $this->reconcile());
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ShipmentBooker.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * `insteadof` hands the method to the trait it names, whatever order the traits are listed
     * in, so the call protects that trait's helper. The one it excludes is never called here.
     */
    public function test_an_insteadof_decides_which_trait_helper_the_call_reaches(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Shipment;
use Illuminate\Support\Facades\DB;

trait ReconcilesLocally
{
    private function reconcile(): void
    {
        Shipment::create([]);
        Shipment::create([]);
    }
}

trait ReconcilesRemotely
{
    private function reconcile(): void
    {
        Shipment::create([]);
        Shipment::create([]);
    }
}

class ShipmentBooker
{
    use ReconcilesLocally, ReconcilesRemotely {
        ReconcilesRemotely::reconcile insteadof ReconcilesLocally;
    }

    public function book(): void
    {
        DB::transaction(fn () => $this->reconcile());
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ShipmentBooker.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('"ReconcilesLocally::reconcile()"', $issues[0]->message);
    }

    /**
     * A method the class declares itself beats every trait method, so an `insteadof` settling
     * the conflict between two traits does not move the call off the class's own helper.
     */
    public function test_an_insteadof_does_not_override_the_class_s_own_helper(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Shipment;
use Illuminate\Support\Facades\DB;

trait ReconcilesLocally
{
    private function reconcile(): void
    {
    }
}

trait ReconcilesRemotely
{
    private function reconcile(): void
    {
    }
}

class ShipmentBooker
{
    use ReconcilesLocally, ReconcilesRemotely {
        ReconcilesRemotely::reconcile insteadof ReconcilesLocally;
    }

    public function book(): void
    {
        DB::transaction(fn () => $this->reconcile());
    }

    private function reconcile(): void
    {
        Shipment::create([]);
        Shipment::create([]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ShipmentBooker.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * `$this` in a trait method is the class using it, so the call reaches that class's helper.
     */
    public function test_a_trait_method_reaches_the_helper_of_the_class_using_it(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Shipment;
use Illuminate\Support\Facades\DB;

trait Books
{
    public function book(): void
    {
        DB::transaction(fn () => $this->reconcile());
    }
}

class ShipmentBooker
{
    use Books;

    private function reconcile(): void
    {
        Shipment::create([]);
        Shipment::create([]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ShipmentBooker.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * A parent's call dispatches to the override a subclass in the same file declares.
     */
    public function test_a_parent_call_reaches_the_override_a_child_declares(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Shipment;
use Illuminate\Support\Facades\DB;

abstract class BaseBooker
{
    public function book(): void
    {
        DB::transaction(fn () => $this->reconcile());
    }

    abstract protected function reconcile(): void;
}

class ShipmentBooker extends BaseBooker
{
    protected function reconcile(): void
    {
        Shipment::create([]);
        Shipment::create([]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ShipmentBooker.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * An anonymous subclass is a subclass like any other: the parent's call reaches its override.
     */
    public function test_a_parent_call_reaches_the_override_an_anonymous_subclass_declares(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Shipment;
use Illuminate\Support\Facades\DB;

class ShipmentBooker
{
    public function book(): void
    {
        DB::transaction(fn () => $this->reconcile());
    }

    public function withHistory(): self
    {
        return new class extends ShipmentBooker
        {
            protected function reconcile(): void
            {
                Shipment::create([]);
                Shipment::create([]);
            }
        };
    }

    protected function reconcile(): void
    {
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ShipmentBooker.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * #427 taught the receiver check to find a property declared on a trait the writing
     * class uses. This is the mirror: the trait holds the method and the class using it
     * declares the client, so the trait's own declaration has nothing to look up.
     */
    public function test_ignores_a_cache_client_the_class_using_a_trait_declares(): void
    {
        $tempDir = $this->createTempDirectory([
            'Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use Illuminate\Contracts\Cache\Repository;

class TagService
{
    use FlushesCache;

    protected Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The template method pattern: the base declares the algorithm and the child supplies
     * the collaborator it runs against.
     */
    public function test_ignores_a_cache_client_the_child_of_an_abstract_parent_declares(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

abstract class BaseService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

class TagService extends BaseService
{
    protected Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * A concrete parent has the same gap as an abstract one, so the lookup is not gated on
     * whether the declaration could have been instantiated on its own.
     */
    public function test_ignores_a_cache_client_the_child_of_a_concrete_parent_declares(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

class BaseService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

class TagService extends BaseService
{
    protected Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * A trait's methods are inlined into the class using it and do read its private
     * properties, and a promoted constructor property is the commonest spelling of an
     * injected client, so a private one has to count here.
     */
    public function test_ignores_a_private_cache_client_the_class_using_a_trait_promotes(): void
    {
        $tempDir = $this->createTempDirectory([
            'Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use Illuminate\Contracts\Cache\Repository;

class TagService
{
    use FlushesCache;

    public function __construct(private Repository $cache) {}
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_ignores_a_cache_client_declared_two_levels_below_a_trait(): void
    {
        $tempDir = $this->createTempDirectory([
            'Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;

abstract class BaseService
{
    use FlushesCache;
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

class TagService extends BaseService
{
    protected Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * Two classes using one trait name the same collaborator at different cache contracts.
     * Neither reaches the database, so the trait's writes are exempt even though the two
     * declared types are not the same type.
     */
    public function test_ignores_a_client_two_users_of_a_trait_spell_as_different_contracts(): void
    {
        $tempDir = $this->createTempDirectory([
            'Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use Illuminate\Contracts\Cache\Repository;

class TagService
{
    use FlushesCache;

    protected Repository $cache;
}
PHP,
            'Services/PsrService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use Psr\SimpleCache\CacheInterface;

class PsrService
{
    use FlushesCache;

    protected CacheInterface $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The downward mirror of the casing case: a child naming its parent in a different case
     * than the parent was declared still supplies that parent with its client.
     */
    public function test_a_child_referenced_with_different_casing_still_supplies_its_client(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

abstract class BaseService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

class TagService extends BASESERVICE
{
    protected Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The same shape as the exempt trait case with one thing changed: the class using the
     * trait declares the property at a model. The writes are real and stay reported.
     */
    public function test_still_flags_a_model_property_the_class_using_a_trait_declares(): void
    {
        $tempDir = $this->createTempDirectory([
            'Concerns/SavesTwice.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait SavesTwice
{
    public function persist(array $data)
    {
        $this->model->save();
        $this->model->update($data);
    }
}
PHP,
            'Services/Thing.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\SavesTwice;
use App\Models\Widget;

class Thing
{
    use SavesTwice;

    protected Widget $model;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "SavesTwice::persist()"', $result);
    }

    /**
     * One class using the trait declares the property at a cache contract and another at a
     * model, so there is no single answer for the trait's method and no exemption.
     */
    public function test_still_flags_a_trait_method_when_one_user_declares_the_property_as_a_model(): void
    {
        $tempDir = $this->createTempDirectory([
            'Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use Illuminate\Contracts\Cache\Repository;

class TagService
{
    use FlushesCache;

    protected Repository $cache;
}
PHP,
            'Services/RowService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use App\Models\CacheRow;

class RowService
{
    use FlushesCache;

    protected CacheRow $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "FlushesCache::flush()"', $result);
    }

    public function test_still_flags_a_trait_method_whose_property_no_user_declares(): void
    {
        $tempDir = $this->createTempDirectory([
            'Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;

class TagService
{
    use FlushesCache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "FlushesCache::flush()"', $result);
    }

    /**
     * What a declaration says about its own property is the answer, whatever a child says
     * about a property of the same name.
     */
    public function test_a_child_client_does_not_override_the_model_the_parent_declares_itself(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Models\Widget;

abstract class BaseService
{
    protected Widget $cache;

    public function flush(array $data)
    {
        $this->cache->save();
        $this->cache->update($data);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

class TagService extends BaseService
{
    protected Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "BaseService::flush()"', $result);
    }

    /**
     * An anonymous class has no name for the registry to file it under, so it supplies
     * nothing to the parent it extends. It can only ever be a leaf, which is why the
     * registry does not carry the synthetic key it would take to reach one.
     */
    public function test_an_anonymous_subclass_does_not_supply_a_client_to_its_parents_method(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

abstract class BaseService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/Builder.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

class Builder
{
    public function build(Repository $store)
    {
        return new class($store) extends BaseService
        {
            public function __construct(protected Repository $cache) {}
        };
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "BaseService::flush()"', $result);
    }

    /**
     * Alpha and Beta each name the other as their parent, so walking inwards from the trait
     * they both draw from reaches Alpha, then Beta, then Alpha again. An AST can express that
     * even though PHP could not load it, and the walk has to stop rather than circle.
     *
     * The trait carries a second method whose writes nothing exempts, so the run has to report
     * that one. Terminating by throwing would be swallowed by the per-file catch in
     * runAnalysis() and would leave the file contributing nothing, which a bare assertPassed
     * could not tell apart from the walk having worked.
     */
    public function test_terminates_on_a_reverse_hierarchy_that_refers_back_to_itself(): void
    {
        $tempDir = $this->createTempDirectory([
            'Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

use App\Models\Widget;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }

    public function persist(Widget $widget, array $data)
    {
        $widget->save();
        $widget->update($data);
    }
}
PHP,
            'Services/Looping.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use Illuminate\Contracts\Cache\Repository;

class Alpha extends Beta
{
    use FlushesCache;
}

class Beta extends Alpha
{
    protected Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // The cycle resolved and exempted flush(); persist() is the file's one real finding,
        // which also proves the file was analysed rather than abandoned.
        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('Method "FlushesCache::persist()"', $result);
    }

    /**
     * A user of the trait that leaves the property untyped cannot say what it holds, and a
     * property nobody can put a type to is not a property everybody agrees is a client.
     */
    public function test_still_flags_a_trait_method_when_one_user_leaves_the_property_untyped(): void
    {
        $tempDir = $this->createTempDirectory([
            'Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use Illuminate\Contracts\Cache\Repository;

class TagService
{
    use FlushesCache;

    protected Repository $cache;
}
PHP,
            'Services/RowService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use App\Models\CacheRow;

class RowService
{
    use FlushesCache;

    protected $cache;

    public function __construct(CacheRow $row)
    {
        $this->cache = $row;
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "FlushesCache::flush()"', $result);
    }

    /**
     * A union type is no more resolvable to one client than no type is, so it dissents the
     * same way.
     */
    public function test_still_flags_a_trait_method_when_one_user_gives_the_property_a_union_type(): void
    {
        $tempDir = $this->createTempDirectory([
            'Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use Illuminate\Contracts\Cache\Repository;

class TagService
{
    use FlushesCache;

    protected Repository $cache;
}
PHP,
            'Services/RowService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use App\Models\CacheRow;
use Illuminate\Contracts\Cache\Repository;

class RowService
{
    use FlushesCache;

    protected CacheRow|Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "FlushesCache::flush()"', $result);
    }

    /**
     * The dissenting user declares nothing itself and picks the model up from a second
     * trait. What it sees for the property is still a model, so it still dissents.
     */
    public function test_still_flags_a_trait_method_when_one_user_takes_the_property_from_another_trait(): void
    {
        $tempDir = $this->createTempDirectory([
            'Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Concerns/HasCacheRow.php' => <<<'PHP'
<?php

namespace App\Concerns;

use App\Models\CacheRow;

trait HasCacheRow
{
    protected CacheRow $cache;
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use Illuminate\Contracts\Cache\Repository;

class TagService
{
    use FlushesCache;

    protected Repository $cache;
}
PHP,
            'Services/RowService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\FlushesCache;
use App\Concerns\HasCacheRow;

class RowService
{
    use FlushesCache;
    use HasCacheRow;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "FlushesCache::flush()"', $result);
    }

    /**
     * A parent's method cannot read a child's private property. What it reads is a dynamic
     * property of the same name, which the parent may itself have put a model in, so the
     * child's private client says nothing about it.
     */
    public function test_still_flags_a_parent_method_when_only_a_child_private_property_names_the_client(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Models\Widget;

abstract class BaseService
{
    public function bind(Widget $widget)
    {
        $this->cache = $widget;
    }

    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

class TagService extends BaseService
{
    private Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "BaseService::flush()"', $result);
    }

    /**
     * The counterpart: every edge on the path is a trait use, so the trait holding the
     * method is inlined into the class all the way down and does read its private property.
     */
    public function test_ignores_a_private_client_reached_through_a_trait_that_uses_another_trait(): void
    {
        $tempDir = $this->createTempDirectory([
            'Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Concerns/ManagesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait ManagesCache
{
    use FlushesCache;
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Concerns\ManagesCache;
use Illuminate\Contracts\Cache\Repository;

class TagService
{
    use ManagesCache;

    private Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The index is built from the files the analysis pass is willing to judge. A test double
     * is not one, so it cannot settle a finding against the production class it extends.
     */
    public function test_a_test_double_does_not_supply_a_client_to_the_class_it_extends(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

abstract class BaseService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'tests/Doubles/FakeService.php' => <<<'PHP'
<?php

namespace Tests\Doubles;

use App\Services\BaseService;
use Illuminate\Contracts\Cache\Repository;

class FakeService extends BaseService
{
    protected Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "BaseService::flush()"', $result);
    }

    /**
     * The same exclusion in the other direction: a double must not withdraw an exemption the
     * production code earns, or adding one would move findings no production edit touched.
     */
    public function test_a_test_double_does_not_withdraw_a_client_a_production_child_supplies(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

abstract class BaseService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

class TagService extends BaseService
{
    protected Repository $cache;
}
PHP,
            'tests/Doubles/RecordingService.php' => <<<'PHP'
<?php

namespace Tests\Doubles;

use App\Models\CacheRow;
use App\Services\BaseService;

class RecordingService extends BaseService
{
    protected CacheRow $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * Seeders and factories are skipped by the analysis pass on the same footing as tests, so
     * they are skipped by the index too.
     */
    public function test_a_seeder_does_not_supply_a_client_to_the_class_it_extends(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

abstract class BaseService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'database/seeders/WarmCacheSeeder.php' => <<<'PHP'
<?php

namespace Database\Seeders;

use App\Services\BaseService;
use Illuminate\Contracts\Cache\Repository;

class WarmCacheSeeder extends BaseService
{
    protected Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "BaseService::flush()"', $result);
    }

    /**
     * One name declared in two files leaves the last declaration standing. The parent the
     * earlier one extended must not go on being answered for by a class that no longer
     * extends it.
     */
    public function test_a_redeclared_class_does_not_supply_a_client_to_the_parent_it_no_longer_extends(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/BaseService.php' => <<<'PHP'
<?php

namespace App\Services;

abstract class BaseService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Services/OtherBase.php' => <<<'PHP'
<?php

namespace App\Services;

abstract class OtherBase
{
}
PHP,
            'a/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Models\CacheRow;

class TagService extends BaseService
{
    protected CacheRow $cache;
}
PHP,
            'b/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Contracts\Cache\Repository;

class TagService extends OtherBase
{
    protected Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "BaseService::flush()"', $result);
    }

    /**
     * One class reached both ways: it uses the trait through a second trait and also extends
     * a class that uses it. The trait is inlined into it either way, so the private client
     * counts, and the longer path through the parent must not leave a second, blinder answer
     * standing beside it.
     */
    public function test_ignores_a_private_client_on_a_class_reached_by_a_trait_and_a_parent(): void
    {
        $tempDir = $this->createTempDirectory([
            'Base/BaseService.php' => <<<'PHP'
<?php

namespace App\Base;

use App\Concerns\FlushesCache;

class BaseService
{
    use FlushesCache;
}
PHP,
            'Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'Concerns/ManagesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait ManagesCache
{
    use FlushesCache;
}
PHP,
            'Services/TagService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Base\BaseService;
use App\Concerns\ManagesCache;
use Illuminate\Contracts\Cache\Repository;

class TagService extends BaseService
{
    use ManagesCache;

    private Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * isDevelopmentFile() matches on a filename suffix as well as a directory, so a class
     * written in the factory pattern trips it. What a class inherits does not depend on
     * where its parent was written, so the walk outwards has to read the file anyway.
     */
    public function test_a_parent_in_a_file_named_like_a_factory_still_supplies_its_client(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Support/GatewayFactory.php' => <<<'PHP'
<?php

namespace App\Support;

use Illuminate\Contracts\Cache\Repository;

abstract class GatewayFactory
{
    protected Repository $cache;
}
PHP,
            'app/Services/StripeGateway.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Support\GatewayFactory;

class StripeGateway extends GatewayFactory
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The same, through a trait, in a file whose name ends the way a seeder's does.
     */
    public function test_a_trait_in_a_file_named_like_a_seeder_still_supplies_its_client(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Jobs/ImportSeeder.php' => <<<'PHP'
<?php

namespace App\Jobs;

use Illuminate\Contracts\Cache\Repository;

trait HoldsCache
{
    protected Repository $cache;
}
PHP,
            'app/Services/Importer.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Jobs\HoldsCache;

class Importer
{
    use HoldsCache;

    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The same as the test double that extends, across a trait edge. A fixture using a trait
     * is the only declaration naming the client, and it does not get to settle a finding
     * against the trait the production code also uses.
     */
    public function test_a_test_double_using_a_trait_does_not_supply_its_client(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Concerns/FlushesCache.php' => <<<'PHP'
<?php

namespace App\Concerns;

trait FlushesCache
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
            'tests/Doubles/FakeTagServiceTest.php' => <<<'PHP'
<?php

namespace App\Tests\Doubles;

use App\Concerns\FlushesCache;
use Illuminate\Contracts\Cache\Repository;

class FakeTagServiceTest
{
    use FlushesCache;

    protected Repository $cache;
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Method "FlushesCache::flush()"', $result);
    }

    /**
     * A property written `?Repository` is a NullableType wrapping the Name, so reading the Name
     * straight off it yields nothing and the property is recorded with no type. An untyped
     * property stays flaggable by design, so the unwrap is the whole of what keeps a nullable
     * client exempt.
     */
    public function test_ignores_a_nullable_cache_client_declared_on_a_parent(): void
    {
        $tempDir = $this->createTempDirectory([
            'Support/BaseReportService.php' => <<<'PHP'
<?php

namespace App\Support;

use Illuminate\Contracts\Cache\Repository;

abstract class BaseReportService
{
    protected ?Repository $cache = null;
}
PHP,
            'Support/ReportService.php' => <<<'PHP'
<?php

namespace App\Support;

class ReportService extends BaseReportService
{
    public function flush(string $a, string $b)
    {
        $this->cache->delete($a);
        $this->cache->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The class a facade chain is judged by sits at the root of the chain, not at the node the
     * write was entered on. Two calls deep is what exercises the walk: with one, the facade is
     * already `$node->var` and the loop never runs, which a mutation confirmed. Every other
     * facade fixture here writes straight off the facade, so nothing else reaches it.
     */
    public function test_ignores_a_cache_facade_reached_through_a_tagged_chain(): void
    {
        $tempDir = $this->createTempDirectory([
            'Support/TagFlusher.php' => <<<'PHP'
<?php

namespace App\Support;

use Illuminate\Support\Facades\Cache;

class TagFlusher
{
    public function flush(string $a, string $b)
    {
        Cache::store('redis')->tags('reports')->delete($a);
        Cache::store('redis')->tags('reports')->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_does_not_write_resolution_into_the_shared_parser_cache(): void
    {
        // This analyzer used to resolve names in a pass of its own, twice over every file. With
        // replaceNodes off the Name survives, but a resolvedName attribute and a namespacedName
        // on the declaration take its place, and parseFile() hands back a shared, mtime-cached
        // tree, so both outlived the run. Collecting imports during each walk writes nothing,
        // and neither of this analyzer's traversers registers ParentConnectingVisitor, so the
        // walk is cache-clean in full rather than in part. Both halves are asserted, so
        // reinstating a resolving pass fails here rather than in whatever later reads it.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function place(array $a, array $b)
    {
        Order::create($a);
        Order::create($b);
    }
}
PHP;

        // Parse first and keep the nodes, so what is inspected afterwards is the very tree the
        // analyzer was handed rather than a second parse of the same file. The cache is keyed
        // by path and mtime with no normalisation, so setPaths() below has to name 'Services'
        // and not '.', or the analyzer would look up '<dir>/./Services/OrderService.php' and
        // get its own entry.
        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);
        $path = $tempDir.'/Services/OrderService.php';
        $ast = $this->parser->parseFile($path);

        /** @var array<int, Node\Expr\StaticCall> $calls */
        $calls = $this->parser->findNodes($ast, Node\Expr\StaticCall::class);
        $this->assertCount(2, $calls);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Services']);

        $result = $analyzer->analyze();

        // A finding rather than a pass, because runAnalysis() swallows a per-file throw and
        // reports a pass: an assertPassed() here would read the same whether the file was
        // walked or never reached, and an untouched tree would then prove nothing.
        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);

        // One entry, or the analyzer parsed a second spelling of the same file and left the
        // tree below pristine for the wrong reason.
        $this->assertSame(1, $this->cachedTreesFor($path));

        /** @var array<int, Node\Expr\StaticCall> $reparsed */
        $reparsed = $this->parser->findNodes($this->parser->parseFile($path), Node\Expr\StaticCall::class);
        $this->assertSame($calls[0], $reparsed[0]);

        $class = $calls[0]->class;
        if (! $class instanceof Node\Name) {
            self::fail('Expected the static call to name a class.');
        }

        $this->assertNull($class->getAttribute('resolvedName'));

        /** @var array<int, Node\Stmt\Class_> $declarations */
        $declarations = $this->parser->findNodes($ast, Node\Stmt\Class_::class);
        $this->assertCount(1, $declarations);
        $this->assertFalse(isset($declarations[0]->namespacedName));

        // The parent half of the claim above. Registering ParentConnectingVisitor on either
        // traverser writes a parent attribute onto every node in the shared tree, which
        // outlives the run exactly as a resolved name would, and the two assertions above
        // would not notice.
        $this->assertFalse($calls[0]->hasAttribute('parent'));
    }

    /**
     * A file whose two `use` statements land on one alias is one PHP would reject. The
     * resolving pass threw on it and the analyzer carried on with the whole file unresolved,
     * after which isLikelyDatabaseClass() could not tell a model from anything else and
     * answered that everything was one. An import table keeps the first spelling and resolves
     * the rest, so the collision costs one alias instead of the file.
     *
     * Both methods are in the one file so that the walk is shown to have run: a pass on a
     * fixture with nothing to find reads the same as a file that was never reached.
     */
    public function test_a_colliding_import_no_longer_makes_every_static_call_a_model(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/Report.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use App\Support\Cache;

class Report
{
    public function build(array $a, array $b)
    {
        \App\Support\Ledger::create($a);
        \App\Support\Ledger::create($b);
    }

    public function record(array $a, array $b)
    {
        \App\Models\Order::create($a);
        \App\Models\Order::create($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Services']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('Report::record()', $result);
    }

    /**
     * The other side of the same degrade. isNonDbFacadeName() matches an unqualified name
     * against the facade short names, which is right for `Storage::` in a file with no
     * namespace and wrong for anything the resolver simply never reached. With the whole file
     * unresolved, a model named after a facade took the exemption and silenced every later
     * write on the variable holding it.
     */
    public function test_a_colliding_import_no_longer_lets_a_model_borrow_a_facade_exemption(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/SessionService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use App\Support\Cache;
use App\Models\Session;

class SessionService
{
    public function touch(array $a, array $b)
    {
        $rows = Session::where('active', true);
        $rows->update($a);
        $rows->update($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Services']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('SessionService::touch()', $result);
    }

    /**
     * The facade was matched on the name as written, so only the bare `DB` spelling counted as
     * a transaction and the writes inside any other spelling were reported as unprotected.
     */
    public function test_recognises_a_fully_qualified_transaction(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/OrderService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function place(array $a, array $b)
    {
        \Illuminate\Support\Facades\DB::transaction(function () use ($a, $b) {
            Order::create($a);
            Order::create($b);
        });
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Services']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_recognises_a_transaction_on_an_aliased_facade(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/LedgerService.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\DB as Database;
use App\Models\Entry;

class LedgerService
{
    public function post(array $a, array $b)
    {
        Database::transaction(function () use ($a, $b) {
            Entry::create($a);
            Entry::create($b);
        });
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Services']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The facade exemption used to be decided on the last segment of the resolved name, so a
     * model sharing a short name with a facade took it and its writes went uncounted. The
     * marking path had always matched the whole name for that reason; the two write paths now
     * agree with it.
     */
    public function test_flags_a_model_whose_short_name_matches_a_facade(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/SessionService.php' => <<<'PHP'
<?php

namespace App\Services;

use App\Models\Session;

class SessionService
{
    public function open(array $a, array $b)
    {
        Session::create($a);
        Session::create($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Services']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('2 database write operation(s)', $result);
    }

    /**
     * A guard, not a proof: this reads the same before the change as after.
     *
     * classMatches() is shared with the analyzers that exempt a much longer list of facades,
     * and taking that list along with the matcher would have quietly exempted Http, Mail, Event
     * and some thirty others here. A chain is where that would show: a static call is gated by
     * isLikelyDatabaseClass() as well, and reflection already answers that Http is not a model,
     * so only the chain path rests on the candidate list alone.
     *
     * The finding itself is arguable, and that is the point of fixing the boundary rather than
     * the list: what this analyzer counts as a write is a separate question from how a class is
     * named, and only the naming was in hand here.
     */
    public function test_a_facade_outside_this_analyzers_list_is_still_counted_in_a_chain(): void
    {
        $tempDir = $this->createTempDirectory([
            'Services/Purger.php' => <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;

class Purger
{
    public function purge(string $a, string $b)
    {
        Http::withToken('t')->delete($a);
        Http::withToken('t')->delete($b);
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Services']);

        $this->assertFailed($analyzer->analyze());
    }
}
