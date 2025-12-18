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
}
