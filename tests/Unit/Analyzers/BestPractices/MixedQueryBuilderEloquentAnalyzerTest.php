<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\MixedQueryBuilderEloquentAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MixedQueryBuilderEloquentAnalyzerTest extends AnalyzerTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        MixedQueryBuilderEloquentAnalyzer::clearRegistryCache();
    }

    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        // Build best-practices config with defaults
        $analyzerConfig = [
            'whitelist' => $config['whitelist'] ?? [],
        ];

        // Add optional config options if provided
        if (array_key_exists('treat_tobase_as_query_builder', $config)) {
            $analyzerConfig['treat_tobase_as_query_builder'] = $config['treat_tobase_as_query_builder'];
        }

        if (array_key_exists('mixing_threshold', $config)) {
            $analyzerConfig['mixing_threshold'] = $config['mixing_threshold'];
        }

        if (array_key_exists('model_paths', $config)) {
            $analyzerConfig['model_paths'] = $config['model_paths'];
        }

        if (array_key_exists('table_mappings', $config)) {
            $analyzerConfig['table_mappings'] = $config['table_mappings'];
        }

        $bestPracticesConfig = [
            'enabled' => true,
            'mixed-query-builder-eloquent' => $analyzerConfig,
        ];

        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => $bestPracticesConfig,
                ],
            ],
        ]);

        return new MixedQueryBuilderEloquentAnalyzer($this->parser, $configRepo);
    }

    public function test_passes_with_only_eloquent(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\User;

class UserRepository
{
    public function findActive()
    {
        return User::where('active', true)->get();
    }

    public function findByEmail($email)
    {
        return User::where('email', $email)->first();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/UserRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_only_query_builder(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use Illuminate\Support\Facades\DB;

class ReportRepository
{
    public function getStatistics()
    {
        return DB::table('orders')
            ->select(DB::raw('DATE(created_at) as date'), DB::raw('COUNT(*) as count'))
            ->groupBy('date')
            ->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/ReportRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_mixed_usage_on_same_table(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\User;
use Illuminate\Support\Facades\DB;

class UserRepository
{
    public function findActive()
    {
        return User::where('active', true)->get();
    }

    public function getUserCount()
    {
        return DB::table('users')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/UserRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
    }

    public function test_detects_significant_mixing(): void
    {
        // Models to register so QB tables count toward threshold
        $orderModel = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class Order extends Model {}
PHP;

        $customerStatModel = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class CustomerStat extends Model
{
    protected $table = 'customer_stats';
}
PHP;

        $orderItemModel = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class OrderItem extends Model
{
    protected $table = 'order_items';
}
PHP;

        $paymentModel = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class Payment extends Model {}
PHP;

        $code = <<<'PHP'
<?php

namespace Services;

use Models\Order;
use Illuminate\Support\Facades\DB;

class OrderService
{
    public function getOrders()
    {
        return Order::all();
    }

    public function getCustomerStats()
    {
        return DB::table('customer_stats')->get();
    }

    public function getOrderItems()
    {
        return DB::table('order_items')->get();
    }

    public function getPayments()
    {
        return DB::table('payments')->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/Order.php' => $orderModel,
            'Models/CustomerStat.php' => $customerStatModel,
            'Models/OrderItem.php' => $orderItemModel,
            'Models/Payment.php' => $paymentModel,
            'Services/OrderService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Services']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_provides_consistency_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\Product;
use Illuminate\Support\Facades\DB;

class ProductRepository
{
    public function findAll()
    {
        return Product::all();
    }

    public function getProductCount()
    {
        return DB::table('products')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/ProductRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('consistent', $issues[0]->recommendation);
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

    public function test_detects_custom_table_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Person extends Model
{
    protected $table = 'people';
}
PHP;

        $repositoryCode = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\Person;
use Illuminate\Support\Facades\DB;

class PersonRepository
{
    public function findAll()
    {
        return Person::all();
    }

    public function getCount()
    {
        return DB::table('people')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/Person.php' => $code,
            'Repositories/PersonRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
    }

    public function test_handles_irregular_pluralization(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\Status;
use Illuminate\Support\Facades\DB;

class StatusRepository
{
    public function findAll()
    {
        return Status::all();
    }

    public function getCount()
    {
        return DB::table('statuses')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/StatusRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
    }

    public function test_respects_suppression_comments(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\User;
use Illuminate\Support\Facades\DB;

/**
 * @shieldci-ignore mixed-query-builder-eloquent
 */
class UserRepository
{
    public function findActive()
    {
        return User::where('active', true)->get();
    }

    public function getUserCount()
    {
        return DB::table('users')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/UserRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_extended_eloquent_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\Order;
use Illuminate\Support\Facades\DB;

class OrderRepository
{
    public function findOrFail($id)
    {
        return Order::findOrFail($id);
    }

    public function createOrUpdate($data)
    {
        return Order::updateOrCreate(['id' => $data['id']], $data);
    }

    public function getRawCount()
    {
        return DB::table('orders')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/OrderRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
    }

    public function test_same_table_mixing_has_high_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\Product;
use Illuminate\Support\Facades\DB;

class ProductRepository
{
    public function findAll()
    {
        return Product::all();
    }

    public function getProductCount()
    {
        return DB::table('products')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/ProductRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));

        // Find the issue about mixing on same table
        $sameTableIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'both Eloquent and Query Builder for table')) {
                $sameTableIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($sameTableIssue, 'Should find same-table mixing issue');
        $this->assertEquals('High', $sameTableIssue->severity->name);
        $this->assertStringContainsString('may bypass global scopes', $sameTableIssue->recommendation);
    }

    public function test_general_suppression_comment_works(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\User;
use Illuminate\Support\Facades\DB;

/**
 * @shieldci-ignore
 */
class UserRepository
{
    public function findActive()
    {
        return User::where('active', true)->get();
    }

    public function getUserCount()
    {
        return DB::table('users')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/UserRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_query_builder_via_model_tobase(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\User;
use Illuminate\Support\Facades\DB;

class UserRepository
{
    public function findActive()
    {
        return User::where('active', true)->get();
    }

    public function getCountWithToBase()
    {
        return User::query()->toBase()->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/UserRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
    }

    public function test_relationship_queries_not_flagged_without_type_inference(): void
    {
        // Note: This test verifies that relationship queries like $user->posts()->where()
        // are NOT flagged because without proper type inference, we cannot reliably
        // determine what model the relationship resolves to. This reduces false positives.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\DB;

class UserService
{
    public function getUserPosts($user)
    {
        return $user->posts()->where('published', true)->get();
    }

    public function getPostCount()
    {
        return DB::table('posts')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Passes because we can't reliably infer that $user->posts() relates to 'posts' table
        // without runtime type information. This avoids false positives.
        $this->assertPassed($result);
    }

    public function test_respects_whitelist_configuration(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\User;
use Illuminate\Support\Facades\DB;

class LegacyReportRepository
{
    public function findActive()
    {
        return User::where('active', true)->get();
    }

    public function getUserCount()
    {
        return DB::table('users')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/LegacyReportRepository.php' => $code]);

        // Create analyzer with whitelist configuration
        $analyzer = $this->createAnalyzer([
            'whitelist' => ['LegacyReportRepository'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_method_chaining_patterns(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;
use Illuminate\Support\Facades\DB;

class OrderService
{
    public function getOrders()
    {
        $query = Order::where('status', 'pending');
        $query->where('verified', true);
        return $query->get();
    }

    public function getRawOrders()
    {
        return DB::table('orders')->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
    }

    public function test_detects_dynamic_model_references(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;
use Illuminate\Support\Facades\DB;

class DynamicQueryService
{
    public function queryModel($modelClass)
    {
        return $modelClass::where('active', true)->get();
    }

    public function getProductCount()
    {
        return DB::table('products')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DynamicQueryService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // This test verifies the analyzer doesn't crash on dynamic references
        // Actual detection is limited without runtime information
        $this->assertTrue($result->getStatus()->name === 'Passed' || $result->getStatus()->name === 'Failed');
    }

    public function test_passes_when_only_relationship_queries_used(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserPostService
{
    public function getUserPosts($user)
    {
        return $user->posts()->where('published', true)->get();
    }

    public function getUserComments($user)
    {
        return $user->comments()->latest()->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserPostService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_factory_or_builder_classes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\DB;

class FactoryService
{
    public function createUser()
    {
        // Factory::create() should not be flagged as model usage
        return Factory::create('user');
    }

    public function buildQuery()
    {
        // Builder::where() should not be flagged as model usage
        return Builder::where('active', true)->get();
    }

    public function getCollection()
    {
        // Collection::where() should not be flagged as model usage
        return Collection::where('active', true)->get();
    }

    public function getUserData()
    {
        return DB::table('users')->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/FactoryService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass - Factory, Builder, Collection are not models
        $this->assertPassed($result);
    }

    public function test_tobase_not_flagged_when_configured(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\User;

class UserRepository
{
    public function findActive()
    {
        return User::where('active', true)->get();
    }

    public function getCountWithToBase()
    {
        // toBase() is used intentionally for performance
        return User::query()->toBase()->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/UserRepository.php' => $code]);

        // Configure to NOT treat toBase as Query Builder usage
        $analyzer = $this->createAnalyzer([
            'treat_tobase_as_query_builder' => false,
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because toBase is not flagged when configured
        $this->assertPassed($result);
    }

    public function test_custom_mixing_threshold(): void
    {
        // Models to register so QB tables count toward threshold
        $orderModel = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class Order extends Model {}
PHP;

        $customerStatModel = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class CustomerStat extends Model
{
    protected $table = 'customer_stats';
}
PHP;

        $orderItemModel = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class OrderItem extends Model
{
    protected $table = 'order_items';
}
PHP;

        $paymentModel = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class Payment extends Model {}
PHP;

        $shipmentModel = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class Shipment extends Model {}
PHP;

        $code = <<<'PHP'
<?php

namespace Services;

use Models\Order;
use Illuminate\Support\Facades\DB;

class OrderService
{
    public function getOrders()
    {
        return Order::all();
    }

    public function getCustomerStats()
    {
        return DB::table('customer_stats')->get();
    }

    public function getOrderItems()
    {
        return DB::table('order_items')->get();
    }

    public function getPayments()
    {
        return DB::table('payments')->get();
    }

    public function getShipments()
    {
        return DB::table('shipments')->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/Order.php' => $orderModel,
            'Models/CustomerStat.php' => $customerStatModel,
            'Models/OrderItem.php' => $orderItemModel,
            'Models/Payment.php' => $paymentModel,
            'Models/Shipment.php' => $shipmentModel,
            'Services/OrderService.php' => $code,
        ]);

        // With default threshold of 2, this would fail (4 QB tables with models > 2)
        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Services']);

        $result = $analyzer->analyze();
        $this->assertFailed($result);

        // With higher threshold, it should pass
        $analyzer2 = $this->createAnalyzer([
            'model_paths' => ['Models'],
            'mixing_threshold' => 5,
        ]);
        $analyzer2->setBasePath($tempDir);
        $analyzer2->setPaths(['Services']);

        $result2 = $analyzer2->analyze();
        $this->assertPassed($result2);
    }

    public function test_variable_tracking_resets_per_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\User;
use App\Models\Product;
use Illuminate\Support\Facades\DB;

class MultiModelRepository
{
    public function getUserQuery()
    {
        // Variable $query tracks User model here
        $query = User::where('active', true);
        return $query->get();
    }

    public function getProductQuery()
    {
        // This $query should NOT inherit User tracking from previous method
        // It's a different scope
        $query = Product::where('available', true);
        return $query->get();
    }

    public function getRawUserData()
    {
        return DB::table('users')->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/MultiModelRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // The issue should only be about users table (Eloquent User + DB::table('users'))
        // Not about product because variable tracking resets per method
        $this->assertFailed($result);

        // Should have exactly 1 issue about the 'users' table mixing
        $issues = $result->getIssues();
        $mixedIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'both Eloquent and Query Builder for table')) {
                $mixedIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($mixedIssue, 'Should detect mixed usage on users table');
        $this->assertStringContainsString('users', $mixedIssue->message);
    }

    public function test_scans_model_with_custom_table_property(): void
    {
        // Model with custom $table property
        $modelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class Person extends Model
{
    protected $table = 'people';
}
PHP;

        // Repository using Person model + DB::table('people')
        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\Person;
use Illuminate\Support\Facades\DB;

class PersonRepository
{
    public function findAll()
    {
        return Person::all();
    }

    public function getCount()
    {
        // Uses 'people' table - should match scanned model
        return DB::table('people')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/Person.php' => $modelCode,
            'Repositories/PersonRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing because Person model has $table = 'people'
        // and DB::table('people') is used
        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
        $this->assertHasIssueContaining('people', $result);
    }

    public function test_str_plural_fallback_for_model_without_table_property(): void
    {
        // Model without custom $table property
        $modelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class Category extends Model
{
    // No $table property - should use Str::plural() => 'categories'
}
PHP;

        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\Category;
use Illuminate\Support\Facades\DB;

class CategoryRepository
{
    public function findAll()
    {
        return Category::all();
    }

    public function getCount()
    {
        // Uses 'categories' table - matches Str::plural('category')
        return DB::table('categories')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/Category.php' => $modelCode,
            'Repositories/CategoryRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing - Str::plural('category') = 'categories'
        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
    }

    public function test_config_table_mapping_overrides_scanning(): void
    {
        // Model with $table = 'scanned_table'
        $modelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class Widget extends Model
{
    protected $table = 'scanned_table';
}
PHP;

        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\Widget;
use Illuminate\Support\Facades\DB;

class WidgetRepository
{
    public function findAll()
    {
        return Widget::all();
    }

    public function getCount()
    {
        // Uses 'config_override_table' - matches config override
        return DB::table('config_override_table')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/Widget.php' => $modelCode,
            'Repositories/WidgetRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
            'table_mappings' => [
                'Models\\Widget' => 'config_override_table',
            ],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Config mapping overrides scanned $table property
        // Widget maps to 'config_override_table', DB::table('config_override_table') matches
        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
    }

    public function test_nested_model_directories_scanned(): void
    {
        // Model in nested directory
        $modelCode = <<<'PHP'
<?php

namespace Models\Admin;

use Illuminate\Database\Eloquent\Model;

class AdminUser extends Model
{
    protected $table = 'admin_users';
}
PHP;

        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\Admin\AdminUser;
use Illuminate\Support\Facades\DB;

class AdminRepository
{
    public function findAll()
    {
        return AdminUser::all();
    }

    public function getCount()
    {
        return DB::table('admin_users')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/Admin/AdminUser.php' => $modelCode,
            'Repositories/AdminRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing - nested model directory is scanned
        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
        $this->assertHasIssueContaining('admin_users', $result);
    }

    public function test_multiple_models_in_registry(): void
    {
        $userModel = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    // Default: users table via Str::plural
}
PHP;

        $personModel = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class Person extends Model
{
    protected $table = 'people';
}
PHP;

        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\User;
use Models\Person;
use Illuminate\Support\Facades\DB;

class MixedRepository
{
    public function findUsers()
    {
        return User::all();
    }

    public function findPeople()
    {
        return Person::all();
    }

    public function getUserCount()
    {
        return DB::table('users')->count();
    }

    public function getPeopleCount()
    {
        return DB::table('people')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/User.php' => $userModel,
            'Models/Person.php' => $personModel,
            'Repositories/MixedRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing on both tables
        $this->assertFailed($result);
        $issues = $result->getIssues();

        // Check for issues mentioning both tables
        $usersIssue = false;
        $peopleIssue = false;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'users')) {
                $usersIssue = true;
            }
            if (str_contains($issue->message, 'people')) {
                $peopleIssue = true;
            }
        }

        $this->assertTrue($usersIssue, 'Should detect mixed usage on users table');
        $this->assertTrue($peopleIssue, 'Should detect mixed usage on people table');
    }

    public function test_detects_chained_tobase_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Repositories;

use App\Models\User;

class UserRepository
{
    public function findActive()
    {
        return User::where('active', true)->get();
    }

    public function getCountWithChainedToBase()
    {
        // Chained method calls before toBase()
        return User::query()
            ->where('active', true)
            ->orderBy('name')
            ->toBase()
            ->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Repositories/UserRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
    }

    public function test_no_mixing_when_tables_differ(): void
    {
        // Model with custom table
        $modelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class Item extends Model
{
    protected $table = 'inventory_items';
}
PHP;

        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\Item;
use Illuminate\Support\Facades\DB;

class ItemRepository
{
    public function findAll()
    {
        // Uses Item model -> 'inventory_items' table
        return Item::all();
    }

    public function getOtherData()
    {
        // Uses different table - no mixing
        return DB::table('other_table')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/Item.php' => $modelCode,
            'Repositories/ItemRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should pass - different tables used
        $this->assertPassed($result);
    }

    public function test_system_tables_without_models_not_counted_toward_threshold(): void
    {
        // This test verifies the fix for false positives: using Eloquent for business models
        // while using Query Builder for system tables (jobs, cache, sessions) should NOT
        // trigger the "significant mixing" warning.

        $userModel = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model {}
PHP;

        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\User;
use Illuminate\Support\Facades\DB;

class UserRepository
{
    public function findActive()
    {
        // Business logic using Eloquent
        return User::where('active', true)->get();
    }

    public function clearOldJobs()
    {
        // System table - no model exists for 'jobs'
        return DB::table('jobs')->where('created_at', '<', now()->subDays(7))->delete();
    }

    public function flushCache()
    {
        // System table - no model exists for 'cache'
        return DB::table('cache')->truncate();
    }

    public function expireSessions()
    {
        // System table - no model exists for 'sessions'
        return DB::table('sessions')->where('last_activity', '<', now()->subHours(24))->delete();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/User.php' => $userModel,
            'Repositories/UserRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should pass - jobs, cache, sessions don't have models so they don't count toward threshold
        $this->assertPassed($result);
    }

    public function test_recognizes_models_extending_custom_base_model(): void
    {
        // BaseModel extends Model
        $baseModelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

abstract class BaseModel extends Model
{
    // Common functionality for all models
}
PHP;

        // User extends BaseModel (not directly Model)
        $userModelCode = <<<'PHP'
<?php

namespace Models;

class User extends BaseModel
{
    protected $table = 'users';
}
PHP;

        // Repository using User model + DB::table('users')
        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\User;
use Illuminate\Support\Facades\DB;

class UserRepository
{
    public function findAll()
    {
        return User::all();
    }

    public function getCount()
    {
        return DB::table('users')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/BaseModel.php' => $baseModelCode,
            'Models/User.php' => $userModelCode,
            'Repositories/UserRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing because User extends BaseModel extends Model
        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
        $this->assertHasIssueContaining('users', $result);
    }

    public function test_handles_deep_inheritance_chains(): void
    {
        // BaseModel extends Model
        $baseModelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

abstract class BaseModel extends Model {}
PHP;

        // TenantModel extends BaseModel
        $tenantModelCode = <<<'PHP'
<?php

namespace Models;

abstract class TenantModel extends BaseModel
{
    // Adds tenant scoping
}
PHP;

        // Post extends TenantModel (3-level deep inheritance)
        $postModelCode = <<<'PHP'
<?php

namespace Models;

class Post extends TenantModel
{
    protected $table = 'posts';
}
PHP;

        // Repository using Post model + DB::table('posts')
        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\Post;
use Illuminate\Support\Facades\DB;

class PostRepository
{
    public function findAll()
    {
        return Post::all();
    }

    public function getCount()
    {
        return DB::table('posts')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/BaseModel.php' => $baseModelCode,
            'Models/TenantModel.php' => $tenantModelCode,
            'Models/Post.php' => $postModelCode,
            'Repositories/PostRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing through deep inheritance chain
        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
        $this->assertHasIssueContaining('posts', $result);
    }

    public function test_handles_multiple_custom_base_models(): void
    {
        // BaseModel extends Model
        $baseModelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

abstract class BaseModel extends Model {}
PHP;

        // SoftDeleteModel extends Model (different base)
        $softDeleteModelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

abstract class SoftDeleteModel extends Model
{
    // Uses soft deletes
}
PHP;

        // User extends BaseModel
        $userModelCode = <<<'PHP'
<?php

namespace Models;

class User extends BaseModel
{
    protected $table = 'users';
}
PHP;

        // Post extends SoftDeleteModel
        $postModelCode = <<<'PHP'
<?php

namespace Models;

class Post extends SoftDeleteModel
{
    protected $table = 'posts';
}
PHP;

        // Repository using both models + DB::table
        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\User;
use Models\Post;
use Illuminate\Support\Facades\DB;

class MixedRepository
{
    public function findUsers()
    {
        return User::all();
    }

    public function findPosts()
    {
        return Post::all();
    }

    public function getUserCount()
    {
        return DB::table('users')->count();
    }

    public function getPostCount()
    {
        return DB::table('posts')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/BaseModel.php' => $baseModelCode,
            'Models/SoftDeleteModel.php' => $softDeleteModelCode,
            'Models/User.php' => $userModelCode,
            'Models/Post.php' => $postModelCode,
            'Repositories/MixedRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing on both tables (each uses different base class)
        $this->assertFailed($result);
        $issues = $result->getIssues();

        $usersIssue = false;
        $postsIssue = false;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'users')) {
                $usersIssue = true;
            }
            if (str_contains($issue->message, 'posts')) {
                $postsIssue = true;
            }
        }

        $this->assertTrue($usersIssue, 'Should detect mixed usage on users table');
        $this->assertTrue($postsIssue, 'Should detect mixed usage on posts table');
    }

    public function test_non_model_classes_not_included_in_registry(): void
    {
        // Service class that does NOT extend Model
        $serviceCode = <<<'PHP'
<?php

namespace Models;

class UserService
{
    protected $table = 'user_services';
}
PHP;

        // Actual model
        $userModelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model {}
PHP;

        // Repository code
        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\User;
use Illuminate\Support\Facades\DB;

class UserRepository
{
    public function findUsers()
    {
        return User::all();
    }

    public function getServiceCount()
    {
        // This should NOT be flagged - UserService is not a model
        return DB::table('user_services')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/UserService.php' => $serviceCode,
            'Models/User.php' => $userModelCode,
            'Repositories/UserRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should pass - UserService is not a model, so user_services table is not in registry
        $this->assertPassed($result);
    }

    public function test_model_extending_authenticatable(): void
    {
        // User extends Authenticatable (common Laravel pattern)
        $userModelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    protected $table = 'users';
}
PHP;

        // Repository using User model + DB::table('users')
        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\User;
use Illuminate\Support\Facades\DB;

class UserRepository
{
    public function findAll()
    {
        return User::all();
    }

    public function getCount()
    {
        return DB::table('users')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/User.php' => $userModelCode,
            'Repositories/UserRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing - User extends Authenticatable which is a known base
        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
    }

    public function test_custom_base_extending_authenticatable(): void
    {
        // BaseUser extends Authenticatable
        $baseUserCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Foundation\Auth\User as Authenticatable;

abstract class BaseUser extends Authenticatable {}
PHP;

        // Admin extends BaseUser
        $adminModelCode = <<<'PHP'
<?php

namespace Models;

class Admin extends BaseUser
{
    protected $table = 'admins';
}
PHP;

        // Repository using Admin model + DB::table('admins')
        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\Admin;
use Illuminate\Support\Facades\DB;

class AdminRepository
{
    public function findAll()
    {
        return Admin::all();
    }

    public function getCount()
    {
        return DB::table('admins')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/BaseUser.php' => $baseUserCode,
            'Models/Admin.php' => $adminModelCode,
            'Repositories/AdminRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing through BaseUser -> Authenticatable chain
        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
        $this->assertHasIssueContaining('admins', $result);
    }

    public function test_detects_table_from_get_table_method(): void
    {
        // Model with getTable() method returning string literal
        $modelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class AuditLog extends Model
{
    public function getTable(): string
    {
        return 'audit_logs';
    }
}
PHP;

        // Repository using AuditLog model + DB::table('audit_logs')
        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\AuditLog;
use Illuminate\Support\Facades\DB;

class AuditLogRepository
{
    public function findAll()
    {
        return AuditLog::all();
    }

    public function getCount()
    {
        return DB::table('audit_logs')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/AuditLog.php' => $modelCode,
            'Repositories/AuditLogRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing because getTable() returns 'audit_logs'
        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
        $this->assertHasIssueContaining('audit_logs', $result);
    }

    public function test_get_table_method_takes_precedence_over_property(): void
    {
        // Model with both $table property and getTable() method
        $modelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class Document extends Model
{
    protected $table = 'wrong_table';

    public function getTable(): string
    {
        return 'documents';
    }
}
PHP;

        // Repository that uses getTable() value (not $table property)
        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\Document;
use Illuminate\Support\Facades\DB;

class DocumentRepository
{
    public function findAll()
    {
        return Document::all();
    }

    public function getCount()
    {
        // Uses 'documents' - should match getTable() return, not $table property
        return DB::table('documents')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/Document.php' => $modelCode,
            'Repositories/DocumentRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing - getTable() returns 'documents', DB::table('documents') matches
        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
        $this->assertHasIssueContaining('documents', $result);
    }

    public function test_dynamic_get_table_falls_back_to_property(): void
    {
        // Model with dynamic getTable() (uses concatenation)
        $modelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class TenantUser extends Model
{
    protected $table = 'tenant_users';

    public function getTable(): string
    {
        return tenant()->id . '_users';
    }
}
PHP;

        // Repository that uses $table property value
        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\TenantUser;
use Illuminate\Support\Facades\DB;

class TenantUserRepository
{
    public function findAll()
    {
        return TenantUser::all();
    }

    public function getCount()
    {
        // Uses $table property fallback since getTable() is dynamic
        return DB::table('tenant_users')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/TenantUser.php' => $modelCode,
            'Repositories/TenantUserRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing - dynamic getTable() falls back to $table='tenant_users'
        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
        $this->assertHasIssueContaining('tenant_users', $result);
    }

    public function test_config_based_get_table_uses_str_plural_fallback(): void
    {
        // Model with config-based getTable() (no $table property)
        $modelCode = <<<'PHP'
<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;

class Setting extends Model
{
    // No $table property

    public function getTable(): string
    {
        return config('database.tables.settings', 'settings');
    }
}
PHP;

        // Repository that uses Str::plural('setting') = 'settings'
        $repositoryCode = <<<'PHP'
<?php

namespace Repositories;

use Models\Setting;
use Illuminate\Support\Facades\DB;

class SettingRepository
{
    public function findAll()
    {
        return Setting::all();
    }

    public function getCount()
    {
        // Uses Str::plural fallback since getTable() is dynamic and no $table property
        return DB::table('settings')->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/Setting.php' => $modelCode,
            'Repositories/SettingRepository.php' => $repositoryCode,
        ]);

        $analyzer = $this->createAnalyzer([
            'model_paths' => ['Models'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Repositories']);

        $result = $analyzer->analyze();

        // Should detect mixing - config() is dynamic, falls back to Str::plural('setting')='settings'
        $this->assertFailed($result);
        $this->assertHasIssueContaining('both Eloquent and Query Builder', $result);
    }
}
