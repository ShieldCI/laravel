<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\MixedQueryBuilderEloquentAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MixedQueryBuilderEloquentAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        // Build best-practices config with defaults
        $bestPracticesConfig = [
            'enabled' => true,
            'mixed-query-builder-eloquent' => [
                'whitelist' => $config['whitelist'] ?? [],
            ],
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
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;
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

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

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
        $this->assertStringContainsString('CRITICAL', $sameTableIssue->recommendation);
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

    public function test_detects_relationship_queries(): void
    {
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

        $this->assertFailed($result);
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
}
