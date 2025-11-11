<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\MixedQueryBuilderEloquentAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MixedQueryBuilderEloquentAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MixedQueryBuilderEloquentAnalyzer($this->parser);
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
}
