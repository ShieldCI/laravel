<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\MissingModelScopeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MissingModelScopeAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MissingModelScopeAnalyzer($this->parser);
    }

    public function test_passes_with_single_where_clause(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        return User::where('status', 'active')->get();
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

    public function test_detects_repeated_where_chain(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveVerifiedUsers()
    {
        return User::where('status', 'active')->where('verified', true)->get();
    }

    public function getInactiveUsers()
    {
        return User::where('status', 'active')->where('verified', true)->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('appears 2 times', $result);
    }

    public function test_detects_repeated_where_with_different_models(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Post;

class PostService
{
    public function getPublishedPosts()
    {
        return Post::where('status', 'published')->where('deleted_at', null)->get();
    }

    public function countPublishedPosts()
    {
        return Post::where('status', 'published')->where('deleted_at', null)->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PostService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_repeated_or_where_clause(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function getAvailableProducts()
    {
        return Product::where('stock', '>', 0)->orWhere('backorder', true)->get();
    }

    public function searchAvailableProducts($term)
    {
        return Product::where('stock', '>', 0)->orWhere('backorder', true)->where('name', 'like', "%{$term}%")->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_provides_scope_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        return User::where('status', 'active')->where('verified', true)->get();
    }

    public function countActiveUsers()
    {
        return User::where('status', 'active')->where('verified', true)->count();
    }

    public function getActiveUsersByRole($role)
    {
        return User::where('status', 'active')->where('verified', true)->where('role', $role)->get();
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
        $this->assertStringContainsString('scope', $issues[0]->recommendation);
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

    public function test_detects_multiple_repeated_patterns(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function getPaidOrders()
    {
        return Order::where('status', 'paid')->where('processed', false)->get();
    }

    public function countPaidOrders()
    {
        return Order::where('status', 'paid')->where('processed', false)->count();
    }

    public function getShippedOrders()
    {
        return Order::where('status', 'shipped')->where('delivered', false)->get();
    }

    public function countShippedOrders()
    {
        return Order::where('status', 'shipped')->where('delivered', false)->count();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertGreaterThanOrEqual(2, count($result->getIssues()));
    }
}
