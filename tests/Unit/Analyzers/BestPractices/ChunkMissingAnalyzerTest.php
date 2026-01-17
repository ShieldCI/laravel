<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\ChunkMissingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ChunkMissingAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ChunkMissingAnalyzer($this->parser);
    }

    public function test_passes_with_chunk_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processAllUsers()
    {
        User::chunk(1000, function ($users) {
            foreach ($users as $user) {
                // Process user
            }
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

    public function test_passes_with_cursor_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function processOrders()
    {
        foreach (Order::cursor() as $order) {
            // Process order
        }
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

    public function test_passes_with_lazy_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function processProducts()
    {
        foreach (Product::lazy() as $product) {
            // Process product
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_all_in_foreach(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processAllUsers()
    {
        foreach (User::all() as $user) {
            // Process user
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('all()', $result);
    }

    public function test_detects_get_in_foreach(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function processOrders()
    {
        foreach (Order::where('status', 'pending')->get() as $order) {
            // Process order
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('get()', $result);
    }

    public function test_detects_query_result_in_foreach(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function updatePrices()
    {
        $products = Product::where('active', true)->get();
        foreach ($products as $product) {
            $product->update(['price' => $product->price * 1.1]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Now detects variable assignment pattern
        $this->assertFailed($result);
        $this->assertHasIssueContaining('variable', $result);
    }

    public function test_provides_chunking_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processUsers()
    {
        foreach (User::all() as $user) {
            // Process
        }
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
        $this->assertStringContainsString('chunk()', $issues[0]->recommendation);
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

    public function test_passes_with_lazy_by_id(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processUsers()
    {
        foreach (User::lazyById() as $user) {
            // Process user
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

    public function test_passes_with_chunk_by_id(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function processOrders()
    {
        Order::chunkById(500, function ($orders) {
            foreach ($orders as $order) {
                // Process order
            }
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

    public function test_passes_with_limit_modifier(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getRecentUsers()
    {
        foreach (User::limit(10)->get() as $user) {
            // Process limited dataset
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

    public function test_passes_with_take_modifier(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function getFeaturedProducts()
    {
        foreach (Product::take(5)->get() as $product) {
            // Process small dataset
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_multiple_issues_in_file(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Order;

class BatchService
{
    public function processBoth()
    {
        foreach (User::all() as $user) {
            // Process user
        }

        foreach (Order::get() as $order) {
            // Process order
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/BatchService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
    }

    public function test_detects_complex_method_chain(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processActiveUsers()
    {
        foreach (User::with('posts')->where('active', true)->orderBy('name')->get() as $user) {
            // Process user
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('get()', $result);
    }

    public function test_passes_with_paginate(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function listUsers()
    {
        foreach (User::where('active', true)->paginate(20) as $user) {
            // Paginated results are memory-safe
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

    public function test_passes_with_simple_paginate(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function listOrders()
    {
        foreach (Order::simplePaginate(15) as $order) {
            // Simple pagination is memory-safe
        }
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

    public function test_passes_with_cursor_paginate(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function listProducts()
    {
        foreach (Product::cursorPaginate(50) as $product) {
            // Cursor pagination is memory-safe
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_find_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getSingleRecords(int $id)
    {
        // These all return single records, not collections
        $user1 = User::find($id);
        $user2 = User::findOrFail($id);
        $user3 = User::where('email', 'test@example.com')->sole();
        $user4 = User::where('email', 'test@example.com')->firstOrFail();
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

    public function test_detects_collection_method_after_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processFilteredUsers()
    {
        // All records loaded into memory, then sorted - should be flagged
        foreach (User::all()->sortBy('name') as $user) {
            // Process user
        }
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

    public function test_detects_collection_filter_after_get(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function processExpensiveProducts()
    {
        // All records loaded, then filtered in memory - should be flagged
        foreach (Product::where('active', true)->get()->filter(fn($p) => $p->price > 100) as $product) {
            // Process product
        }
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

    public function test_grammar_singular_vs_plural(): void
    {
        // Test singular
        $code1 = <<<'PHP'
<?php
namespace App\Services;
use App\Models\User;
class UserService
{
    public function process()
    {
        foreach (User::all() as $user) {}
    }
}
PHP;

        $tempDir1 = $this->createTempDirectory(['Services/UserService.php' => $code1]);
        $analyzer1 = $this->createAnalyzer();
        $analyzer1->setBasePath($tempDir1);
        $analyzer1->setPaths(['.']);
        $result1 = $analyzer1->analyze();

        $this->assertStringContainsString('1 query', $result1->getMessage());
        $this->assertStringNotContainsString('queries', $result1->getMessage());

        // Test plural
        $code2 = <<<'PHP'
<?php
namespace App\Services;
use App\Models\User;
class UserService
{
    public function process()
    {
        foreach (User::all() as $user) {}
        foreach (User::get() as $user) {}
    }
}
PHP;

        $tempDir2 = $this->createTempDirectory(['Services/UserService.php' => $code2]);
        $analyzer2 = $this->createAnalyzer();
        $analyzer2->setBasePath($tempDir2);
        $analyzer2->setPaths(['.']);
        $result2 = $analyzer2->analyze();

        $this->assertStringContainsString('2 queries', $result2->getMessage());
    }
}
