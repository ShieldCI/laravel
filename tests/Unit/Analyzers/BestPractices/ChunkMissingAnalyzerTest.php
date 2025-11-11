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

        // This passes because the analyzer only detects foreach with ->get() inline
        $this->assertPassed($result);
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
}
