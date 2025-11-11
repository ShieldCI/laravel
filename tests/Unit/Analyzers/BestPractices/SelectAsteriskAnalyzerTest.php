<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\SelectAsteriskAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class SelectAsteriskAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new SelectAsteriskAnalyzer($this->parser);
    }

    public function test_passes_with_explicit_select(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getUsers()
    {
        return User::select(['id', 'name', 'email'])->get();
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

    public function test_detects_all_without_select(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getUsers()
    {
        return User::all();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('without ->select()', $result);
    }

    public function test_detects_get_without_select(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function getProducts()
    {
        return Product::where('active', true)->get();
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

    public function test_detects_first_without_select(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function getOrder($id)
    {
        return Order::find($id);
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

    public function test_provides_performance_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getUsers()
    {
        return User::all();
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
        $this->assertStringContainsString('select', $issues[0]->recommendation);
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
