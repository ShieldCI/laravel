<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\HelperFunctionAbuseAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class HelperFunctionAbuseAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new HelperFunctionAbuseAnalyzer($this->parser);
    }

    public function test_detects_excessive_helper_usage(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        $user = auth()->user();
        $data = request()->all();
        cache()->put('key', 'value', 3600);
        logger()->info('Order created');
        event(new OrderCreated());
        session()->flash('success', 'Order created');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('helper', $result);
    }

    public function test_passes_with_dependency_injection(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function __construct(
        private OrderService $orders,
        private CacheManager $cache
    ) {}

    public function store(Request $request)
    {
        $user = $request->user();
        $order = $this->orders->create($request->all());
        $this->cache->put('order', $order, 3600);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
