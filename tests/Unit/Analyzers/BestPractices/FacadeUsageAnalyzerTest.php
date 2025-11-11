<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\FacadeUsageAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class FacadeUsageAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new FacadeUsageAnalyzer($this->parser);
    }

    public function test_detects_excessive_facade_usage(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use DB;
use Cache;
use Log;
use Event;
use Mail;
use Queue;

class OrderService
{
    public function processOrder($orderId)
    {
        $order = DB::table('orders')->find($orderId);
        Cache::put("order_{$orderId}", $order, 3600);
        Log::info("Processing order {$orderId}");
        Event::dispatch(new OrderProcessing($order));
        Mail::to($order->customer)->send(new OrderConfirmation($order));
        Queue::push(new GenerateInvoice($order));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('facade', $result);
    }

    public function test_passes_with_dependency_injection(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function __construct(
        private OrderRepository $orders,
        private CacheManager $cache,
        private LoggerInterface $logger
    ) {}

    public function processOrder($orderId)
    {
        $order = $this->orders->find($orderId);
        $this->cache->put("order_{$orderId}", $order, 3600);
        $this->logger->info("Processing order {$orderId}");
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
