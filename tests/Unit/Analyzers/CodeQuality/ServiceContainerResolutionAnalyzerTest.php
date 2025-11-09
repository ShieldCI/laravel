<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\ServiceContainerResolutionAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ServiceContainerResolutionAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ServiceContainerResolutionAnalyzer($this->parser);
    }

    public function test_detects_manual_service_resolution(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderProcessor
{
    public function process($orderId)
    {
        $repository = app(OrderRepository::class);
        $payment = resolve(PaymentGateway::class);
        $mailer = App::make('mailer');

        $order = $repository->find($orderId);
        $result = $payment->charge($order);
        $mailer->send(new OrderConfirmation($order));

        return $result;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderProcessor.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('service resolution', $result);
    }

    public function test_passes_with_constructor_injection(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderProcessor
{
    public function __construct(
        private OrderRepository $repository,
        private PaymentGateway $payment,
        private Mailer $mailer
    ) {}

    public function process($orderId)
    {
        $order = $this->repository->find($orderId);
        $result = $this->payment->charge($order);
        $this->mailer->send(new OrderConfirmation($order));

        return $result;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderProcessor.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
