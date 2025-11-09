<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\ParameterCountAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ParameterCountAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ParameterCountAnalyzer($this->parser);
    }

    public function test_detects_too_many_parameters(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function createOrder($userId, $productId, $quantity, $address, $city, $zip, $country, $paymentMethod)
    {
        return Order::create(compact('userId', 'productId', 'quantity', 'address', 'city', 'zip', 'country', 'paymentMethod'));
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
        $this->assertHasIssueContaining('parameters', $result);
    }

    public function test_passes_with_dto(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function createOrder(CreateOrderRequest $request)
    {
        return Order::create($request->toArray());
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
