<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\DuplicateCodeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class DuplicateCodeAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new DuplicateCodeAnalyzer($this->parser);
    }

    public function test_detects_duplicate_code(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function processOnlineOrder($order)
    {
        $this->validateOrder($order);
        $this->calculateTax($order);
        $this->applyDiscount($order);
        $this->processPayment($order);
        $this->sendConfirmation($order);

        return $order;
    }

    public function processPhoneOrder($order)
    {
        $this->validateOrder($order);
        $this->calculateTax($order);
        $this->applyDiscount($order);
        $this->processPayment($order);
        $this->sendConfirmation($order);

        return $order;
    }

    private function validateOrder($order) {}
    private function calculateTax($order) {}
    private function applyDiscount($order) {}
    private function processPayment($order) {}
    private function sendConfirmation($order) {}
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
        $this->assertHasIssueContaining('Duplicate', $result);
    }

    public function test_passes_with_unique_code(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUser($id)
    {
        return User::find($id);
    }

    public function createUser($data)
    {
        return User::create($data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
