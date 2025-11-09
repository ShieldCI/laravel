<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\CyclomaticComplexityAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CyclomaticComplexityAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CyclomaticComplexityAnalyzer($this->parser);
    }

    public function test_detects_high_cyclomatic_complexity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderProcessor
{
    public function process($order)
    {
        if ($order->isValid()) {
            if ($order->hasCustomer()) {
                if ($order->customer->isActive()) {
                    foreach ($order->items as $item) {
                        if ($item->inStock()) {
                            if ($item->price > 0) {
                                return true;
                            } elseif ($item->isFree()) {
                                return true;
                            } elseif ($item->onSale()) {
                                return true;
                            }
                        } elseif ($item->canBackorder()) {
                            return true;
                        } elseif ($item->isPreorder()) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
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
        $this->assertHasIssueContaining('cyclomatic complexity', $result);
    }

    public function test_passes_with_low_complexity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class SimpleService
{
    public function process($data)
    {
        if (!$data) {
            return null;
        }

        return $this->transform($data);
    }

    private function transform($data)
    {
        return strtoupper($data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/SimpleService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
