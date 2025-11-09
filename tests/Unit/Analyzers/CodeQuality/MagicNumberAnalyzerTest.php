<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\MagicNumberAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MagicNumberAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MagicNumberAnalyzer($this->parser);
    }

    public function test_detects_magic_numbers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PricingService
{
    public function calculateDiscount($price)
    {
        if ($price > 500) {
            return $price * 0.15;
        }

        if ($price > 250) {
            return $price * 0.10;
        }

        return $price * 0.05;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/PricingService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Magic number', $result);
    }

    public function test_passes_with_constants(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PricingService
{
    private const TIER1_THRESHOLD = 500;
    private const TIER1_DISCOUNT = 0.15;

    public function calculateDiscount($price)
    {
        if ($price > self::TIER1_THRESHOLD) {
            return $price * self::TIER1_DISCOUNT;
        }

        return $price;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/PricingService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
