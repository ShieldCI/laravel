<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\CognitiveComplexityAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CognitiveComplexityAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CognitiveComplexityAnalyzer($this->parser);
    }

    public function test_detects_high_cognitive_complexity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ComplexProcessor
{
    public function process($data)
    {
        if ($data) {
            foreach ($data as $item) {
                if ($item->isValid()) {
                    for ($i = 0; $i < 10; $i++) {
                        if ($i % 2 === 0) {
                            while ($condition) {
                                if ($nested) {
                                    return true;
                                }
                            }
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
            'app/Services/ComplexProcessor.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('cognitive complexity', $result);
    }

    public function test_passes_with_low_cognitive_complexity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class SimpleProcessor
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
        return array_map(fn($item) => $item->value, $data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/SimpleProcessor.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
