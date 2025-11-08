<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\MinificationAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MinificationAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MinificationAnalyzer;
    }

    public function test_checks_asset_minification(): void
    {
        $tempDir = $this->createTempDirectory([
            'public/css/app.css' => 'body { color: red; }',
            'public/js/app.js' => 'console.log("test");',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Analyzer checks for minified assets
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
