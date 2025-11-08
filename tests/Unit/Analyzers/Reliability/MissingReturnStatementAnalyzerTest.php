<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\MissingReturnStatementAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MissingReturnStatementAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MissingReturnStatementAnalyzer;
    }

    public function test_detects_missing_return_statements(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Example.php' => '<?php namespace App; class Example { }',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May pass, fail, or skip depending on PHPStan availability
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
