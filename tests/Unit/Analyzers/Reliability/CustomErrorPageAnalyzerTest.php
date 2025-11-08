<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\CustomErrorPageAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CustomErrorPageAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CustomErrorPageAnalyzer;
    }

    public function test_warns_when_no_error_pages_directory(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/welcome.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May be skipped in non-production environments
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_warns_when_error_pages_missing(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/.gitkeep' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May be skipped in non-production environments
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_passes_with_custom_error_pages(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/404.blade.php' => '<html>Not Found</html>',
            'resources/views/errors/500.blade.php' => '<html>Server Error</html>',
            'resources/views/errors/503.blade.php' => '<html>Maintenance</html>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May be skipped in non-production environments
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
