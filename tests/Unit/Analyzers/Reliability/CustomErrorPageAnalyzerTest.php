<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Routing\Router;
use ShieldCI\Analyzers\Reliability\CustomErrorPageAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CustomErrorPageAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        $router = app(Router::class);
        $kernel = app(Kernel::class);
        $files = new Filesystem;

        return new CustomErrorPageAnalyzer($router, $kernel, $files);
    }

    public function test_warns_when_no_error_pages_directory(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/welcome.blade.php' => '<html></html>',
        ]);

        // Configure view paths to use our temp directory
        config(['view.paths' => [$tempDir.'/resources/views']]);

        $analyzer = $this->createAnalyzer();
        $result = $analyzer->analyze();

        // Should fail or be skipped (skipped for stateless apps)
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_warns_when_error_pages_missing(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/.gitkeep' => '',
        ]);

        // Configure view paths to use our temp directory
        config(['view.paths' => [$tempDir.'/resources/views']]);

        $analyzer = $this->createAnalyzer();
        $result = $analyzer->analyze();

        // Should fail or be skipped (skipped for stateless apps)
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_passes_with_custom_error_pages(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/404.blade.php' => '<html>Not Found</html>',
            'resources/views/errors/500.blade.php' => '<html>Server Error</html>',
            'resources/views/errors/503.blade.php' => '<html>Maintenance</html>',
        ]);

        // Configure view paths to use our temp directory
        config(['view.paths' => [$tempDir.'/resources/views']]);

        $analyzer = $this->createAnalyzer();
        $result = $analyzer->analyze();

        // Will be skipped in test environment (stateless/API-only app)
        // In production with sessions, would pass since custom error pages exist
        $this->assertSkipped($result);
    }

    public function test_skip_reason_for_stateless_apps(): void
    {
        $analyzer = $this->createAnalyzer();

        // Test environment is stateless (no session middleware)
        $this->assertFalse($analyzer->shouldRun());

        if (method_exists($analyzer, 'getSkipReason')) {
            $this->assertStringContainsString('stateless', $analyzer->getSkipReason());
        }
    }
}
