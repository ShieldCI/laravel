<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\View;
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

    public function test_fails_when_required_templates_missing(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/welcome.blade.php' => '<html></html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Custom error pages not configured', $result);
    }

    public function test_passes_with_custom_error_pages(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/404.blade.php' => '<html>404</html>',
            'resources/views/errors/500.blade.php' => '<html>500</html>',
            'resources/views/errors/503.blade.php' => '<html>503</html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_error_namespace_is_used(): void
    {
        $tempDir = $this->createTempDirectory([
            'custom/errors/404.blade.php' => '<html>404</html>',
            'custom/errors/500.blade.php' => '<html>500</html>',
            'custom/errors/503.blade.php' => '<html>503</html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);
        View::addNamespace('errors', $tempDir.'/custom/errors');

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
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
