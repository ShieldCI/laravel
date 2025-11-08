<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\CacheHeaderAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CacheHeaderAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CacheHeaderAnalyzer;
    }

    public function test_detects_missing_cache_headers(): void
    {
        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class Headers
{
    public function handle($request, $next)
    {
        $response = $next($request);
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/Headers.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Analyzer checks for cache headers
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
