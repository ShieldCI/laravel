<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\UnusedGlobalMiddlewareAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class UnusedGlobalMiddlewareAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new UnusedGlobalMiddlewareAnalyzer;
    }

    public function test_passes_when_no_unused_middleware(): void
    {
        $kernelCode = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middleware = [
        // No unused middleware
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernelCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_trust_proxies_without_configuration(): void
    {
        $kernelCode = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Http\Middleware\TrustProxies;

class Kernel extends HttpKernel
{
    protected $middleware = [
        TrustProxies::class,
    ];
}
PHP;

        $trustProxiesCode = <<<'PHP'
<?php

namespace App\Http\Middleware;

use Illuminate\Http\Middleware\TrustProxies as Middleware;

class TrustProxies extends Middleware
{
    protected $proxies = null;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernelCode,
            'app/Http/Middleware/TrustProxies.php' => $trustProxiesCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('TrustProxies', $result);
    }

    public function test_passes_when_trust_proxies_has_configuration(): void
    {
        $kernelCode = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Http\Middleware\TrustProxies;

class Kernel extends HttpKernel
{
    protected $middleware = [
        TrustProxies::class,
    ];
}
PHP;

        $trustProxiesCode = <<<'PHP'
<?php

namespace App\Http\Middleware;

use Illuminate\Http\Middleware\TrustProxies as Middleware;

class TrustProxies extends Middleware
{
    protected $proxies = '*';
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernelCode,
            'app/Http/Middleware/TrustProxies.php' => $trustProxiesCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_trust_hosts_without_trust_proxies(): void
    {
        $kernelCode = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Http\Middleware\TrustHosts;

class Kernel extends HttpKernel
{
    protected $middleware = [
        TrustHosts::class,
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernelCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('TrustHosts', $result);
    }

    public function test_fails_when_cors_without_configuration(): void
    {
        $kernelCode = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Http\Middleware\HandleCors;

class Kernel extends HttpKernel
{
    protected $middleware = [
        HandleCors::class,
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernelCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('HandleCors', $result);
    }

    public function test_passes_when_cors_has_configuration(): void
    {
        $kernelCode = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Http\Middleware\HandleCors;

class Kernel extends HttpKernel
{
    protected $middleware = [
        HandleCors::class,
    ];
}
PHP;

        // The pattern looks for "paths" => [ with a quote, so format it correctly
        $corsConfig = <<<'PHP'
<?php

return [
    "paths" => ["api/*", "sanctum/csrf-cookie"],
    "allowed_methods" => ["*"],
    "allowed_origins" => ["*"],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernelCode,
            'config/cors.php' => $corsConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_when_kernel_file_not_found(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Kernel', $result);
    }
}
