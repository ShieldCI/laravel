<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\LoginThrottlingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class LoginThrottlingAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new LoginThrottlingAnalyzer($this->parser);
    }

    public function test_passes_with_throttle_middleware_in_kernel(): void
    {
        $kernelCode = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middlewareAliases = [
        'throttle' => \Illuminate\Routing\Middleware\ThrottleRequests::class,
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernelCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_rate_limiter_usage(): void
    {
        $serviceProvider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\Facades\RateLimiter;

class RouteServiceProvider
{
    public function boot()
    {
        RateLimiter::for('login', function ($request) {
            return Limit::perMinute(5);
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/RouteServiceProvider.php' => $serviceProvider,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_no_login_routes_found(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
