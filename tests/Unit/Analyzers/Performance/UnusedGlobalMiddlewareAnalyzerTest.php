<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Middleware\HandleCors;
use Illuminate\Http\Middleware\TrustHosts;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Routing\Router;
use Mockery;
use ReflectionClass;
use ShieldCI\Analyzers\Performance\UnusedGlobalMiddlewareAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class UnusedGlobalMiddlewareAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<int, string>  $globalMiddleware
     * @param  array<string, mixed>  $configValues
     */
    protected function createAnalyzer(
        array $globalMiddleware = [],
        array $configValues = []
    ): AnalyzerInterface {
        /** @var Application&\Mockery\MockInterface $app */
        $app = Mockery::mock(Application::class);

        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        /** @var Router&\Mockery\MockInterface $router */
        $router = Mockery::mock(Router::class);

        /** @var Kernel&\Mockery\MockInterface $kernel */
        $kernel = Mockery::mock(Kernel::class);

        // Mock the kernel to return global middleware via reflection
        $this->mockKernelMiddleware($kernel, $globalMiddleware);

        // Mock config values
        foreach ($configValues as $key => $value) {
            /** @phpstan-ignore-next-line */
            $config->shouldReceive('get')
                ->with($key, Mockery::any())
                ->andReturn($value);
        }

        // Set default config values if not provided
        if (! isset($configValues['trustedproxy.proxies'])) {
            /** @phpstan-ignore-next-line */
            $config->shouldReceive('get')
                ->with('trustedproxy.proxies')
                ->andReturn(null);
        }

        if (! isset($configValues['cors.paths'])) {
            /** @phpstan-ignore-next-line */
            $config->shouldReceive('get')
                ->with('cors.paths', [])
                ->andReturn([]);
        }

        // Mock app->make() for middleware instantiation
        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->andReturnUsing(function ($class) {
                if ($class === TrustProxies::class) {
                    return new class
                    {
                        /** @var mixed */
                        protected $proxies = null;
                    };
                }

                return new $class;
            });

        return new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
    }

    /**
     * @param  array<int, string>  $middleware
     */
    private function mockKernelMiddleware(Kernel $kernel, array $middleware): void
    {
        // We need to mock the reflection access to the middleware property
        // Create a real Kernel object that we can use reflection on
        $realKernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct()
            {
                // Don't call parent constructor to avoid dependencies
            }

            /** @var array<int, string> */
            protected $middleware = [];

            /**
             * @param  array<int, string>  $middleware
             */
            public function setMiddleware(array $middleware): void
            {
                $this->middleware = $middleware;
            }
        };

        $realKernel->setMiddleware($middleware);

        // Copy the middleware property to the mock
        $reflection = new ReflectionClass($realKernel);
        $property = $reflection->getProperty('middleware');
        $property->setAccessible(true);

        $kernelReflection = new ReflectionClass($kernel);
        try {
            $kernelProperty = $kernelReflection->getProperty('middleware');
            $kernelProperty->setAccessible(true);
            $kernelProperty->setValue($kernel, $middleware);
        } catch (\ReflectionException $e) {
            // Property doesn't exist on mock, define it dynamically
            // This is a limitation of Mockery - we'll work around it differently
        }

        // Since we can't easily set properties on Mockery mocks via reflection,
        // we'll just ensure the kernel is set up properly by extending the real kernel
    }

    public function test_passes_when_no_unused_middleware(): void
    {
        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        // Create a real Kernel instance with no middleware
        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct()
            {
                // Don't call parent to avoid dependencies
            }

            /** @var array<int, string> */
            protected $middleware = [];
        };

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line Mockery mocks passed to constructor */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_trust_proxies_without_configuration(): void
    {
        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        // Create a real Kernel instance with TrustProxies in middleware
        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct()
            {
                // Don't call parent to avoid dependencies
            }

            /** @var array<int, string> */
            protected $middleware = [
                TrustProxies::class,
            ];
        };

        // Mock the TrustProxies middleware with null proxies
        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        // Mock config to return null for trustedproxy.proxies
        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line Mockery mocks passed to constructor */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('TrustProxies', $result);
    }

    public function test_passes_when_trust_proxies_has_configuration(): void
    {
        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct() {}

            /** @var array<int, string> */
            protected $middleware = [
                TrustProxies::class,
            ];
        };

        // Mock TrustProxies with configured proxies
        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = '*';
            });

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line Mockery mocks passed to constructor */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_trust_hosts_without_trust_proxies(): void
    {
        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct() {}

            /** @var array<int, string> */
            protected $middleware = [
                TrustHosts::class,
            ];
        };

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line Mockery mocks passed to constructor */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('TrustHosts', $result);
    }

    public function test_fails_when_cors_without_configuration(): void
    {
        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct() {}

            /** @var array<int, string> */
            protected $middleware = [
                HandleCors::class,
            ];
        };

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line Mockery mocks passed to constructor */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('HandleCors', $result);
    }

    public function test_passes_when_cors_has_configuration(): void
    {
        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct() {}

            /** @var array<int, string> */
            protected $middleware = [
                HandleCors::class,
            ];
        };

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn(['api/*', 'sanctum/csrf-cookie']);

        /** @phpstan-ignore-next-line Mockery mocks passed to constructor */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
