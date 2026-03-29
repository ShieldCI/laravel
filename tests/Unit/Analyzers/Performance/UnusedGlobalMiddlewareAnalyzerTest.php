<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Fruitcake\Cors\HandleCors as FruitcakeHandleCors;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Middleware\HandleCors;
use Illuminate\Http\Middleware\TrustHosts;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Routing\Router;
use Mockery;
use Mockery\MockInterface;
use ReflectionClass;
use ShieldCI\Analyzers\Performance\UnusedGlobalMiddlewareAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
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
        /** @var Application&MockInterface $app */
        $app = Mockery::mock(Application::class);

        /** @var ConfigRepository&MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        /** @var Router&MockInterface $router */
        $router = Mockery::mock(Router::class);

        /** @var Kernel&MockInterface $kernel */
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

    /**
     * Skip the test if running on Laravel 11+, where TrustProxies/TrustHosts checks
     * are intentionally suppressed (they are framework defaults, not user-registered middleware).
     */
    private function skipOnLaravel11(string $reason = ''): void
    {
        if (class_exists(Middleware::class)) {
            $this->markTestSkipped(
                'TrustProxies/TrustHosts checks are suppressed on Laravel 11+'.($reason ? ": $reason" : '.')
            );
        }
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

    public function test_warns_when_trust_proxies_without_configuration(): void
    {
        $this->skipOnLaravel11();
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

        $this->assertWarning($result);
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

    public function test_warns_when_trust_hosts_without_trust_proxies(): void
    {
        $this->skipOnLaravel11();
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

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('TrustHosts', $result);
    }

    public function test_warns_when_cors_without_configuration(): void
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

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('HandleCors', $result);
    }

    public function test_warns_about_trust_hosts_only_when_trust_proxies_unused(): void
    {
        $this->skipOnLaravel11();
        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct() {}

            /** @var array<int, string> */
            protected $middleware = [
                TrustHosts::class,
                TrustProxies::class,
            ];
        };

        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
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

        $this->assertWarning($result);
        $this->assertIssueCount(2, $result);

        $issues = $result->getIssues();
        $classes = array_map(fn ($issue) => $issue->metadata['middleware_class'] ?? null, $issues);
        $this->assertContains(TrustProxies::class, $classes);
        $this->assertContains(TrustHosts::class, $classes);
    }

    public function test_warns_when_fruitcake_cors_without_configuration(): void
    {
        if (! class_exists(FruitcakeHandleCors::class)) {
            $this->markTestSkipped('Fruitcake CORS package not installed');
        }

        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct() {}

            /** @var array<int, string> */
            protected $middleware = [
                /** @phpstan-ignore-next-line Class exists due to skip check above */
                FruitcakeHandleCors::class,
            ];
        };

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        /** @phpstan-ignore-next-line Mockery mocks passed to constructor */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $issues = $result->getIssues();
        $this->assertContains(
            $issues[0]->metadata['middleware_class'] ?? null,
            [FruitcakeHandleCors::class, HandleCors::class]
        );
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

    public function test_passes_when_trust_proxies_has_array_configuration(): void
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

        // Mock TrustProxies with array of IPs
        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = ['192.168.1.1', '10.0.0.0/8'];
            });

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_trust_proxies_configured_via_config(): void
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

        // TrustProxies middleware has null proxies
        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        // But config has proxies configured (Fideloper package pattern)
        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(['192.168.1.1']);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_middleware_instantiation_failure_gracefully(): void
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

        // Mock app->make() to throw exception
        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andThrow(new \Exception('Cannot instantiate'));

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        // Should pass because exception is caught and check is skipped
        $this->assertPassed($result);
    }

    public function test_handles_invalid_config_types_gracefully(): void
    {
        $this->skipOnLaravel11();
        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct() {}

            /** @var array<int, string> */
            protected $middleware = [
                TrustProxies::class,
                HandleCors::class,
            ];
        };

        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        // Return invalid types for config values
        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(12345); // Invalid: should be string, array, or null

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn('not-an-array'); // Invalid: should be array

        /** @phpstan-ignore-next-line */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        // Should warn about both middleware being unused (invalid types treated as null/empty)
        $this->assertWarning($result);
        $this->assertIssueCount(2, $result);
    }

    public function test_warns_when_multiple_middleware_unused(): void
    {
        $this->skipOnLaravel11();
        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct() {}

            /** @var array<int, string> */
            protected $middleware = [
                TrustProxies::class,
                HandleCors::class,
            ];
        };

        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(2, $result);
        $this->assertHasIssueContaining('TrustProxies', $result);
        $this->assertHasIssueContaining('HandleCors', $result);
    }

    public function test_warns_when_all_three_middleware_types_unused(): void
    {
        $this->skipOnLaravel11();
        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct() {}

            /** @var array<int, string> */
            protected $middleware = [
                TrustProxies::class,
                TrustHosts::class,
                HandleCors::class,
            ];
        };

        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(3, $result);

        $issues = $result->getIssues();
        $classes = array_map(fn ($issue) => $issue->metadata['middleware_class'] ?? null, $issues);
        $this->assertContains(TrustProxies::class, $classes);
        $this->assertContains(TrustHosts::class, $classes);
        $this->assertContains(HandleCors::class, $classes);
    }

    public function test_trust_hosts_appears_only_once_when_trust_proxies_unused(): void
    {
        $this->skipOnLaravel11();
        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct() {}

            /** @var array<int, string> */
            protected $middleware = [
                TrustProxies::class,
                TrustHosts::class,
            ];
        };

        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertWarning($result);
        // Should only have 2 issues: TrustProxies and TrustHosts (not duplicate TrustHosts)
        $this->assertIssueCount(2, $result);

        // Verify TrustHosts appears exactly once
        $issues = $result->getIssues();
        $trustHostsCount = collect($issues)->filter(fn ($issue) => ($issue->metadata['middleware_class'] ?? null) === TrustHosts::class)->count();
        $this->assertEquals(1, $trustHostsCount, 'TrustHosts should appear exactly once in the issues list');
    }

    public function test_issue_metadata_includes_all_required_fields(): void
    {
        $this->skipOnLaravel11();
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

        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertArrayHasKey('middleware_class', $issue->metadata);
        $this->assertArrayHasKey('middleware_name', $issue->metadata);
        $this->assertArrayHasKey('reason', $issue->metadata);
        $this->assertEquals(TrustProxies::class, $issue->metadata['middleware_class']);
        $this->assertEquals('TrustProxies', $issue->metadata['middleware_name']);
        $this->assertIsString($issue->metadata['reason']);
        $this->assertStringContainsString('No proxies', $issue->metadata['reason']);
    }

    public function test_result_message_format_includes_count(): void
    {
        $this->skipOnLaravel11();
        $app = Mockery::mock(Application::class);
        $config = Mockery::mock(ConfigRepository::class);
        $router = Mockery::mock(Router::class);

        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct() {}

            /** @var array<int, string> */
            protected $middleware = [
                TrustProxies::class,
                HandleCors::class,
            ];
        };

        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertStringContainsString('Found 2 unused global middleware', $result->getMessage());
    }

    public function test_all_issues_have_low_severity(): void
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
                HandleCors::class,
            ];
        };

        /** @phpstan-ignore-next-line */
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertEquals(Severity::Low, $issue->severity);
        }
    }

    public function test_reports_bootstrap_app_path_on_laravel_11(): void
    {
        if (! class_exists(Middleware::class)) {
            $this->markTestSkipped('bootstrap/app.php path and withMiddleware() recommendations only apply to Laravel 11+.');
        }

        // Create a temp dir that mimics a Laravel 11+ project (no Kernel.php, has bootstrap/app.php)
        $tempDir = sys_get_temp_dir().DIRECTORY_SEPARATOR.'shieldci_test_'.uniqid();
        mkdir($tempDir.DIRECTORY_SEPARATOR.'bootstrap', 0777, true);

        $bootstrapAppContent = <<<'PHP'
<?php

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__.'/../routes/web.php')
    ->withMiddleware(function (Middleware $middleware) {
        //
    })
    ->create();
PHP;
        file_put_contents($tempDir.DIRECTORY_SEPARATOR.'bootstrap'.DIRECTORY_SEPARATOR.'app.php', $bootstrapAppContent);

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

        // Use an anonymous subclass to override getBasePath() since AbstractAnalyzer
        // doesn't expose setBasePath() — only AbstractFileAnalyzer does.
        /** @phpstan-ignore-next-line Anonymous class with dynamic base path */
        $analyzer = new class($app, $config, $router, $kernel, $tempDir) extends UnusedGlobalMiddlewareAnalyzer
        {
            public function __construct(
                Application $app,
                ConfigRepository $config,
                Router $router,
                Kernel $kernel,
                private string $testBasePath
            ) {
                parent::__construct($app, $config, $router, $kernel);
            }

            protected function getBasePath(): string
            {
                return $this->testBasePath;
            }
        };

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        // File path should point to bootstrap/app.php, not a non-existent Kernel.php
        $this->assertNotNull($issue->location);
        $this->assertStringEndsWith('bootstrap'.DIRECTORY_SEPARATOR.'app.php', $issue->location->file);
        // Recommendation should mention withMiddleware, not Kernel.php
        $this->assertStringContainsString('withMiddleware', $issue->recommendation);
        $this->assertStringNotContainsString('Kernel.php', $issue->recommendation);

        // Cleanup
        unlink($tempDir.DIRECTORY_SEPARATOR.'bootstrap'.DIRECTORY_SEPARATOR.'app.php');
        rmdir($tempDir.DIRECTORY_SEPARATOR.'bootstrap');
        rmdir($tempDir);
    }

    public function test_passes_when_mixed_used_and_unused_middleware(): void
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
                HandleCors::class,
            ];
        };

        // TrustProxies is configured
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

        // CORS is not configured
        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        /** @phpstan-ignore-next-line */
        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        // Should only warn about CORS
        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('HandleCors', $result);
    }
}
