<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Fideloper\Proxy\TrustProxies as FideloperTrustProxies;
use Fruitcake\Cors\HandleCors as FruitcakeHandleCors;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Middleware\HandleCors;
use Illuminate\Http\Middleware\TrustHosts;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Routing\Router;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use ReflectionClass;
use ShieldCI\Analyzers\Performance\UnusedGlobalMiddlewareAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
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
            $config->shouldReceive('get')
                ->with($key, Mockery::any())
                ->andReturn($value);
        }

        // Set default config values if not provided
        if (! isset($configValues['trustedproxy.proxies'])) {
            $config->shouldReceive('get')
                ->with('trustedproxy.proxies')
                ->andReturn(null);
        }

        if (! isset($configValues['cors.paths'])) {
            $config->shouldReceive('get')
                ->with('cors.paths', [])
                ->andReturn([]);
        }

        // Mock app->make() for middleware instantiation
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

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_when_trust_proxies_without_configuration(): void
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
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        // Mock config to return null for trustedproxy.proxies
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

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
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = '*';
            });

        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

        $this->assertPassed($result);
    }

    public function test_never_flags_trust_hosts_without_trust_proxies(): void
    {
        // TrustHosts validates the Host header on its own; it never consults TrustProxies,
        // so registering it without TrustProxies leaves nothing unused.
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

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

        $this->assertPassed($result);
        $this->assertIssueCount(0, $result);
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

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('HandleCors', $result);
    }

    public function test_never_flags_trust_hosts_when_trust_proxies_unused(): void
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
                TrustProxies::class,
            ];
        };

        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

        // TrustProxies is still flagged; TrustHosts does not depend on it.
        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);

        $issues = $result->getIssues();
        $classes = array_map(fn ($issue) => $issue->metadata['middleware_class'] ?? null, $issues);
        $this->assertContains(TrustProxies::class, $classes);
        $this->assertNotContains(TrustHosts::class, $classes);
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

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

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

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn(['api/*', 'sanctum/csrf-cookie']);

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
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = ['192.168.1.1', '10.0.0.0/8'];
            });

        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

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
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        // But config has proxies configured (Fideloper package pattern)
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(['192.168.1.1']);

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

        $this->assertPassed($result);
    }

    public function test_warns_when_trust_proxies_cannot_be_instantiated(): void
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

        $makeCalls = 0;
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturnUsing(function () use (&$makeCalls) {
                $makeCalls++;

                throw new \RuntimeException('Cannot instantiate');
            });

        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

        // The only registered middleware was never examined, so this is not a clean pass.
        $this->assertSame(1, $makeCalls);
        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertSame(
            'No unused global middleware detected, but TrustProxies could not be inspected: Cannot instantiate',
            $result->getMessage()
        );
    }

    public function test_passes_when_trust_proxies_configures_proxies_through_the_method(): void
    {
        // The framework reads $this->proxies(), so an app that overrides the method
        // rather than setting the property has configured its proxies.
        $middleware = new class extends TrustProxies
        {
            protected function proxies(): string
            {
                return '*';
            }
        };

        $result = $this->analyzeOnLaravel10(
            $this->analyzerWithTrustProxies(get_class($middleware), fn () => $middleware)
        );

        $this->assertPassed($result);
    }

    /**
     * @dataProvider emptyProxiesProvider
     */
    #[DataProvider('emptyProxiesProvider')]
    public function test_warns_when_trust_proxies_method_returns_nothing(?string $proxies): void
    {
        $middleware = new class($proxies) extends TrustProxies
        {
            public function __construct(private ?string $configured) {}

            protected function proxies(): ?string
            {
                return $this->configured;
            }
        };

        $result = $this->analyzeOnLaravel10(
            $this->analyzerWithTrustProxies(get_class($middleware), fn () => $middleware)
        );

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame(get_class($middleware), $result->getIssues()[0]->metadata['middleware_class'] ?? null);
    }

    /**
     * @return array<string, array{?string}>
     */
    public static function emptyProxiesProvider(): array
    {
        return [
            'null' => [null],
            'empty string' => [''],
        ];
    }

    public function test_warns_when_reading_trust_proxies_throws(): void
    {
        $middleware = new class extends TrustProxies
        {
            protected function proxies(): never
            {
                throw new \RuntimeException('Proxy list unavailable');
            }
        };

        $result = $this->analyzeOnLaravel10(
            $this->analyzerWithTrustProxies(get_class($middleware), fn () => $middleware)
        );

        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertStringEndsWith('could not be inspected: Proxy list unavailable', $result->getMessage());
    }

    public function test_warns_when_the_container_returns_no_object_for_trust_proxies(): void
    {
        $result = $this->analyzeOnLaravel10(
            $this->analyzerWithTrustProxies(TrustProxies::class, fn () => null)
        );

        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertSame(
            'No unused global middleware detected, but TrustProxies could not be inspected: the container did not return an object',
            $result->getMessage()
        );
    }

    public function test_names_the_exception_when_trust_proxies_fails_without_a_message(): void
    {
        $result = $this->analyzeOnLaravel10(
            $this->analyzerWithTrustProxies(TrustProxies::class, function () {
                throw new \RuntimeException('');
            })
        );

        $this->assertWarning($result);
        $this->assertSame(
            'No unused global middleware detected, but TrustProxies could not be inspected: RuntimeException',
            $result->getMessage()
        );
    }

    public function test_passes_without_instantiating_trust_proxies_when_config_sets_proxies(): void
    {
        // The framework falls back to trustedproxy.proxies whatever the instance holds,
        // so a configured value settles the question before the middleware is built.
        $makeCalls = 0;
        $result = $this->analyzeOnLaravel10(
            $this->analyzerWithTrustProxies(TrustProxies::class, function () use (&$makeCalls) {
                $makeCalls++;

                throw new \RuntimeException('boom');
            }, '*')
        );

        $this->assertPassed($result);
        $this->assertSame(0, $makeCalls);
    }

    public function test_warns_when_trust_proxies_cannot_be_instantiated_and_config_sets_none(): void
    {
        $result = $this->analyzeOnLaravel10(
            $this->analyzerWithTrustProxies(TrustProxies::class, function () {
                throw new \RuntimeException('boom');
            })
        );

        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertSame(
            'No unused global middleware detected, but TrustProxies could not be inspected: boom',
            $result->getMessage()
        );
    }

    public function test_names_the_exception_when_trust_proxies_fails_with_a_blank_message(): void
    {
        $result = $this->analyzeOnLaravel10(
            $this->analyzerWithTrustProxies(TrustProxies::class, function () {
                throw new \RuntimeException('   ');
            })
        );

        $this->assertSame(
            'No unused global middleware detected, but TrustProxies could not be inspected: RuntimeException',
            $result->getMessage()
        );
    }

    public function test_names_an_anonymous_exception_without_its_file_path(): void
    {
        $result = $this->analyzeOnLaravel10(
            $this->analyzerWithTrustProxies(TrustProxies::class, function () {
                throw new class('') extends \RuntimeException {};
            })
        );

        $this->assertSame(
            'No unused global middleware detected, but TrustProxies could not be inspected: RuntimeException@anonymous',
            $result->getMessage()
        );
    }

    /**
     * Fideloper's middleware reads the $proxies property and never calls a proxies()
     * method, so one a subclass happens to define must not be consulted. Runs in its own
     * process because the Fideloper stub below would change class_exists() for every
     * later test.
     *
     * @runInSeparateProcess
     *
     * @preserveGlobalState disabled
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function test_reads_the_property_of_a_fideloper_middleware_that_defines_proxies(): void
    {
        if (! class_exists(FideloperTrustProxies::class)) {
            eval('namespace Fideloper\\Proxy; class TrustProxies { protected $config; protected $proxies; public function __construct(\\Illuminate\\Contracts\\Config\\Repository $config) { $this->config = $config; } }');
        }

        // Declared and built through eval() too: PHPStan cannot see the stub, so a class
        // extending it in source is a non-ignorable class.notFound.
        $middleware = eval('namespace ShieldCI\\Tests\\Fixtures\\Fideloper; class ProxiesMethodTrustProxies extends \\Fideloper\\Proxy\\TrustProxies { protected $proxies = \'*\'; public function proxies() { return null; } } return new ProxiesMethodTrustProxies(\\Mockery::mock(\\Illuminate\\Contracts\\Config\\Repository::class));');
        $this->assertIsObject($middleware);

        $result = $this->analyzeOnLaravel10(
            $this->analyzerWithTrustProxies(get_class($middleware), fn () => $middleware)
        );

        $this->assertPassed($result);
    }

    public function test_summary_notes_uninspected_trust_proxies_alongside_findings(): void
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

        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andThrow(new \RuntimeException('Cannot instantiate'));

        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('HandleCors', $result);
        $this->assertSame(
            'Found 1 unused global middleware (TrustProxies could not be inspected: Cannot instantiate)',
            $result->getMessage()
        );
    }

    public function test_handles_invalid_config_types_gracefully(): void
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

        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        // Return invalid types for config values
        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(12345); // Invalid: should be string, array, or null

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn('not-an-array'); // Invalid: should be array

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

        // Should warn about both middleware being unused (invalid types treated as null/empty)
        $this->assertWarning($result);
        $this->assertIssueCount(2, $result);
    }

    public function test_warns_when_multiple_middleware_unused(): void
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

        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

        $this->assertWarning($result);
        $this->assertIssueCount(2, $result);
        $this->assertHasIssueContaining('TrustProxies', $result);
        $this->assertHasIssueContaining('HandleCors', $result);
    }

    public function test_warns_about_trust_proxies_and_cors_but_not_trust_hosts(): void
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
                TrustHosts::class,
                HandleCors::class,
            ];
        };

        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

        $this->assertWarning($result);
        $this->assertIssueCount(2, $result);

        $issues = $result->getIssues();
        $classes = array_map(fn ($issue) => $issue->metadata['middleware_class'] ?? null, $issues);
        $this->assertContains(TrustProxies::class, $classes);
        $this->assertContains(HandleCors::class, $classes);
        $this->assertNotContains(TrustHosts::class, $classes);
    }

    public function test_issue_metadata_includes_all_required_fields(): void
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

        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

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

        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

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

        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = null;
            });

        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertEquals(Severity::Low, $issue->severity);
        }
    }

    public function test_reports_the_bootstrap_app_of_a_new_skeleton_project(): void
    {
        // No runtime version guard: the fixture below decides the answer, so this holds
        // on every row of the Laravel 9-13 matrix rather than only on 11+.
        // Mimics a Laravel 11+ project: bootstrap/app.php, no Kernel.php.
        $tempDir = $this->uniqueTempPath('shieldci_test_');
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

        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        // Use an anonymous subclass to override getBasePath() since AbstractAnalyzer
        // doesn't expose setBasePath() — only AbstractFileAnalyzer does.
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
        $app->shouldReceive('make')
            ->with(TrustProxies::class)
            ->andReturn(new class
            {
                /** @var mixed */
                protected $proxies = '*';
            });

        $config->shouldReceive('get')
            ->with('trustedproxy.proxies')
            ->andReturn(null);

        // CORS is not configured
        $config->shouldReceive('get')
            ->with('cors.paths', [])
            ->andReturn([]);

        $analyzer = new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
        $result = $this->analyzeOnLaravel10($analyzer);

        // Should only warn about CORS
        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('HandleCors', $result);
    }

    // =========================================================================
    // Issue Location — the reported file comes from the scanned project
    // =========================================================================

    public function test_reports_the_http_kernel_when_the_project_has_one(): void
    {
        $dir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $this->kernelFixture(),
        ]);

        $result = $this->withBasePath($dir, fn () => $this->analyzerWithUnusedCors()->analyze());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $location = $issues[0]->location;
        $this->assertNotNull($location);
        $this->assertSame('app/Http/Kernel.php', $location->file);
        $this->assertStringContainsString('app/Http/Kernel.php', $issues[0]->recommendation);
        $this->assertStringNotContainsString('withMiddleware', $issues[0]->recommendation);
    }

    public function test_prefers_the_http_kernel_over_a_legacy_bootstrap_app(): void
    {
        // Laravel <= 10 ships both files. app/Http/Kernel.php holds the middleware
        // stack; bootstrap/app.php is the old `new Application(...)` bootstrapper and
        // holds nothing to edit. Probing bootstrap/app.php first would answer with it.
        $dir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $this->kernelFixture(),
            'bootstrap/app.php' => <<<'PHP'
                <?php

                $app = new Illuminate\Foundation\Application(
                    $_ENV['APP_BASE_PATH'] ?? dirname(__DIR__)
                );

                return $app;
                PHP,
        ]);

        $result = $this->withBasePath($dir, fn () => $this->analyzerWithUnusedCors()->analyze());

        $location = $result->getIssues()[0]->location;
        $this->assertNotNull($location);
        $this->assertSame('app/Http/Kernel.php', $location->file);
    }

    public function test_points_at_the_global_middleware_array_rather_than_line_one(): void
    {
        $dir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $this->kernelFixture(),
        ]);

        $result = $this->withBasePath($dir, fn () => $this->analyzerWithUnusedCors()->analyze());

        $location = $result->getIssues()[0]->location;
        $this->assertNotNull($location);
        $this->assertNotNull($location->line);

        $lines = file($dir.'/app/Http/Kernel.php', FILE_IGNORE_NEW_LINES);
        $this->assertIsArray($lines);
        $this->assertStringContainsString('protected $middleware', $lines[$location->line - 1]);
    }

    public function test_omits_the_location_when_no_middleware_file_exists(): void
    {
        $result = $this->withBasePath(
            $this->createTempDirectory([]),
            fn () => $this->analyzerWithUnusedCors()->analyze()
        );

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertNull($issues[0]->location);
        // The finding still stands; only the file reference is unavailable.
        $this->assertStringContainsString('HandleCors', $issues[0]->message);
        // On Laravel 11+ HandleCors is a framework default, so removing it takes remove().
        $this->assertStringContainsString('$middleware->remove()', $issues[0]->recommendation);
        $this->assertStringNotContainsString('that is the withMiddleware() callback', $issues[0]->recommendation);
        // remove() works whether HandleCors comes from the defaults or from a use() list,
        // so the advice must not claim which one the callback holds.
        $this->assertStringNotContainsString('it is a framework default', $issues[0]->recommendation);
    }

    public function test_bootstrap_app_recommendation_removes_the_framework_default(): void
    {
        // HandleCors is in the framework's default global stack on Laravel 11+, and an app
        // may also list it in use(); $middleware->remove() drops it in either case.
        $dir = $this->createTempDirectory([
            'bootstrap/app.php' => <<<'PHP'
                <?php

                return Application::configure(basePath: dirname(__DIR__))
                    ->withMiddleware(function (Middleware $middleware) {
                        //
                    })
                    ->create();
                PHP,
        ]);

        $result = $this->withBasePath($dir, fn () => $this->analyzerWithUnusedCors()->analyze());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('Unused global middleware detected: HandleCors', $issues[0]->message);
        $this->assertStringContainsString('$middleware->remove()', $issues[0]->recommendation);
        $this->assertStringContainsString('withMiddleware()', $issues[0]->recommendation);
        $this->assertStringNotContainsString('Remove HandleCors from the withMiddleware() callback', $issues[0]->recommendation);
        $this->assertStringNotContainsString('rather than an entry in the withMiddleware() callback', $issues[0]->recommendation);
    }

    /**
     * An analyzer whose global stack holds only the given TrustProxies class, resolved
     * through $make, with $configProxies as trustedproxy.proxies and no CORS middleware.
     *
     * @param  array<int, string>|string|null  $configProxies
     */
    private function analyzerWithTrustProxies(
        string $middlewareClass,
        \Closure $make,
        array|string|null $configProxies = null
    ): UnusedGlobalMiddlewareAnalyzer {
        /** @var Application&MockInterface $app */
        $app = Mockery::mock(Application::class);
        $app->shouldReceive('make')->with($middlewareClass)->andReturnUsing($make);

        /** @var ConfigRepository&MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);
        $config->shouldReceive('get')->with('trustedproxy.proxies')->andReturn($configProxies);
        $config->shouldReceive('get')->with('cors.paths', [])->andReturn([]);

        /** @var Router&MockInterface $router */
        $router = Mockery::mock(Router::class);

        $kernel = new class($middlewareClass) extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct(string $middlewareClass)
            {
                $this->middleware = [$middlewareClass];
            }
        };

        return new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
    }

    /**
     * Run the analyzer as if on Laravel 10, where the TrustProxies check is live.
     *
     * isLaravel11OrNewer() reads app()->version(), so the container instance is swapped
     * for one answering 10.48.0 and delegating everything else to the real application.
     */
    private function analyzeOnLaravel10(UnusedGlobalMiddlewareAnalyzer $analyzer): ResultInterface
    {
        $realApp = $this->app;
        $this->assertNotNull($realApp);

        /** @var Application&MockInterface $legacyApp */
        $legacyApp = Mockery::mock(Application::class);
        $legacyApp->shouldReceive('version')->andReturn('10.48.0');
        $legacyApp->shouldReceive('basePath')
            ->andReturnUsing(fn (string $path = '') => $realApp->basePath($path));
        $legacyApp->shouldReceive('environment')
            ->andReturnUsing(fn (...$environments) => $realApp->environment(...$environments));
        $legacyApp->shouldReceive('make')
            ->andReturnUsing(fn (string $abstract, array $parameters = []) => $realApp->make($abstract, $parameters));

        Container::setInstance($legacyApp);

        try {
            return $analyzer->analyze();
        } finally {
            Container::setInstance($realApp);
        }
    }

    /**
     * An analyzer whose only finding is the unused HandleCors middleware, so the
     * assertions above are about the reported file rather than about detection.
     */
    private function analyzerWithUnusedCors(): UnusedGlobalMiddlewareAnalyzer
    {
        /** @var Application&MockInterface $app */
        $app = Mockery::mock(Application::class);

        /** @var ConfigRepository&MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        /** @var Router&MockInterface $router */
        $router = Mockery::mock(Router::class);

        $kernel = new class extends \Illuminate\Foundation\Http\Kernel
        {
            public function __construct() {}

            /** @var array<int, string> */
            protected $middleware = [
                HandleCors::class,
            ];
        };

        $config->shouldReceive('get')->with('cors.paths', [])->andReturn([]);
        $config->shouldReceive('get')->with('trustedproxy.proxies')->andReturn(null);

        return new UnusedGlobalMiddlewareAnalyzer($app, $config, $router, $kernel);
    }

    /**
     * A Laravel 9/10 HTTP kernel whose $middleware array is deliberately not on line 1.
     */
    private function kernelFixture(): string
    {
        return <<<'PHP'
            <?php

            namespace App\Http;

            use Illuminate\Foundation\Http\Kernel as HttpKernel;

            class Kernel extends HttpKernel
            {
                protected $middleware = [
                    \Illuminate\Http\Middleware\HandleCors::class,
                ];
            }
            PHP;
    }
}
