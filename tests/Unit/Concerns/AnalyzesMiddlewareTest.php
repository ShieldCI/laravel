<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use Illuminate\Routing\Route;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Concerns\AnalyzesMiddleware;
use ShieldCI\Tests\TestCase;

class AnalyzesMiddlewareTest extends TestCase
{
    #[Test]
    public function it_detects_global_middleware(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $globalMiddleware = $class->publicGetGlobalMiddleware();

        $this->assertIsArray($globalMiddleware);
    }

    #[Test]
    public function it_detects_all_route_middleware(): void
    {
        // Register some routes with middleware
        $this->app['router']->get('/test', fn () => 'test')->middleware('auth');
        $this->app['router']->get('/admin', fn () => 'admin')->middleware('auth', 'verified');

        $class = $this->createMiddlewareAnalyzerClass();
        $routeMiddleware = $class->publicGetAllRouteMiddleware();

        $this->assertNotEmpty($routeMiddleware);
    }

    #[Test]
    public function it_compiles_all_middleware(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();
        $allMiddleware = $class->publicGetAllMiddleware();

        $this->assertInstanceOf(\Illuminate\Support\Collection::class, $allMiddleware);
    }

    #[Test]
    public function it_checks_if_app_uses_specific_middleware(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        // This should not throw - just returns bool
        $result = $class->publicAppUsesMiddleware('NonExistentMiddleware');
        $this->assertIsBool($result);
    }

    #[Test]
    public function it_checks_if_app_uses_global_middleware(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $result = $class->publicAppUsesGlobalMiddleware('NonExistentMiddleware');
        $this->assertIsBool($result);
    }

    #[Test]
    public function it_gets_middleware_for_a_route(): void
    {
        $this->app['router']->get('/test-route', fn () => 'test')->middleware('auth');

        // Collect routes to resolve
        $routes = $this->app['router']->getRoutes();
        $routes->refreshNameLookups();

        $class = $this->createMiddlewareAnalyzerClass();

        foreach ($routes as $route) {
            if ($route instanceof Route && $route->uri() === 'test-route') {
                $middleware = $class->publicGetMiddleware($route);
                $this->assertIsArray($middleware);

                break;
            }
        }
    }

    #[Test]
    public function it_checks_route_uses_middleware(): void
    {
        $this->app['router']->get('/protected', fn () => 'protected')->middleware('auth');

        $routes = $this->app['router']->getRoutes();
        $routes->refreshNameLookups();

        $class = $this->createMiddlewareAnalyzerClass();

        foreach ($routes as $route) {
            if ($route instanceof Route && $route->uri() === 'protected') {
                $usesAuth = $class->publicRouteUsesMiddleware($route, 'auth');
                $this->assertIsBool($usesAuth);

                break;
            }
        }
    }

    #[Test]
    public function it_checks_route_uses_basename_middleware(): void
    {
        $this->app['router']->get('/base', fn () => 'base')->middleware('auth');

        $routes = $this->app['router']->getRoutes();
        $routes->refreshNameLookups();

        $class = $this->createMiddlewareAnalyzerClass();

        foreach ($routes as $route) {
            if ($route instanceof Route && $route->uri() === 'base') {
                $result = $class->publicRouteUsesBasenameMiddleware($route, 'auth');
                $this->assertIsBool($result);

                break;
            }
        }
    }

    #[Test]
    public function it_gets_basename_middleware_classes(): void
    {
        $this->app['router']->get('/basename-test', fn () => 'test')->middleware('auth');

        $routes = $this->app['router']->getRoutes();
        $routes->refreshNameLookups();

        $class = $this->createMiddlewareAnalyzerClass();

        foreach ($routes as $route) {
            if ($route instanceof Route && $route->uri() === 'basename-test') {
                $basenames = $class->publicGetBasenameMiddlewareClasses($route);
                $this->assertIsArray($basenames);

                break;
            }
        }
    }

    #[Test]
    public function it_determines_if_app_is_stateless(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $isStateless = $class->publicAppIsStateless();
        $this->assertIsBool($isStateless);
    }

    #[Test]
    public function it_determines_if_app_uses_cookies(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $usesCookies = $class->publicAppUsesCookies();
        $this->assertIsBool($usesCookies);
    }

    /**
     * @return object
     */
    private function createMiddlewareAnalyzerClass()
    {
        $router = $this->app['router'];
        $kernel = $this->app->make(\Illuminate\Contracts\Http\Kernel::class);

        return new class($router, $kernel)
        {
            use AnalyzesMiddleware;

            public function __construct(
                protected $router,
                protected $kernel,
            ) {}

            public function publicGetGlobalMiddleware(): array
            {
                return $this->getGlobalMiddleware();
            }

            public function publicGetAllRouteMiddleware(): \Illuminate\Support\Collection
            {
                return $this->getAllRouteMiddleware();
            }

            public function publicGetAllMiddleware(): \Illuminate\Support\Collection
            {
                return $this->getAllMiddleware();
            }

            public function publicAppUsesMiddleware(string $class): bool
            {
                return $this->appUsesMiddleware($class);
            }

            public function publicAppUsesGlobalMiddleware(string $class): bool
            {
                return $this->appUsesGlobalMiddleware($class);
            }

            public function publicGetMiddleware(\Illuminate\Routing\Route $route): array
            {
                return $this->getMiddleware($route);
            }

            public function publicRouteUsesMiddleware(\Illuminate\Routing\Route $route, string $class): bool
            {
                return $this->routeUsesMiddleware($route, $class);
            }

            public function publicRouteUsesBasenameMiddleware(\Illuminate\Routing\Route $route, string $class): bool
            {
                return $this->routeUsesBasenameMiddleware($route, $class);
            }

            public function publicGetBasenameMiddlewareClasses(\Illuminate\Routing\Route $route): array
            {
                return $this->getBasenameMiddlewareClasses($route);
            }

            public function publicAppIsStateless(): bool
            {
                return $this->appIsStateless();
            }

            public function publicAppUsesCookies(): bool
            {
                return $this->appUsesCookies();
            }
        };
    }
}
