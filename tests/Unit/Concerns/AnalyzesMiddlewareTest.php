<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use Illuminate\Routing\Route;
use Illuminate\Session\Middleware\StartSession;
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

    // =========================================================================
    // isStartSessionMiddleware()
    // =========================================================================

    #[Test]
    public function is_start_session_middleware_matches_exact_class(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicIsStartSessionMiddleware(StartSession::class));
    }

    #[Test]
    public function is_start_session_middleware_matches_by_basename(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        // A namespaced class whose basename is 'StartSession' should match
        $this->assertTrue($class->publicIsStartSessionMiddleware('App\Http\Middleware\StartSession'));
    }

    #[Test]
    public function is_start_session_middleware_matches_subclass(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        // A class that extends StartSession should also be considered a session middleware
        $subclass = new class extends StartSession
        {
            public function __construct() {} // avoid DI requirements
        };

        $this->assertTrue($class->publicIsStartSessionMiddleware($subclass::class));
    }

    #[Test]
    public function is_start_session_middleware_rejects_unrelated_middleware(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertFalse($class->publicIsStartSessionMiddleware('App\Http\Middleware\Authenticate'));
        $this->assertFalse($class->publicIsStartSessionMiddleware('auth'));
        $this->assertFalse($class->publicIsStartSessionMiddleware(''));
    }

    // =========================================================================
    // getGroupsContainingSession()
    // =========================================================================

    #[Test]
    public function get_groups_containing_session_returns_groups_with_start_session(): void
    {
        $router = $this->app['router'];
        $router->middlewareGroup('web', [StartSession::class]);
        $router->middlewareGroup('api', ['throttle:api']);

        $class = $this->createMiddlewareAnalyzerClass();
        $groups = $class->publicGetGroupsContainingSession();

        $this->assertContains('web', $groups);
        $this->assertNotContains('api', $groups);
    }

    #[Test]
    public function get_groups_containing_session_excludes_groups_without_session(): void
    {
        $router = $this->app['router'];
        // Register a group that has no session middleware
        $router->middlewareGroup('custom-api', ['throttle:60,1', 'auth:api']);

        $class = $this->createMiddlewareAnalyzerClass();
        $groups = $class->publicGetGroupsContainingSession();

        $this->assertIsArray($groups);
        $this->assertNotContains('custom-api', $groups);
    }

    // =========================================================================
    // hasSessionInGlobalMiddleware()
    // =========================================================================

    #[Test]
    public function has_session_in_global_middleware_returns_false_in_test_env(): void
    {
        // The Orchestra Testbench kernel does not include StartSession globally
        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertFalse($class->publicHasSessionInGlobalMiddleware());
    }

    #[Test]
    public function has_session_in_global_middleware_returns_true_when_start_session_is_global(): void
    {
        $class = $this->createMiddlewareAnalyzerClassWithGlobalMiddleware([StartSession::class]);

        $this->assertTrue($class->publicHasSessionInGlobalMiddleware());
    }

    #[Test]
    public function app_is_not_stateless_when_start_session_is_in_global_middleware(): void
    {
        // Exercises the fast-exit path of appIsStateless() (line 199)
        $class = $this->createMiddlewareAnalyzerClassWithGlobalMiddleware([StartSession::class]);

        $this->assertFalse($class->publicAppIsStateless());
    }

    // =========================================================================
    // hasSessionGroupUsedByRoutes()
    // =========================================================================

    #[Test]
    public function has_session_group_used_by_routes_returns_true_for_app_web_route(): void
    {
        $router = $this->app['router'];
        $router->middlewareGroup('web', [StartSession::class]);
        // App-defined closure route using web (closures are not vendor routes)
        $router->get('/home', fn () => 'home')->middleware('web');

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicHasSessionGroupUsedByRoutes());
    }

    #[Test]
    public function has_session_group_used_by_routes_returns_false_when_only_api_routes(): void
    {
        $router = $this->app['router'];
        $router->middlewareGroup('web', [StartSession::class]);
        $router->get('/api/users', fn () => [])->middleware('api');

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertFalse($class->publicHasSessionGroupUsedByRoutes());
    }

    // =========================================================================
    // isVendorRoute()
    // =========================================================================

    #[Test]
    public function is_vendor_route_returns_false_for_closure_routes(): void
    {
        $router = $this->app['router'];
        $route = $router->get('/closure', fn () => 'ok');

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertFalse($class->publicIsVendorRoute($route));
    }

    #[Test]
    public function is_vendor_route_returns_true_for_vendor_controller(): void
    {
        $router = $this->app['router'];
        // Illuminate\Foundation\Auth\User is in vendor/laravel/framework
        $route = $router->get('/vendor-route', [\Illuminate\Foundation\Auth\User::class, 'all']);

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicIsVendorRoute($route));
    }

    #[Test]
    public function is_vendor_route_returns_true_for_vendor_interface_as_controller(): void
    {
        // Interfaces resolved through the container (e.g. Vapor contracts) must also
        // be detected as vendor routes, since class_exists() returns false for interfaces.
        $router = $this->app['router'];
        // StartSession itself is from vendor; use its interface counterpart via any
        // concrete vendor class that lives in vendor/ to prove the ReflectionClass path works.
        $route = $router->post('/vendor-if', StartSession::class.'@handle');

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicIsVendorRoute($route));
    }

    #[Test]
    public function is_vendor_route_returns_false_for_unknown_class(): void
    {
        $router = $this->app['router'];
        $route = $router->get('/unknown', 'App\Http\Controllers\NonExistentController@index');

        $class = $this->createMiddlewareAnalyzerClass();

        // ReflectionClass throws for non-existent classes → falls back to false
        $this->assertFalse($class->publicIsVendorRoute($route));
    }

    // =========================================================================
    // routeMiddlewareContainsSession()
    // =========================================================================

    #[Test]
    public function route_middleware_contains_session_detects_direct_start_session(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicRouteMiddlewareContainsSession(
            [StartSession::class],
            []
        ));
    }

    #[Test]
    public function route_middleware_contains_session_detects_session_group_name(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicRouteMiddlewareContainsSession(
            ['web'],
            ['web'] // 'web' is a known session-containing group
        ));
    }

    #[Test]
    public function route_middleware_contains_session_returns_false_for_non_session_middleware(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertFalse($class->publicRouteMiddlewareContainsSession(
            ['api', 'throttle:60,1'],
            []
        ));
    }

    #[Test]
    public function route_middleware_contains_session_skips_non_string_items(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        // Non-string items must be skipped gracefully (line 375 in the trait)
        $this->assertFalse($class->publicRouteMiddlewareContainsSession([42, null, 'auth'], []));
        $this->assertTrue($class->publicRouteMiddlewareContainsSession([42, StartSession::class], []));
    }

    #[Test]
    public function route_middleware_contains_session_returns_false_for_non_array(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertFalse($class->publicRouteMiddlewareContainsSession(null, []));
        $this->assertFalse($class->publicRouteMiddlewareContainsSession('web', []));
    }

    // =========================================================================
    // appIsStateless() — stateful cases
    // =========================================================================

    #[Test]
    public function app_is_not_stateless_when_closure_route_uses_session_group(): void
    {
        $router = $this->app['router'];
        $router->middlewareGroup('web', [StartSession::class]);
        $router->get('/home', fn () => 'home')->middleware('web');

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertFalse($class->publicAppIsStateless());
    }

    /**
     * Creates an analyzer class whose getGlobalMiddleware() returns the given list.
     * Used to exercise the hasSessionInGlobalMiddleware() / appIsStateless() fast-exit path.
     *
     * @param  array<int, string>  $globalMiddleware
     * @return object
     */
    private function createMiddlewareAnalyzerClassWithGlobalMiddleware(array $globalMiddleware)
    {
        $router = $this->app['router'];
        $kernel = $this->app->make(\Illuminate\Contracts\Http\Kernel::class);

        return new class($router, $kernel, $globalMiddleware)
        {
            use AnalyzesMiddleware;

            /** @param array<int, string> $fixedGlobal */
            public function __construct(
                protected \Illuminate\Routing\Router $router,
                protected $kernel,
                private array $fixedGlobal,
            ) {}

            protected function getGlobalMiddleware(): array
            {
                return $this->fixedGlobal;
            }

            public function publicHasSessionInGlobalMiddleware(): bool
            {
                return $this->hasSessionInGlobalMiddleware();
            }

            public function publicAppIsStateless(): bool
            {
                return $this->appIsStateless();
            }
        };
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
                protected \Illuminate\Routing\Router $router,
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

            public function publicIsStartSessionMiddleware(string $middleware): bool
            {
                return $this->isStartSessionMiddleware($middleware);
            }

            public function publicGetGroupsContainingSession(): array
            {
                return $this->getGroupsContainingSession();
            }

            public function publicHasSessionInGlobalMiddleware(): bool
            {
                return $this->hasSessionInGlobalMiddleware();
            }

            public function publicHasSessionGroupUsedByRoutes(): bool
            {
                return $this->hasSessionGroupUsedByRoutes();
            }

            public function publicIsVendorRoute(\Illuminate\Routing\Route $route): bool
            {
                return $this->isVendorRoute($route);
            }

            /** @param array<int, string> $sessionGroups */
            public function publicRouteUsesSession(\Illuminate\Routing\Route $route, array $sessionGroups): bool
            {
                return $this->routeUsesSession($route, $sessionGroups);
            }

            /** @param array<int, string> $sessionGroups */
            public function publicRouteMiddlewareContainsSession(mixed $middleware, array $sessionGroups): bool
            {
                return $this->routeMiddlewareContainsSession($middleware, $sessionGroups);
            }
        };
    }
}
