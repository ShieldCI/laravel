<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Auth\User;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Collection;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Concerns\AnalyzesMiddleware;
use ShieldCI\Tests\TestCase;

class AnalyzesMiddlewareTest extends TestCase
{
    private function getRouter(): Router
    {
        return $this->app->make(Router::class);
    }

    /** @test */
    #[Test]
    public function it_detects_global_middleware(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $globalMiddleware = $class->publicGetGlobalMiddleware();

        $this->assertIsArray($globalMiddleware);
    }

    /** @test */
    #[Test]
    public function it_detects_all_route_middleware(): void
    {
        // Register some routes with middleware
        $this->getRouter()->get('/test', fn () => 'test')->middleware('auth');
        $this->getRouter()->get('/admin', fn () => 'admin')->middleware('auth', 'verified');

        $class = $this->createMiddlewareAnalyzerClass();
        $routeMiddleware = $class->publicGetAllRouteMiddleware();

        $this->assertNotEmpty($routeMiddleware);
    }

    /** @test */
    #[Test]
    public function it_compiles_all_middleware(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();
        $allMiddleware = $class->publicGetAllMiddleware();

        $this->assertInstanceOf(Collection::class, $allMiddleware);
    }

    /** @test */
    #[Test]
    public function it_checks_if_app_uses_specific_middleware(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        // This should not throw - just returns bool
        $result = $class->publicAppUsesMiddleware('NonExistentMiddleware');
        $this->assertIsBool($result);
    }

    /** @test */
    #[Test]
    public function it_checks_if_app_uses_global_middleware(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $result = $class->publicAppUsesGlobalMiddleware('NonExistentMiddleware');
        $this->assertIsBool($result);
    }

    /** @test */
    #[Test]
    public function it_gets_middleware_for_a_route(): void
    {
        $this->getRouter()->get('/test-route', fn () => 'test')->middleware('auth');

        // Collect routes to resolve
        $routeCollection = $this->getRouter()->getRoutes();
        $routeCollection->refreshNameLookups();

        $class = $this->createMiddlewareAnalyzerClass();

        foreach ($routeCollection->getRoutes() as $route) {
            if ($route->uri() === 'test-route') {
                $middleware = $class->publicGetMiddleware($route);
                $this->assertIsArray($middleware);

                break;
            }
        }
    }

    /** @test */
    #[Test]
    public function it_checks_route_uses_middleware(): void
    {
        $this->getRouter()->get('/protected', fn () => 'protected')->middleware('auth');

        $routeCollection = $this->getRouter()->getRoutes();
        $routeCollection->refreshNameLookups();

        $class = $this->createMiddlewareAnalyzerClass();

        foreach ($routeCollection->getRoutes() as $route) {
            if ($route->uri() === 'protected') {
                $usesAuth = $class->publicRouteUsesMiddleware($route, 'auth');
                $this->assertIsBool($usesAuth);

                break;
            }
        }
    }

    /** @test */
    #[Test]
    public function it_checks_route_uses_basename_middleware(): void
    {
        $this->getRouter()->get('/base', fn () => 'base')->middleware('auth');

        $routeCollection = $this->getRouter()->getRoutes();
        $routeCollection->refreshNameLookups();

        $class = $this->createMiddlewareAnalyzerClass();

        foreach ($routeCollection->getRoutes() as $route) {
            if ($route->uri() === 'base') {
                $result = $class->publicRouteUsesBasenameMiddleware($route, 'auth');
                $this->assertIsBool($result);

                break;
            }
        }
    }

    /** @test */
    #[Test]
    public function it_gets_basename_middleware_classes(): void
    {
        $this->getRouter()->get('/basename-test', fn () => 'test')->middleware('auth');

        $routeCollection = $this->getRouter()->getRoutes();
        $routeCollection->refreshNameLookups();

        $class = $this->createMiddlewareAnalyzerClass();

        foreach ($routeCollection->getRoutes() as $route) {
            if ($route->uri() === 'basename-test') {
                $basenames = $class->publicGetBasenameMiddlewareClasses($route);
                $this->assertIsArray($basenames);

                break;
            }
        }
    }

    /** @test */
    #[Test]
    public function it_determines_if_app_is_stateless(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $isStateless = $class->publicAppIsStateless();
        $this->assertIsBool($isStateless);
    }

    /** @test */
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

    /** @test */
    #[Test]
    public function is_start_session_middleware_matches_exact_class(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicIsStartSessionMiddleware(StartSession::class));
    }

    /** @test */
    #[Test]
    public function is_start_session_middleware_matches_by_basename(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        // A namespaced class whose basename is 'StartSession' should match
        $this->assertTrue($class->publicIsStartSessionMiddleware('App\Http\Middleware\StartSession'));
    }

    /** @test */
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

    /** @test */
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

    /** @test */
    #[Test]
    public function get_groups_containing_session_returns_groups_with_start_session(): void
    {
        $router = $this->getRouter();
        $router->middlewareGroup('web', [StartSession::class]);
        $router->middlewareGroup('api', ['throttle:api']);

        $class = $this->createMiddlewareAnalyzerClass();
        $groups = $class->publicGetGroupsContainingSession();

        $this->assertContains('web', $groups);
        $this->assertNotContains('api', $groups);
    }

    /** @test */
    #[Test]
    public function get_groups_containing_session_excludes_groups_without_session(): void
    {
        $router = $this->getRouter();
        // Register a group that has no session middleware
        $router->middlewareGroup('custom-api', ['throttle:60,1', 'auth:api']);

        $class = $this->createMiddlewareAnalyzerClass();
        $groups = $class->publicGetGroupsContainingSession();

        $this->assertIsArray($groups);
        $this->assertNotContains('custom-api', $groups);
    }

    // =========================================================================
    // appUsesGroupMiddleware()
    // =========================================================================

    /** @test */
    #[Test]
    public function app_uses_group_middleware_detects_middleware_in_a_group(): void
    {
        // Laravel 11+ ships EncryptCookies in the default `web` group, not the
        // global stack — this is the registration the analyzer must detect.
        $router = $this->getRouter();
        $router->middlewareGroup('web', [EncryptCookies::class]);

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicAppUsesGroupMiddleware(EncryptCookies::class));
    }

    /** @test */
    #[Test]
    public function app_uses_group_middleware_returns_false_when_absent_from_all_groups(): void
    {
        $router = $this->getRouter();
        $router->middlewareGroup('web', [StartSession::class]);

        $class = $this->createMiddlewareAnalyzerClass();

        // A middleware registered in no group must not be reported as present.
        $this->assertFalse($class->publicAppUsesGroupMiddleware('App\Http\Middleware\NeverRegisteredMiddleware'));
    }

    /** @test */
    #[Test]
    public function app_uses_group_middleware_matches_a_subclass(): void
    {
        // A custom App\Http\Middleware\EncryptCookies extending the framework one
        // should still be detected when queried by the parent class.
        $subclass = new class extends EncryptCookies
        {
            public function __construct() {} // avoid DI requirements
        };

        $router = $this->getRouter();
        $router->middlewareGroup('web', [$subclass::class]);

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicAppUsesGroupMiddleware(EncryptCookies::class));
    }

    /** @test */
    #[Test]
    public function app_uses_group_middleware_returns_false_when_groups_is_not_an_array(): void
    {
        // getMiddlewareGroups() is documented `@return array` but is untyped, so the
        // normalizer guards against a malformed (non-array) router value rather than
        // crashing. Query a class registered in no group (the kernel's real groups are
        // still merged in) to assert the malformed router input is simply ignored.
        $class = $this->createMiddlewareAnalyzerClass();
        $this->setRouterMiddlewareGroups('not-an-array');

        $this->assertFalse($class->publicAppUsesGroupMiddleware('App\Http\Middleware\NeverRegisteredMiddleware'));
    }

    /** @test */
    #[Test]
    public function app_uses_group_middleware_skips_groups_with_a_non_array_value(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();
        $this->setRouterMiddlewareGroups(['web' => 'not-an-array']);

        $this->assertFalse($class->publicAppUsesGroupMiddleware('App\Http\Middleware\NeverRegisteredMiddleware'));
    }

    /** @test */
    #[Test]
    public function app_uses_group_middleware_skips_non_string_group_members(): void
    {
        // A non-string member (here an int) is skipped — proving the guard continues
        // instead of crashing on Str::before() — and a real class after it still matches.
        $class = $this->createMiddlewareAnalyzerClass();
        $this->setRouterMiddlewareGroups(['web' => [123, EncryptCookies::class]]);

        $this->assertTrue($class->publicAppUsesGroupMiddleware(EncryptCookies::class));
    }

    /**
     * Overwrite the router singleton's middleware groups with arbitrary (possibly
     * malformed) data to exercise the defensive guards in appUsesGroupMiddleware().
     */
    private function setRouterMiddlewareGroups(mixed $groups): void
    {
        $router = $this->getRouter();
        (new \ReflectionProperty($router, 'middlewareGroups'))->setValue($router, $groups);
    }

    /** @test */
    #[Test]
    public function app_uses_group_middleware_reads_from_kernel_when_router_groups_are_wiped(): void
    {
        // Regression: a runner that snapshots/restores the router's middleware maps can
        // leave the web group without its lazily-attached framework defaults. The kernel
        // retains them, so group detection must consult the kernel — not the router alone.
        $kernel = new class
        {
            /** @return array<string, array<int, string>> */
            public function getMiddlewareGroups(): array
            {
                return ['web' => [EncryptCookies::class]];
            }
        };

        $class = $this->createMiddlewareAnalyzerClassWithKernel($kernel);
        $this->setRouterMiddlewareGroups([]); // router has no web group at all

        $this->assertTrue($class->publicAppUsesGroupMiddleware(EncryptCookies::class));
    }

    /** @test */
    #[Test]
    public function app_uses_group_middleware_falls_back_to_router_when_kernel_lacks_method(): void
    {
        // Older Laravel HTTP kernels expose no getMiddlewareGroups(); detection then
        // relies solely on the router's groups.
        $kernel = new class
        {
            // intentionally no getMiddlewareGroups()
        };

        $class = $this->createMiddlewareAnalyzerClassWithKernel($kernel);
        $this->setRouterMiddlewareGroups(['web' => [EncryptCookies::class]]);

        $this->assertTrue($class->publicAppUsesGroupMiddleware(EncryptCookies::class));
    }

    /** @test */
    #[Test]
    public function get_middleware_groups_skips_non_string_group_names(): void
    {
        // Numeric/empty keys (possible in a raw, untyped group map) are dropped so callers
        // that key on the group name — e.g. getGroupsContainingSession() — stay well-typed.
        $kernel = new class
        {
            /** @return array<int, array<int, string>> */
            public function getMiddlewareGroups(): array
            {
                return [0 => [StartSession::class]];
            }
        };

        $class = $this->createMiddlewareAnalyzerClassWithKernel($kernel);
        $this->setRouterMiddlewareGroups([]);

        $this->assertSame([], $class->publicGetMiddlewareGroups());
    }

    /** @test */
    #[Test]
    public function get_groups_containing_session_reads_from_kernel(): void
    {
        // The session-group path uses the same kernel-preferred source, so a kernel-only
        // web group (router wiped) is still recognized as session-bearing.
        $kernel = new class
        {
            /** @return array<string, array<int, string>> */
            public function getMiddlewareGroups(): array
            {
                return ['web' => [StartSession::class]];
            }
        };

        $class = $this->createMiddlewareAnalyzerClassWithKernel($kernel);
        $this->setRouterMiddlewareGroups([]);

        $this->assertSame(['web'], $class->publicGetGroupsContainingSession());
    }

    /**
     * Build the middleware-analyzer wrapper with a caller-supplied kernel, so tests can
     * control kernel->getMiddlewareGroups() independently of the router (including a kernel
     * without that method, which exercises the older-Laravel router-only path).
     */
    private function createMiddlewareAnalyzerClassWithKernel(object $kernel): object
    {
        $router = $this->getRouter();

        return new class($router, $kernel)
        {
            use AnalyzesMiddleware;

            public function __construct(protected Router $router, protected $kernel) {}

            public function publicAppUsesGroupMiddleware(string $class): bool
            {
                return $this->appUsesGroupMiddleware($class);
            }

            /** @return array<int, string> */
            public function publicGetGroupsContainingSession(): array
            {
                return $this->getGroupsContainingSession();
            }

            /** @return array<string, array<int, string>> */
            public function publicGetMiddlewareGroups(): array
            {
                return $this->getMiddlewareGroups();
            }
        };
    }

    // =========================================================================
    // hasSessionInGlobalMiddleware()
    // =========================================================================

    /** @test */
    #[Test]
    public function has_session_in_global_middleware_returns_false_in_test_env(): void
    {
        // The Orchestra Testbench kernel does not include StartSession globally
        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertFalse($class->publicHasSessionInGlobalMiddleware());
    }

    /** @test */
    #[Test]
    public function has_session_in_global_middleware_returns_true_when_start_session_is_global(): void
    {
        $class = $this->createMiddlewareAnalyzerClassWithGlobalMiddleware([StartSession::class]);

        $this->assertTrue($class->publicHasSessionInGlobalMiddleware());
    }

    /** @test */
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

    /** @test */
    #[Test]
    public function has_session_group_used_by_routes_returns_true_for_app_web_route(): void
    {
        $router = $this->getRouter();
        $router->middlewareGroup('web', [StartSession::class]);
        // App-defined closure route using web (closures are not vendor routes)
        $router->get('/home', fn () => 'home')->middleware('web');

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicHasSessionGroupUsedByRoutes());
    }

    /** @test */
    #[Test]
    public function has_session_group_used_by_routes_returns_false_when_only_api_routes(): void
    {
        $router = $this->getRouter();
        $router->middlewareGroup('web', [StartSession::class]);
        $router->get('/api/users', fn () => [])->middleware('api');

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertFalse($class->publicHasSessionGroupUsedByRoutes());
    }

    // =========================================================================
    // isVendorRoute()
    // =========================================================================

    /** @test */
    #[Test]
    public function is_vendor_route_returns_false_for_closure_routes(): void
    {
        $router = $this->getRouter();
        $route = $router->get('/closure', fn () => 'ok');

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertFalse($class->publicIsVendorRoute($route));
    }

    /** @test */
    #[Test]
    public function is_vendor_route_returns_true_for_vendor_controller(): void
    {
        $router = $this->getRouter();
        // Illuminate\Foundation\Auth\User is in vendor/laravel/framework
        $route = $router->get('/vendor-route', [User::class, 'all']);

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicIsVendorRoute($route));
    }

    /** @test */
    #[Test]
    public function is_vendor_route_returns_true_for_vendor_interface_as_controller(): void
    {
        // Interfaces resolved through the container (e.g. Vapor contracts) must also
        // be detected as vendor routes, since class_exists() returns false for interfaces.
        $router = $this->getRouter();
        // StartSession itself is from vendor; use its interface counterpart via any
        // concrete vendor class that lives in vendor/ to prove the ReflectionClass path works.
        $route = $router->post('/vendor-if', StartSession::class.'@handle');

        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicIsVendorRoute($route));
    }

    /** @test */
    #[Test]
    public function is_vendor_route_returns_false_for_unknown_class(): void
    {
        $router = $this->getRouter();
        $route = $router->get('/unknown', 'App\Http\Controllers\NonExistentController@index');

        $class = $this->createMiddlewareAnalyzerClass();

        // ReflectionClass throws for non-existent classes → falls back to false
        $this->assertFalse($class->publicIsVendorRoute($route));
    }

    // =========================================================================
    // routeMiddlewareContainsSession()
    // =========================================================================

    /** @test */
    #[Test]
    public function route_middleware_contains_session_detects_direct_start_session(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicRouteMiddlewareContainsSession(
            [StartSession::class],
            []
        ));
    }

    /** @test */
    #[Test]
    public function route_middleware_contains_session_detects_session_group_name(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertTrue($class->publicRouteMiddlewareContainsSession(
            ['web'],
            ['web'] // 'web' is a known session-containing group
        ));
    }

    /** @test */
    #[Test]
    public function route_middleware_contains_session_returns_false_for_non_session_middleware(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        $this->assertFalse($class->publicRouteMiddlewareContainsSession(
            ['api', 'throttle:60,1'],
            []
        ));
    }

    /** @test */
    #[Test]
    public function route_middleware_contains_session_skips_non_string_items(): void
    {
        $class = $this->createMiddlewareAnalyzerClass();

        // Non-string items must be skipped gracefully (line 375 in the trait)
        $this->assertFalse($class->publicRouteMiddlewareContainsSession([42, null, 'auth'], []));
        $this->assertTrue($class->publicRouteMiddlewareContainsSession([42, StartSession::class], []));
    }

    /** @test */
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

    /** @test */
    #[Test]
    public function app_is_not_stateless_when_closure_route_uses_session_group(): void
    {
        $router = $this->getRouter();
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
        $router = $this->getRouter();
        $kernel = $this->app->make(Kernel::class);

        return new class($router, $kernel, $globalMiddleware)
        {
            use AnalyzesMiddleware;

            /** @param array<int, string> $fixedGlobal */
            public function __construct(
                protected Router $router,
                protected $kernel,
                private array $fixedGlobal,
            ) {}

            /** @return array<int, string> */
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
        $router = $this->getRouter();
        $kernel = $this->app->make(Kernel::class);

        return new class($router, $kernel)
        {
            use AnalyzesMiddleware;

            public function __construct(
                protected Router $router,
                protected $kernel,
            ) {}

            /** @return array<int, string> */
            public function publicGetGlobalMiddleware(): array
            {
                return $this->getGlobalMiddleware();
            }

            public function publicGetAllRouteMiddleware(): Collection
            {
                return $this->getAllRouteMiddleware();
            }

            public function publicGetAllMiddleware(): Collection
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

            public function publicAppUsesGroupMiddleware(string $class): bool
            {
                return $this->appUsesGroupMiddleware($class);
            }

            /** @return array<int, string> */
            public function publicGetMiddleware(Route $route): array
            {
                return $this->getMiddleware($route);
            }

            public function publicRouteUsesMiddleware(Route $route, string $class): bool
            {
                return $this->routeUsesMiddleware($route, $class);
            }

            public function publicRouteUsesBasenameMiddleware(Route $route, string $class): bool
            {
                return $this->routeUsesBasenameMiddleware($route, $class);
            }

            /** @return array<int, string> */
            public function publicGetBasenameMiddlewareClasses(Route $route): array
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

            /** @return array<int, string> */
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

            public function publicIsVendorRoute(Route $route): bool
            {
                return $this->isVendorRoute($route);
            }

            /** @param array<int, string> $sessionGroups */
            public function publicRouteUsesSession(Route $route, array $sessionGroups): bool
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
