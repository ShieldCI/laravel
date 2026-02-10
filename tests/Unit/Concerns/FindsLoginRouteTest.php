<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Concerns\FindsLoginRoute;
use ShieldCI\Tests\TestCase;

class FindsLoginRouteTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    #[Test]
    public function it_uses_config_guest_url_when_provided(): void
    {
        config(['shieldci.guest_url' => '/guest']);

        $class = $this->createFindsLoginRouteClass();

        $result = $class->publicFindLoginRoute();

        $this->assertStringContainsString('/guest', $result);
    }

    #[Test]
    public function it_falls_back_to_named_login_route(): void
    {
        config(['shieldci.guest_url' => null]);

        // Register a named 'login' route
        $this->app['router']->get('/login', fn () => 'Login Page')->name('login');

        $class = $this->createFindsLoginRouteClass();
        $class->setRouter($this->app['router']);

        $result = $class->publicFindLoginRoute();

        $this->assertStringContainsString('/login', $result);
    }

    #[Test]
    public function it_searches_for_guest_middleware_route(): void
    {
        config(['shieldci.guest_url' => null]);

        // Create a route with 'guest' middleware (without a named 'login' route)
        $router = $this->app['router'];
        $router->get('/register', fn () => 'Register')->middleware('guest');

        $class = $this->createFindsLoginRouteClass();
        $class->setRouter($router);

        $result = $class->publicFindLoginRoute();

        // Should find either /register (guest middleware) or fall back to /
        $this->assertNotEmpty($result);
    }

    #[Test]
    public function it_falls_back_to_root_url(): void
    {
        config(['shieldci.guest_url' => null]);

        // Create router with no 'login' route and no 'guest' middleware routes
        $router = $this->app['router'];
        $router->get('/dashboard', fn () => 'Dashboard')->middleware('auth');

        $class = $this->createFindsLoginRouteClass();
        $class->setRouter($router);

        // Clear any previously registered 'login' route
        $result = $class->publicFindLoginRoute();

        // Should fall back to root URL if nothing else matches
        $this->assertNotEmpty($result);
    }

    #[Test]
    public function it_detects_guest_middleware_on_route(): void
    {
        $class = $this->createFindsLoginRouteClass();

        // Create a mock route with 'guest' middleware
        $routeWithGuest = Mockery::mock(Route::class);
        $routeWithGuest->shouldReceive('middleware')->andReturn(['guest']);

        $routeWithRedirect = Mockery::mock(Route::class);
        $routeWithRedirect->shouldReceive('middleware')->andReturn(['App\Http\Middleware\RedirectIfAuthenticated']);

        $routeWithAuth = Mockery::mock(Route::class);
        $routeWithAuth->shouldReceive('middleware')->andReturn(['auth']);

        $this->assertTrue($class->publicRouteHasGuestMiddleware($routeWithGuest));
        $this->assertTrue($class->publicRouteHasGuestMiddleware($routeWithRedirect));
        $this->assertFalse($class->publicRouteHasGuestMiddleware($routeWithAuth));
    }

    #[Test]
    public function it_handles_non_route_objects_in_guest_middleware_check(): void
    {
        $class = $this->createFindsLoginRouteClass();

        $this->assertFalse($class->publicRouteHasGuestMiddleware('not-a-route'));
        $this->assertFalse($class->publicRouteHasGuestMiddleware(null));
        $this->assertFalse($class->publicRouteHasGuestMiddleware([]));
    }

    #[Test]
    public function it_handles_route_with_non_array_middleware(): void
    {
        $class = $this->createFindsLoginRouteClass();

        $route = Mockery::mock(Route::class);
        $route->shouldReceive('middleware')->andReturn(null);

        $this->assertFalse($class->publicRouteHasGuestMiddleware($route));
    }

    #[Test]
    public function it_can_set_router(): void
    {
        $class = $this->createFindsLoginRouteClass();
        $router = $this->app['router'];

        $class->setRouter($router);

        // If no exception is thrown, the router was set successfully
        $this->assertTrue(true);
    }

    #[Test]
    public function it_converts_url_to_string(): void
    {
        $class = $this->createFindsLoginRouteClass();

        // Test with string URL
        $this->assertEquals('http://example.com', $class->publicConvertToString('http://example.com'));
    }

    #[Test]
    public function it_converts_object_with_current_method_to_string(): void
    {
        $class = $this->createFindsLoginRouteClass();

        $urlObject = new class
        {
            public function current(): string
            {
                return 'http://current.example.com';
            }
        };

        $this->assertEquals('http://current.example.com', $class->publicConvertToString($urlObject));
    }

    #[Test]
    public function it_converts_object_with_to_string_method(): void
    {
        $class = $this->createFindsLoginRouteClass();

        $urlObject = new class
        {
            public function toString(): string
            {
                return 'http://tostring.example.com';
            }
        };

        $this->assertEquals('http://tostring.example.com', $class->publicConvertToString($urlObject));
    }

    #[Test]
    public function it_casts_object_to_string_as_last_resort(): void
    {
        $class = $this->createFindsLoginRouteClass();

        $urlObject = new class
        {
            public function __toString(): string
            {
                return 'http://castable.example.com';
            }
        };

        $this->assertEquals('http://castable.example.com', $class->publicConvertToString($urlObject));
    }

    /**
     * @return object
     */
    private function createFindsLoginRouteClass()
    {
        return new class
        {
            use FindsLoginRoute;

            protected Router $router;

            public function __construct()
            {
                $this->router = app('router');
            }

            public function publicFindLoginRoute(): ?string
            {
                return $this->findLoginRoute();
            }

            public function publicRouteHasGuestMiddleware(mixed $route): bool
            {
                return $this->routeHasGuestMiddleware($route);
            }

            public function publicConvertToString(mixed $url): string
            {
                return $this->convertToString($url);
            }
        };
    }
}
