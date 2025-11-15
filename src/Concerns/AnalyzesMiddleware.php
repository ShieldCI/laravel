<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use Closure;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Str;
use ReflectionClass;

/**
 * Provides methods for analyzing middleware usage in the application.
 */
trait AnalyzesMiddleware
{
    /**
     * The router instance.
     *
     * @var \Illuminate\Routing\Router
     */
    protected $router;

    /**
     * The HTTP kernel instance.
     *
     * @var \Illuminate\Contracts\Http\Kernel
     */
    protected $kernel;

    /**
     * Determine if the application uses the provided middleware.
     *
     * @throws \ReflectionException
     */
    protected function appUsesMiddleware(string $middlewareClass): bool
    {
        return $this->getAllMiddleware()->contains(function ($middleware) use ($middlewareClass) {
            return $middleware === $middlewareClass
                || (class_exists($middlewareClass) && is_subclass_of($middleware, $middlewareClass));
        });
    }

    /**
     * Compile a list of all middlewares used by the application.
     *
     * @return \Illuminate\Support\Collection<int, string>
     *
     * @throws \ReflectionException
     */
    protected function getAllMiddleware()
    {
        return $this->getAllRouteMiddleware()->merge($this->getGlobalMiddleware());
    }

    /**
     * Compile a list of all route middlewares used by the application.
     *
     * @return \Illuminate\Support\Collection<int, string>
     */
    protected function getAllRouteMiddleware()
    {
        $routes = $this->router->getRoutes();
        $routeList = [];

        // RouteCollectionInterface implements IteratorAggregate, so it's iterable
        /** @phpstan-ignore-next-line */
        foreach ($routes as $route) {
            if ($route instanceof \Illuminate\Routing\Route) {
                $routeList = array_merge($routeList, $this->getMiddleware($route));
            }
        }

        /** @var \Illuminate\Support\Collection<int, string> */
        return collect($routeList)->unique()->values();
    }

    /**
     * Get the global middleware from the kernel instance using reflection.
     *
     * @return array<int, string>
     *
     * @throws \ReflectionException
     */
    protected function getGlobalMiddleware(): array
    {
        $mirror = new ReflectionClass($this->kernel);
        $property = $mirror->getProperty('middleware');
        $property->setAccessible(true);

        $middlewareList = $property->getValue($this->kernel);

        /** @var array<int, string> */
        return collect(is_array($middlewareList) ? $middlewareList : [])->map(function ($middleware): string {
            // To get the middleware class names, we must separate the parameters.
            return is_string($middleware) ? Str::before($middleware, ':') : '';
        })->filter()->values()->toArray();
    }

    /**
     * Determine if the application uses the provided global HTTP middleware.
     *
     * @throws \ReflectionException
     */
    protected function appUsesGlobalMiddleware(string $middlewareClass): bool
    {
        return collect($this->getGlobalMiddleware())->contains(function ($middleware) use ($middlewareClass) {
            return $middleware === $middlewareClass
                || (class_exists($middlewareClass) && is_subclass_of($middleware, $middlewareClass));
        });
    }

    /**
     * Determine if the route uses the provided middleware.
     *
     * @param  \Illuminate\Routing\Route  $route
     */
    protected function routeUsesMiddleware($route, string $middlewareClass): bool
    {
        return collect($this->getMiddleware($route))->contains(function ($middleware) use ($middlewareClass) {
            return $middleware === $middlewareClass
                || (class_exists($middlewareClass) && is_subclass_of($middleware, $middlewareClass));
        });
    }

    /**
     * Get the middleware for a route.
     *
     * @param  \Illuminate\Routing\Route  $route
     * @return array<int, string>
     */
    protected function getMiddleware($route): array
    {
        /** @var array<int, string> */
        return collect($this->router->gatherRouteMiddleware($route))->map(function ($middleware): string {
            return $middleware instanceof Closure ? 'Closure' : (string) $middleware;
        })->map(function (string $middleware): string {
            // To get the middleware class names, we must separate the parameters.
            return Str::before($middleware, ':');
        })->values()->toArray();
    }

    /**
     * Determine if the route uses the provided middleware class (by basename).
     *
     * @param  \Illuminate\Routing\Route  $route
     */
    protected function routeUsesBasenameMiddleware($route, string $basenameMiddlewareClass): bool
    {
        return collect($this->getBasenameMiddlewareClasses($route))
            ->contains(function ($middleware) use ($basenameMiddlewareClass) {
                return $middleware === $basenameMiddlewareClass;
            });
    }

    /**
     * Get the basename of the middleware classes for a route.
     *
     * @param  \Illuminate\Routing\Route  $route
     * @return array<int, string>
     */
    protected function getBasenameMiddlewareClasses($route): array
    {
        /** @var array<int, string> */
        return collect($this->getMiddleware($route))->map(function (string $middleware): string {
            return class_basename($middleware);
        })->values()->toArray();
    }

    /**
     * Determine if the app is stateless (API-only, no sessions).
     *
     * @throws \ReflectionException
     */
    protected function appIsStateless(): bool
    {
        // If the app doesn't start sessions, it is stateless
        return ! $this->appUsesMiddleware(StartSession::class);
    }

    /**
     * Determine if the app uses cookies.
     *
     * @throws \ReflectionException
     */
    protected function appUsesCookies(): bool
    {
        return $this->appUsesMiddleware(AddQueuedCookiesToResponse::class);
    }
}
