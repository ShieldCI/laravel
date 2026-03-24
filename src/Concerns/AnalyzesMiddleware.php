<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use Closure;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Str;
use ReflectionClass;
use ReflectionException;

/**
 * Provides methods for analyzing middleware usage in the application.
 */
trait AnalyzesMiddleware
{
    /**
     * The router instance.
     */
    protected Router $router;

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
     * Get the global middleware from the kernel instance.
     *
     * Prefers the public getGlobalMiddleware() method available since Laravel 10,
     * falling back to reflection for older versions.
     *
     * @return array<int, string>
     */
    protected function getGlobalMiddleware(): array
    {
        // Prefer public method (Laravel 10+)
        if (method_exists($this->kernel, 'getGlobalMiddleware')) {
            /** @phpstan-ignore-next-line method.notFound */
            $middleware = $this->kernel->getGlobalMiddleware();

            return is_array($middleware) ? $middleware : [];
        }

        // Reflection fallback for older Laravel
        try {
            $mirror = new ReflectionClass($this->kernel);
            $property = $mirror->getProperty('middleware');
            $property->setAccessible(true);

            $middlewareList = $property->getValue($this->kernel);

            /** @var array<int, string> */
            return collect(is_array($middlewareList) ? $middlewareList : [])->map(function ($middleware): string {
                return is_string($middleware) ? Str::before($middleware, ':') : '';
            })->filter()->values()->toArray();
        } catch (ReflectionException) {
            return [];
        }
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
     * Uses a two-pass check to avoid false positives on apps where a session-
     * containing group (e.g. 'web') is defined but not assigned to any route.
     *
     * Pass 1: global middleware (fast).
     * Pass 2: check whether any session-containing group is actually used by routes.
     */
    protected function appIsStateless(): bool
    {
        // Pass 1: check global middleware (fast)
        if ($this->hasSessionInGlobalMiddleware()) {
            return false;
        }

        // Pass 2: check if any session-containing group is actually used by routes
        return ! $this->hasSessionGroupUsedByRoutes();
    }

    /**
     * Check if StartSession middleware is registered as global middleware.
     */
    protected function hasSessionInGlobalMiddleware(): bool
    {
        foreach ($this->getGlobalMiddleware() as $middleware) {
            if ($this->isStartSessionMiddleware($middleware)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if any route uses middleware that resolves to StartSession.
     *
     * Avoids false positives where a group (e.g. 'web') contains StartSession
     * but no routes actually use that group (e.g. API-only apps), or where the
     * only routes using the group are vendor-injected infrastructure routes
     * (e.g. Laravel Vapor's signed-storage-url).
     */
    protected function hasSessionGroupUsedByRoutes(): bool
    {
        $sessionGroups = $this->getGroupsContainingSession();

        /** @phpstan-ignore-next-line RouteCollection implements Traversable */
        foreach ($this->router->getRoutes() as $route) {
            if (! $route instanceof Route) {
                continue;
            }

            // Skip vendor-registered infrastructure routes — they don't represent
            // the app developer's own session usage (e.g. Vapor, Sanctum helpers).
            if ($this->isVendorRoute($route)) {
                continue;
            }

            if ($this->routeUsesSession($route, $sessionGroups)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether a route was registered by a vendor package rather than app code.
     *
     * Routes whose controller class lives inside the vendor directory are considered
     * vendor routes. Closure-based routes are always treated as app routes.
     */
    protected function isVendorRoute(Route $route): bool
    {
        $uses = $route->getAction('uses');

        if (! is_string($uses)) {
            return false; // Closure = app-defined route
        }

        $class = Str::before($uses, '@');

        try {
            // ReflectionClass resolves classes, interfaces, abstract classes, and traits.
            // class_exists() alone would miss interfaces (e.g. Laravel Vapor contracts).
            /** @phpstan-ignore-next-line argument.type */
            $file = (new ReflectionClass($class))->getFileName();

            return $file !== false && str_contains(
                str_replace('\\', '/', (string) $file),
                '/vendor/'
            );
        } catch (ReflectionException) {
            return false;
        }
    }

    /**
     * Get the names of middleware groups that contain StartSession.
     *
     * @return array<int, string> e.g. ['web', 'admin']
     */
    protected function getGroupsContainingSession(): array
    {
        if (! method_exists($this->router, 'getMiddlewareGroups')) {
            return [];
        }

        /** @phpstan-ignore-next-line method.notFound */
        $groups = $this->router->getMiddlewareGroups();

        if (! is_array($groups)) {
            return [];
        }

        $sessionGroups = [];

        foreach ($groups as $groupName => $middlewareList) {
            if (! is_string($groupName) || ! is_array($middlewareList)) {
                continue;
            }

            foreach ($middlewareList as $middleware) {
                if (! is_string($middleware)) {
                    continue;
                }

                if ($this->isStartSessionMiddleware(Str::before($middleware, ':'))) {
                    $sessionGroups[] = $groupName;
                    break;
                }
            }
        }

        return $sessionGroups;
    }

    /**
     * Check if a route uses session middleware.
     *
     * Uses gatherRouteMiddleware() for reliable alias/group expansion.
     *
     * @param  array<int, string>  $sessionGroups  Groups known to contain StartSession
     */
    protected function routeUsesSession(Route $route, array $sessionGroups): bool
    {
        if (! method_exists($this->router, 'gatherRouteMiddleware')) {
            return $this->routeMiddlewareContainsSession($route->middleware(), $sessionGroups);
        }

        try {
            /** @phpstan-ignore-next-line method.notFound */
            $gathered = $this->router->gatherRouteMiddleware($route);
        } catch (\Throwable) {
            return $this->routeMiddlewareContainsSession($route->middleware(), $sessionGroups);
        }

        if (! is_array($gathered)) {
            return false;
        }

        foreach ($gathered as $middleware) {
            if (! is_string($middleware)) {
                continue;
            }

            if ($this->isStartSessionMiddleware(Str::before($middleware, ':'))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a raw middleware array contains session middleware.
     *
     * Used as fallback when gatherRouteMiddleware() is unavailable.
     *
     * @param  array<int, string>  $sessionGroups
     */
    protected function routeMiddlewareContainsSession(mixed $middleware, array $sessionGroups): bool
    {
        if (! is_array($middleware)) {
            return false;
        }

        foreach ($middleware as $m) {
            if (! is_string($m)) {
                continue;
            }

            $middlewareName = Str::before($m, ':');

            if ($sessionGroups !== [] && in_array($middlewareName, $sessionGroups, true)) {
                return true;
            }

            if ($this->isStartSessionMiddleware($middlewareName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a middleware class is StartSession or a subclass of it.
     */
    protected function isStartSessionMiddleware(string $middleware): bool
    {
        if ($middleware === StartSession::class) {
            return true;
        }

        if (class_basename($middleware) === 'StartSession') {
            return true;
        }

        if (str_contains($middleware, '\\') && class_exists($middleware) && is_subclass_of($middleware, StartSession::class)) {
            return true;
        }

        return false;
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
