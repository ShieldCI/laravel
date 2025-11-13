<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use Exception;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Str;

/**
 * Trait FindsLoginRoute
 *
 * Provides functionality to discover a guest-accessible URL for HTTP inspection.
 */
trait FindsLoginRoute
{
    /**
     * The router instance.
     */
    protected Router $router;

    /**
     * Find the login route URL. Returns null if not found.
     *
     * Uses a 4-tier fallback system:
     * 1. Check config('shieldci.guest_url') if provided
     * 2. Try to resolve route('login')
     * 3. Search for first route with guest/RedirectIfAuthenticated middleware
     * 4. Fallback to root URL '/'
     */
    protected function findLoginRoute(): ?string
    {
        // Priority 1: Check if a guest path is provided in config
        $guestPath = config('shieldci.guest_url');
        if (! is_null($guestPath) && is_string($guestPath)) {
            return $this->convertToString(url($guestPath));
        }

        // Priority 2: Try the login named route
        // By default, Laravel uses the named route "login" for all its auth scaffolding packages
        try {
            return $this->convertToString(route('login'));
        } catch (Exception $e) {
            // Route doesn't exist, continue to next fallback
        }

        // Priority 3: Search for the first route that has the guest middleware
        $routes = $this->router->getRoutes()->getRoutes();

        foreach ($routes as $route) {
            if ($this->routeHasGuestMiddleware($route)) {
                return $this->convertToString(url($route->uri()));
            }
        }

        // Priority 4: If all else fails, fallback to the root URL
        return $this->convertToString(url('/'));
    }

    /**
     * Convert URL result to string.
     *
     * @param  \Illuminate\Contracts\Routing\UrlGenerator|string  $url
     */
    protected function convertToString($url): string
    {
        if (is_string($url)) {
            return $url;
        }

        // UrlGenerator's to('/') method returns string
        // But in this case, url() already returns the correct URL
        // Just call current() to get the current URL as string
        if (method_exists($url, 'current')) {
            return $url->current();
        }

        // Fallback: try toString method or cast
        if (method_exists($url, 'toString')) {
            return $url->toString();
        }

        // Last resort: PHP's string cast
        // @phpstan-ignore-next-line
        return (string) $url;
    }

    /**
     * Determine if a route uses guest middleware (RedirectIfAuthenticated).
     *
     * @param  mixed  $route
     */
    protected function routeHasGuestMiddleware($route): bool
    {
        if (! ($route instanceof Route)) {
            return false;
        }

        $middleware = $route->middleware();

        // Middleware can be null, array, or Route - handle each case
        if (! is_array($middleware)) {
            return false;
        }

        foreach ($middleware as $m) {
            // Check for guest middleware or RedirectIfAuthenticated class
            if (is_string($m) && ($m === 'guest' || Str::contains($m, 'RedirectIfAuthenticated'))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Set the router instance.
     */
    public function setRouter(Router $router): void
    {
        $this->router = $router;
    }
}
