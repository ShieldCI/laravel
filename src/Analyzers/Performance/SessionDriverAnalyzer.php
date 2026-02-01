<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Str;
use ReflectionClass;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Analyzes session driver configuration for performance and scalability.
 *
 * Checks for:
 * - Null session driver (sessions disabled while routes use them)
 * - File session driver in multi-server environments
 * - Cookie session driver limitations
 * - Array session driver in production
 * - Recommends Redis/Database for production
 *
 * This analyzer uses Laravel's config repository and checks if sessions
 * are actually used before warning about driver choice.
 */
class SessionDriverAnalyzer extends AbstractAnalyzer
{
    public function __construct(
        private ConfigRepository $config,
        private Router $router,
        private Kernel $kernel
    ) {
        $this->configRepository = $config;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'session-driver',
            name: 'Session Driver Configuration Analyzer',
            description: 'Ensures a proper session driver is configured for scalability and performance',
            category: Category::Performance,
            severity: Severity::Critical,
            tags: ['session', 'performance', 'configuration', 'redis', 'scalability'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/session-driver',
            timeToFix: 30
        );
    }

    public function shouldRun(): bool
    {
        // Only run if the app actually uses sessions
        return ! $this->appIsStateless();
    }

    public function getSkipReason(): string
    {
        return 'Application does not use sessions (stateless)';
    }

    protected function runAnalysis(): ResultInterface
    {
        $driver = $this->config->get('session.driver', 'file');
        $environment = $this->getEnvironment();

        if (! is_string($driver) || ! is_string($environment)) {
            return $this->error('Invalid session driver or environment configuration');
        }

        // Assess the driver based on environment
        $issue = $this->assessDriver($driver, $environment);
        $issues = $issue !== null ? [$issue] : [];

        $message = empty($issues)
            ? "Session driver '$driver' is properly configured for $environment environment"
            : "Session driver '$driver' has configuration issues";

        return $this->resultBySeverity($message, $issues);
    }

    /**
     * Assess a session driver and return an issue if problematic.
     */
    private function assessDriver(string $driver, string $environment): ?Issue
    {
        return match ($driver) {
            'null' => $this->assessNullDriver($environment),
            'array' => $this->assessArrayDriver($environment),
            'file' => $this->assessFileDriver($environment),
            'cookie' => $this->assessCookieDriver($environment),
            default => null, // redis, database, memcached, dynamodb are all fine
        };
    }

    /**
     * Assess null driver - sessions are completely disabled.
     */
    private function assessNullDriver(string $environment): Issue
    {
        return $this->createIssue(
            message: "Session driver is set to 'null' - sessions are disabled",
            location: $this->getConfigLocation(),
            severity: Severity::Critical,
            recommendation: 'Null driver disables sessions completely. All session operations will fail. If you have routes using session middleware, this will cause errors. Use redis, database, or file driver instead.',
            metadata: [
                'driver' => 'null',
                'environment' => $environment,
                'uses_sessions' => true,
            ]
        );
    }

    /**
     * Assess array driver - sessions lost after request.
     */
    private function assessArrayDriver(string $environment): ?Issue
    {
        if ($this->isLocalEnvironment($environment)) {
            return null; // Acceptable in local
        }

        return $this->createIssue(
            message: "Session driver is set to 'array' in $environment environment",
            location: $this->getConfigLocation(),
            severity: Severity::Critical,
            recommendation: 'Array driver stores sessions in memory and they are lost after the request. This is only suitable for testing. Use redis, database, or file for production.',
            metadata: [
                'driver' => 'array',
                'environment' => $environment,
            ]
        );
    }

    /**
     * Assess file driver - problematic in multi-server setups.
     */
    private function assessFileDriver(string $environment): ?Issue
    {
        if ($this->isLocalEnvironment($environment)) {
            return null; // Perfectly fine for local dev
        }

        return $this->createIssue(
            message: "Session driver is set to 'file' in $environment environment",
            location: $this->getConfigLocation(),
            severity: Severity::Medium,
            recommendation: 'File session driver only works properly on single-server setups. For load-balanced or multi-server environments, use redis or database driver to share sessions across servers. File sessions can cause users to be logged out when requests hit different servers.',
            metadata: [
                'driver' => 'file',
                'environment' => $environment,
            ]
        );
    }

    /**
     * Assess cookie driver - size limitations and security concerns.
     */
    private function assessCookieDriver(string $environment): ?Issue
    {
        if ($this->isLocalEnvironment($environment)) {
            return null; // Fine for local development
        }

        return $this->createIssue(
            message: "Session driver is set to 'cookie' in $environment environment",
            location: $this->getConfigLocation(),
            severity: Severity::Low,
            recommendation: 'Cookie driver stores all session data in encrypted cookies. This has a 4KB size limit and every request sends all session data. For better performance and security, consider using redis or database driver.',
            metadata: [
                'driver' => 'cookie',
                'environment' => $environment,
            ]
        );
    }

    /**
     * Check if the application is stateless (doesn't use sessions).
     *
     * Optimized detection order:
     * 1. Check global middleware (fast, usually empty or few items)
     * 2. Check if any session-containing middleware group is used by routes
     */
    private function appIsStateless(): bool
    {
        // 1. Check global middleware first (fast)
        if ($this->hasSessionInGlobalMiddleware()) {
            return false;
        }

        // 2. Check if any session-containing group is actually used by routes
        if ($this->hasSessionGroupUsedByRoutes()) {
            return false;
        }

        return true; // App is stateless
    }

    /**
     * Check if StartSession middleware is in global middleware.
     */
    private function hasSessionInGlobalMiddleware(): bool
    {
        $globalMiddleware = $this->getGlobalMiddleware();

        foreach ($globalMiddleware as $middleware) {
            if ($this->isStartSessionMiddleware($middleware)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if any route uses middleware that resolves to StartSession.
     *
     * This avoids false positives where a group (e.g., 'web') contains StartSession
     * but no routes actually use that group (e.g., API-only apps).
     *
     * Uses gatherRouteMiddleware() for reliable alias/group expansion.
     */
    private function hasSessionGroupUsedByRoutes(): bool
    {
        // Early exit: if no middleware group contains StartSession,
        // routes can't possibly use sessions via groups
        $sessionGroups = $this->getGroupsContainingSession();

        // If no groups have sessions, we still need to check for direct StartSession assignment
        // but we can skip the expensive gatherRouteMiddleware if no routes exist
        $routes = $this->router->getRoutes();

        // Check each route's resolved middleware for StartSession
        /** @phpstan-ignore-next-line RouteCollection implements Traversable */
        foreach ($routes as $route) {
            if (! $route instanceof \Illuminate\Routing\Route) {
                continue;
            }

            if ($this->routeUsesSession($route, $sessionGroups)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a route uses session middleware.
     * Uses gatherRouteMiddleware() for reliable alias/group expansion.
     *
     * @param  array<int, string>  $sessionGroups  Groups known to contain StartSession
     */
    private function routeUsesSession(\Illuminate\Routing\Route $route, array $sessionGroups): bool
    {
        // Use gatherRouteMiddleware to properly resolve all middleware
        if (! method_exists($this->router, 'gatherRouteMiddleware')) {
            // Fallback for older Laravel: check raw middleware
            return $this->routeMiddlewareContainsSession($route->middleware(), $sessionGroups);
        }

        try {
            $gathered = $this->router->gatherRouteMiddleware($route);
        } catch (\Throwable) {
            // Fallback on error
            return $this->routeMiddlewareContainsSession($route->middleware(), $sessionGroups);
        }

        if (! is_array($gathered)) {
            return false;
        }

        foreach ($gathered as $middleware) {
            if (! is_string($middleware)) {
                continue;
            }

            $middlewareClass = Str::before($middleware, ':');

            if ($this->isStartSessionMiddleware($middlewareClass)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if raw middleware array contains session middleware.
     * Used as fallback when gatherRouteMiddleware is not available.
     *
     * @param  array<int, string>  $sessionGroups
     */
    private function routeMiddlewareContainsSession(mixed $middleware, array $sessionGroups): bool
    {
        if (! is_array($middleware)) {
            return false;
        }

        foreach ($middleware as $m) {
            if (! is_string($m)) {
                continue;
            }

            $middlewareName = Str::before($m, ':');

            // Check if this middleware is a session-containing group
            if ($sessionGroups !== [] && in_array($middlewareName, $sessionGroups, true)) {
                return true;
            }

            // Check for StartSession directly assigned
            if ($this->isStartSessionMiddleware($middlewareName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the names of middleware groups that contain StartSession.
     *
     * @return array<int, string> Group names like ['web', 'admin']
     */
    private function getGroupsContainingSession(): array
    {
        if (! method_exists($this->router, 'getMiddlewareGroups')) {
            return [];
        }

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

                $middlewareClass = Str::before($middleware, ':');
                if ($this->isStartSessionMiddleware($middlewareClass)) {
                    $sessionGroups[] = $groupName;
                    break; // Found in this group, move to next
                }
            }
        }

        return $sessionGroups;
    }

    /**
     * Get the global middleware from the kernel.
     *
     * @return array<int, string>
     */
    private function getGlobalMiddleware(): array
    {
        // Try the public method first (Laravel 10+)
        if (method_exists($this->kernel, 'getGlobalMiddleware')) {
            $middleware = $this->kernel->getGlobalMiddleware();

            return is_array($middleware) ? $middleware : [];
        }

        // Fall back to reflection for older Laravel versions
        try {
            $mirror = new ReflectionClass($this->kernel);
            $property = $mirror->getProperty('middleware');
            $property->setAccessible(true);

            $middlewareList = $property->getValue($this->kernel);

            if (! is_array($middlewareList)) {
                return [];
            }

            /** @var array<int, string> */
            return array_values(array_filter(array_map(
                fn ($m): string => is_string($m) ? Str::before($m, ':') : '',
                $middlewareList
            )));
        } catch (\ReflectionException) {
            return [];
        }
    }

    /**
     * Check if a middleware class is StartSession or a subclass of it.
     */
    private function isStartSessionMiddleware(string $middleware): bool
    {
        // Exact match
        if ($middleware === StartSession::class) {
            return true;
        }

        // Check basename match (e.g., "StartSession" without namespace)
        if (class_basename($middleware) === 'StartSession') {
            return true;
        }

        // Check if it's a subclass of StartSession
        if (str_contains($middleware, '\\') && class_exists($middleware) && is_subclass_of($middleware, StartSession::class)) {
            return true;
        }

        return false;
    }

    /**
     * Check if environment is local/development.
     */
    private function isLocalEnvironment(string $environment): bool
    {
        return in_array($environment, ['local', 'development', 'testing'], true);
    }

    /**
     * Get the location of the session driver configuration.
     */
    private function getConfigLocation(): Location
    {
        $basePath = $this->getBasePath();
        $configPath = ConfigFileHelper::getConfigPath(
            $basePath,
            'session.php',
            fn ($file) => function_exists('config_path') ? config_path($file) : null
        );

        $lineNumber = ConfigFileHelper::findKeyLine($configPath, 'driver');

        return new Location($this->getRelativePath($configPath), $lineNumber < 1 ? null : $lineNumber);
    }
}
