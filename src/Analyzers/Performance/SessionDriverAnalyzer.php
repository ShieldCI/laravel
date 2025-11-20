<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
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
            name: 'Session Driver Configuration',
            description: 'Ensures a proper session driver is configured for scalability and performance',
            category: Category::Performance,
            severity: Severity::Medium,
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

        if ($issue !== null) {
            return $this->failed(
                "Session driver '$driver' has configuration issues",
                [$issue]
            );
        }

        return $this->passed("Session driver '$driver' is properly configured for $environment environment");
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
        if ($environment === 'local') {
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
        if ($environment === 'local') {
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
        if ($environment === 'local') {
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
     * Checks if session middleware is registered globally or on any routes.
     */
    private function appIsStateless(): bool
    {
        // Check if session middleware is in global middleware
        $globalMiddleware = method_exists($this->kernel, 'getGlobalMiddleware')
            ? $this->kernel->getGlobalMiddleware()
            : [];

        foreach ($globalMiddleware as $middleware) {
            if ($this->isSessionMiddleware($middleware)) {
                return false; // App uses sessions
            }
        }

        // Check if any route uses session middleware
        $routes = $this->router->getRoutes();
        /** @phpstan-ignore-next-line RouteCollection implements Traversable */
        foreach ($routes as $route) {
            $middleware = $route->middleware();

            foreach ($middleware as $m) {
                if ($this->isSessionMiddleware($m)) {
                    return false; // App uses sessions
                }
            }
        }

        return true; // App is stateless
    }

    /**
     * Check if a middleware is session-related.
     */
    private function isSessionMiddleware(string $middleware): bool
    {
        return str_contains($middleware, 'StartSession')
            || str_contains($middleware, 'session')
            || $middleware === 'web'; // 'web' middleware group typically includes session
    }

    /**
     * Get the location of the session driver configuration.
     */
    private function getConfigLocation(): Location
    {
        $basePath = $this->getBasePath();
        $configPath = ConfigFileHelper::getConfigPath($basePath, 'session.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        // Try to find the exact line with 'driver' key
        if (file_exists($configPath)) {
            $lines = file($configPath);
            if ($lines !== false) {
                foreach ($lines as $lineNumber => $line) {
                    if (str_contains($line, "'driver'") || str_contains($line, '"driver"')) {
                        return new Location($configPath, $lineNumber + 1);
                    }
                }
            }
        }

        return new Location($configPath, 1);
    }
}
