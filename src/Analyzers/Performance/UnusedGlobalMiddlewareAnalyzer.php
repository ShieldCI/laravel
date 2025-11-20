<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Fideloper\Proxy\TrustProxies as FideloperTrustProxies;
use Fruitcake\Cors\HandleCors as FruitcakeHandleCors;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Middleware\HandleCors;
use Illuminate\Http\Middleware\TrustHosts;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Routing\Router;
use ReflectionClass;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\AnalyzesMiddleware;

/**
 * Detects unused global HTTP middleware in the application.
 *
 * Uses runtime analysis to accurately detect middleware registration and configuration.
 *
 * Checks for:
 * - TrustProxies middleware without configured proxies
 * - TrustHosts middleware without TrustProxies (useless)
 * - CORS middleware without configured paths
 */
class UnusedGlobalMiddlewareAnalyzer extends AbstractAnalyzer
{
    use AnalyzesMiddleware;

    /**
     * @var array<int, array{name: string, class: string, reason: string, recommendation: string}>
     */
    private array $unusedMiddleware = [];

    public function __construct(
        private Application $app,
        private ConfigRepository $config,
        Router $router,
        Kernel $kernel
    ) {
        $this->router = $router;
        $this->kernel = $kernel;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'unused-global-middleware',
            name: 'Unused Global Middleware',
            description: 'Detects global HTTP middleware that is registered but not being used, causing unnecessary overhead on every request',
            category: Category::Performance,
            severity: Severity::Low,
            tags: ['performance', 'middleware', 'optimization', 'http'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/unused-global-middleware',
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $this->unusedMiddleware = [];

        $this->checkTrustProxiesMiddleware();
        $this->checkTrustHostsMiddleware();
        $this->checkCorsMiddleware();

        if (empty($this->unusedMiddleware)) {
            return $this->passed('No unused global middleware detected');
        }

        $issues = [];
        foreach ($this->unusedMiddleware as $middleware) {
            $issues[] = $this->createIssue(
                message: "Unused global middleware detected: {$middleware['name']}",
                location: new Location(base_path('app/Http/Kernel.php'), 0),
                severity: Severity::Low,
                recommendation: $middleware['recommendation'],
                metadata: [
                    'middleware_class' => $middleware['class'],
                    'middleware_name' => $middleware['name'],
                    'reason' => $middleware['reason'],
                ]
            );
        }

        return $this->failed(
            sprintf('Found %d unused global middleware', count($this->unusedMiddleware)),
            $issues
        );
    }

    private function checkTrustProxiesMiddleware(): void
    {
        // Check if TrustProxies middleware is registered (Laravel 9+ or Fideloper package)
        $isFideloper = class_exists(FideloperTrustProxies::class)
            && $this->appUsesGlobalMiddleware(FideloperTrustProxies::class);
        $isLaravel = class_exists(TrustProxies::class)
            && $this->appUsesGlobalMiddleware(TrustProxies::class);

        if (! $isFideloper && ! $isLaravel) {
            return;
        }

        // Find the actual middleware class being used
        $middlewareClass = collect($this->getGlobalMiddleware())->filter(function ($middleware) {
            return $this->isTrustProxiesMiddleware($middleware);
        })->first();

        if ($middlewareClass === null) {
            return;
        }

        try {
            // Instantiate the middleware and check if proxies are configured
            $middleware = $this->app->make($middlewareClass);

            if (! is_object($middleware)) {
                return;
            }

            $proxies = $this->getPropertyValue($middleware, 'proxies');

            // Check config for older Fideloper package
            $configProxies = $this->config->get('trustedproxy.proxies');

            if (empty($proxies) && is_null($configProxies)) {
                $this->unusedMiddleware[] = [
                    'name' => class_basename($middlewareClass),
                    'class' => $middlewareClass,
                    'reason' => 'No proxies are configured',
                    'recommendation' => 'Remove TrustProxies middleware from app/Http/Kernel.php $middleware array, as no proxies are configured. This middleware runs on every request unnecessarily. Only add it back if you deploy behind a proxy (like CloudFlare, AWS ALB, nginx).',
                ];

                // If TrustHosts is also registered, it's useless without TrustProxies
                if ($this->appUsesGlobalMiddleware(TrustHosts::class)) {
                    $this->unusedMiddleware[] = [
                        'name' => class_basename(TrustHosts::class),
                        'class' => TrustHosts::class,
                        'reason' => 'TrustHosts is useless without TrustProxies',
                        'recommendation' => 'Remove TrustHosts middleware from app/Http/Kernel.php $middleware array. TrustHosts only works when used together with TrustProxies middleware, as it validates the Host header from trusted proxies.',
                    ];
                }
            }
        } catch (\Throwable $e) {
            // Unable to instantiate middleware, skip check
            return;
        }
    }

    private function checkTrustHostsMiddleware(): void
    {
        // Only check if TrustHosts is registered without TrustProxies
        if (! $this->appUsesGlobalMiddleware(TrustHosts::class)) {
            return;
        }

        // Check if TrustProxies is also registered
        $hasTrustProxies = $this->appUsesGlobalMiddleware(TrustProxies::class)
            || (class_exists(FideloperTrustProxies::class) && $this->appUsesGlobalMiddleware(FideloperTrustProxies::class));

        if (! $hasTrustProxies) {
            $this->unusedMiddleware[] = [
                'name' => class_basename(TrustHosts::class),
                'class' => TrustHosts::class,
                'reason' => 'TrustHosts is useless without TrustProxies',
                'recommendation' => 'Remove TrustHosts middleware from app/Http/Kernel.php $middleware array. TrustHosts only works when used together with TrustProxies middleware, as it validates the Host header from trusted proxies.',
            ];
        }
    }

    private function checkCorsMiddleware(): void
    {
        // Check if CORS middleware is registered (Laravel 9+ or Fruitcake package)
        $hasCors = (class_exists(HandleCors::class) && $this->appUsesGlobalMiddleware(HandleCors::class))
            || (class_exists(FruitcakeHandleCors::class) && $this->appUsesGlobalMiddleware(FruitcakeHandleCors::class));

        if (! $hasCors) {
            return;
        }

        // Check if CORS paths are configured
        $corsPaths = $this->config->get('cors.paths', []);

        if (empty($corsPaths)) {
            /** @phpstan-ignore-next-line Class may not exist (optional dependency) */
            $middlewareClass = class_exists(HandleCors::class) ? HandleCors::class : FruitcakeHandleCors::class;

            $this->unusedMiddleware[] = [
                'name' => class_basename($middlewareClass),
                'class' => $middlewareClass,
                'reason' => 'No CORS paths are configured',
                'recommendation' => 'Remove HandleCors middleware from app/Http/Kernel.php $middleware array, as no CORS paths are configured. This middleware runs on every request unnecessarily. Only add it back when you configure specific paths that require CORS handling in config/cors.php.',
            ];
        }
    }

    /**
     * Get property value from an object using reflection.
     */
    private function getPropertyValue(object $instance, string $propertyName): mixed
    {
        try {
            $reflection = new ReflectionClass($instance);
            $property = $reflection->getProperty($propertyName);
            $property->setAccessible(true);
            $value = $property->getValue($instance);
            $property->setAccessible(false);

            return $value;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Check if middleware is TrustProxies middleware.
     */
    private function isTrustProxiesMiddleware(string $middlewareClass): bool
    {
        if (! class_exists($middlewareClass)) {
            return false;
        }

        return $middlewareClass === TrustProxies::class
            || is_subclass_of($middlewareClass, TrustProxies::class)
            || (class_exists(FideloperTrustProxies::class) && (
                $middlewareClass === FideloperTrustProxies::class
                || is_subclass_of($middlewareClass, FideloperTrustProxies::class)
            ));
    }
}
