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
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
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
            name: 'Unused Global Middleware Analyzer',
            description: 'Detects global HTTP middleware that is registered but not being used, causing unnecessary overhead on every request',
            category: Category::Performance,
            severity: Severity::Low,
            tags: ['performance', 'middleware', 'optimization', 'http'],
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $this->unusedMiddleware = [];

        $this->checkTrustProxiesMiddleware();
        $this->checkTrustHostsMiddleware();
        $this->checkCorsMiddleware();

        if (count($this->unusedMiddleware) === 0) {
            return $this->passed('No unused global middleware detected');
        }

        $kernelPath = $this->getKernelPath();
        $middlewareLine = $this->findMiddlewareArrayLine($kernelPath);

        $issues = [];
        foreach ($this->unusedMiddleware as $middleware) {
            $issues[] = $this->createIssueWithSnippet(
                message: "Unused global middleware detected: {$middleware['name']}",
                filePath: $kernelPath,
                lineNumber: $middlewareLine,
                severity: Severity::Low,
                recommendation: $middleware['recommendation'],
                code: $middleware['name'],
                metadata: [
                    'middleware_class' => $middleware['class'],
                    'middleware_name' => $middleware['name'],
                    'reason' => $middleware['reason'],
                ]
            );
        }

        $summary = sprintf('Found %d unused global middleware', count($this->unusedMiddleware));

        return $this->resultBySeverity($summary, $issues);
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

            // Validate proxies value type
            if (! is_string($proxies) && ! is_array($proxies) && $proxies !== null) {
                $proxies = null;
            }

            // Check config for older Fideloper package
            $configProxies = $this->config->get('trustedproxy.proxies');

            // Validate config value type
            if ($configProxies !== null && ! is_string($configProxies) && ! is_array($configProxies)) {
                $configProxies = null;
            }

            if (empty($proxies) && $configProxies === null) {
                $this->addUnusedMiddleware(
                    class_basename($middlewareClass),
                    $middlewareClass,
                    'No proxies are configured',
                    'Remove TrustProxies middleware from app/Http/Kernel.php $middleware array, as no proxies are configured. This middleware runs on every request unnecessarily. Only add it back if you deploy behind a proxy (like CloudFlare, AWS ALB, nginx).'
                );
            }
        } catch (\Throwable $e) {
            // Unable to instantiate middleware, skip check
            return;
        }
    }

    private function checkTrustHostsMiddleware(): void
    {
        // Only check if TrustHosts is registered
        if (! $this->appUsesGlobalMiddleware(TrustHosts::class)) {
            return;
        }

        // Check if TrustProxies is also registered AND configured
        $hasTrustProxies = $this->appUsesGlobalMiddleware(TrustProxies::class)
            || (class_exists(FideloperTrustProxies::class) && $this->appUsesGlobalMiddleware(FideloperTrustProxies::class));

        // Check if TrustProxies is already flagged as unused (meaning it exists but is not configured)
        $trustProxiesUnused = collect($this->unusedMiddleware)->contains(function ($middleware) {
            return $middleware['class'] === TrustProxies::class
                || (class_exists(FideloperTrustProxies::class) && $middleware['class'] === FideloperTrustProxies::class);
        });

        // If TrustProxies doesn't exist, OR it exists but is unused, then TrustHosts is useless
        if (! $hasTrustProxies || $trustProxiesUnused) {
            $this->addUnusedMiddleware(
                class_basename(TrustHosts::class),
                TrustHosts::class,
                'TrustHosts is useless without TrustProxies',
                'Remove TrustHosts middleware from app/Http/Kernel.php $middleware array. TrustHosts only works when used together with TrustProxies middleware, as it validates the Host header from trusted proxies.'
            );
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

        // Validate config value type
        if (! is_array($corsPaths)) {
            $corsPaths = [];
        }

        if (empty($corsPaths)) {
            /** @phpstan-ignore-next-line Class may not exist (optional dependency) */
            $middlewareClass = class_exists(HandleCors::class) ? HandleCors::class : FruitcakeHandleCors::class;

            $this->addUnusedMiddleware(
                class_basename($middlewareClass),
                $middlewareClass,
                'No CORS paths are configured',
                'Remove HandleCors middleware from app/Http/Kernel.php $middleware array, as no CORS paths are configured. This middleware runs on every request unnecessarily. Only add it back when you configure specific paths that require CORS handling in config/cors.php.'
            );
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

    /**
     * Add an unused middleware entry to the list.
     * Avoids duplicates by checking if the class is already in the list.
     */
    private function addUnusedMiddleware(
        string $name,
        string $class,
        string $reason,
        string $recommendation
    ): void {
        // Check if already added
        foreach ($this->unusedMiddleware as $existing) {
            if ($existing['class'] === $class) {
                return; // Already added, skip
            }
        }

        $this->unusedMiddleware[] = [
            'name' => $name,
            'class' => $class,
            'reason' => $reason,
            'recommendation' => $recommendation,
        ];
    }

    /**
     * Get the path to the HTTP Kernel file.
     */
    private function getKernelPath(): string
    {
        $basePath = $this->getBasePath();

        return $basePath.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR.'Kernel.php';
    }

    /**
     * Find the line number of the $middleware array in Kernel.php.
     * Falls back to line 1 if not found.
     */
    private function findMiddlewareArrayLine(string $kernelPath): int
    {
        if (! file_exists($kernelPath)) {
            return 1;
        }

        // Try to find the $middleware property declaration
        $lineNumber = ConfigFileHelper::findKeyLine($kernelPath, 'middleware');

        if ($lineNumber < 1) {
            // Fallback: try to find any line containing 'protected $middleware'
            $lines = FileParser::getLines($kernelPath);
            foreach ($lines as $lineNum => $line) {
                if (preg_match('/protected\s+\$middleware\s*=/', $line) === 1) {
                    return $lineNum + 1;
                }
            }

            return 1;
        }

        return $lineNumber;
    }
}
