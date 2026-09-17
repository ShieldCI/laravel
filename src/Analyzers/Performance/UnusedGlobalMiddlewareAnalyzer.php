<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Fideloper\Proxy\TrustProxies as FideloperTrustProxies;
use Fruitcake\Cors\HandleCors as FruitcakeHandleCors;
use Illuminate\Contracts\Config\Repository as Config;
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
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Concerns\AnalyzesMiddleware;
use ShieldCI\Concerns\DetectsLaravelVersion;
use ShieldCI\Concerns\LocatesMiddlewareFile;

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
    use DetectsLaravelVersion;
    use LocatesMiddlewareFile;

    /**
     * @var array<int, array{name: string, class: string, reason: string, recommendation: string}>
     */
    private array $unusedMiddleware = [];

    public function __construct(
        private Application $app,
        private Config $config,
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

        // Resolved once, and before the checks, because the CORS recommendation
        // names this file too and must not contradict the reported location.
        $middlewareFile = $this->resolveMiddlewareFile();

        $this->checkTrustProxiesMiddleware();
        $this->checkTrustHostsMiddleware();
        $this->checkCorsMiddleware($middlewareFile);

        if (count($this->unusedMiddleware) === 0) {
            return $this->passed('No unused global middleware detected');
        }

        $middlewareLine = $middlewareFile === null
            ? null
            : $this->findMiddlewareArrayLine($middlewareFile);

        $issues = [];
        foreach ($this->unusedMiddleware as $middleware) {
            $message = "Unused global middleware detected: {$middleware['name']}";
            $metadata = [
                'middleware_class' => $middleware['class'],
                'middleware_name' => $middleware['name'],
                'reason' => $middleware['reason'],
            ];

            // createIssueWithSnippet() always builds a Location, so a project with
            // neither candidate file has to go through createIssue() instead.
            $issues[] = $middlewareFile === null
                ? $this->createIssue(
                    message: $message,
                    location: null,
                    severity: $this->metadata()->severity,
                    recommendation: $middleware['recommendation'],
                    metadata: $metadata
                )
                : $this->createIssueWithSnippet(
                    message: $message,
                    filePath: $middlewareFile,
                    lineNumber: $middlewareLine,
                    severity: $this->metadata()->severity,
                    recommendation: $middleware['recommendation'],
                    metadata: $metadata
                );
        }

        $summary = sprintf('Found %d unused global middleware', count($this->unusedMiddleware));

        return $this->resultBySeverity($summary, $issues);
    }

    private function checkTrustProxiesMiddleware(): void
    {
        // In Laravel 11+, TrustProxies is a framework-level default (not user-registered).
        // Flagging it would be a false positive for every Laravel 11+ application.
        if ($this->isLaravel11OrNewer()) {
            return;
        }

        // Check if TrustProxies middleware is registered (Laravel 9/10 or Fideloper package)
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
                    'Remove TrustProxies middleware from the global middleware stack in app/Http/Kernel.php, as no proxies are configured. This middleware runs on every request unnecessarily. Only add it back if you deploy behind a proxy such as CloudFlare, AWS ALB, or nginx.'
                );
            }
        } catch (\Throwable $e) {
            // Unable to instantiate middleware, skip check
            return;
        }
    }

    private function checkTrustHostsMiddleware(): void
    {
        // In Laravel 11+, TrustHosts is managed via the framework's withMiddleware()->trustHosts()
        // method, not as a user-registered global middleware. Skip to avoid false positives.
        if ($this->isLaravel11OrNewer()) {
            return;
        }

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
                'Remove TrustHosts middleware from the global middleware stack in app/Http/Kernel.php. TrustHosts only works when used together with TrustProxies middleware, as it validates the Host header from trusted proxies.'
            );
        }
    }

    private function checkCorsMiddleware(?string $middlewareFile): void
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
                $this->corsRemovalRecommendation($middlewareFile)
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
     * Find the line the global middleware stack is declared on, or null when it
     * cannot be located in the file.
     *
     * Returning null rather than 1 is the point: a reader cannot tell a fabricated 1
     * from a declaration genuinely on line 1, and createIssueWithSnippet() accepts a
     * null line, naming the file without pretending to know where in it to look.
     *
     * The previous Kernel.php lookup went through ConfigFileHelper::findKeyLine(),
     * which searches for a `'middleware' =>` config entry and answers 1 by contract
     * when it finds nothing - so the `$lineNumber < 1` guard below it never fired and
     * the property scan it guarded was unreachable. That scan is now the lookup.
     */
    private function findMiddlewareArrayLine(string $filePath): ?int
    {
        $pattern = $this->middlewareFileIsHttpKernel($filePath)
            ? '/protected\s+\$middleware\s*=/'  // Laravel 9/10: the $middleware property
            : '/withMiddleware\s*\(/';           // Laravel 11+: the withMiddleware() callback

        foreach (FileParser::getLines($filePath) as $lineNum => $line) {
            if (preg_match($pattern, $line) === 1) {
                return $lineNum + 1;
            }
        }

        return null;
    }

    /**
     * Version-correct removal instructions, keyed off the file actually found rather
     * than off the running framework, so the advice cannot name a different file than
     * the issue location does.
     */
    private function corsRemovalRecommendation(?string $middlewareFile): string
    {
        if ($middlewareFile === null) {
            return 'Remove HandleCors from the global middleware stack, as no CORS paths are configured. '
                .'In Laravel 11+ that is the withMiddleware() callback in bootstrap/app.php; in Laravel 9/10 it is the $middleware array in app/Http/Kernel.php. '
                .'This middleware runs on every request unnecessarily. Only add it back when you configure specific paths in config/cors.php.';
        }

        if ($this->middlewareFileIsHttpKernel($middlewareFile)) {
            return 'Remove HandleCors middleware from the global middleware stack in app/Http/Kernel.php, as no CORS paths are configured. This middleware runs on every request unnecessarily. Only add it back when you configure specific paths that require CORS handling in config/cors.php.';
        }

        return 'Remove HandleCors from the withMiddleware() callback in bootstrap/app.php, as no CORS paths are configured. This middleware runs on every request unnecessarily. Only add it back when you configure specific paths in config/cors.php.';
    }
}
