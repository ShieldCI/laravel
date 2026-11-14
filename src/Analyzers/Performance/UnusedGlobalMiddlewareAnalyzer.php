<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Fideloper\Proxy\TrustProxies as FideloperTrustProxies;
use Fruitcake\Cors\HandleCors as FruitcakeHandleCors;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Middleware\HandleCors;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Routing\Router;
use ReflectionClass;
use ReflectionMethod;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Concerns\AnalyzesMiddleware;
use ShieldCI\Concerns\DetectsLaravelVersion;
use ShieldCI\Concerns\LocatesMiddlewareFile;
use ShieldCI\Concerns\SanitizesErrorMessages;

/**
 * Detects unused global HTTP middleware in the application.
 *
 * Uses runtime analysis to accurately detect middleware registration and configuration.
 *
 * Checks for:
 * - TrustProxies middleware without configured proxies
 * - CORS middleware without configured paths
 */
class UnusedGlobalMiddlewareAnalyzer extends AbstractAnalyzer
{
    use AnalyzesMiddleware;
    use DetectsLaravelVersion;
    use LocatesMiddlewareFile;
    use SanitizesErrorMessages;

    /**
     * @var array<int, array{name: string, class: string, reason: string, recommendation: string}>
     */
    private array $unusedMiddleware = [];

    /**
     * Why the registered TrustProxies middleware could not be examined, or null when it
     * was examined or is not registered. A run-status note rather than an issue.
     */
    private ?string $trustProxiesUninspected = null;

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
        $this->trustProxiesUninspected = null;

        // Resolved once, and before the checks, because the CORS recommendation
        // names this file too and must not contradict the reported location.
        $middlewareFile = $this->resolveMiddlewareFile();

        $this->checkTrustProxiesMiddleware();
        $this->checkCorsMiddleware($middlewareFile);

        if (count($this->unusedMiddleware) === 0) {
            // A middleware that was never examined is not a clean bill of health.
            if ($this->trustProxiesUninspected !== null) {
                return $this->warning(
                    'No unused global middleware detected, but '.$this->trustProxiesUninspected
                );
            }

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

        if ($this->trustProxiesUninspected !== null) {
            $summary .= sprintf(' (%s)', $this->trustProxiesUninspected);
        }

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

        // Both the framework and Fideloper fall back to trustedproxy.proxies whatever the
        // instance holds, so a configured value means the middleware is in use and there
        // is no need to build it.
        $configProxies = $this->config->get('trustedproxy.proxies');

        // Validate config value type
        if ($configProxies !== null && ! is_string($configProxies) && ! is_array($configProxies)) {
            $configProxies = null;
        }

        if ($configProxies !== null) {
            return;
        }

        // Only the instantiation and the proxies read are guarded: a failure in either
        // means the middleware could not be examined, which is recorded rather than read
        // as "nothing unused".
        try {
            $middleware = $this->app->make($middlewareClass);
        } catch (\Throwable $e) {
            $this->markTrustProxiesUninspected($middlewareClass, $this->describeFailure($e));

            return;
        }

        if (! is_object($middleware)) {
            $this->markTrustProxiesUninspected($middlewareClass, 'the container did not return an object');

            return;
        }

        try {
            $proxies = $this->readConfiguredProxies($middleware);
        } catch (\Throwable $e) {
            $this->markTrustProxiesUninspected($middlewareClass, $this->describeFailure($e));

            return;
        }

        // Validate proxies value type
        if (! is_string($proxies) && ! is_array($proxies) && $proxies !== null) {
            $proxies = null;
        }

        if (empty($proxies)) {
            $this->addUnusedMiddleware(
                class_basename($middlewareClass),
                $middlewareClass,
                'No proxies are configured',
                'Remove TrustProxies middleware from the global middleware stack in app/Http/Kernel.php, as no proxies are configured. This middleware runs on every request unnecessarily. Only add it back if you deploy behind a proxy such as CloudFlare, AWS ALB, or nginx.'
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
     * Read the proxies the middleware trusts the way the framework does.
     *
     * Illuminate's TrustProxies (9.x onward) reads $this->proxies(), so an app may
     * configure its proxies by overriding that method instead of setting the property.
     * Fideloper's TrustProxies reads the property directly and never calls a proxies()
     * method, even one a subclass defines, so only the Illuminate class gets the call.
     * A throw from the method is left to the caller, which records it.
     */
    private function readConfiguredProxies(object $middleware): mixed
    {
        if ($middleware instanceof TrustProxies) {
            // Protected on the framework class; reflection reaches it without
            // setAccessible() on PHP 8.1+.
            return (new ReflectionMethod($middleware, 'proxies'))->invoke($middleware);
        }

        return $this->getPropertyValue($middleware, 'proxies');
    }

    private function markTrustProxiesUninspected(string $middlewareClass, string $reason): void
    {
        $this->trustProxiesUninspected = sprintf(
            '%s could not be inspected: %s',
            class_basename($middlewareClass),
            $reason
        );
    }

    /**
     * The sanitized exception message, or the exception's short class name when the
     * message is blank, so the note never ends on a dangling colon.
     */
    private function describeFailure(\Throwable $e): string
    {
        $message = trim($this->sanitizedErrorMessage($e->getMessage()));

        if ($message !== '') {
            return $message;
        }

        // An anonymous class name carries "\0<file>:<line>$<n>" after "@anonymous";
        // class_basename() would answer with that file path, so cut it off first.
        return class_basename(strstr(get_class($e), "\0", true) ?: get_class($e));
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
                .'In Laravel 11+ it is part of the framework\'s default global stack, so remove it by calling $middleware->remove() with HandleCors inside the withMiddleware() callback in bootstrap/app.php; in Laravel 9/10 delete it from the $middleware array in app/Http/Kernel.php. '
                .'This middleware runs on every request unnecessarily. Only add it back when you configure specific paths in config/cors.php.';
        }

        if ($this->middlewareFileIsHttpKernel($middlewareFile)) {
            return 'Remove HandleCors middleware from the global middleware stack in app/Http/Kernel.php, as no CORS paths are configured. This middleware runs on every request unnecessarily. Only add it back when you configure specific paths that require CORS handling in config/cors.php.';
        }

        return 'Remove HandleCors from the global middleware stack, as no CORS paths are configured. It is part of the framework\'s default global stack, so remove it by calling $middleware->remove() with HandleCors inside the withMiddleware() callback in bootstrap/app.php, which also drops it from a use() list. This middleware runs on every request unnecessarily. Only add it back when you configure specific paths in config/cors.php.';
    }
}
