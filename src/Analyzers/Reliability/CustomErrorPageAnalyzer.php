<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Routing\Router;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\AnalyzesMiddleware;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Checks for custom error pages using runtime exception rendering.
 *
 * This analyzer:
 * - Checks all configured view paths (not just default)
 * - Detects custom error view namespaces
 * - Actually renders a 404 exception to test if custom pages are used
 * - Skips stateless/API-only apps automatically
 * - Detects framework fingerprinting vulnerability
 */
class CustomErrorPageAnalyzer extends AbstractAnalyzer
{
    use AnalyzesMiddleware;

    /**
     * Custom error page checks require a web server, not applicable in CI.
     */
    public static bool $runInCI = false;

    public function __construct(
        Router $router,
        Kernel $kernel,
        private Filesystem $files
    ) {
        $this->router = $router;
        $this->kernel = $kernel;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'custom-error-pages',
            name: 'Custom Error Pages',
            description: 'Ensures custom error pages are configured to prevent framework fingerprinting and improve UX',
            category: Category::Reliability,
            severity: Severity::Medium,
            tags: ['errors', 'ux', 'reliability', 'security', 'fingerprinting'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/custom-error-pages',
            timeToFix: 30
        );
    }

    public function shouldRun(): bool
    {
        // Skip if app is stateless (API-only apps don't need custom error views)
        try {
            return ! $this->appIsStateless();
        } catch (\ReflectionException $e) {
            // If we can't determine, assume it should run
            return true;
        }
    }

    public function getSkipReason(): string
    {
        return 'Not applicable for stateless/API-only applications (no session middleware detected)';
    }

    protected function runAnalysis(): ResultInterface
    {
        // Method 1: Check all configured view paths for error views
        $hasCustomErrorPages = $this->hasCustomErrorPagesInViewPaths();

        // Method 2: Check for custom error view namespace
        $hasCustomErrorNamespace = $this->hasCustomErrorNamespace();

        // If either method detects custom error pages, we're good
        if ($hasCustomErrorPages || $hasCustomErrorNamespace) {
            return $this->passed('Custom error pages are properly configured');
        }

        // Method 3: Runtime test - Actually render a 404 exception and compare with default
        $usesDefaultErrorPage = $this->rendersDefaultErrorPage();

        if ($usesDefaultErrorPage) {
            return $this->failed(
                'Application uses default Laravel error pages',
                [$this->createIssue(
                    message: 'Custom error pages not configured',
                    location: new Location(base_path('resources/views'), 1),
                    severity: Severity::Medium,
                    recommendation: 'Create custom error pages for better user experience and security. '.
                        'Default Laravel error pages expose your application to framework fingerprinting, '.
                        'allowing potential attackers to identify Laravel as your framework. '.
                        'Run "php artisan vendor:publish --tag=laravel-errors" to publish the default error views, '.
                        'then customize them. At minimum, create 404.blade.php, 500.blade.php, and 503.blade.php in resources/views/errors/',
                    metadata: [
                        'security_impact' => 'Framework fingerprinting vulnerability',
                        'ux_impact' => 'Poor user experience with generic error pages',
                        'view_paths_checked' => config('view.paths', []),
                    ]
                )]
            );
        }

        return $this->passed('Custom error pages are configured');
    }

    /**
     * Check if custom error pages exist in any configured view path.
     */
    private function hasCustomErrorPagesInViewPaths(): bool
    {
        $viewPaths = config('view.paths', []);

        if (! is_array($viewPaths)) {
            return false;
        }

        return collect($viewPaths)->contains(function ($viewPath) {
            if (! is_string($viewPath)) {
                return false;
            }

            return $this->files->exists($viewPath.DIRECTORY_SEPARATOR.'errors'.DIRECTORY_SEPARATOR.'404.blade.php');
        });
    }

    /**
     * Check if a custom 'errors' view namespace is registered.
     */
    private function hasCustomErrorNamespace(): bool
    {
        try {
            /** @var \Illuminate\View\Factory $viewFactory */
            $viewFactory = app('view');
            $viewFinder = $viewFactory->getFinder();

            // PHPStan doesn't know about FileViewFinder's getHints() method
            if (! method_exists($viewFinder, 'getHints')) {
                return false;
            }

            /** @var array<string, array<int, string>> $hints */
            $hints = $viewFinder->getHints();

            return isset($hints['errors']);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Test if the application renders the default Laravel 404 error page.
     */
    private function rendersDefaultErrorPage(): bool
    {
        try {
            // Render a NotFoundHttpException using the app's exception handler
            $exception = new NotFoundHttpException;

            /** @var \Illuminate\Http\Request $request */
            $request = app('request');

            /** @var \Illuminate\Contracts\Debug\ExceptionHandler $exceptionHandler */
            $exceptionHandler = app(ExceptionHandler::class);

            $response = $exceptionHandler->render($request, $exception);
            $renderedContent = $response->getContent();

            if ($renderedContent === false) {
                return false;
            }

            // Get the default Laravel 404 view content
            $defaultView = view('errors::404');

            if (! is_object($defaultView) || ! method_exists($defaultView, 'render')) {
                return false;
            }

            $defaultContent = $defaultView->render();

            // Compare the rendered response with the default
            return $renderedContent === $defaultContent;
        } catch (\Throwable) {
            // If we can't test, assume custom pages exist (fail open)
            return false;
        }
    }
}
