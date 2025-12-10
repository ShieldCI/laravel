<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Routing\Router;
use Illuminate\View\Factory;
use Illuminate\View\FileViewFinder;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\AnalyzesMiddleware;

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

    /**
     * Allows tests to override stateless detection.
     */
    protected ?bool $statelessOverride = null;

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
            name: 'Custom Error Pages Analyzer',
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
            if ($this->statelessOverride !== null) {
                return ! $this->statelessOverride;
            }

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
        $missing = $this->missingErrorTemplates();

        if (empty($missing)) {
            return $this->passed('Custom error pages are properly configured');
        }

        $resourcesViewsPath = $this->getResourcesViewsPath();

        return $this->failed(
            'Application uses default Laravel error pages',
            [$this->createIssue(
                message: 'Custom error pages not configured for: '.implode(', ', $missing),
                location: new Location($this->getRelativePath($resourcesViewsPath), 1),
                severity: Severity::Medium,
                recommendation: $this->getCustomErrorPagesRecommendation(),
                metadata: [
                    'missing_templates' => $missing,
                    'view_paths_checked' => $this->getViewPaths(),
                ]
            )]
        );
    }

    /**
     * Get the path to resources/views directory.
     */
    private function getResourcesViewsPath(): string
    {
        return $this->buildPath('resources', 'views');
    }

    /**
     * Get and validate view paths from config.
     *
     * @return array<string>
     */
    private function getViewPaths(): array
    {
        $viewPaths = config('view.paths', []);

        if (! is_array($viewPaths)) {
            return [];
        }

        // Filter to only string paths
        return array_filter($viewPaths, fn ($path) => is_string($path));
    }

    /**
     * Get recommendation message for custom error pages.
     */
    private function getCustomErrorPagesRecommendation(): string
    {
        return 'Create custom error pages for better user experience and security. '.
               'Default Laravel error pages expose your application to framework fingerprinting, '.
               'allowing potential attackers to identify Laravel as your framework. '.
               'Run "php artisan vendor:publish --tag=laravel-errors" to publish the default error views, '.
               'then customize them. At minimum, create 404.blade.php, 500.blade.php, and 503.blade.php in resources/views/errors/';
    }

    public function setStatelessOverride(?bool $stateless): void
    {
        $this->statelessOverride = $stateless;
    }

    /**
     * @return array<string>
     */
    private function missingErrorTemplates(): array
    {
        $required = ['404.blade.php', '500.blade.php', '503.blade.php'];
        $paths = $this->collectErrorDirectories();

        $missing = [];
        foreach ($required as $template) {
            $found = false;
            foreach ($paths as $path) {
                if ($this->files->exists($path.DIRECTORY_SEPARATOR.$template)) {
                    $found = true;
                    break;
                }
            }

            if (! $found) {
                $missing[] = $template;
            }
        }

        return $missing;
    }

    /**
     * @return array<string>
     */
    private function collectErrorDirectories(): array
    {
        $directories = [];

        foreach ($this->getViewPaths() as $viewPath) {
            $directories[] = $viewPath.DIRECTORY_SEPARATOR.'errors';
        }

        foreach ($this->getErrorNamespaceHints() as $hintPath) {
            $directories[] = $hintPath;
        }

        return array_values(array_unique(array_filter($directories)));
    }

    /**
     * @return array<string>
     */
    private function getErrorNamespaceHints(): array
    {
        try {
            /** @var Factory $viewFactory */
            $viewFactory = app('view');
            $finder = $viewFactory->getFinder();

            if (! $finder instanceof FileViewFinder) {
                return [];
            }

            $hints = $finder->getHints();

            return isset($hints['errors']) ? array_filter($hints['errors']) : [];
        } catch (\Throwable) {
            return [];
        }
    }
}
