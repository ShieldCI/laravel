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
 * Checks for conventional file-based error page templates.
 *
 * This analyzer validates the conventional Laravel approach of creating individual
 * error template files (401.blade.php, 403.blade.php, etc.) in resources/views/errors/.
 *
 * What this analyzer checks:
 * - Existence of conventional error template files on the filesystem
 * - All configured view paths (not just default)
 * - Custom error view namespaces
 * - Skips stateless/API-only apps automatically
 *
 * What this analyzer does NOT check:
 * - Custom exception handlers in app/Exceptions/Handler.php
 * - Dynamic error views (single template handling multiple HTTP codes)
 * - Middleware-level error response overrides
 * - Custom render methods on exception classes
 * - Error responses returned from controllers
 *
 * Note: This analyzer performs a filesystem check only. Applications can implement
 * custom error handling through various approaches. If you use custom exception
 * handlers or other non-conventional methods, you can safely ignore this warning
 * by adding 'custom-error-pages' to the dont_report configuration.
 */
class CustomErrorPageAnalyzer extends AbstractAnalyzer
{
    use AnalyzesMiddleware;

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
            description: 'Checks for conventional file-based error page templates in resources/views/errors/.',
            category: Category::Reliability,
            severity: Severity::Low,
            tags: ['errors', 'ux', 'reliability', 'security', 'fingerprinting'],
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

        return $this->resultBySeverity(
            'Application does not define conventional Laravel error page templates',
            [$this->createIssue(
                message: 'Custom error pages not configured for: '.implode(', ', $missing),
                location: new Location($this->getRelativePath($resourcesViewsPath)),
                severity: $this->metadata()->severity,
                recommendation: $this->getCustomErrorPagesRecommendation($missing),
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
     *
     * @param  array<string>  $missing
     */
    private function getCustomErrorPagesRecommendation(array $missing): string
    {
        $descriptions = [
            '401.blade.php' => '401.blade.php (Unauthorized)',
            '403.blade.php' => '403.blade.php (Forbidden)',
            '404.blade.php' => '404.blade.php (Not Found)',
            '419.blade.php' => '419.blade.php (Page Expired/CSRF)',
            '429.blade.php' => '429.blade.php (Too Many Requests)',
            '500.blade.php' => '500.blade.php (Server Error)',
            '503.blade.php' => '503.blade.php (Service Unavailable)',
        ];

        $missingDescriptions = array_map(
            fn ($t) => $descriptions[$t] ?? $t,
            $missing
        );

        return 'Create custom error pages for better user experience and security. '
            .'Default Laravel error pages may reveal framework-specific branding or structure, '
            .'allowing potential attackers to identify Laravel as your framework. '
            .'Run "php artisan vendor:publish --tag=laravel-errors" to publish the default error views, '
            .'then customize them. Create the following missing templates in resources/views/errors/: '
            .implode(', ', $missingDescriptions);
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
        $configured = config('shieldci.analyzers.reliability.custom-error-pages.required_templates', [
            '401.blade.php',
            '403.blade.php',
            '404.blade.php',
            '419.blade.php',
            '429.blade.php',
            '500.blade.php',
            '503.blade.php',
        ]);

        $required = is_array($configured)
            ? array_filter($configured, fn ($t) => is_string($t))
            : [];

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
