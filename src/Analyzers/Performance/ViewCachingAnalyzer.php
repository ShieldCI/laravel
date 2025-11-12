<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Analyzes view caching setup.
 *
 * Checks for:
 * - Views not cached/compiled in production
 * - Proper use of php artisan view:cache
 * - Compiled view storage location
 */
class ViewCachingAnalyzer extends AbstractFileAnalyzer
{
    /**
     * View caching checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'view-caching',
            name: 'View Caching',
            description: 'Ensures Blade views are properly compiled and cached for optimal performance',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['cache', 'views', 'blade', 'performance', 'optimization'],
            docsUrl: 'https://laravel.com/docs/views#optimizing-views'
        );
    }

    public function shouldRun(): bool
    {
        return file_exists($this->basePath.'/resources/views');
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $environment = $this->getEnvironment();
        $viewsAreCached = $this->viewsAreCached();
        $compiledViewsExist = $this->compiledViewsExist();

        if ($environment !== 'local' && ! $viewsAreCached && ! $compiledViewsExist) {
            $issues[] = $this->createIssue(
                message: "Views are not cached in {$environment} environment",
                location: new Location($this->basePath.'/resources/views', 1),
                severity: Severity::Medium,
                recommendation: 'View caching improves performance by pre-compiling all Blade templates. Add "php artisan view:cache" to your deployment script. This eliminates the need to compile views on each request.',
                metadata: ['environment' => $environment, 'cached' => false]
            );
        }

        if (empty($issues)) {
            return $this->passed("View caching is properly configured for {$environment} environment");
        }

        return $this->warning(
            sprintf('Found %d view caching issues', count($issues)),
            $issues
        );
    }

    private function viewsAreCached(): bool
    {
        // Check if view:cache has been run (creates a cached views file)
        return file_exists($this->basePath.'/bootstrap/cache/views.php');
    }

    private function compiledViewsExist(): bool
    {
        // Check if compiled views directory exists and has files
        $compiledPath = $this->basePath.'/storage/framework/views';

        if (! is_dir($compiledPath)) {
            return false;
        }

        $files = glob($compiledPath.'/*.php');

        return ! empty($files);
    }

    private function getEnvironment(): string
    {
        $envFile = $this->basePath.'/.env';

        if (! file_exists($envFile)) {
            return 'production';
        }

        $content = file_get_contents($envFile);

        if (preg_match('/^APP_ENV\s*=\s*(\w+)/m', $content, $matches)) {
            return $matches[1];
        }

        return 'production';
    }
}
