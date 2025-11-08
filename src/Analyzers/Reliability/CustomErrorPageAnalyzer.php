<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Checks for custom error pages in production.
 *
 * Checks for:
 * - Custom 404 error page exists
 * - Custom 500 error page exists
 * - Custom 503 error page exists
 * - Proper error page customization
 */
class CustomErrorPageAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<int, array{code: int, description: string}>
     */
    private array $errorPages = [
        ['code' => 404, 'description' => 'Not Found'],
        ['code' => 500, 'description' => 'Server Error'],
        ['code' => 503, 'description' => 'Service Unavailable'],
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'custom-error-pages',
            name: 'Custom Error Pages',
            description: 'Ensures custom error pages are configured for production to provide better user experience',
            category: Category::Reliability,
            severity: Severity::Medium,
            tags: ['errors', 'ux', 'reliability', 'production'],
            docsUrl: 'https://laravel.com/docs/errors#custom-http-error-pages'
        );
    }

    public function shouldRun(): bool
    {
        // Only run in production
        $app = app();
        if (! $app instanceof \Illuminate\Contracts\Foundation\Application) {
            return true;
        }

        $environment = $app->environment();

        if (in_array($environment, ['local', 'testing'])) {
            return false;
        }

        return true;
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $errorsDir = $this->basePath.'/resources/views/errors';

        if (! is_dir($errorsDir)) {
            return $this->warning(
                'No custom error pages found',
                [$this->createIssue(
                    message: 'Custom error pages directory does not exist',
                    location: new Location($this->basePath.'/resources/views', 0),
                    severity: Severity::Medium,
                    recommendation: 'Create custom error pages for better user experience in production. Run "php artisan vendor:publish --tag=laravel-errors" to publish the default error views, then customize them. At minimum, create 404.blade.php, 500.blade.php, and 503.blade.php in resources/views/errors/',
                    metadata: [
                        'errors_directory' => $errorsDir,
                    ]
                )]
            );
        }

        // Check for specific error pages
        foreach ($this->errorPages as $errorPage) {
            $code = $errorPage['code'];
            $errorPagePath = $errorsDir.'/'.$code.'.blade.php';

            if (! file_exists($errorPagePath)) {
                $issues[] = $this->createIssue(
                    message: "Custom {$code} error page not found",
                    location: new Location($errorsDir, 0),
                    severity: Severity::Low,
                    recommendation: "Create a custom {$code} ({$errorPage['description']}) error page at resources/views/errors/{$code}.blade.php. This provides a better user experience than Laravel's default error page. You can publish Laravel's default error views with 'php artisan vendor:publish --tag=laravel-errors' and customize them.",
                    metadata: [
                        'error_code' => $code,
                        'description' => $errorPage['description'],
                        'expected_path' => $errorPagePath,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('Custom error pages are configured');
        }

        return $this->warning(
            sprintf('Missing %d custom error page(s)', count($issues)),
            $issues
        );
    }
}
