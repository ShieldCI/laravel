<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\App;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Checks if the application is in maintenance mode.
 *
 * Checks for:
 * - Application is not in maintenance mode in production
 * - Maintenance mode status
 * - Alerts if maintenance mode is active
 */
class MaintenanceModeAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'maintenance-mode-status',
            name: 'Maintenance Mode Status',
            description: 'Checks if the application is in maintenance mode',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['maintenance', 'availability', 'reliability', 'downtime'],
            docsUrl: 'https://laravel.com/docs/configuration#maintenance-mode'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        if (App::isDownForMaintenance()) {
            return $this->failed(
                'Application is in maintenance mode',
                [$this->createIssue(
                    message: 'Application is currently down for maintenance',
                    location: new Location($this->basePath.'/storage/framework/down', 1),
                    severity: Severity::High,
                    recommendation: 'If maintenance is complete, bring the application back online with "php artisan up". If maintenance is ongoing, this is expected. Ensure maintenance mode was intentional and users are properly notified.',
                    metadata: [
                        'is_down' => true,
                    ]
                )]
            );
        }

        return $this->passed('Application is not in maintenance mode');
    }
}
