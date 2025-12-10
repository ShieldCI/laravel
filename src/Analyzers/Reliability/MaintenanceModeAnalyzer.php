<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

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
            name: 'Maintenance Mode Status Analyzer',
            description: 'Checks if the application is in maintenance mode',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['maintenance', 'availability', 'reliability', 'downtime'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/maintenance-mode-status',
            timeToFix: 5
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Check if application is in maintenance mode
        $isDownForMaintenance = $this->isMaintenanceModeActive();

        if ($isDownForMaintenance) {
            $maintenanceFilePath = $this->getMaintenanceFilePath();

            return $this->failed(
                'Application is in maintenance mode',
                [$this->createIssue(
                    message: 'Application is currently down for maintenance',
                    location: new Location($this->getRelativePath($maintenanceFilePath), 1),
                    severity: Severity::High,
                    recommendation: 'If maintenance is complete, bring the application back online with "php artisan up". If maintenance is ongoing, this is expected. Ensure maintenance mode was intentional and users are properly notified.',
                    metadata: [
                        'is_down' => true,
                        'maintenance_file' => $maintenanceFilePath,
                    ]
                )]
            );
        }

        return $this->passed('Application is not in maintenance mode');
    }

    /**
     * Check if the application is in maintenance mode.
     */
    private function isMaintenanceModeActive(): bool
    {
        // Check for maintenance mode file directly
        // This approach is more reliable than using App facade, especially in testing
        return file_exists($this->getMaintenanceFilePath());
    }

    /**
     * Get the maintenance mode file path.
     */
    private function getMaintenanceFilePath(): string
    {
        return $this->buildPath('storage', 'framework', 'down');
    }
}
