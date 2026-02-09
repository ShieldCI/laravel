<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Checks if the application is in maintenance mode.
 *
 * Checks for:
 * - Application is not in maintenance mode
 * - Maintenance mode status
 * - Alerts if maintenance mode is active
 */
class MaintenanceModeAnalyzer extends AbstractFileAnalyzer
{
    /**
     * This analyzer is only relevant in production and staging environments.
     *
     * Not relevant in:
     * - local: Developers intentionally use maintenance mode for testing
     * - development: Same as local
     * - testing: Test suite may test maintenance mode functionality
     *
     * @var array<string>
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    public function shouldRun(): bool
    {
        // Check environment relevance first
        if (! $this->isRelevantForCurrentEnvironment()) {
            return false;
        }

        return true;
    }

    public function getSkipReason(): string
    {
        if (! $this->isRelevantForCurrentEnvironment()) {
            $currentEnv = $this->getEnvironment();
            $relevantEnvs = implode(', ', $this->relevantEnvironments ?? []);

            return "Not relevant in '{$currentEnv}' environment (only relevant in: {$relevantEnvs})";
        }

        return 'Unknown reason';
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'maintenance-mode-status',
            name: 'Maintenance Mode Status Analyzer',
            description: 'Checks if the application is in maintenance mode',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['maintenance', 'availability', 'reliability', 'downtime'],
            timeToFix: 5
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Check if application is in maintenance mode
        $isDownForMaintenance = $this->isMaintenanceModeActive();

        if ($isDownForMaintenance) {
            $maintenanceFilePath = $this->getMaintenanceFilePath();
            $environment = $this->getEnvironment();

            $message = sprintf(
                'Application is in maintenance mode in %s environment - users are affected',
                $environment
            );

            $recommendation = sprintf(
                'The application is in maintenance mode in the %s environment, which affects real users. '.
                'If maintenance is complete, bring the application back online immediately with "php artisan up". '.
                'If maintenance is ongoing, ensure users are properly notified and the downtime window was scheduled.',
                $environment
            );

            return $this->failed(
                'Application is in maintenance mode',
                [$this->createIssue(
                    message: $message,
                    location: null,
                    severity: Severity::High,
                    recommendation: $recommendation,
                    metadata: [
                        'is_down' => true,
                        'maintenance_file' => $maintenanceFilePath,
                        'environment' => $environment,
                        'detected_via' => 'storage/framework/down',
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
