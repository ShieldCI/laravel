<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\MaintenanceModeManager;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Concerns\SanitizesErrorMessages;
use Throwable;

/**
 * Checks if the application is in maintenance mode.
 *
 * When the analyzed project is the application running the analysis, Laravel itself is asked,
 * so the configured driver decides: the cache driver keeps its state only in a cache key, and
 * the file driver writes to storage_path(), which an application can relocate. Any other base
 * path is not this application, so its state is read from its storage/framework/down file.
 */
class MaintenanceModeAnalyzer extends AbstractFileAnalyzer
{
    use SanitizesErrorMessages;

    /**
     * A CI checkout is never in maintenance mode, so a run there would pass without checking.
     */
    public static bool $runInCI = false;

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

    public function __construct(
        private Application $app
    ) {}

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
        if (! $this->analyzesRunningApp()) {
            $maintenanceFile = $this->buildPath('storage', 'framework', 'down');

            return file_exists($maintenanceFile)
                ? $this->maintenanceModeActive('storage/framework/down', $maintenanceFile)
                : $this->passed('Application is not in maintenance mode');
        }

        $driver = $this->app->make(MaintenanceModeManager::class)->getDefaultDriver();

        try {
            $isDown = $this->app->maintenanceMode()->active();
        } catch (Throwable $e) {
            return $this->statusUnknown($driver, $e);
        }

        if (! $isDown) {
            return $this->passed('Application is not in maintenance mode');
        }

        return $driver === 'file'
            ? $this->maintenanceModeActive('storage/framework/down', $this->app->storagePath('framework'.DIRECTORY_SEPARATOR.'down'))
            : $this->maintenanceModeActive($driver, null);
    }

    /**
     * Whether the analyzed base path is the application running this analysis, compared
     * resolved, since deploy and temporary directories are often reached through symlinks.
     */
    private function analyzesRunningApp(): bool
    {
        $running = realpath($this->app->basePath());

        return $running !== false && $running === realpath($this->getBasePath());
    }

    /**
     * The application is down: detected through the named driver, or through the down file
     * at $maintenanceFile for the file driver.
     */
    private function maintenanceModeActive(string $detectedVia, ?string $maintenanceFile): ResultInterface
    {
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

        $metadata = ['is_down' => true];

        if ($maintenanceFile !== null) {
            $metadata['maintenance_file'] = $maintenanceFile;
        }

        $metadata['environment'] = $environment;
        $metadata['detected_via'] = $detectedVia;

        return $this->resultBySeverity(
            'Application is in maintenance mode',
            [$this->createIssue(
                message: $message,
                location: null,
                severity: Severity::High,
                recommendation: $recommendation,
                metadata: $metadata
            )]
        );
    }

    /**
     * Laravel could not answer, so neither "up" nor "down" is known. Medium rather than High:
     * this is not a confirmed outage, but it must not read as a pass either. The error goes in
     * the recommendation and metadata, not the message, so the issue keeps one fingerprint.
     */
    private function statusUnknown(string $driver, Throwable $e): ResultInterface
    {
        $environment = $this->getEnvironment();
        $error = $this->sanitizedErrorMessage($e->getMessage());

        return $this->warning(
            'Maintenance mode status could not be determined',
            [$this->createIssue(
                message: sprintf('Maintenance mode status could not be determined in %s environment', $environment),
                location: null,
                severity: Severity::Medium,
                recommendation: sprintf(
                    'Laravel could not read the maintenance mode state through the "%s" driver, so this run cannot tell whether users are being served. Error: %s. '.
                    'Check that the driver and store configured under app.maintenance are reachable from where shield:analyze runs, then run it again.',
                    $driver,
                    $error
                ),
                metadata: [
                    'environment' => $environment,
                    'detected_via' => $driver,
                    'error' => $error,
                ]
            )]
        );
    }
}
