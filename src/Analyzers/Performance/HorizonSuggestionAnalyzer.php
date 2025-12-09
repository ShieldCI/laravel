<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Analyzes whether Laravel Horizon is installed when using Redis queues.
 *
 * Horizon provides:
 * - Beautiful dashboard for queue monitoring
 * - Configurable provisioning plans for queue workers
 * - Load balancing strategies across workers
 * - Advanced memory management features
 * - Job metrics and performance insights
 *
 * This analyzer recommends Horizon for any application using Redis queues
 * in production environments for better queue management and visibility.
 */
class HorizonSuggestionAnalyzer extends AbstractAnalyzer
{
    public function __construct(
        private ConfigRepository $config
    ) {
        $this->configRepository = $config;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'horizon-suggestion',
            name: 'Horizon Suggestion Analyzer',
            description: 'Recommends using Laravel Horizon when Redis queues are configured',
            category: Category::Performance,
            severity: Severity::Low,
            tags: ['queue', 'horizon', 'redis', 'monitoring', 'performance'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/horizon-suggestion',
            timeToFix: 15
        );
    }

    public function shouldRun(): bool
    {
        // Only run if the default queue connection uses Redis
        $defaultConnection = $this->config->get('queue.default');

        if (! is_string($defaultConnection)) {
            return false;
        }

        $driver = $this->config->get("queue.connections.{$defaultConnection}.driver");

        return $driver === 'redis';
    }

    public function getSkipReason(): string
    {
        $defaultConnection = $this->config->get('queue.default');

        if (! is_string($defaultConnection)) {
            return 'Queue default connection is not configured';
        }

        $driver = $this->config->get("queue.connections.{$defaultConnection}.driver");

        return "Queue driver is '{$driver}', not 'redis' (Horizon only works with Redis queues)";
    }

    protected function runAnalysis(): ResultInterface
    {
        // Check if Horizon is installed
        if (class_exists(\Laravel\Horizon\Horizon::class)) {
            return $this->passed('Laravel Horizon is installed for Redis queue management');
        }

        $basePath = $this->getBasePath();
        $configPath = ConfigFileHelper::getConfigPath(
            $basePath,
            'queue.php',
            fn ($file) => function_exists('config_path') ? config_path($file) : null
        );

        // Fallback to buildPath if ConfigFileHelper returns empty string
        if ($configPath === '' || ! file_exists($configPath)) {
            $configPath = $this->buildPath('config', 'queue.php');
        }

        $defaultConnection = $this->config->get('queue.default');
        $lineNumber = ConfigFileHelper::findKeyLine($configPath, 'default');

        $issues[] = $this->createIssue(
            message: 'Laravel Horizon is not installed for Redis queue management',
            location: new Location($this->getRelativePath($configPath), $lineNumber),
            severity: Severity::Low,
            recommendation: 'Install Laravel Horizon for Redis queue management. Horizon provides a beautiful dashboard for monitoring queues and jobs, configurable provisioning plans for workers, load balancing strategies, and advanced memory management features. Install with: composer require laravel/horizon && php artisan horizon:install',
            metadata: [
                'queue_driver' => 'redis',
                'default_connection' => $defaultConnection,
                'horizon_installed' => false,
            ]
        );

        return $this->resultBySeverity(
            'Laravel Horizon is recommended for Redis queue management',
            $issues
        );
    }
}
