<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\PackageDetector;
use ShieldCI\AnalyzersCore\Support\PlatformDetector;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

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
 *
 * Note: Laravel Horizon is incompatible with Laravel Vapor due to Vapor's
 * serverless architecture. Vapor uses AWS Lambda which cannot support the
 * long-running processes required by Horizon. This analyzer skips when
 * Vapor is detected.
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
            timeToFix: 15
        );
    }

    public function shouldRun(): bool
    {
        // Skip if Laravel Vapor is detected (incompatible with Horizon)
        if (PlatformDetector::isLaravelVapor($this->getBasePath())) {
            return false;
        }

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
        // Check Vapor first
        if (PlatformDetector::isLaravelVapor($this->getBasePath())) {
            return 'Laravel Vapor detected - Horizon is incompatible with Vapor\'s serverless architecture (AWS Lambda cannot support long-running processes)';
        }

        $defaultConnection = $this->config->get('queue.default');

        if (! is_string($defaultConnection)) {
            return 'Queue default connection is not configured';
        }

        $driver = $this->config->get("queue.connections.{$defaultConnection}.driver");

        return "Queue driver is '{$driver}', not 'redis' (Horizon only works with Redis queues)";
    }

    protected function runAnalysis(): ResultInterface
    {
        // Check if Horizon is installed and configured
        if (PackageDetector::isHorizonConfigured($this->getBasePath())) {
            return $this->passed('Laravel Horizon is configured for Redis queue management');
        }

        $basePath = $this->getBasePath();
        $defaultConnection = $this->config->get('queue.default');

        $issues = [];

        // Check if Horizon is installed but not configured
        if (PackageDetector::hasHorizon($basePath)) {
            $issues[] = $this->createIssue(
                message: 'Laravel Horizon is installed but not configured',
                location: null,
                severity: Severity::Low,
                recommendation: 'Configure Laravel Horizon by running: php artisan horizon:install. This will publish the configuration file, create the service provider, and register it in your application.',
                metadata: [
                    'queue_driver' => 'redis',
                    'default_connection' => $defaultConnection,
                    'horizon_installed' => true,
                    'horizon_configured' => false,
                    'detected_via' => 'config/queue.php',
                ]
            );
        } else {
            $issues[] = $this->createIssue(
                message: 'Laravel Horizon is not installed for Redis queue management',
                location: null,
                severity: Severity::Low,
                recommendation: 'Install Laravel Horizon for Redis queue management. Horizon provides a beautiful dashboard for monitoring queues and jobs, configurable provisioning plans for workers, load balancing strategies, and advanced memory management features. Install with: composer require laravel/horizon && php artisan horizon:install',
                metadata: [
                    'queue_driver' => 'redis',
                    'default_connection' => $defaultConnection,
                    'horizon_installed' => false,
                    'horizon_configured' => false,
                    'detected_via' => 'config/queue.php',
                ]
            );
        }

        return $this->resultBySeverity(
            'Laravel Horizon is recommended for Redis queue management',
            $issues
        );
    }
}
