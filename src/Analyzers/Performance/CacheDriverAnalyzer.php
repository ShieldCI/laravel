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
 * Analyzes cache driver configuration for performance best practices.
 *
 * Checks for:
 * - Null or array cache drivers when the environment maps to production/staging
 * - File cache driver in production/staging (allowed elsewhere)
 * - Database cache driver in production/staging (allowed elsewhere)
 * - Recommends Redis/Memcached for production-ready deployments
 *
 * This analyzer uses Laravel's config repository to get runtime values,
 * which respects environment variables and config caching.
 */
class CacheDriverAnalyzer extends AbstractAnalyzer
{
    public function __construct(
        private ConfigRepository $config
    ) {
        $this->configRepository = $config;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'cache-driver',
            name: 'Cache Driver Configuration Analyzer',
            description: 'Ensures a proper cache driver is configured for optimal performance',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['cache', 'performance', 'configuration', 'redis', 'memcached'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/cache-driver',
            timeToFix: 60
        );
    }

    public function shouldRun(): bool
    {
        // Check if cache.default is configured
        $defaultStore = $this->config->get('cache.default');

        return $defaultStore !== null;
    }

    public function getSkipReason(): string
    {
        return 'Cache default store not configured';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Use injected config repository to get runtime values (respects .env and config:cache)
        $defaultStore = $this->config->get('cache.default');
        if (! is_string($defaultStore)) {
            return $this->error('Cache default store is not configured properly');
        }

        $environment = $this->getEnvironment();

        // Validate that the store exists in configuration
        $driver = $this->config->get("cache.stores.{$defaultStore}.driver");

        $basePath = $this->getBasePath();
        $configFile = ConfigFileHelper::getConfigPath($basePath, 'cache.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        if (! is_string($configFile) || ! file_exists($configFile)) {
            return $this->error('Laravel cache configuration file could not be located', [
                'expected_path' => $configFile,
            ]);
        }

        if ($driver === null) {
            $issues[] = $this->createIssue(
                message: "Cache store '{$defaultStore}' is not defined in cache configuration",
                location: new Location($configFile, ConfigFileHelper::findKeyLine($configFile, 'default')),
                severity: Severity::Critical,
                recommendation: 'Define the cache store in config/cache.php or change the default store in your .env file (CACHE_DRIVER)',
                metadata: ['store' => $defaultStore, 'environment' => $environment]
            );

            return $this->failed('Cache configuration is invalid', $issues);
        }

        // Ensure driver is a string for PHPStan
        if (! is_string($driver)) {
            return $this->error('Cache driver configuration is invalid (driver is not a string)');
        }

        // Calculate line number once for all driver checks
        $lineNumber = ConfigFileHelper::findNestedKeyLine($configFile, 'stores', 'driver', $defaultStore);

        // Use match expression for better type safety and clarity
        match ($driver) {
            'null' => $this->assessNullDriver($issues, $configFile, $lineNumber, $defaultStore, $environment),
            'array' => $this->assessArrayDriver($issues, $configFile, $lineNumber, $defaultStore, $environment),
            'file' => $this->assessFileDriver($issues, $configFile, $lineNumber, $defaultStore, $environment),
            'database' => $this->assessDatabaseDriver($issues, $configFile, $lineNumber, $defaultStore, $environment),
            'apc' => $this->assessApcDriver($issues, $configFile, $lineNumber, $defaultStore, $environment),
            'redis', 'memcached' => $this->assessPreferredDriver($driver, $issues, $configFile, $lineNumber, $defaultStore, $environment),
            'dynamodb' => $this->assessDynamoDbDriver($issues, $configFile, $lineNumber, $defaultStore, $environment),
            'octane' => $this->assessOctaneDriver($issues, $configFile, $lineNumber, $defaultStore, $environment),
            default => $this->assessOtherDriver($driver, $issues, $configFile, $lineNumber, $defaultStore, $environment),
        };

        if (count($issues) === 0) {
            return $this->passed("Cache driver '{$driver}' is properly configured for {$environment} environment");
        }

        return $this->resultBySeverity(
            sprintf('Found %d cache driver configuration issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Check if the environment is production or staging.
     */
    private function isProductionOrStaging(string $environment): bool
    {
        return in_array($environment, ['staging', 'production'], true);
    }

    /**
     * Assess the 'null' cache driver.
     * The null driver disables caching completely.
     */
    private function assessNullDriver(array &$issues, string $configFile, int $lineNumber, string $defaultStore, string $environment): void
    {
        // Null driver is acceptable outside staging/production (e.g., local/testing)
        if (! $this->isProductionOrStaging($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: 'Cache driver is set to null - caching is disabled',
            location: new Location($configFile, $lineNumber),
            severity: Severity::Critical,
            recommendation: 'Set CACHE_DRIVER to redis, memcached, or dynamodb in your .env file for production. Null driver means all cache operations will be no-ops.',
            metadata: ['driver' => 'null', 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    /**
     * Assess the 'array' cache driver.
     * The array driver only caches within a single request.
     */
    private function assessArrayDriver(array &$issues, string $configFile, int $lineNumber, string $defaultStore, string $environment): void
    {
        // Array driver is expected for testing/local contexts; only warn in staging/production
        if (! $this->isProductionOrStaging($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: 'Cache driver is set to array - cache not persisted',
            location: new Location($configFile, $lineNumber),
            severity: Severity::Critical,
            recommendation: 'Array driver only caches within a single request and is only suitable for testing. Use redis, memcached, or dynamodb for production.',
            metadata: ['driver' => 'array', 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    /**
     * Assess the 'file' cache driver.
     * The file driver is only suitable for single-server setups.
     */
    private function assessFileDriver(array &$issues, string $configFile, int $lineNumber, string $defaultStore, string $environment): void
    {
        // File driver is acceptable anywhere except staging/production
        if (! $this->isProductionOrStaging($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: "File cache driver in {$environment} environment",
            location: new Location($configFile, $lineNumber),
            severity: Severity::High,
            recommendation: 'File cache is only suitable for single-server setups and causes significant performance degradation in production. Use Redis or Memcached with unix sockets for 10-100x better performance and proper multi-server support.',
            metadata: ['driver' => 'file', 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    /**
     * Assess the 'database' cache driver.
     * The database driver works but has performance issues in production.
     */
    private function assessDatabaseDriver(array &$issues, string $configFile, int $lineNumber, string $defaultStore, string $environment): void
    {
        // Database cache driver is acceptable anywhere except staging/production
        if (! $this->isProductionOrStaging($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: "Database cache driver in {$environment} environment",
            location: new Location($configFile, $lineNumber),
            severity: Severity::High,
            recommendation: 'Database cache driver defeats the purpose of caching by adding load to your database server. This creates a performance bottleneck and can cause cascading failures under high load. Use Redis or Memcached for proper production caching.',
            metadata: ['driver' => 'database', 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    /**
     * Assess other cache drivers (redis, memcached, dynamodb, etc.).
     * These are generally acceptable.
     */
    private function assessOtherDriver(string $driver, array &$issues, string $configFile, int $lineNumber, string $defaultStore, string $environment): void
    {
        $issues[] = $this->createIssue(
            message: "Cache driver '{$driver}' is unsupported by ShieldCI",
            location: new Location($configFile, $lineNumber),
            severity: Severity::Low,
            recommendation: 'Ensure your custom cache driver uses a persistent backend suitable for production workloads. ShieldCI cannot automatically verify custom drivers.',
            metadata: ['driver' => $driver, 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    private function assessPreferredDriver(string $driver, array &$issues, string $configFile, int $lineNumber, string $defaultStore, string $environment): void
    {
        // Redis/Memcached are ideal choices; no action needed.
    }

    private function assessApcDriver(array &$issues, string $configFile, int $lineNumber, string $defaultStore, string $environment): void
    {
        if (! $this->isProductionOrStaging($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: "APC cache driver in {$environment} environment",
            location: new Location($configFile, $lineNumber),
            severity: Severity::High,
            recommendation: 'APCu storage only works on a single server and will cause cache inconsistency in load-balanced or containerized environments. Use Redis or Memcached for proper distributed caching.',
            metadata: ['driver' => 'apc', 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    private function assessDynamoDbDriver(array &$issues, string $configFile, int $lineNumber, string $defaultStore, string $environment): void
    {
        $table = $this->config->get("cache.stores.{$defaultStore}.table");

        if (! is_string($table) || trim($table) === '') {
            $issues[] = $this->createIssue(
                message: 'DynamoDB cache driver is missing a table configuration',
                location: new Location($configFile, $lineNumber),
                severity: Severity::High,
                recommendation: 'Set cache.stores.dynamodb.table (CACHE_DYNAMODB_TABLE) so cache items can be persisted.',
                metadata: ['driver' => 'dynamodb', 'store' => $defaultStore, 'environment' => $environment]
            );

            return;
        }
    }

    private function assessOctaneDriver(array &$issues, string $configFile, int $lineNumber, string $defaultStore, string $environment): void
    {
        if ($this->hasOctaneSupport()) {
            return;
        }

        $issues[] = $this->createIssue(
            message: 'Octane cache driver requires Laravel Octane runtime',
            location: new Location($configFile, $lineNumber),
            severity: Severity::High,
            recommendation: 'Install laravel/octane and ensure Octane workers are running before using the octane cache driver. Otherwise, switch to redis or memcached.',
            metadata: ['driver' => 'octane', 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    private function hasOctaneSupport(): bool
    {
        return class_exists('Laravel\\Octane\\Octane');
    }
}
