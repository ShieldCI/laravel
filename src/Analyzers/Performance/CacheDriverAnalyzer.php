<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as Config;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Analyzes cache driver configuration for performance best practices.
 *
 * Checks for:
 * - Null or array cache drivers when the environment maps to production/staging
 * - File cache driver in production/staging (allowed elsewhere)
 * - Database cache driver in production/staging (allowed elsewhere)
 * - Session cache driver in production/staging (allowed elsewhere)
 * - Storage cache driver on a local disk in production/staging, graded like the file driver
 * - Failover cache stores, graded by the first listed store that can serve cache operations
 * - Recommends Redis/Memcached for production-ready deployments
 *
 * This analyzer uses Laravel's config repository to get runtime values,
 * which respects environment variables and config caching.
 */
class CacheDriverAnalyzer extends AbstractAnalyzer
{
    public static bool $runInCI = false;

    public function __construct(
        private Config $config
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
            severity: Severity::Critical,
            tags: ['cache', 'performance', 'configuration', 'redis', 'memcached'],
            timeToFix: 60
        );
    }

    public function shouldRun(): bool
    {
        // Env::get() turns CACHE_STORE=null into PHP null, and Laravel resolves a null
        // default to the null store. That is only worth reporting where the null driver
        // is, so elsewhere a null default still skips.
        if ($this->config->get('cache.default') !== null) {
            return true;
        }

        return $this->isProductionOrStaging($this->getEnvironment());
    }

    public function getSkipReason(): string
    {
        return 'Cache default store not configured';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $environment = $this->getEnvironment();

        // The store and driver below come from the config repository, which merges the
        // framework's own config/cache.php, so they are correct whether or not the app
        // published the file - and Laravel 11+ invites deleting config files you do not
        // customise. Only the line reference is lost, so an unpublished file degrades the
        // location to null instead of aborting an analysis that already has its answer.
        $basePath = $this->getBasePath();

        // Use injected config repository to get runtime values (respects .env and config:cache)
        $defaultStore = $this->config->get('cache.default');

        // shouldRun() lets a null default through only in production/staging, where
        // CacheManager::getDefaultDriver() resolves it to the null store.
        if ($defaultStore === null) {
            $this->assessNullDriver($issues, ConfigFileHelper::locateConfigKey($basePath, 'cache.php', 'default'), 'null', $environment);

            return $this->resultBySeverity(sprintf('Found %d cache driver configuration issue(s)', count($issues)), $issues);
        }

        // A malformed store name is a fact about the user's configuration, not a failure of
        // this analyzer, so it is reported as a located finding like the undefined-store
        // case below. As an errored result it carried no issue, which left it unbaselineable
        // and unsuppressible.
        if (! is_string($defaultStore)) {
            $issues[] = $this->createIssue(
                message: 'Cache default store is not a string',
                location: ConfigFileHelper::locateConfigKey($basePath, 'cache.php', 'default'),
                severity: Severity::Critical,
                recommendation: 'Set the default cache store to the name of a store defined in config/cache.php. Laravel cannot resolve a store from a non-string value, so every cache read and write fails at runtime.',
                metadata: ['type' => get_debug_type($defaultStore), 'environment' => $environment]
            );

            return $this->failed('Cache configuration is invalid', $issues);
        }

        // Validate that the store exists in configuration
        $driver = $this->storeDriver($defaultStore);

        if ($driver === null) {
            $issues[] = $this->createIssue(
                message: "Cache store '{$defaultStore}' is not defined in cache configuration",
                location: ConfigFileHelper::locateConfigKey($basePath, 'cache.php', 'default'),
                severity: Severity::Critical,
                recommendation: 'Define the cache store in config/cache.php or change the default store in your .env file (CACHE_STORE, or CACHE_DRIVER on Laravel 10 and earlier)',
                metadata: ['store' => $defaultStore, 'environment' => $environment]
            );

            return $this->failed('Cache configuration is invalid', $issues);
        }

        if (! is_string($driver)) {
            $issues[] = $this->createIssue(
                message: "Cache store '{$defaultStore}' has a driver that is not a string",
                location: ConfigFileHelper::locateNestedConfigKey($basePath, 'cache.php', 'stores', 'driver', $defaultStore),
                severity: Severity::Critical,
                recommendation: 'Set the store driver to one of the cache drivers Laravel supports. Laravel cannot build a cache store from a non-string driver, so every cache read and write fails at runtime.',
                metadata: ['store' => $defaultStore, 'type' => get_debug_type($driver), 'environment' => $environment]
            );

            return $this->failed('Cache configuration is invalid', $issues);
        }

        // Resolve the location once so every driver check reports the same one.
        $location = ConfigFileHelper::locateNestedConfigKey($basePath, 'cache.php', 'stores', 'driver', $defaultStore);

        if ($driver === 'failover') {
            $this->assessFailoverDriver($issues, $location, $defaultStore, $environment);
        } else {
            $this->assessDriver($driver, $issues, $location, $defaultStore, $environment);
        }

        if (count($issues) === 0) {
            return $this->passed("Cache driver '{$driver}' is properly configured for {$environment} environment");
        }

        return $this->resultBySeverity(
            sprintf('Found %d cache driver configuration issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Assess a store by its driver. A failover store never reaches this: it is graded
     * through the first member store that can serve it, found by assessFailoverDriver().
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessDriver(string $driver, array &$issues, ?Location $location, string $store, string $environment): void
    {
        match ($driver) {
            'null' => $this->assessNullDriver($issues, $location, $store, $environment),
            'array' => $this->assessArrayDriver($issues, $location, $store, $environment),
            'file' => $this->assessFileDriver($issues, $location, $store, $environment),
            'database' => $this->assessDatabaseDriver($issues, $location, $store, $environment),
            'apc' => $this->assessApcDriver($issues, $location, $store, $environment),
            'redis', 'memcached' => $this->assessPreferredDriver($driver, $issues, $location, $store, $environment),
            'dynamodb' => $this->assessDynamoDbDriver($issues, $location, $store, $environment),
            'octane' => $this->assessOctaneDriver($issues, $location, $store, $environment),
            'storage' => $this->assessStorageDriver($issues, $location, $store, $environment),
            'session' => $this->assessSessionDriver($issues, $location, $store, $environment),
            default => $this->assessOtherDriver($driver, $issues, $location, $store, $environment),
        };
    }

    /**
     * Assess the 'failover' cache driver.
     *
     * FailoverStore::attemptOnAllStores() tries the members in order and serves each
     * operation from the first one that does not throw. So every broken member listed
     * before the first usable one costs a failed attempt on every operation, and the
     * first usable member, found through nested failover stores, is the store that
     * actually serves traffic and is graded with its driver's own assessment.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessFailoverDriver(array &$issues, ?Location $location, string $failoverStore, string $environment): void
    {
        $members = $this->config->get("cache.stores.{$failoverStore}.stores");

        if (! is_array($members) || $members === []) {
            $issues[] = $this->createIssue(
                message: "Failover cache store '{$failoverStore}' does not list any stores",
                location: $location,
                severity: Severity::Critical,
                recommendation: 'List the stores to fail over between under the failover store\'s stores key, fastest first. Without them the failover store has nothing to send cache operations to, so every cache read and write fails at runtime.',
                metadata: ['driver' => 'failover', 'store' => $failoverStore, 'failover_store' => $failoverStore, 'environment' => $environment]
            );

            return;
        }

        $walk = $this->walkFailoverMembers($failoverStore, [$failoverStore]);

        // A cycle never reaches a real store: FailoverStore recurses through it on
        // every cache operation until PHP runs out of stack.
        if ($walk['cycle'] !== null) {
            $issues[] = $this->createIssue(
                message: "Failover cache store '{$failoverStore}' has a cycle in its primary stores",
                location: $location,
                severity: Severity::Critical,
                recommendation: 'Make the first store listed by each failover store a store with a real driver, such as redis. A failover store that leads back to itself never reaches a backend, so every cache operation fails at runtime.',
                metadata: ['driver' => 'failover', 'store' => $failoverStore, 'stores' => $walk['cycle'], 'environment' => $environment]
            );

            return;
        }

        $serving = $walk['serving'];

        // With a usable member behind them the broken members only cost a failed attempt
        // per operation; with none, every operation throws.
        foreach ($walk['broken'] as $broken) {
            $issues[] = $this->createIssue(
                message: $broken['message'],
                location: $location,
                severity: $serving === null ? Severity::Critical : Severity::High,
                recommendation: $broken['fix'].' '.($serving === null
                    ? "No store listed by the failover store '{$failoverStore}' can serve cache operations, so every cache read and write fails at runtime."
                    : "The failover store '{$failoverStore}' tries it and falls back to its next store on every cache operation, paying for a failed attempt each time."),
                metadata: [...$broken['metadata'], 'driver' => 'failover', 'store' => $failoverStore, 'environment' => $environment]
            );
        }

        if ($serving === null) {
            return;
        }

        [$primary, $driver] = $serving;

        $primaryIssues = [];
        $this->assessDriver($driver, $primaryIssues, $location, $primary, $environment);

        foreach ($primaryIssues as $issue) {
            $issues[] = $this->createIssue(
                message: $walk['broken'] === []
                    ? "Failover cache store '{$failoverStore}' uses store '{$primary}' as its primary: {$issue->message}"
                    : "Failover cache store '{$failoverStore}' falls back to store '{$primary}' on every operation: {$issue->message}",
                location: $location,
                severity: $issue->severity,
                recommendation: $walk['broken'] === []
                    ? "The failover store '{$failoverStore}' sends every cache operation to its primary store '{$primary}' first and only falls back when it fails, so the primary sets the cache's performance. {$issue->recommendation}"
                    : "The failover store '{$failoverStore}' cannot use the stores listed before '{$primary}', so '{$primary}' serves every cache operation and sets the cache's performance. {$issue->recommendation}",
                metadata: array_merge($issue->metadata, ['store' => $failoverStore, 'primary_store' => $primary])
            );
        }
    }

    /**
     * Walk a failover store's members in order to the first usable one.
     *
     * A member is broken when every operation on it throws. Each broken member before
     * the first usable one is collected; a nested failover store is walked the same
     * way and is broken when none of its own members is usable.
     *
     * @param  list<string>  $visited  Failover stores on the path to this one
     * @return array{broken: list<array{message: string, fix: string, metadata: array<string, mixed>}>, serving: array{string, string}|null, cycle: list<string>|null}
     */
    private function walkFailoverMembers(string $failoverStore, array $visited): array
    {
        $members = $this->config->get("cache.stores.{$failoverStore}.stores");

        if (! is_array($members) || $members === []) {
            return ['broken' => [[
                'message' => "Failover cache store '{$failoverStore}' does not list any stores",
                'fix' => 'List the stores to fail over between under the failover store\'s stores key, fastest first.',
                'metadata' => ['failover_store' => $failoverStore],
            ]], 'serving' => null, 'cycle' => null];
        }

        $broken = [];

        foreach (array_values($members) as $index => $member) {
            $label = $index === 0 ? 'primary store' : 'store';
            $key = $index === 0 ? 'primary_store' : 'member_store';

            if (! is_string($member)) {
                $broken[] = [
                    'message' => $index === 0
                        ? "Failover cache store '{$failoverStore}' lists a primary store that is not a string"
                        : "Failover cache store '{$failoverStore}' lists a store that is not a string",
                    'fix' => 'List the failover store\'s members by the names of stores defined in config/cache.php, since Laravel cannot resolve a store from a non-string value.',
                    'metadata' => ['failover_store' => $failoverStore, 'type' => get_debug_type($member)],
                ];

                continue;
            }

            $driver = $this->storeDriver($member);

            if ($driver === null) {
                $broken[] = [
                    'message' => "Failover cache store '{$failoverStore}' lists {$label} '{$member}', which is not defined in cache configuration",
                    'fix' => 'Define the store in config/cache.php or remove it from the failover store\'s stores, since Laravel cannot resolve an undefined store.',
                    'metadata' => ['failover_store' => $failoverStore, $key => $member],
                ];

                continue;
            }

            if (! is_string($driver)) {
                $broken[] = [
                    'message' => "Failover cache store '{$failoverStore}' lists {$label} '{$member}', which has a driver that is not a string",
                    'fix' => 'Set the store\'s driver to one of the cache drivers Laravel supports, since Laravel cannot build a cache store from a non-string driver.',
                    'metadata' => ['failover_store' => $failoverStore, $key => $member, 'type' => get_debug_type($driver)],
                ];

                continue;
            }

            if ($driver === 'failover') {
                if (in_array($member, $visited, true)) {
                    return ['broken' => $broken, 'serving' => null, 'cycle' => [...$visited, $member]];
                }

                $nested = $this->walkFailoverMembers($member, [...$visited, $member]);
                $broken = [...$broken, ...$nested['broken']];

                if ($nested['cycle'] !== null || $nested['serving'] !== null) {
                    return ['broken' => $broken, 'serving' => $nested['serving'], 'cycle' => $nested['cycle']];
                }

                continue;
            }

            if ($driver === 'storage') {
                $disk = $this->resolveStorageDisk($member);

                if (isset($disk['message'])) {
                    $broken[] = ['message' => $disk['message'], 'fix' => $disk['fix'], 'metadata' => ['failover_store' => $failoverStore, $key => $member]];

                    continue;
                }
            }

            return ['broken' => $broken, 'serving' => [$member, $driver], 'cycle' => null];
        }

        return ['broken' => $broken, 'serving' => null, 'cycle' => null];
    }

    /**
     * Resolve a storage store's disk and its driver, or describe why it cannot be.
     *
     * @return array{disk: string, driver: string}|array{message: string, fix: string, metadata: array<string, mixed>}
     */
    private function resolveStorageDisk(string $store): array
    {
        // CacheManager passes the store's disk to FilesystemManager::disk(), which falls
        // back to the default disk on any empty name. The shipped store reads an unset
        // CACHE_STORAGE_DISK, so both null and an empty string reach this fallback.
        $disk = $this->config->get("cache.stores.{$store}.disk") ?: $this->config->get('filesystems.default');

        if (! is_string($disk) || $disk === '') {
            return [
                'message' => "Storage cache store '{$store}' does not name a filesystem disk",
                'fix' => 'Set the store\'s disk (CACHE_STORAGE_DISK) or the default filesystem disk to a disk defined in config/filesystems.php.',
                'metadata' => ['type' => get_debug_type($disk)],
            ];
        }

        $diskDriver = $this->config->get("filesystems.disks.{$disk}.driver");

        if (! is_string($diskDriver)) {
            return [
                'message' => "Storage cache store '{$store}' uses disk '{$disk}', which is not defined in filesystem configuration",
                'fix' => 'Define the disk with a driver in config/filesystems.php or point the store\'s disk (CACHE_STORAGE_DISK) at a defined disk.',
                'metadata' => ['disk' => $disk],
            ];
        }

        return ['disk' => $disk, 'driver' => $diskDriver];
    }

    /**
     * Assess the 'storage' cache driver.
     * The storage driver keeps cache items on a filesystem disk, so a local disk has
     * the same single-server limits as the file driver.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessStorageDriver(array &$issues, ?Location $location, string $store, string $environment): void
    {
        $resolved = $this->resolveStorageDisk($store);

        if (isset($resolved['message'])) {
            $issues[] = $this->createIssue(
                message: $resolved['message'],
                location: $location,
                severity: Severity::Critical,
                recommendation: $resolved['fix'].' Laravel cannot build the store\'s disk, so every cache read and write fails at runtime.',
                metadata: [...$resolved['metadata'], 'driver' => 'storage', 'store' => $store, 'environment' => $environment]
            );

            return;
        }

        $disk = $resolved['disk'];

        // A local disk is acceptable anywhere except staging/production, like the file driver
        if ($resolved['driver'] !== 'local' || ! $this->isProductionOrStaging($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: "Storage cache driver on local disk '{$disk}' in {$environment} environment",
            location: $location,
            severity: Severity::High,
            recommendation: 'A storage cache on a local disk is only suitable for single-server setups and causes significant performance degradation in production, like the file driver. Use Redis or Memcached for proper multi-server support.',
            metadata: ['driver' => 'storage', 'store' => $store, 'disk' => $disk, 'disk_driver' => 'local', 'environment' => $environment]
        );
    }

    /**
     * Assess the 'session' cache driver.
     * The session driver keeps cache items in the current user's session, so nothing
     * is shared between users, and a CLI or queue worker gets a cache that lives only
     * as long as the process.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessSessionDriver(array &$issues, ?Location $location, string $store, string $environment): void
    {
        // Session driver is acceptable anywhere except staging/production
        if (! $this->isProductionOrStaging($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: 'Cache driver is set to session - cache is scoped to each user session',
            location: $location,
            severity: Severity::High,
            recommendation: 'The session driver stores cache items in each user\'s session, so nothing is shared between users. Rate limiters that use the default store reset whenever a client drops its session cookie, and in queue workers and console commands the cache behaves like the array driver, which breaks queue:restart and unique job locks. Use a shared persistent store such as Redis or Memcached for production.',
            metadata: ['driver' => 'session', 'store' => $store, 'environment' => $environment]
        );
    }

    /**
     * The driver of a store as CacheManager resolves it: getConfig() answers the store
     * name 'null' with the null driver whether or not config/cache.php defines it, and
     * build() rejects an empty driver ("Driver [] is not supported."), so an empty one,
     * such as an unset environment variable, is reported as no driver at all.
     */
    private function storeDriver(string $store): mixed
    {
        if ($store === 'null') {
            return 'null';
        }

        $driver = $this->config->get("cache.stores.{$store}.driver");

        return $driver === '' ? null : $driver;
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
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessNullDriver(array &$issues, ?Location $location, string $defaultStore, string $environment): void
    {
        // Null driver is acceptable outside staging/production (e.g., local/testing)
        if (! $this->isProductionOrStaging($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: 'Cache driver is set to null - caching is disabled',
            location: $location,
            severity: Severity::Critical,
            recommendation: 'Set CACHE_STORE (CACHE_DRIVER on Laravel 10 and earlier) to redis, memcached, or dynamodb in your .env file for production. Null driver means all cache operations will be no-ops.',
            metadata: ['driver' => 'null', 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    /**
     * Assess the 'array' cache driver.
     * The array driver only caches within a single request.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessArrayDriver(array &$issues, ?Location $location, string $defaultStore, string $environment): void
    {
        // Array driver is expected for testing/local contexts; only warn in staging/production
        if (! $this->isProductionOrStaging($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: 'Cache driver is set to array - cache not persisted',
            location: $location,
            severity: Severity::Critical,
            recommendation: 'Array driver only caches within a single request and is only suitable for testing. Use redis, memcached, or dynamodb for production.',
            metadata: ['driver' => 'array', 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    /**
     * Assess the 'file' cache driver.
     * The file driver is only suitable for single-server setups.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessFileDriver(array &$issues, ?Location $location, string $defaultStore, string $environment): void
    {
        // File driver is acceptable anywhere except staging/production
        if (! $this->isProductionOrStaging($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: "File cache driver in {$environment} environment",
            location: $location,
            severity: Severity::High,
            recommendation: 'File cache is only suitable for single-server setups and causes significant performance degradation in production. Use Redis or Memcached with unix sockets for 10-100x better performance and proper multi-server support.',
            metadata: ['driver' => 'file', 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    /**
     * Assess the 'database' cache driver.
     * The database driver works but has performance issues in production.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessDatabaseDriver(array &$issues, ?Location $location, string $defaultStore, string $environment): void
    {
        // Database cache driver is acceptable anywhere except staging/production
        if (! $this->isProductionOrStaging($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: "Database cache driver in {$environment} environment",
            location: $location,
            severity: Severity::High,
            recommendation: 'Database cache driver defeats the purpose of caching by adding load to your database server. This creates a performance bottleneck and can cause cascading failures under high load. Use Redis or Memcached for proper production caching.',
            metadata: ['driver' => 'database', 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    /**
     * Assess other cache drivers (redis, memcached, dynamodb, etc.).
     * These are generally acceptable.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function assessOtherDriver(string $driver, array &$issues, ?Location $location, string $defaultStore, string $environment): void
    {
        $issues[] = $this->createIssue(
            message: "Cache driver '{$driver}' is unsupported by ShieldCI",
            location: $location,
            severity: Severity::Low,
            recommendation: 'Ensure your custom cache driver uses a persistent backend suitable for production workloads. ShieldCI cannot automatically verify custom drivers.',
            metadata: ['driver' => $driver, 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    /**
     * @param  array<int, Issue>  &$issues
     */
    private function assessPreferredDriver(string $driver, array &$issues, ?Location $location, string $defaultStore, string $environment): void
    {
        // Redis/Memcached are ideal choices; no action needed.
    }

    /**
     * @param  array<int, Issue>  &$issues
     */
    private function assessApcDriver(array &$issues, ?Location $location, string $defaultStore, string $environment): void
    {
        if (! $this->isProductionOrStaging($environment)) {
            return;
        }

        $issues[] = $this->createIssue(
            message: "APC cache driver in {$environment} environment",
            location: $location,
            severity: Severity::High,
            recommendation: 'APCu storage only works on a single server and will cause cache inconsistency in load-balanced or containerized environments. Use Redis or Memcached for proper distributed caching.',
            metadata: ['driver' => 'apc', 'store' => $defaultStore, 'environment' => $environment]
        );
    }

    /**
     * @param  array<int, Issue>  &$issues
     */
    private function assessDynamoDbDriver(array &$issues, ?Location $location, string $defaultStore, string $environment): void
    {
        $table = $this->config->get("cache.stores.{$defaultStore}.table");

        if (! is_string($table) || trim($table) === '') {
            $issues[] = $this->createIssue(
                message: 'DynamoDB cache driver is missing a table configuration',
                location: $location,
                severity: Severity::High,
                recommendation: 'Set cache.stores.dynamodb.table (DYNAMODB_CACHE_TABLE) so cache items can be persisted.',
                metadata: ['driver' => 'dynamodb', 'store' => $defaultStore, 'environment' => $environment]
            );

            return;
        }
    }

    /**
     * @param  array<int, Issue>  &$issues
     */
    private function assessOctaneDriver(array &$issues, ?Location $location, string $defaultStore, string $environment): void
    {
        if ($this->hasOctaneSupport()) {
            return;
        }

        $issues[] = $this->createIssue(
            message: 'Octane cache driver requires Laravel Octane runtime',
            location: $location,
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
