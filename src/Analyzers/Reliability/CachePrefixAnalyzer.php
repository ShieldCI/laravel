<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Support\ConfigurationUrlParser;
use Illuminate\Support\Str;
use InvalidArgumentException;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Checks cache prefix configuration to avoid collisions.
 *
 * Checks for:
 * - Cache prefix is set and not generic
 * - Prevents cache key collisions in shared cache servers
 * - Validates unique app identification
 * - Counts the Redis connection or Memcached client prefix, which is prepended to every key
 * - Checks each shared store behind a failover store
 */
class CachePrefixAnalyzer extends AbstractFileAnalyzer
{
    public static bool $runInCI = false;

    /**
     * Shared cache drivers that require prefix configuration.
     *
     * @var array<string>
     */
    private const SHARED_CACHE_DRIVERS = ['redis', 'memcached', 'dynamodb', 'database'];

    /**
     * Generic prefixes that may cause collisions.
     *
     * @var array<string>
     */
    private const GENERIC_PREFIXES = [
        'laravel_cache',
        'laravel_database_cache',
        'laravel_database',
        'laravel',
        'app',
        'cache',
        'my_app',
        'myapp',
        'test',
        'demo',
        'example',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'cache-prefix-configuration',
            name: 'Cache Prefix Configuration Analyzer',
            description: 'Ensures cache prefix is set to avoid collisions with other applications sharing cache servers',
            category: Category::Reliability,
            severity: Severity::Medium,
            tags: ['cache', 'configuration', 'reliability', 'multi-tenant'],
            timeToFix: 5
        );
    }

    public function shouldRun(): bool
    {
        return $this->getStoresToCheck() !== [];
    }

    public function getSkipReason(): string
    {
        $store = $this->getDefaultStore();
        $driver = $this->getDefaultDriver();
        $driversList = implode('/', self::SHARED_CACHE_DRIVERS);

        if ($driver === 'failover') {
            return "Failover cache store '{$store}' does not use a shared cache driver (requires: {$driversList})";
        }

        return "Not using shared cache driver (current: {$driver}, requires: {$driversList})";
    }

    protected function runAnalysis(): ResultInterface
    {
        $defaultStore = $this->getDefaultStore();
        $failover = $this->getDefaultDriver() === 'failover' ? $defaultStore : null;

        /** @var array<int, array{0: string, 1: Issue}> $findings */
        $findings = [];

        foreach ($this->getStoresToCheck() as [$store, $driver]) {
            $finding = $this->assessStore($store, $driver, $failover);

            if ($finding !== null) {
                $findings[] = $finding;
            }
        }

        if ($findings === []) {
            return $this->passed('Cache prefix is properly configured');
        }

        return $this->resultBySeverity(
            count($findings) === 1 ? $findings[0][0] : sprintf('Found %d cache stores with a weak cache prefix', count($findings)),
            array_map(static fn (array $finding): Issue => $finding[1], $findings)
        );
    }

    /**
     * Grade one store's key namespace, returning the result summary and the issue.
     *
     * @return array{0: string, 1: Issue}|null
     */
    private function assessStore(string $store, string $driver, ?string $failover): ?array
    {
        $cachePrefix = $this->getEffectivePrefix($store);

        // The Redis connection and the Memcached client prepend their own prefix to every
        // key, ahead of the cache prefix, so for those stores it is part of the namespace too.
        $clientPrefix = match ($driver) {
            'redis' => $this->getRedisConnectionPrefix($store),
            'memcached' => $this->getMemcachedClientPrefix($store),
            default => '',
        };
        $prefix = $clientPrefix.$cachePrefix;

        // Database store keys only collide when two applications share one connection and
        // cache table; a cache server is routinely shared between applications.
        $severity = $driver === 'database' ? Severity::Low : Severity::Medium;

        // The prefix comes from the config repository, which merges the framework's own
        // config/cache.php, so it is correct whether or not the app published the file -
        // and Laravel 11+ invites deleting config files you do not customise. Only the
        // line reference is lost, and no location is reported when the file is not there.
        $location = $this->getPrefixLocation($store);

        $about = $failover === null ? '' : "Failover cache store '{$failover}' uses store '{$store}', whose ";
        $metadata = [
            'cache_driver' => $driver,
            'cache_store' => $store,
            'prefix' => $prefix,
        ];

        if ($failover !== null) {
            $metadata['failover_store'] = $failover;
        }

        if ($clientPrefix !== '') {
            $metadata['cache_prefix'] = $cachePrefix;
            $metadata['client_prefix'] = $clientPrefix;
        }

        // Check if prefix is empty
        if ($prefix === '') {
            return ['Cache prefix is not configured', $this->createIssue(
                message: $about === '' ? 'Cache prefix is empty or not set' : $about.'cache prefix is empty or not set',
                location: $location,
                severity: $severity,
                recommendation: $this->getEmptyPrefixRecommendation($driver),
                metadata: $metadata
            )];
        }

        // Check if prefix is too generic: the namespace is only as unique as its most
        // unique part, so a generic client prefix is redeemed by a unique cache prefix.
        if ($this->isGenericPart($clientPrefix) && $this->isGenericPart($cachePrefix)) {
            return ['Cache prefix is too generic', $this->createIssue(
                message: $about === ''
                    ? "Cache prefix '{$prefix}' is too generic and may cause collisions"
                    : $about."cache prefix '{$prefix}' is too generic and may cause collisions",
                location: $location,
                severity: $severity,
                recommendation: $this->getGenericPrefixRecommendation($prefix, $driver),
                metadata: [...$metadata, 'app_name' => $this->getAppName()]
            )];
        }

        return null;
    }

    /**
     * The shared stores whose prefix to check, as store name and driver pairs. A list, not
     * a map, so a numeric store name is not turned into an integer key.
     *
     * A failover store has no keys of its own: FailoverStore hands every operation to the
     * stores it lists, each built from its own configuration, so each shared one is checked.
     *
     * @return list<array{0: string, 1: string}>
     */
    private function getStoresToCheck(): array
    {
        $store = $this->getDefaultStore();
        $driver = $this->getDefaultDriver();

        if ($driver === 'failover') {
            return $this->getFailoverMembers($store, [$store]);
        }

        return in_array($driver, self::SHARED_CACHE_DRIVERS, true) ? [[$store, $driver]] : [];
    }

    /**
     * Collect the shared stores behind a failover store, through nested failover stores.
     *
     * @param  array<int, string>  $visited
     * @return list<array{0: string, 1: string}>
     */
    private function getFailoverMembers(string $failoverStore, array $visited): array
    {
        $members = config("cache.stores.{$failoverStore}.stores");

        if (! is_array($members)) {
            return [];
        }

        $stores = [];

        foreach ($members as $member) {
            if (! is_string($member) || in_array($member, $visited, true)) {
                continue;
            }

            $driver = config("cache.stores.{$member}.driver");

            if ($driver === 'failover') {
                $stores = [...$stores, ...$this->getFailoverMembers($member, [...$visited, $member])];
            } elseif (is_string($driver) && in_array($driver, self::SHARED_CACHE_DRIVERS, true)) {
                $stores[] = [$member, $driver];
            }
        }

        // A store listed by more than one failover store is still one set of keys.
        return array_values(array_unique($stores, SORT_REGULAR));
    }

    /**
     * Get the location of the prefix configuration key.
     *
     * A store-specific prefix needs the nested helper: the flat search's parent scope only
     * ends at a top-level key, so on a store without its own 'prefix' it would run on into
     * the next store and answer with that one's line.
     */
    private function getPrefixLocation(string $store): ?Location
    {
        $basePath = $this->getBasePath();

        if ($this->hasStoreSpecificPrefix($store)) {
            return ConfigFileHelper::locateNestedConfigKey($basePath, 'cache.php', 'stores', 'prefix', $store);
        }

        return ConfigFileHelper::locateConfigKey($basePath, 'cache.php', 'prefix');
    }

    /**
     * Check if one part of the key namespace adds nothing that tells applications apart.
     */
    private function isGenericPart(string $prefix): bool
    {
        return $prefix === '' || $this->isGenericPrefix($prefix);
    }

    /**
     * Check if a prefix is generic and may cause collisions.
     */
    private function isGenericPrefix(string $prefix): bool
    {
        $raw = trim($prefix);
        $normalized = strtolower($raw);
        $slug = Str::slug($raw, '_');

        // Check if prefix is in generic list
        if (in_array($normalized, self::GENERIC_PREFIXES, true)
            || in_array($slug, self::GENERIC_PREFIXES, true)) {
            return true;
        }

        // Check for very short prefixes (1-2 characters)
        if (mb_strlen($raw) <= 2) {
            return true;
        }

        // Check for whitespace-only or underscore-only prefixes
        if (preg_match('/^[\s_]+$/', $prefix)) {
            return true;
        }

        // Check for numeric-only prefixes
        if (ctype_digit($raw)) {
            return true;
        }

        return false;
    }

    /**
     * Resolve the store's prefix as CacheManager::getPrefix() does: the store's own key
     * wins whenever it is set, even to '', and only a missing or null one falls back.
     */
    private function getEffectivePrefix(string $store): string
    {
        $prefix = $this->hasStoreSpecificPrefix($store)
            ? config("cache.stores.{$store}.prefix")
            : config('cache.prefix');

        // Validate that prefix is a string (not numeric, boolean, etc.)
        return is_string($prefix) ? $prefix : '';
    }

    private function hasStoreSpecificPrefix(string $store): bool
    {
        return config("cache.stores.{$store}.prefix") !== null;
    }

    /**
     * Resolve the prefix the store's Redis connection puts on every key.
     *
     * RedisManager::resolve() uses a plain connection of that name before a cluster. For a
     * plain one, the connectors merge the connection's own options over the shared
     * database.redis.options and then copy a set connection-level prefix over both. For a
     * cluster, clusters.options and then the cluster's own options are merged over the
     * shared options. A cluster's own prefix key is never a key namespace: resolveCluster()
     * parses every entry of the cluster as a connection, so the key arrives as a parsed URL
     * that breaks the cluster rather than prefixing its keys.
     */
    private function getRedisConnectionPrefix(string $store): string
    {
        $connection = config("cache.stores.{$store}.connection");
        $connection = is_string($connection) && $connection !== '' ? $connection : 'default';

        $redis = config('database.redis');

        if (! is_array($redis)) {
            return '';
        }

        $prefix = $this->mergeOptionsPrefix($redis['options'] ?? null, null);
        $clusters = $redis['clusters'] ?? null;

        if (isset($redis[$connection])) {
            $connectionConfig = $this->parseRedisConnection($redis[$connection]);
            $prefix = $this->mergeOptionsPrefix($connectionConfig['options'] ?? null, $prefix);

            if (isset($connectionConfig['prefix'])) {
                $prefix = $connectionConfig['prefix'];
            }
        } elseif (is_array($clusters) && is_array($clusters[$connection] ?? null)) {
            $cluster = $clusters[$connection];
            $prefix = $this->mergeOptionsPrefix($clusters['options'] ?? null, $prefix);
            $prefix = $this->mergeOptionsPrefix($cluster['options'] ?? null, $prefix);
        }

        return is_string($prefix) ? $prefix : '';
    }

    /**
     * Apply one array_merge() step of the connectors' option merging to the prefix.
     */
    private function mergeOptionsPrefix(mixed $options, mixed $prefix): mixed
    {
        return is_array($options) && array_key_exists('prefix', $options) ? $options['prefix'] : $prefix;
    }

    /**
     * Expand a connection's URL as RedisManager::parseConnectionConfiguration() does, so a
     * prefix in the URL's query wins over the connection's own keys.
     *
     * @return array<mixed>
     */
    private function parseRedisConnection(mixed $config): array
    {
        if (is_array($config)) {
            // ConfigurationUrlParser::parseConfiguration() is typed array<string, mixed>.
            $named = [];

            foreach ($config as $key => $value) {
                if (is_string($key)) {
                    $named[$key] = $value;
                }
            }

            $config = $named;

            // The parser runs a URL through preg_match(), which throws a TypeError on an
            // array or object. Only a string URL can carry a prefix, so read any other
            // connection's explicit keys, as below.
            $url = $config['url'] ?? null;

            if ($url !== null && ! is_string($url)) {
                return $config;
            }
        } elseif (! is_string($config)) {
            return [];
        }

        try {
            $parsed = (new ConfigurationUrlParser)->parseConfiguration($config);
        } catch (InvalidArgumentException) {
            // A malformed URL fails the connection itself; read the keys that are there.
            return is_array($config) ? $config : [];
        }

        return $parsed;
    }

    /**
     * Resolve the prefix the Memcached client puts on every key.
     *
     * MemcachedConnector passes the store's options to Memcached::setOptions(). The key is
     * Memcached::OPT_PREFIX_KEY, spelled as its value since the extension may not be loaded.
     */
    private function getMemcachedClientPrefix(string $store): string
    {
        $options = config("cache.stores.{$store}.options");
        $prefix = is_array($options) ? ($options[-1002] ?? null) : null;

        return is_string($prefix) ? $prefix : '';
    }

    private function getDefaultStore(): string
    {
        $store = config('cache.default');

        return is_string($store) ? $store : 'unknown';
    }

    private function getDefaultDriver(): string
    {
        $store = $this->getDefaultStore();

        $driver = config("cache.stores.{$store}.driver");
        if (is_string($driver)) {
            return $driver;
        }

        return $store;
    }

    /**
     * Get the app name from config.
     */
    private function getAppName(): ?string
    {
        $name = config('app.name');

        return is_string($name) ? $name : null;
    }

    /**
     * Get recommendation message for empty prefix.
     */
    private function getEmptyPrefixRecommendation(string $driver): string
    {
        return 'Set a unique cache prefix in config/cache.php to avoid collisions with other applications sharing the same cache server. Use your application name or a unique identifier.'
            .$this->getClientRecommendationSuffix($driver);
    }

    /**
     * Get recommendation message for generic prefix.
     */
    private function getGenericPrefixRecommendation(string $prefix, string $driver): string
    {
        return "The cache prefix '{$prefix}' is generic and may collide with other applications using the same cache server. ".
               'Use a unique prefix based on your application name.'.$this->getClientRecommendationSuffix($driver);
    }

    private function getClientRecommendationSuffix(string $driver): string
    {
        return match ($driver) {
            'redis' => ' For a redis store, a unique prefix on its Redis connection in config/database.php also keeps the keys apart, because Laravel prepends it to every key.',
            'memcached' => ' For a memcached store, a unique Memcached::OPT_PREFIX_KEY in the store\'s options also keeps the keys apart, because the client prepends it to every key.',
            default => '',
        };
    }
}
