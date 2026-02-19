<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Support\Str;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Checks cache prefix configuration to avoid collisions.
 *
 * Checks for:
 * - Cache prefix is set and not generic
 * - Prevents cache key collisions in shared cache servers
 * - Validates unique app identification
 */
class CachePrefixAnalyzer extends AbstractFileAnalyzer
{
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
            severity: Severity::High,
            tags: ['cache', 'configuration', 'reliability', 'multi-tenant'],
            timeToFix: 5
        );
    }

    public function shouldRun(): bool
    {
        return in_array($this->getDefaultDriver(), self::SHARED_CACHE_DRIVERS, true);
    }

    public function getSkipReason(): string
    {
        $driver = $this->getDefaultDriver();
        $driversList = implode('/', self::SHARED_CACHE_DRIVERS);

        return "Not using shared cache driver (current: {$driver}, requires: {$driversList})";
    }

    protected function runAnalysis(): ResultInterface
    {
        $configFile = $this->getCacheConfigPath();
        $prefix = $this->getEffectivePrefix();
        $prefixLine = $this->getPrefixLineNumber($configFile);

        // Check if prefix is empty
        if ($prefix === '') {
            return $this->resultBySeverity(
                'Cache prefix is not configured',
                [$this->createIssue(
                    message: 'Cache prefix is empty or not set',
                    location: new Location($this->getRelativePath($configFile), $prefixLine),
                    severity: $this->metadata()->severity,
                    recommendation: $this->getEmptyPrefixRecommendation(),
                    code: FileParser::getCodeSnippet($configFile, $prefixLine),
                    metadata: [
                        'cache_driver' => $this->getDefaultDriver(),
                        'prefix' => $prefix,
                    ]
                )]
            );
        }

        // Check if prefix is too generic
        if ($this->isGenericPrefix($prefix)) {
            return $this->resultBySeverity(
                'Cache prefix is too generic',
                [$this->createIssue(
                    message: "Cache prefix '{$prefix}' is too generic and may cause collisions",
                    location: new Location($this->getRelativePath($configFile), $prefixLine),
                    severity: $this->metadata()->severity,
                    recommendation: $this->getGenericPrefixRecommendation($prefix),
                    code: FileParser::getCodeSnippet($configFile, $prefixLine),
                    metadata: [
                        'cache_driver' => $this->getDefaultDriver(),
                        'prefix' => $prefix,
                        'app_name' => $this->getAppName(),
                    ]
                )]
            );
        }

        return $this->passed('Cache prefix is properly configured');
    }

    /**
     * Get the path to the cache configuration file.
     */
    private function getCacheConfigPath(): string
    {
        $basePath = $this->getBasePath();

        return ConfigFileHelper::getConfigPath(
            $basePath,
            'cache.php',
            fn ($file) => function_exists('config_path') ? config_path($file) : null
        );
    }

    /**
     * Get the line number for the prefix configuration key.
     * Falls back to line 1 if not found.
     */
    private function getPrefixLineNumber(string $configFile): int
    {
        if (! file_exists($configFile)) {
            return 1;
        }

        $store = $this->getDefaultStore();

        if ($this->hasStoreSpecificPrefix($store)) {
            // Find stores.{store}.prefix (e.g., stores.redis.prefix)
            $line = ConfigFileHelper::findNestedKeyLine($configFile, 'stores', $store, 'prefix');

            return $line > 0 ? $line : 1;
        }

        $lineNumber = ConfigFileHelper::findKeyLine($configFile, 'prefix');

        return $lineNumber > 0 ? $lineNumber : 1;
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

    private function getEffectivePrefix(): string
    {
        $store = $this->getDefaultStore();

        // Check store-specific prefix first
        $storePrefix = config("cache.stores.{$store}.prefix");
        if (is_string($storePrefix) && $storePrefix !== '') {
            return $storePrefix;
        }

        // Fall back to global prefix
        $globalPrefix = config('cache.prefix');

        // Validate that prefix is a string (not numeric, boolean, etc.)
        if (! is_string($globalPrefix)) {
            return '';
        }

        return $globalPrefix;
    }

    private function hasStoreSpecificPrefix(string $store): bool
    {
        $prefix = config("cache.stores.{$store}.prefix");

        return is_string($prefix) && $prefix !== '';
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
    private function getEmptyPrefixRecommendation(): string
    {
        return 'Set a unique cache prefix in config/cache.php to avoid collisions with other applications sharing the same cache server. Use your application name or a unique identifier.';
    }

    /**
     * Get recommendation message for generic prefix.
     */
    private function getGenericPrefixRecommendation(string $prefix): string
    {
        return "The cache prefix '{$prefix}' is generic and may collide with other applications using the same cache server. ".
               'Use a unique prefix based on your application name. ';
    }
}
