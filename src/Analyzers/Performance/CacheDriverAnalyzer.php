<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Analyzes cache driver configuration for performance best practices.
 *
 * Checks for:
 * - Null or array cache drivers in production
 * - File cache driver in non-local environments
 * - Database cache driver in production
 * - Recommends Redis/Memcached for production
 *
 * This analyzer uses Laravel's config repository to get runtime values,
 * which respects environment variables and config caching.
 */
class CacheDriverAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ConfigRepository $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'cache-driver',
            name: 'Cache Driver Configuration',
            description: 'Ensures a proper cache driver is configured for optimal performance',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['cache', 'performance', 'configuration', 'redis', 'memcached'],
            docsUrl: 'https://laravel.com/docs/cache#configuration'
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

        $environment = $this->config->get('app.env', 'production');

        // Validate that the store exists in configuration
        $driver = $this->config->get("cache.stores.{$defaultStore}.driver");
        if ($driver === null) {
            $issues[] = $this->createIssue(
                message: "Cache store '{$defaultStore}' is not defined in cache configuration",
                location: new Location($this->getConfigPath('cache.php'), $this->findLineInConfig('cache', 'default')),
                severity: Severity::Critical,
                recommendation: 'Define the cache store in config/cache.php or change the default store in your .env file (CACHE_STORE)',
                metadata: ['store' => $defaultStore, 'environment' => $environment]
            );

            return $this->failed('Cache configuration is invalid', $issues);
        }

        // Check for problematic drivers
        if ($driver === 'null') {
            $issues[] = $this->createIssue(
                message: 'Cache driver is set to null - caching is disabled',
                location: new Location($this->getConfigPath('cache.php'), $this->findDriverLineInConfig($defaultStore)),
                severity: Severity::Critical,
                recommendation: 'Set CACHE_STORE to redis, memcached, or dynamodb in your .env file for production. Null driver means all cache operations will be no-ops.',
                metadata: ['driver' => 'null', 'store' => $defaultStore, 'environment' => $environment]
            );
        } elseif ($driver === 'array') {
            $issues[] = $this->createIssue(
                message: 'Cache driver is set to array - cache not persisted',
                location: new Location($this->getConfigPath('cache.php'), $this->findDriverLineInConfig($defaultStore)),
                severity: Severity::Critical,
                recommendation: 'Array driver only caches within a single request and is only suitable for testing. Use redis, memcached, or dynamodb for production.',
                metadata: ['driver' => 'array', 'store' => $defaultStore, 'environment' => $environment]
            );
        } elseif ($driver === 'file' && $environment !== 'local') {
            $issues[] = $this->createIssue(
                message: "File cache driver in {$environment} environment",
                location: new Location($this->getConfigPath('cache.php'), $this->findDriverLineInConfig($defaultStore)),
                severity: Severity::Medium,
                recommendation: 'File cache is only suitable for single-server setups. For better performance, use Redis or Memcached with unix sockets. They provide faster access and more efficient eviction of expired cache items.',
                metadata: ['driver' => 'file', 'store' => $defaultStore, 'environment' => $environment]
            );
        } elseif ($driver === 'database' && $environment !== 'local') {
            $issues[] = $this->createIssue(
                message: "Database cache driver in {$environment} environment",
                location: new Location($this->getConfigPath('cache.php'), $this->findDriverLineInConfig($defaultStore)),
                severity: Severity::Medium,
                recommendation: 'Database cache driver is not recommended for production. Use Redis or Memcached for better performance and robustness.',
                metadata: ['driver' => 'database', 'store' => $defaultStore, 'environment' => $environment]
            );
        }

        if (empty($issues)) {
            return $this->passed("Cache driver '{$driver}' is properly configured for {$environment} environment");
        }

        return $this->failed(
            sprintf('Found %d cache driver configuration issues', count($issues)),
            $issues
        );
    }

    private function getConfigPath(string $file): string
    {
        return $this->basePath.'/config/'.$file;
    }

    /**
     * Find the line number where a specific key is defined in a config file.
     * Uses precise patterns to avoid matches in comments.
     */
    private function findLineInConfig(string $file, string $key): int
    {
        $configFile = $this->getConfigPath($file.'.php');

        $content = $this->readFile($configFile);
        if ($content === null) {
            return 1;
        }

        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Strip single-line comments (// and #)
            $lineWithoutComments = preg_replace('/\/\/.*$|#.*$/', '', $line);
            if (! is_string($lineWithoutComments)) {
                $lineWithoutComments = $line;
            }

            // Look for array key pattern: 'key' => or "key" => or 'key'=> (with optional spaces)
            // This ensures we match actual array keys, not strings in comments
            $pattern = '/[\'"](?:'.preg_quote($key, '/').')[\'"]\s*=>/';
            if (preg_match($pattern, $lineWithoutComments)) {
                return $lineNumber + 1;
            }
        }

        return 1;
    }

    /**
     * Find the line number where a specific cache store's driver is defined.
     * This searches for the store name in the 'stores' array using precise patterns
     * to avoid matches in comments.
     */
    private function findDriverLineInConfig(string $storeName): int
    {
        $configFile = $this->getConfigPath('cache.php');

        $content = $this->readFile($configFile);
        if ($content === null) {
            return 1;
        }

        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Strip single-line comments (// and #)
            $lineWithoutComments = preg_replace('/\/\/.*$|#.*$/', '', $line);
            if (! is_string($lineWithoutComments)) {
                $lineWithoutComments = $line;
            }

            // Look for store name as array key: 'storeName' => [ or "storeName" => [
            // This ensures we match actual store definitions, not strings in comments
            $pattern = '/[\'"](?:'.preg_quote($storeName, '/').')[\'"]\s*=>\s*\[/';
            if (preg_match($pattern, $lineWithoutComments)) {
                // Found the store definition, now look for 'driver' key within this store
                // Search forward from this line for the driver definition
                for ($i = $lineNumber + 1; $i < count($lines) && $i < $lineNumber + 20; $i++) {
                    $storeLine = $lines[$i];
                    
                    // Stop if we hit the next store definition or closing bracket
                    if (preg_match('/[\'"][a-zA-Z_][a-zA-Z0-9_]*[\'"]\s*=>\s*\[/', $storeLine) ||
                        preg_match('/^\s*\]/', $storeLine)) {
                        break;
                    }

                    // Strip comments
                    $storeLineWithoutComments = preg_replace('/\/\/.*$|#.*$/', '', $storeLine);
                    if (! is_string($storeLineWithoutComments)) {
                        $storeLineWithoutComments = $storeLine;
                    }

                    // Look for 'driver' => 'value' pattern
                    if (preg_match('/[\'"]driver[\'"]\s*=>/', $storeLineWithoutComments)) {
                        return $i + 1;
                    }
                }

                // If driver not found within store definition, return store definition line
                return $lineNumber + 1;
            }
        }

        // Fallback to 'default' key if store name not found
        return $this->findLineInConfig('cache', 'default');
    }
}
