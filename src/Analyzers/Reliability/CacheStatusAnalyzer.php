<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Support\Facades\Cache;
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
 * Checks that the application cache is working properly.
 *
 * Checks for:
 * - Cache driver is accessible and functional
 * - Cache can store and retrieve values
 * - Cache operations don't throw exceptions
 */
class CacheStatusAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Cache connectivity checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'cache-status',
            name: 'Cache Status Analyzer',
            description: 'Ensures the application cache is working properly and can store/retrieve values',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['cache', 'infrastructure', 'reliability', 'availability'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/cache-status',
            timeToFix: 15
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $testKey = 'shieldci:cache:test:'.Str::random(10);
        $testValue = Str::random(20);
        $configLocation = $this->getCacheConfigLocation();

        try {
            // Test cache write
            Cache::put($testKey, $testValue, 60);

            // Test cache read
            $retrievedValue = Cache::get($testKey);

            // Verify retrieved value matches
            if ($retrievedValue !== $testValue) {
                // Clean up test key before returning
                $this->cleanupTestKey($testKey);

                return $this->failed(
                    'Cache storage is not working correctly - values are not being retrieved as expected',
                    [$this->createIssue(
                        message: 'Cache write/read test failed',
                        location: $configLocation,
                        severity: Severity::Critical,
                        recommendation: $this->getWriteReadFailureRecommendation(),
                        code: FileParser::getCodeSnippet($configLocation->file, $configLocation->line),
                        metadata: [
                            'cache_driver' => $this->getCacheDriver(),
                            'expected' => $testValue,
                            'received' => $retrievedValue,
                        ]
                    )]
                );
            }

            // Clean up test key after successful test
            $this->cleanupTestKey($testKey);

            return $this->passed('Cache is working correctly');
        } catch (\Throwable $e) {
            // Ensure cleanup on exception
            $this->cleanupTestKey($testKey);

            return $this->failed(
                'Cache is not accessible or not functioning properly',
                [$this->createIssue(
                    message: 'Cache connection/operation failed',
                    location: $configLocation,
                    severity: Severity::Critical,
                    recommendation: $this->getConnectionFailureRecommendation($e),
                    code: FileParser::getCodeSnippet($configLocation->file, $configLocation->line),
                    metadata: [
                        'cache_driver' => $this->getCacheDriver(),
                        'exception' => get_class($e),
                        'error' => $e->getMessage(),
                    ]
                )]
            );
        }
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
     * Get the location of the cache configuration file.
     * Attempts to find the 'default' key line, falls back to line 1.
     */
    private function getCacheConfigLocation(): Location
    {
        $configFile = $this->getCacheConfigPath();

        if (file_exists($configFile)) {
            $lineNumber = ConfigFileHelper::findKeyLine($configFile, 'default');

            if ($lineNumber < 1) {
                $lineNumber = 1;
            }

            return new Location($this->getRelativePath($configFile), $lineNumber);
        }

        return new Location($this->getRelativePath($configFile), 1);
    }

    /**
     * Get the cache driver from config.
     */
    private function getCacheDriver(): string
    {
        $driver = config('cache.default');

        return is_string($driver) ? $driver : 'unknown';
    }

    /**
     * Get recommendation message for cache write/read failure.
     */
    private function getWriteReadFailureRecommendation(): string
    {
        return 'Check your cache configuration in config/cache.php. Ensure the cache driver is properly configured and the cache server (Redis, Memcached, etc.) is running and accessible. Test connection to cache server manually.';
    }

    /**
     * Get recommendation message for cache connection failure.
     */
    private function getConnectionFailureRecommendation(\Throwable $e): string
    {
        $errorMessage = $e->getMessage();
        $sanitizedError = $this->sanitizeErrorMessage($errorMessage);

        return "Check your cache configuration and ensure the cache server is running. Error: {$sanitizedError}. Common issues: 1) Redis/Memcached server not running, 2) Incorrect host/port configuration, 3) Authentication issues, 4) Firewall blocking connection.";
    }

    /**
     * Sanitize error message for display in recommendations.
     */
    private function sanitizeErrorMessage(string $error): string
    {
        // Limit error message length to prevent overly long recommendations
        $maxLength = 200;
        if (strlen($error) > $maxLength) {
            return substr($error, 0, $maxLength).'...';
        }

        return $error;
    }

    /**
     * Clean up test cache key.
     * Silently ignores any cleanup errors to prevent masking the original issue.
     */
    private function cleanupTestKey(string $testKey): void
    {
        try {
            Cache::forget($testKey);
        } catch (\Throwable $cleanupException) {
            // Silently ignore cleanup errors - we don't want cleanup failures
            // to mask the actual cache issue we're testing for
        }
    }

}
