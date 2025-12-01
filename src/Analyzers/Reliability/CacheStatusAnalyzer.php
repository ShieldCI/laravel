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
            name: 'Cache Status',
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

            // Clean up test key (ensure cleanup even if read fails)
            try {
                Cache::forget($testKey);
            } catch (\Throwable $cleanupException) {
                // Ignore cleanup errors, but log them in metadata if needed
            }

            if ($retrievedValue !== $testValue) {
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

            return $this->passed('Cache is working correctly');
        } catch (\Throwable $e) {
            // Ensure cleanup on exception
            try {
                Cache::forget($testKey);
            } catch (\Throwable $cleanupException) {
                // Ignore cleanup errors
            }

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

            return new Location($configFile, $lineNumber);
        }

        return new Location($configFile, 1);
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
}
