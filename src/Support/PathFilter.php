<?php

declare(strict_types=1);

namespace ShieldCI\Support;

/**
 * Helper class for filtering paths based on configuration.
 */
class PathFilter
{
    /**
     * @param  array<string>  $analyzePaths
     * @param  array<string>  $excludedPaths
     */
    public function __construct(
        private array $analyzePaths,
        private array $excludedPaths
    ) {
    }

    /**
     * Check if a file path should be analyzed.
     */
    public function shouldAnalyze(string $path): bool
    {
        // Normalize path
        $path = str_replace('\\', '/', $path);
        $basePath = base_path();
        $relativePath = str_starts_with($path, $basePath)
            ? substr($path, strlen($basePath) + 1)
            : $path;

        // Check if excluded
        if ($this->isExcluded($relativePath)) {
            return false;
        }

        // Check if in analyze paths
        return $this->isInAnalyzePaths($relativePath);
    }

    /**
     * Check if path matches any exclusion pattern.
     */
    private function isExcluded(string $path): bool
    {
        foreach ($this->excludedPaths as $pattern) {
            if ($this->matchesPattern($path, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if path is within any analyze paths.
     */
    private function isInAnalyzePaths(string $path): bool
    {
        // If no paths configured, analyze everything (except excluded)
        if (empty($this->analyzePaths)) {
            return true;
        }

        foreach ($this->analyzePaths as $analyzePath) {
            // Normalize analyze path
            $analyzePath = trim($analyzePath, '/');

            // Check if path starts with analyze path
            if (str_starts_with($path, $analyzePath.'/') || $path === $analyzePath) {
                return true;
            }
        }

        return false;
    }

    /**
     * Match path against glob pattern.
     */
    private function matchesPattern(string $path, string $pattern): bool
    {
        // Convert glob pattern to regex
        $pattern = str_replace(
            ['\\', '/', '*', '?'],
            ['\\\\', '\\/', '.*', '.'],
            $pattern
        );

        return (bool) preg_match('/^'.$pattern.'$/i', $path);
    }

    /**
     * Get paths to analyze.
     */
    public function getAnalyzePaths(): array
    {
        return $this->analyzePaths;
    }

    /**
     * Get excluded paths.
     */
    public function getExcludedPaths(): array
    {
        return $this->excludedPaths;
    }
}
