<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Filesystem\Filesystem;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Checks write permissions for critical Laravel directories.
 *
 * Checks for:
 * - storage/ directory is writable
 * - bootstrap/cache/ directory is writable
 * - Configurable via shieldci.writable_directories
 */
class DirectoryWritePermissionsAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private Filesystem $files
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'directory-write-permissions',
            name: 'Directory Write Permissions Analyzer',
            description: 'Ensures critical Laravel directories have proper write permissions',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['permissions', 'filesystem', 'reliability', 'deployment'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/directory-write-permissions',
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $basePath = $this->getBasePath();

        // Get directories to check from config or use defaults
        $directoriesToCheck = $this->getDirectoriesToCheck($basePath);

        // Find directories that are not writable
        $failedDirs = $this->findNonWritableDirectories($directoriesToCheck);

        if (empty($failedDirs)) {
            return $this->passed('All critical directories have proper write permissions');
        }

        // Create issues for failed directories
        $issues = $this->createIssuesForFailedDirectories($failedDirs, $basePath);

        return $this->failed(
            sprintf('Found %d directory permission issue(s)', count($failedDirs)),
            $issues
        );
    }

    /**
     * Get directories to check from config or return defaults.
     *
     * @return array<string>
     */
    private function getDirectoriesToCheck(string $basePath): array
    {
        $directoriesToCheck = $this->safeExecute(
            fn () => config('shieldci.writable_directories'),
            null
        );

        if (is_array($directoriesToCheck) && ! empty($directoriesToCheck)) {
            $filtered = array_filter($directoriesToCheck, fn ($dir) => is_string($dir) && $dir !== '');

            // Convert relative paths to absolute paths
            return array_map(function ($dir) use ($basePath) {
                if ($this->isAbsolutePath($dir)) {
                    return $dir;
                }

                // Handle paths with / or \ by replacing them with DIRECTORY_SEPARATOR
                $normalizedDir = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $dir);

                return $basePath.DIRECTORY_SEPARATOR.$normalizedDir;
            }, $filtered);
        }

        return $this->getDefaultDirectories($basePath);
    }

    /**
     * Get default directories to check.
     *
     * @return array<string>
     */
    private function getDefaultDirectories(string $basePath): array
    {
        $directories = [];

        // Try to get storage path using Laravel helper or fallback
        $storagePath = $this->getStoragePath($basePath);
        if ($storagePath !== '') {
            $directories[] = $storagePath;
        }

        // Try to get bootstrap/cache path
        $bootstrapCachePath = $this->getBootstrapCachePath($basePath);
        if ($bootstrapCachePath !== '') {
            $directories[] = $bootstrapCachePath;
        }

        return $directories;
    }

    /**
     * Get storage path with fallback.
     */
    private function getStoragePath(string $basePath): string
    {
        if (function_exists('storage_path')) {
            $path = $this->safeExecute(fn () => storage_path(), '');
            if (is_string($path) && $path !== '') {
                return $path;
            }
        }

        // Fallback to default storage path
        return $this->buildPath($basePath, 'storage');
    }

    /**
     * Get bootstrap/cache path with fallback.
     */
    private function getBootstrapCachePath(string $basePath): string
    {
        if (function_exists('base_path')) {
            $path = $this->safeExecute(fn () => base_path('bootstrap/cache'), '');
            if (is_string($path) && $path !== '') {
                return $path;
            }
        }

        // Fallback to default bootstrap/cache path
        return $this->buildPath($basePath, 'bootstrap', 'cache');
    }

    /**
     * Find directories that are not writable.
     *
     * @param  array<string>  $directories
     * @return array<string>
     */
    private function findNonWritableDirectories(array $directories): array
    {
        $failedDirs = [];

        foreach ($directories as $directory) {
            if (! is_string($directory) || $directory === '') {
                continue;
            }

            if (! $this->isDirectoryWritable($directory)) {
                $failedDirs[] = $directory;
            }
        }

        return $failedDirs;
    }

    /**
     * Check if a directory exists and is writable.
     */
    private function isDirectoryWritable(string $directory): bool
    {
        // Check if directory exists first
        if (! $this->files->isDirectory($directory)) {
            return false;
        }

        return $this->safeExecute(
            fn () => $this->files->isWritable($directory),
            false
        );
    }

    /**
     * Create issues for failed directories.
     *
     * @param  array<string>  $failedDirs
     * @return array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>
     */
    private function createIssuesForFailedDirectories(array $failedDirs, string $basePath): array
    {
        $issues = [];
        $formattedDirs = array_map(fn ($path) => $this->formatPath($path, $basePath), $failedDirs);
        $failedDirsList = implode(', ', $formattedDirs);

        // Use the first failed directory for location, or base path as fallback
        $locationPath = ! empty($failedDirs) ? $failedDirs[0] : $basePath;
        $locationPath = $this->formatPath($locationPath, $basePath);

        $issues[] = $this->createIssue(
            message: 'Storage and cache directories are not writable',
            location: new Location($this->getRelativePath($locationPath), 1),
            severity: Severity::Critical,
            recommendation: $this->buildRecommendation($failedDirsList, $formattedDirs),
            code: FileParser::getCodeSnippet($locationPath, 1),
            metadata: [
                'failed_directories' => $formattedDirs,
                'count' => count($failedDirs),
            ]
        );

        return $issues;
    }

    /**
     * Build recommendation message.
     *
     * @param  array<string>  $formattedDirs
     */
    private function buildRecommendation(string $failedDirsList, array $formattedDirs): string
    {
        $dirsForCommand = implode(' ', $formattedDirs);

        return sprintf(
            <<<'RECOMMENDATION'
The following directories must be writable: %s.

To fix this, run one of the following commands:

Unix/Linux:
  %s %s
  or
  %s %s (adjust user/group as needed)

Windows:
  Use File Explorer to grant write permissions to the directories.

These directories are required for logs, sessions, cache, compiled views, and configuration caching.
RECOMMENDATION,
            $failedDirsList,
            'chmod -R 775',
            $dirsForCommand,
            'chown -R www-data:www-data',
            $dirsForCommand
        );
    }

    /**
     * Format a path for display (relative to base path if possible).
     */
    private function formatPath(string $path, string $basePath): string
    {
        if ($path === '') {
            return $basePath; // Never return empty string
        }

        if ($basePath === '') {
            return $path;
        }

        // Normalize paths for comparison
        $normalizedPath = $this->normalizePath($path);
        $normalizedBasePath = $this->normalizePath($basePath);

        if (str_starts_with($normalizedPath, $normalizedBasePath)) {
            $relative = substr($normalizedPath, strlen($normalizedBasePath));
            $relative = ltrim($relative, DIRECTORY_SEPARATOR);

            return $relative !== '' ? $relative : $path;
        }

        return $path;
    }

    /**
     * Normalize path for cross-platform comparison.
     */
    private function normalizePath(string $path): string
    {
        return str_replace(['/', '\\'], DIRECTORY_SEPARATOR, rtrim($path, '/\\'));
    }

    /**
     * Execute a callable safely, returning default on exception.
     *
     * @template T
     *
     * @param  callable(): T  $callback
     * @param  T  $default
     * @return T
     */
    private function safeExecute(callable $callback, mixed $default): mixed
    {
        try {
            return $callback();
        } catch (\Throwable $e) {
            return $default;
        }
    }

    /**
     * Check if a path is absolute.
     */
    private function isAbsolutePath(string $path): bool
    {
        if ($path === '') {
            return false;
        }

        // Unix absolute path starts with /
        if ($path[0] === '/') {
            return true;
        }

        // Windows absolute path: C:\ or C:/
        if (strlen($path) >= 3 && ctype_alpha($path[0]) && $path[1] === ':' && ($path[2] === '\\' || $path[2] === '/')) {
            return true;
        }

        return false;
    }
}
