<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Filesystem\Filesystem;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
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

        // Find directories that are missing or not writable
        ['missing' => $missingDirs, 'non_writable' => $nonWritableDirs] = $this->findDirectoryIssues($directoriesToCheck);

        if (empty($missingDirs) && empty($nonWritableDirs)) {
            return $this->passed('All critical directories exist and have proper write permissions');
        }

        // Create issues for failed directories
        $issues = $this->createIssuesForFailedDirectories($missingDirs, $nonWritableDirs, $basePath);

        $totalIssues = count($missingDirs) + count($nonWritableDirs);

        return $this->failed(
            sprintf('Found %d directory permission issue(s)', $totalIssues),
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
            $filtered = array_filter(
                array_map(fn ($dir) => is_string($dir) ? trim($dir) : null, $directoriesToCheck),
                fn ($dir) => is_string($dir) && $dir !== ''
            );

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
     * Find directories that are missing or not writable.
     *
     * @param  array<string>  $directories
     * @return array{missing: array<string>, non_writable: array<string>}
     */
    private function findDirectoryIssues(array $directories): array
    {
        $missingDirs = [];
        $nonWritableDirs = [];

        foreach ($directories as $directory) {
            if (! is_string($directory) || $directory === '') {
                continue;
            }

            if (! $this->files->isDirectory($directory)) {
                $missingDirs[] = $directory;
            } elseif (! $this->isWritable($directory)) {
                $nonWritableDirs[] = $directory;
            }
        }

        return [
            'missing' => $missingDirs,
            'non_writable' => $nonWritableDirs,
        ];
    }

    /**
     * Check if a directory is writable (assumes directory exists).
     */
    private function isWritable(string $directory): bool
    {
        return $this->safeExecute(
            fn () => $this->files->isWritable($directory),
            false
        );
    }

    /**
     * Create issues for failed directories.
     *
     * @param  array<string>  $missingDirs
     * @param  array<string>  $nonWritableDirs
     * @return array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>
     */
    private function createIssuesForFailedDirectories(array $missingDirs, array $nonWritableDirs, string $basePath): array
    {
        $issues = [];

        $formattedMissing = array_map(fn ($path) => $this->formatPath($path, $basePath), $missingDirs);
        $formattedNonWritable = array_map(fn ($path) => $this->formatPath($path, $basePath), $nonWritableDirs);

        // Determine message based on what failed
        $message = $this->buildMessage($missingDirs, $nonWritableDirs);

        // Use the first problematic directory for location, or base path as fallback
        $locationPath = ! empty($missingDirs) ? $missingDirs[0] : (! empty($nonWritableDirs) ? $nonWritableDirs[0] : $basePath);

        $issues[] = $this->createIssue(
            message: $message,
            location: new Location($this->getRelativePath($locationPath)),
            severity: Severity::Critical,
            recommendation: $this->buildRecommendation($formattedMissing, $formattedNonWritable),
            code: null,
            metadata: [
                'missing_directories' => $formattedMissing,
                'non_writable_directories' => $formattedNonWritable,
                'missing_count' => count($missingDirs),
                'non_writable_count' => count($nonWritableDirs),
            ]
        );

        return $issues;
    }

    /**
     * Build issue message based on failure types.
     *
     * @param  array<string>  $missingDirs
     * @param  array<string>  $nonWritableDirs
     */
    private function buildMessage(array $missingDirs, array $nonWritableDirs): string
    {
        $hasMissing = ! empty($missingDirs);
        $hasNonWritable = ! empty($nonWritableDirs);

        if ($hasMissing && $hasNonWritable) {
            return sprintf(
                'Found %d missing and %d non-writable directories',
                count($missingDirs),
                count($nonWritableDirs)
            );
        }

        if ($hasMissing) {
            return sprintf('%d required %s not found', count($missingDirs), count($missingDirs) === 1 ? 'directory' : 'directories');
        }

        return sprintf('%d %s not writable', count($nonWritableDirs), count($nonWritableDirs) === 1 ? 'directory is' : 'directories are');
    }

    /**
     * Build recommendation message.
     *
     * @param  array<string>  $formattedMissing
     * @param  array<string>  $formattedNonWritable
     */
    private function buildRecommendation(array $formattedMissing, array $formattedNonWritable): string
    {
        $recommendations = [];

        if (! empty($formattedMissing)) {
            $missingList = implode(', ', $formattedMissing);
            $recommendations[] = sprintf(
                "Missing directories: %s\nCreate them manually or via your OS tooling (e.g., mkdir -p %s)",
                $missingList,
                implode(' ', $formattedMissing)
            );
        }

        if (! empty($formattedNonWritable)) {
            $nonWritableList = implode(', ', $formattedNonWritable);
            $recommendations[] = sprintf(
                "Non-writable directories: %s\nApply appropriate write permissions (e.g., chmod -R 775 %s) according to your environment.",
                $nonWritableList,
                implode(' ', $formattedNonWritable)
            );
        }

        $rec = implode("\n\n", $recommendations);
        $rec .= "\n\nThese directories are required for logs, sessions, cache, compiled views, and configuration caching.";

        return $rec;
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
