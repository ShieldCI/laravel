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
 * Checks write permissions for critical Laravel directories and symlinks.
 *
 * Checks for:
 * - storage/ directory is writable
 * - bootstrap/cache/ directory is writable
 * - Configurable via shieldci.writable_directories
 * - Storage symlinks from config('filesystems.links') are valid
 * - Configurable via shieldci.check_symlinks
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
            description: 'Ensures critical Laravel directories have proper write permissions and storage symlinks are valid',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['permissions', 'filesystem', 'reliability', 'deployment', 'symlinks'],
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

        // Check symlinks if enabled (default: true)
        $brokenSymlinks = $this->isSymlinkCheckEnabled() ? $this->checkSymlinks() : [];

        $hasDirectoryIssues = ! empty($missingDirs) || ! empty($nonWritableDirs);
        $hasSymlinkIssues = ! empty($brokenSymlinks);

        if (! $hasDirectoryIssues && ! $hasSymlinkIssues) {
            return $this->passed('All critical directories exist and have proper write permissions, and all symlinks are valid');
        }

        $issues = [];

        // Create issues for failed directories
        if ($hasDirectoryIssues) {
            $issues = array_merge($issues, $this->createIssuesForFailedDirectories($missingDirs, $nonWritableDirs, $basePath));
        }

        // Create issues for broken symlinks
        if ($hasSymlinkIssues) {
            $issues = array_merge($issues, $this->createIssuesForBrokenSymlinks($brokenSymlinks, $basePath));
        }

        $totalIssues = count($missingDirs) + count($nonWritableDirs) + count($brokenSymlinks);

        return $this->failed(
            sprintf('Found %d filesystem issue(s)', $totalIssues),
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
     * Check if symlink checking is enabled.
     */
    private function isSymlinkCheckEnabled(): bool
    {
        $enabled = $this->safeExecute(
            fn () => config('shieldci.check_symlinks', true),
            true
        );

        return is_bool($enabled) ? $enabled : true;
    }

    /**
     * Get symlinks to check from Laravel's filesystems config.
     *
     * @return array<string, string> Map of link path => target path
     */
    private function getSymlinksToCheck(): array
    {
        $basePath = $this->getBasePath();

        // Try to get from Laravel config
        $links = $this->safeExecute(
            fn () => config('filesystems.links'),
            null
        );

        if (is_array($links) && ! empty($links)) {
            // Filter to ensure we have string keys and values
            $validLinks = [];
            foreach ($links as $link => $target) {
                if (is_string($link) && is_string($target)) {
                    $validLinks[$link] = $target;
                }
            }

            return $validLinks;
        }

        // Default: public/storage -> storage/app/public
        $publicStorageLink = function_exists('public_path')
            ? $this->safeExecute(fn () => public_path('storage'), '')
            : $this->buildPath($basePath, 'public', 'storage');

        $storageAppPublic = function_exists('storage_path')
            ? $this->safeExecute(fn () => storage_path('app/public'), '')
            : $this->buildPath($basePath, 'storage', 'app', 'public');

        if ($publicStorageLink !== '' && $storageAppPublic !== '') {
            return [$publicStorageLink => $storageAppPublic];
        }

        return [];
    }

    /**
     * Check symlinks and return broken ones.
     *
     * @return array<int, array{link: string, target: string, reason: string}>
     */
    private function checkSymlinks(): array
    {
        $brokenSymlinks = [];

        foreach ($this->getSymlinksToCheck() as $link => $target) {
            if (! is_link($link)) {
                // Symlink doesn't exist
                $brokenSymlinks[] = [
                    'link' => $link,
                    'target' => $target,
                    'reason' => 'missing',
                ];
            } elseif (! file_exists($link)) {
                // Symlink exists but target doesn't (broken symlink)
                $brokenSymlinks[] = [
                    'link' => $link,
                    'target' => $target,
                    'reason' => 'broken',
                ];
            } elseif (! is_dir($link)) {
                // Target exists but isn't a directory
                $brokenSymlinks[] = [
                    'link' => $link,
                    'target' => $target,
                    'reason' => 'not_directory',
                ];
            }
        }

        return $brokenSymlinks;
    }

    /**
     * Create issues for broken symlinks.
     *
     * @param  array<int, array{link: string, target: string, reason: string}>  $brokenSymlinks
     * @return array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>
     */
    private function createIssuesForBrokenSymlinks(array $brokenSymlinks, string $basePath): array
    {
        $issues = [];

        $formattedSymlinks = array_map(function ($symlink) use ($basePath) {
            return [
                'link' => $this->formatPath($symlink['link'], $basePath),
                'target' => $this->formatPath($symlink['target'], $basePath),
                'reason' => $symlink['reason'],
            ];
        }, $brokenSymlinks);

        // Build message based on symlink issues
        $message = $this->buildSymlinkMessage($brokenSymlinks);

        // Use the first broken symlink for location
        $locationPath = $brokenSymlinks[0]['link'];

        $issues[] = $this->createIssue(
            message: $message,
            location: new Location($this->getRelativePath($locationPath)),
            severity: Severity::Critical,
            recommendation: $this->buildSymlinkRecommendation($formattedSymlinks),
            code: null,
            metadata: [
                'broken_symlinks' => $formattedSymlinks,
                'broken_symlink_count' => count($brokenSymlinks),
            ]
        );

        return $issues;
    }

    /**
     * Build message for symlink issues.
     *
     * @param  array<int, array{link: string, target: string, reason: string}>  $brokenSymlinks
     */
    private function buildSymlinkMessage(array $brokenSymlinks): string
    {
        $count = count($brokenSymlinks);
        $reasons = array_unique(array_column($brokenSymlinks, 'reason'));

        if (count($reasons) === 1) {
            return match ($reasons[0]) {
                'missing' => sprintf('%d storage %s missing', $count, $count === 1 ? 'symlink is' : 'symlinks are'),
                'broken' => sprintf('%d storage %s broken (target does not exist)', $count, $count === 1 ? 'symlink is' : 'symlinks are'),
                'not_directory' => sprintf('%d storage %s invalid (target is not a directory)', $count, $count === 1 ? 'symlink is' : 'symlinks are'),
                default => sprintf('%d storage %s invalid', $count, $count === 1 ? 'symlink is' : 'symlinks are'),
            };
        }

        return sprintf('%d storage %s invalid', $count, $count === 1 ? 'symlink is' : 'symlinks are');
    }

    /**
     * Build recommendation for symlink issues.
     *
     * @param  array<int, array{link: string, target: string, reason: string}>  $formattedSymlinks
     */
    private function buildSymlinkRecommendation(array $formattedSymlinks): string
    {
        $recommendations = [];

        $recommendations[] = 'Run `php artisan storage:link` to create missing symlinks.';

        $linkDetails = [];
        foreach ($formattedSymlinks as $symlink) {
            $reasonText = match ($symlink['reason']) {
                'missing' => 'does not exist',
                'broken' => 'exists but target is missing',
                'not_directory' => 'target is not a directory',
                default => 'is invalid',
            };
            $linkDetails[] = sprintf('  - %s → %s (%s)', $symlink['link'], $symlink['target'], $reasonText);
        }

        $recommendations[] = "Broken symlinks:\n".implode("\n", $linkDetails);

        $rec = implode("\n\n", $recommendations);
        $rec .= "\n\nStorage symlinks are required for serving publicly accessible files (uploads, images, etc.).";

        return $rec;
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
