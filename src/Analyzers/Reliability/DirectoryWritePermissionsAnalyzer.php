<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;
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
            name: 'Directory Write Permissions',
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
        // Get directories to check from config (Laravel-style helper functions)
        $directoriesToCheck = config('shieldci.writable_directories');

        if (! is_array($directoriesToCheck)) {
            $directoriesToCheck = [
                storage_path(),
                base_path('bootstrap/cache'),
            ];
        }

        // Find directories that are not writable
        $failedDirs = collect($directoriesToCheck)
            ->reject(function ($directory) {
                if (! is_string($directory)) {
                    return true;
                }

                return $this->files->isWritable($directory);
            })
            ->map(fn ($path) => $this->formatPath((string) $path))
            ->values()
            ->all();

        if (empty($failedDirs)) {
            return $this->passed('All critical directories have proper write permissions');
        }

        // Create a single issue with all failed directories
        $failedDirsList = implode(', ', $failedDirs);

        return $this->failed(
            sprintf('Found %d directory permission issue(s)', count($failedDirs)),
            [$this->createIssue(
                message: 'Storage and cache directories are not writable',
                location: new Location($this->basePath, 1),
                severity: Severity::Critical,
                recommendation: "The following directories must be writable: {$failedDirsList}. ".
                    'Run: chmod -R 775 storage bootstrap/cache or '.
                    'chown -R www-data:www-data storage bootstrap/cache (adjust user/group as needed). '.
                    'These directories are required for logs, sessions, cache, compiled views, and configuration caching.',
                metadata: [
                    'failed_directories' => $failedDirs,
                    'count' => count($failedDirs),
                ]
            )]
        );
    }

    /**
     * Format a path for display (relative to base path if possible).
     */
    private function formatPath(string $path): string
    {
        if (Str::contains($path, $this->basePath)) {
            return trim(Str::after($path, $this->basePath), '/');
        }

        return $path;
    }
}
