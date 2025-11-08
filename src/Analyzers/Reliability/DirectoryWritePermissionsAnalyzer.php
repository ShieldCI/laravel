<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

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
 * - Proper permissions for application functionality
 */
class DirectoryWritePermissionsAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<string, array{description: string, severity: string}>
     */
    private array $criticalDirectories = [
        'storage' => [
            'description' => 'Required for logs, sessions, cache, and file uploads',
            'severity' => 'critical',
        ],
        'storage/app' => [
            'description' => 'Required for file storage',
            'severity' => 'high',
        ],
        'storage/framework' => [
            'description' => 'Required for sessions, cache, and compiled views',
            'severity' => 'critical',
        ],
        'storage/framework/cache' => [
            'description' => 'Required for file-based cache',
            'severity' => 'high',
        ],
        'storage/framework/sessions' => [
            'description' => 'Required for file-based sessions',
            'severity' => 'high',
        ],
        'storage/framework/views' => [
            'description' => 'Required for compiled Blade templates',
            'severity' => 'critical',
        ],
        'storage/logs' => [
            'description' => 'Required for application logs',
            'severity' => 'critical',
        ],
        'bootstrap/cache' => [
            'description' => 'Required for configuration and route caching',
            'severity' => 'critical',
        ],
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'directory-write-permissions',
            name: 'Directory Write Permissions',
            description: 'Ensures critical Laravel directories have proper write permissions',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['permissions', 'filesystem', 'reliability', 'deployment'],
            docsUrl: 'https://laravel.com/docs/installation#directory-permissions'
        );
    }

    public function shouldRun(): bool
    {
        // Don't run on Windows where permissions work differently
        return PHP_OS_FAMILY !== 'Windows';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        foreach ($this->criticalDirectories as $dir => $info) {
            $fullPath = $this->basePath.'/'.$dir;

            if (! file_exists($fullPath)) {
                $issues[] = $this->createIssue(
                    message: "Directory '{$dir}' does not exist",
                    location: new Location($this->basePath, 0),
                    severity: $info['severity'] === 'critical' ? Severity::Critical : Severity::High,
                    recommendation: "Create the '{$dir}' directory. {$info['description']}. Run: mkdir -p {$fullPath} && chmod -R 775 {$fullPath}",
                    metadata: [
                        'directory' => $dir,
                        'full_path' => $fullPath,
                        'exists' => false,
                    ]
                );

                continue;
            }

            if (! is_writable($fullPath)) {
                $currentPerms = $this->getPermissions($fullPath);

                $issues[] = $this->createIssue(
                    message: "Directory '{$dir}' is not writable",
                    location: new Location($fullPath, 0),
                    severity: $info['severity'] === 'critical' ? Severity::Critical : Severity::High,
                    recommendation: "Make '{$dir}' writable. {$info['description']}. ".
                                   "Run: chmod -R 775 {$fullPath} or chown -R www-data:www-data {$fullPath} (adjust user/group as needed). ".
                                   "Current permissions: {$currentPerms}",
                    metadata: [
                        'directory' => $dir,
                        'full_path' => $fullPath,
                        'exists' => true,
                        'writable' => false,
                        'permissions' => $currentPerms,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('All critical directories have proper write permissions');
        }

        return $this->failed(
            sprintf('Found %d directory permission issue(s)', count($issues)),
            $issues
        );
    }

    private function getPermissions(string $path): string
    {
        $perms = fileperms($path);

        if ($perms === false) {
            return 'unknown';
        }

        return substr(sprintf('%o', $perms), -4);
    }
}
