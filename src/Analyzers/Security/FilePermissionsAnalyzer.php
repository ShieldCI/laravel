<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Validates file and directory permissions for security.
 *
 * Checks for:
 * - Directories with overly permissive permissions (> 775)
 * - Files with write permissions for others (world-writable)
 * - Sensitive files (.env, config files) with insecure permissions
 * - Executable permissions on non-executable files
 */
class FilePermissionsAnalyzer extends AbstractFileAnalyzer
{
    private array $criticalDirectories = [
        'app',
        'config',
        'database',
        'resources',
        'routes',
        'storage',
        'public',
        'bootstrap',
    ];

    private array $criticalFiles = [
        '.env',
        '.env.production',
        '.env.prod',
        'config/app.php',
        'config/database.php',
        'config/services.php',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'file-permissions',
            name: 'File Permissions Security Analyzer',
            description: 'Validates that project files and directories use secure permissions',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['permissions', 'file-security', 'security', 'access-control'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/file-permissions',
            timeToFix: 15
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check critical directories
        foreach ($this->criticalDirectories as $dir) {
            $path = $this->basePath.'/'.$dir;
            if (is_dir($path)) {
                $this->checkDirectoryPermissions($path, $issues);
            }
        }

        // Check critical files
        foreach ($this->criticalFiles as $file) {
            $path = $this->basePath.'/'.$file;
            if (file_exists($path)) {
                $this->checkFilePermissions($path, $issues);
            }
        }

        // Check storage directory specifically
        $this->checkStoragePermissions($issues);

        if (empty($issues)) {
            return $this->passed('File and directory permissions are secure');
        }

        return $this->failed(
            sprintf('Found %d file permission security issues', count($issues)),
            $issues
        );
    }

    /**
     * Check directory permissions.
     */
    private function checkDirectoryPermissions(string $path, array &$issues): void
    {
        $perms = fileperms($path);
        $octal = substr(sprintf('%o', $perms), -3);

        // Check if directory is world-writable (permissions like 777)
        if (($perms & 0x0002)) {
            $issues[] = $this->createIssue(
                message: sprintf('Directory "%s" is world-writable (permissions: %s)', basename($path), $octal),
                location: new Location(
                    $this->getRelativePath($path),
                    1
                ),
                severity: Severity::Critical,
                recommendation: 'Change permissions to 775 or 755: chmod 755 '.$this->getRelativePath($path),
                code: sprintf('Current permissions: %s', $octal)
            );
        }

        // Check if permissions are more permissive than 775
        $numericPerms = octdec($octal);
        if ($numericPerms > 775) {
            $issues[] = $this->createIssue(
                message: sprintf('Directory "%s" has overly permissive permissions (%s)', basename($path), $octal),
                location: new Location(
                    $this->getRelativePath($path),
                    1
                ),
                severity: Severity::High,
                recommendation: 'Change permissions to 775 or 755: chmod 755 '.$this->getRelativePath($path),
                code: sprintf('Current permissions: %s', $octal)
            );
        }
    }

    /**
     * Check file permissions.
     */
    private function checkFilePermissions(string $path, array &$issues): void
    {
        $perms = fileperms($path);
        $octal = substr(sprintf('%o', $perms), -3);

        // Check if file is world-writable
        if (($perms & 0x0002)) {
            $issues[] = $this->createIssue(
                message: sprintf('File "%s" is world-writable (permissions: %s)', basename($path), $octal),
                location: new Location(
                    $this->getRelativePath($path),
                    1
                ),
                severity: Severity::Critical,
                recommendation: 'Change permissions to 644: chmod 644 '.$this->getRelativePath($path),
                code: sprintf('Current permissions: %s', $octal)
            );
        }

        // Check if .env files have appropriate permissions
        if (str_contains($path, '.env')) {
            $numericPerms = octdec($octal);
            if ($numericPerms > 644) {
                $issues[] = $this->createIssue(
                    message: sprintf('.env file has insecure permissions (%s)', $octal),
                    location: new Location(
                        $this->getRelativePath($path),
                        1
                    ),
                    severity: Severity::Critical,
                    recommendation: 'Change permissions to 600 or 644: chmod 600 '.$this->getRelativePath($path),
                    code: sprintf('Current permissions: %s', $octal)
                );
            }
        }

        // Check for executable permissions on non-script files
        if (! str_ends_with($path, '.sh') && ! str_contains($path, 'artisan')) {
            if (($perms & 0x0040) || ($perms & 0x0008) || ($perms & 0x0001)) {
                $issues[] = $this->createIssue(
                    message: sprintf('Non-executable file "%s" has execute permissions (%s)', basename($path), $octal),
                    location: new Location(
                        $this->getRelativePath($path),
                        1
                    ),
                    severity: Severity::Medium,
                    recommendation: 'Remove execute permissions: chmod 644 '.$this->getRelativePath($path),
                    code: sprintf('Current permissions: %s', $octal)
                );
            }
        }
    }

    /**
     * Check storage directory permissions specifically.
     */
    private function checkStoragePermissions(array &$issues): void
    {
        $storagePath = $this->basePath.'/storage';

        if (! is_dir($storagePath)) {
            return;
        }

        // Storage directories should be writable by web server
        $subdirs = ['app', 'framework', 'logs'];

        foreach ($subdirs as $subdir) {
            $path = $storagePath.'/'.$subdir;

            if (! is_dir($path)) {
                continue;
            }

            $perms = fileperms($path);
            $octal = substr(sprintf('%o', $perms), -3);

            // Storage needs to be writable, but check for world-writable
            if (($perms & 0x0002)) {
                $issues[] = $this->createIssue(
                    message: sprintf('Storage directory "%s" is world-writable (permissions: %s)', $subdir, $octal),
                    location: new Location(
                        $this->getRelativePath($path),
                        1
                    ),
                    severity: Severity::High,
                    recommendation: 'Change permissions to 775: chmod 775 '.$this->getRelativePath($path),
                    code: sprintf('Current permissions: %s', $octal)
                );
            }
        }
    }
}
