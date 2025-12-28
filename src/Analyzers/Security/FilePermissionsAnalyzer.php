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
 * - Group-writable permissions on sensitive files
 */
class FilePermissionsAnalyzer extends AbstractFileAnalyzer
{
    /** Mask to isolate permission bits (strip file type and special bits) */
    private const PERMISSION_MASK = 0x01FF; // 0777

    private const WORLD_WRITABLE = 0x0002;

    private const WORLD_READABLE = 0x0004;

    private const WORLD_EXECUTE = 0x0001;

    private const GROUP_WRITABLE = 0x0010;

    private const GROUP_READABLE = 0x0020;

    private const GROUP_EXECUTE = 0x0008;

    private const USER_EXECUTE = 0x0040;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'file-permissions',
            name: 'File Permissions Analyzer',
            description: 'Validates that project files and directories use secure permissions',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['permissions', 'file-security', 'security', 'access-control'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/file-permissions',
            timeToFix: 15
        );
    }

    public function shouldRun(): bool
    {
        // Check if at least one configured path exists
        foreach ($this->getPathsToCheck() as $relativePath => $config) {
            $path = $this->buildPath($relativePath);
            if (file_exists($path)) {
                return true;
            }
        }

        return false;
    }

    public function getSkipReason(): string
    {
        return 'No configured files or directories found to analyze';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        foreach ($this->getPathsToCheck() as $relativePath => $config) {
            $path = $this->buildPath($relativePath);

            if (! file_exists($path)) {
                continue;
            }

            $this->checkPath($path, $relativePath, $config, $issues);
        }

        $summary = empty($issues)
            ? 'File and directory permissions are secure'
            : sprintf('Found %d file permission security issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Get paths to check with their configuration.
     *
     * Format: ['path' => ['type' => 'file|directory', 'max' => 644, 'recommended' => 600, 'critical' => true, 'executable' => true]]
     *
     * @return array<string, array{type: string, max: int, recommended: int, critical?: bool, executable?: bool}>
     */
    private function getPathsToCheck(): array
    {
        /** @var array<string, array{type: string, max: int, recommended: int, critical?: bool, executable?: bool}> $defaults */
        $defaults = [
            // Critical directories (values in octal converted to decimal for comparison)
            'app' => ['type' => 'directory', 'max' => octdec('775'), 'recommended' => octdec('755')],
            'config' => ['type' => 'directory', 'max' => octdec('775'), 'recommended' => octdec('755')],
            'database' => ['type' => 'directory', 'max' => octdec('775'), 'recommended' => octdec('755')],
            'resources' => ['type' => 'directory', 'max' => octdec('775'), 'recommended' => octdec('755')],
            'routes' => ['type' => 'directory', 'max' => octdec('775'), 'recommended' => octdec('755')],
            'bootstrap' => ['type' => 'directory', 'max' => octdec('775'), 'recommended' => octdec('755')],
            'public' => ['type' => 'directory', 'max' => octdec('775'), 'recommended' => octdec('755')],

            // Storage directories (need to be writable)
            'storage' => ['type' => 'directory', 'max' => octdec('775'), 'recommended' => octdec('775')],
            'storage/app' => ['type' => 'directory', 'max' => octdec('775'), 'recommended' => octdec('775')],
            'storage/framework' => ['type' => 'directory', 'max' => octdec('775'), 'recommended' => octdec('775')],
            'storage/logs' => ['type' => 'directory', 'max' => octdec('775'), 'recommended' => octdec('775')],

            // Critical files - stricter permissions
            '.env' => ['type' => 'file', 'max' => octdec('600'), 'recommended' => octdec('600'), 'critical' => true],
            '.env.production' => ['type' => 'file', 'max' => octdec('600'), 'recommended' => octdec('600'), 'critical' => true],
            '.env.prod' => ['type' => 'file', 'max' => octdec('600'), 'recommended' => octdec('600'), 'critical' => true],
            'config/app.php' => ['type' => 'file', 'max' => octdec('644'), 'recommended' => octdec('644')],
            'config/database.php' => ['type' => 'file', 'max' => octdec('644'), 'recommended' => octdec('644')],
            'config/services.php' => ['type' => 'file', 'max' => octdec('644'), 'recommended' => octdec('644')],

            // Executable files
            'artisan' => ['type' => 'file', 'max' => octdec('775'), 'recommended' => octdec('755'), 'executable' => true],
        ];

        // Allow configuration override
        /** @var array<string, array{type: string, max: int, recommended: int, critical?: bool, executable?: bool}> $config */
        $config = function_exists('config') ? config('shieldci.file_permissions', []) : [];

        return array_merge($defaults, $config);
    }

    /**
     * Check a single path's permissions.
     *
     * @param  array{type?: string, max: int, recommended: int, critical?: bool, executable?: bool}  $config
     * @param  array<int, mixed>  $issues
     */
    private function checkPath(string $path, string $relativePath, array $config, array &$issues): void
    {
        $permissions = $this->getPermissions($path);
        if ($permissions === null) {
            return;
        }

        $type = $config['type'] ?? 'file';
        $max = $config['max'];
        $recommended = $config['recommended'];
        $isCritical = $config['critical'] ?? false;
        $isExecutable = $config['executable'] ?? false;

        // Check 1: World-writable (CRITICAL - always)
        if ($this->isWorldWritable($permissions['raw'])) {
            $issues[] = $this->createIssue(
                message: sprintf('%s "%s" is world-writable (permissions: %s)', ucfirst($type), $relativePath, $permissions['octal']),
                location: new Location($relativePath),
                severity: Severity::Critical,
                recommendation: sprintf(
                    'Change permissions to %s: chmod %s %s',
                    decoct($recommended),
                    decoct($recommended),
                    $relativePath
                ),
                metadata: [
                    'path' => $relativePath,
                    'permissions' => $permissions['octal'],
                    'numeric_permissions' => $permissions['numeric'],
                    'type' => $type,
                    'world_writable' => true,
                    'world_readable' => $this->isWorldReadable($permissions['raw']),
                    'group_writable' => $this->isGroupWritable($permissions['raw']),
                    'group_readable' => $this->isGroupReadable($permissions['raw']),
                ]
            );

            return; // Don't check further - world-writable is the main issue
        }

        // Check 2: World-readable on critical files (CRITICAL - for sensitive files)
        if ($isCritical && $this->isWorldReadable($permissions['raw'])) {
            $issues[] = $this->createIssue(
                message: sprintf('Critical file "%s" is world-readable (permissions: %s)', $relativePath, $permissions['octal']),
                location: new Location($relativePath),
                severity: Severity::Critical,
                recommendation: sprintf(
                    'Remove world read permissions: chmod %s %s',
                    decoct($recommended),
                    $relativePath
                ),
                code: null,
                metadata: [
                    'path' => $relativePath,
                    'permissions' => $permissions['octal'],
                    'numeric_permissions' => $permissions['numeric'],
                    'type' => $type,
                    'world_writable' => false,
                    'world_readable' => true,
                    'group_writable' => $this->isGroupWritable($permissions['raw']),
                    'group_readable' => $this->isGroupReadable($permissions['raw']),
                ]
            );

            return; // Don't check further
        }

        // Check 3: Exceeds maximum permissions (using bit mask comparison, not numeric magnitude)
        // Check if actual permissions have bits set that max permissions don't allow
        // Example: actual=0777, max=0755 → (0777 & ~0755) = 0022 (group/other write bits) → exceeds
        $exceededBits = $permissions['numeric'] & (~$max & self::PERMISSION_MASK);
        if ($exceededBits !== 0) {
            $severity = $isCritical ? Severity::Critical : Severity::High;

            $issues[] = $this->createIssue(
                message: sprintf('%s "%s" has overly permissive permissions (%s)', ucfirst($type), $relativePath, $permissions['octal']),
                location: new Location($relativePath),
                severity: $severity,
                recommendation: sprintf(
                    'Change permissions to %s or %s: chmod %s %s',
                    decoct($max),
                    decoct($recommended),
                    decoct($recommended),
                    $relativePath
                ),
                code: null,
                metadata: [
                    'path' => $relativePath,
                    'permissions' => $permissions['octal'],
                    'numeric_permissions' => $permissions['numeric'],
                    'type' => $type,
                    'max_allowed' => $max,
                    'recommended' => $recommended,
                    'exceeded_bits' => sprintf('%03o', $exceededBits),
                    'world_writable' => false,
                    'world_readable' => $this->isWorldReadable($permissions['raw']),
                    'group_writable' => $this->isGroupWritable($permissions['raw']),
                    'group_readable' => $this->isGroupReadable($permissions['raw']),
                ]
            );

            return; // Don't check further
        }

        // Check 4: Group-writable on critical files (Medium severity)
        if ($isCritical && $this->isGroupWritable($permissions['raw'])) {
            $issues[] = $this->createIssue(
                message: sprintf('Critical file "%s" is group-writable (permissions: %s)', $relativePath, $permissions['octal']),
                location: new Location($relativePath),
                severity: Severity::Medium,
                recommendation: sprintf(
                    'Remove group write permissions: chmod %s %s',
                    decoct($recommended),
                    $relativePath
                ),
                code: null,
                metadata: [
                    'path' => $relativePath,
                    'permissions' => $permissions['octal'],
                    'numeric_permissions' => $permissions['numeric'],
                    'type' => $type,
                    'world_writable' => false,
                    'world_readable' => $this->isWorldReadable($permissions['raw']),
                    'group_writable' => true,
                    'group_readable' => $this->isGroupReadable($permissions['raw']),
                ]
            );

            return; // Don't check executable if already flagged
        }

        // Check 5: Executable permissions on non-executable files (Medium severity)
        if ($type === 'file' && ! $isExecutable && $this->hasExecutePermissions($permissions['raw'])) {
            $issues[] = $this->createIssue(
                message: sprintf('Non-executable file "%s" has execute permissions (%s)', $relativePath, $permissions['octal']),
                location: new Location($relativePath),
                severity: Severity::Medium,
                recommendation: sprintf(
                    'Remove execute permissions: chmod %s %s',
                    decoct($recommended),
                    $relativePath
                ),
                code: null,
                metadata: [
                    'path' => $relativePath,
                    'permissions' => $permissions['octal'],
                    'numeric_permissions' => $permissions['numeric'],
                    'type' => $type,
                    'has_execute' => true,
                    'should_be_executable' => false,
                    'world_writable' => false,
                    'world_readable' => $this->isWorldReadable($permissions['raw']),
                    'group_writable' => $this->isGroupWritable($permissions['raw']),
                    'group_readable' => $this->isGroupReadable($permissions['raw']),
                ]
            );
        }
    }

    /**
     * Get permissions for a path.
     *
     * @return array{raw: int, octal: string, numeric: int}|null
     */
    private function getPermissions(string $path): ?array
    {
        $perms = @fileperms($path);
        if ($perms === false) {
            return null;
        }

        // Isolate permission bits only (strip file type and special bits)
        $permissionBits = $perms & self::PERMISSION_MASK;

        $octal = sprintf('%03o', $permissionBits);

        return [
            'raw' => $permissionBits,
            'octal' => $octal,
            'numeric' => $permissionBits,
        ];
    }

    /**
     * Check if path is world-writable.
     */
    private function isWorldWritable(int $perms): bool
    {
        return (bool) ($perms & self::WORLD_WRITABLE);
    }

    /**
     * Check if path is world-readable.
     */
    private function isWorldReadable(int $perms): bool
    {
        return (bool) ($perms & self::WORLD_READABLE);
    }

    /**
     * Check if path is group-writable.
     */
    private function isGroupWritable(int $perms): bool
    {
        return (bool) ($perms & self::GROUP_WRITABLE);
    }

    /**
     * Check if path is group-readable.
     */
    private function isGroupReadable(int $perms): bool
    {
        return (bool) ($perms & self::GROUP_READABLE);
    }

    /**
     * Check if path has any execute permissions.
     */
    private function hasExecutePermissions(int $perms): bool
    {
        $permBits = $perms & self::PERMISSION_MASK;

        return (bool) ($permBits & (self::USER_EXECUTE | self::GROUP_EXECUTE | self::WORLD_EXECUTE));
    }
}
