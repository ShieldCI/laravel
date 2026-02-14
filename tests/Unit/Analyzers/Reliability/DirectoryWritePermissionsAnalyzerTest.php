<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Filesystem\Filesystem;
use ShieldCI\Analyzers\Reliability\DirectoryWritePermissionsAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class DirectoryWritePermissionsAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new DirectoryWritePermissionsAnalyzer(new Filesystem);
    }

    // =========================================================================
    // Basic Functionality Tests
    // =========================================================================

    public function test_passes_when_all_directories_writable(): void
    {
        // Create writable directories
        $tempDir = $this->createTempDirectory([
            'storage/app/.gitkeep' => '',
            'storage/framework/cache/.gitkeep' => '',
            'storage/framework/sessions/.gitkeep' => '',
            'storage/framework/views/.gitkeep' => '',
            'storage/logs/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
        ]);

        // Configure to check these specific directories (disable symlink check for this test)
        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass since directories exist and are writable
        $this->assertPassed($result);
        $this->assertStringContainsString('proper write permissions', $result->getMessage());
    }

    public function test_fails_when_directories_missing(): void
    {
        $tempDir = $this->createTempDirectory([]);

        // Configure to check non-existent directories
        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not found', $result);
    }

    public function test_fails_when_directory_not_writable(): void
    {
        // Create a directory with read-only permissions
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
        ]);

        // Make directory read-only
        chmod($tempDir.'/storage', 0555);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions for cleanup
        chmod($tempDir.'/storage', 0755);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not writable', $result);
    }

    public function test_reports_multiple_failed_directories(): void
    {
        $tempDir = $this->createTempDirectory([]);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
                $tempDir.'/custom/cache',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('3 filesystem issue(s)', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertArrayHasKey('missing_directories', $issues[0]->metadata);
        $this->assertArrayHasKey('missing_count', $issues[0]->metadata);
        $missingDirs = $issues[0]->metadata['missing_directories'];
        $this->assertIsArray($missingDirs);
        $this->assertCount(3, $missingDirs);
        $this->assertSame(3, $issues[0]->metadata['missing_count']);
    }

    // =========================================================================
    // Config Handling Tests
    // =========================================================================

    public function test_uses_config_when_available(): void
    {
        $tempDir = $this->createTempDirectory([
            'custom/path/.gitkeep' => '',
        ]);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/custom/path',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_falls_back_to_defaults_when_config_empty(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
        ]);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should use default directories and pass
        $this->assertPassed($result);
    }

    public function test_handles_invalid_config_gracefully(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
        ]);

        // Set invalid config (not an array)
        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => 'not-an-array',
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fall back to defaults and pass
        $this->assertPassed($result);
    }

    public function test_filters_out_non_string_directories_from_config(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
        ]);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                null,
                123,
                '',
                ['nested' => 'array'],
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should only check the valid string directory
        $this->assertPassed($result);
    }

    public function test_handles_relative_paths_from_config(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
            'custom/dir/.gitkeep' => '',
        ]);

        // Use relative paths like in the real config
        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                'storage',
                'bootstrap/cache',
                'custom/dir',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should convert relative paths to absolute and check them
        $this->assertPassed($result);
    }

    public function test_handles_mixed_absolute_and_relative_paths(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
            'cache/.gitkeep' => '',
        ]);

        // Mix of absolute and relative paths
        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage', // Absolute
                'cache',              // Relative
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should handle both types correctly
        $this->assertPassed($result);
    }

    // =========================================================================
    // Recommendation & Metadata Tests
    // =========================================================================

    public function test_includes_fix_commands_in_recommendation(): void
    {
        $tempDir = $this->createTempDirectory([]);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $recommendation = $issues[0]->recommendation;
        // Missing directories should get mkdir command
        $this->assertStringContainsString('mkdir -p', $recommendation);
        $this->assertStringContainsString('storage', $recommendation);
    }

    public function test_includes_failed_directories_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([]);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $this->assertArrayHasKey('missing_directories', $issues[0]->metadata);
        $this->assertArrayHasKey('non_writable_directories', $issues[0]->metadata);
        $this->assertArrayHasKey('missing_count', $issues[0]->metadata);
        $this->assertArrayHasKey('non_writable_count', $issues[0]->metadata);
        $this->assertSame(2, $issues[0]->metadata['missing_count']);
    }

    public function test_formats_paths_relative_to_basepath(): void
    {
        $tempDir = $this->createTempDirectory([]);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        // Path should be relative, not absolute
        $missingDirs = $issues[0]->metadata['missing_directories'];
        $this->assertIsArray($missingDirs);
        $this->assertCount(1, $missingDirs);
        $this->assertSame('storage', $missingDirs[0]);
    }

    // =========================================================================
    // Split Diagnostics Tests
    // =========================================================================

    public function test_distinguishes_missing_from_non_writable(): void
    {
        // Create one directory that exists but is not writable
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
        ]);

        // Make storage read-only
        chmod($tempDir.'/storage', 0555);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',        // exists but not writable
                $tempDir.'/bootstrap/cache', // missing
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions
        chmod($tempDir.'/storage', 0755);

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        // Should have both types
        $missingDirs = $issues[0]->metadata['missing_directories'];
        $nonWritableDirs = $issues[0]->metadata['non_writable_directories'];
        $this->assertIsArray($missingDirs);
        $this->assertIsArray($nonWritableDirs);
        $this->assertCount(1, $missingDirs);
        $this->assertCount(1, $nonWritableDirs);
        $this->assertSame(1, $issues[0]->metadata['missing_count']);
        $this->assertSame(1, $issues[0]->metadata['non_writable_count']);

        // Check correct directories are in correct categories
        $this->assertContains('bootstrap/cache', $missingDirs);
        $this->assertContains('storage', $nonWritableDirs);
    }

    public function test_provides_mkdir_command_for_missing_directories(): void
    {
        $tempDir = $this->createTempDirectory([]);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('Missing directories:', $recommendation);
        $this->assertStringContainsString('mkdir -p storage', $recommendation);
        $this->assertStringNotContainsString('chmod', $recommendation);
    }

    public function test_provides_chmod_command_for_non_writable_directories(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
        ]);

        // Make read-only
        chmod($tempDir.'/storage', 0555);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions
        chmod($tempDir.'/storage', 0755);

        $this->assertFailed($result);
        $issues = $result->getIssues();

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('Non-writable directories:', $recommendation);
        $this->assertStringContainsString('chmod -R 775 storage', $recommendation);
        $this->assertStringNotContainsString('mkdir', $recommendation);
    }

    public function test_provides_both_commands_when_both_types_present(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
        ]);

        chmod($tempDir.'/storage', 0555);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/cache',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        chmod($tempDir.'/storage', 0755);

        $this->assertFailed($result);
        $issues = $result->getIssues();

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('Missing directories:', $recommendation);
        $this->assertStringContainsString('mkdir -p cache', $recommendation);
        $this->assertStringContainsString('Non-writable directories:', $recommendation);
        $this->assertStringContainsString('chmod -R 775 storage', $recommendation);
    }

    public function test_message_reflects_failure_types(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
        ]);

        chmod($tempDir.'/storage', 0555);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/cache',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        chmod($tempDir.'/storage', 0755);

        $this->assertFailed($result);
        // Message should indicate both types
        $this->assertStringContainsString('1 missing and 1 non-writable', $result->getIssues()[0]->message);
    }

    // =========================================================================
    // Edge Cases Tests
    // =========================================================================

    public function test_handles_symlinked_directories(): void
    {
        $tempDir = $this->createTempDirectory([
            'real-storage/.gitkeep' => '',
        ]);

        $symlinkPath = $tempDir.'/storage-link';

        // Create symlink
        if (! @symlink($tempDir.'/real-storage', $symlinkPath)) {
            $this->markTestSkipped('Cannot create symlinks on this system');
        }

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $symlinkPath,
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should handle symlinks correctly
        $this->assertPassed($result);
    }

    public function test_handles_empty_basepath(): void
    {
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath('');

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => null,
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $result = $analyzer->analyze();

        // Should not crash, even with empty basepath
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    // =========================================================================
    // Symlink Verification Tests
    // =========================================================================

    public function test_passes_when_symlinks_exist_and_valid(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/app/public/.gitkeep' => '',
            'storage/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
        ]);

        // Create the public directory and symlink
        mkdir($tempDir.'/public', 0755, true);
        if (! @symlink($tempDir.'/storage/app/public', $tempDir.'/public/storage')) {
            $this->markTestSkipped('Cannot create symlinks on this system');
        }

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
            ],
            'filesystems.links' => [
                $tempDir.'/public/storage' => $tempDir.'/storage/app/public',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => true,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('symlinks are valid', $result->getMessage());
    }

    public function test_fails_when_symlink_missing(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/app/public/.gitkeep' => '',
            'storage/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
            'public/.gitkeep' => '',
        ]);

        // Don't create the symlink

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
            ],
            'filesystems.links' => [
                $tempDir.'/public/storage' => $tempDir.'/storage/app/public',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => true,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('symlink', $result);

        $issues = $result->getIssues();
        // Find the symlink issue
        $symlinkIssue = null;
        foreach ($issues as $issue) {
            if (isset($issue->metadata['broken_symlinks'])) {
                $symlinkIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($symlinkIssue);
        $this->assertEquals('missing', $symlinkIssue->metadata['broken_symlinks'][0]['reason']);
    }

    public function test_fails_when_symlink_target_missing(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
        ]);

        // Create public directory and a broken symlink (target doesn't exist)
        mkdir($tempDir.'/public', 0755, true);
        if (! @symlink($tempDir.'/storage/app/public', $tempDir.'/public/storage')) {
            $this->markTestSkipped('Cannot create symlinks on this system');
        }

        // Note: storage/app/public doesn't exist, so symlink is broken

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
            ],
            'filesystems.links' => [
                $tempDir.'/public/storage' => $tempDir.'/storage/app/public',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => true,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $symlinkIssue = null;
        foreach ($issues as $issue) {
            if (isset($issue->metadata['broken_symlinks'])) {
                $symlinkIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($symlinkIssue);
        $this->assertEquals('broken', $symlinkIssue->metadata['broken_symlinks'][0]['reason']);
    }

    public function test_fails_when_symlink_target_not_directory(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/app/public' => 'this is a file, not a directory',
            'storage/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
        ]);

        // Create public directory and symlink to a file
        mkdir($tempDir.'/public', 0755, true);
        if (! @symlink($tempDir.'/storage/app/public', $tempDir.'/public/storage')) {
            $this->markTestSkipped('Cannot create symlinks on this system');
        }

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
            ],
            'filesystems.links' => [
                $tempDir.'/public/storage' => $tempDir.'/storage/app/public',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => true,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $symlinkIssue = null;
        foreach ($issues as $issue) {
            if (isset($issue->metadata['broken_symlinks'])) {
                $symlinkIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($symlinkIssue);
        $this->assertEquals('not_directory', $symlinkIssue->metadata['broken_symlinks'][0]['reason']);
    }

    public function test_uses_default_storage_symlink(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
            'public/.gitkeep' => '',
        ]);

        // No symlink created, and no filesystems.links config
        // Should use default public/storage -> storage/app/public

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
            ],
            'filesystems.links' => null,
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => true,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because default symlink doesn't exist
        $this->assertFailed($result);
    }

    public function test_uses_custom_symlinks_from_config(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/app/public/.gitkeep' => '',
            'storage/app/uploads/.gitkeep' => '',
            'storage/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
        ]);

        // Create public directory with both symlinks
        mkdir($tempDir.'/public', 0755, true);
        if (! @symlink($tempDir.'/storage/app/public', $tempDir.'/public/storage')) {
            $this->markTestSkipped('Cannot create symlinks on this system');
        }
        if (! @symlink($tempDir.'/storage/app/uploads', $tempDir.'/public/uploads')) {
            $this->markTestSkipped('Cannot create symlinks on this system');
        }

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
            ],
            'filesystems.links' => [
                $tempDir.'/public/storage' => $tempDir.'/storage/app/public',
                $tempDir.'/public/uploads' => $tempDir.'/storage/app/uploads',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => true,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_symlink_check_can_be_disabled(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
            'public/.gitkeep' => '',
        ]);

        // No symlink created, but check is disabled

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
            ],
            'filesystems.links' => [
                $tempDir.'/public/storage' => $tempDir.'/storage/app/public',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => false,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass because symlink check is disabled
        $this->assertPassed($result);
    }

    public function test_symlink_recommendation_includes_artisan_command(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
            'public/.gitkeep' => '',
        ]);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
            ],
            'filesystems.links' => [
                $tempDir.'/public/storage' => $tempDir.'/storage/app/public',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => true,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $symlinkIssue = null;
        foreach ($issues as $issue) {
            if (isset($issue->metadata['broken_symlinks'])) {
                $symlinkIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($symlinkIssue);
        $this->assertStringContainsString('php artisan storage:link', $symlinkIssue->recommendation);
    }

    public function test_symlink_metadata_includes_count(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
            'public/.gitkeep' => '',
        ]);

        config([
            'shieldci.analyzers.reliability.directory-write-permissions.writable_directories' => [
                $tempDir.'/storage',
                $tempDir.'/bootstrap/cache',
            ],
            'filesystems.links' => [
                $tempDir.'/public/storage' => $tempDir.'/storage/app/public',
                $tempDir.'/public/uploads' => $tempDir.'/storage/app/uploads',
            ],
            'shieldci.analyzers.reliability.directory-write-permissions.check_symlinks' => true,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $symlinkIssue = null;
        foreach ($issues as $issue) {
            if (isset($issue->metadata['broken_symlink_count'])) {
                $symlinkIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($symlinkIssue);
        $this->assertEquals(2, $symlinkIssue->metadata['broken_symlink_count']);
    }
}
