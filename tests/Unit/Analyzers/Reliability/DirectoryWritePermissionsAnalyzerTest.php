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

        // Configure to check these specific directories
        config(['shieldci.writable_directories' => [
            $tempDir.'/storage',
            $tempDir.'/bootstrap/cache',
        ]]);

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
        config(['shieldci.writable_directories' => [
            $tempDir.'/storage',
            $tempDir.'/bootstrap/cache',
        ]]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not writable', $result);
    }

    public function test_fails_when_directory_not_writable(): void
    {
        // Create a directory with read-only permissions
        $tempDir = $this->createTempDirectory([
            'storage/.gitkeep' => '',
        ]);

        // Make directory read-only
        chmod($tempDir.'/storage', 0555);

        config(['shieldci.writable_directories' => [
            $tempDir.'/storage',
        ]]);

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

        config(['shieldci.writable_directories' => [
            $tempDir.'/storage',
            $tempDir.'/bootstrap/cache',
            $tempDir.'/custom/cache',
        ]]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('3 directory permission issue(s)', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertArrayHasKey('failed_directories', $issues[0]->metadata);
        $failedDirs = $issues[0]->metadata['failed_directories'];
        $this->assertIsArray($failedDirs);
        $this->assertCount(3, $failedDirs);
    }

    // =========================================================================
    // Config Handling Tests
    // =========================================================================

    public function test_uses_config_when_available(): void
    {
        $tempDir = $this->createTempDirectory([
            'custom/path/.gitkeep' => '',
        ]);

        config(['shieldci.writable_directories' => [
            $tempDir.'/custom/path',
        ]]);

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

        config(['shieldci.writable_directories' => []]);

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
        config(['shieldci.writable_directories' => 'not-an-array']);

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

        config(['shieldci.writable_directories' => [
            $tempDir.'/storage',
            null,
            123,
            '',
            ['nested' => 'array'],
        ]]);

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
        config(['shieldci.writable_directories' => [
            'storage',
            'bootstrap/cache',
            'custom/dir',
        ]]);

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
        config(['shieldci.writable_directories' => [
            $tempDir.'/storage', // Absolute
            'cache',              // Relative
        ]]);

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

        config(['shieldci.writable_directories' => [
            $tempDir.'/storage',
        ]]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('chmod -R 775', $recommendation);
        $this->assertStringContainsString('chown -R www-data:www-data', $recommendation);
        $this->assertStringContainsString('Unix/Linux', $recommendation);
        $this->assertStringContainsString('Windows', $recommendation);
    }

    public function test_includes_failed_directories_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([]);

        config(['shieldci.writable_directories' => [
            $tempDir.'/storage',
            $tempDir.'/bootstrap/cache',
        ]]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $this->assertArrayHasKey('failed_directories', $issues[0]->metadata);
        $this->assertArrayHasKey('count', $issues[0]->metadata);
        $this->assertSame(2, $issues[0]->metadata['count']);
    }

    public function test_formats_paths_relative_to_basepath(): void
    {
        $tempDir = $this->createTempDirectory([]);

        config(['shieldci.writable_directories' => [
            $tempDir.'/storage',
        ]]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        // Path should be relative, not absolute
        $failedDirs = $issues[0]->metadata['failed_directories'];
        $this->assertIsArray($failedDirs);
        $this->assertCount(1, $failedDirs);
        $this->assertSame('storage', $failedDirs[0]);
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

        config(['shieldci.writable_directories' => [
            $symlinkPath,
        ]]);

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

        config(['shieldci.writable_directories' => null]);

        $result = $analyzer->analyze();

        // Should not crash, even with empty basepath
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
