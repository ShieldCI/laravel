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

    public function test_checks_directory_permissions(): void
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
}
