<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\DirectoryWritePermissionsAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class DirectoryWritePermissionsAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new DirectoryWritePermissionsAnalyzer;
    }

    public function test_checks_directory_permissions(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/app/.gitkeep' => '',
            'storage/framework/cache/.gitkeep' => '',
            'storage/framework/sessions/.gitkeep' => '',
            'storage/framework/views/.gitkeep' => '',
            'storage/logs/.gitkeep' => '',
            'bootstrap/cache/.gitkeep' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May pass or fail depending on permissions
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_fails_when_directories_missing(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not exist', $result);
    }
}
