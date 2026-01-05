<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\EnvFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class EnvFileAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EnvFileAnalyzer;
    }

    // =========================================================================
    // Basic Functionality Tests
    // =========================================================================

    public function test_passes_when_env_file_exists(): void
    {
        $envContent = 'APP_ENV=local
APP_KEY=base64:test123
DB_CONNECTION=mysql';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('exists and is valid', $result->getMessage());
    }

    public function test_fails_when_env_file_missing(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not exist', $result);
    }

    public function test_fails_when_env_file_not_readable(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=local',
        ]);

        // Make file unreadable
        $envPath = $tempDir.'/.env';
        chmod($envPath, 0000);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions for cleanup
        chmod($envPath, 0644);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not readable', $result);
    }

    public function test_fails_when_env_file_empty(): void
    {
        $tempDir = $this->createTempDirectory([]);

        // Explicitly create an empty .env file
        $envPath = $tempDir.'/.env';
        file_put_contents($envPath, '');

        // Verify it's actually empty
        $this->assertEquals(0, filesize($envPath), '.env file should be empty');

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('empty', $result->getMessage());
    }

    // =========================================================================
    // Recommendation Tests
    // =========================================================================

    public function test_recommendation_when_env_example_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_ENV=local',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('cp .env.example .env', $recommendation);
        $this->assertStringContainsString('copy .env.example .env', $recommendation);
    }

    public function test_recommendation_when_env_example_missing(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('Create a .env file', $recommendation);
        $this->assertStringContainsString('.env.example', $recommendation);
    }

    // =========================================================================
    // Metadata Tests
    // =========================================================================

    public function test_metadata_includes_env_path(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $this->assertArrayHasKey('env_path', $issues[0]->metadata);
        $envPath = $issues[0]->metadata['env_path'];
        $this->assertIsString($envPath);
        $this->assertStringContainsString('.env', $envPath);
    }

    public function test_metadata_includes_env_example_exists_flag(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_ENV=local',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $this->assertArrayHasKey('env_example_exists', $issues[0]->metadata);
        $this->assertTrue($issues[0]->metadata['env_example_exists']);
    }

    public function test_metadata_when_env_example_missing(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $this->assertArrayHasKey('env_example_exists', $issues[0]->metadata);
        $this->assertFalse($issues[0]->metadata['env_example_exists']);
    }

    // =========================================================================
    // Symlink Tests
    // =========================================================================

    public function test_passes_with_valid_symlink(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.production' => 'APP_ENV=production
APP_KEY=base64:test123',
        ]);

        $symlinkPath = $tempDir.'/.env';
        $targetPath = $tempDir.'/.env.production';

        // Create symlink
        if (! @symlink($targetPath, $symlinkPath)) {
            $this->markTestSkipped('Cannot create symlinks on this system');
        }

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_broken_symlink(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $symlinkPath = $tempDir.'/.env';
        $targetPath = $tempDir.'/.env.nonexistent';

        // Create symlink to non-existent file
        if (! @symlink($targetPath, $symlinkPath)) {
            $this->markTestSkipped('Cannot create symlinks on this system');
        }

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('broken symlink', $result);

        $issues = $result->getIssues();
        $this->assertArrayHasKey('is_symlink', $issues[0]->metadata);
        $this->assertTrue($issues[0]->metadata['is_symlink']);
    }

    // =========================================================================
    // Edge Cases Tests
    // =========================================================================

    public function test_handles_empty_basepath(): void
    {
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath('');

        $result = $analyzer->analyze();

        // Should not crash with empty basepath
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
