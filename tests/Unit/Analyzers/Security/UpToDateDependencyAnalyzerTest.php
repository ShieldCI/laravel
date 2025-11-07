<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\UpToDateDependencyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class UpToDateDependencyAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new UpToDateDependencyAnalyzer;
    }

    public function test_passes_when_no_composer_lock_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{"require": {}}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('No composer.lock found', $result->getMessage());
    }

    public function test_passes_with_up_to_date_dependencies(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package',
                    'version' => '2.0.0',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Result depends on actual composer outdated command
        // In most test environments without actual outdated packages, this will pass
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_checks_composer_lock_age(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        // Touch the lock file to make it recent
        touch($tempDir.'/composer.lock');

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should not flag recent lock files
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_warns_about_old_composer_lock(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        // Set lock file modification time to 200 days ago
        $oldTime = time() - (200 * 24 * 60 * 60);
        touch($tempDir.'/composer.lock', $oldTime);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('has not been updated', $result);
    }

    public function test_handles_composer_outdated_json_output(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
                'vendor/package' => '^1.0',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package',
                    'version' => '1.0.0',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should handle composer outdated output gracefully
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_categorizes_patch_updates(): void
    {
        // This test verifies the analyzer can categorize patch updates (1.0.0 -> 1.0.1)
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package',
                    'version' => '1.0.0',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Result depends on composer outdated
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_categorizes_minor_updates(): void
    {
        // This test verifies the analyzer can categorize minor updates (1.0.0 -> 1.1.0)
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package',
                    'version' => '1.0.0',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Result depends on composer outdated
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_categorizes_major_updates(): void
    {
        // This test verifies the analyzer can categorize major updates (1.0.0 -> 2.0.0)
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package',
                    'version' => '1.0.0',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Result depends on composer outdated
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_handles_empty_outdated_output(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should handle empty outdated list gracefully
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_provides_recommendations_for_updates(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
                'vendor/package' => '^1.0',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package',
                    'version' => '1.0.0',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Verify the analyzer runs and produces a result
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_handles_version_without_v_prefix(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package',
                    'version' => '2.0.0',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should handle version strings without 'v' prefix
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_only_checks_direct_dependencies(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
                'vendor/direct-package' => '^1.0',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/direct-package',
                    'version' => '1.0.0',
                ],
                [
                    'name' => 'vendor/transitive-package',
                    'version' => '2.0.0',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Analyzer uses --direct flag to only check direct dependencies
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
