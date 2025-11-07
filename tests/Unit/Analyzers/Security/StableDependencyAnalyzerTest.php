<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\StableDependencyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class StableDependencyAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new StableDependencyAnalyzer;
    }

    public function test_passes_when_no_composer_json_exists(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('No composer.json found', $result->getMessage());
    }

    public function test_passes_with_stable_configuration(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
                'laravel/framework' => '^10.0',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'laravel/framework',
                    'version' => '10.0.0',
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

        $this->assertPassed($result);
    }

    public function test_fails_when_minimum_stability_is_dev(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'dev',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('minimum-stability', $result);
        $this->assertHasIssueContaining('dev', $result);
    }

    public function test_fails_when_prefer_stable_is_missing(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('prefer-stable', $result);
    }

    public function test_fails_when_prefer_stable_is_false(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => false,
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('prefer-stable', $result);
    }

    public function test_detects_dev_version_constraints(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
                'vendor/package' => 'dev-master',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('dev-master', $result);
    }

    public function test_detects_alpha_version_constraints(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
                'vendor/package' => '2.0.0@alpha',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('@alpha', $result);
    }

    public function test_detects_beta_version_constraints(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
                'vendor/package' => '3.0@beta',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('@beta', $result);
    }

    public function test_detects_rc_version_constraints(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
                'vendor/package' => '4.0@RC',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('@RC', $result);
    }

    public function test_ignores_php_and_extensions(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '>=8.1',
                'ext-json' => '*',
                'ext-mbstring' => '*',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_dev_versions_in_composer_lock(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package',
                    'version' => 'dev-main',
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('unstable', $result);
    }

    public function test_detects_alpha_versions_in_composer_lock(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package',
                    'version' => '2.0.0-alpha.1',
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('unstable', $result);
    }

    public function test_detects_multiple_unstable_packages(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package1',
                    'version' => 'dev-master',
                ],
                [
                    'name' => 'vendor/package2',
                    'version' => '2.0.0-beta',
                ],
                [
                    'name' => 'vendor/package3',
                    'version' => '3.0.0-RC1',
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('3 unstable', $result);
    }

    public function test_passes_with_all_stable_versions(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
                'vendor/package' => '^2.0',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package',
                    'version' => '2.3.5',
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

        $this->assertPassed($result);
    }
}
