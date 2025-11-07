<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\LicenseAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class LicenseAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new LicenseAnalyzer;
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

    public function test_passes_with_all_mit_licensed_packages(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package1',
                    'version' => '1.0.0',
                    'license' => ['MIT'],
                ],
                [
                    'name' => 'vendor/package2',
                    'version' => '2.0.0',
                    'license' => ['MIT'],
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_whitelisted_licenses(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/apache-package',
                    'version' => '1.0.0',
                    'license' => ['Apache-2.0'],
                ],
                [
                    'name' => 'vendor/bsd-package',
                    'version' => '1.0.0',
                    'license' => ['BSD-3-Clause'],
                ],
                [
                    'name' => 'vendor/isc-package',
                    'version' => '1.0.0',
                    'license' => ['ISC'],
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_gpl_licensed_package(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/gpl-package',
                    'version' => '1.0.0',
                    'license' => ['GPL-3.0'],
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('restrictive license', $result);
        $this->assertHasIssueContaining('GPL-3.0', $result);
    }

    public function test_fails_with_agpl_licensed_package(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/agpl-package',
                    'version' => '1.0.0',
                    'license' => ['AGPL-3.0'],
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('restrictive license', $result);
        $this->assertHasIssueContaining('AGPL-3.0', $result);
    }

    public function test_detects_package_without_license(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/no-license-package',
                    'version' => '1.0.0',
                    'license' => [],
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('no license information', $result);
    }

    public function test_flags_non_standard_license(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/custom-license-package',
                    'version' => '1.0.0',
                    'license' => ['Custom-Proprietary'],
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('non-standard license', $result);
        $this->assertHasIssueContaining('Custom-Proprietary', $result);
    }

    public function test_accepts_lgpl_license(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/lgpl-package',
                    'version' => '1.0.0',
                    'license' => ['LGPL-3.0'],
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_multiple_licenses(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/dual-license-package',
                    'version' => '1.0.0',
                    'license' => ['MIT', 'Apache-2.0'],
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because at least one license (MIT) is whitelisted
        $this->assertPassed($result);
    }

    public function test_handles_gpl_in_dev_dependencies(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/prod-package',
                    'version' => '1.0.0',
                    'license' => ['MIT'],
                ],
            ],
            'packages-dev' => [
                [
                    'name' => 'vendor/dev-gpl-package',
                    'version' => '1.0.0',
                    'license' => ['GPL-3.0'],
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should flag GPL in dev dependencies but with lower severity
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Dev package', $result);
    }

    public function test_detects_multiple_license_issues(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/gpl-package',
                    'version' => '1.0.0',
                    'license' => ['GPL-3.0'],
                ],
                [
                    'name' => 'vendor/no-license',
                    'version' => '1.0.0',
                    'license' => [],
                ],
                [
                    'name' => 'vendor/custom-license',
                    'version' => '1.0.0',
                    'license' => ['Proprietary'],
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(3, $result);
    }

    public function test_case_insensitive_license_matching(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/lowercase-mit',
                    'version' => '1.0.0',
                    'license' => ['mit'],
                ],
                [
                    'name' => 'vendor/uppercase-MIT',
                    'version' => '1.0.0',
                    'license' => ['MIT'],
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_packages_without_license_field(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package',
                    'version' => '1.0.0',
                    // No license field at all
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('no license information', $result);
    }
}
