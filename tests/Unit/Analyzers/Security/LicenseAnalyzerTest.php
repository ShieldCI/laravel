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

        // shouldRun() returns false, so result is skipped
        $this->assertSkipped($result);
        $this->assertStringContainsString('No composer.lock file found', $result->getMessage());
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

        // Missing license is Medium severity → Warning
        $this->assertWarning($result);
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

        // Non-standard license is Low severity → Warning
        $this->assertWarning($result);
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

        // GPL in dev dependencies is Low severity → Warning
        $this->assertWarning($result);
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

        // Missing license is Medium severity → Warning
        $this->assertWarning($result);
        $this->assertHasIssueContaining('no license information', $result);
    }

    public function test_handles_invalid_json_in_composer_lock(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.lock' => 'invalid json {{{',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass gracefully (not crash)
        $this->assertPassed($result);
    }

    public function test_handles_composer_lock_without_packages_key(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.lock' => json_encode(['some' => 'data']),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_malformed_package_entries(): void
    {
        $composerLock = json_encode([
            'packages' => [
                'not-an-array',  // Invalid entry
                ['name' => 'vendor/valid', 'license' => ['MIT']],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass - only valid package matters
        $this->assertPassed($result);
    }

    public function test_handles_dual_license_with_gpl_and_safe_license(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/dual-mit-gpl',
                    'version' => '1.0.0',
                    'license' => ['MIT', 'GPL-3.0'],
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

        // Should pass because MIT is whitelisted (dual-licensing allows choice)
        $this->assertPassed($result);
    }

    public function test_ignores_dev_dependencies_without_licenses(): void
    {
        $composerLock = json_encode([
            'packages' => [
                ['name' => 'vendor/prod', 'license' => ['MIT']],
            ],
            'packages-dev' => [
                ['name' => 'vendor/dev-no-license', 'license' => []],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass - dev without license is ignored
        $this->assertPassed($result);
    }

    public function test_detects_all_gpl_variants(): void
    {
        $gplVariants = [
            'GPL-2.0',
            'GPL-2.0-only',
            'GPL-2.0-or-later',
            'GPL-3.0-only',
            'GPL-3.0-or-later',
            'AGPL-3.0-only',
            'AGPL-3.0-or-later',
        ];

        foreach ($gplVariants as $license) {
            $composerLock = json_encode([
                'packages' => [
                    ['name' => 'vendor/gpl', 'version' => '1.0.0', 'license' => [$license]],
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
        }
    }

    public function test_accepts_all_whitelisted_licenses(): void
    {
        $whitelistedLicenses = [
            'Apache2',
            'BSD-2-Clause',
            'LGPL-2.1-only',
            'LGPL-2.1',
            'LGPL-2.1-or-later',
            'LGPL-3.0-only',
            'LGPL-3.0-or-later',
            'CC0-1.0',
            'Unlicense',
            'WTFPL',
        ];

        foreach ($whitelistedLicenses as $license) {
            $composerLock = json_encode([
                'packages' => [
                    ['name' => 'vendor/package', 'version' => '1.0.0', 'license' => [$license]],
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
    }

    public function test_handles_license_as_string(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/string-license',
                    'version' => '1.0.0',
                    'license' => 'MIT',  // String, not array
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

        // Should pass - license string should be normalized to array
        $this->assertPassed($result);
    }

    public function test_handles_gpl_license_as_string(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/gpl-string',
                    'version' => '1.0.0',
                    'license' => 'GPL-3.0',  // String, not array
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

        // Should fail - GPL license (even as string) should be detected
        $this->assertFailed($result);
        $this->assertHasIssueContaining('restrictive license', $result);
    }

    public function test_non_standard_license_has_low_severity(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/proprietary',
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

        // Should show as warning (low severity), not failed
        $this->assertWarning($result);
        $this->assertHasIssueContaining('non-standard license', $result);
    }

    public function test_handles_conjunctive_licenses_with_safe_licenses(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/dual-safe',
                    'version' => '1.0.0',
                    'license' => '(MIT and Apache-2.0)',
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

        // Should pass because both MIT and Apache-2.0 are whitelisted
        $this->assertPassed($result);
    }

    public function test_fails_conjunctive_licenses_with_gpl(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/mixed-license',
                    'version' => '1.0.0',
                    'license' => '(MIT and GPL-3.0)',
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

        // Should fail because GPL-3.0 is restrictive even though MIT is safe
        $this->assertFailed($result);
        $this->assertHasIssueContaining('conjunctive', $result);
        $this->assertHasIssueContaining('ALL apply', $result);
    }

    public function test_passes_disjunctive_licenses_with_gpl_and_safe_option(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/choice-license',
                    'version' => '1.0.0',
                    'license' => 'MIT or GPL-3.0',
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

        // Should pass because MIT is an option (disjunctive/OR)
        $this->assertPassed($result);
    }

    public function test_detects_conjunctive_licenses_without_parentheses(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/and-license',
                    'version' => '1.0.0',
                    'license' => 'MIT and GPL-3.0',
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

        // Should fail - conjunctive license with GPL
        $this->assertFailed($result);
        $this->assertHasIssueContaining('GPL', $result);
    }

    public function test_metadata_includes_license_type_for_conjunctive(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/conjunctive-pkg',
                    'version' => '1.0.0',
                    'license' => '(BSD-3-Clause and GPL-3.0)',
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
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('conjunctive', $issues[0]->metadata['license_type']);
    }

    public function test_metadata_includes_license_type_for_disjunctive(): void
    {
        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/disjunctive-pkg',
                    'version' => '1.0.0',
                    'license' => ['MIT', 'GPL-3.0'],
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

        // Should pass because MIT is available (disjunctive)
        $this->assertPassed($result);
    }
}
