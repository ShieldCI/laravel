<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use Mockery;
use RuntimeException;
use ShieldCI\Analyzers\Security\StableDependencyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Support\Composer;
use ShieldCI\Tests\AnalyzerTestCase;

class StableDependencyAnalyzerTest extends AnalyzerTestCase
{
    private const DEFAULT_COMPOSER_OUTPUT = "Nothing to install or update\n";

    protected function createAnalyzer(?Composer $composer = null): AnalyzerInterface
    {
        return new StableDependencyAnalyzer($composer ?? $this->mockComposer());
    }

    /**
     * @return Composer&\Mockery\MockInterface
     */
    private function mockComposer(?string $output = null, ?\Throwable $throwable = null): Composer
    {
        /** @var Composer&\Mockery\MockInterface $composer */
        $composer = Mockery::mock(Composer::class);

        if ($throwable !== null) {
            /** @phpstan-ignore-next-line Mockery expectation chaining */
            $composer->shouldReceive('updateDryRun')->andThrow($throwable);

            return $composer;
        }

        $composer->shouldReceive('updateDryRun')
            ->andReturn($output ?? self::DEFAULT_COMPOSER_OUTPUT);

        return $composer;
    }

    public function test_skips_when_no_composer_json_exists(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
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

    public function test_flags_missing_minimum_stability_when_enforce_explicit_enabled(): void
    {
        // Enable the enforcement config
        config(['shieldci.analyzers.security.stable-dependencies.enforce_explicit_minimum_stability' => true]);

        $composerJson = json_encode([
            'name' => 'test/app',
            // Missing minimum-stability - using implicit default
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

        // Should be warning (Low severity), not failed
        $this->assertWarning($result);
        $this->assertHasIssueContaining('minimum-stability is not explicitly set', $result);
        $this->assertHasIssueContaining('implicit default', $result);
    }

    public function test_does_not_flag_missing_minimum_stability_by_default(): void
    {
        // Default behavior: don't flag implicit minimum-stability
        config(['shieldci.analyzers.security.stable-dependencies.enforce_explicit_minimum_stability' => false]);

        $composerJson = json_encode([
            'name' => 'test/app',
            // Missing minimum-stability - using implicit default
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

        // Should pass - implicit minimum-stability not flagged by default
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('3 unstable', $result);
    }

    public function test_detects_unstable_packages_in_packages_dev(): void
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
            'packages-dev' => [
                [
                    'name' => 'vendor/dev-package',
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('unstable', $result);
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

    public function test_flags_prefer_stable_dry_run_changes(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
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

        $composer = $this->mockComposer("Loading composer repositories\nUpgrading vendor/package (1.0.0 => 1.0.1)\n");

        $analyzer = $this->createAnalyzer($composer);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('prefer-stable', $result);
    }

    public function test_returns_error_when_composer_update_fails(): void
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
                    'version' => '1.0.0',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $composer = $this->mockComposer(null, new RuntimeException('Composer binary missing'));

        $analyzer = $this->createAnalyzer($composer);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('Unable to verify dependency stability', $result->getMessage());
    }

    public function test_handles_invalid_json_in_composer_json_gracefully(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{ invalid json }',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass gracefully (no valid data to check), not throw exception
        $this->assertPassed($result);
    }

    public function test_handles_invalid_json_in_composer_lock_gracefully(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => '{ invalid json in lock file }',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass (composer.json is valid, lock file error is ignored)
        $this->assertPassed($result);
    }

    public function test_detects_branch_alias_dev_version(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
                'vendor/package' => '2.0.x-dev',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('2.0.x-dev', $result);
    }

    public function test_detects_version_with_v_prefix_and_beta(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
                'vendor/package' => 'v1.0.0-beta1',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('v1.0.0-beta1', $result);
    }

    public function test_detects_unstable_versions_in_require_dev(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
            'require-dev' => [
                'vendor/dev-tool' => 'dev-master',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('dev-master', $result);
        $this->assertHasIssueContaining('require-dev', $result);
    }

    public function test_passes_with_only_stable_versions_in_require_dev(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
            'require-dev' => [
                'phpunit/phpunit' => '^10.0',
                'mockery/mockery' => '^1.5',
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

    public function test_detects_downgrading_in_composer_dry_run(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
                'vendor/package' => '^1.0',
            ],
        ]);

        $composerLock = json_encode([
            'packages' => [
                [
                    'name' => 'vendor/package',
                    'version' => '1.5.0',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $composer = $this->mockComposer("Loading composer repositories\nDowngrading vendor/package (1.5.0 => 1.0.0)\n");

        $analyzer = $this->createAnalyzer($composer);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('prefer-stable', $result);
    }

    public function test_handles_empty_require_section(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [],
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

    public function test_handles_non_string_version_values(): void
    {
        $composerJson = <<<'JSON'
        {
            "name": "test/app",
            "minimum-stability": "stable",
            "prefer-stable": true,
            "require": {
                "php": "^8.1",
                "vendor/package": 123
            }
        }
        JSON;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should not crash, just skip invalid entry
        $this->assertPassed($result);
    }

    public function test_handles_missing_packages_array_in_composer_lock(): void
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
            'content-hash' => 'abc123',
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass gracefully (lock file exists but has no packages array)
        $this->assertPassed($result);
    }

    public function test_finds_correct_line_numbers_for_packages(): void
    {
        // Create a multi-line composer.json with specific package on line 7
        $composerJson = <<<'JSON'
        {
            "name": "test/app",
            "minimum-stability": "stable",
            "prefer-stable": true,
            "require": {
                "php": "^8.1",
                "vendor/unstable-package": "dev-master"
            }
        }
        JSON;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();

        // Find the issue for vendor/unstable-package
        $found = false;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'vendor/unstable-package')) {
                // The package is on line 7 in the JSON above
                $this->assertEquals(7, $issue->location->line);
                $found = true;
                break;
            }
        }

        $this->assertTrue($found, 'Should find issue for vendor/unstable-package');
    }

    public function test_reports_accurate_line_numbers_for_composer_lock(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        // Create a composer.lock with unstable package on a specific line
        $composerLock = <<<'JSON'
        {
            "packages": [
                {
                    "name": "vendor/stable-package",
                    "version": "1.0.0"
                },
                {
                    "name": "vendor/unstable-package",
                    "version": "dev-master"
                }
            ]
        }
        JSON;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();

        // Should find the issue and report it on the line where the first unstable package is defined
        $found = false;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'unstable package versions')) {
                // The first unstable package "vendor/unstable-package" is on line 8
                $this->assertEquals(8, $issue->location->line);
                $found = true;
                break;
            }
        }

        $this->assertTrue($found, 'Should find unstable package issue with accurate line number');
    }

    /**
     * @dataProvider unstableVersionFormatsProvider
     */
    public function test_detects_all_composer_unstable_version_formats(string $version, string $description): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
                'vendor/package' => $version,
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining($version, $result);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function unstableVersionFormatsProvider(): array
    {
        return [
            'dash-alpha' => ['1.0.0-alpha', 'Standard alpha with dash'],
            'no-dash-alpha' => ['1.0.0alpha', 'Alpha without dash'],
            'v-prefix-alpha' => ['v1.0.0-alpha', 'Alpha with v prefix and dash'],
            'v-prefix-no-dash-alpha' => ['v1.0.0alpha', 'Alpha with v prefix no dash'],
            'alpha-dot-number' => ['1.0.0-alpha.1', 'Alpha with dot separator'],
            'alpha-number' => ['1.0.0-alpha1', 'Alpha with number suffix'],
            'alpha-no-dash-number' => ['1.0.0alpha1', 'Alpha no dash with number'],

            'dash-beta' => ['1.0.0-beta', 'Standard beta with dash'],
            'no-dash-beta' => ['1.0.0beta', 'Beta without dash'],
            'v-prefix-beta' => ['v1.0.0-beta', 'Beta with v prefix and dash'],
            'v-prefix-no-dash-beta' => ['v1.0.0beta', 'Beta with v prefix no dash'],
            'beta-dot-number' => ['1.0.0-beta.2', 'Beta with dot separator'],
            'beta-number' => ['1.0.0-beta2', 'Beta with number suffix'],
            'beta-no-dash-number' => ['1.0.0beta2', 'Beta no dash with number'],

            'dash-rc' => ['1.0.0-RC', 'Standard RC with dash'],
            'no-dash-rc' => ['1.0.0RC', 'RC without dash'],
            'v-prefix-rc' => ['v1.0.0-RC', 'RC with v prefix and dash'],
            'v-prefix-no-dash-rc' => ['v1.0.0RC', 'RC with v prefix no dash'],
            'rc-dot-number' => ['1.0.0-RC.1', 'RC with dot separator'],
            'rc-number' => ['1.0.0-RC1', 'RC with number suffix'],
            'rc-no-dash-number' => ['1.0.0RC1', 'RC no dash with number'],

            'dev-master' => ['dev-master', 'Dev master branch'],
            'dev-main' => ['dev-main', 'Dev main branch'],
            'version-dev' => ['2.0.x-dev', 'Dev version suffix'],
        ];
    }

    /**
     * @dataProvider stableVersionFormatsProvider
     */
    public function test_does_not_flag_stable_version_formats(string $version, string $description): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
                'vendor/package' => $version,
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass - no unstable versions detected
        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function stableVersionFormatsProvider(): array
    {
        return [
            'simple-version' => ['1.0.0', 'Simple semantic version'],
            'v-prefix-stable' => ['v1.0.0', 'Stable with v prefix'],
            'caret-constraint' => ['^1.0', 'Caret version constraint'],
            'tilde-constraint' => ['~1.0.0', 'Tilde version constraint'],
            'exact-constraint' => ['1.0.0', 'Exact version'],
            'wildcard' => ['1.0.*', 'Wildcard version'],
            'range' => ['>=1.0.0 <2.0.0', 'Version range'],
            'patch-suffix' => ['1.0.0-patch1', 'Patch suffix (not unstable flag)'],
            'build-metadata' => ['1.0.0+20240101', 'Build metadata'],
        ];
    }

    public function test_detects_composer_changes_with_english_output(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        // Mock Composer output with English text (current format)
        $composerOutput = <<<'OUTPUT'
        Loading composer repositories with package information
        Updating dependencies
        Lock file operations: 0 installs, 1 update, 0 removals
          - Upgrading vendor/package (1.0.0 => 2.0.0)
        Writing lock file
        OUTPUT;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $composerMock = $this->createMock(\ShieldCI\Support\Composer::class);
        $composerMock->method('updateDryRun')->willReturn($composerOutput);

        $analyzer = new \ShieldCI\Analyzers\Security\StableDependencyAnalyzer($composerMock);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('would modify installed packages', $result);
    }

    public function test_detects_composer_changes_with_arrow_notation(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        // Mock output using -> instead of => (alternative format)
        $composerOutput = <<<'OUTPUT'
        Package operations:
        vendor/package (1.0.0 -> 2.0.0)
        vendor/another (dev-master -> 1.0.0)
        OUTPUT;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $composerMock = $this->createMock(\ShieldCI\Support\Composer::class);
        $composerMock->method('updateDryRun')->willReturn($composerOutput);

        $analyzer = new \ShieldCI\Analyzers\Security\StableDependencyAnalyzer($composerMock);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('would modify installed packages', $result);
    }

    public function test_detects_composer_changes_locale_independent(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        // Mock output in hypothetical non-English format
        // The key is the structural pattern: "  - vendor/package (...)"
        $composerOutput = <<<'OUTPUT'
        Chargement des dépôts
        Mise à jour des dépendances
          - symfony/console (5.0.0 => 6.0.0)
          - doctrine/orm (2.0.0 => 3.0.0)
        OUTPUT;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $composerMock = $this->createMock(\ShieldCI\Support\Composer::class);
        $composerMock->method('updateDryRun')->willReturn($composerOutput);

        $analyzer = new \ShieldCI\Analyzers\Security\StableDependencyAnalyzer($composerMock);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should detect changes despite French text
        $this->assertWarning($result);
        $this->assertHasIssueContaining('would modify installed packages', $result);
    }

    public function test_no_false_positive_when_no_changes(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        // Mock output when no changes would be made
        $composerOutput = <<<'OUTPUT'
        Loading composer repositories with package information
        Updating dependencies
        Nothing to modify in lock file
        Writing lock file
        OUTPUT;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $composerMock = $this->createMock(\ShieldCI\Support\Composer::class);
        $composerMock->method('updateDryRun')->willReturn($composerOutput);

        $analyzer = new \ShieldCI\Analyzers\Security\StableDependencyAnalyzer($composerMock);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass when no changes detected
        $this->assertPassed($result);
    }

    public function test_handles_empty_composer_output(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $composerMock = $this->createMock(\ShieldCI\Support\Composer::class);
        $composerMock->method('updateDryRun')->willReturn('');

        $analyzer = new \ShieldCI\Analyzers\Security\StableDependencyAnalyzer($composerMock);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass when output is empty
        $this->assertPassed($result);
    }

    public function test_ignores_package_names_in_non_operation_lines(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
        ]);

        // Output that mentions packages but has no actual operations
        $composerOutput = <<<'OUTPUT'
        Analyzing vendor/package-a
        Analyzing vendor/package-b
        All packages are up to date
        OUTPUT;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $composerMock = $this->createMock(\ShieldCI\Support\Composer::class);
        $composerMock->method('updateDryRun')->willReturn($composerOutput);

        $analyzer = new \ShieldCI\Analyzers\Security\StableDependencyAnalyzer($composerMock);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should not flag this as operations
        $this->assertPassed($result);
    }

    public function test_require_dev_unstable_with_stable_minimum_is_low_severity(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
            'require-dev' => [
                'vendor/dev-tool' => 'dev-master',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should be warning (Low severity) not failed (Medium severity)
        $this->assertWarning($result);
        $this->assertHasIssueContaining('dev-master', $result);
        $this->assertHasIssueContaining('require-dev', $result);

        // Verify severity is Low
        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'dev-master')) {
                $this->assertEquals('low', $issue->severity->value);
                break;
            }
        }
    }

    public function test_require_dev_unstable_without_explicit_stability_is_low_severity(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            // No minimum-stability (defaults to 'stable')
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
            'require-dev' => [
                'vendor/dev-tool' => '1.0.0-beta',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should be warning (Low severity)
        $this->assertWarning($result);

        // Verify the beta package has Low severity
        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            if (str_contains($issue->message, '1.0.0-beta')) {
                $this->assertEquals('low', $issue->severity->value);
                break;
            }
        }
    }

    public function test_require_dev_unstable_with_dev_minimum_is_medium_severity(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'dev',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
            ],
            'require-dev' => [
                'vendor/dev-tool' => 'dev-master',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Verify the dev-master package has Medium severity (not Low)
        // because minimum-stability is 'dev' (not 'stable')
        $issues = $result->getIssues();
        $foundMediumSeverity = false;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'dev-master') && str_contains($issue->message, 'require-dev')) {
                $this->assertEquals('medium', $issue->severity->value);
                $foundMediumSeverity = true;
                break;
            }
        }
        $this->assertTrue($foundMediumSeverity, 'Should find dev-master issue with Medium severity');
    }

    public function test_require_unstable_always_medium_severity(): void
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

        // Should have at least one Medium severity issue
        $issues = $result->getIssues();
        $foundMediumSeverity = false;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'dev-master') && str_contains($issue->message, 'require')) {
                $this->assertEquals('medium', $issue->severity->value);
                $foundMediumSeverity = true;
                break;
            }
        }
        $this->assertTrue($foundMediumSeverity, 'Should find dev-master in require with Medium severity');
    }

    public function test_require_unstable_with_beta_minimum_is_medium_severity(): void
    {
        $composerJson = json_encode([
            'name' => 'test/app',
            'minimum-stability' => 'beta',
            'prefer-stable' => true,
            'require' => [
                'php' => '^8.1',
                'vendor/package' => '1.0.0-alpha',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Verify the alpha package in require has Medium severity
        // Packages in 'require' always get Medium severity regardless of minimum-stability
        $issues = $result->getIssues();
        $foundMediumSeverity = false;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, '1.0.0-alpha') && str_contains($issue->message, 'require ')) {
                $this->assertEquals('medium', $issue->severity->value);
                $foundMediumSeverity = true;
                break;
            }
        }
        $this->assertTrue($foundMediumSeverity, 'Should find alpha package in require with Medium severity');
    }
}
