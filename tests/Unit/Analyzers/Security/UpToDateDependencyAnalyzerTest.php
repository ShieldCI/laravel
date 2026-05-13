<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use Mockery;
use Mockery\MockInterface;
use ShieldCI\Analyzers\Security\UpToDateDependencyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Support\Composer;
use ShieldCI\Tests\AnalyzerTestCase;

class UpToDateDependencyAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, array<string, string>>|null  $composerJsonData
     */
    protected function createAnalyzer(
        ?string $composerLockPath = '/path/to/composer.lock',
        ?string $allDepsOutput = null,
        ?string $prodDepsOutput = null,  // DEPRECATED: No longer used (optimization)
        ?string $composerJsonPath = '/path/to/composer.json',
        ?array $composerJsonData = null,
        ?\Throwable $installDryRunException = null,
        bool $devPackagesInstalled = true,
    ): AnalyzerInterface {
        /** @var Composer&MockInterface $composer */
        $composer = Mockery::mock(Composer::class);

        // Mock getLockFile
        $composer->shouldReceive('getLockFile')
            ->andReturn($composerLockPath);

        $composer->shouldReceive('getJsonFile')
            ->andReturn($composerJsonPath);

        $composer->shouldReceive('areDevPackagesInstalled')
            ->andReturn($devPackagesInstalled);

        // Create temporary composer.json with require-dev if data provided
        if ($composerJsonPath !== null && $composerJsonData !== null) {
            file_put_contents($composerJsonPath, json_encode($composerJsonData));
            // Register cleanup
            register_shutdown_function(fn () => @unlink($composerJsonPath));
        }

        // Mock installDryRun - now called only ONCE per analysis (performance optimization!)
        if ($installDryRunException !== null) {
            /** @phpstan-ignore-next-line Mockery expectation chaining */
            $composer->shouldReceive('installDryRun')->andThrow($installDryRunException);
        } elseif ($allDepsOutput !== null) {
            /** @phpstan-ignore-next-line Mockery's times() is not recognized by PHPStan */
            $composer->shouldReceive('installDryRun')
                ->once()
                ->andReturn($allDepsOutput);
        }

        return new UpToDateDependencyAnalyzer($composer);
    }

    public function test_skips_when_no_composer_lock_exists(): void
    {
        $analyzer = $this->createAnalyzer(composerLockPath: null, composerJsonPath: null);

        $this->assertFalse($analyzer->shouldRun());

        $this->assertStringContainsString('composer.json', $analyzer->getSkipReason());
    }

    public function test_warns_when_composer_lock_missing_but_json_exists(): void
    {
        $analyzer = $this->createAnalyzer(
            composerLockPath: null,
            composerJsonPath: '/path/to/composer.json'
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('composer.lock file is missing', $result);
    }

    public function test_passes_when_all_dependencies_up_to_date_composer_1(): void
    {
        $output = "Nothing to install or update\n";

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $output,
            prodDepsOutput: $output
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('up-to-date', $result->getMessage());
    }

    public function test_passes_when_all_dependencies_up_to_date_composer_2(): void
    {
        $output = "Nothing to install, update or remove\n";

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $output,
            prodDepsOutput: $output
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('up-to-date', $result->getMessage());
    }

    public function test_fails_when_both_production_and_dev_dependencies_need_updates(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies (including require-dev) from lock file
Package operations: 0 installs, 5 updates, 0 removals
  - Updating vendor/package1 (v1.0.0 => v1.0.1)
  - Updating vendor/package2 (v2.0.0 => v2.1.0)
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_both_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/package1' => '^1.0'],
                'require-dev' => ['vendor/package2' => '^2.0'],
            ]
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Production and development dependencies are not up-to-date', $result);

        // Check metadata contains scope information
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('production and dev', $issues[0]->metadata['scope'] ?? '');
    }

    public function test_fails_when_only_production_dependencies_need_updates(): void
    {
        // This tests when ONLY production dependencies have updates (dev is up-to-date)
        // Both outputs are IDENTICAL because only production package needs updating
        // (no dev-specific packages to update)
        $output = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies (including require-dev) from lock file
Package operations: 0 installs, 1 update, 0 removals
  - Updating vendor/prod-package (v1.0.0 => v1.0.1)
OUTPUT;

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $output,
            prodDepsOutput: $output
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Production dependencies are not up-to-date', $result);

        // Check metadata contains scope information
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('production', $issues[0]->metadata['scope'] ?? '');
        $this->assertEquals(Severity::Medium, $issues[0]->severity);
    }

    public function test_fails_with_low_severity_when_only_dev_dependencies_need_updates(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies (including require-dev) from lock file
Package operations: 0 installs, 2 updates, 0 removals
  - Updating phpunit/phpunit (v9.0.0 => v9.1.0)
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_dev_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/prod-pkg' => '^1.0'],
                'require-dev' => ['phpunit/phpunit' => '^9.0'],
            ]
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Development dependencies are not up-to-date', $result);

        // Dev dependencies should be low severity
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(Severity::Low, $issues[0]->severity);
        $this->assertEquals('dev', $issues[0]->metadata['scope'] ?? '');
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('up-to-date-dependencies', $metadata->id);
        $this->assertEquals('Up-to-Date Dependencies Analyzer', $metadata->name);
        $this->assertEquals(Category::Security, $metadata->category);
        $this->assertEquals(Severity::Medium, $metadata->severity);
        $this->assertContains('dependencies', $metadata->tags);
        $this->assertContains('security-patches', $metadata->tags);
    }

    public function test_returns_error_when_composer_command_fails(): void
    {
        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            composerJsonPath: '/path/to/composer.json',
            installDryRunException: new \RuntimeException('Composer binary missing')
        );

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('Unable to check dependency status', $result->getMessage());
    }

    public function test_provides_helpful_recommendations(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Package operations: 0 installs, 5 updates, 0 removals
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_dev_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/prod-pkg' => '^1.0'],
                'require-dev' => ['phpunit/phpunit' => '^9.0'],
            ]
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        // Verify recommendation contains actionable advice
        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('composer update', $recommendation);
    }

    public function test_handles_non_string_composer_output(): void
    {
        /** @var Composer&MockInterface $composer */
        $composer = Mockery::mock(Composer::class);

        $composer->shouldReceive('getLockFile')
            ->andReturn('/path/to/composer.lock');

        $composer->shouldReceive('getJsonFile')
            ->andReturn('/path/to/composer.json');

        $composer->shouldReceive('areDevPackagesInstalled')
            ->andReturn(true);

        // Return non-string values
        $composer->shouldReceive('installDryRun')
            ->andReturn(null);

        $analyzer = new UpToDateDependencyAnalyzer($composer);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('Unable to check dependency status', $result->getMessage());
    }

    public function test_detects_updates_with_different_composer_2_output_format(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Updating dependencies
Lock file operations: 0 installs, 2 updates, 0 removals
  - Upgrading vendor/package1 (1.0.0 => 1.0.1)
  - Upgrading vendor/dev-package (2.0.0 => 2.1.0)
OUTPUT;

        $prodDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Updating dependencies
Lock file operations: 0 installs, 1 update, 0 removals
  - Upgrading vendor/package1 (1.0.0 => 1.0.1)
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_format_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/package1' => '^1.0'],
                'require-dev' => ['vendor/dev-package' => '^2.0'],
            ]
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Production and development dependencies are not up-to-date', $result);
    }

    public function test_handles_composer_output_with_downgrades(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies from lock file
Package operations: 0 installs, 1 update, 0 removals
  - Downgrading vendor/package1 (v2.0.0 => v1.9.0)
OUTPUT;

        $prodDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies from lock file
Package operations: 0 installs, 1 update, 0 removals
  - Downgrading vendor/package1 (v2.0.0 => v1.9.0)
OUTPUT;

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            prodDepsOutput: $prodDepsOutput
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Production dependencies are not up-to-date', $result);
    }

    public function test_handles_composer_output_with_removals(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies from lock file
Package operations: 0 installs, 0 updates, 1 removal
  - Removing vendor/old-package (v1.0.0)
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_removals_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/prod-pkg' => '^1.0'],
                'require-dev' => ['vendor/old-package' => '^1.0'],
            ]
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Development dependencies are not up-to-date', $result);
    }

    public function test_composer_install_dry_run_called_once_for_performance(): void
    {
        /** @var Composer&MockInterface $composer */
        $composer = Mockery::mock(Composer::class);

        $composer->shouldReceive('getLockFile')
            ->andReturn('/path/to/composer.lock');

        $composer->shouldReceive('getJsonFile')
            ->andReturn('/path/to/composer.json');

        $composer->shouldReceive('areDevPackagesInstalled')
            ->andReturn(true);

        // OPTIMIZATION: Verify installDryRun is called only ONCE (not twice)
        // This cuts CI execution time in half for large projects
        /** @phpstan-ignore-next-line Mockery expectation chaining */
        $composer->shouldReceive('installDryRun')
            ->once()
            ->andReturn("Nothing to install or update\n");

        $analyzer = new UpToDateDependencyAnalyzer($composer);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_recommendation_contains_specific_composer_command_for_production(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Package operations: 0 installs, 1 update, 0 removals
  - Updating vendor/prod-package (v1.0.0 => v1.0.1)
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_prod_cmd_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/prod-package' => '^1.0'],
                'require-dev' => ['phpunit/phpunit' => '^9.0'],
            ]
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        // Verify recommendation contains actionable composer command
        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('composer update', $recommendation);
        $this->assertStringContainsString('--no-dev', $recommendation);
    }

    public function test_recommendation_contains_specific_composer_command_for_dev_only(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Package operations: 0 installs, 1 update, 0 removals
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_dev_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/prod-pkg' => '^1.0'],
                'require-dev' => ['phpunit/phpunit' => '^9.0'],
            ]
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        // Dev-only updates should recommend full composer update
        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('composer update', $recommendation);
        $this->assertStringNotContainsString('--no-dev', $recommendation);
    }

    public function test_handles_empty_composer_output(): void
    {
        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: '',
            prodDepsOutput: ''
        );

        $result = $analyzer->analyze();

        // Empty output means something to update (doesn't match "Nothing to install" pattern)
        $this->assertWarning($result);
    }

    public function test_handles_composer_output_with_warnings(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Warning: Some deprecation warnings
Loading composer repositories with package information
Installing dependencies from lock file
Nothing to install or update
OUTPUT;

        $prodDepsOutput = <<<'OUTPUT'
Warning: Some deprecation warnings
Loading composer repositories with package information
Installing dependencies from lock file
Nothing to install or update
OUTPUT;

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            prodDepsOutput: $prodDepsOutput
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_severity_is_medium_for_production_updates(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Package operations: 0 installs, 2 updates, 0 removals
OUTPUT;

        $prodDepsOutput = <<<'OUTPUT'
Package operations: 0 installs, 1 update, 0 removals
OUTPUT;

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            prodDepsOutput: $prodDepsOutput
        );

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(Severity::Medium, $issues[0]->severity);
    }

    public function test_both_updates_scenario_includes_both_in_recommendation(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Package operations: 0 installs, 3 updates, 0 removals
  - Updating vendor/prod-pkg (v1.0.0 => v1.0.1)
  - Updating vendor/dev-pkg (v2.0.0 => v2.1.0)
OUTPUT;

        $prodDepsOutput = <<<'OUTPUT'
Package operations: 0 installs, 1 update, 0 removals
  - Updating vendor/prod-pkg (v1.0.0 => v1.0.1)
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_both_rec_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/prod-pkg' => '^1.0'],
                'require-dev' => ['vendor/dev-pkg' => '^2.0'],
            ]
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        // Should mention both production and development
        $message = $issues[0]->message;
        $this->assertStringContainsString('production', strtolower($message));
        $this->assertStringContainsString('development', strtolower($message));
    }

    public function test_handles_operation_counts_in_different_order(): void
    {
        // Test that order-independent regex works: updates before installs
        $allDepsOutput = <<<'OUTPUT'
Package operations: 2 updates, 1 install
  - Updating vendor/package1 (v1.0.0 => v1.0.1)
  - Installing vendor/package2 (v1.0.0)
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_order_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/package1' => '^1.0'],
                'require-dev' => ['vendor/package2' => '^1.0'],
            ]
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('dependencies are not up-to-date', $result);
    }

    public function test_handles_operation_counts_with_missing_fields(): void
    {
        // Test that missing "removals" field doesn't break parsing
        $allDepsOutput = <<<'OUTPUT'
Package operations: 0 installs, 3 updates
  - Updating vendor/prod-pkg (v1.0.0 => v1.0.1)
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_missing_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/prod-pkg' => '^1.0'],
                'require-dev' => [],
            ]
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Production dependencies are not up-to-date', $result);
    }

    public function test_handles_singular_operation_counts(): void
    {
        // Test singular forms: "1 update" instead of "1 updates"
        $allDepsOutput = <<<'OUTPUT'
Package operations: 0 installs, 1 update, 0 removals
  - Updating vendor/package (v1.0.0 => v1.0.1)
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_singular_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/package' => '^1.0'],
                'require-dev' => [],
            ]
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
    }

    public function test_handles_lock_file_operations_format(): void
    {
        // Test "Lock file operations:" instead of "Package operations:"
        $allDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Updating dependencies
Lock file operations: 2 updates, 0 removals
  - Upgrading vendor/package1 (1.0.0 => 1.0.1)
  - Upgrading vendor/package2 (2.0.0 => 2.1.0)
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_lockfile_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/package1' => '^1.0'],
                'require-dev' => ['vendor/package2' => '^2.0'],
            ]
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('dependencies are not up-to-date', $result);
    }

    public function test_handles_all_zero_counts_with_different_formats(): void
    {
        // Test that all-zero counts in various formats result in "up-to-date"
        $allDepsOutput = <<<'OUTPUT'
Package operations: 0 updates, 0 installs, 0 removals
Nothing to install or update
OUTPUT;

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('up-to-date', $result->getMessage());
    }

    public function test_passes_when_no_dev_installed_and_production_up_to_date(): void
    {
        // Simulates: composer install --no-dev was run, all production deps are current.
        // The analyzer should run --dry-run --no-dev and report "passed", not flag missing dev packages.
        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: "Nothing to install or update\n",
            devPackagesInstalled: false,
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('up-to-date', $result->getMessage());
    }

    public function test_warns_production_only_when_dev_packages_not_installed(): void
    {
        // Simulates: composer install --no-dev was run, one production package has an update.
        // Dev packages (phpunit) are intentionally absent and must NOT appear in the report.
        $allDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies from lock file
Package operations: 0 installs, 1 update, 0 removals
  - Updating vendor/prod-package (v1.0.0 => v1.0.1)
OUTPUT;

        $composerJsonPath = sys_get_temp_dir().'/composer_nodev_'.uniqid().'.json';

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            composerJsonPath: $composerJsonPath,
            composerJsonData: [
                'require' => ['vendor/prod-package' => '^1.0'],
                'require-dev' => ['phpunit/phpunit' => '^9.0'],
            ],
            devPackagesInstalled: false,
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertHasIssueContaining('Production dependencies are not up-to-date', $result);

        // Scope must be production-only — dev packages are intentionally excluded
        $this->assertEquals('production', $issues[0]->metadata['scope'] ?? '');
        $this->assertEquals(Severity::Medium, $issues[0]->severity);

        // Dry-run flag recorded in metadata must reflect --no-dev mode
        $versionCheck = $issues[0]->metadata['composer_version_check'] ?? '';
        $this->assertIsString($versionCheck);
        $this->assertStringContainsString('--no-dev', $versionCheck);

        // The false-positive message must NOT appear
        $this->assertStringNotContainsString('development', strtolower($issues[0]->message));
    }

    public function test_passes_on_vapor_with_up_to_date_dependencies(): void
    {
        /** @var UpToDateDependencyAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: "Nothing to install or update\n",
        );
        $analyzer->setDeploymentPlatform('vapor');

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('up-to-date', $result->getMessage());
    }

    public function test_skips_on_serverless_runtime_via_analyze(): void
    {
        // On a live Lambda container the analyzer must not run at all — shouldRun() returns
        // false for 'serverless' so analyze() returns a Skipped result immediately.
        // No allDepsOutput passed so no installDryRun expectation is registered (it won't be called).
        /** @var UpToDateDependencyAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
        );
        $analyzer->setDeploymentPlatform('serverless');

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('serverless', $result->getMessage());
    }

    public function test_passes_on_laravel_cloud_with_up_to_date_dependencies(): void
    {
        /** @var UpToDateDependencyAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: "Nothing to install or update\n",
        );
        $analyzer->setDeploymentPlatform('laravel-cloud');

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('up-to-date', $result->getMessage());
    }

    public function test_passes_ignore_platform_reqs_to_dry_run_on_laravel_cloud(): void
    {
        /** @var Composer&MockInterface $composer */
        $composer = Mockery::mock(Composer::class);

        $composer->shouldReceive('getLockFile')->andReturn('/path/to/composer.lock');
        $composer->shouldReceive('getJsonFile')->andReturn('/path/to/composer.json');
        $composer->shouldReceive('areDevPackagesInstalled')->andReturn(true);

        /** @phpstan-ignore-next-line Mockery expectation chaining */
        $composer->shouldReceive('installDryRun')
            ->with(['--ignore-platform-reqs'])
            ->once()
            ->andReturn("Nothing to install or update\n");

        $analyzer = new UpToDateDependencyAnalyzer($composer);
        $analyzer->setDeploymentPlatform('laravel-cloud');

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_ignore_platform_reqs_to_dry_run_on_vapor(): void
    {
        /** @var Composer&MockInterface $composer */
        $composer = Mockery::mock(Composer::class);

        $composer->shouldReceive('getLockFile')->andReturn('/path/to/composer.lock');
        $composer->shouldReceive('getJsonFile')->andReturn('/path/to/composer.json');
        $composer->shouldReceive('areDevPackagesInstalled')->andReturn(true);

        // Verify that --ignore-platform-reqs is passed when running in Vapor
        /** @phpstan-ignore-next-line Mockery expectation chaining */
        $composer->shouldReceive('installDryRun')
            ->with(['--ignore-platform-reqs'])
            ->once()
            ->andReturn("Nothing to install or update\n");

        $analyzer = new UpToDateDependencyAnalyzer($composer);
        $analyzer->setDeploymentPlatform('vapor');

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_ignore_platform_reqs_alongside_no_dev_on_vapor(): void
    {
        /** @var Composer&MockInterface $composer */
        $composer = Mockery::mock(Composer::class);

        $composer->shouldReceive('getLockFile')->andReturn('/path/to/composer.lock');
        $composer->shouldReceive('getJsonFile')->andReturn('/path/to/composer.json');
        $composer->shouldReceive('areDevPackagesInstalled')->andReturn(false);

        // When --no-dev mode is active, --ignore-platform-reqs is appended after it
        /** @phpstan-ignore-next-line Mockery expectation chaining */
        $composer->shouldReceive('installDryRun')
            ->with(['--no-dev', '--ignore-platform-reqs'])
            ->once()
            ->andReturn("Nothing to install or update\n");

        $analyzer = new UpToDateDependencyAnalyzer($composer);
        $analyzer->setDeploymentPlatform('vapor');

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_detects_real_outdated_deps_on_vapor(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies from lock file
Package operations: 0 installs, 1 update, 0 removals
  - Updating vendor/prod-package (v1.0.0 => v1.0.1)
OUTPUT;

        /** @var UpToDateDependencyAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
        );
        $analyzer->setDeploymentPlatform('vapor');

        $result = $analyzer->analyze();

        // Real version updates must still be reported even in Vapor environments
        $this->assertWarning($result);
        $this->assertHasIssueContaining('dependencies are not up-to-date', $result);
    }

    public function test_skips_on_serverless_runtime(): void
    {
        // On a live Lambda container Composer is not installed, so installDryRun() exits
        // immediately with an error. That empty/unrecognised output falls through to the
        // conservative fallback in isUpToDate() and produces a false positive. shouldRun()
        // must return false for serverless runtimes to prevent the analyzer from running at all.
        /** @var UpToDateDependencyAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setDeploymentPlatform('serverless');

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString('serverless', $analyzer->getSkipReason());
    }

    public function test_dry_run_flag_in_metadata_reflects_ignore_platform_reqs(): void
    {
        // composer_version_check in issue metadata must match the actual options passed to
        // installDryRun() — previously the string was built independently of $dryRunOptions
        // and never included --ignore-platform-reqs even when it was used.
        /** @var Composer&MockInterface $composer */
        $composer = Mockery::mock(Composer::class);

        $composer->shouldReceive('getLockFile')->andReturn('/path/to/composer.lock');
        $composer->shouldReceive('getJsonFile')->andReturn('/path/to/composer.json');
        $composer->shouldReceive('areDevPackagesInstalled')->andReturn(true);

        // Output with a Lock file operations line but no parseable "- Verb Package" lines
        // so we reach the scope='unknown' branch where $dryRunFlag is recorded.
        /** @phpstan-ignore-next-line Mockery expectation chaining */
        $composer->shouldReceive('installDryRun')
            ->with(['--ignore-platform-reqs'])
            ->once()
            ->andReturn('Lock file operations: 0 installs, 1 update, 0 removals');

        $analyzer = new UpToDateDependencyAnalyzer($composer);
        $analyzer->setDeploymentPlatform('vapor');

        $result = $analyzer->analyze();
        $issues = $result->getIssues();

        $this->assertNotEmpty($issues);
        $versionCheck = $issues[0]->metadata['composer_version_check'] ?? '';
        $this->assertIsString($versionCheck);
        $this->assertStringContainsString('--ignore-platform-reqs', $versionCheck);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
