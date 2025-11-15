<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use Mockery;
use ShieldCI\Analyzers\Security\UpToDateDependencyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Support\Composer;
use ShieldCI\Tests\AnalyzerTestCase;

class UpToDateDependencyAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(
        ?string $composerLockPath = '/path/to/composer.lock',
        ?string $allDepsOutput = null,
        ?string $prodDepsOutput = null
    ): AnalyzerInterface {
        /** @var Composer&\Mockery\MockInterface $composer */
        $composer = Mockery::mock(Composer::class);

        // Mock getLockFile
        $composer->shouldReceive('getLockFile')
            ->andReturn($composerLockPath);

        // Mock installDryRun - called twice per analysis
        if ($allDepsOutput !== null && $prodDepsOutput !== null) {
            /** @phpstan-ignore-next-line Mockery's times() is not recognized by PHPStan */
            $composer->shouldReceive('installDryRun')
                ->times(2)
                ->andReturnUsing(function ($args = []) use ($allDepsOutput, $prodDepsOutput) {
                    if (empty($args)) {
                        return $allDepsOutput;
                    }
                    if (in_array('--no-dev', $args)) {
                        return $prodDepsOutput;
                    }

                    return '';
                });
        }

        return new UpToDateDependencyAnalyzer($composer);
    }

    public function test_skips_when_no_composer_lock_exists(): void
    {
        $analyzer = $this->createAnalyzer(composerLockPath: null);

        $this->assertFalse($analyzer->shouldRun());

        if (method_exists($analyzer, 'getSkipReason')) {
            $this->assertStringContainsString('composer.lock', $analyzer->getSkipReason());
        }
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

    public function test_fails_when_all_dependencies_need_updates(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies (including require-dev) from lock file
Package operations: 0 installs, 5 updates, 0 removals
  - Updating vendor/package1 (v1.0.0 => v1.0.1)
  - Updating vendor/package2 (v2.0.0 => v2.1.0)
OUTPUT;

        $prodDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies from lock file
Package operations: 0 installs, 3 updates, 0 removals
  - Updating vendor/package1 (v1.0.0 => v1.0.1)
OUTPUT;

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            prodDepsOutput: $prodDepsOutput
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Dependencies are not up-to-date', $result);

        // Check metadata contains scope information
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('all (production and dev)', $issues[0]->metadata['scope'] ?? '');
    }

    public function test_fails_when_production_and_all_dependencies_need_updates(): void
    {
        // This tests when BOTH production and dev dependencies have updates
        $allDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies (including require-dev) from lock file
Package operations: 0 installs, 3 updates, 0 removals
  - Updating vendor/package1 (v1.0.0 => v1.0.1)
OUTPUT;

        $prodDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies from lock file
Package operations: 0 installs, 3 updates, 0 removals
  - Updating vendor/package1 (v1.0.0 => v1.0.1)
OUTPUT;

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            prodDepsOutput: $prodDepsOutput
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // When both fail, it should report as all dependencies
        $this->assertHasIssueContaining('Dependencies are not up-to-date', $result);

        // Check metadata contains scope information
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('all (production and dev)', $issues[0]->metadata['scope'] ?? '');
    }

    public function test_fails_with_low_severity_when_only_dev_dependencies_need_updates(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Loading composer repositories with package information
Installing dependencies (including require-dev) from lock file
Package operations: 0 installs, 2 updates, 0 removals
  - Updating phpunit/phpunit (v9.0.0 => v9.1.0)
OUTPUT;

        $prodDepsOutput = "Nothing to install or update\n";

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            prodDepsOutput: $prodDepsOutput
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Development dependencies are not up-to-date', $result);

        // Dev dependencies should be low severity
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $issues[0]->severity);
        $this->assertEquals('dev only', $issues[0]->metadata['scope'] ?? '');
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('up-to-date-dependencies', $metadata->id);
        $this->assertEquals('Up-to-Date Dependency Analyzer', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Security, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $metadata->severity);
        $this->assertContains('dependencies', $metadata->tags);
        $this->assertContains('security-patches', $metadata->tags);
    }

    public function test_provides_helpful_recommendations(): void
    {
        $allDepsOutput = <<<'OUTPUT'
Package operations: 0 installs, 5 updates, 0 removals
OUTPUT;

        $prodDepsOutput = "Nothing to install or update\n";

        $analyzer = $this->createAnalyzer(
            composerLockPath: '/path/to/composer.lock',
            allDepsOutput: $allDepsOutput,
            prodDepsOutput: $prodDepsOutput
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        // Verify recommendation contains actionable advice
        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('composer update', $recommendation);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
