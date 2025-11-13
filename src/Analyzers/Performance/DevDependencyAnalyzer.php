<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects if dev dependencies are installed in production.
 *
 * Checks for:
 * - Dev dependencies in vendor directory
 * - Packages that should only be in require-dev
 * - Common dev packages like debugbar, telescope (dev mode), ignition
 */
class DevDependencyAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Dev dependency checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

    private array $commonDevPackages = [
        'barryvdh/laravel-debugbar',
        'facade/ignition',
        'spatie/laravel-ignition',
        'nunomaduro/collision',
        'phpunit/phpunit',
        'mockery/mockery',
        'fakerphp/faker',
        'laravel/pint',
        'laravel/sail',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'dev-dependencies-production',
            name: 'Dev Dependencies in Production',
            description: 'Detects if development dependencies are installed in production environment',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['composer', 'dependencies', 'performance', 'memory', 'production'],
            docsUrl: 'https://getcomposer.org/doc/03-cli.md#install-i'
        );
    }

    public function shouldRun(): bool
    {
        // Skip in local environment if configured
        if ($this->isLocalAndShouldSkip()) {
            return false;
        }

        $environment = $this->getEnvironment();

        // Only run in non-local environments
        return $environment !== 'local' && file_exists($this->basePath.'/composer.json');
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $composerJsonPath = $this->basePath.'/composer.json';
        $composerLockPath = $this->basePath.'/composer.lock';

        if (! file_exists($composerJsonPath)) {
            return $this->skipped('composer.json not found');
        }

        // Check if composer.lock exists
        if (! file_exists($composerLockPath)) {
            $issues[] = $this->createIssue(
                message: 'composer.lock file not found in production',
                location: new Location($this->basePath, 1),
                severity: Severity::High,
                recommendation: 'Always commit composer.lock to ensure consistent dependency versions across environments. Run "composer install" instead of "composer update" in production.',
                metadata: ['environment' => $this->getEnvironment()]
            );

            return $this->failed('composer.lock missing', $issues);
        }

        // Parse composer.json to get dev dependencies
        $composerJson = json_decode(file_get_contents($composerJsonPath), true);

        if (! is_array($composerJson)) {
            return $this->failed('Invalid composer.json', $issues);
        }

        $devDependencies = $composerJson['require-dev'] ?? [];

        if (! is_array($devDependencies)) {
            $devDependencies = [];
        }

        // Check if common dev packages are installed
        $installedDevPackages = [];

        foreach ($this->commonDevPackages as $package) {
            $packagePath = $this->basePath.'/vendor/'.$package;

            if (file_exists($packagePath)) {
                $installedDevPackages[] = $package;
            }
        }

        // Also check packages from require-dev that are installed
        foreach (array_keys($devDependencies) as $package) {
            $packagePath = $this->basePath.'/vendor/'.$package;

            if (file_exists($packagePath) && ! in_array($package, $installedDevPackages)) {
                $installedDevPackages[] = $package;
            }
        }

        if (! empty($installedDevPackages)) {
            $issues[] = $this->createIssue(
                message: sprintf('Found %d dev dependencies installed in production', count($installedDevPackages)),
                location: new Location($composerJsonPath, 1),
                severity: Severity::High,
                recommendation: 'Use "composer install --no-dev" in production to exclude development dependencies. Dev packages like Ignition and Debugbar can cause memory leaks and slow down your application. Add --no-dev flag to your deployment script.',
                metadata: [
                    'installed_dev_packages' => array_slice($installedDevPackages, 0, 10),
                    'total_count' => count($installedDevPackages),
                    'environment' => $this->getEnvironment(),
                ]
            );
        }

        if (empty($issues)) {
            return $this->passed('No dev dependencies detected in production');
        }

        return $this->failed(
            sprintf('Found %d dev dependency issues', count($issues)),
            $issues
        );
    }
}
