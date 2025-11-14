<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects if dev dependencies are installed in production.
 *
 * Uses two detection methods:
 * 1. Composer dry-run (authoritative, zero maintenance)
 * 2. File system check (fallback when Composer unavailable)
 *
 * Also checks for missing composer.lock file.
 */
class DevDependencyAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Dev dependency checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

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
        // Skip if user configured to skip in local environment
        if ($this->isLocalAndShouldSkip()) {
            return false;
        }

        // Check other conditions
        return file_exists($this->basePath.'/composer.json');
    }

    public function getSkipReason(): string
    {
        if ($this->isLocalAndShouldSkip()) {
            return 'Skipped in local environment (configured)';
        }

        return 'Composer configuration file (composer.json) not found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $composerJsonPath = $this->basePath.'/composer.json';
        $composerLockPath = $this->basePath.'/composer.lock';

        // Check 1: Verify composer.lock exists (critical for production)
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

        // Check 2: Detect dev dependencies using best available method
        // Try Composer dry-run first (100% accurate), fall back to file system check
        if ($this->isComposerAvailable()) {
            $devDepsResult = $this->checkViaComposerDryRun($composerJsonPath);
        } else {
            $devDepsResult = $this->checkViaFileSystem($composerJsonPath);
        }

        if ($devDepsResult !== null) {
            $issues[] = $devDepsResult;
        }

        if (empty($issues)) {
            return $this->passed('No dev dependencies detected in production');
        }

        return $this->failed(
            sprintf('Found %d dev dependency issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Check if Composer binary is available.
     */
    private function isComposerAvailable(): bool
    {
        // Check if composer command exists
        $output = shell_exec('command -v composer 2>&1');

        return ! empty($output);
    }

    /**
     * Check for dev dependencies using Composer dry-run
     * This is the most accurate method as it uses Composer's own logic.
     */
    private function checkViaComposerDryRun(string $composerJsonPath): ?Issue
    {
        // Run: composer install --dry-run --no-dev
        // If output contains "Removing", dev dependencies are installed
        $command = sprintf(
            'cd %s && composer install --dry-run --no-dev 2>&1',
            escapeshellarg($this->basePath)
        );

        $output = shell_exec($command);

        if ($output === null || $output === false) {
            // Command failed, fall back to file system check
            return $this->checkViaFileSystem($composerJsonPath);
        }

        // Check if output contains "Removing" which indicates dev packages would be removed
        if (stripos((string) $output, 'Removing') !== false) {
            return $this->createIssue(
                message: 'Dev dependencies are installed in production environment',
                location: new Location($composerJsonPath, 1),
                severity: Severity::High,
                recommendation: 'Use "composer install --no-dev" in production to exclude development dependencies. Dev packages like Ignition and Debugbar can cause memory leaks and slow down your application. Add --no-dev flag to your deployment script.',
                metadata: [
                    'detection_method' => 'composer_dry_run',
                    'environment' => $this->getEnvironment(),
                ]
            );
        }

        return null; // No dev dependencies detected
    }

    /**
     * Check for dev dependencies via file system (fallback method).
     * Parses composer.json and checks if require-dev packages exist in vendor/.
     */
    private function checkViaFileSystem(string $composerJsonPath): ?Issue
    {
        // Parse composer.json to get dev dependencies
        $composerJson = json_decode(file_get_contents($composerJsonPath), true);

        if (! is_array($composerJson)) {
            return null; // Invalid composer.json
        }

        $devDependencies = $composerJson['require-dev'] ?? [];

        if (! is_array($devDependencies) || empty($devDependencies)) {
            return null; // No dev dependencies defined
        }

        // Check which require-dev packages are actually installed in vendor/
        $installedDevPackages = [];

        foreach (array_keys($devDependencies) as $package) {
            if (! is_string($package)) {
                continue;
            }

            $packagePath = $this->basePath.'/vendor/'.$package;

            if (file_exists($packagePath) && is_dir($packagePath)) {
                $installedDevPackages[] = $package;
            }
        }

        if (empty($installedDevPackages)) {
            return null; // No dev dependencies installed
        }

        return $this->createIssue(
            message: sprintf('Found %d dev dependencies installed in production', count($installedDevPackages)),
            location: new Location($composerJsonPath, 1),
            severity: Severity::High,
            recommendation: 'Use "composer install --no-dev" in production to exclude development dependencies. Dev packages like Ignition and Debugbar can cause memory leaks and slow down your application. Add --no-dev flag to your deployment script.',
            metadata: [
                'detection_method' => 'file_system',
                'installed_dev_packages' => array_slice($installedDevPackages, 0, 10),
                'total_count' => count($installedDevPackages),
                'environment' => $this->getEnvironment(),
            ]
        );
    }
}
