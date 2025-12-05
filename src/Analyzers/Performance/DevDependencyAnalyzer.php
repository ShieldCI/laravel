<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
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
 *
 * Environment Relevance:
 * - Production/Staging: Critical (dev packages cause memory leaks and security issues)
 * - Local/Development: Not relevant (dev dependencies are necessary for development)
 * - Testing: Not relevant (tests need dev dependencies like PHPUnit)
 */
class DevDependencyAnalyzer extends AbstractAnalyzer
{
    /**
     * Dev dependency checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

    /**
     * This analyzer is only relevant in production and staging environments.
     *
     * Dev dependencies like Debugbar, Ignition, and Telescope can cause memory leaks,
     * performance degradation, and security issues in production.
     *
     * @var array<string>
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    /**
     * Cached Composer availability check result.
     */
    private ?bool $composerAvailable = null;

    private ?bool $timeoutAvailable = null;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'dev-dependencies-production',
            name: 'Dev Dependencies in Production Analyzer',
            description: 'Detects if development dependencies are installed in production environment',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['composer', 'dependencies', 'performance', 'memory', 'production'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/dev-dependencies-production',
            timeToFix: 10
        );
    }

    public function shouldRun(): bool
    {
        // Check environment relevance first
        if (! $this->isRelevantForCurrentEnvironment()) {
            return false;
        }

        // Check other conditions
        $composerJsonPath = $this->buildPath('composer.json');

        return file_exists($composerJsonPath);
    }

    public function getSkipReason(): string
    {
        if (! $this->isRelevantForCurrentEnvironment()) {
            $currentEnv = $this->getEnvironment();
            $relevantEnvs = implode(', ', $this->relevantEnvironments ?? []);

            return "Not relevant in '{$currentEnv}' environment (only relevant in: {$relevantEnvs})";
        }

        return 'Composer configuration file (composer.json) not found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $composerJsonPath = $this->buildPath('composer.json');
        $composerLockPath = $this->buildPath('composer.lock');

        // Check 1: Verify composer.lock exists (critical for production)
        if (! file_exists($composerLockPath)) {
            $issues[] = $this->createIssue(
                message: 'composer.lock file not found in production',
                location: new Location($composerLockPath, 1),
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

        if (count($issues) === 0) {
            return $this->passed('No dev dependencies detected in production');
        }

        return $this->resultBySeverity(
            sprintf('Found %d dev dependency issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Check if Composer binary is available.
     * Result is cached to avoid repeated shell executions.
     */
    protected function isComposerAvailable(): bool
    {
        // Return cached result if already checked
        if ($this->composerAvailable !== null) {
            return $this->composerAvailable;
        }

        if (PHP_OS_FAMILY === 'Windows') {
            $output = shell_exec('where composer 2>nul');
            $this->composerAvailable = is_string($output) && ! empty(trim($output));
        } else {
            $output = shell_exec('command -v composer 2>&1');
            $this->composerAvailable = is_string($output) && ! empty(trim($output));
        }

        return $this->composerAvailable;
    }

    /**
     * Check for dev dependencies using Composer dry-run
     * This is the most accurate method as it uses Composer's own logic.
     * Uses --working-dir for better portability and includes command timeout.
     */
    private function checkViaComposerDryRun(string $composerJsonPath): ?Issue
    {
        $basePath = $this->getBasePath();

        // Use --working-dir instead of cd for better portability
        $command = sprintf(
            'composer install --working-dir=%s --dry-run --no-dev --no-interaction 2>&1',
            escapeshellarg($basePath)
        );

        $outputLines = [];
        $exitCode = 0;

        // Execute with timeout (30 seconds)
        $result = $this->executeWithTimeout($command, 30, $outputLines, $exitCode);

        if (! $result || $exitCode !== 0) {
            // Fall back to file system check if composer command fails
            return $this->checkViaFileSystem($composerJsonPath);
        }

        $output = implode("\n", $outputLines);

        // More robust pattern matching for different Composer versions
        // Matches: "- Removing", "- would remove", "Removing package/name"
        // Pattern matches standard Composer output format: "package/vendor" format
        // Updated to support dots in package names (e.g., symfony/polyfill-php8.0)
        if (preg_match('/-\s+(Removing|would\s+remove)\s+([a-z0-9\-_.]+\/[a-z0-9\-_.]+)/i', $output)) {
            // Extract package names for better reporting
            preg_match_all('/-\s+(Removing|would\s+remove)\s+([a-z0-9\-_.]+\/[a-z0-9\-_.]+)/i', $output, $allMatches);
            /** @var array<int, string> $packageNames */
            $packageNames = $allMatches[2];
            $removedPackages = array_slice($packageNames, 0, 10);

            return $this->createIssue(
                message: 'Dev dependencies are installed in production environment',
                location: new Location($composerJsonPath, 1),
                severity: Severity::High,
                recommendation: 'Use "composer install --no-dev" in production to exclude development dependencies. Dev packages like Ignition and Debugbar can cause memory leaks and slow down your application. Add --no-dev flag to your deployment script.',
                metadata: [
                    'detection_method' => 'composer_dry_run',
                    'environment' => $this->getEnvironment(),
                    'packages_to_remove' => $removedPackages,
                    'total_packages' => count($packageNames),
                ]
            );
        }

        return null;
    }

    /**
     * Execute command with timeout.
     *
     * @param  array<int, string>  $outputLines
     */
    private function executeWithTimeout(string $command, int $timeoutSeconds, array &$outputLines, int &$exitCode): bool
    {
        // For Windows, timeout is less reliable, fall back to regular exec
        if (PHP_OS_FAMILY === 'Windows') {
            exec($command, $outputLines, $exitCode);

            return $exitCode === 0;
        }

        // On Unix systems, use timeout command if available
        if ($this->isTimeoutAvailable()) {
            $command = sprintf('timeout %d %s', $timeoutSeconds, $command);
        }

        exec($command, $outputLines, $exitCode);

        // Exit code 124 means timeout was triggered
        if ($exitCode === 124) {
            return false;
        }

        return $exitCode === 0;
    }

    /**
     * Check if timeout command is available (cached).
     */
    private function isTimeoutAvailable(): bool
    {
        // Return cached result if already checked
        if ($this->timeoutAvailable !== null) {
            return $this->timeoutAvailable;
        }

        $output = shell_exec('command -v timeout 2>&1');
        $this->timeoutAvailable = is_string($output) && ! empty(trim($output));

        return $this->timeoutAvailable;
    }

    /**
     * Check for dev dependencies via file system (fallback method).
     * Parses composer.json and checks if require-dev packages exist in vendor/.
     */
    private function checkViaFileSystem(string $composerJsonPath): ?Issue
    {
        // Check if vendor directory exists first
        $vendorPath = $this->buildPath('vendor');
        if (! file_exists($vendorPath) || ! is_dir($vendorPath)) {
            // No vendor directory means no packages installed at all
            return null;
        }

        $devDependencies = $this->getDevPackagesFromLock() ?? $this->getDevPackagesFromComposerJson($composerJsonPath);

        if (empty($devDependencies)) {
            return null;
        }

        $installedDevPackages = [];

        foreach ($devDependencies as $package) {
            if (! is_string($package)) {
                continue;
            }

            $normalizedPath = str_replace('/', DIRECTORY_SEPARATOR, $package);
            $packagePath = $vendorPath.DIRECTORY_SEPARATOR.$normalizedPath;

            if (file_exists($packagePath) && is_dir($packagePath)) {
                $installedDevPackages[] = $package;
            }
        }

        if (empty($installedDevPackages)) {
            return null;
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

    /**
     * Get dev packages from composer.lock.
     *
     * @return array<int, string>|null
     */
    private function getDevPackagesFromLock(): ?array
    {
        $lockPath = $this->buildPath('composer.lock');

        if (! file_exists($lockPath)) {
            return null;
        }

        $contents = FileParser::readFile($lockPath);

        if ($contents === null) {
            return null;
        }

        $lockData = json_decode($contents, true);

        if (json_last_error() !== JSON_ERROR_NONE || ! is_array($lockData)) {
            return null;
        }

        if (! isset($lockData['packages-dev']) || ! is_array($lockData['packages-dev'])) {
            return [];
        }

        $packages = [];

        foreach ($lockData['packages-dev'] as $package) {
            if (is_array($package) && isset($package['name']) && is_string($package['name'])) {
                $packages[] = $package['name'];
            }
        }

        return $packages;
    }

    /**
     * Get dev packages from composer.json.
     *
     * @return array<int, string>
     */
    private function getDevPackagesFromComposerJson(string $composerJsonPath): array
    {
        $contents = FileParser::readFile($composerJsonPath);

        if ($contents === null) {
            return [];
        }

        $composerJson = json_decode($contents, true);

        if (json_last_error() !== JSON_ERROR_NONE || ! is_array($composerJson)) {
            return [];
        }

        $devDependencies = $composerJson['require-dev'] ?? [];

        if (! is_array($devDependencies) || empty($devDependencies)) {
            return [];
        }

        return array_values(array_filter(array_keys($devDependencies), fn ($key) => is_string($key)));
    }
}
