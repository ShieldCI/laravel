<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Validates that dependencies are up-to-date with available updates.
 *
 * Checks for:
 * - Outdated Composer packages
 * - Available security patches
 * - Major/minor version updates
 * - Dependencies with significant version lag
 */
class UpToDateDependencyAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'up-to-date-dependencies',
            name: 'Up-to-Date Dependency Analyzer',
            description: 'Checks if dependencies are up-to-date with available bug fixes and security patches',
            category: Category::Security,
            severity: Severity::Low,
            tags: ['dependencies', 'composer', 'updates', 'maintenance', 'security-patches'],
            docsUrl: 'https://getcomposer.org/doc/03-cli.md#outdated'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check if composer.lock exists
        $composerLock = $this->basePath.'/composer.lock';

        if (! file_exists($composerLock)) {
            return $this->passed('No composer.lock found - skipping update check');
        }

        // Run composer outdated to check for available updates
        $outdatedPackages = $this->checkOutdatedPackages();

        if (! empty($outdatedPackages)) {
            $this->createOutdatedIssues($outdatedPackages, $issues);
        }

        // Check composer.lock age
        $this->checkLockFileAge($composerLock, $issues);

        if (empty($issues)) {
            return $this->passed('All dependencies are up-to-date');
        }

        return $this->failed(
            sprintf('Found %d outdated dependencies', count($issues)),
            $issues
        );
    }

    /**
     * Check for outdated packages using composer outdated.
     */
    private function checkOutdatedPackages(): array
    {
        // Change to the base directory
        $originalDir = getcwd();
        chdir($this->basePath);

        // Run composer outdated with JSON output (only direct dependencies)
        $output = shell_exec('composer outdated --direct --format=json 2>&1');

        // Change back to original directory
        chdir($originalDir);

        if ($output === null) {
            return [];
        }

        // Try to decode JSON output
        $result = json_decode($output, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            // If JSON parsing fails, try plain text parsing
            return $this->parseOutdatedPlainText($output);
        }

        return $result['installed'] ?? [];
    }

    /**
     * Parse plain text composer outdated output as fallback.
     */
    private function parseOutdatedPlainText(string $output): array
    {
        $packages = [];
        $lines = explode("\n", $output);

        foreach ($lines as $line) {
            // Match pattern: "vendor/package version1 version2"
            if (preg_match('/^([a-z0-9\-]+\/[a-z0-9\-]+)\s+(\S+)\s+(\S+)/i', trim($line), $matches)) {
                $packages[] = [
                    'name' => $matches[1],
                    'version' => $matches[2],
                    'latest' => $matches[3],
                ];
            }
        }

        return $packages;
    }

    /**
     * Create issues for outdated packages.
     */
    private function createOutdatedIssues(array $outdatedPackages, array &$issues): void
    {
        $securityUpdates = [];
        $majorUpdates = [];
        $minorUpdates = [];

        foreach ($outdatedPackages as $package) {
            $name = $package['name'] ?? 'Unknown';
            $current = $package['version'] ?? '';
            $latest = $package['latest'] ?? $package['latest-version'] ?? '';

            // Skip if no version info
            if (empty($current) || empty($latest)) {
                continue;
            }

            // Determine update type
            $updateType = $this->determineUpdateType($current, $latest);

            switch ($updateType) {
                case 'major':
                    $majorUpdates[] = sprintf('%s (%s → %s)', $name, $current, $latest);
                    break;
                case 'minor':
                    $minorUpdates[] = sprintf('%s (%s → %s)', $name, $current, $latest);
                    break;
                case 'patch':
                    $securityUpdates[] = sprintf('%s (%s → %s)', $name, $current, $latest);
                    break;
            }
        }

        // Create issues based on update types
        if (! empty($securityUpdates)) {
            $count = count($securityUpdates);
            $examples = implode(', ', array_slice($securityUpdates, 0, 3));

            $issues[] = $this->createIssue(
                message: sprintf('Found %d package(s) with available patch updates', $count),
                location: new Location(
                    'composer.lock',
                    1
                ),
                severity: Severity::Medium,
                recommendation: sprintf(
                    'Update packages with security/bug fixes: %s%s. Run "composer update"',
                    $examples,
                    $count > 3 ? sprintf(' and %d more', $count - 3) : ''
                ),
                code: sprintf('Patch updates available: %d', $count)
            );
        }

        if (! empty($minorUpdates)) {
            $count = count($minorUpdates);
            $examples = implode(', ', array_slice($minorUpdates, 0, 3));

            $issues[] = $this->createIssue(
                message: sprintf('Found %d package(s) with available minor updates', $count),
                location: new Location(
                    'composer.lock',
                    1
                ),
                severity: Severity::Low,
                recommendation: sprintf(
                    'Consider updating: %s%s. Run "composer update"',
                    $examples,
                    $count > 3 ? sprintf(' and %d more', $count - 3) : ''
                ),
                code: sprintf('Minor updates available: %d', $count)
            );
        }

        if (! empty($majorUpdates)) {
            $count = count($majorUpdates);
            $examples = implode(', ', array_slice($majorUpdates, 0, 3));

            $issues[] = $this->createIssue(
                message: sprintf('Found %d package(s) with available major updates', $count),
                location: new Location(
                    'composer.lock',
                    1
                ),
                severity: Severity::Low,
                recommendation: sprintf(
                    'Major updates available (may have breaking changes): %s%s. Review changelogs before updating',
                    $examples,
                    $count > 3 ? sprintf(' and %d more', $count - 3) : ''
                ),
                code: sprintf('Major updates available: %d', $count)
            );
        }
    }

    /**
     * Determine update type (major, minor, patch).
     */
    private function determineUpdateType(string $current, string $latest): string
    {
        // Remove 'v' prefix if present
        $current = ltrim($current, 'v');
        $latest = ltrim($latest, 'v');

        // Parse semantic versions
        $currentParts = explode('.', $current);
        $latestParts = explode('.', $latest);

        // Extract major.minor.patch
        $currentMajor = (int) ($currentParts[0] ?? 0);
        $currentMinor = (int) ($currentParts[1] ?? 0);

        $latestMajor = (int) ($latestParts[0] ?? 0);
        $latestMinor = (int) ($latestParts[1] ?? 0);

        if ($latestMajor > $currentMajor) {
            return 'major';
        }

        if ($latestMinor > $currentMinor) {
            return 'minor';
        }

        return 'patch';
    }

    /**
     * Check composer.lock file age.
     */
    private function checkLockFileAge(string $composerLock, array &$issues): void
    {
        $lastModified = filemtime($composerLock);

        if ($lastModified === false) {
            return;
        }

        $daysSinceUpdate = (time() - $lastModified) / (60 * 60 * 24);

        // Warn if composer.lock hasn't been updated in 6 months
        if ($daysSinceUpdate > 180) {
            $months = round($daysSinceUpdate / 30, 1);

            $issues[] = $this->createIssue(
                message: sprintf('composer.lock has not been updated in %.1f months', $months),
                location: new Location(
                    'composer.lock',
                    1
                ),
                severity: Severity::Low,
                recommendation: sprintf(
                    'Dependencies have not been updated in %.1f months. Run "composer update" to get latest patches',
                    $months
                ),
                code: sprintf('Last updated: %s', date('Y-m-d', $lastModified))
            );
        }
    }
}
