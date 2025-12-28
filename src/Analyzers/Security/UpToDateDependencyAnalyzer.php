<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Support\Composer;

/**
 * Validates that dependencies are up-to-date with available updates.
 *
 * Runs `composer install --dry-run` to check
 * if there are any pending dependency updates within version constraints.
 *
 * This approach is superior because:
 * - More reliable than parsing `composer outdated`
 * - Respects composer.json version constraints
 * - Works consistently across Composer 1 and 2
 * - Simpler and more performant
 */
class UpToDateDependencyAnalyzer extends AbstractAnalyzer
{
    /**
     * Patterns indicating Composer is performing operations (updates available).
     * These are more reliable than looking for "nothing to" messages because:
     * - They appear consistently across Composer versions
     * - They're less affected by locale/translation
     * - They indicate actual work being done
     *
     * @var array<string>
     */
    private const UPDATE_OPERATION_PATTERNS = [
        'Updating',      // "- Updating vendor/package (v1.0 => v2.0)"
        'Installing',    // "- Installing vendor/package (v1.0)"
        'Downgrading',   // "- Downgrading vendor/package (v2.0 => v1.0)"
        'Removing',      // "- Removing vendor/package (v1.0)"
        'Upgrading',     // "- Upgrading vendor/package (v1.0 => v2.0)" (Composer 2.x)
    ];

    /**
     * Fallback patterns indicating no updates needed.
     * Used as secondary check if no operation patterns found.
     *
     * @var array<string>
     */
    private const NOTHING_TO_UPDATE_PATTERNS = [
        'Nothing to install or update',
        'Nothing to install, update or remove',
        'Nothing to modify in lock file',
    ];

    public function __construct(
        private Composer $composer
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'up-to-date-dependencies',
            name: 'Up-to-Date Dependencies Analyzer',
            description: 'Checks if dependencies are up-to-date with available bug fixes and security patches',
            category: Category::Security,
            severity: Severity::Low,
            tags: ['dependencies', 'composer', 'updates', 'maintenance', 'security-patches'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/up-to-date-dependencies',
            timeToFix: 60
        );
    }

    public function shouldRun(): bool
    {
        // Run if composer.json exists (even if composer.lock is missing)
        // We want to warn about missing composer.lock
        return $this->composer->getJsonFile() !== null;
    }

    public function getSkipReason(): string
    {
        return 'No composer.json file found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $composerLockPath = $this->composer->getLockFile();

        if ($composerLockPath === null) {
            return $this->warning(
                'composer.lock file not found',
                [$this->createIssue(
                    message: 'composer.lock file is missing',
                    location: new Location('composer.lock'),
                    severity: Severity::Medium,
                    recommendation: 'Run "composer install" to generate composer.lock for dependency tracking.',
                    metadata: []
                )]
            );
        }

        $issues = [];

        try {
            // Check production dependencies only
            $prodDepsOutput = $this->composer->installDryRun(['--no-dev']);

            // Check all dependencies (including dev)
            $allDepsOutput = $this->composer->installDryRun();

            // Validate outputs are strings
            if (! is_string($allDepsOutput) || ! is_string($prodDepsOutput)) {
                return $this->error('Unable to check dependency status - Composer command failed');
            }

            $prodDepsUpToDate = $this->isUpToDate($prodDepsOutput);
            $allDepsUpToDate = $this->isUpToDate($allDepsOutput);

            // Derive update status from boolean logic
            $hasProdUpdates = ! $prodDepsUpToDate;
            $hasAnyUpdates = ! $allDepsUpToDate;

            // Derive scenarios from the two base booleans
            $hasDevUpdatesOnly = $hasAnyUpdates && ! $hasProdUpdates;

            // When both have updates, distinguish "prod only" from "both":
            // If outputs are semantically identical → only prod needs updates
            // If outputs differ → both prod AND dev need updates
            $hasBothUpdates = $hasAnyUpdates && $hasProdUpdates && ! $this->outputsAreSimilar($prodDepsOutput, $allDepsOutput);

            if ($hasBothUpdates) {
                // Scenario 1: Both production AND dev need updates
                $issues[] = $this->createIssue(
                    message: 'Production and development dependencies are not up-to-date',
                    location: new Location($this->getRelativePath($composerLockPath)),
                    severity: Severity::Medium,
                    recommendation: $this->getBothDepsRecommendation(),
                    code: FileParser::getCodeSnippet($composerLockPath, 1),
                    metadata: [
                        'scope' => 'production and dev',
                        'composer_version_check' => 'install --dry-run',
                    ]
                );
            } elseif ($hasProdUpdates) {
                // Scenario 2: Only production needs updates (dev is up-to-date)
                $issues[] = $this->createIssue(
                    message: 'Production dependencies are not up-to-date',
                    location: new Location($this->getRelativePath($composerLockPath)),
                    severity: Severity::Medium,
                    recommendation: $this->getProductionDepsRecommendation(),
                    code: FileParser::getCodeSnippet($composerLockPath, 1),
                    metadata: [
                        'scope' => 'production',
                        'composer_version_check' => 'install --dry-run --no-dev',
                    ]
                );
            } elseif ($hasDevUpdatesOnly) {
                // Scenario 3: Only dev needs updates (production is up-to-date)
                $issues[] = $this->createIssue(
                    message: 'Development dependencies are not up-to-date',
                    location: new Location($this->getRelativePath($composerLockPath)),
                    severity: Severity::Low,
                    recommendation: $this->getDevDepsRecommendation(),
                    code: FileParser::getCodeSnippet($composerLockPath, 1),
                    metadata: [
                        'scope' => 'dev',
                        'composer_version_check' => 'install --dry-run',
                    ]
                );
            }
            // Scenario 4: Everything up-to-date - no issues created
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('Unable to check dependency status: %s', $e->getMessage()),
                []
            );
        }

        if (empty($issues)) {
            return $this->passed('All dependencies are up-to-date');
        }

        return $this->resultBySeverity(
            sprintf('Found %d dependency update issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Check if Composer output indicates dependencies are up-to-date.
     *
     * Uses a multi-stage approach for robustness:
     * 1. Check for explicit "nothing to update" messages (definitive)
     * 2. Check for update operation patterns (Updating, Installing, etc.)
     * 3. Parse "Package operations:" and "Lock file operations:" for non-zero counts
     * 4. Handle edge cases (empty output, very short output)
     *
     * This approach is more resilient to:
     * - Locale/translation differences
     * - Composer version variations
     * - Extra whitespace or formatting
     * - Plugin output interference
     */
    private function isUpToDate(string $output): bool
    {
        // Normalize output for case-insensitive, whitespace-tolerant matching
        $normalizedOutput = strtolower(trim($output));

        // STEP 1: Check for explicit "nothing to update" messages
        // If we find these, we're definitely up-to-date
        foreach (self::NOTHING_TO_UPDATE_PATTERNS as $pattern) {
            if (stripos($normalizedOutput, strtolower($pattern)) !== false) {
                return true; // Explicitly stated nothing to update
            }
        }

        // STEP 2: Check for update operation patterns (action words)
        // If we find any, dependencies are NOT up-to-date
        foreach (self::UPDATE_OPERATION_PATTERNS as $pattern) {
            if (stripos($normalizedOutput, strtolower($pattern)) !== false) {
                return false; // Found update operations
            }
        }

        // STEP 3: Parse "Package operations:" or "Lock file operations:" for non-zero counts
        // Example: "Package operations: 0 installs, 5 updates, 0 removals"
        if (preg_match('/(package|lock file) operations:\s*(\d+)\s*installs?,\s*(\d+)\s*updates?,\s*(\d+)\s*removals?/i', $normalizedOutput, $matches)) {
            $installs = (int) $matches[2];
            $updates = (int) $matches[3];
            $removals = (int) $matches[4];

            // If any operation count is non-zero, updates are needed
            if ($installs > 0 || $updates > 0 || $removals > 0) {
                return false;
            }

            // All counts are zero - dependencies are up-to-date
            return true;
        }

        // STEP 4: Handle edge cases
        // Empty output is ambiguous but should be treated as potentially needing updates
        if (strlen($normalizedOutput) === 0) {
            return false; // Conservative: assume updates might be needed
        }

        // Very short output without clear indicators - likely up-to-date
        // (e.g., just "Loading..." messages)
        if (strlen($normalizedOutput) < 50) {
            return true;
        }

        // CONSERVATIVE FALLBACK: If we can't determine, assume updates might be needed
        // Better to warn unnecessarily than miss actual updates
        return false;
    }

    /**
     * Check if two Composer outputs are semantically similar.
     * Uses normalized comparison to avoid fragility from:
     * - Whitespace differences
     * - Plugin messages
     * - Timestamp variations
     * - Minor formatting changes
     */
    private function outputsAreSimilar(string $output1, string $output2): bool
    {
        // Normalize both outputs
        $normalized1 = $this->normalizeComposerOutput($output1);
        $normalized2 = $this->normalizeComposerOutput($output2);

        return $normalized1 === $normalized2;
    }

    /**
     * Normalize Composer output for comparison by:
     * - Trimming whitespace
     * - Removing empty lines
     * - Normalizing line endings
     * - Sorting lines (to handle order variations)
     */
    private function normalizeComposerOutput(string $output): string
    {
        // Split into lines, trim each, remove empty lines
        $lines = array_filter(
            array_map('trim', explode("\n", $output)),
            fn ($line) => $line !== ''
        );

        // Sort lines to handle order variations
        sort($lines);

        return implode("\n", $lines);
    }

    /**
     * Get recommendation message for both production and dev dependencies.
     */
    private function getBothDepsRecommendation(): string
    {
        return 'Your application\'s production and development dependencies are not up-to-date. '.
            'These may include bug fixes and/or security patches. '.
            'Run "composer update" to update all dependencies within your version constraints. '.
            'Review the changes before deploying to production.';
    }

    /**
     * Get recommendation message for production dependencies only.
     */
    private function getProductionDepsRecommendation(): string
    {
        return 'Your application\'s production dependencies are not up-to-date. '.
            'These may include bug fixes and/or security patches. '.
            'Run "composer update --no-dev" to update production dependencies only, '.
            'or "composer update" to update all dependencies. '.
            'Review the changes before deploying to production.';
    }

    /**
     * Get recommendation message for development dependencies only.
     */
    private function getDevDepsRecommendation(): string
    {
        return 'Your application\'s development dependencies are not up-to-date. '.
            'While these don\'t affect production, keeping them updated helps maintain a healthy development environment. '.
            'Run "composer update" to update all dependencies.';
    }
}
