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
            severity: Severity::Medium,
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
            // OPTIMIZATION: Run composer install --dry-run only ONCE (all dependencies)
            // This is significantly faster than running it twice (once with --no-dev, once without)
            $allDepsOutput = $this->composer->installDryRun();

            // Validate output is string
            if (! is_string($allDepsOutput)) {
                return $this->error('Unable to check dependency status - Composer command failed');
            }

            // EARLY EXIT: If everything is up-to-date, no need for further parsing
            if ($this->isUpToDate($allDepsOutput)) {
                return $this->passed('All dependencies are up-to-date');
            }

            // Dependencies need updating - determine if prod, dev, or both
            // Extract which packages are being updated from Composer output
            $updatedPackages = $this->extractUpdatedPackages($allDepsOutput);

            // If we can't extract packages (unexpected output format), report general update needed
            if (empty($updatedPackages)) {
                $issues[] = $this->createIssue(
                    message: 'Dependencies are not up-to-date',
                    location: new Location($this->getRelativePath($composerLockPath)),
                    severity: Severity::Medium,
                    recommendation: $this->getBothDepsRecommendation(),
                    code: FileParser::getCodeSnippet($composerLockPath, 1),
                    metadata: [
                        'scope' => 'unknown',
                        'composer_version_check' => 'install --dry-run',
                    ]
                );
            } else {
                // Get dev packages from composer.json
                $devPackages = $this->getDevPackages();

                // Categorize updated packages as prod or dev
                $categorized = $this->categorizePackages($updatedPackages, $devPackages);

                $hasProdUpdates = ! empty($categorized['prod']);
                $hasDevUpdates = ! empty($categorized['dev']);

                if ($hasProdUpdates && $hasDevUpdates) {
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
                            'prod_packages' => $categorized['prod'],
                            'dev_packages' => $categorized['dev'],
                        ]
                    );
                } elseif ($hasProdUpdates) {
                    // Scenario 2: Only production needs updates
                    $issues[] = $this->createIssue(
                        message: 'Production dependencies are not up-to-date',
                        location: new Location($this->getRelativePath($composerLockPath)),
                        severity: Severity::Medium,
                        recommendation: $this->getProductionDepsRecommendation(),
                        code: FileParser::getCodeSnippet($composerLockPath, 1),
                        metadata: [
                            'scope' => 'production',
                            'composer_version_check' => 'install --dry-run',
                            'packages' => $categorized['prod'],
                        ]
                    );
                } elseif ($hasDevUpdates) {
                    // Scenario 3: Only dev needs updates
                    $issues[] = $this->createIssue(
                        message: 'Development dependencies are not up-to-date',
                        location: new Location($this->getRelativePath($composerLockPath)),
                        severity: Severity::Low,
                        recommendation: $this->getDevDepsRecommendation(),
                        code: FileParser::getCodeSnippet($composerLockPath, 1),
                        metadata: [
                            'scope' => 'dev',
                            'composer_version_check' => 'install --dry-run',
                            'packages' => $categorized['dev'],
                        ]
                    );
                }
            }
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
     * 1. Check for explicit "nothing to update" messages (most definitive)
     * 2. Parse "Package operations:" counts (authoritative structured data)
     * 3. Check for update operation verb patterns (fallback for edge cases)
     * 4. Handle edge cases (empty output, very short output)
     *
     * This approach is more resilient to:
     * - Locale/translation differences
     * - Composer version variations
     * - Extra whitespace or formatting
     * - Plugin output interference (plugins can log "Installing..." but won't fake operation counts)
     */
    private function isUpToDate(string $output): bool
    {
        // Normalize output for case-insensitive, whitespace-tolerant matching
        $normalizedOutput = strtolower(trim($output));

        // STEP 1: Check for explicit "nothing to update" messages (most definitive)
        // If we find these, we're definitely up-to-date
        foreach (self::NOTHING_TO_UPDATE_PATTERNS as $pattern) {
            if (stripos($normalizedOutput, strtolower($pattern)) !== false) {
                return true; // Explicitly stated nothing to update
            }
        }

        // STEP 2: Parse "Package operations:" or "Lock file operations:" for counts (authoritative)
        // Example: "Package operations: 0 installs, 5 updates, 0 removals"
        // This is more reliable than verb matching because:
        // - Operation counts are Composer's official structured summary
        // - Plugins can output "Installing..." logs but won't fake this line
        // - Less affected by locale/translation
        //
        // Match counts independently (not positionally) to handle:
        // - Different field ordering
        // - Missing fields (e.g., no removals mentioned)
        // - Singular vs plural variations
        if (preg_match('/(package|lock file) operations:/i', $normalizedOutput, $operationMatch)) {
            // Extract the line containing operation counts
            $operationLineStart = (int) stripos($normalizedOutput, $operationMatch[0]);
            $operationLineEnd = strpos($normalizedOutput, "\n", $operationLineStart);
            $operationLine = $operationLineEnd !== false
                ? substr($normalizedOutput, $operationLineStart, $operationLineEnd - $operationLineStart)
                : substr($normalizedOutput, $operationLineStart);

            // Match each operation type independently (order-agnostic, optional fields)
            $totalOperations = 0;

            // Match: "5 installs" or "5 install" or "1 install"
            if (preg_match('/(\d+)\s*installs?/i', $operationLine, $installMatch)) {
                $totalOperations += (int) $installMatch[1];
            }

            // Match: "3 updates" or "3 update" or "1 update"
            if (preg_match('/(\d+)\s*updates?/i', $operationLine, $updateMatch)) {
                $totalOperations += (int) $updateMatch[1];
            }

            // Match: "2 removals" or "2 removal" or "1 removal"
            if (preg_match('/(\d+)\s*removals?/i', $operationLine, $removalMatch)) {
                $totalOperations += (int) $removalMatch[1];
            }

            // If total operations is zero, dependencies are up-to-date
            // If non-zero, updates are needed
            return $totalOperations === 0;
        }

        // STEP 3: Check for update operation verb patterns (fallback)
        // If we find action words, dependencies are NOT up-to-date
        // This is a fallback for older Composer versions or different output formats
        foreach (self::UPDATE_OPERATION_PATTERNS as $pattern) {
            if (stripos($normalizedOutput, strtolower($pattern)) !== false) {
                return false; // Found update operations
            }
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

    /**
     * Get the list of dev package names from composer.json.
     *
     * @return array<string> Array of package names (e.g., ['phpunit/phpunit', 'mockery/mockery'])
     */
    private function getDevPackages(): array
    {
        $composerJsonPath = $this->composer->getJsonFile();

        if ($composerJsonPath === null || ! file_exists($composerJsonPath)) {
            return [];
        }

        $content = file_get_contents($composerJsonPath);
        if ($content === false) {
            return [];
        }

        $data = json_decode($content, true);
        if (! is_array($data) || ! isset($data['require-dev']) || ! is_array($data['require-dev'])) {
            return [];
        }

        return array_keys($data['require-dev']);
    }

    /**
     * Extract package names being updated from Composer output.
     *
     * Parses output lines like:
     * - "  - Updating vendor/package (v1.0 => v2.0)"
     * - "  - Installing vendor/package (v1.0)"
     * - "  - Upgrading vendor/package (v1.0 => v2.0)"
     * - "  - Downgrading vendor/package (v2.0 => v1.0)"
     * - "  - Removing vendor/package (v1.0)"
     *
     * @return array<string> Array of package names (e.g., ['vendor/package1', 'vendor/package2'])
     */
    private function extractUpdatedPackages(string $output): array
    {
        $packages = [];
        $lines = explode("\n", $output);

        foreach ($lines as $line) {
            // Match lines like: "  - Updating vendor/package (v1.0 => v2.0)"
            // Pattern captures: action word, then vendor/package name
            if (preg_match('/^\s*-\s*(?:Updating|Installing|Upgrading|Downgrading|Removing)\s+([a-z0-9_.-]+\/[a-z0-9_.-]+)/i', $line, $matches)) {
                $packages[] = $matches[1];
            }
        }

        return array_unique($packages);
    }

    /**
     * Categorize updated packages into production and dev.
     *
     * @param  array<string>  $updatedPackages  List of packages being updated
     * @param  array<string>  $devPackages  List of dev packages from composer.json
     * @return array{prod: array<string>, dev: array<string>}
     */
    private function categorizePackages(array $updatedPackages, array $devPackages): array
    {
        $prod = [];
        $dev = [];

        foreach ($updatedPackages as $package) {
            if (in_array($package, $devPackages, true)) {
                $dev[] = $package;
            } else {
                $prod[] = $package;
            }
        }

        return ['prod' => $prod, 'dev' => $dev];
    }
}
