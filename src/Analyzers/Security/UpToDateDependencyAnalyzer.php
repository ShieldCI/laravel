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
     * Composer output patterns indicating no updates needed.
     * First string is for Composer 1, second is for Composer 2.
     *
     * @var array<string>
     */
    private const NOTHING_TO_UPDATE_PATTERNS = [
        'Nothing to install or update',
        'Nothing to install, update or remove',
    ];

    public function __construct(
        private Composer $composer
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'up-to-date-dependencies',
            name: 'Up-to-Date Dependency Analyzer',
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
        return $this->composer->getLockFile() !== null
            || $this->composer->getJsonFile() !== null;
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
                    location: new Location('composer.lock', 1),
                    severity: Severity::Medium,
                    recommendation: 'Run "composer install" to generate composer.lock for dependency tracking.',
                    metadata: []
                )]
            );
        }

        $issues = [];

        try {
            // Check all dependencies (including dev)
            $allDepsOutput = $this->composer->installDryRun();

            // Check production dependencies only
            $prodDepsOutput = $this->composer->installDryRun(['--no-dev']);

            // Validate outputs are strings
            if (! is_string($allDepsOutput) || ! is_string($prodDepsOutput)) {
                return $this->error('Unable to check dependency status - Composer command failed');
            }

            $allDepsUpToDate = $this->isUpToDate($allDepsOutput);
            $prodDepsUpToDate = $this->isUpToDate($prodDepsOutput);

            // If both all deps and prod deps need updates, create a single issue
            if (! $allDepsUpToDate && ! $prodDepsUpToDate) {
                $issues[] = $this->createIssue(
                    message: 'Dependencies are not up-to-date',
                    location: new Location($composerLockPath, 1),
                    severity: Severity::Medium,
                    recommendation: $this->getAllDepsRecommendation(),
                    code: FileParser::getCodeSnippet($composerLockPath, 1),
                    metadata: [
                        'scope' => 'all (production and dev)',
                        'composer_version_check' => 'install --dry-run',
                    ]
                );
            } elseif (! $prodDepsUpToDate) {
                // Only production dependencies need updates
                $issues[] = $this->createIssue(
                    message: 'Production dependencies are not up-to-date',
                    location: new Location($composerLockPath, 1),
                    severity: Severity::Medium,
                    recommendation: $this->getProductionDepsRecommendation(),
                    code: FileParser::getCodeSnippet($composerLockPath, 1),
                    metadata: [
                        'scope' => 'production only',
                        'composer_version_check' => 'install --dry-run --no-dev',
                    ]
                );
            } elseif (! $allDepsUpToDate) {
                // Only dev dependencies need updates (production is up-to-date)
                $issues[] = $this->createIssue(
                    message: 'Development dependencies are not up-to-date',
                    location: new Location($composerLockPath, 1),
                    severity: Severity::Low,
                    recommendation: $this->getDevDepsRecommendation(),
                    code: FileParser::getCodeSnippet($composerLockPath, 1),
                    metadata: [
                        'scope' => 'dev only',
                        'composer_version_check' => 'install --dry-run',
                    ]
                );
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

        return $this->failed(
            sprintf('Found %d dependency update issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Check if Composer output indicates dependencies are up-to-date.
     */
    private function isUpToDate(string $output): bool
    {
        foreach (self::NOTHING_TO_UPDATE_PATTERNS as $pattern) {
            if (str_contains($output, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get recommendation message for all dependencies (production and dev).
     */
    private function getAllDepsRecommendation(): string
    {
        return 'Your application\'s dependencies (including production and dev) are not up-to-date. '.
            'These may include bug fixes and/or security patches. '.
            'Run "composer update" to update dependencies within your version constraints. '.
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
