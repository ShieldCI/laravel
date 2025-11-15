<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use Illuminate\Support\Str;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
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
            docsUrl: 'https://getcomposer.org/doc/03-cli.md#install'
        );
    }

    public function shouldRun(): bool
    {
        // Only run if composer.lock exists
        return $this->composer->getLockFile() !== null;
    }

    public function getSkipReason(): string
    {
        return 'No composer.lock file found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check all dependencies (including dev)
        $allDepsOutput = $this->composer->installDryRun();

        // Check production dependencies only
        $prodDepsOutput = $this->composer->installDryRun(['--no-dev']);

        // First string match is for Composer 1 and the second one is for Composer 2.
        $nothingToUpdate = [
            'Nothing to install or update',
            'Nothing to install, update or remove',
        ];

        $allDepsUpToDate = Str::contains($allDepsOutput, $nothingToUpdate);
        $prodDepsUpToDate = Str::contains($prodDepsOutput, $nothingToUpdate);

        // If both all deps and prod deps need updates, create a single issue
        if (! $allDepsUpToDate && ! $prodDepsUpToDate) {
            $issues[] = $this->createIssue(
                message: 'Dependencies are not up-to-date',
                location: new Location('composer.lock', 1),
                severity: Severity::Medium,
                recommendation: 'Your application\'s dependencies (including production and dev) are not up-to-date. '.
                    'These may include bug fixes and/or security patches. '.
                    'Run "composer update" to update dependencies within your version constraints. '.
                    'Review the changes before deploying to production.',
                metadata: [
                    'scope' => 'all (production and dev)',
                    'composer_version_check' => 'install --dry-run',
                ]
            );
        } elseif (! $prodDepsUpToDate) {
            // Only production dependencies need updates
            $issues[] = $this->createIssue(
                message: 'Production dependencies are not up-to-date',
                location: new Location('composer.lock', 1),
                severity: Severity::Medium,
                recommendation: 'Your application\'s production dependencies are not up-to-date. '.
                    'These may include bug fixes and/or security patches. '.
                    'Run "composer update --no-dev" to update production dependencies only, '.
                    'or "composer update" to update all dependencies. '.
                    'Review the changes before deploying to production.',
                metadata: [
                    'scope' => 'production only',
                    'composer_version_check' => 'install --dry-run --no-dev',
                ]
            );
        } elseif (! $allDepsUpToDate) {
            // Only dev dependencies need updates (production is up-to-date)
            $issues[] = $this->createIssue(
                message: 'Development dependencies are not up-to-date',
                location: new Location('composer.lock', 1),
                severity: Severity::Low,
                recommendation: 'Your application\'s development dependencies are not up-to-date. '.
                    'While these don\'t affect production, keeping them updated helps maintain a healthy development environment. '.
                    'Run "composer update" to update all dependencies.',
                metadata: [
                    'scope' => 'dev only',
                    'composer_version_check' => 'install --dry-run',
                ]
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
}
