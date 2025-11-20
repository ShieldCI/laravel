<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Validates that dependencies use stable versions rather than dev/beta/alpha.
 *
 * Checks for:
 * - Dev versions (dev-master, dev-main)
 * - Alpha/Beta/RC versions
 * - Unstable version constraints
 * - Missing prefer-stable configuration
 */
class StableDependencyAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'stable-dependencies',
            name: 'Stable Dependency Analyzer',
            description: 'Validates that all dependencies use stable versions rather than dev/alpha/beta releases',
            category: Category::Security,
            severity: Severity::Low,
            tags: ['dependencies', 'composer', 'stability', 'versions', 'production'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/stable-dependencies'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check composer.json configuration
        $composerJson = $this->basePath.'/composer.json';

        if (! file_exists($composerJson)) {
            return $this->passed('No composer.json found - skipping stability check');
        }

        $this->checkComposerConfiguration($composerJson, $issues);

        // Check composer.lock for unstable versions
        $composerLock = $this->basePath.'/composer.lock';
        if (file_exists($composerLock)) {
            $this->checkComposerLock($composerLock, $issues);
        }

        if (empty($issues)) {
            return $this->passed('All dependencies are using stable versions');
        }

        return $this->failed(
            sprintf('Found %d dependency stability issues', count($issues)),
            $issues
        );
    }

    /**
     * Check composer.json configuration.
     */
    private function checkComposerConfiguration(string $composerJson, array &$issues): void
    {
        $content = FileParser::readFile($composerJson);
        if ($content === null) {
            return;
        }

        $data = json_decode($content, true);
        if ($data === null) {
            return;
        }

        // Check minimum-stability setting
        $minimumStability = $data['minimum-stability'] ?? 'stable';

        if ($minimumStability !== 'stable') {
            $issues[] = $this->createIssue(
                message: sprintf('Composer minimum-stability is set to "%s" instead of "stable"', $minimumStability),
                location: new Location(
                    'composer.json',
                    1
                ),
                severity: Severity::Medium,
                recommendation: 'Set "minimum-stability": "stable" in composer.json to prefer stable package versions',
                code: sprintf('"minimum-stability": "%s"', $minimumStability)
            );
        }

        // Check if prefer-stable is enabled
        if (! isset($data['prefer-stable']) || $data['prefer-stable'] !== true) {
            $issues[] = $this->createIssue(
                message: 'Composer prefer-stable is not enabled',
                location: new Location(
                    'composer.json',
                    1
                ),
                severity: Severity::Low,
                recommendation: 'Set "prefer-stable": true in composer.json to prefer stable versions when possible',
                code: 'Missing "prefer-stable": true'
            );
        }

        // Check for dev version constraints in require section
        if (isset($data['require']) && is_array($data['require'])) {
            $this->checkVersionConstraints($data['require'], 'require', $issues);
        }
    }

    /**
     * Check version constraints for unstable patterns.
     */
    private function checkVersionConstraints(array $packages, string $section, array &$issues): void
    {
        foreach ($packages as $package => $version) {
            // Skip PHP and extensions
            if ($package === 'php' || str_starts_with($package, 'ext-')) {
                continue;
            }

            // Check for dev versions
            if (str_contains(strtolower($version), 'dev-')) {
                $issues[] = $this->createIssue(
                    message: sprintf('Package "%s" requires unstable dev version: %s', $package, $version),
                    location: new Location(
                        'composer.json',
                        1
                    ),
                    severity: Severity::Medium,
                    recommendation: sprintf('Update "%s" to use a stable version constraint', $package),
                    code: sprintf('"%s": "%s"', $package, $version)
                );
            }

            // Check for @dev, @alpha, @beta, @RC stability flags
            if (preg_match('/@(dev|alpha|beta|rc)/i', $version, $matches)) {
                $stability = $matches[1];
                $issues[] = $this->createIssue(
                    message: sprintf('Package "%s" requires unstable version: %s', $package, $version),
                    location: new Location(
                        'composer.json',
                        1
                    ),
                    severity: Severity::Medium,
                    recommendation: sprintf('Remove @%s flag and use stable version for "%s"', $stability, $package),
                    code: sprintf('"%s": "%s"', $package, $version)
                );
            }
        }
    }

    /**
     * Check composer.lock for unstable installed versions.
     */
    private function checkComposerLock(string $composerLock, array &$issues): void
    {
        $content = FileParser::readFile($composerLock);
        if ($content === null) {
            return;
        }

        $lockData = json_decode($content, true);

        if (! isset($lockData['packages'])) {
            return;
        }

        $unstablePackages = [];

        foreach ($lockData['packages'] as $package) {
            $packageName = $package['name'] ?? 'Unknown';
            $version = $package['version'] ?? '';

            // Check for dev versions
            if (str_starts_with($version, 'dev-')) {
                $unstablePackages[] = sprintf('%s (%s)', $packageName, $version);
            }

            // Check for alpha/beta/RC versions
            if (preg_match('/(alpha|beta|rc)/i', $version)) {
                $unstablePackages[] = sprintf('%s (%s)', $packageName, $version);
            }
        }

        if (! empty($unstablePackages)) {
            $count = count($unstablePackages);
            $examples = implode(', ', array_slice($unstablePackages, 0, 3));

            $issues[] = $this->createIssue(
                message: sprintf('Found %d unstable package versions installed', $count),
                location: new Location(
                    'composer.lock',
                    1
                ),
                severity: Severity::Low,
                recommendation: sprintf(
                    'Update to stable versions: %s%s. Run "composer update --prefer-stable"',
                    $examples,
                    $count > 3 ? sprintf(' and %d more', $count - 3) : ''
                ),
                code: sprintf('Unstable packages: %s', $examples)
            );
        }
    }
}
