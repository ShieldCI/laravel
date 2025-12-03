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
use ShieldCI\Support\SecurityAdvisories\AdvisoryAnalyzerInterface;
use ShieldCI\Support\SecurityAdvisories\AdvisoryFetcherInterface;
use ShieldCI\Support\SecurityAdvisories\ComposerDependencyReader;
use Throwable;

/**
 * Detects vulnerable dependencies with known security issues.
 *
 * Checks for:
 * - Composer packages with known CVEs
 * - Outdated packages with security patches
 * - Packages flagged by security advisories
 */
class VulnerableDependencyAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private AdvisoryFetcherInterface $advisoryFetcher,
        private AdvisoryAnalyzerInterface $advisoryAnalyzer,
        private ComposerDependencyReader $dependencyReader
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'vulnerable-dependencies',
            name: 'Vulnerable Dependency Analyzer',
            description: 'Scans composer dependencies for known security vulnerabilities',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['dependencies', 'composer', 'vulnerabilities', 'cve', 'security'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/vulnerable-dependencies',
            timeToFix: 60
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $composerLock = $this->buildPath('composer.lock');

        if (! file_exists($composerLock)) {
            $issues[] = $this->createIssue(
                message: 'composer.lock file not found',
                location: new Location('composer.lock', 1),
                severity: Severity::Medium,
                recommendation: 'Run "composer install" to generate composer.lock for dependency tracking.',
                code: null,
                metadata: []
            );

            return $this->failed('composer.lock file not found', $issues);
        }

        try {
            $dependencies = $this->dependencyReader->read($composerLock);
        } catch (Throwable $exception) {
            return $this->error('Unable to read composer.lock: '.$exception->getMessage());
        }

        if (empty($dependencies)) {
            $advisories = [];
        } else {
            try {
                $advisories = $this->advisoryFetcher->fetch($dependencies);
            } catch (Throwable $exception) {
                return $this->error('Unable to fetch security advisories: '.$exception->getMessage());
            }
        }

        $vulnerabilities = $this->advisoryAnalyzer->analyze($dependencies, $advisories);

        foreach ($vulnerabilities as $package => $details) {
            if (! is_string($package) || $package === '') {
                continue;
            }

            $version = isset($details['version']) && is_string($details['version'])
                ? $details['version']
                : 'unknown';

            $packageAdvisories = isset($details['advisories']) && is_array($details['advisories'])
                ? $details['advisories']
                : [];

            foreach ($packageAdvisories as $advisory) {
                if (! is_array($advisory) || empty($advisory)) {
                    continue;
                }

                // Validate advisory has at least a title
                if (! isset($advisory['title']) || ! is_string($advisory['title'])) {
                    continue;
                }

                $issues[] = $this->createIssue(
                    message: sprintf(
                        'Package "%s" (%s) has a known vulnerability: %s',
                        $package,
                        $version,
                        $advisory['title']
                    ),
                    location: new Location(
                        $this->getRelativePath($composerLock),
                        1
                    ),
                    severity: Severity::Critical,
                    recommendation: $this->formatRecommendation($package, $advisory),
                    code: FileParser::getCodeSnippet($composerLock, 1),
                    metadata: [
                        'package' => $package,
                        'version' => $version,
                        'cve' => isset($advisory['cve']) && is_string($advisory['cve']) ? $advisory['cve'] : null,
                        'link' => isset($advisory['link']) && is_string($advisory['link']) ? $advisory['link'] : null,
                        'affected_versions' => isset($advisory['affected_versions']) ? $advisory['affected_versions'] : null,
                    ]
                );
            }
        }

        $this->checkAbandonedPackages($issues, $composerLock);

        if (empty($issues)) {
            return $this->passed('No vulnerable dependencies detected');
        }

        return $this->failed(
            sprintf('Found %d dependency security issues', count($issues)),
            $issues
        );
    }

    /**
     * Check for abandoned packages in composer.lock.
     */
    private function checkAbandonedPackages(array &$issues, string $composerLock): void
    {
        $lockData = $this->parseComposerLock($composerLock);

        if ($lockData === null) {
            return;
        }

        $packages = $this->getAllPackages($lockData);

        foreach ($packages as $package) {
            if (! is_array($package) || ! isset($package['abandoned'])) {
                continue;
            }

            $packageName = isset($package['name']) && is_string($package['name'])
                ? $package['name']
                : 'Unknown';

            $replacement = is_string($package['abandoned']) && $package['abandoned'] !== ''
                ? $package['abandoned']
                : null;

            $recommendation = $replacement
                ? sprintf('Replace with "%s": composer require %s', $replacement, $replacement)
                : sprintf('Find an alternative package and remove "%s"', $packageName);

            $issues[] = $this->createIssue(
                message: sprintf('Package "%s" is abandoned and no longer maintained', $packageName),
                location: new Location(
                    $this->getRelativePath($composerLock),
                    1
                ),
                severity: Severity::Medium,
                recommendation: $recommendation,
                code: FileParser::getCodeSnippet($composerLock, 1),
                metadata: [
                    'package' => $packageName,
                    'replacement' => $replacement,
                ]
            );
        }
    }

    /**
     * @param  array<string, mixed>  $advisory
     */
    private function formatRecommendation(string $package, array $advisory): string
    {
        $recommendation = sprintf('Update "%s" to a patched version.', $package);

        if (isset($advisory['link']) && is_string($advisory['link'])) {
            $recommendation .= sprintf(' See %s for details.', $advisory['link']);
        }

        if (isset($advisory['affected_versions'])) {
            $affected = is_array($advisory['affected_versions'])
                ? implode(', ', array_map('strval', array_filter($advisory['affected_versions'], 'is_scalar')))
                : (is_string($advisory['affected_versions']) ? $advisory['affected_versions'] : null);

            if ($affected !== null && $affected !== '') {
                $recommendation .= sprintf(' Affected versions: %s.', $affected);
            }
        }

        return trim($recommendation);
    }

    /**
     * Parse composer.lock file and return the decoded array.
     *
     * @return array<string, mixed>|null
     */
    private function parseComposerLock(string $composerLock): ?array
    {
        if (! file_exists($composerLock)) {
            return null;
        }

        $content = FileParser::readFile($composerLock);

        if ($content === null) {
            return null;
        }

        $lockData = json_decode($content, true);

        if (json_last_error() !== JSON_ERROR_NONE || ! is_array($lockData)) {
            return null;
        }

        return $lockData;
    }

    /**
     * Get all packages (regular and dev) from composer.lock data.
     *
     * @param  array<string, mixed>  $lockData
     * @return array<int, mixed>
     */
    private function getAllPackages(array $lockData): array
    {
        return array_merge(
            isset($lockData['packages']) && is_array($lockData['packages']) ? $lockData['packages'] : [],
            isset($lockData['packages-dev']) && is_array($lockData['packages-dev']) ? $lockData['packages-dev'] : []
        );
    }
}
