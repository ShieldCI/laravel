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
use ShieldCI\Support\Composer;
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
            name: 'Vulnerable Dependencies Analyzer',
            description: 'Scans composer dependencies for known security vulnerabilities',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['dependencies', 'composer', 'vulnerabilities', 'cve', 'security'],
            timeToFix: 60
        );
    }

    public function shouldRun(): bool
    {
        $composerLock = $this->buildPath('composer.lock');

        return file_exists($composerLock);
    }

    public function getSkipReason(): string
    {
        return 'No composer.lock file found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $composerLock = $this->buildPath('composer.lock');

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
        if (! is_array($vulnerabilities)) {
            return $this->error('Invalid advisory analysis result');
        }

        // Cache for package line numbers to avoid repeated lookups
        // Key: package name, Value: line number
        $lineNumberCache = [];

        // Aggregate advisories per package to avoid flooding output with multiple issues
        // for the same package (e.g., a package with 5 CVEs creates 5 issues → now 1 issue)
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

            // Filter out invalid advisories
            $validAdvisories = array_filter($packageAdvisories, function ($advisory) {
                return is_array($advisory)
                    && ! empty($advisory)
                    && isset($advisory['title'])
                    && is_string($advisory['title']);
            });

            if (empty($validAdvisories)) {
                continue;
            }

            $lineNumber = $this->getPackageLineNumber($composerLock, $package, $lineNumberCache);
            $advisoryCount = count($validAdvisories);

            // Build aggregated message
            $message = $advisoryCount === 1
                ? sprintf('Package "%s" (%s) has a known vulnerability', $package, $version)
                : sprintf('Package "%s" (%s) has %d known vulnerabilities', $package, $version, $advisoryCount);

            // Build comprehensive recommendation mentioning all CVEs
            $recommendation = $this->formatAggregatedRecommendation($package, $validAdvisories, $version);

            // Extract all CVEs and links for metadata
            $cves = [];
            $links = [];
            $advisoriesMetadata = [];

            foreach ($validAdvisories as $advisory) {
                if (isset($advisory['cve']) && is_string($advisory['cve']) && $advisory['cve'] !== '') {
                    $cves[] = $advisory['cve'];
                }
                if (isset($advisory['link']) && is_string($advisory['link']) && $advisory['link'] !== '') {
                    $links[] = $advisory['link'];
                }

                // Store full advisory details
                $advisoriesMetadata[] = [
                    'title' => $advisory['title'] ?? '',
                    'cve' => $advisory['cve'] ?? null,
                    'link' => $advisory['link'] ?? null,
                    'affected_versions' => $advisory['affected_versions'] ?? null,
                ];
            }

            $issues[] = $this->createIssue(
                message: $message,
                location: new Location($this->getRelativePath($composerLock), $lineNumber),
                severity: Severity::Critical,
                recommendation: $recommendation,
                code: FileParser::getCodeSnippet($composerLock, $lineNumber),
                metadata: [
                    'package' => $package,
                    'version' => $version,
                    'vulnerability_count' => $advisoryCount,
                    'cves' => array_unique($cves),
                    'links' => array_unique($links),
                    'advisories' => $advisoriesMetadata,
                ]
            );
        }

        $this->checkAbandonedPackages($issues, $composerLock, $lineNumberCache);

        if (empty($issues)) {
            return $this->passed('No vulnerable dependencies detected');
        }

        return $this->resultBySeverity(
            sprintf('Found %d dependency security issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Check for abandoned packages in composer.lock.
     *
     * @param  array<string, int>  $lineNumberCache  Cache of package line numbers
     */
    private function checkAbandonedPackages(array &$issues, string $composerLock, array &$lineNumberCache): void
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

            $lineNumber = $this->getPackageLineNumber($composerLock, $packageName, $lineNumberCache);

            $issues[] = $this->createIssue(
                message: sprintf('Package "%s" is abandoned and no longer maintained', $packageName),
                location: new Location($this->getRelativePath($composerLock), $lineNumber),
                severity: Severity::Medium,
                recommendation: $recommendation,
                code: FileParser::getCodeSnippet($composerLock, $lineNumber),
                metadata: [
                    'package' => $packageName,
                    'replacement' => $replacement,
                ]
            );
        }
    }

    /**
     * Get package line number with caching to avoid repeated lookups.
     *
     * Line number lookups involve parsing composer.lock, which is expensive.
     * Cache results to avoid repeated lookups for the same package.
     *
     * @param  array<string, int>  $cache  Cache reference (modified by this method)
     */
    private function getPackageLineNumber(string $composerLock, string $packageName, array &$cache): int
    {
        // Check cache first
        if (isset($cache[$packageName])) {
            return $cache[$packageName];
        }

        // Cache miss - perform lookup and store result
        $lineNumber = Composer::findPackageLineNumber($composerLock, $packageName);
        $cache[$packageName] = $lineNumber;

        return $lineNumber;
    }

    /**
     * Format aggregated recommendation for multiple advisories affecting the same package.
     *
     * @param  array<int, array<string, mixed>>  $advisories
     */
    private function formatAggregatedRecommendation(string $package, array $advisories, string $version): string
    {
        $recommendation = sprintf('Update "%s" (currently %s) to a patched version.', $package, $version);

        // Extract and list all CVEs
        $cves = [];
        foreach ($advisories as $advisory) {
            if (isset($advisory['cve']) && is_string($advisory['cve']) && $advisory['cve'] !== '') {
                $cves[] = $advisory['cve'];
            }
        }

        if (! empty($cves)) {
            $cveList = implode(', ', array_unique($cves));
            $recommendation .= sprintf(' Known CVEs: %s.', $cveList);
        }

        // List vulnerability titles for context
        $titles = [];
        foreach ($advisories as $advisory) {
            if (isset($advisory['title']) && is_string($advisory['title'])) {
                $titles[] = $advisory['title'];
            }
        }

        if (! empty($titles)) {
            $recommendation .= ' Vulnerabilities: '.implode('; ', array_slice($titles, 0, 3));
            if (count($titles) > 3) {
                $recommendation .= sprintf(' (and %d more)', count($titles) - 3);
            }
            $recommendation .= '.';
        }

        // Add primary advisory link if available
        foreach ($advisories as $advisory) {
            if (isset($advisory['link']) && is_string($advisory['link'])) {
                $recommendation .= sprintf(' See %s for details.', $advisory['link']);
                break; // Only show first link to keep recommendation concise
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
