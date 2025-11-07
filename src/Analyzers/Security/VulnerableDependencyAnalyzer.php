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
 * Detects vulnerable dependencies with known security issues.
 *
 * Checks for:
 * - Composer packages with known CVEs
 * - Outdated packages with security patches
 * - Packages flagged by security advisories
 */
class VulnerableDependencyAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'vulnerable-dependencies',
            name: 'Vulnerable Dependency Analyzer',
            description: 'Scans composer dependencies for known security vulnerabilities',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['dependencies', 'composer', 'vulnerabilities', 'cve', 'security'],
            docsUrl: 'https://getcomposer.org/doc/articles/scripts.md#command-events'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check if composer.lock exists
        $composerLock = $this->basePath.'/composer.lock';

        if (! file_exists($composerLock)) {
            $issues[] = $this->createIssue(
                message: 'composer.lock file not found',
                location: new Location(
                    'composer.lock',
                    1
                ),
                severity: Severity::Medium,
                recommendation: 'Run "composer install" to generate composer.lock for dependency tracking',
                code: 'Missing composer.lock'
            );

            return $this->failed('composer.lock file not found', $issues);
        }

        // Run composer audit to check for vulnerabilities
        $auditResults = $this->runComposerAudit();

        if ($auditResults !== null) {
            $this->parseAuditResults($auditResults, $issues);
        }

        // Check for abandoned packages
        $this->checkAbandonedPackages($issues);

        if (empty($issues)) {
            return $this->passed('No vulnerable dependencies detected');
        }

        return $this->failed(
            sprintf('Found %d dependency security issues', count($issues)),
            $issues
        );
    }

    /**
     * Run composer audit command.
     */
    private function runComposerAudit(): ?array
    {
        // Change to the base directory
        $originalDir = getcwd();
        chdir($this->basePath);

        // Run composer audit with JSON output
        $output = shell_exec('composer audit --format=json 2>&1');

        // Change back to original directory
        chdir($originalDir);

        if ($output === null) {
            return null;
        }

        // Try to decode JSON output
        $result = json_decode($output, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            // If JSON parsing fails, try to parse plain text output
            return $this->parsePlainTextAudit($output);
        }

        return $result;
    }

    /**
     * Parse plain text audit output as fallback.
     */
    private function parsePlainTextAudit(string $output): ?array
    {
        $result = ['advisories' => []];

        // Look for vulnerability patterns in output
        if (preg_match('/(\d+)\s+package.*vulnerabilit/i', $output, $matches)) {
            $count = (int) $matches[1];
            if ($count > 0) {
                $result['advisories']['summary'] = [
                    'message' => "Found {$count} packages with known vulnerabilities",
                ];
            }
        }

        return empty($result['advisories']) ? null : $result;
    }

    /**
     * Parse composer audit results.
     */
    private function parseAuditResults(array $results, array &$issues): void
    {
        if (empty($results)) {
            return;
        }

        // Check for advisories in the result
        $advisories = $results['advisories'] ?? [];

        foreach ($advisories as $package => $advisory) {
            if (is_array($advisory)) {
                // Multiple advisories for same package
                foreach ($advisory as $item) {
                    $this->createVulnerabilityIssue($package, $item, $issues);
                }
            } else {
                // Single advisory
                $this->createVulnerabilityIssue($package, $advisory, $issues);
            }
        }

        // Also check for summary information
        if (isset($results['summary'])) {
            $this->parseSummary($results['summary'], $issues);
        }
    }

    /**
     * Create vulnerability issue from advisory data.
     */
    private function createVulnerabilityIssue(string $package, mixed $advisory, array &$issues): void
    {
        $message = is_array($advisory) && isset($advisory['title'])
            ? $advisory['title']
            : 'Known security vulnerability';

        $cve = is_array($advisory) && isset($advisory['cve'])
            ? $advisory['cve']
            : 'Unknown CVE';

        $affectedVersions = is_array($advisory) && isset($advisory['affectedVersions'])
            ? $advisory['affectedVersions']
            : 'Unknown version';

        $issues[] = $this->createIssue(
            message: sprintf('Package "%s" has a known vulnerability: %s', $package, $message),
            location: new Location(
                'composer.lock',
                1
            ),
            severity: Severity::Critical,
            recommendation: sprintf(
                'Update package "%s" (affected versions: %s). CVE: %s. Run "composer update %s"',
                $package,
                $affectedVersions,
                $cve,
                $package
            ),
            code: sprintf('Vulnerable package: %s', $package)
        );
    }

    /**
     * Parse summary information.
     */
    private function parseSummary(mixed $summary, array &$issues): void
    {
        if (is_array($summary) && isset($summary['message'])) {
            $issues[] = $this->createIssue(
                message: $summary['message'],
                location: new Location(
                    'composer.lock',
                    1
                ),
                severity: Severity::Critical,
                recommendation: 'Review composer audit output and update vulnerable packages',
                code: 'Run: composer audit --format=json'
            );
        }
    }

    /**
     * Check for abandoned packages in composer.lock.
     */
    private function checkAbandonedPackages(array &$issues): void
    {
        $composerLock = $this->basePath.'/composer.lock';
        $content = FileParser::readFile($composerLock);

        if ($content === null) {
            return;
        }

        $lockData = json_decode($content, true);

        if (! isset($lockData['packages'])) {
            return;
        }

        foreach ($lockData['packages'] as $package) {
            if (isset($package['abandoned'])) {
                $packageName = $package['name'] ?? 'Unknown';
                $replacement = is_string($package['abandoned']) ? $package['abandoned'] : null;

                $recommendation = $replacement
                    ? sprintf('Replace with "%s": composer require %s', $replacement, $replacement)
                    : sprintf('Find an alternative package and remove "%s"', $packageName);

                $issues[] = $this->createIssue(
                    message: sprintf('Package "%s" is abandoned and no longer maintained', $packageName),
                    location: new Location(
                        'composer.lock',
                        1
                    ),
                    severity: Severity::Medium,
                    recommendation: $recommendation,
                    code: sprintf('Abandoned: %s', $packageName)
                );
            }
        }
    }
}
