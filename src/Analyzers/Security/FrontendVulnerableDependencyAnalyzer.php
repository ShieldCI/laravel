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
 * Detects vulnerable frontend dependencies (npm/yarn) with known security issues.
 *
 * Checks for:
 * - NPM packages with known CVEs
 * - Yarn packages with security vulnerabilities
 * - Outdated frontend packages with security patches
 */
class FrontendVulnerableDependencyAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'frontend-vulnerable-dependencies',
            name: 'Frontend Vulnerable Dependency Analyzer',
            description: 'Scans npm/yarn dependencies for known security vulnerabilities',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['dependencies', 'npm', 'yarn', 'vulnerabilities', 'frontend', 'javascript'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/frontend-vulnerable-dependencies'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check if package.json exists
        $packageJson = $this->basePath.'/package.json';

        if (! file_exists($packageJson)) {
            return $this->passed('No package.json found - skipping frontend dependency check');
        }

        // Check if package-lock.json or yarn.lock exists
        $hasPackageLock = file_exists($this->basePath.'/package-lock.json');
        $hasYarnLock = file_exists($this->basePath.'/yarn.lock');

        if (! $hasPackageLock && ! $hasYarnLock) {
            $issues[] = $this->createIssue(
                message: 'No package-lock.json or yarn.lock found',
                location: new Location(
                    'package.json',
                    1
                ),
                severity: Severity::Medium,
                recommendation: 'Run "npm install" or "yarn install" to generate lock file for dependency tracking',
                code: 'Missing lock file'
            );

            return $this->failed('Frontend dependency lock file not found', $issues);
        }

        // Run npm audit or yarn audit
        if ($hasPackageLock) {
            $auditResults = $this->runNpmAudit();
            if ($auditResults !== null) {
                $this->parseNpmAuditResults($auditResults, $issues);
            }
        } elseif ($hasYarnLock) {
            $auditResults = $this->runYarnAudit();
            if ($auditResults !== null) {
                $this->parseYarnAuditResults($auditResults, $issues);
            }
        }

        if (empty($issues)) {
            return $this->passed('No vulnerable frontend dependencies detected');
        }

        return $this->failed(
            sprintf('Found %d frontend dependency security issues', count($issues)),
            $issues
        );
    }

    /**
     * Run npm audit command.
     */
    private function runNpmAudit(): ?array
    {
        // Change to the base directory
        $originalDir = getcwd();
        chdir($this->basePath);

        // Run npm audit with JSON output
        $output = shell_exec('npm audit --json 2>&1');

        // Change back to original directory
        chdir($originalDir);

        if ($output === null) {
            return null;
        }

        // Try to decode JSON output
        $result = json_decode($output, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            // If JSON parsing fails, try to parse plain text output
            return $this->parseNpmPlainTextAudit($output);
        }

        return $result;
    }

    /**
     * Parse plain text npm audit output as fallback.
     */
    private function parseNpmPlainTextAudit(string $output): ?array
    {
        $result = ['vulnerabilities' => []];

        // Look for vulnerability patterns in output
        if (preg_match('/(\d+)\s+vulnerabilit/i', $output, $matches)) {
            $count = (int) $matches[1];
            if ($count > 0) {
                $result['metadata'] = [
                    'vulnerabilities' => [
                        'total' => $count,
                    ],
                ];
            }
        }

        return empty($result['metadata']) ? null : $result;
    }

    /**
     * Parse npm audit results.
     */
    private function parseNpmAuditResults(array $results, array &$issues): void
    {
        if (empty($results)) {
            return;
        }

        // Check for vulnerabilities in the result (npm v7+)
        if (isset($results['vulnerabilities']) && is_array($results['vulnerabilities'])) {
            foreach ($results['vulnerabilities'] as $package => $vulnerability) {
                $this->createFrontendVulnerabilityIssue($package, $vulnerability, $issues);
            }
        }

        // Check for advisories (npm v6)
        if (isset($results['advisories']) && is_array($results['advisories'])) {
            foreach ($results['advisories'] as $advisory) {
                if (isset($advisory['module_name'])) {
                    $this->createFrontendVulnerabilityIssue($advisory['module_name'], $advisory, $issues);
                }
            }
        }

        // Check for metadata summary
        if (isset($results['metadata']['vulnerabilities'])) {
            $vulns = $results['metadata']['vulnerabilities'];
            $total = $vulns['total'] ?? 0;

            if ($total > 0 && empty($issues)) {
                $issues[] = $this->createIssue(
                    message: sprintf('Found %d frontend package vulnerabilities', $total),
                    location: new Location(
                        'package-lock.json',
                        1
                    ),
                    severity: Severity::Critical,
                    recommendation: 'Run "npm audit" to see details and "npm audit fix" to automatically fix vulnerabilities',
                    code: sprintf('Total vulnerabilities: %d', $total)
                );
            }
        }
    }

    /**
     * Run yarn audit command.
     */
    private function runYarnAudit(): ?array
    {
        // Change to the base directory
        $originalDir = getcwd();
        chdir($this->basePath);

        // Run yarn audit with JSON output
        $output = shell_exec('yarn audit --json 2>&1');

        // Change back to original directory
        chdir($originalDir);

        if ($output === null) {
            return null;
        }

        // Yarn outputs newline-delimited JSON
        $lines = array_filter(explode("\n", $output));
        $result = ['advisories' => []];

        foreach ($lines as $line) {
            $decoded = json_decode($line, true);
            if (json_last_error() === JSON_ERROR_NONE && isset($decoded['type'])) {
                if ($decoded['type'] === 'auditAdvisory' && isset($decoded['data']['advisory'])) {
                    $result['advisories'][] = $decoded['data']['advisory'];
                } elseif ($decoded['type'] === 'auditSummary' && isset($decoded['data'])) {
                    $result['summary'] = $decoded['data'];
                }
            }
        }

        return empty($result['advisories']) && empty($result['summary']) ? null : $result;
    }

    /**
     * Parse yarn audit results.
     */
    private function parseYarnAuditResults(array $results, array &$issues): void
    {
        if (empty($results)) {
            return;
        }

        // Parse advisories
        if (isset($results['advisories']) && is_array($results['advisories'])) {
            foreach ($results['advisories'] as $advisory) {
                $package = $advisory['module_name'] ?? 'Unknown';
                $this->createFrontendVulnerabilityIssue($package, $advisory, $issues);
            }
        }

        // Check summary
        if (isset($results['summary']['vulnerabilities'])) {
            $total = $results['summary']['vulnerabilities'];
            if ($total > 0 && empty($issues)) {
                $issues[] = $this->createIssue(
                    message: sprintf('Found %d frontend package vulnerabilities', $total),
                    location: new Location(
                        'yarn.lock',
                        1
                    ),
                    severity: Severity::Critical,
                    recommendation: 'Run "yarn audit" to see details and upgrade vulnerable packages',
                    code: sprintf('Total vulnerabilities: %d', $total)
                );
            }
        }
    }

    /**
     * Create vulnerability issue from advisory data.
     */
    private function createFrontendVulnerabilityIssue(string $package, mixed $advisory, array &$issues): void
    {
        $message = is_array($advisory) && isset($advisory['title'])
            ? $advisory['title']
            : 'Known security vulnerability';

        $severity = Severity::Critical;
        if (is_array($advisory) && isset($advisory['severity'])) {
            $severity = match (strtolower($advisory['severity'])) {
                'critical' => Severity::Critical,
                'high' => Severity::High,
                'moderate' => Severity::Medium,
                'low' => Severity::Low,
                default => Severity::Critical,
            };
        }

        $recommendation = is_array($advisory) && isset($advisory['recommendation'])
            ? $advisory['recommendation']
            : sprintf('Update package "%s" to a patched version', $package);

        $issues[] = $this->createIssue(
            message: sprintf('Frontend package "%s" has a known vulnerability: %s', $package, $message),
            location: new Location(
                file_exists($this->basePath.'/package-lock.json') ? 'package-lock.json' : 'yarn.lock',
                1
            ),
            severity: $severity,
            recommendation: $recommendation,
            code: sprintf('Vulnerable package: %s', $package)
        );
    }
}
