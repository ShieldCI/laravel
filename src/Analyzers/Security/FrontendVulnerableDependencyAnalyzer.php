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
            docsUrl: 'https://docs.shieldci.com/analyzers/security/frontend-vulnerable-dependencies',
            timeToFix: 60
        );
    }

    public function shouldRun(): bool
    {
        $packageJson = $this->buildPath('package.json');

        return file_exists($packageJson);
    }

    public function getSkipReason(): string
    {
        return 'No package.json found - not a frontend project';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check if package-lock.json or yarn.lock exists
        $packageLock = $this->buildPath('package-lock.json');
        $yarnLock = $this->buildPath('yarn.lock');
        $hasPackageLock = file_exists($packageLock);
        $hasYarnLock = file_exists($yarnLock);

        if (! $hasPackageLock && ! $hasYarnLock) {
            $packageJson = $this->buildPath('package.json');
            $issues[] = $this->createIssue(
                message: 'No package-lock.json or yarn.lock found',
                location: new Location(
                    $this->getRelativePath($packageJson),
                    1
                ),
                severity: Severity::Medium,
                recommendation: 'Run "npm install" or "yarn install" to generate lock file for dependency tracking',
                code: FileParser::getCodeSnippet($packageJson, 1),
                metadata: [
                    'issue_type' => 'missing_lock_file',
                ]
            );

            return $this->resultBySeverity(
                'Frontend dependency lock file not found',
                $issues
            );
        }

        // Run npm audit or yarn audit
        $basePath = $this->getBasePath();

        if ($hasPackageLock) {
            $auditResults = $this->runAuditCommand($basePath, 'npm');
            if ($auditResults !== null) {
                $this->parseNpmAuditResults($auditResults, $issues, $packageLock);
            }
        } elseif ($hasYarnLock) {
            $auditResults = $this->runAuditCommand($basePath, 'yarn');
            if ($auditResults !== null) {
                $this->parseYarnAuditResults($auditResults, $issues, $yarnLock);
            }
        }

        $summary = empty($issues)
            ? 'No vulnerable frontend dependencies detected'
            : sprintf('Found %d frontend dependency security issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Run audit command (npm or yarn) with timeout protection.
     */
    private function runAuditCommand(string $basePath, string $tool): ?array
    {
        $currentDir = getcwd();
        if ($currentDir === false) {
            return null;
        }

        try {
            // Change to the base directory
            if (! @chdir($basePath)) {
                return null;
            }

            // Build command
            $command = $tool === 'npm' ? 'npm audit --json 2>&1' : 'yarn audit --json 2>&1';

            // Use proc_open for timeout control
            $descriptors = [
                0 => ['pipe', 'r'],  // stdin
                1 => ['pipe', 'w'],  // stdout
                2 => ['pipe', 'w'],  // stderr
            ];

            $process = proc_open($command, $descriptors, $pipes);

            if (! is_resource($process)) {
                return null;
            }

            // Close stdin
            fclose($pipes[0]);

            // Set timeout (60 seconds)
            $timeout = 60;
            $start = time();
            $output = '';

            // Read output with timeout
            stream_set_blocking($pipes[1], false);
            while (! feof($pipes[1])) {
                if (time() - $start > $timeout) {
                    // Timeout - kill process
                    proc_terminate($process);
                    fclose($pipes[1]);
                    fclose($pipes[2]);
                    proc_close($process);

                    return null;
                }

                $chunk = fread($pipes[1], 8192);
                if ($chunk !== false) {
                    $output .= $chunk;
                }

                usleep(100000); // 0.1 second
            }

            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);

            if ($output === '') {
                return null;
            }

            // Parse based on tool
            if ($tool === 'npm') {
                return $this->parseNpmOutput($output);
            } else {
                return $this->parseYarnOutput($output);
            }
        } catch (\Throwable $e) {
            // Log failure if logger is available
            if (function_exists('logger')) {
                $logger = logger();
                if ($logger !== null) {
                    $logger->debug("Frontend dependency audit failed: {$e->getMessage()}", [
                        'tool' => $tool,
                        'base_path' => $basePath,
                    ]);
                }
            }

            return null;
        } finally {
            // Always restore the original directory
            @chdir($currentDir);
        }
    }

    /**
     * Parse npm output (JSON or plain text fallback).
     */
    private function parseNpmOutput(string $output): ?array
    {
        // Try to decode JSON output
        $result = json_decode($output, true);

        if (json_last_error() === JSON_ERROR_NONE && is_array($result)) {
            return $result;
        }

        // Fallback to plain text parsing
        return $this->parseNpmPlainTextAudit($output);
    }

    /**
     * Parse yarn output (newline-delimited JSON).
     */
    private function parseYarnOutput(string $output): ?array
    {
        // Yarn outputs newline-delimited JSON
        $lines = array_filter(explode("\n", $output));
        $result = ['advisories' => []];

        foreach ($lines as $line) {
            if (! is_string($line) || $line === '') {
                continue;
            }

            $decoded = json_decode($line, true);

            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded) && isset($decoded['type']) && is_string($decoded['type'])) {
                if ($decoded['type'] === 'auditAdvisory' && isset($decoded['data']['advisory']) && is_array($decoded['data']['advisory'])) {
                    $result['advisories'][] = $decoded['data']['advisory'];
                } elseif ($decoded['type'] === 'auditSummary' && isset($decoded['data']) && is_array($decoded['data'])) {
                    $result['summary'] = $decoded['data'];
                }
            }
        }

        return empty($result['advisories']) && empty($result['summary']) ? null : $result;
    }

    /**
     * Parse plain text npm audit output as fallback.
     */
    private function parseNpmPlainTextAudit(string $output): ?array
    {
        $result = ['vulnerabilities' => []];

        // Look for vulnerability patterns in output
        if (preg_match('/(\d+)\s+vulnerabilit/i', $output, $matches)) {
            if (is_numeric($matches[1])) {
                $count = (int) $matches[1];
                if ($count > 0) {
                    $result['metadata'] = [
                        'vulnerabilities' => [
                            'total' => $count,
                        ],
                    ];
                }
            }
        }

        return empty($result['metadata']) ? null : $result;
    }

    /**
     * Parse npm audit results.
     */
    private function parseNpmAuditResults(array $results, array &$issues, string $packageLock): void
    {
        if (empty($results)) {
            return;
        }

        $detailedIssuesCreated = false;

        // Check for vulnerabilities in the result (npm v7+)
        if (isset($results['vulnerabilities']) && is_array($results['vulnerabilities'])) {
            foreach ($results['vulnerabilities'] as $package => $vulnerability) {
                if (is_string($package) && is_array($vulnerability)) {
                    $this->createFrontendVulnerabilityIssue($package, $vulnerability, $issues, $packageLock);
                    $detailedIssuesCreated = true;
                }
            }
        }

        // Check for advisories (npm v6)
        if (isset($results['advisories']) && is_array($results['advisories'])) {
            foreach ($results['advisories'] as $advisory) {
                if (is_array($advisory) && isset($advisory['module_name']) && is_string($advisory['module_name'])) {
                    $this->createFrontendVulnerabilityIssue($advisory['module_name'], $advisory, $issues, $packageLock);
                    $detailedIssuesCreated = true;
                }
            }
        }

        // Only create summary issue if no detailed issues were created
        if (! $detailedIssuesCreated && isset($results['metadata']['vulnerabilities']) && is_array($results['metadata']['vulnerabilities'])) {
            $vulns = $results['metadata']['vulnerabilities'];
            $total = isset($vulns['total']) && is_numeric($vulns['total']) ? (int) $vulns['total'] : 0;

            if ($total > 0) {
                // Determine severity from breakdown
                $severity = $this->determineSeverityFromSummary($vulns);

                $issues[] = $this->createIssue(
                    message: sprintf('Found %d frontend package vulnerabilities', $total),
                    location: new Location(
                        $this->getRelativePath($packageLock),
                        1
                    ),
                    severity: $severity,
                    recommendation: 'Run "npm audit" to see details and "npm audit fix" to automatically fix vulnerabilities',
                    code: FileParser::getCodeSnippet($packageLock, 1),
                    metadata: [
                        'total_vulnerabilities' => $total,
                        'issue_type' => 'summary',
                        'breakdown' => $vulns,
                    ]
                );
            }
        }
    }

    /**
     * Parse yarn audit results.
     */
    private function parseYarnAuditResults(array $results, array &$issues, string $yarnLock): void
    {
        if (empty($results)) {
            return;
        }

        $detailedIssuesCreated = false;

        // Parse advisories
        if (isset($results['advisories']) && is_array($results['advisories'])) {
            foreach ($results['advisories'] as $advisory) {
                if (! is_array($advisory)) {
                    continue;
                }

                $package = isset($advisory['module_name']) && is_string($advisory['module_name'])
                    ? $advisory['module_name']
                    : 'Unknown';

                $this->createFrontendVulnerabilityIssue($package, $advisory, $issues, $yarnLock);
                $detailedIssuesCreated = true;
            }
        }

        // Only create summary issue if no detailed issues were created
        if (! $detailedIssuesCreated && isset($results['summary']['vulnerabilities']) && is_numeric($results['summary']['vulnerabilities'])) {
            $total = (int) $results['summary']['vulnerabilities'];
            if ($total > 0) {
                // Use High severity for summaries (less severe than always Critical)
                $issues[] = $this->createIssue(
                    message: sprintf('Found %d frontend package vulnerabilities', $total),
                    location: new Location(
                        $this->getRelativePath($yarnLock),
                        1
                    ),
                    severity: Severity::High,
                    recommendation: 'Run "yarn audit" to see details and upgrade vulnerable packages',
                    code: FileParser::getCodeSnippet($yarnLock, 1),
                    metadata: [
                        'total_vulnerabilities' => $total,
                        'issue_type' => 'summary',
                    ]
                );
            }
        }
    }

    /**
     * Determine severity from summary breakdown.
     *
     * @param  array<string, mixed>  $vulnerabilities
     */
    private function determineSeverityFromSummary(array $vulnerabilities): Severity
    {
        $critical = isset($vulnerabilities['critical']) && is_numeric($vulnerabilities['critical'])
            ? (int) $vulnerabilities['critical']
            : 0;
        $high = isset($vulnerabilities['high']) && is_numeric($vulnerabilities['high'])
            ? (int) $vulnerabilities['high']
            : 0;
        $moderate = isset($vulnerabilities['moderate']) && is_numeric($vulnerabilities['moderate'])
            ? (int) $vulnerabilities['moderate']
            : 0;

        if ($critical > 0) {
            return Severity::Critical;
        }

        if ($high > 0) {
            return Severity::High;
        }

        if ($moderate > 0) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Create vulnerability issue from advisory data.
     */
    private function createFrontendVulnerabilityIssue(string $package, mixed $advisory, array &$issues, string $lockFile): void
    {
        if (! is_array($advisory)) {
            return;
        }

        // Check if package or advisory is ignored in configuration
        $config = $this->getConfiguration();

        /** @var array<int, string> $ignoredPackages */
        $ignoredPackages = $config['ignored_packages'];
        if (in_array($package, $ignoredPackages)) {
            return;
        }

        $advisoryId = $advisory['id'] ?? $advisory['github_advisory_id'] ?? null;
        /** @var array<int, string> $ignoredAdvisories */
        $ignoredAdvisories = $config['ignored_advisories'];
        if ($advisoryId && in_array($advisoryId, $ignoredAdvisories)) {
            return;
        }

        $message = isset($advisory['title']) && is_string($advisory['title'])
            ? $advisory['title']
            : 'Known security vulnerability';

        $severity = Severity::Critical;
        if (isset($advisory['severity']) && is_string($advisory['severity'])) {
            $severity = match (strtolower($advisory['severity'])) {
                'critical' => Severity::Critical,
                'high' => Severity::High,
                'moderate' => Severity::Medium,
                'low' => Severity::Low,
                default => Severity::Critical,
            };
        }

        $recommendation = isset($advisory['recommendation']) && is_string($advisory['recommendation'])
            ? $advisory['recommendation']
            : sprintf('Update package "%s" to a patched version', $package);

        // Extract metadata
        $metadata = [
            'package' => $package,
            'severity' => $advisory['severity'] ?? 'unknown',
            'issue_type' => 'vulnerability',
        ];

        // Add CVE/CWE if available
        if (isset($advisory['cves']) && is_array($advisory['cves'])) {
            $metadata['cves'] = $advisory['cves'];
        }

        if (isset($advisory['cwe']) && is_string($advisory['cwe'])) {
            $metadata['cwe'] = $advisory['cwe'];
        }

        // Add version information
        if (isset($advisory['vulnerable_versions']) && is_string($advisory['vulnerable_versions'])) {
            $metadata['vulnerable_versions'] = $advisory['vulnerable_versions'];
        }

        if (isset($advisory['patched_versions']) && is_string($advisory['patched_versions'])) {
            $metadata['patched_versions'] = $advisory['patched_versions'];
        }

        // Add advisory URL
        if (isset($advisory['url']) && is_string($advisory['url'])) {
            $metadata['advisory_url'] = $advisory['url'];
        }

        // Add GitHub advisory ID
        if ($advisoryId) {
            $metadata['advisory_id'] = $advisoryId;
        }

        $issues[] = $this->createIssue(
            message: sprintf('Frontend package "%s" has a known vulnerability: %s', $package, $message),
            location: new Location(
                $this->getRelativePath($lockFile),
                1
            ),
            severity: $severity,
            recommendation: $recommendation,
            code: FileParser::getCodeSnippet($lockFile, 1),
            metadata: $metadata
        );
    }

    /**
     * Get analyzer configuration.
     *
     * @return array<string, mixed>
     */
    private function getConfiguration(): array
    {
        /** @var array<string, mixed> $config */
        $config = config('shieldci.frontend_vulnerable_dependencies', []);

        return array_merge([
            'ignored_packages' => [],
            'ignored_advisories' => [],
        ], $config);
    }
}
