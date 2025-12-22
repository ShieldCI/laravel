<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use Illuminate\Contracts\Config\Repository as Config;
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
    /**
     * @var array<string>
     */
    private array $ignoredPackages = [];

    /**
     * @var array<string>
     */
    private array $ignoredAdvisories = [];

    public function __construct(
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'frontend-vulnerable-dependencies',
            name: 'Frontend Vulnerable Dependencies Analyzer',
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

    /**
     * Load configuration from config repository.
     */
    private function loadConfiguration(): void
    {
        // Default empty arrays (no packages or advisories ignored by default)
        $defaultIgnoredPackages = [];
        $defaultIgnoredAdvisories = [];

        // Load from config
        $configIgnoredPackages = $this->config->get('shieldci.analyzers.security.frontend-vulnerable-dependencies.ignored_packages', []);

        // Ensure configIgnoredPackages is an array
        if (! is_array($configIgnoredPackages)) {
            $configIgnoredPackages = [];
        }

        $configIgnoredAdvisories = $this->config->get('shieldci.analyzers.security.frontend-vulnerable-dependencies.ignored_advisories', []);

        // Ensure configIgnoredAdvisories is an array
        if (! is_array($configIgnoredAdvisories)) {
            $configIgnoredAdvisories = [];
        }

        // Merge config with defaults, ensuring no duplicates
        $this->ignoredPackages = array_values(array_unique(array_merge($defaultIgnoredPackages, $configIgnoredPackages)));
        $this->ignoredAdvisories = array_values(array_unique(array_merge($defaultIgnoredAdvisories, $configIgnoredAdvisories)));
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration
        $this->loadConfiguration();

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
                location: new Location($this->getRelativePath($packageJson)),
                severity: Severity::Medium,
                recommendation: 'Run "npm install" or "yarn install" to generate lock file for dependency tracking',
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
            $command = $tool === 'npm' ? 'npm audit --json --ignore-scripts' : 'yarn audit --json --no-progress';

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
                    location: new Location($this->getRelativePath($packageLock)),
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
        if (! $detailedIssuesCreated && isset($results['summary']) && is_array($results['summary'])) {
            $summary = $results['summary'];

            // Case A: vulnerabilities is a breakdown object (preferred)
            if (isset($summary['vulnerabilities']) && is_array($summary['vulnerabilities'])) {
                $breakdown = $summary['vulnerabilities'];

                // Compute total from breakdown
                $total = 0;
                foreach ($breakdown as $count) {
                    if (is_numeric($count)) {
                        $total += (int) $count;
                    }
                }

                if ($total > 0) {
                    // Map yarn's "info" to your "low" bucket (optional)
                    if (isset($breakdown['info']) && is_numeric($breakdown['info']) && ! isset($breakdown['low'])) {
                        $breakdown['low'] = (int) $breakdown['info'];
                    }

                    $severity = $this->determineSeverityFromSummary($breakdown);

                    $issues[] = $this->createIssue(
                        message: sprintf('Found %d frontend package vulnerabilities', $total),
                        location: new Location($this->getRelativePath($yarnLock)),
                        severity: $severity,
                        recommendation: 'Run "yarn audit" to see details and upgrade vulnerable packages',
                        code: FileParser::getCodeSnippet($yarnLock, 1),
                        metadata: [
                            'total_vulnerabilities' => $total,
                            'issue_type' => 'summary',
                            'breakdown' => $breakdown,
                        ]
                    );
                }

                return;
            }

            // Case B: vulnerabilities is a numeric total (fallback)
            if (isset($summary['vulnerabilities']) && is_numeric($summary['vulnerabilities'])) {
                $total = (int) $summary['vulnerabilities'];

                if ($total > 0) {
                    $issues[] = $this->createIssue(
                        message: sprintf('Found %d frontend package vulnerabilities', $total),
                        location: new Location($this->getRelativePath($yarnLock)),
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
        if (in_array($package, $this->ignoredPackages)) {
            return;
        }

        $advisoryId = $advisory['id'] ?? $advisory['github_advisory_id'] ?? null;
        if ($advisoryId && in_array($advisoryId, $this->ignoredAdvisories)) {
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

        // Build recommendation with fix information if available
        $recommendation = null;

        if (isset($advisory['recommendation']) && is_string($advisory['recommendation'])) {
            $recommendation = $advisory['recommendation'];
        } elseif (isset($advisory['fixAvailable']) && is_array($advisory['fixAvailable'])) {
            // Use fixAvailable information from npm audit
            $fixName = $advisory['fixAvailable']['name'] ?? null;
            $fixVersion = $advisory['fixAvailable']['version'] ?? null;

            if ($fixName && $fixVersion) {
                if ($fixName === $package) {
                    $recommendation = sprintf('Update "%s" to version %s or later', $package, $fixVersion);
                } else {
                    $recommendation = sprintf('Update "%s" to version %s to fix vulnerability in "%s"', $fixName, $fixVersion, $package);
                }
            }
        }

        // Fallback recommendation
        if ($recommendation === null) {
            $recommendation = sprintf('Update package "%s" to a patched version', $package);
        }

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

        // Find the exact line number of the package in the lock file
        $lineNumber = $this->findPackageLineNumber($lockFile, $package);

        $issues[] = $this->createIssue(
            message: sprintf('Frontend package "%s" has a known vulnerability: %s', $package, $message),
            location: new Location($this->getRelativePath($lockFile), $lineNumber),
            severity: $severity,
            recommendation: $recommendation,
            code: FileParser::getCodeSnippet($lockFile, $lineNumber),
            metadata: $metadata
        );
    }

    /**
     * Find the line number where a package is defined in the lock file.
     */
    private function findPackageLineNumber(string $lockFile, string $package): int
    {
        $lines = FileParser::getLines($lockFile);

        if (empty($lines)) {
            return 1;
        }

        // For package-lock.json, look for "node_modules/package-name" or "packages/node_modules/package-name"
        // For yarn.lock, look for package-name@version
        $isYarnLock = str_ends_with($lockFile, 'yarn.lock');

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            if ($isYarnLock) {
                // Yarn lock format: "package-name@version":
                // Also handle scoped packages: "@scope/package-name@version":
                if (preg_match('/^"?'.preg_quote($package, '/').'@/i', trim($line))) {
                    return $lineNumber + 1;
                }
            } else {
                // NPM lock format: "node_modules/package-name": {
                // Also handle scoped packages: "node_modules/@scope/package-name": {
                if (preg_match('/"node_modules\/'.preg_quote($package, '/').'":\s*\{/i', $line)) {
                    return $lineNumber + 1;
                }

                // Alternative npm format (newer versions): "packages": { "node_modules/package-name": {
                if (preg_match('/"packages\/node_modules\/'.preg_quote($package, '/').'":\s*\{/i', $line)) {
                    return $lineNumber + 1;
                }

                // Direct package name in dependencies object (npm v7+)
                if (preg_match('/"'.preg_quote($package, '/').'":\s*\{/i', $line)) {
                    return $lineNumber + 1;
                }
            }
        }

        // If not found, return 1
        return 1;
    }
}
