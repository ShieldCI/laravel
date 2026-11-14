<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use Illuminate\Contracts\Config\Repository as Config;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\MessageHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\DetectsDeploymentPlatform;

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
    use DetectsDeploymentPlatform;

    public static bool $runInCI = false;

    /**
     * @var array<string>
     */
    private array $ignoredPackages = [];

    /**
     * @var array<string>
     */
    private array $ignoredAdvisories = [];

    /**
     * How long the audit may run before it is abandoned. A property rather than a literal so
     * the timeout path can be tested without waiting a minute.
     */
    private int $auditTimeoutSeconds = 60;

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
            timeToFix: 60
        );
    }

    public function shouldRun(): bool
    {
        if ($this->isVaporOrServerless()) {
            return false;
        }

        $packageJson = $this->buildPath('package.json');

        if (! file_exists($packageJson)) {
            return false;
        }

        $content = file_get_contents($packageJson);
        if ($content === false) {
            return false;
        }

        $data = json_decode($content, true);
        if (! is_array($data)) {
            return false;
        }

        $deps = isset($data['dependencies']) && is_array($data['dependencies']) ? $data['dependencies'] : [];
        $devDeps = isset($data['devDependencies']) && is_array($data['devDependencies']) ? $data['devDependencies'] : [];

        return $deps !== [] || $devDeps !== [];
    }

    public function getSkipReason(): string
    {
        if ($this->isVaporOrServerless()) {
            return 'Vapor removes frontend lock files (yarn.lock, package-lock.json) from the deployment package; frontend dependencies are managed outside the Lambda runtime';
        }

        return 'No package.json found or no dependencies declared';
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
        $this->ignoredPackages = array_values(array_unique(array_filter(array_merge($defaultIgnoredPackages, $configIgnoredPackages), 'is_string')));
        $this->ignoredAdvisories = array_values(array_unique(array_filter(array_merge($defaultIgnoredAdvisories, $configIgnoredAdvisories), 'is_string')));
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
        $tool = $hasPackageLock ? 'npm' : 'yarn';

        $auditResults = $this->runAuditCommand($basePath, $tool);

        // A string is the reason the audit produced no result. No result is not a clean
        // result: reporting passed here would read a missing tool or a refused registry
        // request as proof that no dependency is vulnerable.
        if (is_string($auditResults)) {
            return $this->warning(sprintf('Frontend dependency audit did not run: %s', $auditResults));
        }

        $lockFile = $hasPackageLock ? $packageLock : $yarnLock;

        if ($hasPackageLock) {
            $this->parseNpmAuditResults($auditResults, $issues, $packageLock);
        } else {
            $this->parseYarnAuditResults($auditResults, $issues, $yarnLock);
        }

        // The audit covers only what the lock file holds. A clean audit of a lock that lacks a
        // declared dependency says nothing about that dependency, so it is not a pass. Findings
        // still stand: a vulnerability found in what was covered must fail regardless.
        if ($issues === []) {
            $missing = $this->findDeclaredDependenciesMissingFromLock($lockFile, $tool);

            if ($missing !== []) {
                $shown = array_slice($missing, 0, 5);
                $names = implode(', ', $shown);
                if (count($missing) > count($shown)) {
                    $names .= sprintf(' and %d more', count($missing) - count($shown));
                }

                return $this->warning(
                    sprintf(
                        'Frontend dependency audit did not cover the declared dependencies: %s is out of date and has no entry for %s; run "%s install" to update it',
                        basename($lockFile),
                        $names,
                        $tool
                    ),
                    [],
                    ['missing_from_lock' => $missing]
                );
            }
        }

        $summary = empty($issues)
            ? 'No vulnerable frontend dependencies detected'
            : sprintf('Found %d frontend dependency security issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Run audit command (npm or yarn) with timeout protection.
     *
     * Returns the decoded audit result, or a string saying why there is none. The two must
     * stay apart: a tool that is missing, refused by its registry or cut off by the timeout
     * has not reported anything, and an empty result would read as a clean audit.
     *
     * @return array<array-key, mixed>|string
     */
    private function runAuditCommand(string $basePath, string $tool): array|string
    {
        $currentDir = getcwd();
        if ($currentDir === false) {
            return 'the current working directory could not be read';
        }

        try {
            // Change to the base directory
            if (! @chdir($basePath)) {
                return 'could not change into the project directory';
            }

            // Build command. --offline=false because offline=true in .npmrc or the environment
            // makes npm print a well-formed, empty report without asking the registry, and only a
            // command-line flag overrides both. yarn v1 needs nothing similar: offline mode makes
            // its audit request fail, which surfaces as an error line rather than a clean report.
            // --include-workspace-root=true because workspaces=true or workspace=<name> in the
            // same places audits only the workspaces and drops the root's dependencies; it is
            // harmless without workspaces, unlike --workspaces=false, which would drop theirs.
            $command = $tool === 'npm'
                ? 'npm audit --json --ignore-scripts --offline=false --include-workspace-root=true'
                : 'yarn audit --json --no-progress';

            // Use proc_open for timeout control
            $descriptors = [
                0 => ['pipe', 'r'],  // stdin
                1 => ['pipe', 'w'],  // stdout
                2 => ['pipe', 'w'],  // stderr
            ];

            $process = proc_open($command, $descriptors, $pipes);

            if (! is_resource($process)) {
                return sprintf('%s could not be started', $tool);
            }

            // Close stdin
            fclose($pipes[0]);

            $start = time();
            $output = '';
            $errorOutput = '';

            // Read output with timeout. stderr is drained alongside stdout so a chatty tool
            // cannot fill that pipe and stall, and so a failure can say what the tool printed.
            stream_set_blocking($pipes[1], false);
            stream_set_blocking($pipes[2], false);
            while (! feof($pipes[1])) {
                if (time() - $start > $this->auditTimeoutSeconds) {
                    // Timeout - kill process
                    proc_terminate($process);
                    fclose($pipes[1]);
                    fclose($pipes[2]);
                    proc_close($process);

                    return sprintf('%s audit timed out after %ds', $tool, $this->auditTimeoutSeconds);
                }

                $chunk = fread($pipes[1], 8192);
                if ($chunk !== false) {
                    $output .= $chunk;
                }

                $errorChunk = fread($pipes[2], 8192);
                if ($errorChunk !== false) {
                    $errorOutput .= $errorChunk;
                }

                usleep(100000); // 0.1 second
            }

            $errorChunk = stream_get_contents($pipes[2]);
            if ($errorChunk !== false) {
                $errorOutput .= $errorChunk;
            }

            fclose($pipes[1]);
            fclose($pipes[2]);
            $exitCode = proc_close($process);

            if (trim($output) === '') {
                // 127 is the shell's "command not found"
                if ($exitCode === 127) {
                    return sprintf('%s was not found on PATH', $tool);
                }

                return $this->withToolExcerpt(
                    sprintf('%s audit produced no output (exit code %d)', $tool, $exitCode),
                    $errorOutput,
                    $basePath
                );
            }

            // Parse based on tool
            if ($tool === 'npm') {
                return $this->parseNpmOutput($output, $basePath);
            }

            return $this->parseYarnOutput($output, $basePath);
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

            return $this->withToolExcerpt(sprintf('%s audit failed', $tool), $e->getMessage(), $basePath);
        } finally {
            // Always restore the original directory
            @chdir($currentDir);
        }
    }

    /**
     * Parse npm output (JSON or plain text fallback).
     *
     * npm audit exits non-zero whenever it finds a vulnerability, so the exit code cannot tell
     * a report from a failure; the payload has to.
     *
     * @return array<array-key, mixed>|string the audit result, or why there is none
     */
    private function parseNpmOutput(string $output, string $basePath): array|string
    {
        // Try to decode JSON output
        $result = json_decode($output, true);

        if (json_last_error() === JSON_ERROR_NONE && is_array($result)) {
            // npm reports a failed audit (ENOAUDIT, E403, ENOLOCK, ...) as {"error": {...}}
            if (array_key_exists('error', $result)) {
                return $this->describeNpmError($result['error'], $basePath);
            }

            if (! $this->isNpmAuditReport($result)) {
                return 'npm audit output was not an audit report';
            }

            return $result;
        }

        // Fallback to plain text parsing
        return $this->parseNpmPlainTextAudit($output)
            ?? $this->withToolExcerpt('npm audit output could not be parsed', $output, $basePath);
    }

    /**
     * Whether a decoded npm payload is an audit report: npm v7+ carries auditReportVersion
     * and a vulnerabilities map, npm v6 carries advisories, and both carry a
     * metadata.vulnerabilities breakdown.
     *
     * @param  array<array-key, mixed>  $result
     */
    private function isNpmAuditReport(array $result): bool
    {
        if (isset($result['auditReportVersion'])) {
            return true;
        }

        if (isset($result['vulnerabilities']) && is_array($result['vulnerabilities'])) {
            return true;
        }

        if (isset($result['advisories']) && is_array($result['advisories'])) {
            return true;
        }

        $metadata = $result['metadata'] ?? null;

        return is_array($metadata) && isset($metadata['vulnerabilities']) && is_array($metadata['vulnerabilities']);
    }

    /**
     * Describe the error object npm prints in place of an audit report.
     */
    private function describeNpmError(mixed $error, string $basePath): string
    {
        $code = is_array($error) && isset($error['code']) && is_string($error['code']) && $error['code'] !== ''
            ? $error['code']
            : null;
        $summary = is_array($error) && isset($error['summary']) && is_string($error['summary'])
            ? $error['summary']
            : '';

        $reason = $code !== null
            ? sprintf('npm audit returned %s', $this->toolExcerpt($code, $basePath))
            : 'npm audit returned an error';

        return $this->withToolExcerpt($reason, $summary, $basePath);
    }

    /**
     * Parse yarn output (newline-delimited JSON).
     *
     * A yarn v1 audit that ran always ends with an auditSummary line, so output with neither a
     * summary nor an advisory is a failure, whatever the exit code (which yarn sets from the
     * severities found).
     *
     * @return array<array-key, mixed>|string the audit result, or why there is none
     */
    private function parseYarnOutput(string $output, string $basePath): array|string
    {
        // Yarn outputs newline-delimited JSON
        $lines = array_filter(explode("\n", $output));
        $result = ['advisories' => []];
        $error = null;

        foreach ($lines as $line) {
            if (! is_string($line) || $line === '') {
                continue;
            }

            $decoded = json_decode($line, true);

            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded) && isset($decoded['type']) && is_string($decoded['type'])) {
                $data = $decoded['data'] ?? null;
                if ($decoded['type'] === 'auditAdvisory' && is_array($data) && isset($data['advisory']) && is_array($data['advisory'])) {
                    $result['advisories'][] = $data['advisory'];
                } elseif ($decoded['type'] === 'auditSummary' && is_array($data)) {
                    $result['summary'] = $data;
                } elseif ($decoded['type'] === 'error' && $error === null) {
                    $error = is_string($data) ? $data : '';
                }
            }
        }

        if ($result['advisories'] !== [] || isset($result['summary'])) {
            return $result;
        }

        if ($error !== null) {
            return $this->withToolExcerpt('yarn audit returned an error', $error, $basePath);
        }

        return 'yarn audit output had no audit summary';
    }

    /**
     * Parse plain text npm audit output as fallback.
     *
     * "found 0 vulnerabilities" is a clean audit and yields a zero total; null means the text
     * did not report a count at all.
     *
     * @return array<array-key, mixed>|null
     */
    private function parseNpmPlainTextAudit(string $output): ?array
    {
        // Look for vulnerability patterns in output
        if (! preg_match('/(\d+)\s+vulnerabilit/i', $output, $matches)) {
            return null;
        }

        return [
            'vulnerabilities' => [],
            'metadata' => [
                'vulnerabilities' => [
                    'total' => (int) $matches[1],
                ],
            ],
        ];
    }

    /**
     * Append a short excerpt of what the tool printed to a failure reason, if it printed anything.
     */
    private function withToolExcerpt(string $reason, string $toolOutput, string $basePath): string
    {
        $excerpt = $this->toolExcerpt($toolOutput, $basePath);

        return $excerpt === '' ? $reason : $reason.': '.$excerpt;
    }

    /**
     * The first non-empty line of tool output, with the project path replaced by "." and
     * credentials redacted. MessageHelper's 200-character default applies rather than
     * SanitizesErrorMessages' 500, because the excerpt is a clause in the result message,
     * not the whole message.
     */
    private function toolExcerpt(string $toolOutput, string $basePath): string
    {
        $line = '';
        foreach (preg_split('/\R/', $toolOutput) ?: [] as $candidate) {
            $candidate = trim($candidate);
            if ($candidate !== '') {
                $line = $candidate;

                break;
            }
        }

        if ($line === '') {
            return '';
        }

        $paths = [];
        foreach ([$basePath, realpath($basePath)] as $path) {
            $path = is_string($path) ? rtrim($path, '/\\') : '';
            if ($path !== '' && $path !== '.') {
                $paths[] = $path;
            }
        }

        // Longest first, so a resolved path that extends the given one is replaced whole
        usort($paths, fn (string $a, string $b): int => strlen($b) <=> strlen($a));

        return MessageHelper::sanitizeErrorMessage(str_replace($paths, '.', $line));
    }

    /**
     * Direct dependencies package.json declares (dependencies and devDependencies) that the lock
     * file has no entry for, in declaration order. For an npm workspaces project the same holds
     * for each workspace, labelled "name (workspace path)", and a workspace folder the lock does
     * not record is labelled "workspace <path>".
     *
     * Read from the lock file rather than the audit report's metadata.dependencies counts: the
     * lock names each package, while the counts differ by npm version (npm 11 counts the root
     * project under "prod" but not "total"), are absent from npm 6's report and from yarn's and
     * plain-text output, and cannot say which dependency is missing. An empty list means
     * nothing is missing or there is no evidence either way (an unreadable package.json or lock).
     *
     * @return list<string>
     */
    private function findDeclaredDependenciesMissingFromLock(string $lockFile, string $tool): array
    {
        $packageJson = @file_get_contents($this->buildPath('package.json'));
        $lockContents = @file_get_contents($lockFile);
        if ($packageJson === false || $lockContents === false) {
            return [];
        }

        $package = json_decode($packageJson, true);
        if (! is_array($package)) {
            return [];
        }

        if ($tool === 'yarn' && isset($package['workspaces'])) {
            // yarn v1 never writes workspace packages into yarn.lock, and a workspace dependency
            // is declared with a plain semver range, so a missing entry proves nothing here.
            return [];
        }

        $locked = $tool === 'npm'
            ? $this->npmLockedPaths($lockContents)
            : $this->yarnLockedPaths($lockContents);
        if ($locked === null) {
            return [];
        }

        // Workspaces need lockfileVersion 2 or 3, whose "packages" map always holds the root
        // project under "". npm 6 (lockfileVersion 1) had no workspaces.
        $members = $tool === 'npm' && isset($locked['']) ? $this->npmWorkspaceMembers($package) : [];

        $memberNames = [];
        foreach ($members as $member) {
            if (isset($member['name']) && is_string($member['name'])) {
                $memberNames[$member['name']] = true;
            }
        }

        $missing = [];
        $this->collectDependenciesMissingFromLock($package, '', $locked, $memberNames, $missing);

        foreach ($members as $path => $member) {
            if (! isset($locked[$path])) {
                $missing[] = sprintf('workspace %s', $path);

                continue;
            }

            $this->collectDependenciesMissingFromLock($member, $path, $locked, $memberNames, $missing);
        }

        return $missing;
    }

    /**
     * Add to $missing each direct dependency of one package.json that the lock has no install
     * of. A dependency counts as locked when it is installed at the root
     * (node_modules/<name>), where npm hoists it, or, for a workspace, under that workspace
     * (<path>/node_modules/<name>).
     *
     * @param  array<array-key, mixed>  $package  the decoded package.json
     * @param  string  $path  the workspace folder relative to the project, or '' for the root
     * @param  array<string, true>  $locked  install paths the lock records
     * @param  array<string, true>  $memberNames  workspace package names, linked rather than installed
     * @param  list<string>  $missing
     */
    private function collectDependenciesMissingFromLock(array $package, string $path, array $locked, array $memberNames, array &$missing): void
    {
        foreach (['dependencies', 'devDependencies'] as $section) {
            $declared = $package[$section] ?? null;
            if (! is_array($declared)) {
                continue;
            }

            foreach ($declared as $name => $range) {
                $name = (string) $name;

                // link: and workspace: targets are never locked by name, and a dependency on
                // another workspace resolves to that workspace's folder
                if (is_string($range) && preg_match('/^(link|workspace):/', $range) === 1) {
                    continue;
                }

                if (isset($memberNames[$name])) {
                    continue;
                }

                if (isset($locked['node_modules/'.$name]) || ($path !== '' && isset($locked[$path.'/node_modules/'.$name]))) {
                    continue;
                }

                $label = $path === '' ? $name : sprintf('%s (%s)', $name, $path);
                if (! in_array($label, $missing, true)) {
                    $missing[] = $label;
                }
            }
        }
    }

    /**
     * The npm workspaces package.json declares, keyed by folder relative to the project, each
     * with its decoded package.json. Reads "workspaces" as an array of patterns or as
     * {"packages": [...]}. Each pattern goes through glob(), so literal folders and single-segment
     * wildcards (*, ?, [...]) are supported; "**" matches one level only. A pattern starting with
     * "!" removes the folders it matches. A folder without a readable package.json is not a
     * workspace.
     *
     * @param  array<array-key, mixed>  $package  the root package.json
     * @return array<string, array<array-key, mixed>>
     */
    private function npmWorkspaceMembers(array $package): array
    {
        $patterns = $package['workspaces'] ?? null;
        if (is_array($patterns) && isset($patterns['packages']) && is_array($patterns['packages'])) {
            $patterns = $patterns['packages'];
        }

        if (! is_array($patterns)) {
            return [];
        }

        $include = [];
        $exclude = [];
        foreach ($patterns as $pattern) {
            if (! is_string($pattern)) {
                continue;
            }

            $negated = str_starts_with($pattern, '!');
            $pattern = $this->normalizeWorkspacePath($negated ? substr($pattern, 1) : $pattern);
            if ($pattern === '') {
                continue;
            }

            if ($negated) {
                $exclude[] = $pattern;
            } else {
                $include[] = $pattern;
            }
        }

        $basePath = $this->getBasePath();
        $members = [];

        foreach ($include as $pattern) {
            foreach (glob($basePath.'/'.$pattern, GLOB_ONLYDIR) ?: [] as $directory) {
                $path = $this->normalizeWorkspacePath(substr($directory, strlen($basePath) + 1));
                if ($path === '' || isset($members[$path])) {
                    continue;
                }

                foreach ($exclude as $excluded) {
                    if (fnmatch($excluded, $path)) {
                        continue 2;
                    }
                }

                $contents = @file_get_contents($directory.'/package.json');
                $member = $contents === false ? null : json_decode($contents, true);
                if (is_array($member)) {
                    $members[$path] = $member;
                }
            }
        }

        return $members;
    }

    /**
     * A workspace path as npm writes it in the lock: forward slashes, no leading "./", no
     * trailing slash.
     */
    private function normalizeWorkspacePath(string $path): string
    {
        $path = str_replace('\\', '/', trim($path));
        $path = preg_replace('#^(\./)+#', '', $path) ?? $path;

        return rtrim($path, '/');
    }

    /**
     * Install paths package-lock.json records: the "packages" map's keys as written
     * (lockfileVersion 2 and 3), which include "" for the root, "node_modules/<name>" for a
     * root install, "<workspace>" for a workspace folder and "<workspace>/node_modules/<name>"
     * for a dependency installed under it; or "node_modules/<name>" for each key of the
     * "dependencies" map (lockfileVersion 1). Null when the lock is not a JSON object.
     *
     * @return array<string, true>|null
     */
    private function npmLockedPaths(string $lockContents): ?array
    {
        $lock = json_decode($lockContents, true);
        if (! is_array($lock)) {
            return null;
        }

        $paths = [];

        if (isset($lock['packages']) && is_array($lock['packages'])) {
            foreach (array_keys($lock['packages']) as $path) {
                $paths[(string) $path] = true;
            }

            return $paths;
        }

        if (isset($lock['dependencies']) && is_array($lock['dependencies'])) {
            foreach (array_keys($lock['dependencies']) as $name) {
                $paths['node_modules/'.$name] = true;
            }
        }

        return $paths;
    }

    /**
     * Install paths, as "node_modules/<name>", for the package names with an entry in a yarn v1
     * lock file. Each entry starts with an unindented line listing its "name@range" keys, comma
     * separated and quoted when they hold special characters, such as
     * `"@scope/pkg@^1.0.0", "@scope/pkg@^1.1.0":`. The name runs up to the first "@" after a
     * scope's leading one, which also holds for aliases, git and tarball ranges.
     *
     * @return array<string, true>
     */
    private function yarnLockedPaths(string $lockContents): array
    {
        $paths = [];

        foreach (preg_split('/\R/', $lockContents) ?: [] as $line) {
            $line = rtrim($line);
            if ($line === '' || $line[0] === ' ' || $line[0] === "\t" || $line[0] === '#' || ! str_ends_with($line, ':')) {
                continue;
            }

            foreach (explode(',', substr($line, 0, -1)) as $key) {
                $key = trim(trim($key), '"');
                $at = strpos($key, '@', 1);
                if ($at !== false) {
                    $paths['node_modules/'.substr($key, 0, $at)] = true;
                }
            }
        }

        return $paths;
    }

    /**
     * Parse npm audit results.
     *
     * @param  array<int, Issue>  &$issues
     * @param  array<array-key, mixed>  $results
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
                if (! is_string($package) || ! is_array($vulnerability)) {
                    continue;
                }

                $via = isset($vulnerability['via']) && is_array($vulnerability['via'])
                    ? $vulnerability['via']
                    : [];

                $createdAny = false;

                foreach ($via as $viaItem) {
                    if (is_array($viaItem)) {
                        // npm v7+: advisory details (title, url, severity, range, cves) live inside via entries
                        $merged = array_merge($vulnerability, $viaItem);
                        $this->createFrontendVulnerabilityIssue($package, $merged, $issues, $packageLock);
                        $createdAny = true;
                    }
                    // string entries mean a transitive dependency — skip, the root package is reported separately
                }

                // Fallback for old / non-standard format with no via key at all
                if (! $createdAny && $via === []) {
                    $this->createFrontendVulnerabilityIssue($package, $vulnerability, $issues, $packageLock);
                    $createdAny = true;
                }

                if ($createdAny) {
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
        $metadata = $results['metadata'] ?? null;
        if (! $detailedIssuesCreated && is_array($metadata) && isset($metadata['vulnerabilities']) && is_array($metadata['vulnerabilities'])) {
            $vulns = $metadata['vulnerabilities'];
            $total = isset($vulns['total']) && is_numeric($vulns['total']) ? (int) $vulns['total'] : 0;

            if ($total > 0) {
                // Determine severity from breakdown
                $severity = $this->determineSeverityFromSummary($vulns);

                $issues[] = $this->createIssue(
                    message: sprintf('Found %d frontend package vulnerabilities', $total),
                    location: new Location($this->getRelativePath($packageLock)),
                    severity: $severity,
                    recommendation: 'Run "npm audit" to see details and "npm audit fix" to automatically fix vulnerabilities',
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
     *
     * @param  array<int, Issue>  &$issues
     * @param  array<array-key, mixed>  $results
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
     *
     * @param  array<int, Issue>  &$issues
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

        // A missing or unrecognised level is still a reported vulnerability, so it fails the
        // build as High; it is not escalated to Critical on no evidence. "info" is npm's and
        // yarn's lowest documented level.
        $severity = Severity::High;
        if (isset($advisory['severity']) && is_string($advisory['severity'])) {
            $severity = match (strtolower($advisory['severity'])) {
                'critical' => Severity::Critical,
                'high' => Severity::High,
                'moderate' => Severity::Medium,
                'low', 'info' => Severity::Low,
                default => Severity::High,
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

            if (is_string($fixName) && is_string($fixVersion) && $fixName !== '' && $fixVersion !== '') {
                $fixNameStr = $fixName;
                $fixVersionStr = $fixVersion;
                if ($fixNameStr === $package) {
                    $recommendation = sprintf('Update "%s" to version %s or later', $package, $fixVersionStr);
                } else {
                    $recommendation = sprintf('Update "%s" to version %s to fix vulnerability in "%s"', $fixNameStr, $fixVersionStr, $package);
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

        $issues[] = $this->createIssue(
            message: sprintf('Frontend package "%s" has a known vulnerability: %s', $package, $message),
            location: new Location($this->getRelativePath($lockFile)),
            severity: $severity,
            recommendation: $recommendation,
            metadata: $metadata
        );
    }
}
