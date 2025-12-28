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
 * Validates .env file security and location.
 *
 * Checks for:
 * - .env files in public directory
 * - .env.example containing sensitive data
 * - .env committed to git
 * - Missing .env.example file
 * - Weak .env file permissions
 */
class EnvFileSecurityAnalyzer extends AbstractFileAnalyzer
{
    private const WORLD_READABLE = 0x0004;

    private const WORLD_WRITABLE = 0x0002;

    private const GROUP_READABLE = 0x0020;

    private const GROUP_WRITABLE = 0x0040;

    private array $sensitiveKeys = [
        'APP_KEY',
        'DB_PASSWORD',
        'AWS_SECRET_ACCESS_KEY',
        'MAIL_PASSWORD',
        'REDIS_PASSWORD',
        'SESSION_SECRET',
        'JWT_SECRET',
        'STRIPE_SECRET',
        'PUSHER_APP_SECRET',
        'DATABASE_URL',
        'API_KEY',
        'SECRET_KEY',
        'PRIVATE_KEY',
        'OAUTH_CLIENT_SECRET',
    ];

    private array $placeholderKeywords = ['null', '""', "''", 'your-', 'change-', 'example'];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'env-file',
            name: 'Environment File Analyzer',
            description: 'Validates .env file security, location, and prevents exposure of sensitive data',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['env', 'environment', 'secrets', 'security', 'configuration'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/env-file',
            timeToFix: 10
        );
    }

    public function shouldRun(): bool
    {
        $envFile = $this->buildPath('.env');
        $envExample = $this->buildPath('.env.example');
        $gitignore = $this->buildPath('.gitignore');
        $gitDir = $this->buildPath('.git');

        // Check for public directories
        $publicDirs = [
            $this->buildPath('public'),
            $this->buildPath('public_html'),
            $this->buildPath('www'),
            $this->buildPath('html'),
        ];

        $hasPublicDir = false;
        foreach ($publicDirs as $dir) {
            if (is_dir($dir)) {
                $hasPublicDir = true;
                break;
            }
        }

        return file_exists($envFile) ||
               file_exists($envExample) ||
               file_exists($gitignore) ||
               is_dir($gitDir) ||
               $hasPublicDir;
    }

    public function getSkipReason(): string
    {
        return 'No environment files, git repository, or public directories found to analyze';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check for .env in public directory
        $this->checkPublicEnvFile($issues);

        // Check .env.example for sensitive data
        $this->checkEnvExample($issues);

        // Check if .env is in .gitignore
        $this->checkGitignore($issues);

        // Check .env file permissions
        $this->checkEnvPermissions($issues);

        $summary = empty($issues)
            ? 'Environment files are properly secured'
            : sprintf('Found %d environment file security issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check for .env file in public directory.
     */
    private function checkPublicEnvFile(array &$issues): void
    {
        $publicEnvPaths = [
            $this->buildPath('public', '.env'),
            $this->buildPath('public_html', '.env'),
            $this->buildPath('www', '.env'),
            $this->buildPath('html', '.env'),
        ];

        foreach ($publicEnvPaths as $path) {
            if (file_exists($path)) {
                $issues[] = $this->createIssue(
                    message: '.env file found in publicly accessible directory',
                    location: new Location($this->getRelativePath($path)),
                    severity: Severity::Critical,
                    recommendation: 'IMMEDIATELY remove .env from public directory. It should be in the application root, one level above public/',
                    metadata: ['path' => $path]
                );
            }
        }
    }

    /**
     * Check .env.example for sensitive data.
     */
    private function checkEnvExample(array &$issues): void
    {
        $envExample = $this->buildPath('.env.example');
        $envFile = $this->buildPath('.env');

        if (! file_exists($envExample)) {
            // Only flag missing .env.example if .env exists
            if (! file_exists($envFile)) {
                return;
            }
            // While not critical, it's good practice to have .env.example
            $issues[] = $this->createIssue(
                message: 'Missing .env.example file',
                location: new Location('.env.example'),
                severity: Severity::Low,
                recommendation: 'Create .env.example as a template for environment configuration (without sensitive values)',
                metadata: [
                    'file' => '.env.example',
                    'exists' => false,
                    'env_file_exists' => true,
                ]
            );

            return;
        }

        $content = FileParser::readFile($envExample);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($envExample);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            foreach ($this->sensitiveKeys as $key) {
                // Check if sensitive key has a real value (not placeholder)
                $pattern = '/^'.preg_quote($key, '/').'\s*=\s*(.+)$/i';
                if (preg_match($pattern, trim($line), $matches)) {
                    if (! isset($matches[1]) || ! is_string($matches[1])) {
                        continue;
                    }

                    $value = trim($matches[1]);
                    $value = trim($value, "\"'");

                    // Skip if empty or it's a common placeholder
                    if ($value === '') {
                        continue;
                    }

                    $isPlaceholder = false;
                    $lowerValue = strtolower($value);
                    foreach ($this->placeholderKeywords as $placeholder) {
                        if (str_contains($lowerValue, $placeholder)) {
                            $isPlaceholder = true;
                            break;
                        }
                    }

                    // If it looks like a real value (long enough and not a placeholder)
                    if (! $isPlaceholder && strlen($value) > 20 && ! str_starts_with($value, 'base64:')) {
                        $issues[] = $this->createIssueWithSnippet(
                            message: sprintf('Sensitive key "%s" may contain real credentials in .env.example', $key),
                            filePath: $envExample,
                            lineNumber: $lineNumber + 1,
                            severity: Severity::High,
                            recommendation: 'Replace with placeholder value. .env.example should not contain real credentials',
                            code: $key,
                            metadata: [
                                'key' => $key,
                                'value_length' => strlen($value),
                                'file' => '.env.example',
                            ]
                        );
                    }
                }
            }
        }
    }

    /**
     * Check if .env is properly excluded in .gitignore.
     */
    private function checkGitignore(array &$issues): void
    {
        $gitignorePath = $this->buildPath('.gitignore');

        if (! file_exists($gitignorePath)) {
            return; // No git repo
        }

        $content = FileParser::readFile($gitignorePath);
        if ($content === null || ! is_string($content)) {
            return;
        }

        // Check if .env is ignored
        $ignored = preg_match('/^\s*(?:\.env|\*\.env)\s*$/m', $content) === 1;
        if (! $ignored) {
            $issues[] = $this->createIssueWithSnippet(
                message: '.env file is not excluded in .gitignore',
                filePath: $gitignorePath,
                lineNumber: null,
                severity: Severity::Critical,
                recommendation: 'Add ".env" to .gitignore to prevent accidentally committing secrets to version control',
                code: '.env',
                metadata: [
                    'file' => '.gitignore',
                    'missing_pattern' => '.env',
                ]
            );
        }

        // Check if .env is actually committed (presence in git)
        $gitPath = $this->buildPath('.git');
        if (is_dir($gitPath)) {
            $this->checkIfEnvCommitted($issues);
        }
    }

    /**
     * Check if .env file was committed to git.
     */
    private function checkIfEnvCommitted(array &$issues): void
    {
        $envPath = $this->buildPath('.env');

        if (! file_exists($envPath)) {
            return;
        }

        // Check if .env is tracked by git using proc_open for security
        $descriptorspec = [
            0 => ['pipe', 'r'],  // stdin
            1 => ['pipe', 'w'],  // stdout
            2 => ['pipe', 'w'],  // stderr
        ];

        $process = proc_open(
            ['git', 'ls-files', '--error-unmatch', '.env'],
            $descriptorspec,
            $pipes,
            $this->getBasePath()
        );

        if (! is_resource($process)) {
            return;
        }

        $output = stream_get_contents($pipes[1]);
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $returnCode = proc_close($process);

        // Return code 0 means file is tracked by git
        if ($returnCode === 0 && is_string($output) && str_contains($output, '.env')) {
            $issues[] = $this->createIssueWithSnippet(
                message: '.env file is committed to git repository',
                filePath: $envPath,
                lineNumber: null,
                severity: Severity::Critical,
                recommendation: 'Remove .env from git: "git rm --cached .env" and ensure it\'s in .gitignore',
                code: 'git-tracked',
                metadata: [
                    'file' => '.env',
                    'git_tracked' => true,
                ]
            );
        }
    }

    /**
     * Check .env file permissions.
     */
    private function checkEnvPermissions(array &$issues): void
    {
        $envPath = $this->buildPath('.env');

        if (! file_exists($envPath)) {
            return;
        }

        $perms = @fileperms($envPath);
        if ($perms === false) {
            return;
        }

        $octal = substr(sprintf('%o', $perms), -3);

        // Check if file is world-readable or world-writable (Critical)
        if (($perms & self::WORLD_READABLE) || ($perms & self::WORLD_WRITABLE)) {
            $issues[] = $this->createIssueWithSnippet(
                message: sprintf('.env file has insecure permissions (%s)', $octal),
                filePath: $envPath,
                lineNumber: null,
                severity: Severity::Critical,
                recommendation: 'Restrict .env permissions: chmod 600 .env',
                code: 'permissions',
                metadata: [
                    'permissions' => $octal,
                    'world_readable' => (bool) ($perms & self::WORLD_READABLE),
                    'world_writable' => (bool) ($perms & self::WORLD_WRITABLE),
                ]
            );

            return; // Don't check for less severe issues if Critical issue exists
        }

        // Check if file is group-readable or group-writable (Medium)
        if (($perms & self::GROUP_READABLE) || ($perms & self::GROUP_WRITABLE)) {
            $issues[] = $this->createIssueWithSnippet(
                message: sprintf('.env file has overly permissive permissions (%s)', $octal),
                filePath: $envPath,
                lineNumber: null,
                severity: Severity::Medium,
                recommendation: 'Consider restricting .env permissions: chmod 600 .env (readable only by owner)',
                code: 'permissions',
                metadata: [
                    'permissions' => $octal,
                    'group_readable' => (bool) ($perms & self::GROUP_READABLE),
                    'group_writable' => (bool) ($perms & self::GROUP_WRITABLE),
                ]
            );
        }
    }
}
