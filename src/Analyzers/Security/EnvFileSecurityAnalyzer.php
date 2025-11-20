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
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'env-file-security',
            name: 'Environment File Security Analyzer',
            description: 'Validates .env file security, location, and prevents exposure of sensitive data',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['env', 'environment', 'secrets', 'security', 'configuration'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/env-file-security'
        );
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

        if (empty($issues)) {
            return $this->passed('Environment files are properly secured');
        }

        return $this->failed(
            sprintf('Found %d environment file security issues', count($issues)),
            $issues
        );
    }

    /**
     * Check for .env file in public directory.
     */
    private function checkPublicEnvFile(array &$issues): void
    {
        $publicEnvPaths = [
            $this->basePath.'/public/.env',
            $this->basePath.'/public_html/.env',
            $this->basePath.'/www/.env',
            $this->basePath.'/html/.env',
        ];

        foreach ($publicEnvPaths as $path) {
            if (file_exists($path)) {
                $issues[] = $this->createIssue(
                    message: '.env file found in publicly accessible directory',
                    location: new Location(
                        $this->getRelativePath($path),
                        1
                    ),
                    severity: Severity::Critical,
                    recommendation: 'IMMEDIATELY remove .env from public directory. It should be in the application root, one level above public/',
                    code: 'Critical security risk: .env file is publicly accessible'
                );
            }
        }
    }

    /**
     * Check .env.example for sensitive data.
     */
    private function checkEnvExample(array &$issues): void
    {
        $envExample = $this->basePath.'/.env.example';

        if (! file_exists($envExample)) {
            // While not critical, it's good practice to have .env.example
            $issues[] = $this->createIssue(
                message: 'Missing .env.example file',
                location: new Location(
                    '.env.example',
                    1
                ),
                severity: Severity::Low,
                recommendation: 'Create .env.example as a template for environment configuration (without sensitive values)',
                code: 'Best practice: provide .env.example for team members'
            );

            return;
        }

        $content = FileParser::readFile($envExample);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($envExample);

        foreach ($lines as $lineNumber => $line) {
            foreach ($this->sensitiveKeys as $key) {
                // Check if sensitive key has a real value (not placeholder)
                if (preg_match('/^'.preg_quote($key, '/').'\s*=\s*(.+)$/i', trim($line), $matches)) {
                    $value = trim($matches[1]);

                    // Skip if it's a common placeholder
                    $placeholders = ['', 'null', '""', "''", 'your-', 'change-', 'example', 'secret', 'password'];
                    $isPlaceholder = false;

                    foreach ($placeholders as $placeholder) {
                        if (empty($value) || str_contains(strtolower($value), $placeholder)) {
                            $isPlaceholder = true;
                            break;
                        }
                    }

                    // If it looks like a real value (long enough and not a placeholder)
                    if (! $isPlaceholder && strlen($value) > 20 && ! str_starts_with($value, 'base64:')) {
                        $issues[] = $this->createIssue(
                            message: sprintf('Sensitive key "%s" may contain real credentials in .env.example', $key),
                            location: new Location(
                                $this->getRelativePath($envExample),
                                $lineNumber + 1
                            ),
                            severity: Severity::High,
                            recommendation: 'Replace with placeholder value. .env.example should not contain real credentials',
                            code: sprintf('%s=***REDACTED***', $key)
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
        $gitignorePath = $this->basePath.'/.gitignore';

        if (! file_exists($gitignorePath)) {
            return; // No git repo
        }

        $content = FileParser::readFile($gitignorePath);
        if ($content === null) {
            return;
        }

        // Check if .env is ignored
        if (! str_contains($content, '.env') && ! str_contains($content, '*.env')) {
            $issues[] = $this->createIssue(
                message: '.env file is not excluded in .gitignore',
                location: new Location(
                    $this->getRelativePath($gitignorePath),
                    1
                ),
                severity: Severity::Critical,
                recommendation: 'Add ".env" to .gitignore to prevent accidentally committing secrets to version control',
                code: 'Missing .env in .gitignore'
            );
        }

        // Check if .env is actually committed (presence in git)
        if (file_exists($this->basePath.'/.git')) {
            $this->checkIfEnvCommitted($issues);
        }
    }

    /**
     * Check if .env file was committed to git.
     */
    private function checkIfEnvCommitted(array &$issues): void
    {
        $envPath = $this->basePath.'/.env';

        if (! file_exists($envPath)) {
            return;
        }

        // Check if .env is tracked by git
        $output = shell_exec(sprintf(
            'cd %s && git ls-files --error-unmatch .env 2>/dev/null',
            escapeshellarg($this->basePath)
        ));

        if (! empty($output) && str_contains($output, '.env')) {
            $issues[] = $this->createIssue(
                message: '.env file is committed to git repository',
                location: new Location(
                    '.env',
                    1
                ),
                severity: Severity::Critical,
                recommendation: 'Remove .env from git: "git rm --cached .env" and ensure it\'s in .gitignore',
                code: 'Critical: Secrets are in version control history'
            );
        }
    }

    /**
     * Check .env file permissions.
     */
    private function checkEnvPermissions(array &$issues): void
    {
        $envPath = $this->basePath.'/.env';

        if (! file_exists($envPath)) {
            return;
        }

        $perms = fileperms($envPath);
        $octal = substr(sprintf('%o', $perms), -3);

        // Check if file is world-readable or world-writable
        if (($perms & 0x0004) || ($perms & 0x0002)) {
            $issues[] = $this->createIssue(
                message: sprintf('.env file has insecure permissions (%s)', $octal),
                location: new Location(
                    '.env',
                    1
                ),
                severity: Severity::Critical,
                recommendation: 'Restrict .env permissions: chmod 600 .env',
                code: sprintf('Current permissions: %s (should be 600)', $octal)
            );
        }

        // Check if file is group-readable (could be okay but not ideal)
        $numericPerms = octdec($octal);
        if ($numericPerms > 600 && $numericPerms !== 644) {
            $issues[] = $this->createIssue(
                message: sprintf('.env file has overly permissive permissions (%s)', $octal),
                location: new Location(
                    '.env',
                    1
                ),
                severity: Severity::Medium,
                recommendation: 'Consider restricting .env permissions: chmod 600 .env (readable only by owner)',
                code: sprintf('Current permissions: %s', $octal)
            );
        }
    }
}
