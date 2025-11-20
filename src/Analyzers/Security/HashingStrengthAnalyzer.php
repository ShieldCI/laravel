<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Validates password hashing configuration strength.
 *
 * Checks for:
 * - Bcrypt rounds >= 12 (default 10 is weak)
 * - Argon2 memory >= 65536 KB
 * - Argon2 time >= 2
 * - Weak hashing algorithms (MD5, SHA1)
 */
class HashingStrengthAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Hashing configuration is environment-specific, not applicable in CI.
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'hashing-strength',
            name: 'Password Hashing Strength Analyzer',
            description: 'Validates that password hashing configuration uses secure parameters',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['hashing', 'passwords', 'bcrypt', 'argon2', 'security'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/hashing-strength'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check config/hashing.php
        $this->checkHashingConfig($issues);

        // Check for weak hashing functions in code
        $this->checkWeakHashingInCode($issues);

        if (empty($issues)) {
            return $this->passed('Password hashing configuration is secure');
        }

        return $this->failed(
            sprintf('Found %d password hashing security issues', count($issues)),
            $issues
        );
    }

    /**
     * Check hashing configuration file.
     */
    private function checkHashingConfig(array &$issues): void
    {
        $hashingConfig = ConfigFileHelper::getConfigPath($this->basePath, 'hashing.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        if (! file_exists($hashingConfig)) {
            return;
        }

        $content = FileParser::readFile($hashingConfig);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($hashingConfig);

        foreach ($lines as $lineNumber => $line) {
            // Check bcrypt rounds
            if (preg_match('/["\']rounds["\']\s*=>\s*(\d+)/i', $line, $matches)) {
                $rounds = (int) $matches[1];

                if ($rounds < 12) {
                    $issues[] = $this->createIssue(
                        message: sprintf('Bcrypt rounds (%d) is below recommended minimum of 12', $rounds),
                        location: new Location(
                            $this->getRelativePath($hashingConfig),
                            $lineNumber + 1
                        ),
                        severity: Severity::High,
                        recommendation: 'Set bcrypt rounds to at least 12 for better protection against brute-force attacks',
                        code: trim($line)
                    );
                }
            }

            // Check argon2 memory
            if (preg_match('/["\']memory["\']\s*=>\s*(\d+)/i', $line, $matches)) {
                $memory = (int) $matches[1];

                if ($memory < 65536) {
                    $issues[] = $this->createIssue(
                        message: sprintf('Argon2 memory (%d KB) is below recommended minimum of 65536 KB', $memory),
                        location: new Location(
                            $this->getRelativePath($hashingConfig),
                            $lineNumber + 1
                        ),
                        severity: Severity::High,
                        recommendation: 'Set argon2 memory to at least 65536 KB (64 MB)',
                        code: trim($line)
                    );
                }
            }

            // Check argon2 time cost
            if (preg_match('/["\']time["\']\s*=>\s*(\d+)/i', $line, $matches)) {
                $time = (int) $matches[1];

                if ($time < 2) {
                    $issues[] = $this->createIssue(
                        message: sprintf('Argon2 time cost (%d) is below recommended minimum of 2', $time),
                        location: new Location(
                            $this->getRelativePath($hashingConfig),
                            $lineNumber + 1
                        ),
                        severity: Severity::Medium,
                        recommendation: 'Set argon2 time cost to at least 2',
                        code: trim($line)
                    );
                }
            }

            // Check for weak default driver
            if (preg_match('/["\']driver["\']\s*=>\s*["\'](md5|sha1|sha256)["\']/i', $line, $matches)) {
                $driver = $matches[1];

                $issues[] = $this->createIssue(
                    message: sprintf('Weak hashing driver "%s" configured', $driver),
                    location: new Location(
                        $this->getRelativePath($hashingConfig),
                        $lineNumber + 1
                    ),
                    severity: Severity::Critical,
                    recommendation: 'Use "bcrypt" or "argon2id" as the hashing driver',
                    code: trim($line)
                );
            }
        }
    }

    /**
     * Check for weak hashing functions in code.
     */
    private function checkWeakHashingInCode(array &$issues): void
    {
        $weakHashFunctions = ['md5', 'sha1'];

        foreach ($this->getPhpFiles() as $file) {
            // Skip vendor and test files
            if (str_contains($file, '/vendor/') ||
                str_contains($file, '/tests/') ||
                str_contains($file, '/Tests/')) {
                continue;
            }

            $lines = FileParser::getLines($file);

            foreach ($lines as $lineNumber => $line) {
                // Skip comments
                if (preg_match('/^\s*\/\/|^\s*\*/', $line)) {
                    continue;
                }

                foreach ($weakHashFunctions as $func) {
                    // Check for password hashing with weak functions
                    if (preg_match('/\b'.$func.'\s*\(\s*(?:\$password|\$_POST|\$request|request\()/i', $line)) {
                        $issues[] = $this->createIssue(
                            message: sprintf('Weak hashing function %s() used for password', $func),
                            location: new Location(
                                $this->getRelativePath($file),
                                $lineNumber + 1
                            ),
                            severity: Severity::Critical,
                            recommendation: 'Use Hash::make() or bcrypt() for password hashing',
                            code: trim($line)
                        );
                    }
                }

                // Check for plain password storage
                if (preg_match('/password["\']?\s*=\s*\$(?:password|_POST|_GET|request)/i', $line) &&
                    ! str_contains($line, 'Hash::') &&
                    ! str_contains($line, 'bcrypt(') &&
                    ! str_contains($line, 'password_hash(')) {

                    $issues[] = $this->createIssue(
                        message: 'Potential plain-text password storage detected',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Critical,
                        recommendation: 'Always hash passwords using Hash::make() or bcrypt()',
                        code: trim($line)
                    );
                }
            }
        }
    }
}
