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
 * - Argon2 threads >= 2
 * - Weak hashing algorithms (MD5, SHA1, SHA256)
 * - Weak password_hash() algorithms
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
            docsUrl: 'https://docs.shieldci.com/analyzers/security/hashing-strength',
            timeToFix: 15
        );
    }

    public function shouldRun(): bool
    {
        // Run if hashing config exists OR if there are PHP files to scan
        $hashingConfig = ConfigFileHelper::getConfigPath(
            $this->basePath,
            'hashing.php',
            fn ($file) => function_exists('config_path') ? config_path($file) : null
        );

        if (file_exists($hashingConfig)) {
            return true;
        }

        // Check if there are any PHP files to scan
        $phpFiles = $this->getPhpFiles();

        return ! empty($phpFiles);
    }

    public function getSkipReason(): string
    {
        return 'No hashing configuration file found and no PHP files to scan';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check config/hashing.php
        $this->checkHashingConfig($issues);

        // Check for weak hashing functions in code
        $this->checkWeakHashingInCode($issues);

        $summary = empty($issues)
            ? 'Password hashing configuration is secure'
            : sprintf('Found %d password hashing security issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
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
        $config = $this->getConfiguration();

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check bcrypt rounds
            /** @var int $bcryptMinRounds */
            $bcryptMinRounds = $config['bcrypt_min_rounds'];
            $this->checkConfigParameter(
                'rounds',
                $bcryptMinRounds,
                '',
                Severity::Critical,
                $issues,
                $hashingConfig,
                $lineNumber,
                $line,
                'Bcrypt rounds',
                'Set bcrypt rounds to at least %d for better protection against brute-force attacks'
            );

            // Check argon2 memory
            /** @var int $argon2MinMemory */
            $argon2MinMemory = $config['argon2_min_memory'];
            $this->checkConfigParameter(
                'memory',
                $argon2MinMemory,
                ' KB',
                Severity::Critical,
                $issues,
                $hashingConfig,
                $lineNumber,
                $line,
                'Argon2 memory',
                'Set argon2 memory to at least %d KB (64 MB)'
            );

            // Check argon2 time cost
            /** @var int $argon2MinTime */
            $argon2MinTime = $config['argon2_min_time'];
            $this->checkConfigParameter(
                'time',
                $argon2MinTime,
                '',
                Severity::Medium,
                $issues,
                $hashingConfig,
                $lineNumber,
                $line,
                'Argon2 time cost',
                'Set argon2 time cost to at least %d'
            );

            // Check argon2 threads
            /** @var int $argon2MinThreads */
            $argon2MinThreads = $config['argon2_min_threads'];
            $this->checkConfigParameter(
                'threads',
                $argon2MinThreads,
                '',
                Severity::Low,
                $issues,
                $hashingConfig,
                $lineNumber,
                $line,
                'Argon2 threads',
                'Set argon2 threads to at least %d'
            );

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
                    code: FileParser::getCodeSnippet($hashingConfig, $lineNumber + 1),
                    metadata: ['driver' => $driver, 'issue_type' => 'weak_driver']
                );
            }
        }
    }

    /**
     * Check configuration parameter against minimum threshold.
     *
     * @param  array<int, mixed>  $issues
     */
    private function checkConfigParameter(
        string $param,
        int $minValue,
        string $unit,
        Severity $severity,
        array &$issues,
        string $file,
        int $lineNumber,
        string $line,
        string $displayName,
        string $recommendationTemplate
    ): void {
        $pattern = sprintf('/["\']%s["\']\s*=>\s*(\d+)/i', preg_quote($param, '/'));

        if (preg_match($pattern, $line, $matches)) {
            $value = (int) $matches[1];

            if ($value < $minValue) {
                $issues[] = $this->createIssue(
                    message: sprintf('%s (%d%s) is below recommended minimum of %d%s',
                        $displayName,
                        $value,
                        $unit,
                        $minValue,
                        $unit
                    ),
                    location: new Location($this->getRelativePath($file), $lineNumber + 1),
                    severity: $severity,
                    recommendation: sprintf($recommendationTemplate, $minValue),
                    code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                    metadata: [$param => $value, 'issue_type' => 'weak_'.$param]
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
        $config = $this->getConfiguration();

        foreach ($this->getPhpFiles() as $file) {
            // Skip vendor and test files
            if (str_contains($file, '/vendor/') ||
                str_contains($file, '/tests/') ||
                str_contains($file, '/Tests/')) {
                continue;
            }

            // Skip ignored paths
            $relativePath = $this->getRelativePath($file);
            foreach ($config['ignored_paths'] as $ignoredPath) {
                if (is_string($ignoredPath) && str_contains($relativePath, $ignoredPath)) {
                    continue 2;
                }
            }

            $lines = FileParser::getLines($file);

            foreach ($lines as $lineNumber => $line) {
                if (! is_string($line)) {
                    continue;
                }

                // Skip comments (improved detection)
                if ($this->isCommentLine($line)) {
                    continue;
                }

                // Remove inline comments for analysis
                $codeOnly = preg_replace('/\/\/.*$/', '', $line);
                if (! is_string($codeOnly)) {
                    continue;
                }

                // Check for weak hash functions
                foreach ($weakHashFunctions as $func) {
                    // Skip if this is an allowed pattern (cache, fingerprint, etc.)
                    /** @var array<int, string> $allowedPatterns */
                    $allowedPatterns = $config['allowed_weak_hash_patterns'];
                    if ($this->isAllowedWeakHashPattern($codeOnly, $allowedPatterns)) {
                        continue;
                    }

                    // Check for password hashing with weak functions
                    // Detect password variable hashing (direct or through object/array access)
                    if (preg_match('/\b'.$func.'\s*\(\s*\$(?:password|(?:request|_POST|_GET)(?:->|\[).*password)/i', $codeOnly)) {
                        $issues[] = $this->createIssue(
                            message: sprintf('Weak hashing function %s() used for password', $func),
                            location: new Location(
                                $this->getRelativePath($file),
                                $lineNumber + 1
                            ),
                            severity: Severity::Critical,
                            recommendation: 'Use Hash::make() or bcrypt() for password hashing',
                            code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                            metadata: ['function' => $func, 'issue_type' => 'weak_hash_function']
                        );
                    }
                }

                // Check for weak password_hash algorithms
                if (preg_match('/password_hash\s*\([^,]+,\s*PASSWORD_(MD5|SHA1|SHA256)/i', $codeOnly, $matches)) {
                    $algorithm = $matches[1];

                    $issues[] = $this->createIssue(
                        message: sprintf('Weak password_hash algorithm PASSWORD_%s used', $algorithm),
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Critical,
                        recommendation: 'Use PASSWORD_BCRYPT or PASSWORD_ARGON2ID',
                        code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                        metadata: ['algorithm' => "PASSWORD_$algorithm", 'issue_type' => 'weak_password_hash_algorithm']
                    );
                }

                // Check for plain password storage (improved detection)
                if ($this->isPlainTextPasswordStorage($codeOnly)) {
                    $issues[] = $this->createIssue(
                        message: 'Potential plain-text password storage detected',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Critical,
                        recommendation: 'Always hash passwords using Hash::make() or bcrypt()',
                        code: FileParser::getCodeSnippet($file, $lineNumber + 1),
                        metadata: ['issue_type' => 'plain_text_password']
                    );
                }
            }
        }
    }

    /**
     * Check if line is a comment.
     */
    private function isCommentLine(string $line): bool
    {
        $trimmed = trim($line);

        return str_starts_with($trimmed, '//') ||
               str_starts_with($trimmed, '*') ||
               str_starts_with($trimmed, '/*') ||
               str_starts_with($trimmed, '#');
    }

    /**
     * Check if weak hash usage matches allowed patterns.
     *
     * @param  array<int, string>  $allowedPatterns
     */
    private function isAllowedWeakHashPattern(string $line, array $allowedPatterns): bool
    {
        foreach ($allowedPatterns as $pattern) {
            if (is_string($pattern) && stripos($line, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if line represents plain-text password storage.
     */
    private function isPlainTextPasswordStorage(string $line): bool
    {
        // Don't flag comparisons (===, ==, !=, !==)
        if (preg_match('/[=!]==?/', $line)) {
            return false;
        }

        // Don't flag hashed variable names
        if (preg_match('/\$(hashed|encrypted|encoded|hash)Password/i', $line)) {
            return false;
        }

        // Don't flag if Hash::, bcrypt(), or password_hash() is present
        if (str_contains($line, 'Hash::') ||
            str_contains($line, 'bcrypt(') ||
            str_contains($line, 'password_hash(')) {
            return false;
        }

        // Detect password assignment from user input
        if (preg_match('/password["\']?\s*=\s*\$(?:password|_POST|_GET|request)/i', $line)) {
            return true;
        }

        return false;
    }

    /**
     * Get analyzer configuration.
     *
     * @return array<string, mixed>
     */
    private function getConfiguration(): array
    {
        /** @var array<string, mixed> $config */
        $config = config('shieldci.hashing_strength', []);

        return array_merge([
            'bcrypt_min_rounds' => 12,
            'argon2_min_memory' => 65536,
            'argon2_min_time' => 2,
            'argon2_min_threads' => 2,
            'ignored_paths' => [],
            'allowed_weak_hash_patterns' => [
                'cache',
                'fingerprint',
                'checksum',
                'etag',
            ],
        ], $config);
    }
}
