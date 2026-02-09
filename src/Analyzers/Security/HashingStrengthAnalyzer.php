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
            timeToFix: 15
        );
    }

    public function shouldRun(): bool
    {
        // Run if hashing config exists OR if there are PHP files to scan
        $hashingConfig = ConfigFileHelper::getConfigPath(
            $this->getBasePath(),
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
        $hashingConfig = ConfigFileHelper::getConfigPath($this->getBasePath(), 'hashing.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        if (! file_exists($hashingConfig)) {
            return;
        }

        $configArray = $this->loadHashingConfigArray($hashingConfig);

        if (! is_array($configArray)) {
            return;
        }
        $config = $this->getConfiguration();
        $lineMap = $this->mapConfigKeyLines($hashingConfig);

        /**
         * ------------------------------------------------------------
         * Default driver
         * ------------------------------------------------------------
         */
        if (isset($configArray['driver'])) {
            $driver = strtolower((string) $configArray['driver']);

            if (in_array($driver, ['md5', 'sha1', 'sha256'], true)) {
                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf('Weak hashing driver "%s" configured', $driver),
                    filePath: $hashingConfig,
                    lineNumber: $lineMap['driver'] ?? 1,
                    severity: Severity::Critical,
                    recommendation: 'Use "bcrypt" or "argon2id" as the hashing driver',
                    metadata: ['driver' => $driver, 'issue_type' => 'weak_driver']
                );
            }
        }

        /**
         * ------------------------------------------------------------
         * Bcrypt
         * ------------------------------------------------------------
         */
        $minRounds = $config['bcrypt_min_rounds'];

        if (isset($configArray['bcrypt']['rounds']) && is_int($configArray['bcrypt']['rounds']) && $configArray['bcrypt']['rounds'] < $minRounds) {
            $issues[] = $this->createIssueWithSnippet(
                message: sprintf(
                    'Bcrypt rounds (%d) is below recommended minimum of %d',
                    $configArray['bcrypt']['rounds'],
                    $minRounds
                ),
                filePath: $hashingConfig,
                lineNumber: $lineMap['rounds'] ?? ($lineMap['bcrypt'] ?? 1),
                severity: Severity::Critical,
                recommendation: sprintf(
                    'Set bcrypt rounds to at least %d for better protection against brute-force attacks',
                    $minRounds
                ),
                metadata: [
                    'rounds' => $configArray['bcrypt']['rounds'],
                    'issue_type' => 'weak_bcrypt_rounds',
                ]
            );
        }

        /**
         * ------------------------------------------------------------
         * Argon / Argon2id
         * ------------------------------------------------------------
         */
        $argon = $configArray['argon'] ?? $configArray['argon2id'] ?? null;

        if (is_array($argon)) {
            $minArgonMemory = $config['argon2_min_memory'];

            if (
                isset($argon['memory']) &&
                is_int($argon['memory']) &&
                $argon['memory'] < $minArgonMemory
            ) {
                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf(
                        'Argon2 memory (%d KB) is below recommended minimum of %d KB',
                        $argon['memory'],
                        $minArgonMemory
                    ),
                    filePath: $hashingConfig,
                    lineNumber: $lineMap['memory'] ?? ($lineMap['argon'] ?? 1),
                    severity: Severity::Critical,
                    recommendation: sprintf(
                        'Set argon2 memory to at least %d KB',
                        $minArgonMemory
                    ),
                    metadata: [
                        'memory' => $argon['memory'],
                        'issue_type' => 'weak_argon2_memory',
                    ]
                );
            }

            $minArgonTime = $config['argon2_min_time'];
            if (isset($argon['time']) && is_int($argon['time']) && $argon['time'] < $minArgonTime) {
                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf(
                        'Argon2 time cost (%d) is below recommended minimum of %d',
                        $argon['time'],
                        $minArgonTime
                    ),
                    filePath: $hashingConfig,
                    lineNumber: $lineMap['time'] ?? ($lineMap['argon'] ?? 1),
                    severity: Severity::Medium,
                    recommendation: sprintf(
                        'Set argon2 time cost to at least %d',
                        $minArgonTime
                    ),
                    metadata: [
                        'time' => $argon['time'],
                        'issue_type' => 'weak_argon2_time',
                    ]
                );
            }

            $minArgonThreads = $config['argon2_min_threads'];
            if (isset($argon['threads']) && is_int($argon['threads']) && $argon['threads'] < $minArgonThreads) {
                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf(
                        'Argon2 threads (%d) is below recommended minimum of %d',
                        $argon['threads'],
                        $minArgonThreads
                    ),
                    filePath: $hashingConfig,
                    lineNumber: $lineMap['threads'] ?? ($lineMap['argon'] ?? 1),
                    severity: Severity::Low,
                    recommendation: sprintf(
                        'Set argon2 threads to at least %d',
                        $minArgonThreads
                    ),
                    metadata: [
                        'threads' => $argon['threads'],
                        'issue_type' => 'weak_argon2_threads',
                    ]
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
                        $issues[] = $this->createIssueWithSnippet(
                            message: sprintf('Weak hashing function %s() used for password', $func),
                            filePath: $file,
                            lineNumber: $lineNumber + 1,
                            severity: Severity::Critical,
                            recommendation: 'Use Hash::make() or bcrypt() for password hashing',
                            metadata: ['function' => $func, 'issue_type' => 'weak_hash_function']
                        );
                    }
                }

                // Check for weak password_hash algorithms
                if (preg_match('/password_hash\s*\([^,]+,\s*PASSWORD_(MD5|SHA1|SHA256)/i', $codeOnly, $matches)) {
                    $algorithm = $matches[1];

                    $issues[] = $this->createIssueWithSnippet(
                        message: sprintf('Weak password_hash algorithm PASSWORD_%s used', $algorithm),
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::Critical,
                        recommendation: 'Use PASSWORD_BCRYPT or PASSWORD_ARGON2ID',
                        metadata: ['algorithm' => "PASSWORD_$algorithm", 'issue_type' => 'weak_password_hash_algorithm']
                    );
                }

                // Check for plain password storage (improved detection)
                if ($this->isPlainTextPasswordStorage($codeOnly)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Potential plain-text password storage detected',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::Critical,
                        recommendation: 'Always hash passwords using Hash::make() or bcrypt()',
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
     * @return array{
     *    bcrypt_min_rounds: int,
     *    argon2_min_memory: int,
     *    argon2_min_time: int,
     *    argon2_min_threads: int,
     *    ignored_paths: array<int, string>,
     *    allowed_weak_hash_patterns: array<int, string>
     * }
     * */
    private function getConfiguration(): array
    {
        /** @var array{
         *    bcrypt_min_rounds?: int,
         *    argon2_min_memory?: int,
         *    argon2_min_time?: int,
         *    argon2_min_threads?: int,
         *    ignored_paths?: array<int, string>,
         *    allowed_weak_hash_patterns?: array<int, string>
         * } $config
         */
        $config = config('shieldci.hashing_strength', []);

        return [
            'bcrypt_min_rounds' => ($config['bcrypt_min_rounds'] ?? 12),
            'argon2_min_memory' => ($config['argon2_min_memory'] ?? 65536),
            'argon2_min_time' => ($config['argon2_min_time'] ?? 2),
            'argon2_min_threads' => ($config['argon2_min_threads'] ?? 2),
            'ignored_paths' => is_array($config['ignored_paths'] ?? null)
                ? $config['ignored_paths']
                : [],
            'allowed_weak_hash_patterns' => is_array($config['allowed_weak_hash_patterns'] ?? null)
                ? $config['allowed_weak_hash_patterns']
                : [
                    'cache',
                    'fingerprint',
                    'checksum',
                    'etag',
                ],
        ];
    }

    /**
     * Safely load a PHP config file without bootstrapping the app.
     */
    private function loadHashingConfigArray(string $path): ?array
    {
        try {
            $config = require $path;

            return is_array($config) ? $config : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Map config keys to their line numbers.
     *
     * @return array<string, int>
     */
    private function mapConfigKeyLines(string $file): array
    {
        $lines = FileParser::getLines($file);
        $map = [];

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Matches: 'rounds' =>, "memory" =>, etc.
            if (preg_match('/[\'"]([\w]+)[\'"]\s*=>/', $line, $matches)) {
                $key = $matches[1];

                // Only record first occurrence
                $map[$key] ??= $lineNumber + 1;
            }
        }

        return $map;
    }
}
