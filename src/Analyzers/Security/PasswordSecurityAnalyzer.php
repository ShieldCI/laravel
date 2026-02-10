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
 * Validates password security: hashing configuration AND password policies.
 *
 * Hashing checks (from original HashingStrengthAnalyzer):
 * - Bcrypt rounds >= 12 (default 10 is weak)
 * - Argon2 memory >= 65536 KB
 * - Argon2 time >= 2
 * - Argon2 threads >= 2
 * - Weak hashing algorithms (MD5, SHA1, SHA256)
 * - Weak password_hash() algorithms
 *
 * Password policy checks (new):
 * - Password::defaults() usage in AppServiceProvider
 * - Minimum password length in validation rules
 * - Complexity rules (letters, mixedCase, numbers, symbols)
 * - Breached password check (uncompromised())
 * - Password confirmation timeout in auth config
 */
class PasswordSecurityAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Hashing configuration is environment-specific, not applicable in CI.
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'password-security',
            name: 'Password Security Analyzer',
            description: 'Validates password hashing configuration and password policy enforcement',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['hashing', 'passwords', 'bcrypt', 'argon2', 'security', 'policy', 'validation'],
            timeToFix: 20
        );
    }

    public function shouldRun(): bool
    {
        $hashingConfig = ConfigFileHelper::getConfigPath(
            $this->getBasePath(),
            'hashing.php',
            fn ($file) => function_exists('config_path') ? config_path($file) : null
        );

        if (file_exists($hashingConfig)) {
            return true;
        }

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

        $this->checkHashingConfig($issues);
        $this->checkWeakHashingInCode($issues);
        $this->checkPasswordPolicyDefaults($issues);
        $this->checkPasswordValidationRules($issues);
        $this->checkPasswordConfirmationTimeout($issues);

        $summary = empty($issues)
            ? 'Password security configuration is strong'
            : sprintf('Found %d password security issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

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

    private function checkWeakHashingInCode(array &$issues): void
    {
        $weakHashFunctions = ['md5', 'sha1'];
        $config = $this->getConfiguration();

        foreach ($this->getPhpFiles() as $file) {
            if (str_contains($file, '/vendor/') ||
                str_contains($file, '/tests/') ||
                str_contains($file, '/Tests/') ||
                str_contains($file, '/database/seeders/') ||
                str_contains($file, '/database/factories/')) {
                continue;
            }

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

                if ($this->isCommentLine($line)) {
                    continue;
                }

                $codeOnly = preg_replace('/\/\/.*$/', '', $line);
                if (! is_string($codeOnly)) {
                    continue;
                }

                $codeOnly = preg_replace('/\/\*.*?\*\//', '', $codeOnly);
                if (! is_string($codeOnly)) {
                    continue;
                }

                foreach ($weakHashFunctions as $func) {
                    /** @var array<int, string> $allowedPatterns */
                    $allowedPatterns = $config['allowed_weak_hash_patterns'];
                    if ($this->isAllowedWeakHashPattern($codeOnly, $allowedPatterns)) {
                        continue;
                    }

                    if (preg_match('/\b'.$func.'\s*\(\s*\$(?:password\b|(?:request|_POST|_GET)(?:->|\[).*password)/i', $codeOnly)) {
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

    private function checkPasswordPolicyDefaults(array &$issues): void
    {
        $serviceProviderPaths = $this->getPasswordPolicyPaths();
        $bootstrapApp = $this->buildPath('bootstrap', 'app.php');

        $anyProviderExists = false;
        $foundPasswordDefaults = false;
        $hasUncompromised = false;
        $hasMinLength = false;
        $hasMixedCase = false;

        foreach ($serviceProviderPaths as $providerPath) {
            if (! file_exists($providerPath)) {
                continue;
            }

            if ($providerPath !== $bootstrapApp) {
                $anyProviderExists = true;
            }

            $content = FileParser::readFile($providerPath);
            if ($content === null) {
                continue;
            }

            $codeContent = $this->stripComments($content);

            if (preg_match('/Password::defaults\s*\(/', $codeContent)) {
                $foundPasswordDefaults = true;
                $anyProviderExists = true;

                $defaultsBody = $this->extractDefaultsBody($codeContent);

                if (str_contains($defaultsBody, '->uncompromised(') || str_contains($defaultsBody, 'uncompromised()')) {
                    $hasUncompromised = true;
                }

                if (preg_match('/Password::min\s*\(\s*(\d+)/', $defaultsBody, $minMatch)) {
                    $minLength = (int) $minMatch[1];
                    $hasMinLength = $minLength >= 8;
                }

                if (str_contains($defaultsBody, '->mixedCase(')) {
                    $hasMixedCase = true;
                }
            }
        }

        if (! $anyProviderExists) {
            return;
        }

        if (! $foundPasswordDefaults) {
            $issues[] = $this->createIssue(
                message: 'No Password::defaults() configured in service providers',
                location: new \ShieldCI\AnalyzersCore\ValueObjects\Location('app/Providers/AppServiceProvider.php'),
                severity: Severity::Medium,
                recommendation: 'Define password validation defaults in a service provider boot() method or bootstrap/app.php: Password::defaults(function () { return Password::min(8)->letters()->mixedCase()->numbers()->symbols()->uncompromised(); });',
                metadata: ['issue_type' => 'missing_password_defaults']
            );

            return;
        }

        if (! $hasMinLength) {
            $issues[] = $this->createIssue(
                message: 'Password::defaults() does not enforce minimum 8 character length',
                location: new \ShieldCI\AnalyzersCore\ValueObjects\Location('app/Providers/AppServiceProvider.php'),
                severity: Severity::Medium,
                recommendation: 'Set minimum password length: Password::min(8)',
                metadata: ['issue_type' => 'weak_password_min_length']
            );
        }

        if (! $hasMixedCase) {
            $issues[] = $this->createIssue(
                message: 'Password::defaults() does not require mixed case characters',
                location: new \ShieldCI\AnalyzersCore\ValueObjects\Location('app/Providers/AppServiceProvider.php'),
                severity: Severity::Low,
                recommendation: 'Add mixed case requirement: Password::min(8)->mixedCase()',
                metadata: ['issue_type' => 'no_mixed_case_requirement']
            );
        }

        if (! $hasUncompromised) {
            $issues[] = $this->createIssue(
                message: 'Password::defaults() does not check against breached password databases',
                location: new \ShieldCI\AnalyzersCore\ValueObjects\Location('app/Providers/AppServiceProvider.php'),
                severity: Severity::Low,
                recommendation: 'Add breached password check: Password::min(8)->uncompromised()',
                metadata: ['issue_type' => 'no_breached_password_check']
            );
        }
    }

    private function checkPasswordValidationRules(array &$issues): void
    {
        foreach ($this->getPhpFiles() as $file) {
            if (! str_contains($file, '/Requests/') && ! str_contains($file, '/Controllers/')) {
                continue;
            }

            if (str_contains($file, '/vendor/') || str_contains($file, '/tests/') || str_contains($file, '/Tests/')) {
                continue;
            }

            $content = FileParser::readFile($file);
            if ($content === null) {
                continue;
            }

            $lines = FileParser::getLines($file);

            foreach ($lines as $lineNumber => $line) {
                if (! is_string($line)) {
                    continue;
                }

                if ($this->isCommentLine($line)) {
                    continue;
                }

                if (preg_match("/['\"]password['\"].*\bmin:(\d+)/", $line, $matches)) {
                    $minLen = (int) $matches[1];
                    if ($minLen < 8) {
                        $issues[] = $this->createIssueWithSnippet(
                            message: sprintf('Password validation requires only %d characters (minimum recommended: 8)', $minLen),
                            filePath: $file,
                            lineNumber: $lineNumber + 1,
                            severity: Severity::Medium,
                            recommendation: 'Set minimum password length to at least 8 characters: \'password\' => [\'required\', Password::min(8)]',
                            metadata: ['min_length' => $minLen, 'issue_type' => 'weak_validation_min_length']
                        );
                    }
                }
            }
        }
    }

    private function checkPasswordConfirmationTimeout(array &$issues): void
    {
        $authConfig = ConfigFileHelper::getConfigPath(
            $this->getBasePath(),
            'auth.php',
            fn ($file) => function_exists('config_path') ? config_path($file) : null
        );

        if (! file_exists($authConfig)) {
            return;
        }

        $content = FileParser::readFile($authConfig);
        if ($content === null) {
            return;
        }

        if (preg_match("/['\"]password_timeout['\"]\\s*=>\\s*(\\d+)/", $content, $matches)) {
            $timeout = (int) $matches[1];

            if ($timeout > 3600) {
                $lineMap = $this->mapConfigKeyLines($authConfig);

                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf('Password confirmation timeout is %d seconds (%s) - consider reducing', $timeout, $this->formatDuration($timeout)),
                    filePath: $authConfig,
                    lineNumber: $lineMap['password_timeout'] ?? 1,
                    severity: Severity::Low,
                    recommendation: 'Reduce password confirmation timeout to 3600 seconds (1 hour) or less for better security',
                    metadata: [
                        'timeout_seconds' => $timeout,
                        'issue_type' => 'long_password_confirmation_timeout',
                    ]
                );
            }
        }
    }

    private function formatDuration(int $seconds): string
    {
        $hours = intdiv($seconds, 3600);
        $minutes = intdiv($seconds % 3600, 60);

        if ($hours > 0 && $minutes > 0) {
            return sprintf('%dh %dm', $hours, $minutes);
        }

        if ($hours > 0) {
            return sprintf('%dh', $hours);
        }

        return sprintf('%dm', $minutes);
    }

    private function isCommentLine(string $line): bool
    {
        $trimmed = trim($line);

        return str_starts_with($trimmed, '//') ||
               str_starts_with($trimmed, '*') ||
               str_starts_with($trimmed, '/*') ||
               str_starts_with($trimmed, '#');
    }

    /**
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

    private function isPlainTextPasswordStorage(string $line): bool
    {
        if (preg_match('/[=!]==?/', $line)) {
            return false;
        }

        if (preg_match('/\$(hashed|encrypted|encoded|hash)Password/i', $line)) {
            return false;
        }

        if (str_contains($line, 'Hash::') ||
            str_contains($line, 'bcrypt(') ||
            str_contains($line, 'password_hash(')) {
            return false;
        }

        if (preg_match('/->password\s*=/', $line)) {
            return false;
        }

        if (preg_match('/password["\']?\s*=\s*\$(?:password|_POST|_GET|request)/i', $line)) {
            return true;
        }

        return false;
    }

    /**
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
        $config = config('shieldci.password_security', []);

        if (empty($config)) {
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
        }

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

    private function loadHashingConfigArray(string $path): ?array
    {
        try {
            $config = require $path;

            return is_array($config) ? $config : null;
        } catch (\Throwable) {
            return null;
        }
    }

    private function stripComments(string $content): string
    {
        $tokens = @token_get_all($content);
        $result = '';

        foreach ($tokens as $token) {
            if (is_array($token)) {
                if ($token[0] === T_COMMENT || $token[0] === T_DOC_COMMENT) {
                    continue;
                }
                $result .= $token[1];
            } else {
                $result .= $token;
            }
        }

        return $result;
    }

    /**
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

            if (preg_match('/[\'"]([\w]+)[\'"]\s*=>/', $line, $matches)) {
                $key = $matches[1];
                $map[$key] ??= $lineNumber + 1;
            }
        }

        return $map;
    }

    /**
     * @return array<int, string>
     */
    private function getPasswordPolicyPaths(): array
    {
        $paths = [
            $this->buildPath('app', 'Providers', 'AppServiceProvider.php'),
            $this->buildPath('app', 'Providers', 'AuthServiceProvider.php'),
            $this->buildPath('bootstrap', 'app.php'),
        ];

        $providersDir = $this->buildPath('app', 'Providers');
        if (is_dir($providersDir)) {
            /** @var array<int, string>|false $files */
            $files = glob($providersDir.'/*.php');
            if (is_array($files)) {
                foreach ($files as $file) {
                    if (! in_array($file, $paths, true)) {
                        $paths[] = $file;
                    }
                }
            }
        }

        return $paths;
    }

    private function extractDefaultsBody(string $content): string
    {
        $pos = strpos($content, 'Password::defaults(');
        if ($pos === false) {
            return '';
        }

        $start = $pos + strlen('Password::defaults(');
        $depth = 1;
        $end = $start;
        $len = strlen($content);

        while ($end < $len && $depth > 0) {
            if ($content[$end] === '(') {
                $depth++;
            } elseif ($content[$end] === ')') {
                $depth--;
            }
            $end++;
        }

        return substr($content, $start, $end - $start - 1);
    }
}
