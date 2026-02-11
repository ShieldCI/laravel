<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use PhpParser\Node;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
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

    public function __construct(
        private ParserInterface $parser
    ) {}

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
        $this->checkPasswordRehashUsage($issues);

        $summary = empty($issues)
            ? 'Password security configuration is strong'
            : sprintf('Found %d password security issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * @param  array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
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

        $driverValue = $configArray['driver'] ?? null;
        $driver = is_string($driverValue) ? strtolower($driverValue) : null;

        if ($driver !== null && in_array($driver, ['md5', 'sha1', 'sha256'], true)) {
            $issues[] = $this->createIssueWithSnippet(
                message: sprintf('Weak hashing driver "%s" configured', $driver),
                filePath: $hashingConfig,
                lineNumber: $lineMap['driver'] ?? 1,
                severity: Severity::Critical,
                recommendation: 'Use "bcrypt" or "argon2id" as the hashing driver',
                metadata: ['driver' => $driver, 'issue_type' => 'weak_driver']
            );
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

        $isArgonDriver = ($driver === null || in_array($driver, ['argon2id', 'argon2i', 'argon'], true));

        if (! $isArgonDriver) {
            return;
        }

        $argon = $configArray['argon'] ?? $configArray['argon2id'] ?? null;

        if (! is_array($argon)) {
            return;
        }

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

    /**
     * @param  array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function checkWeakHashingInCode(array &$issues): void
    {
        $config = $this->getConfiguration();

        foreach ($this->getPhpFiles() as $file) {
            if ($this->shouldSkipFileForCodeScan($file, $config)) {
                continue;
            }

            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            $this->detectWeakHashing($file, $ast, $config, $issues);
            $this->detectWeakPasswordHashAlgorithm($file, $ast, $config, $issues);
            $this->detectPlainTextPasswordStorage($file, $ast, $issues);
        }
    }

    /**
     * @param  array<Node>  $ast
     * @param  array{bcrypt_min_rounds: int, argon2_min_memory: int, argon2_min_time: int, argon2_min_threads: int, ignored_paths: array<int, string>, allowed_weak_hash_patterns: array<int, string>, password_confirmation_max_timeout: int}  $config
     * @param  array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function detectWeakHashing(string $file, array $ast, array $config, array &$issues): void
    {
        $weakFunctions = ['md5', 'sha1'];
        $weakHashAlgorithms = ['md5', 'sha1', 'sha256', 'sha384', 'sha512'];

        /** @var array<Node\Expr\FuncCall> $calls */
        $calls = $this->parser->findNodes($ast, Node\Expr\FuncCall::class);

        foreach ($calls as $call) {
            if (! $call instanceof Node\Expr\FuncCall) {
                continue;
            }

            if (! $call->name instanceof Node\Name) {
                continue;
            }

            $func = $call->name->toString();

            if (in_array($func, $weakFunctions, true)) {
                if (empty($call->args) || ! isset($call->args[0]) || ! $call->args[0] instanceof Node\Arg) {
                    continue;
                }

                if (! $this->isPasswordRelatedArgument($call->args[0]->value)) {
                    continue;
                }

                $lineNumber = $call->getStartLine();
                $lineContent = $this->getLineContent($file, $lineNumber);

                /** @var array<int, string> $allowedPatterns */
                $allowedPatterns = $config['allowed_weak_hash_patterns'];
                if ($lineContent !== null && $this->isAllowedWeakHashPattern($lineContent, $allowedPatterns)) {
                    continue;
                }

                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf('Weak hashing function %s() used for password', $func),
                    filePath: $file,
                    lineNumber: $lineNumber,
                    severity: Severity::Critical,
                    recommendation: 'Use Hash::make() or bcrypt() for password hashing',
                    metadata: ['function' => $func, 'issue_type' => 'weak_hash_function']
                );
            } elseif ($func === 'hash') {
                if (count($call->args) < 2
                    || ! isset($call->args[0], $call->args[1])
                    || ! $call->args[0] instanceof Node\Arg
                    || ! $call->args[1] instanceof Node\Arg) {
                    continue;
                }

                $algoArg = $call->args[0]->value;
                if (! $algoArg instanceof Node\Scalar\String_) {
                    continue;
                }

                $algo = strtolower($algoArg->value);
                if (! in_array($algo, $weakHashAlgorithms, true)) {
                    continue;
                }

                if (! $this->isPasswordRelatedArgument($call->args[1]->value)) {
                    continue;
                }

                $lineNumber = $call->getStartLine();
                $lineContent = $this->getLineContent($file, $lineNumber);

                /** @var array<int, string> $allowedPatterns */
                $allowedPatterns = $config['allowed_weak_hash_patterns'];
                if ($lineContent !== null && $this->isAllowedWeakHashPattern($lineContent, $allowedPatterns)) {
                    continue;
                }

                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf("Weak hashing algorithm hash('%s') used for password", $algo),
                    filePath: $file,
                    lineNumber: $lineNumber,
                    severity: Severity::Critical,
                    recommendation: 'Use Hash::make() or bcrypt() for password hashing',
                    metadata: ['function' => 'hash', 'algorithm' => $algo, 'issue_type' => 'weak_hash_function']
                );
            }
        }
    }

    /**
     * @param  array<Node>  $ast
     * @param  array{bcrypt_min_rounds: int, argon2_min_memory: int, argon2_min_time: int, argon2_min_threads: int, ignored_paths: array<int, string>, allowed_weak_hash_patterns: array<int, string>, password_confirmation_max_timeout: int}  $config
     * @param  array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function detectWeakPasswordHashAlgorithm(string $file, array $ast, array $config, array &$issues): void
    {
        $safeConstants = ['PASSWORD_DEFAULT', 'PASSWORD_BCRYPT', 'PASSWORD_ARGON2I', 'PASSWORD_ARGON2ID'];

        /** @var array<Node\Expr\FuncCall> $calls */
        $calls = $this->parser->findNodes($ast, Node\Expr\FuncCall::class);

        foreach ($calls as $call) {
            if (! $call instanceof Node\Expr\FuncCall) {
                continue;
            }

            if (! $call->name instanceof Node\Name || $call->name->toString() !== 'password_hash') {
                continue;
            }

            if (empty($call->args) || ! isset($call->args[0]) || ! $call->args[0] instanceof Node\Arg) {
                continue;
            }

            if (! $this->isPasswordRelatedArgument($call->args[0]->value)) {
                continue;
            }

            if (! isset($call->args[1]) || ! $call->args[1] instanceof Node\Arg) {
                continue;
            }

            $algoArg = $call->args[1]->value;

            $isSafeAlgo = $algoArg instanceof Node\Expr\ConstFetch
                && $algoArg->name instanceof Node\Name
                && in_array($algoArg->name->toString(), $safeConstants, true);

            if (! $isSafeAlgo) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'password_hash() called with potentially weak or unknown algorithm',
                    filePath: $file,
                    lineNumber: $call->getStartLine(),
                    severity: Severity::Critical,
                    recommendation: 'Use PASSWORD_DEFAULT, PASSWORD_BCRYPT, or PASSWORD_ARGON2ID as the algorithm argument',
                    metadata: ['issue_type' => 'weak_password_hash_algorithm']
                );

                continue;
            }

            if (isset($call->args[2])
                && $call->args[2] instanceof Node\Arg
                && $call->args[2]->value instanceof Node\Expr\Array_
                && $algoArg instanceof Node\Expr\ConstFetch
                && $algoArg->name instanceof Node\Name
            ) {
                $this->validatePasswordHashOptions($file, $call, $call->args[2]->value, $algoArg->name->toString(), $config, $issues);
            }
        }
    }

    /**
     * @param  array{bcrypt_min_rounds: int, argon2_min_memory: int, argon2_min_time: int, argon2_min_threads: int, ignored_paths: array<int, string>, allowed_weak_hash_patterns: array<int, string>, password_confirmation_max_timeout: int}  $config
     * @param  array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function validatePasswordHashOptions(
        string $file,
        Node\Expr\FuncCall $call,
        Node\Expr\Array_ $optionsArray,
        string $algoName,
        array $config,
        array &$issues
    ): void {
        if ($algoName === 'PASSWORD_DEFAULT') {
            $issues[] = $this->createIssueWithSnippet(
                message: 'password_hash() uses PASSWORD_DEFAULT with an explicit options array; options are algorithm-specific and may become invalid if PHP changes the default algorithm',
                filePath: $file,
                lineNumber: $call->getStartLine(),
                severity: Severity::Info,
                recommendation: "Use Laravel's Hash::make() for password hashing, or specify an explicit algorithm constant (PASSWORD_BCRYPT or PASSWORD_ARGON2ID) when algorithm-specific options are needed",
                metadata: ['issue_type' => 'password_default_with_options']
            );

            return;
        }

        $isBcrypt = $algoName === 'PASSWORD_BCRYPT';
        $isArgon = in_array($algoName, ['PASSWORD_ARGON2I', 'PASSWORD_ARGON2ID'], true);

        $validKeys = $isBcrypt
            ? ['cost']
            : ($isArgon ? ['memory_cost', 'time_cost', 'threads'] : []);

        $unknownKeys = [];
        foreach ($optionsArray->items as $item) {
            if (! $item instanceof Node\Expr\ArrayItem) {
                continue;
            }

            $key = $this->extractPasswordHashArrayKey($item->key);
            if ($key === null) {
                continue;
            }

            if (! in_array($key, $validKeys, true)) {
                $unknownKeys[] = $key;
            }

            if (! $item->value instanceof Node\Scalar\Int_) {
                continue;
            }

            $value = $item->value->value;

            if ($isBcrypt && $key === 'cost' && $value < $config['bcrypt_min_rounds']) {
                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf(
                        'password_hash() bcrypt cost (%d) is below recommended minimum of %d',
                        $value,
                        $config['bcrypt_min_rounds']
                    ),
                    filePath: $file,
                    lineNumber: $call->getStartLine(),
                    severity: Severity::Critical,
                    recommendation: sprintf(
                        'Set bcrypt cost to at least %d for better protection against brute-force attacks',
                        $config['bcrypt_min_rounds']
                    ),
                    metadata: ['cost' => $value, 'issue_type' => 'weak_password_hash_bcrypt_cost']
                );
            }

            if ($isArgon && $key === 'memory_cost' && $value < $config['argon2_min_memory']) {
                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf(
                        'password_hash() argon2 memory_cost (%d KB) is below recommended minimum of %d KB',
                        $value,
                        $config['argon2_min_memory']
                    ),
                    filePath: $file,
                    lineNumber: $call->getStartLine(),
                    severity: Severity::Critical,
                    recommendation: sprintf(
                        'Set argon2 memory_cost to at least %d KB',
                        $config['argon2_min_memory']
                    ),
                    metadata: ['memory_cost' => $value, 'issue_type' => 'weak_password_hash_argon2_memory']
                );
            }

            if ($isArgon && $key === 'time_cost' && $value < $config['argon2_min_time']) {
                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf(
                        'password_hash() argon2 time_cost (%d) is below recommended minimum of %d',
                        $value,
                        $config['argon2_min_time']
                    ),
                    filePath: $file,
                    lineNumber: $call->getStartLine(),
                    severity: Severity::Medium,
                    recommendation: sprintf(
                        'Set argon2 time_cost to at least %d',
                        $config['argon2_min_time']
                    ),
                    metadata: ['time_cost' => $value, 'issue_type' => 'weak_password_hash_argon2_time']
                );
            }

            if ($isArgon && $key === 'threads' && $value < $config['argon2_min_threads']) {
                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf(
                        'password_hash() argon2 threads (%d) is below recommended minimum of %d',
                        $value,
                        $config['argon2_min_threads']
                    ),
                    filePath: $file,
                    lineNumber: $call->getStartLine(),
                    severity: Severity::Low,
                    recommendation: sprintf(
                        'Set argon2 threads to at least %d',
                        $config['argon2_min_threads']
                    ),
                    metadata: ['threads' => $value, 'issue_type' => 'weak_password_hash_argon2_threads']
                );
            }
        }

        if (! empty($unknownKeys)) {
            $issues[] = $this->createIssueWithSnippet(
                message: sprintf('password_hash() options contain unknown key(s): %s', implode(', ', $unknownKeys)),
                filePath: $file,
                lineNumber: $call->getStartLine(),
                severity: Severity::Info,
                recommendation: sprintf('Valid options for %s are: %s. Remove unrecognized keys.', $algoName, implode(', ', $validKeys)),
                metadata: ['issue_type' => 'unknown_password_hash_options', 'unknown_keys' => $unknownKeys]
            );
        }
    }

    /**
     * Extract a string key from an array item key node.
     */
    private function extractPasswordHashArrayKey(?Node\Expr $keyNode): ?string
    {
        if ($keyNode === null) {
            return null;
        }

        if ($keyNode instanceof Node\Scalar\String_) {
            return $keyNode->value;
        }

        return null;
    }

    /**
     * @param  array<Node>  $ast
     * @param  array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function detectPlainTextPasswordStorage(string $file, array $ast, array &$issues): void
    {
        /** @var array<Node\Expr\Assign> $assignments */
        $assignments = $this->parser->findNodes($ast, Node\Expr\Assign::class);

        foreach ($assignments as $assign) {
            if (! $assign instanceof Node\Expr\Assign) {
                continue;
            }

            if (! $this->isPasswordAssignmentTarget($assign->var)) {
                continue;
            }

            if ($this->isHashedValue($assign->expr)) {
                continue;
            }

            if (! $this->isRawPasswordInput($assign->expr)) {
                continue;
            }

            $issues[] = $this->createIssueWithSnippet(
                message: 'Potential plain-text password storage detected',
                filePath: $file,
                lineNumber: $assign->getStartLine(),
                severity: Severity::Critical,
                recommendation: 'Always hash passwords using Hash::make() or bcrypt()',
                metadata: ['issue_type' => 'plain_text_password']
            );
        }
    }

    private function isPasswordRelatedArgument(Node $node): bool
    {
        if ($node instanceof Node\Expr\Variable && is_string($node->name) && $node->name === 'password') {
            return true;
        }

        if ($node instanceof Node\Expr\PropertyFetch
            && $node->name instanceof Node\Identifier
            && $node->name->name === 'password') {
            return true;
        }

        if ($node instanceof Node\Expr\MethodCall
            && $node->name instanceof Node\Identifier
            && in_array($node->name->name, ['input', 'get'], true)
            && ! empty($node->args)
            && isset($node->args[0])
            && $node->args[0] instanceof Node\Arg
            && $node->args[0]->value instanceof Node\Scalar\String_
            && $node->args[0]->value->value === 'password') {
            return true;
        }

        if ($node instanceof Node\Expr\ArrayDimFetch
            && $node->dim instanceof Node\Scalar\String_
            && $node->dim->value === 'password') {
            return true;
        }

        if ($node instanceof Node\Expr\BinaryOp\Coalesce) {
            return $this->isPasswordRelatedArgument($node->left);
        }

        return false;
    }

    private function isPasswordAssignmentTarget(Node $node): bool
    {
        if ($node instanceof Node\Expr\Variable && is_string($node->name) && $node->name === 'password') {
            return true;
        }

        if ($node instanceof Node\Expr\PropertyFetch
            && $node->name instanceof Node\Identifier
            && $node->name->name === 'password') {
            return true;
        }

        if ($node instanceof Node\Expr\ArrayDimFetch
            && $node->dim instanceof Node\Scalar\String_
            && $node->dim->value === 'password') {
            return true;
        }

        return false;
    }

    private function isHashedValue(Node $node): bool
    {
        if ($node instanceof Node\Expr\StaticCall
            && $node->class instanceof Node\Name
            && $node->class->toString() === 'Hash'
            && $node->name instanceof Node\Identifier
            && $node->name->name === 'make') {
            return true;
        }

        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $name = $node->name->toString();
            if (in_array($name, ['bcrypt', 'password_hash'], true)) {
                return true;
            }
        }

        if ($node instanceof Node\Expr\MethodCall
            && $node->name instanceof Node\Identifier
            && $node->name->name === 'make'
            && $node->var instanceof Node\Expr\StaticCall
            && $node->var->class instanceof Node\Name
            && $node->var->class->toString() === 'Hash'
            && $node->var->name instanceof Node\Identifier
            && $node->var->name->name === 'driver') {
            return true;
        }

        return false;
    }

    private function isRawPasswordInput(Node $node): bool
    {
        return $this->isPasswordRelatedArgument($node);
    }

    /**
     * @param  array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function checkPasswordPolicyDefaults(array &$issues): void
    {
        $serviceProviderPaths = $this->getPasswordPolicyPaths();
        $bootstrapApp = $this->buildPath('bootstrap', 'app.php');

        $anyProviderExists = false;
        $foundPasswordDefaults = false;

        /** @var array<int, array{uncompromised: bool, minLength: bool, mixedCase: bool}> $callResults */
        $callResults = [];

        foreach ($serviceProviderPaths as $providerPath) {
            if (! file_exists($providerPath)) {
                continue;
            }

            if ($providerPath !== $bootstrapApp) {
                $anyProviderExists = true;
            }

            $ast = $this->parser->parseFile($providerPath);
            if (empty($ast)) {
                continue;
            }

            /** @var array<Node\Expr\StaticCall> $defaultsCalls */
            $defaultsCalls = $this->parser->findStaticCalls($ast, 'Password', 'defaults');

            if (empty($defaultsCalls)) {
                continue;
            }

            $foundPasswordDefaults = true;
            $anyProviderExists = true;

            foreach ($defaultsCalls as $defaultsCall) {
                if (! $defaultsCall instanceof Node\Expr\StaticCall) {
                    continue;
                }

                if (empty($defaultsCall->args) || ! isset($defaultsCall->args[0]) || ! $defaultsCall->args[0] instanceof Node\Arg) {
                    continue;
                }

                $closureArg = $defaultsCall->args[0]->value;

                if (! $closureArg instanceof Node\Expr\Closure && ! $closureArg instanceof Node\Expr\ArrowFunction) {
                    continue;
                }

                $callUncompromised = false;
                $callMinLength = false;
                $callMixedCase = false;
                $this->analyzePasswordDefaultsBody($closureArg, $callUncompromised, $callMinLength, $callMixedCase);
                $callResults[] = ['uncompromised' => $callUncompromised, 'minLength' => $callMinLength, 'mixedCase' => $callMixedCase];
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

        $hasUncompromised = ! empty($callResults);
        $hasMinLength = ! empty($callResults);
        $hasMixedCase = ! empty($callResults);

        foreach ($callResults as $r) {
            if (! $r['uncompromised']) {
                $hasUncompromised = false;
            }
            if (! $r['minLength']) {
                $hasMinLength = false;
            }
            if (! $r['mixedCase']) {
                $hasMixedCase = false;
            }
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

    private function analyzePasswordDefaultsBody(Node\Expr\Closure|Node\Expr\ArrowFunction $closureNode, bool &$hasUncompromised, bool &$hasMinLength, bool &$hasMixedCase): void
    {
        /** @var array<Node\Expr\MethodCall> $methodCalls */
        $methodCalls = $this->parser->findNodes([$closureNode], Node\Expr\MethodCall::class);

        foreach ($methodCalls as $methodCall) {
            if (! $methodCall instanceof Node\Expr\MethodCall || ! $methodCall->name instanceof Node\Identifier) {
                continue;
            }

            $methodName = $methodCall->name->name;

            if ($methodName === 'uncompromised') {
                $hasUncompromised = true;
            }

            if ($methodName === 'mixedCase') {
                $hasMixedCase = true;
            }
        }

        /** @var array<Node\Expr\StaticCall> $staticCalls */
        $staticCalls = $this->parser->findStaticCalls([$closureNode], 'Password', 'min');

        foreach ($staticCalls as $staticCall) {
            if (! $staticCall instanceof Node\Expr\StaticCall) {
                continue;
            }

            if (! empty($staticCall->args) && isset($staticCall->args[0]) && $staticCall->args[0] instanceof Node\Arg) {
                $argValue = $staticCall->args[0]->value;
                if ($argValue instanceof Node\Scalar\Int_ && $argValue->value >= 8) {
                    $hasMinLength = true;
                }
            }
        }
    }

    /**
     * @param  array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function checkPasswordValidationRules(array &$issues): void
    {
        foreach ($this->getPhpFiles() as $file) {
            if (! str_contains($file, '/Requests/') && ! str_contains($file, '/Controllers/')) {
                continue;
            }

            if (str_contains($file, '/vendor/') || str_contains($file, '/tests/') || str_contains($file, '/Tests/')) {
                continue;
            }

            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            /** @var array<Node\Expr\ArrayItem> $arrayItems */
            $arrayItems = $this->parser->findNodes($ast, Node\Expr\ArrayItem::class);

            foreach ($arrayItems as $item) {
                if (! $item instanceof Node\Expr\ArrayItem) {
                    continue;
                }

                if (! $item->key instanceof Node\Scalar\String_ || $item->key->value !== 'password') {
                    continue;
                }

                $minLength = $this->extractPasswordMinLength($item->value);

                if ($minLength !== null && $minLength < 8) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: sprintf('Password validation requires only %d characters (minimum recommended: 8)', $minLength),
                        filePath: $file,
                        lineNumber: $item->getStartLine(),
                        severity: Severity::Medium,
                        recommendation: 'Set minimum password length to at least 8 characters: \'password\' => [\'required\', Password::min(8)]',
                        metadata: ['min_length' => $minLength, 'issue_type' => 'weak_validation_min_length']
                    );
                }
            }
        }
    }

    private function extractPasswordMinLength(Node $value): ?int
    {
        if ($value instanceof Node\Scalar\String_) {
            if (preg_match('/\bmin:(\d+)/', $value->value, $matches)) {
                return (int) $matches[1];
            }

            return null;
        }

        if ($value instanceof Node\Expr\Array_) {
            foreach ($value->items as $arrayItem) {
                if ($arrayItem === null) {
                    continue;
                }

                if ($arrayItem->value instanceof Node\Scalar\String_) {
                    if (preg_match('/\bmin:(\d+)/', $arrayItem->value->value, $matches)) {
                        return (int) $matches[1];
                    }
                }

                $minFromCall = $this->extractMinFromNode($arrayItem->value);
                if ($minFromCall !== null) {
                    return $minFromCall;
                }
            }

            return null;
        }

        return $this->extractMinFromNode($value);
    }

    private function extractMinFromNode(Node $node): ?int
    {
        if ($node instanceof Node\Expr\StaticCall) {
            return $this->extractMinFromPasswordCall($node);
        }

        if ($node instanceof Node\Expr\MethodCall) {
            return $this->extractMinFromMethodChain($node);
        }

        return null;
    }

    private function extractMinFromPasswordCall(Node\Expr\StaticCall $call): ?int
    {
        if (! $call->class instanceof Node\Name || $call->class->toString() !== 'Password') {
            return null;
        }

        if (! $call->name instanceof Node\Identifier || $call->name->name !== 'min') {
            return null;
        }

        if (! empty($call->args) && isset($call->args[0]) && $call->args[0] instanceof Node\Arg) {
            $argValue = $call->args[0]->value;
            if ($argValue instanceof Node\Scalar\Int_) {
                return $argValue->value;
            }
        }

        return null;
    }

    private function extractMinFromMethodChain(Node\Expr\MethodCall $call): ?int
    {
        $current = $call;

        while ($current instanceof Node\Expr\MethodCall) {
            if ($current->var instanceof Node\Expr\StaticCall) {
                return $this->extractMinFromPasswordCall($current->var);
            }
            $current = $current->var;
        }

        return null;
    }

    /**
     * @param  array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
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

        $config = $this->getConfiguration();
        $maxTimeout = $config['password_confirmation_max_timeout'];

        if (preg_match("/['\"]password_timeout['\"]\\s*=>\\s*(\\d+)/", $content, $matches)) {
            $timeout = (int) $matches[1];

            if ($timeout > $maxTimeout) {
                $lineMap = $this->mapConfigKeyLines($authConfig);

                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf('Password confirmation timeout is %d seconds (%s) - consider reducing', $timeout, $this->formatDuration($timeout)),
                    filePath: $authConfig,
                    lineNumber: $lineMap['password_timeout'] ?? 1,
                    severity: Severity::Low,
                    recommendation: sprintf('Reduce password confirmation timeout to %d seconds (%s) or less for better security', $maxTimeout, $this->formatDuration($maxTimeout)),
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

    /**
     * @return array{
     *    bcrypt_min_rounds: int,
     *    argon2_min_memory: int,
     *    argon2_min_time: int,
     *    argon2_min_threads: int,
     *    ignored_paths: array<int, string>,
     *    allowed_weak_hash_patterns: array<int, string>,
     *    password_confirmation_max_timeout: int
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
         *    allowed_weak_hash_patterns?: array<int, string>,
         *    password_confirmation_max_timeout?: int
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
             *    allowed_weak_hash_patterns?: array<int, string>,
             *    password_confirmation_max_timeout?: int
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
            'password_confirmation_max_timeout' => ($config['password_confirmation_max_timeout'] ?? 10800),
        ];
    }

    /**
     * @return array<string, mixed>|null
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

    /**
     * @param  array{bcrypt_min_rounds: int, argon2_min_memory: int, argon2_min_time: int, argon2_min_threads: int, ignored_paths: array<int, string>, allowed_weak_hash_patterns: array<int, string>, password_confirmation_max_timeout: int}  $config
     */
    private function shouldSkipFileForCodeScan(string $file, array $config): bool
    {
        if (str_contains($file, '/vendor/') ||
            str_contains($file, '/tests/') ||
            str_contains($file, '/Tests/') ||
            str_contains($file, '/database/seeders/') ||
            str_contains($file, '/database/factories/')) {
            return true;
        }

        $relativePath = $this->getRelativePath($file);
        foreach ($config['ignored_paths'] as $ignoredPath) {
            if (is_string($ignoredPath) && str_contains($relativePath, $ignoredPath)) {
                return true;
            }
        }

        return false;
    }

    private function getLineContent(string $file, int $lineNumber): ?string
    {
        $lines = FileParser::getLines($file);
        $index = $lineNumber - 1;

        if (! isset($lines[$index]) || ! is_string($lines[$index])) {
            return null;
        }

        return $lines[$index];
    }

    /**
     * @param  array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function checkPasswordRehashUsage(array &$issues): void
    {
        $hashingConfigPath = ConfigFileHelper::getConfigPath(
            $this->getBasePath(),
            'hashing.php',
            fn ($file) => function_exists('config_path') ? config_path($file) : null
        );

        $rehashOnLogin = null;
        if (file_exists($hashingConfigPath)) {
            $configArray = $this->loadHashingConfigArray($hashingConfigPath);
            if (is_array($configArray) && array_key_exists('rehash_on_login', $configArray)) {
                $rehashOnLogin = (bool) $configArray['rehash_on_login'];
            }
        }

        if ($rehashOnLogin === true) {
            return;
        }

        $hasLoginFlow = false;
        $loginFlowFile = '';
        $hasRehash = false;

        foreach ($this->getPhpFiles() as $file) {
            if (str_contains($file, '/vendor/') || str_contains($file, '/tests/') || str_contains($file, '/Tests/')) {
                continue;
            }

            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            if (! $hasLoginFlow) {
                foreach (['attempt', 'login', 'loginUsingId'] as $method) {
                    if (! $hasLoginFlow && ! empty($this->parser->findStaticCalls($ast, 'Auth', $method))) {
                        $hasLoginFlow = true;
                        $loginFlowFile = $file;
                    }
                }
                if (! $hasLoginFlow && ! empty($this->parser->findStaticCalls($ast, 'Fortify', 'authenticateUsing'))) {
                    $hasLoginFlow = true;
                    $loginFlowFile = $file;
                }
                if (! $hasLoginFlow && $this->hasAuthHelperLogin($ast)) {
                    $hasLoginFlow = true;
                    $loginFlowFile = $file;
                }
            }

            if (! $hasRehash) {
                if (! empty($this->parser->findStaticCalls($ast, 'Hash', 'needsRehash'))) {
                    $hasRehash = true;
                }
                if (! $hasRehash && $this->hasRehashCall($ast)) {
                    $hasRehash = true;
                }
            }

            if ($hasLoginFlow && $hasRehash) {
                return;
            }
        }

        if (! $hasLoginFlow) {
            return;
        }

        if ($rehashOnLogin === false) {
            $lineNumber = 1;
            if (file_exists($hashingConfigPath)) {
                $lineMap = $this->mapConfigKeyLines($hashingConfigPath);
                $lineNumber = $lineMap['rehash_on_login'] ?? 1;
            }
            $issues[] = $this->createIssueWithSnippet(
                message: 'Password rehashing on login is disabled (rehash_on_login is false)',
                filePath: $hashingConfigPath,
                lineNumber: $lineNumber,
                severity: Severity::Medium,
                recommendation: "Set 'rehash_on_login' => true in config/hashing.php so passwords are automatically rehashed when algorithm options change",
                metadata: ['issue_type' => 'rehash_on_login_disabled']
            );

            return;
        }

        if (! $hasRehash) {
            $issues[] = $this->createIssue(
                message: 'Login flow detected but never rehashes passwords when hash parameters change',
                location: new \ShieldCI\AnalyzersCore\ValueObjects\Location(
                    $this->getRelativePath($loginFlowFile)
                ),
                severity: Severity::Medium,
                recommendation: "Add Hash::needsRehash() after authentication, or upgrade to Laravel 11+ and set 'rehash_on_login' => true in config/hashing.php",
                metadata: ['issue_type' => 'missing_password_rehash']
            );
        }
    }

    /**
     * @param  array<Node>  $ast
     */
    private function hasAuthHelperLogin(array $ast): bool
    {
        $loginMethods = ['attempt', 'login', 'loginUsingId'];

        /** @var array<Node\Expr\MethodCall> $methodCalls */
        $methodCalls = $this->parser->findNodes($ast, Node\Expr\MethodCall::class);

        foreach ($methodCalls as $call) {
            if (! $call instanceof Node\Expr\MethodCall) {
                continue;
            }
            if (! $call->name instanceof Node\Identifier || ! in_array($call->name->name, $loginMethods, true)) {
                continue;
            }
            if ($call->var instanceof Node\Expr\FuncCall
                && $call->var->name instanceof Node\Name
                && $call->var->name->toString() === 'auth') {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<Node>  $ast
     */
    private function hasRehashCall(array $ast): bool
    {
        /** @var array<Node\Expr\FuncCall> $funcCalls */
        $funcCalls = $this->parser->findNodes($ast, Node\Expr\FuncCall::class);

        foreach ($funcCalls as $call) {
            if ($call instanceof Node\Expr\FuncCall
                && $call->name instanceof Node\Name
                && $call->name->toString() === 'password_needs_rehash') {
                return true;
            }
        }

        /** @var array<Node\Expr\MethodCall> $methodCalls */
        $methodCalls = $this->parser->findNodes($ast, Node\Expr\MethodCall::class);

        foreach ($methodCalls as $call) {
            if ($call instanceof Node\Expr\MethodCall
                && $call->name instanceof Node\Identifier
                && $call->name->name === 'needsRehash'
                && $call->var instanceof Node\Expr\Variable
                && is_string($call->var->name)
                && stripos($call->var->name, 'hash') !== false) {
                return true;
            }
        }

        return false;
    }
}
