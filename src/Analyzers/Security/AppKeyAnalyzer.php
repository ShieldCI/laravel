<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Return_;
use PhpParser\NodeFinder;
use PhpParser\PrettyPrinter\Standard;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\Support\ConfigFileParser;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\DetectsLaravelVersion;

/**
 * Validates that the application encryption key is properly configured.
 *
 * Checks for:
 * - APP_KEY is set in .env files
 * - APP_KEY is not the default/example value
 * - APP_KEY follows proper format (base64: prefix)
 * - APP_KEY is the size the configured cipher needs
 * - each APP_PREVIOUS_KEYS entry is the size the configured cipher needs (Laravel 11+)
 * - config/app.php has proper key configuration
 */
class AppKeyAnalyzer extends AbstractFileAnalyzer
{
    use DetectsLaravelVersion;

    /**
     * App key configuration is environment-specific, not applicable in CI.
     */
    public static bool $runInCI = false;

    /**
     * Key size in bytes for each cipher Illuminate\Encryption\Encrypter accepts, on every
     * supported Laravel version. The encrypter rejects a key of any other size.
     */
    private const CIPHER_KEY_BYTES = [
        'aes-128-cbc' => 16,
        'aes-256-cbc' => 32,
        'aes-128-gcm' => 16,
        'aes-256-gcm' => 32,
    ];

    /**
     * The previous_keys entry of the framework's config/app.php, printed with single quotes:
     * Laravel 11 writes the first, Laravel 12 and later the second.
     */
    private const ENV_PREVIOUS_KEYS_ENTRIES = [
        "[...array_filter(explode(',', env('APP_PREVIOUS_KEYS', '')))]",
        "[...array_filter(explode(',', (string) env('APP_PREVIOUS_KEYS', '')))]",
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'app-key-security',
            name: 'Application Key Analyzer',
            description: 'Validates that the application encryption key is properly configured and secure',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['encryption', 'app-key', 'security', 'configuration'],
            timeToFix: 5
        );
    }

    public function shouldRun(): bool
    {
        // Check if there is .env file or config/app.php to analyze
        return file_exists($this->buildPath('.env')) ||
               file_exists($this->buildPath('config', 'app.php'));
    }

    public function getSkipReason(): string
    {
        return 'No .env files or app configuration found to analyze';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $appConfig = ConfigFileHelper::getConfigPath($this->getBasePath(), 'app.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);

        // Read the returned array rather than the raw lines, so a commented-out entry or one
        // nested under another key is not mistaken for app.key or app.cipher.
        $config = file_exists($appConfig)
            ? (new ConfigFileParser(app(AstParser::class)))->parseArray($appConfig)
            : null;

        $cipher = $this->effectiveCipher($appConfig, $config);

        // Check .env file for APP_KEY
        $this->checkEnvFile($issues, $cipher);

        // Check .env file for APP_PREVIOUS_KEYS
        if ($cipher !== null && $this->previousKeysComeFromEnv($appConfig, $config)) {
            $this->checkPreviousKeys($issues, $cipher);
        }

        // Check config/app.php
        if ($config !== null) {
            $this->checkAppConfig($issues, $appConfig, $config);
        }

        $summary = empty($issues)
            ? 'Application encryption key is properly configured'
            : sprintf('Found %d application key security issue%s', count($issues), count($issues) === 1 ? '' : 's');

        /** @var array<Issue> $issues */
        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check .env file for APP_KEY configuration.
     *
     * @param  array<int, mixed>  &$issues
     * @param  string|null  $cipher  The cipher the encrypter runs with, or null when it cannot be read
     */
    private function checkEnvFile(array &$issues, ?string $cipher): void
    {
        $requiredBytes = $cipher === null ? null : self::CIPHER_KEY_BYTES[$cipher];

        $envFile = $this->buildPath('.env');

        if (! file_exists($envFile)) {
            // Don't report missing .env - EnvFileAnalyzer handles this
            return;
        }

        $content = FileParser::readFile($envFile);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($envFile);
        $appKeyCount = 0;
        $firstKeyLine = 0;
        $keyLine = 0;
        $keyLineText = '';
        $appKeyValue = '';

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            $trimmedLine = trim($line);

            // Skip comments
            if ($trimmedLine === '' ||
                str_starts_with($trimmedLine, '#') ||
                str_starts_with($trimmedLine, '//')) {
                continue;
            }

            // Check for APP_KEY setting
            if (($assignment = $this->envAssignment($trimmedLine, 'APP_KEY')) !== null) {
                $appKeyCount++;

                if ($appKeyCount === 1) {
                    $firstKeyLine = $lineNumber;
                }

                // The dotenv loader lets a later line win, so the last definition is the key Laravel reads
                $keyLine = $lineNumber;
                $keyLineText = $line;
                $appKeyValue = $this->normalizeKeyValue($this->stripInlineComment($assignment));

                // Detect multiple APP_KEY definitions
                if ($appKeyCount > 1) {
                    $issues[] = $this->createIssue(
                        message: sprintf('Multiple APP_KEY definitions found (first at line %d, duplicate at line %d)', $firstKeyLine + 1, $lineNumber + 1),
                        location: new Location($this->getRelativePath($envFile), $lineNumber + 1),
                        severity: Severity::High,
                        recommendation: 'Remove duplicate APP_KEY definitions. Only one APP_KEY should be defined per file.',
                        metadata: ['duplicate_count' => $appKeyCount]
                    );
                }
            }
        }

        // Flag missing APP_KEY
        if ($appKeyCount === 0) {
            $issues[] = $this->createIssue(
                message: 'APP_KEY is not defined in .env file',
                location: new Location($this->getRelativePath($envFile)),
                severity: Severity::Critical,
                recommendation: 'Add APP_KEY to your .env file and run "php artisan key:generate"',
                metadata: ['file' => basename($envFile)]
            );

            return;
        }

        $normalizedValue = $this->normalizeKeyValue($appKeyValue);
        $rewriteFirst = $this->keyGenerateCanRewrite($keyLineText, $appKeyValue)
            ? ''
            : ' First rewrite this line as a plain, unquoted APP_KEY= line with no export prefix, as "php artisan key:generate" only rewrites a line that starts with APP_KEY= followed by the current value.';

        // Check if APP_KEY is empty or whitespace
        if ($normalizedValue === '') {
            $issues[] = $this->createIssue(
                message: 'APP_KEY is not set or is empty',
                location: new Location($this->getRelativePath($envFile), $keyLine + 1),
                severity: Severity::Critical,
                recommendation: 'Run "php artisan key:generate" to generate a secure application key.'.$rewriteFirst,
                metadata: ['file' => basename($envFile)]
            );
        }
        // Check if APP_KEY is a placeholder (case-insensitive)
        elseif ($this->isPlaceholderValue($appKeyValue)) {
            $issues[] = $this->createIssue(
                message: 'APP_KEY is set to a placeholder/example value',
                location: new Location($this->getRelativePath($envFile), $keyLine + 1),
                severity: Severity::Critical,
                recommendation: 'Replace the placeholder value by running "php artisan key:generate" to generate a real application key.'.$rewriteFirst,
                metadata: [
                    'file' => basename($envFile),
                    'placeholder_detected' => $normalizedValue,
                ]
            );
        }
        // Validate APP_KEY format and strength
        elseif (! $this->isValidAppKey($appKeyValue, $requiredBytes)) {
            $issues[] = $this->createIssue(
                message: 'APP_KEY does not follow the expected format or is too short',
                location: new Location($this->getRelativePath($envFile), $keyLine + 1),
                severity: Severity::High,
                recommendation: 'Regenerate APP_KEY with "php artisan key:generate". Laravel\'s encrypter needs a key of exactly the cipher\'s size: a base64: key that decodes to 32 bytes for the AES-256 ciphers or 16 bytes for the AES-128 ciphers.'.$rewriteFirst,
                metadata: [
                    'file' => basename($envFile),
                    'provided_length' => strlen($normalizedValue),
                    'minimum_length' => $requiredBytes ?? 32,
                ]
            );
        }
        // Validate APP_KEY size against the cipher the encrypter runs with
        elseif ($cipher !== null && ($keyBytes = $this->keyByteLength($normalizedValue)) !== $requiredBytes) {
            $issues[] = $this->createIssue(
                message: sprintf('APP_KEY is %d bytes but the %s cipher needs a %d-byte key', $keyBytes, strtoupper($cipher), $requiredBytes),
                location: new Location($this->getRelativePath($envFile), $keyLine + 1),
                severity: Severity::Critical,
                recommendation: 'Laravel\'s encrypter only accepts a key of exactly the cipher\'s size and throws on any other, which fails every request that touches an encrypted cookie. Generate a key for the configured cipher with "php artisan key:generate", or set the cipher back to the one this key was generated for so existing encrypted data stays readable.'.$rewriteFirst,
                metadata: [
                    'file' => basename($envFile),
                    'cipher' => $cipher,
                    'key_bytes' => $keyBytes,
                    'required_bytes' => $requiredBytes,
                ]
            );
        }
    }

    /**
     * Whether "php artisan key:generate" can rewrite this .env line.
     *
     * The command replaces /^APP_KEY=<current key>/m, so the line must start with APP_KEY= followed
     * by the value as Laravel read it: no export prefix, quotes, indentation or spaces around =.
     * The value must also end the line or be followed by whitespace, as the command leaves anything
     * else in place, so APP_KEY="" becomes APP_KEY=<new key>"" and the new key reads with the quotes.
     */
    private function keyGenerateCanRewrite(string $line, string $value): bool
    {
        return preg_match('/^APP_KEY='.preg_quote($value, '/').'(?:\s|$)/', $line) === 1;
    }

    /**
     * Check each APP_PREVIOUS_KEYS entry in .env against the size the cipher needs.
     *
     * The list is split the way the framework's config/app.php splits it, with no trimming,
     * and the last definition is the one read, as the dotenv loader lets a later line win.
     *
     * @param  array<int, mixed>  &$issues
     */
    private function checkPreviousKeys(array &$issues, string $cipher): void
    {
        $envFile = $this->buildPath('.env');

        if (! file_exists($envFile)) {
            return;
        }

        $value = null;
        $definitionLine = 0;

        foreach (FileParser::getLines($envFile) as $lineNumber => $line) {
            if (is_string($line) && ($assignment = $this->envAssignment(trim($line), 'APP_PREVIOUS_KEYS')) !== null) {
                $value = $this->normalizeKeyValue($this->stripInlineComment($assignment));
                $definitionLine = $lineNumber + 1;
            }
        }

        // An interpolated value cannot be sized from the file
        if ($value === null || str_contains($value, '${')) {
            return;
        }

        // env() turns these words into booleans or null before explode() reads them
        $value = match (strtolower($value)) {
            'true', '(true)' => '1',
            'false', '(false)', 'empty', '(empty)', 'null', '(null)' => '',
            default => $value,
        };

        $requiredBytes = self::CIPHER_KEY_BYTES[$cipher];

        foreach (array_filter(explode(',', $value)) as $index => $entry) {
            $keyBytes = $this->keyByteLength($entry);

            if ($keyBytes === $requiredBytes) {
                continue;
            }

            $issues[] = $this->createIssue(
                message: sprintf('APP_PREVIOUS_KEYS entry %d is %d bytes but the %s cipher needs a %d-byte key', $index + 1, $keyBytes, strtoupper($cipher), $requiredBytes),
                location: new Location($this->getRelativePath($envFile), $definitionLine),
                severity: Severity::Critical,
                recommendation: 'Laravel checks every previous key against the configured cipher and throws on one of any other size, which fails every request that touches an encrypted cookie. Remove this key from APP_PREVIOUS_KEYS: the encrypter decrypts with the configured cipher whatever the key, so a key generated for another cipher cannot read the data it encrypted anyway.',
                metadata: [
                    'file' => basename($envFile),
                    'entry' => $index + 1,
                    'cipher' => $cipher,
                    'key_bytes' => $keyBytes,
                    'required_bytes' => $requiredBytes,
                ]
            );
        }
    }

    /**
     * Whether the encrypter receives APP_PREVIOUS_KEYS as the framework's config/app.php reads it.
     *
     * Laravel passes previous keys to the encrypter from 11.0. A published config/app.php that
     * leaves the entry out still gets the framework's through the configuration merge, unless the
     * application turned that merge off. An entry in any other form, or one a spread or a
     * computed key could override, is not read as APP_PREVIOUS_KEYS.
     *
     * @param  array<string, array{value: mixed, line: int, isEnvCall: bool, envDefault: mixed, envHasDefault: bool}>|null  $config
     */
    private function previousKeysComeFromEnv(string $appConfig, ?array $config): bool
    {
        if (! $this->isLaravel11OrNewer()) {
            return false;
        }

        if ($config !== null) {
            $return = $this->returnedArray($appConfig);

            if ($return === null || ! $this->literalKeysDecide($return, 'previous_keys')) {
                return false;
            }

            $entry = $this->lastEntry($return, 'previous_keys');

            if ($entry !== null) {
                $printed = str_replace('"', "'", (new Standard)->prettyPrintExpr($entry->value));

                return in_array($printed, self::ENV_PREVIOUS_KEYS_ENTRIES, true);
            }
        }

        // The same guard LoadConfiguration applies: the opt-out arrived after Laravel 11.0
        $app = app();

        return ! method_exists($app, 'shouldMergeFrameworkConfiguration') || $app->shouldMergeFrameworkConfiguration();
    }

    /**
     * Check config/app.php for key configuration.
     *
     * @param  array<int, mixed>  &$issues
     * @param  array<string, array{value: mixed, line: int, isEnvCall: bool, envDefault: mixed, envHasDefault: bool}>  $config
     */
    private function checkAppConfig(array &$issues, string $appConfig, array $config): void
    {
        $key = $config['key'] ?? null;

        if ($key !== null && is_string($key['value']) && $key['value'] !== '') {
            $issues[] = $this->createIssueWithSnippet(
                message: 'Application key is hardcoded in config/app.php instead of using environment variable',
                filePath: $appConfig,
                lineNumber: $key['line'],
                severity: Severity::Critical,
                recommendation: 'Reference the APP_KEY environment variable in config/app.php rather than hardcoding the key directly in the configuration file.',
                metadata: [
                    'file' => 'app.php',
                    'config_key' => 'key',
                ]
            );
        }

        $cipherEntry = $config['cipher'] ?? null;

        if ($cipherEntry === null || ! is_string($cipherEntry['value'])) {
            return;
        }

        $cipher = strtolower($cipherEntry['value']);

        if (! isset(self::CIPHER_KEY_BYTES[$cipher])) {
            $issues[] = $this->createIssueWithSnippet(
                message: $cipher === ''
                    ? 'Cipher is empty in config/app.php'
                    : sprintf('Unsupported or weak cipher algorithm: %s', $cipher),
                filePath: $appConfig,
                lineNumber: $cipherEntry['line'],
                severity: Severity::High,
                recommendation: 'Use a cipher Laravel\'s encrypter supports: AES-256-GCM, AES-128-GCM, AES-256-CBC or AES-128-CBC. The GCM modes also authenticate the encrypted payload.',
                metadata: [
                    'file' => 'app.php',
                    'config_key' => 'cipher',
                    'cipher' => $cipher,
                ]
            );
        }
    }

    /**
     * The cipher the encrypter runs with, lowercased, or null when config/app.php does not say.
     *
     * An unpublished config/app.php, or one without a cipher entry, runs on the framework default.
     * A file that would not parse, one whose cipher a spread, a computed key or a non-literal
     * return could set or override, a cipher read from env() or any other expression, and a
     * cipher the encrypter does not support all answer null, so the key is not sized against a
     * guess.
     *
     * @param  array<string, array{value: mixed, line: int, isEnvCall: bool, envDefault: mixed, envHasDefault: bool}>|null  $config
     */
    private function effectiveCipher(string $appConfig, ?array $config): ?string
    {
        if ($config === null) {
            return 'aes-256-cbc';
        }

        if (app(AstParser::class)->hasFailure($appConfig)) {
            return null;
        }

        $return = $this->returnedArray($appConfig);

        if ($return === null || ! $this->literalKeysDecide($return, 'cipher')) {
            return null;
        }

        if (! isset($config['cipher'])) {
            return 'aes-256-cbc';
        }

        $cipher = $config['cipher']['value'];

        if (! is_string($cipher) || ! isset(self::CIPHER_KEY_BYTES[strtolower($cipher)])) {
            return null;
        }

        return strtolower($cipher);
    }

    /**
     * The array literal config/app.php returns, or null when it returns anything else, such as
     * array_merge(): its entries are then never the last word on any key.
     */
    private function returnedArray(string $appConfig): ?Array_
    {
        $return = (new NodeFinder)->findFirstInstanceOf(app(AstParser::class)->parseFile($appConfig), Return_::class);

        return $return instanceof Return_ && $return->expr instanceof Array_ ? $return->expr : null;
    }

    /**
     * Whether the literal entries of the returned array are the last word on $key.
     *
     * No entry after the last literal $key, or after any entry at all when there is none, may be
     * a spread or a computed key: either can set $key in a way the literal entries do not show.
     */
    private function literalKeysDecide(Array_ $return, string $key): bool
    {
        // Walk back from the end: a later entry overrides an earlier one, so only the entries
        // after the literal key can change it
        foreach (array_reverse($return->items) as $item) {
            if (! $item->key instanceof String_) {
                return false;
            }

            if ($item->key->value === $key) {
                return true;
            }
        }

        return true;
    }

    /**
     * The last entry of the returned array under the literal $key, the one that wins.
     */
    private function lastEntry(Array_ $return, string $key): ?ArrayItem
    {
        foreach (array_reverse($return->items) as $item) {
            if ($item->key instanceof String_ && $item->key->value === $key) {
                return $item;
            }
        }

        return null;
    }

    /**
     * The raw value this .env line assigns to $name, or null when it assigns another name.
     *
     * Names match as dotenv reads them: case-sensitive, with an optional export prefix and
     * optional matching single or double quotes.
     */
    private function envAssignment(string $line, string $name): ?string
    {
        return preg_match('/^(?:export\s+)?(["\']?)'.preg_quote($name, '/').'\1\s*=\s*(.*)$/', $line, $matches) === 1 ? $matches[2] : null;
    }

    /**
     * Remove inline comments from env values.
     */
    private function stripInlineComment(string $value): string
    {
        $value = trim($value);

        // Fully-quoted values are returned verbatim.
        if (preg_match('/^([\'"]).*\1$/', $value)) {
            return $value;
        }

        // In .env files, only `#` starts an inline comment, and only when preceded
        // by whitespace. Base64 keys can contain `//`, `+`, and `/`, so those must
        // never be treated as comment delimiters.
        return preg_replace('/\s+#.*$/', '', $value) ?? $value;
    }

    /**
     * Normalize key value by removing quotes and whitespace.
     */
    private function normalizeKeyValue(string $value): string
    {
        $value = trim($value);

        if (
            (str_starts_with($value, '"') && str_ends_with($value, '"')) ||
            (str_starts_with($value, "'") && str_ends_with($value, "'"))
        ) {
            return substr($value, 1, -1);
        }

        return $value;
    }

    /**
     * Check if value is a placeholder/example value.
     */
    private function isPlaceholderValue(string $value): bool
    {
        $normalized = $this->normalizeKeyValue($value);
        $lower = strtolower($normalized);

        // Empty or null
        if ($lower === '' || $lower === 'null') {
            return true;
        }

        // Common placeholder patterns
        $patterns = [
            '/^base64:\s*$/',                    // base64: with nothing after
            '/your[-_]?key[-_]?here/i',          // your-key-here variants
            '/change[-_]?me/i',                  // change-me variants
            '/replace[-_]?this/i',               // replace-this variants
            '/example[-_]?key/i',                // example-key variants
            '/test[-_]?key/i',                   // test-key variants
            '/secret[-_]?key[-_]?here/i',        // secret-key-here variants
            '/random[-_]?string/i',              // random-string variants
            '/^(xxx+|yyy+|zzz+|aaa+)$/i',       // repeated chars
            '/placeholder/i',                    // contains "placeholder"
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $normalized)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validate APP_KEY format and strength.
     *
     * @param  int|null  $requiredBytes  The cipher's key size, or null when the cipher is unknown
     */
    private function isValidAppKey(string $value, ?int $requiredBytes): bool
    {
        $normalized = $this->normalizeKeyValue($value);

        // Check for base64: prefix
        if (str_starts_with($normalized, 'base64:')) {
            return $this->validateBase64Key($normalized);
        }

        // Keys without base64: prefix should be at least the cipher's size, or 32 characters
        // when the cipher is unknown
        return strlen($normalized) >= ($requiredBytes ?? 32);
    }

    /**
     * Size in bytes of the key the encrypter receives, decoded as EncryptionServiceProvider does:
     * a base64: prefix is decoded leniently, anything else is the key itself.
     */
    private function keyByteLength(string $normalized): int
    {
        if (str_starts_with($normalized, 'base64:')) {
            return strlen(base64_decode(substr($normalized, 7)));
        }

        return strlen($normalized);
    }

    /**
     * Validate base64-encoded APP_KEY.
     */
    private function validateBase64Key(string $value): bool
    {
        // Extract encoded portion after 'base64:' prefix
        $encoded = substr($value, 7);

        // Check if empty
        if ($encoded === '') {
            return false;
        }

        // Validate base64 format (alphanumeric + / + = for padding)
        if (! preg_match('/^[A-Za-z0-9+\/]+=*$/', $encoded)) {
            return false;
        }

        // Validate base64 padding
        if (! $this->isValidBase64Padding($encoded)) {
            return false;
        }

        // Check minimum encoded length
        // AES-128 requires 16 bytes (24 base64 chars)
        // AES-256 requires 32 bytes (44 base64 chars)
        if (strlen($encoded) < 24) {
            return false;
        }

        // Verify it decodes properly
        $decoded = base64_decode($encoded, true);
        if ($decoded === false) {
            return false;
        }

        // Check decoded length (minimum 16 bytes for AES-128)
        if (strlen($decoded) < 16) {
            return false;
        }

        return true;
    }

    /**
     * Validate base64 padding is correct.
     */
    private function isValidBase64Padding(string $encoded): bool
    {
        // Count padding characters
        $paddingCount = substr_count($encoded, '=');

        // Max 2 padding chars for base64
        if ($paddingCount > 2) {
            return false;
        }

        // Padding must be at the end
        if ($paddingCount > 0) {
            $paddingStart = strlen($encoded) - $paddingCount;
            if (substr($encoded, $paddingStart) !== str_repeat('=', $paddingCount)) {
                return false;
            }
        }

        return true;
    }
}
