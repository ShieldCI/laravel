<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\Security\AppKeyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Tests\AnalyzerTestCase;

class AppKeyAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new AppKeyAnalyzer;
    }

    public function test_passes_with_valid_app_key_in_env(): void
    {
        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
APP_DEBUG=false
ENV;

        $configContent = <<<'PHP'
<?php

return [
    'name' => env('APP_NAME', 'Laravel'),
    'env' => env('APP_ENV', 'production'),
    'key' => env('APP_KEY'),
    'cipher' => 'AES-256-CBC',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_base64_key_containing_double_slash(): void
    {
        // A valid 32-byte key whose base64 encoding contains "//" (legal base64).
        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_KEY=base64:2/J40U++LCAOMbcQXVMoijPIbW48//FuI/2ppake6b4=
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_strips_trailing_inline_comment(): void
    {
        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA= # production app key
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_app_key_is_empty(): void
    {
        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_KEY=
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APP_KEY is not set or is empty', $result);
    }

    public function test_fails_when_app_key_is_placeholder(): void
    {
        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_KEY=SomeRandomString
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('placeholder/example value', $result);
    }

    public function test_fails_when_app_key_is_too_short(): void
    {
        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_KEY=short
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not follow the expected format or is too short', $result);
    }

    public function test_fails_when_app_key_is_missing_in_env(): void
    {
        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APP_KEY is not defined', $result);
    }

    public function test_fails_when_app_key_is_hardcoded_in_config(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
ENV;

        $configContent = <<<'PHP'
<?php

return [
    'key' => 'base64:hardcoded-key-12345678901234567890123456789012',
    'cipher' => 'AES-256-CBC',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('hardcoded in config/app.php', $result);
    }

    public function test_fails_when_cipher_is_insecure(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
ENV;

        $configContent = <<<'PHP'
<?php

return [
    'key' => env('APP_KEY'),
    'cipher' => 'DES',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Unsupported or weak cipher', $result);
        $this->assertStringContainsString('AES-256-GCM', $result->getIssues()[0]->recommendation);
    }

    /** @dataProvider supportedCipherProvider */
    #[DataProvider('supportedCipherProvider')]
    public function test_passes_with_every_cipher_laravel_supports(string $cipher): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=',
            'config/app.php' => "<?php\n\nreturn [\n    'key' => env('APP_KEY'),\n    'cipher' => '{$cipher}',\n];\n",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function supportedCipherProvider(): array
    {
        return [
            'AES-128-CBC' => ['AES-128-CBC'],
            'AES-256-CBC' => ['AES-256-CBC'],
            'AES-128-GCM' => ['AES-128-GCM'],
            'AES-256-GCM' => ['AES-256-GCM'],
            'lowercase aes-256-gcm' => ['aes-256-gcm'],
        ];
    }

    public function test_passes_with_aes_128_cbc_cipher(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
ENV;

        $configContent = <<<'PHP'
<?php

return [
    'key' => env('APP_KEY'),
    'cipher' => 'AES-128-CBC',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_missing_app_key_in_env_example(): void
    {
        $envExampleContent = <<<'ENV'
APP_NAME=Laravel
APP_DEBUG=false
ENV;

        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
APP_DEBUG=false
ENV;

        $tempDir = $this->createTempDirectory([
            '.env.example' => $envExampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_when_no_env_or_config_exists(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertSame('No .env files or app configuration found to analyze', $result->getMessage());
    }

    // ==================== CRITICAL BUG FIX TESTS ====================

    public function test_fails_when_base64_key_is_too_short(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:abc
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not follow the expected format or is too short', $result);
    }

    public function test_fails_when_base64_key_is_short_but_valid_format(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:short123
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not follow the expected format or is too short', $result);
    }

    public function test_fails_when_base64_prefix_with_empty_content(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('is set to a placeholder/example value', $result);
    }

    public function test_fails_when_base64_content_is_invalid(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:!!!invalid!!!
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not follow the expected format or is too short', $result);
    }

    // ==================== PLACEHOLDER CASE SENSITIVITY TESTS ====================

    public function test_fails_when_app_key_is_null_uppercase(): void
    {
        $envContent = <<<'ENV'
APP_KEY=NULL
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('placeholder/example value', $result);
    }

    public function test_fails_when_app_key_is_null_mixed_case(): void
    {
        $envContent = <<<'ENV'
APP_KEY=Null
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('placeholder/example value', $result);
    }

    public function test_fails_when_app_key_is_somerandomstring_lowercase(): void
    {
        $envContent = <<<'ENV'
APP_KEY=somerandomstring
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('placeholder/example value', $result);
    }

    public function test_fails_when_app_key_is_base64_your_key_here(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:your-key-here
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('placeholder/example value', $result);
    }

    // ==================== WHITESPACE TESTS ====================

    public function test_fails_when_app_key_is_only_whitespace(): void
    {
        $envContent = <<<'ENV'
APP_KEY=
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APP_KEY is not set or is empty', $result);
    }

    public function test_fails_when_app_key_is_quoted_whitespace(): void
    {
        $envContent = <<<'ENV'
APP_KEY="  "
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APP_KEY is not set or is empty', $result);
    }

    // ==================== QUOTED VALUES TESTS ====================

    public function test_passes_with_quoted_valid_key(): void
    {
        $envContent = <<<'ENV'
APP_KEY="base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA="
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_single_quoted_valid_key(): void
    {
        $envContent = <<<'ENV'
APP_KEY='base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA='
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_quoted_null(): void
    {
        $envContent = <<<'ENV'
APP_KEY="null"
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('placeholder/example value', $result);
    }

    // ==================== 32+ CHARACTER KEYS WITHOUT BASE64 ====================

    public function test_passes_with_32_character_key_without_base64(): void
    {
        $envContent = <<<'ENV'
APP_KEY=abcdefghijklmnopqrstuvwxyz123456
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== CIPHER CASE VARIATIONS ====================

    public function test_passes_with_cipher_mixed_case(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
ENV;

        $configContent = <<<'PHP'
<?php

return [
    'key' => env('APP_KEY'),
    'cipher' => 'AES-256-cbc',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_cipher_all_lowercase(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
ENV;

        $configContent = <<<'PHP'
<?php

return [
    'key' => env('APP_KEY'),
    'cipher' => 'aes-256-cbc',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== EDGE CASES ====================

    public function test_ignores_commented_hardcoded_key(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
ENV;

        $configContent = <<<'PHP'
<?php

return [
    // 'key' => 'base64:hardcoded-key-12345678901234567890123456789012',
    'key' => env('APP_KEY'),
    'cipher' => 'AES-256-CBC',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /** @dataProvider commentedConfigEntryProvider */
    #[DataProvider('commentedConfigEntryProvider')]
    public function test_ignores_hardcoded_entries_in_comments(string $commented): void
    {
        $configContent = "<?php\n\nreturn [\n{$commented}\n    'key' => env('APP_KEY'),\n    'cipher' => 'AES-256-CBC',\n];\n";

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=',
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function commentedConfigEntryProvider(): array
    {
        return [
            'hash comment key' => ["    # 'key' => 'base64:c3RhbGUta2V5LWZyb20tYW4tb2xkLWRlcGxveQ==',"],
            'inline block comment key' => ["    /* 'key' => 'base64:c3RhbGUta2V5LWZyb20tYW4tb2xkLWRlcGxveQ==', */"],
            'docblock prose key' => ["    /*\n     * Never write 'key' => 'base64:...' here.\n     */"],
            'double-slash comment cipher' => ["    // 'cipher' => 'DES',"],
            'hash comment cipher' => ["    # 'cipher' => 'RC4',"],
        ];
    }

    public function test_fails_when_hardcoded_key_has_env_in_trailing_comment(): void
    {
        $configContent = <<<'PHP'
<?php

return [
    'name' => 'Inventory',
    'key' => 'base64:c3RhbGUta2V5LWZyb20tYW4tb2xkLWRlcGxveQ==', // was 'key' => env('APP_KEY'),
    'cipher' => 'AES-256-CBC',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=',
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('Application key is hardcoded in config/app.php instead of using environment variable', $issues[0]->message);
        $this->assertSame(5, $issues[0]->location?->line);
    }

    public function test_ignores_key_and_cipher_nested_under_another_config_key(): void
    {
        $configContent = <<<'PHP'
<?php

return [
    'key' => env('APP_KEY'),
    'cipher' => 'AES-256-CBC',
    'reporting' => [
        'key' => 'abc123',
        'cipher' => 'none',
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=',
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_reports_hardcoded_key_and_weak_cipher_on_their_key_lines(): void
    {
        $configContent = <<<'PHP'
<?php

return [
    'name' => env('APP_NAME', 'Inventory'),

    'key' => 'base64:c3RhbGUta2V5LWZyb20tYW4tb2xkLWRlcGxveQ==',

    'cipher' => 'DES',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=',
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $issues = $analyzer->analyze()->getIssues();

        $this->assertCount(2, $issues);
        $this->assertSame('Application key is hardcoded in config/app.php instead of using environment variable', $issues[0]->message);
        $this->assertSame(6, $issues[0]->location?->line);
        $this->assertSame('Unsupported or weak cipher algorithm: des', $issues[1]->message);
        $this->assertSame(8, $issues[1]->location?->line);
    }

    public function test_fails_when_cipher_is_empty_string(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=',
            'config/app.php' => "<?php\n\nreturn [\n    'key' => env('APP_KEY'),\n    'cipher' => '',\n];\n",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $issues = $analyzer->analyze()->getIssues();

        $this->assertCount(1, $issues);
        $this->assertSame('Cipher is empty in config/app.php', $issues[0]->message);
        $this->assertSame(5, $issues[0]->location?->line);
    }

    public function test_records_unparseable_app_config_on_the_shared_parser(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=',
            'config/app.php' => "<?php\n\nreturn [\n    'key' => 'base64:c3RhbGUta2V5LWZyb20tYW4tb2xkLWRlcGxveQ==',\n",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertPassed($analyzer->analyze());

        // The report's parse_failures section reads this log, so the broken file is surfaced there
        $this->assertTrue(app(AstParser::class)->hasFailure($tempDir.'/config/app.php'));
    }

    public function test_passes_with_valid_aes_256_key(): void
    {
        // Generate a proper AES-256 key (32 bytes = 44 base64 chars)
        $envContent = <<<'ENV'
APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_valid_aes_128_key(): void
    {
        // Generate a proper AES-128 key (16 bytes = 24 base64 chars)
        $envContent = <<<'ENV'
APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAA==
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== MULTIPLE APP_KEY DEFINITIONS TESTS ====================

    public function test_fails_when_multiple_app_keys_in_same_file(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
APP_DEBUG=false
APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Multiple APP_KEY definitions', $result);
        $this->assertHasIssueContaining('first at line 1', $result);
        $this->assertHasIssueContaining('duplicate at line 3', $result);
    }

    public function test_fails_with_three_app_keys_in_same_file(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
APP_KEY=base64:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should have 2 issues - one for each duplicate
        $issues = $result->getIssues();
        $duplicateIssues = array_filter($issues, fn ($issue) => str_contains($issue->message, 'Multiple APP_KEY'));
        $this->assertCount(2, $duplicateIssues);
    }

    // ==================== BASE64 PADDING VALIDATION TESTS ====================

    public function test_fails_with_too_many_padding_equals(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAA====
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not follow the expected format or is too short', $result);
    }

    public function test_fails_with_padding_in_wrong_position(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:AAA=AAAAAAAAAAAAAAAAAAA
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not follow the expected format or is too short', $result);
    }

    public function test_passes_with_single_padding_equals(): void
    {
        // Real AES-256 key with 1 padding char (32 bytes = 43 chars + 1 padding)
        $envContent = <<<'ENV'
APP_KEY=base64:5jIQITq0dF4pGlRzzvExUkqoGtkl9mvEE/Y+Itia/fM=
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_two_padding_equals(): void
    {
        // Real AES-128 key with 2 padding chars (16 bytes = 22 chars + 2 padding)
        $envContent = <<<'ENV'
APP_KEY=base64:bR/mRSJE/jR5awWSPE/Yew==
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_no_padding(): void
    {
        // Valid key that doesn't require padding (24 bytes = 32 chars, no padding needed)
        $envContent = <<<'ENV'
APP_KEY=base64:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== SHOULD RUN TESTS ====================

    public function test_should_run_when_env_exists(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_when_config_app_exists(): void
    {
        $configContent = <<<'PHP'
<?php

return [
    'key' => env('APP_KEY'),
    'cipher' => 'AES-256-CBC',
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/app.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_not_run_when_no_files_exist(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_get_skip_reason(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertSame(
            'No .env files or app configuration found to analyze',
            $analyzer->getSkipReason()
        );
    }
}
