<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\AppKeyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
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

    // ==================== CONFIG CACHE DETECTION TESTS ====================

    public function test_fails_when_config_is_cached(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
ENV;

        $cachedConfig = <<<'PHP'
<?php return ['app' => ['key' => 'base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=']];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'bootstrap/cache/config.php' => $cachedConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Configuration is cached', $result);
    }

    public function test_passes_when_no_cached_config(): void
    {
        $envContent = <<<'ENV'
APP_KEY=base64:/AvmHMmBChdiKxwxReS4zWfHKXAfl0vsbJIf2fT3gHA=
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
