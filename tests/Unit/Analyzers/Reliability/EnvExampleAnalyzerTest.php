<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\EnvExampleAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class EnvExampleAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EnvExampleAnalyzer;
    }

    // =========================================================================
    // Basic Functionality Tests
    // =========================================================================

    public function test_passes_when_all_variables_documented(): void
    {
        $envContent = 'APP_NAME=MyApp
APP_ENV=production
APP_KEY=base64:real_key_here';

        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:test123';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('All environment variables are documented', $result->getMessage());
    }

    public function test_fails_when_variables_undocumented(): void
    {
        $envContent = 'APP_NAME=MyApp
APP_ENV=production
NEW_API_KEY=secret123
STRIPE_SECRET=sk_test_xyz';

        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Undocumented environment variables', $result);
    }

    public function test_fails_when_env_example_missing(): void
    {
        $envContent = 'APP_NAME=MyApp
APP_ENV=production
APP_KEY=base64:key';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('missing', $result);
    }

    public function test_warning_when_env_missing(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('.env file not found', $result->getMessage());
    }

    public function test_passes_when_example_has_extra_variables(): void
    {
        $envContent = 'APP_NAME=MyApp
APP_ENV=production';

        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
APP_DEBUG=true
DB_CONNECTION=mysql
EXTRA_VAR=some_value';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - extra variables in .env.example are fine (documentation can be more comprehensive)
        $this->assertPassed($result);
    }

    public function test_reports_multiple_undocumented_variables(): void
    {
        $envContent = 'APP_NAME=MyApp
APP_ENV=production
NEW_VAR_1=value1
NEW_VAR_2=value2
NEW_VAR_3=value3
NEW_VAR_4=value4
NEW_VAR_5=value5';

        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('5 undocumented environment variable(s)', $result->getMessage());
    }

    // =========================================================================
    // Parsing Tests
    // =========================================================================

    public function test_ignores_comments(): void
    {
        $envContent = '# Application settings
APP_NAME=MyApp
# Database
APP_ENV=production';

        $exampleContent = '# My app config
APP_NAME=Laravel
# Environment
APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_blank_lines(): void
    {
        $envContent = 'APP_NAME=MyApp

APP_ENV=production

';

        $exampleContent = 'APP_NAME=Laravel

APP_ENV=local

';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_variables_with_spaces_around_equals(): void
    {
        $envContent = 'APP_NAME = MyApp
APP_ENV= production
APP_KEY =real';

        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
APP_KEY=test';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_variables_with_empty_values(): void
    {
        $envContent = 'APP_NAME=MyApp
APP_KEY=
DB_PASSWORD=';

        $exampleContent = 'APP_NAME=Laravel
APP_KEY=
DB_PASSWORD=';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_variables_with_special_characters(): void
    {
        $envContent = 'APP_KEY=base64:xyz789+/=
DATABASE_URL=mysql://root:secret@127.0.0.1/mydb';

        $exampleContent = 'APP_KEY=base64:abc123+/=
DATABASE_URL=mysql://user:pass@localhost/db';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // Metadata Tests
    // =========================================================================

    public function test_metadata_includes_undocumented_count(): void
    {
        $envContent = 'APP_NAME=MyApp
NEW_VAR_1=value1
NEW_VAR_2=value2
NEW_VAR_3=value3';

        $exampleContent = 'APP_NAME=Laravel';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $this->assertArrayHasKey('undocumented_count', $issues[0]->metadata);
        $this->assertSame(3, $issues[0]->metadata['undocumented_count']);
    }

    public function test_metadata_includes_undocumented_variables_list(): void
    {
        $envContent = 'APP_NAME=MyApp
NEW_API_KEY=secret
STRIPE_KEY=sk_test
CUSTOM_VAR=value';

        $exampleContent = 'APP_NAME=Laravel';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $this->assertArrayHasKey('undocumented_variables', $issues[0]->metadata);
        $undocumentedVars = $issues[0]->metadata['undocumented_variables'];
        $this->assertIsArray($undocumentedVars);
        $this->assertContains('NEW_API_KEY', $undocumentedVars);
        $this->assertContains('STRIPE_KEY', $undocumentedVars);
        $this->assertContains('CUSTOM_VAR', $undocumentedVars);
    }

    // =========================================================================
    // Recommendation Tests
    // =========================================================================

    public function test_recommendation_for_missing_example_file(): void
    {
        $envContent = 'APP_NAME=MyApp';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('Create a .env.example file', $recommendation);
    }

    public function test_recommendation_for_undocumented_variables(): void
    {
        $envContent = 'APP_NAME=MyApp
NEW_API_KEY=secret
STRIPE_SECRET=sk_test';

        $exampleContent = 'APP_NAME=Laravel';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('NEW_API_KEY', $recommendation);
        $this->assertStringContainsString('STRIPE_SECRET', $recommendation);
    }

    // =========================================================================
    // Edge Cases Tests
    // =========================================================================

    public function test_handles_empty_env_file(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => '',
            '.env.example' => 'APP_NAME=Laravel',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - no variables to document
        $this->assertPassed($result);
    }

    public function test_handles_empty_env_example_file(): void
    {
        $envContent = 'APP_NAME=MyApp
APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail - variables need to be documented
        $this->assertWarning($result);
        $this->assertStringContainsString('2 undocumented environment variable(s)', $result->getMessage());
    }

    public function test_handles_unreadable_env_file(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_NAME=MyApp',
            '.env.example' => 'APP_NAME=Laravel',
        ]);

        // Make .env unreadable
        $envPath = $tempDir.'/.env';
        chmod($envPath, 0000);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions for cleanup
        chmod($envPath, 0644);

        // Should pass - can't read .env, treated as empty
        $this->assertPassed($result);
    }

    public function test_handles_unreadable_env_example_file(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_NAME=MyApp',
            '.env.example' => 'APP_NAME=Laravel',
        ]);

        // Make .env.example unreadable
        $examplePath = $tempDir.'/.env.example';
        chmod($examplePath, 0000);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions for cleanup
        chmod($examplePath, 0644);

        // Should fail - can't read .env.example, all variables appear undocumented
        $this->assertWarning($result);
    }

    public function test_handles_empty_basepath(): void
    {
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath('');

        $result = $analyzer->analyze();

        // Should return warning - .env not found
        $this->assertInstanceOf(ResultInterface::class, $result);
    }

    public function test_handles_both_files_missing(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should return warning - can't verify without .env
        $this->assertWarning($result);
        $this->assertStringContainsString('.env file not found', $result->getMessage());
    }

    public function test_detects_single_undocumented_variable(): void
    {
        $envContent = 'APP_NAME=MyApp
APP_ENV=production
NEW_SECRET_KEY=abc123';

        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('1 undocumented environment variable(s)', $result->getMessage());

        $issues = $result->getIssues();
        $undocumentedVars = $issues[0]->metadata['undocumented_variables'];
        $this->assertIsArray($undocumentedVars);
        $this->assertCount(1, $undocumentedVars);
        $this->assertContains('NEW_SECRET_KEY', $undocumentedVars);
    }

    public function test_is_not_run_in_ci_mode(): void
    {
        $this->assertFalse(EnvExampleAnalyzer::$runInCI);
    }

    public function test_case_sensitive_variable_matching(): void
    {
        $envContent = 'APP_NAME=MyApp
app_name=lowercase';

        $exampleContent = 'APP_NAME=Laravel';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // app_name (lowercase) won't be parsed as it doesn't match the regex
        // Only APP_NAME should be recognized, which is documented
        $this->assertPassed($result);
    }

    // =========================================================================
    // Vapor / Serverless Skip Tests
    // =========================================================================

    public function test_skips_on_vapor(): void
    {
        /** @var EnvExampleAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setDeploymentPlatform('vapor');

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString('Vapor', $analyzer->getSkipReason());
    }

    public function test_skips_on_serverless(): void
    {
        /** @var EnvExampleAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setDeploymentPlatform('serverless');

        $this->assertFalse($analyzer->shouldRun());
    }

    // =========================================================================
    // Config → .env.example Completeness Tests (no-default rule)
    // =========================================================================

    private const FRAMEWORK_STUB = "<?php\n\nreturn ['name' => env('APP_NAME', 'Laravel')];";

    public function test_flags_bare_config_key_undocumented_in_env_example(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
            'config/acme.php' => "<?php\n\nreturn ['acme' => ['key' => env('ACME_API_KEY')]];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(
            "Environment variable 'ACME_API_KEY' is read in config files but not documented in .env.example",
            $issues[0]->message
        );
        $this->assertSame('medium', $issues[0]->severity->value);
        $this->assertSame('undocumented-config-key', $issues[0]->metadata['code']);
        $this->assertSame('ACME_API_KEY', $issues[0]->metadata['key']);
        $this->assertNotNull($issues[0]->location);
        $this->assertStringContainsString('config/acme.php', $issues[0]->location->file);
        $this->assertGreaterThan(0, $issues[0]->location->line);
    }

    public function test_defaulted_config_keys_are_never_flagged(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
            'config/app.php' => "<?php\n\nreturn ['timezone' => env('APP_TIMEZONE', 'UTC'), 'seats' => env('WIDGET_MAX_SEATS', 1000)];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertEmpty($result->getIssues());
    }

    public function test_null_default_is_treated_as_no_default(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
            'config/acme.php' => "<?php\n\nreturn ['key' => env('ACME_SECRET_KEY', null)];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertSame('ACME_SECRET_KEY', $result->getIssues()[0]->metadata['key']);
    }

    public function test_empty_string_default_counts_as_default(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
            'config/widget.php' => "<?php\n\nreturn ['label' => env('WIDGET_LABEL', '')];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_bare_config_key_documented_active(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => "APP_NAME=Laravel\nACME_API_KEY=",
            '.env' => 'APP_NAME=MyApp',
            'config/acme.php' => "<?php\n\nreturn ['key' => env('ACME_API_KEY')];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_bare_config_key_documented_as_commented(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => "APP_NAME=Laravel\n# ACME_API_KEY=",
            '.env' => 'APP_NAME=MyApp',
            'config/acme.php' => "<?php\n\nreturn ['key' => env('ACME_API_KEY')];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_bare_stock_keys_covered_by_framework_stubs_are_not_flagged(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
            'config/cache.php' => "<?php\n\nreturn ['memcached' => ['username' => env('MEMCACHED_USERNAME'), 'password' => env('MEMCACHED_PASSWORD')]];",
            'config/session.php' => "<?php\n\nreturn ['store' => env('SESSION_STORE'), 'lifetime' => env('SESSION_LIFETIME', 120)];",
            'vendor/laravel/framework/config/cache.php' => "<?php\n\nreturn ['memcached' => ['username' => env('MEMCACHED_USERNAME'), 'password' => env(\n    'MEMCACHED_PASSWORD'\n)]];",
            'vendor/laravel/framework/config/session.php' => "<?php\n\nreturn ['store' => env('SESSION_STORE')];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertEmpty($result->getIssues());
    }

    public function test_config_direction_skipped_without_framework_stubs(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
            'config/acme.php' => "<?php\n\nreturn ['key' => env('ACME_API_KEY')];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertEmpty($result->getIssues());
    }

    public function test_project_ignored_keys_suppress_findings(): void
    {
        config(['shieldci.analyzers.reliability.env-example-documented.ignored_keys' => [
            'WIDGET_TOKEN',
            'ACME_*',
            42,
        ]]);

        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
            'config/widget.php' => "<?php\n\nreturn ['token' => env('WIDGET_TOKEN'), 'timeout' => env('ACME_TIMEOUT'), 'secret' => env('WIDGET_SECRET')];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('WIDGET_SECRET', $issues[0]->metadata['key']);
    }

    public function test_vendor_shipped_bare_keys_are_not_flagged(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
            'vendor/acme/widget/config/widget.php' => "<?php\n\nreturn ['timeout' => env(\n    'ACME_WIDGET_TIMEOUT'\n)];",
            'config/custom.php' => "<?php\n\nreturn ['timeout' => env('ACME_WIDGET_TIMEOUT')];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertEmpty($result->getIssues());
    }

    public function test_unreadable_vendor_config_falls_back_to_flagging(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
            'vendor/acme/widget/config/widget.php' => "<?php\n\nreturn ['timeout' => env('ACME_WIDGET_TIMEOUT')];",
            'config/custom.php' => "<?php\n\nreturn ['timeout' => env('ACME_WIDGET_TIMEOUT')];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $vendorConfigPath = $tempDir.'/vendor/acme/widget/config/widget.php';
        chmod($vendorConfigPath, 0000);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions for cleanup
        chmod($vendorConfigPath, 0644);

        $this->assertWarning($result);
        $this->assertSame('ACME_WIDGET_TIMEOUT', $result->getIssues()[0]->metadata['key']);
    }

    public function test_bare_key_in_vendor_named_config_file_is_not_flagged(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
            'config/services.php' => "<?php\n\nreturn ['mailer' => ['key' => env('ACME_MAIL_KEY')]];",
            'vendor/laravel/framework/config/services.php' => "<?php\n\nreturn ['mailer' => ['key' => env('OTHER_MAIL_KEY')]];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertEmpty($result->getIssues());
    }

    public function test_custom_disk_keys_in_vendor_named_filesystems_config_are_not_flagged(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
            'config/filesystems.php' => "<?php\n\nreturn ['disks' => ['acme' => ['url' => env('ACME_DISK_URL'), 'endpoint' => env('ACME_DISK_ENDPOINT')]]];",
            'vendor/laravel/framework/config/filesystems.php' => "<?php\n\nreturn ['disks' => ['local' => ['serve' => env('FILESYSTEM_SERVE', true)]]];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertEmpty($result->getIssues());
    }

    public function test_config_direction_runs_when_env_missing(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            'config/acme.php' => "<?php\n\nreturn ['key' => env('ACME_API_KEY')];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('undocumented-config-key', $issues[0]->metadata['code']);
    }

    public function test_env_missing_with_clean_config_keeps_existing_warning(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => "APP_NAME=Laravel\nWIDGET_MAX_SEATS=1000",
            'config/widget.php' => "<?php\n\nreturn ['seats' => env('WIDGET_MAX_SEATS', 1000)];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertEmpty($result->getIssues());
        $this->assertStringContainsString('.env file not found', $result->getMessage());
    }

    public function test_both_directions_report_combined_issues(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => "APP_NAME=MyApp\nACME_UNDOCUMENTED=1",
            'config/acme.php' => "<?php\n\nreturn ['key' => env('ACME_API_KEY')];",
            'vendor/laravel/framework/config/app.php' => self::FRAMEWORK_STUB,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);

        $codes = array_map(static fn ($issue) => $issue->metadata['code'], $issues);
        $this->assertContains('undocumented-config-key', $codes);
        $this->assertContains('undocumented-variables', $codes);
    }
}
