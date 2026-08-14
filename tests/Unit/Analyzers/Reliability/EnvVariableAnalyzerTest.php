<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\EnvVariableAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class EnvVariableAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EnvVariableAnalyzer;
    }

    // =========================================================================
    // Basic Functionality Tests
    // =========================================================================

    public function test_passes_when_all_variables_present(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:test123';

        $envContent = 'APP_NAME=MyApp
APP_ENV=production
APP_KEY=base64:real_key_here';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('All environment variables', $result->getMessage());
    }

    public function test_fails_when_variables_missing(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
APP_KEY=
DB_CONNECTION=mysql
DB_HOST=127.0.0.1';

        $envContent = 'APP_NAME=Laravel
APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Missing environment variables', $result);
    }

    public function test_fails_when_env_file_missing(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
APP_KEY=
DB_CONNECTION=mysql';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('missing', $result);
    }

    public function test_warning_when_env_example_missing(): void
    {
        $envContent = 'APP_NAME=MyApp
APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('.env.example file not found', $result->getMessage());
    }

    public function test_passes_when_env_has_extra_variables(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local';

        $envContent = 'APP_NAME=MyApp
APP_ENV=production
APP_DEBUG=false
DB_CONNECTION=mysql
EXTRA_VAR=some_value';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - extra variables in .env are fine
        $this->assertPassed($result);
    }

    public function test_reports_multiple_missing_variables(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
APP_KEY=
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel';

        $envContent = 'APP_NAME=Laravel
APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('5 environment variable issue(s)', $result->getMessage());
    }

    // =========================================================================
    // Parsing Tests
    // =========================================================================

    public function test_ignores_comments(): void
    {
        $exampleContent = '# Application settings
APP_NAME=Laravel
# Database
APP_ENV=local';

        $envContent = '# My app config
APP_NAME=MyApp
# Environment
APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_blank_lines(): void
    {
        $exampleContent = 'APP_NAME=Laravel

APP_ENV=local

';

        $envContent = 'APP_NAME=MyApp

APP_ENV=production

';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_variables_with_spaces_around_equals(): void
    {
        $exampleContent = 'APP_NAME = Laravel
APP_ENV= local
APP_KEY =test';

        $envContent = 'APP_NAME=MyApp
APP_ENV=production
APP_KEY=real';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_variables_with_empty_values(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_KEY=
DB_PASSWORD=';

        $envContent = 'APP_NAME=MyApp
APP_KEY=
DB_PASSWORD=';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_variables_with_special_characters(): void
    {
        $exampleContent = 'APP_KEY=base64:abc123+/=
DATABASE_URL=mysql://user:pass@localhost/db';

        $envContent = 'APP_KEY=base64:xyz789+/=
DATABASE_URL=mysql://root:secret@127.0.0.1/mydb';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // Metadata Tests
    // =========================================================================

    public function test_metadata_includes_missing_count(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
APP_KEY=
DB_CONNECTION=mysql';

        $envContent = 'APP_NAME=MyApp';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $this->assertArrayHasKey('missing_count', $issues[0]->metadata);
        $this->assertSame(3, $issues[0]->metadata['missing_count']);
    }

    public function test_metadata_includes_missing_variables_list(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
APP_KEY=
DB_CONNECTION=mysql';

        $envContent = 'APP_NAME=MyApp';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $this->assertArrayHasKey('missing_variables', $issues[0]->metadata);
        $missingVars = $issues[0]->metadata['missing_variables'];
        $this->assertIsArray($missingVars);
        $this->assertContains('APP_ENV', $missingVars);
        $this->assertContains('APP_KEY', $missingVars);
        $this->assertContains('DB_CONNECTION', $missingVars);
    }

    // =========================================================================
    // Recommendation Tests
    // =========================================================================

    public function test_recommendation_for_missing_env_file(): void
    {
        $exampleContent = 'APP_NAME=Laravel';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('cp .env.example .env', $recommendation);
        $this->assertStringContainsString('copy .env.example .env', $recommendation);
    }

    public function test_recommendation_for_missing_variables(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
DB_CONNECTION=mysql';

        $envContent = 'APP_NAME=MyApp';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('APP_ENV', $recommendation);
        $this->assertStringContainsString('DB_CONNECTION', $recommendation);
    }

    // =========================================================================
    // Edge Cases Tests
    // =========================================================================

    public function test_handles_empty_env_example_file(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => '',
            '.env' => 'APP_NAME=MyApp',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - no variables required
        $this->assertPassed($result);
    }

    public function test_handles_empty_env_file(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail - missing all variables
        $this->assertFailed($result);
        $this->assertStringContainsString('2 environment variable issue(s)', $result->getMessage());
    }

    public function test_handles_unreadable_env_example_file(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
        ]);

        // Make .env.example unreadable
        $examplePath = $tempDir.'/.env.example';
        chmod($examplePath, 0000);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions for cleanup
        chmod($examplePath, 0644);

        // Should fail - parsing error is now properly reported
        $this->assertFailed($result);
        $this->assertStringContainsString('parse', strtolower($result->getMessage()));
    }

    public function test_handles_unreadable_env_file(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
        ]);

        // Make .env unreadable
        $envPath = $tempDir.'/.env';
        chmod($envPath, 0000);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions for cleanup
        chmod($envPath, 0644);

        // Should fail - can't read .env, treated as missing all variables
        $this->assertFailed($result);
    }

    public function test_handles_empty_basepath(): void
    {
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath('');

        $result = $analyzer->analyze();

        // Should return warning - .env.example not found
        $this->assertInstanceOf(ResultInterface::class, $result);
    }

    public function test_handles_both_files_missing(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should return warning - can't verify without .env.example
        $this->assertWarning($result);
        $this->assertStringContainsString('.env.example file not found', $result->getMessage());
    }

    // =========================================================================
    // Commented Variables Tests
    // =========================================================================

    public function test_detects_commented_variables(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_KEY=
DB_PASSWORD=';

        $envContent = 'APP_NAME=MyApp
# APP_KEY=base64:test123
# DB_PASSWORD=secret';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('2 commented environment variable(s)', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(2, $issues[0]->metadata['commented_count']);

        $commentedVars = $issues[0]->metadata['commented_variables'];
        $this->assertIsArray($commentedVars);
        $this->assertContains('APP_KEY', $commentedVars);
        $this->assertContains('DB_PASSWORD', $commentedVars);
    }

    public function test_distinguishes_missing_from_commented(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_KEY=
DB_PASSWORD=
MAIL_FROM=';

        $envContent = 'APP_NAME=MyApp
# APP_KEY=base64:test123';
        // DB_PASSWORD is completely absent
        // MAIL_FROM is completely absent

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);

        // Find missing and commented issues
        $missingIssue = collect($issues)->first(fn ($i) => ($i->metadata['missing_count'] ?? 0) > 0);
        $commentedIssue = collect($issues)->first(fn ($i) => ($i->metadata['commented_count'] ?? 0) > 0);

        $this->assertNotNull($missingIssue);
        $this->assertNotNull($commentedIssue);

        $this->assertSame(2, $missingIssue->metadata['missing_count']);

        $missingVars = $missingIssue->metadata['missing_variables'];
        $this->assertIsArray($missingVars);
        $this->assertContains('DB_PASSWORD', $missingVars);
        $this->assertContains('MAIL_FROM', $missingVars);

        $this->assertSame(1, $commentedIssue->metadata['commented_count']);

        $commentedVars = $commentedIssue->metadata['commented_variables'];
        $this->assertIsArray($commentedVars);
        $this->assertContains('APP_KEY', $commentedVars);
    }

    public function test_handles_commented_variables_with_spaces(): void
    {
        $exampleContent = 'APP_KEY=';

        $envContent = '#   APP_KEY=base64:test123';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $commentedVars = $issues[0]->metadata['commented_variables'];
        $this->assertIsArray($commentedVars);
        $this->assertContains('APP_KEY', $commentedVars);
    }

    public function test_ignores_regular_comments(): void
    {
        $exampleContent = 'APP_NAME=Laravel';

        $envContent = '# This is a regular comment
# TODO: Add more config
APP_NAME=MyApp';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - regular comments are not variable definitions
        $this->assertPassed($result);
    }

    public function test_only_commented_variables_returns_warning_not_failed(): void
    {
        $exampleContent = 'APP_KEY=';

        $envContent = '# APP_KEY=base64:test123';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Only commented variables should be a warning, not a failure
        $this->assertWarning($result);
        $this->assertStringContainsString('commented', strtolower($result->getMessage()));
    }

    // =========================================================================
    // Parse Error Handling Tests
    // =========================================================================

    public function test_reports_parse_error_for_env_example(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
        ]);

        // Make .env.example unreadable to simulate parse error
        $examplePath = $tempDir.'/.env.example';
        chmod($examplePath, 0000);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions
        chmod($examplePath, 0644);

        $this->assertFailed($result);
        $this->assertStringContainsString('parse', strtolower($result->getMessage()));

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('parse-error-example', $issues[0]->metadata['code']);
        $this->assertArrayHasKey('error', $issues[0]->metadata);

        $error = $issues[0]->metadata['error'];
        $this->assertIsString($error);
        $this->assertStringContainsString('not readable', $error);
    }

    public function test_reports_parse_error_for_env(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_NAME=Laravel',
            '.env' => 'APP_NAME=MyApp',
        ]);

        // Make .env unreadable to simulate parse error
        $envPath = $tempDir.'/.env';
        chmod($envPath, 0000);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions
        chmod($envPath, 0644);

        $this->assertFailed($result);
        $this->assertStringContainsString('parse', strtolower($result->getMessage()));

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('parse-error-env', $issues[0]->metadata['code']);
        $this->assertArrayHasKey('error', $issues[0]->metadata);
    }

    public function test_parse_error_prevents_false_pass(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_KEY=
DB_PASSWORD=
REQUIRED_VAR=',
            '.env' => 'APP_KEY=test',
        ]);

        // Make .env.example unreadable - this should fail, not pass
        $examplePath = $tempDir.'/.env.example';
        chmod($examplePath, 0000);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions
        chmod($examplePath, 0644);

        // Should FAIL due to parse error, not incorrectly PASS
        $this->assertFailed($result);

        // The old silent behavior would have returned empty [] and passed
        // The new behavior properly reports the parse error
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('parse', strtolower($issues[0]->message));
    }

    public function test_empty_env_file_is_not_parse_error(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_KEY=',
            '.env' => '', // Empty but valid
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail for missing variable, not for parse error
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('missing-variables', $issues[0]->metadata['code']);
        $this->assertNotSame('parse-error-env', $issues[0]->metadata['code']);
    }

    public function test_is_not_run_in_ci_mode(): void
    {
        $this->assertFalse(EnvVariableAnalyzer::$runInCI);
    }

    // =========================================================================
    // Vapor / Serverless Skip Tests
    // =========================================================================

    public function test_skips_on_vapor(): void
    {
        /** @var EnvVariableAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setDeploymentPlatform('vapor');

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString('Vapor', $analyzer->getSkipReason());
    }

    public function test_skips_on_serverless(): void
    {
        /** @var EnvVariableAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setDeploymentPlatform('serverless');

        $this->assertFalse($analyzer->shouldRun());
    }

    // =========================================================================
    // Default-Aware Grading Tests (lean .env style)
    // =========================================================================

    public function test_passes_when_missing_variables_have_config_defaults(): void
    {
        $configContent = <<<'PHP'
<?php

return [
    'max_seats' => env('WIDGET_MAX_SEATS', 1000),
    'nested' => [
        'poll_interval' => env('WIDGET_POLL_INTERVAL', 5000),
    ],
    'timeout' => env(
        'WIDGET_TIMEOUT',
        30
    ),
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env.example' => "APP_NAME=Laravel\nWIDGET_MAX_SEATS=1000\nWIDGET_POLL_INTERVAL=5000\nWIDGET_TIMEOUT=30",
            '.env' => 'APP_NAME=MyApp',
            'config/widget.php' => $configContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('config defaults', $result->getMessage());

        $metadata = $result->getMetadata();
        $this->assertSame(3, $metadata['defaulted_count']);
        $this->assertEqualsCanonicalizing(
            ['WIDGET_MAX_SEATS', 'WIDGET_POLL_INTERVAL', 'WIDGET_TIMEOUT'],
            $metadata['defaulted_variables']
        );
    }

    public function test_reports_defaulted_variables_as_info_when_flag_enabled(): void
    {
        config(['shieldci.analyzers.reliability.env-variables-complete.report_defaulted' => true]);

        $tempDir = $this->createTempDirectory([
            '.env.example' => "APP_NAME=Laravel\nWIDGET_MAX_SEATS=1000",
            '.env' => 'APP_NAME=MyApp',
            'config/widget.php' => "<?php\n\nreturn ['max_seats' => env('WIDGET_MAX_SEATS', 1000)];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('info', $issues[0]->severity->value);
        $this->assertSame('defaulted-variables', $issues[0]->metadata['code']);
        $this->assertContains('WIDGET_MAX_SEATS', $issues[0]->metadata['defaulted_variables']);
    }

    public function test_bare_env_call_in_config_stays_high(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => "APP_NAME=Laravel\nACME_SECRET_KEY=",
            '.env' => 'APP_NAME=MyApp',
            'config/services.php' => "<?php\n\nreturn ['acme' => ['key' => env('ACME_SECRET_KEY')]];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('Missing environment variables', $issues[0]->message);
        $this->assertSame('missing-variables', $issues[0]->metadata['code']);
        $this->assertContains('ACME_SECRET_KEY', $issues[0]->metadata['missing_variables']);
    }

    public function test_null_default_in_config_stays_high(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => "APP_NAME=Laravel\nACME_SECRET_KEY=",
            '.env' => 'APP_NAME=MyApp',
            'config/services.php' => "<?php\n\nreturn ['key' => env('ACME_SECRET_KEY', null)];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertSame('missing-variables', $result->getIssues()[0]->metadata['code']);
    }

    public function test_empty_string_default_counts_as_default(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => "APP_NAME=Laravel\nWIDGET_LABEL=",
            '.env' => 'APP_NAME=MyApp',
            'config/widget.php' => "<?php\n\nreturn ['label' => env('WIDGET_LABEL', '')];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertContains('WIDGET_LABEL', $result->getMetadata()['defaulted_variables']);
    }

    public function test_mixed_defaulted_and_bare_missing_variables_partition(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => "APP_NAME=Laravel\nACME_SECRET_KEY=\nWIDGET_MAX_SEATS=1000",
            '.env' => 'APP_NAME=MyApp',
            'config/widget.php' => "<?php\n\nreturn ['seats' => env('WIDGET_MAX_SEATS', 1000), 'key' => env('ACME_SECRET_KEY')];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(1, $issues[0]->metadata['missing_count']);
        $this->assertSame(['ACME_SECRET_KEY'], $issues[0]->metadata['missing_variables']);
        $this->assertSame(['WIDGET_MAX_SEATS'], $result->getMetadata()['defaulted_variables']);
    }

    public function test_missing_variable_not_referenced_in_config_stays_high(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => "APP_NAME=Laravel\nVITE_ACME_KEY=",
            '.env' => 'APP_NAME=MyApp',
            'config/widget.php' => "<?php\n\nreturn ['name' => env('APP_NAME', 'Laravel')];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertContains('VITE_ACME_KEY', $result->getIssues()[0]->metadata['missing_variables']);
    }

    public function test_bare_call_in_one_file_overrides_default_in_another(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => "APP_NAME=Laravel\nACME_SECRET_KEY=",
            '.env' => 'APP_NAME=MyApp',
            'config/widget.php' => "<?php\n\nreturn ['key' => env('ACME_SECRET_KEY', 'fallback')];",
            'config/services.php' => "<?php\n\nreturn ['key' => env('ACME_SECRET_KEY')];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertContains('ACME_SECRET_KEY', $result->getIssues()[0]->metadata['missing_variables']);
    }

    public function test_dynamic_env_key_in_config_is_ignored(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => "APP_NAME=Laravel\nWIDGET_MAX_SEATS=1000",
            '.env' => 'APP_NAME=MyApp',
            'config/widget.php' => "<?php\n\nreturn ['seats' => env('WIDGET_MAX_SEATS', 1000), 'other' => env(\$dynamicKey)];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertContains('WIDGET_MAX_SEATS', $result->getMetadata()['defaulted_variables']);
    }

    // =========================================================================
    // Redundant Override Tests (opt-in flag)
    // =========================================================================

    public function test_redundant_override_not_reported_by_default(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'WIDGET_MAX_SEATS=1000',
            '.env' => 'WIDGET_MAX_SEATS=1000',
            'config/widget.php' => "<?php\n\nreturn ['seats' => env('WIDGET_MAX_SEATS', 1000)];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertEmpty($result->getIssues());
    }

    public function test_redundant_override_reported_when_flag_enabled(): void
    {
        config(['shieldci.analyzers.reliability.env-variables-complete.report_redundant' => true]);

        $tempDir = $this->createTempDirectory([
            '.env.example' => "WIDGET_MAX_SEATS=1000\nWIDGET_LABEL=widgets",
            '.env' => "WIDGET_MAX_SEATS=1000\nWIDGET_LABEL=\"widgets\"",
            'config/widget.php' => "<?php\n\nreturn ['seats' => env('WIDGET_MAX_SEATS', 1000), 'label' => env('WIDGET_LABEL', 'widgets')];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('info', $issues[0]->severity->value);
        $this->assertSame('redundant-override', $issues[0]->metadata['code']);
        $this->assertEqualsCanonicalizing(
            ['WIDGET_MAX_SEATS', 'WIDGET_LABEL'],
            $issues[0]->metadata['redundant_variables']
        );
    }

    public function test_redundant_override_matches_boolean_default_text(): void
    {
        config(['shieldci.analyzers.reliability.env-variables-complete.report_redundant' => true]);

        $tempDir = $this->createTempDirectory([
            '.env.example' => 'WIDGET_ENABLED=false',
            '.env' => 'WIDGET_ENABLED=false',
            'config/widget.php' => "<?php\n\nreturn ['enabled' => env('WIDGET_ENABLED', false)];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertSame('redundant-override', $result->getIssues()[0]->metadata['code']);
    }

    public function test_redundant_override_ignores_non_literal_defaults_and_differing_values(): void
    {
        config(['shieldci.analyzers.reliability.env-variables-complete.report_redundant' => true]);

        $tempDir = $this->createTempDirectory([
            '.env.example' => "WIDGET_PATH=/tmp/widgets\nWIDGET_MAX_SEATS=1000",
            '.env' => "WIDGET_PATH=/tmp/widgets\nWIDGET_MAX_SEATS=2000",
            'config/widget.php' => "<?php\n\nreturn ['path' => env('WIDGET_PATH', storage_path('widgets')), 'seats' => env('WIDGET_MAX_SEATS', 1000)];",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertEmpty($result->getIssues());
    }
}
