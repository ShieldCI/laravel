<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\EnvVariableAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
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

        // Should pass - can't read .env.example, treated as empty
        $this->assertPassed($result);
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
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
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
}
