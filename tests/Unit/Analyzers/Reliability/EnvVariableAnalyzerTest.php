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
        $this->assertStringContainsString('5 missing environment variable(s)', $result->getMessage());
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
        $this->assertStringContainsString('Open .env.example', $recommendation);
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
        $this->assertStringContainsString('2 missing environment variable(s)', $result->getMessage());
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
}
