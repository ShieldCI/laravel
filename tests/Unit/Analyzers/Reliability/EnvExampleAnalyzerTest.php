<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\EnvExampleAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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
        $this->assertStringContainsString('placeholder', $recommendation);
        $this->assertStringContainsString('Never commit real secrets', $recommendation);
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

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('NEW_API_KEY', $recommendation);
        $this->assertStringContainsString('STRIPE_SECRET', $recommendation);
        $this->assertStringContainsString('Open .env.example', $recommendation);
        $this->assertStringContainsString('placeholder values', $recommendation);
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
        $this->assertFailed($result);
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
        $this->assertFailed($result);
    }

    public function test_handles_empty_basepath(): void
    {
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath('');

        $result = $analyzer->analyze();

        // Should return warning - .env not found
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
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

        $this->assertFailed($result);
        $this->assertStringContainsString('1 undocumented environment variable(s)', $result->getMessage());

        $issues = $result->getIssues();
        $undocumentedVars = $issues[0]->metadata['undocumented_variables'];
        $this->assertCount(1, $undocumentedVars);
        $this->assertContains('NEW_SECRET_KEY', $undocumentedVars);
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
}
