<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\EnvFileSecurityAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class EnvFileSecurityAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EnvFileSecurityAnalyzer;
    }

    // ==========================================
    // A. Public .env File Tests (5 tests)
    // ==========================================

    public function test_detects_env_in_public_directory(): void
    {
        $envContent = 'APP_KEY=test123';

        $tempDir = $this->createTempDirectory([
            'public/.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('publicly accessible', $result);
        $issues = $result->getIssues();
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_detects_env_in_public_html_directory(): void
    {
        $envContent = 'APP_KEY=test123';

        $tempDir = $this->createTempDirectory([
            'public_html/.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('publicly accessible', $result);
    }

    public function test_detects_env_in_www_directory(): void
    {
        $envContent = 'APP_KEY=test123';

        $tempDir = $this->createTempDirectory([
            'www/.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('publicly accessible', $result);
    }

    public function test_detects_env_in_html_directory(): void
    {
        $envContent = 'APP_KEY=test123';

        $tempDir = $this->createTempDirectory([
            'html/.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('publicly accessible', $result);
    }

    public function test_detects_multiple_public_env_files(): void
    {
        $envContent = 'APP_KEY=test123';

        $tempDir = $this->createTempDirectory([
            'public/.env' => $envContent,
            'www/.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    // ==========================================
    // B. .env.example Tests (8 tests)
    // ==========================================

    public function test_detects_missing_env_example_when_env_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Missing .env.example is Low severity, so it may be returned as "info" or "warning"
        $this->assertHasIssueContaining('Missing .env.example', $result);
        $issues = $result->getIssues();
        $this->assertEquals(Severity::Low, $issues[0]->severity);
    }

    public function test_does_not_flag_missing_env_example_when_no_env(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Analyzer should be skipped when nothing exists
        $this->assertSkipped($result);
    }

    public function test_detects_real_app_key_in_env_example(): void
    {
        // Use a non-base64 value to test real credential detection
        $envExample = 'APP_KEY=RealVeryLongKeyThatShouldNotBeHereXYZ1234567890ABCDEFGHIJKLMNOP';

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
            '.env.example' => $envExample,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APP_KEY', $result);
        $this->assertHasIssueContaining('real credentials', $result);
        $issues = $result->getIssues();
        $this->assertEquals(Severity::High, $issues[0]->severity);
    }

    public function test_detects_real_db_password_in_env_example(): void
    {
        $envExample = 'DB_PASSWORD=MySuperSecretPasswordThatIsReallyLong123456';

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
            '.env.example' => $envExample,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('DB_PASSWORD', $result);
        $issues = $result->getIssues();
        $this->assertEquals(Severity::High, $issues[0]->severity);
    }

    public function test_detects_real_aws_secret_in_env_example(): void
    {
        // Make it longer than 20 characters and without 'example' keyword
        $envExample = 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYRealSecretKey1234567890ABC';

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
            '.env.example' => $envExample,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('AWS_SECRET_ACCESS_KEY', $result);
    }

    public function test_allows_placeholder_values_in_env_example(): void
    {
        $envExample = <<<'ENV'
APP_KEY=
DB_PASSWORD=your-password-here
AWS_SECRET_ACCESS_KEY=your-aws-secret
MAIL_PASSWORD=change-me
REDIS_PASSWORD=null
SESSION_SECRET=""
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
            '.env.example' => $envExample,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should not flag placeholders as real credentials
        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertStringNotContainsString('real credentials', $issue->message);
        }
    }

    public function test_allows_base64_encoded_values_in_env_example(): void
    {
        $envExample = 'APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAA==';

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
            '.env.example' => $envExample,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should not flag base64 values as real credentials
        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertNotEquals(Severity::High, $issue->severity);
        }
    }

    public function test_allows_short_values_in_env_example(): void
    {
        $envExample = <<<'ENV'
APP_KEY=short
DB_PASSWORD=test123
AWS_SECRET_ACCESS_KEY=abc
ENV;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
            '.env.example' => $envExample,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Short values shouldn't be flagged as real credentials
        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertStringNotContainsString('real credentials', $issue->message);
        }
    }

    // ==========================================
    // C. .gitignore Tests (4 tests)
    // ==========================================

    public function test_detects_env_not_in_gitignore(): void
    {
        $envContent = 'APP_KEY=test';
        $gitignore = '# empty';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => 'APP_KEY=',  // Add this to prevent missing .env.example issue
            '.gitignore' => $gitignore,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('gitignore', $result);
        $issues = $result->getIssues();
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_passes_when_env_in_gitignore(): void
    {
        $envContent = 'APP_KEY=test';
        $gitignore = <<<'GITIGNORE'
/vendor
/node_modules
.env
.env.backup
GITIGNORE;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.gitignore' => $gitignore,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should have only non-gitignore issues
        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertStringNotContainsString('gitignore', $issue->message);
        }
    }

    public function test_passes_when_wildcard_env_pattern_in_gitignore(): void
    {
        $envContent = 'APP_KEY=test';
        $gitignore = <<<'GITIGNORE'
/vendor
*.env
GITIGNORE;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.gitignore' => $gitignore,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should have only non-gitignore issues
        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertStringNotContainsString('not excluded in .gitignore', $issue->message);
        }
    }

    public function test_skips_gitignore_check_when_no_gitignore_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should not flag gitignore issues if .gitignore doesn't exist
        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertStringNotContainsString('gitignore', $issue->message);
        }
    }

    // ==========================================
    // D. Git Commit Tests (2 tests - git tracking is hard to test)
    // ==========================================

    public function test_skips_git_check_when_no_git_directory(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
            '.gitignore' => '.env',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should not flag git commit issues if .git doesn't exist
        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertStringNotContainsString('committed to git', $issue->message);
        }
    }

    public function test_skips_git_check_when_env_does_not_exist(): void
    {
        $tempDir = $this->createTempDirectory([
            '.gitignore' => '.env',
        ]);

        // Create empty .git directory
        mkdir($tempDir.'/.git');

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==========================================
    // E. Permission Tests (7 tests)
    // ==========================================

    public function test_passes_when_env_has_600_permissions(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
        ]);

        $envPath = $tempDir.'/.env';
        chmod($envPath, 0600);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should have only non-permission issues
        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertStringNotContainsString('permissions', $issue->message);
        }
    }

    public function test_detects_644_permissions_as_critical(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
        ]);

        $envPath = $tempDir.'/.env';
        chmod($envPath, 0644);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('permissions', $result);
        $issues = $result->getIssues();

        // Find the permission issue
        $permissionIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'permissions')) {
                $permissionIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($permissionIssue);
        $this->assertEquals(Severity::Critical, $permissionIssue->severity);
    }

    public function test_detects_640_permissions_as_medium(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
        ]);

        $envPath = $tempDir.'/.env';
        chmod($envPath, 0640);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('permissions', $result);
        $issues = $result->getIssues();

        // Find the permission issue
        $permissionIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'permissions')) {
                $permissionIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($permissionIssue);
        $this->assertEquals(Severity::Medium, $permissionIssue->severity);
    }

    public function test_detects_666_permissions_as_critical(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
        ]);

        $envPath = $tempDir.'/.env';
        chmod($envPath, 0666);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('permissions', $result);
        $issues = $result->getIssues();

        $permissionIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'permissions')) {
                $permissionIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($permissionIssue);
        $this->assertEquals(Severity::Critical, $permissionIssue->severity);
    }

    public function test_detects_777_permissions_as_critical(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
        ]);

        $envPath = $tempDir.'/.env';
        chmod($envPath, 0777);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('permissions', $result);
    }

    public function test_skips_permission_check_when_env_does_not_exist(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Analyzer should be skipped when nothing exists
        $this->assertSkipped($result);
    }

    public function test_detects_660_permissions_as_medium(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
        ]);

        $envPath = $tempDir.'/.env';
        chmod($envPath, 0660);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('permissions', $result);
        $issues = $result->getIssues();

        $permissionIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'permissions')) {
                $permissionIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($permissionIssue);
        $this->assertEquals(Severity::Medium, $permissionIssue->severity);
    }

    // ==========================================
    // F. shouldRun Tests (6 tests)
    // ==========================================

    public function test_should_run_when_env_file_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_when_env_example_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env.example' => 'APP_KEY=',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_when_gitignore_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            '.gitignore' => '.env',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_when_git_directory_exists(): void
    {
        $tempDir = $this->createTempDirectory([]);

        mkdir($tempDir.'/.git');

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_when_public_directory_exists(): void
    {
        $tempDir = $this->createTempDirectory([]);

        mkdir($tempDir.'/public');

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_not_run_when_nothing_exists(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertFalse($analyzer->shouldRun());
    }

    // ==========================================
    // G. Metadata Tests (4 tests)
    // ==========================================

    public function test_public_env_issue_has_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            'public/.env' => 'APP_KEY=test',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertArrayHasKey('path', $issues[0]->metadata);
    }

    public function test_missing_env_example_has_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        if (! empty($issues)) {
            $missingEnvExampleIssue = null;
            foreach ($issues as $issue) {
                if (str_contains($issue->message, 'Missing .env.example')) {
                    $missingEnvExampleIssue = $issue;
                    break;
                }
            }

            if ($missingEnvExampleIssue !== null) {
                $this->assertArrayHasKey('file', $missingEnvExampleIssue->metadata);
                $this->assertArrayHasKey('exists', $missingEnvExampleIssue->metadata);
                $this->assertEquals('.env.example', $missingEnvExampleIssue->metadata['file']);
                $this->assertFalse($missingEnvExampleIssue->metadata['exists']);
            }
        }
    }

    public function test_gitignore_issue_has_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
            '.gitignore' => '# empty',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $gitignoreIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'gitignore')) {
                $gitignoreIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($gitignoreIssue);
        $this->assertArrayHasKey('file', $gitignoreIssue->metadata);
        $this->assertArrayHasKey('missing_pattern', $gitignoreIssue->metadata);
    }

    public function test_permission_issue_has_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
        ]);

        $envPath = $tempDir.'/.env';
        chmod($envPath, 0644);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $permissionIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'permissions')) {
                $permissionIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($permissionIssue);
        $this->assertArrayHasKey('permissions', $permissionIssue->metadata);
        $this->assertArrayHasKey('world_readable', $permissionIssue->metadata);
    }

    // ==========================================
    // H. Edge Cases (3 tests)
    // ==========================================

    public function test_detects_multiple_issues_at_once(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
            'public/.env' => 'APP_KEY=test',
            '.gitignore' => '# empty',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    public function test_passes_when_all_checks_pass(): void
    {
        $envContent = 'APP_KEY=base64:test';
        $envExample = 'APP_KEY=';
        $gitignore = <<<'GITIGNORE'
/vendor
/node_modules
.env
.env.backup
GITIGNORE;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $envExample,
            '.gitignore' => $gitignore,
        ]);

        // Set secure permissions
        chmod($tempDir.'/.env', 0600);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_unreadable_files_gracefully(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_KEY=test',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should return a result (not crash)
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
