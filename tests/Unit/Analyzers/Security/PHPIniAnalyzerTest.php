<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\PHPIniAnalyzer;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Tests\AnalyzerTestCase;

class PHPIniAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): PHPIniAnalyzer
    {
        return new PHPIniAnalyzer;
    }

    public function test_it_passes_when_php_configuration_is_secure(): void
    {
        $secureIniPath = $this->createPhpIniFixture([
            'allow_url_fopen = Off',
            'allow_url_include = Off',
            'expose_php = Off',
            'display_errors = Off',
            'display_startup_errors = Off',
            'log_errors = On',
            'ignore_repeated_errors = Off',
            'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source',
            'open_basedir = /var/www/html',
            'error_reporting = '.(E_ALL & ~E_STRICT & ~E_DEPRECATED & ~E_NOTICE),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($secureIniPath);
        $analyzer->setBasePath(dirname($secureIniPath));
        $analyzer->setIniValues($this->secureIniValues());

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertIssueCount(0, $result);
    }

    public function test_it_detects_multiple_insecure_settings(): void
    {
        $iniPath = $this->createPhpIniFixture([
            'allow_url_fopen = On',
            'allow_url_include = On',
            'expose_php = On',
            'display_errors = On',
            'display_startup_errors = On',
            'log_errors = Off',
            'ignore_repeated_errors = On',
            'disable_functions = ',
            'open_basedir = ',
            'error_reporting = E_ALL',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues($this->secureIniValues([
            'allow_url_fopen' => '1',
            'allow_url_include' => '1',
            'expose_php' => '1',
            'display_errors' => '1',
            'display_startup_errors' => '1',
            'log_errors' => '0',
            'ignore_repeated_errors' => '1',
            'disable_functions' => '',
            'open_basedir' => '',
            'error_reporting' => 'E_ALL',
        ]));

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Note: error_reporting, open_basedir, and disable_functions checks are skipped in Laravel
        $this->assertIssueCount(7, $result);
        $this->assertHasIssueContaining('allow_url_fopen', $result);
    }

    public function test_it_is_skipped_outside_relevant_environments(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => "APP_ENV=local\n",
            'php.ini' => 'display_errors = On',
        ]);

        $iniPath = $tempDir.'/php.ini';

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setIniValues($this->secureIniValues([
            'display_errors' => '1',
        ]));

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_it_detects_verbose_error_reporting_with_e_strict(): void
    {
        // Note: This test is now obsolete since error_reporting checks are skipped in Laravel.
        // Laravel intentionally sets error_reporting(-1) and controls display via display_errors.
        // Keeping the test but updating expectations to reflect new behavior.
        $testValue = E_ALL & ~E_DEPRECATED & ~E_NOTICE | E_STRICT;

        $iniPath = $this->createPhpIniFixture([
            'error_reporting = '.$testValue,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues($this->secureIniValues([
            'error_reporting' => (string) $testValue,
        ]));

        $result = $analyzer->analyze();

        // error_reporting checks are skipped in Laravel applications
        $this->assertPassed($result);
    }

    public function test_it_detects_verbose_error_reporting_with_e_deprecated(): void
    {
        // Note: This test is now obsolete since error_reporting checks are skipped in Laravel.
        // Laravel intentionally sets error_reporting(-1) and controls display via display_errors.
        // Keeping the test but updating expectations to reflect new behavior.
        $testValue = E_ALL & ~E_STRICT & ~E_NOTICE | E_DEPRECATED;

        $iniPath = $this->createPhpIniFixture([
            'error_reporting = '.$testValue,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues($this->secureIniValues([
            'error_reporting' => (string) $testValue,
        ]));

        $result = $analyzer->analyze();

        // error_reporting checks are skipped in Laravel applications
        $this->assertPassed($result);
    }

    public function test_it_handles_missing_php_ini_path_gracefully(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => "APP_ENV=production\n",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath('/nonexistent/php.ini');
        $analyzer->setBasePath($tempDir);
        $analyzer->setIniValues($this->secureIniValues());

        $result = $analyzer->analyze();

        // When file doesn't exist but ini values are provided (mocked), it still passes
        // because it uses the mocked values via getIniValue()
        $this->assertPassed($result);
    }

    public function test_it_merges_custom_config_settings(): void
    {
        $iniPath = $this->createPhpIniFixture([
            'custom_setting = On',
        ]);

        config([
            'shieldci.analyzers.security.php-ini.php_configuration.secure_settings' => [
                'custom_setting' => false,
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues(array_merge($this->secureIniValues(), [
            'custom_setting' => '1',
        ]));

        $result = $analyzer->analyze();

        // Medium severity = Warning status
        $this->assertWarning($result);
        $this->assertHasIssueContaining('custom_setting', $result);
    }

    public function test_it_ignores_settings_in_comments(): void
    {
        $iniPath = $this->createPhpIniFixture([
            '; display_errors = On',
            '# expose_php = On',
            '// allow_url_fopen = On',
            'allow_url_fopen = Off',
            'expose_php = Off',
            'display_errors = Off',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues($this->secureIniValues());

        $result = $analyzer->analyze();

        // Should pass because actual settings (not comments) are secure
        $this->assertPassed($result);
    }

    public function test_it_finds_correct_line_for_settings_with_similar_names(): void
    {
        $iniPath = $this->createPhpIniFixture([
            '; This is a comment about display_errors',
            'display_errors = Off',
            'display_startup_errors = Off',
            '; Another comment mentioning display_errors',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues($this->secureIniValues());

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @param  array<int, string>  $lines
     */
    private function createPhpIniFixture(array $lines): string
    {
        $tempDir = $this->createTempDirectory([
            '.env' => "APP_ENV=production\n",
            'php.ini' => implode(PHP_EOL, $lines),
        ]);

        return $tempDir.'/php.ini';
    }

    public function test_it_detects_setting_defined_in_main_php_ini(): void
    {
        $iniPath = $this->createPhpIniFixture([
            'allow_url_fopen = On',
            'expose_php = Off',
            'display_errors = Off',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues(array_merge($this->secureIniValues(), [
            'allow_url_fopen' => '1',
        ]));

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        // Find the allow_url_fopen issue
        $allowUrlFopenIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'allow_url_fopen')) {
                $allowUrlFopenIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($allowUrlFopenIssue, 'Should have an issue for allow_url_fopen');

        // Check that it points to php.ini
        $this->assertNotNull($allowUrlFopenIssue->location);
        $this->assertStringContainsString('php.ini', $allowUrlFopenIssue->location->file);

        // Check that recommendation mentions the file
        $this->assertStringContainsString('php.ini', $allowUrlFopenIssue->recommendation);

        // Check metadata includes actual source
        $this->assertArrayHasKey('actual_source', $allowUrlFopenIssue->metadata);
        $this->assertNotNull($allowUrlFopenIssue->metadata['actual_source']);
        $this->assertEquals('main_ini', $allowUrlFopenIssue->metadata['actual_source']['type']);
    }

    public function test_metadata_shows_when_setting_not_found_in_file(): void
    {
        // Create php.ini with only some settings, not all
        $tempDir = $this->createTempDirectory([
            '.env' => "APP_ENV=production\n",
            'php.ini' => "expose_php = Off\ndisplay_errors = Off\n",
        ]);

        $iniPath = $tempDir.'/php.ini';

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath($tempDir);
        // Runtime shows allow_url_fopen is enabled, but it's not defined in php.ini
        $analyzer->setIniValues(array_merge($this->secureIniValues(), [
            'allow_url_fopen' => '1',
        ]));

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        // Find the allow_url_fopen issue
        $allowUrlFopenIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'allow_url_fopen')) {
                $allowUrlFopenIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($allowUrlFopenIssue, 'Should have an issue for allow_url_fopen');

        // Primary assertion: metadata should show actual_source is null
        // (meaning the setting was not found in any .ini file)
        $this->assertArrayHasKey('actual_source', $allowUrlFopenIssue->metadata);
        $this->assertNull(
            $allowUrlFopenIssue->metadata['actual_source'],
            'actual_source should be null when setting is not defined in any .ini file'
        );

        // Check recommendation warns about unknown source
        $this->assertStringContainsString('WARNING', $allowUrlFopenIssue->recommendation);

        // Check metadata includes configuration sources
        $this->assertArrayHasKey('configuration_sources', $allowUrlFopenIssue->metadata);
    }

    public function test_it_includes_configuration_sources_in_metadata(): void
    {
        $iniPath = $this->createPhpIniFixture([
            'allow_url_fopen = On',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues(array_merge($this->secureIniValues(), [
            'allow_url_fopen' => '1',
        ]));

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        $this->assertGreaterThan(0, count($issues));

        // Check that all issues include configuration_sources metadata
        foreach ($issues as $issue) {
            $this->assertArrayHasKey('configuration_sources', $issue->metadata);
            $sources = $issue->metadata['configuration_sources'];

            $this->assertIsArray($sources);
            $this->assertArrayHasKey('main', $sources);
            $this->assertArrayHasKey('additional', $sources);
        }
    }

    public function test_it_points_to_correct_file_in_location(): void
    {
        $iniPath = $this->createPhpIniFixture([
            'allow_url_fopen = On',
            'expose_php = Off',
            'display_errors = Off',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues(array_merge($this->secureIniValues(), [
            'allow_url_fopen' => '1',
        ]));

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        $allowUrlFopenIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'allow_url_fopen')) {
                $allowUrlFopenIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($allowUrlFopenIssue);
        $this->assertNotNull($allowUrlFopenIssue->location);

        // Verify it points to the php.ini file
        $this->assertStringContainsString('php.ini', $allowUrlFopenIssue->location->file);

        // Verify line number is set (greater than 0)
        $this->assertGreaterThan(0, $allowUrlFopenIssue->location->line);

        // Verify actual source metadata is populated
        $this->assertArrayHasKey('actual_source', $allowUrlFopenIssue->metadata);
        $this->assertNotNull($allowUrlFopenIssue->metadata['actual_source']);
    }

    public function test_it_generates_clear_recommendations_for_main_ini(): void
    {
        $iniPath = $this->createPhpIniFixture([
            'allow_url_fopen = On',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues(array_merge($this->secureIniValues(), [
            'allow_url_fopen' => '1',
        ]));

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        $allowUrlFopenIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'allow_url_fopen')) {
                $allowUrlFopenIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($allowUrlFopenIssue);

        // Should tell user exactly what to do
        $this->assertStringContainsString('Set allow_url_fopen = Off', $allowUrlFopenIssue->recommendation);
        $this->assertStringContainsString('php.ini', $allowUrlFopenIssue->recommendation);
        $this->assertStringContainsString('main php.ini', $allowUrlFopenIssue->recommendation);
    }

    public function test_it_handles_enabled_settings_correctly(): void
    {
        $iniPath = $this->createPhpIniFixture([
            'log_errors = Off',  // Should be On
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues(array_merge($this->secureIniValues(), [
            'log_errors' => '0',
        ]));

        $result = $analyzer->analyze();

        // log_errors is Medium severity, so status is 'warning' not 'failed'
        $this->assertWarning($result);
        $issues = $result->getIssues();

        $logErrorsIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'log_errors')) {
                $logErrorsIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($logErrorsIssue);
        $this->assertStringContainsString('should be enabled', $logErrorsIssue->message);
        $this->assertStringContainsString('Set log_errors = On', $logErrorsIssue->recommendation);
    }

    public function test_it_detects_non_existent_settings(): void
    {
        $iniPath = $this->createPhpIniFixture([
            'expose_php = Off',
            'display_errors = Off',
            // NOTE: allow_url_fopen is intentionally NOT defined
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        // Simulate ini_get() returning false for non-existent setting
        $analyzer->setIniValues([
            'allow_url_fopen' => false,  // Non-existent
            'expose_php' => '0',
            'display_errors' => '0',
            'log_errors' => '1',
            'allow_url_include' => '0',
            'display_startup_errors' => '0',
            'ignore_repeated_errors' => '0',
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        // Find the allow_url_fopen issue
        $allowUrlFopenIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'allow_url_fopen')) {
                $allowUrlFopenIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($allowUrlFopenIssue, 'Should detect non-existent setting');

        // Should clearly indicate the setting doesn't exist
        $this->assertStringContainsString('not configured', $allowUrlFopenIssue->message);
        $this->assertStringContainsString('does not exist', $allowUrlFopenIssue->message);

        // Metadata should indicate missing setting
        $this->assertArrayHasKey('issue_type', $allowUrlFopenIssue->metadata);
        $this->assertEquals('missing_setting', $allowUrlFopenIssue->metadata['issue_type']);
        $this->assertEquals('not_configured', $allowUrlFopenIssue->metadata['current_value']);
    }

    public function test_it_detects_ambiguous_empty_string_values(): void
    {
        $iniPath = $this->createPhpIniFixture([
            'allow_url_fopen = ',  // Empty value - ambiguous!
            'expose_php = Off',
            'display_errors = Off',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues(array_merge($this->secureIniValues(), [
            'allow_url_fopen' => '',  // Empty string - ambiguous
        ]));

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        // Find the allow_url_fopen issue
        $allowUrlFopenIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'allow_url_fopen')) {
                $allowUrlFopenIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($allowUrlFopenIssue, 'Should detect ambiguous empty value');

        // Should clearly indicate the value is ambiguous
        $this->assertStringContainsString('empty string', $allowUrlFopenIssue->message);
        $this->assertStringContainsString('ambiguous', $allowUrlFopenIssue->message);

        // Metadata should indicate ambiguous value
        $this->assertArrayHasKey('issue_type', $allowUrlFopenIssue->metadata);
        $this->assertEquals('ambiguous_value', $allowUrlFopenIssue->metadata['issue_type']);
        $this->assertEquals('', $allowUrlFopenIssue->metadata['current_value']);
    }

    public function test_it_distinguishes_between_zero_and_empty(): void
    {
        $iniPath = $this->createPhpIniFixture([
            'allow_url_fopen = 0',  // Explicitly disabled
            'allow_url_include = ',  // Empty - ambiguous
            'expose_php = Off',
            'display_errors = Off',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues([
            'allow_url_fopen' => '0',  // Explicitly '0'
            'allow_url_include' => '',  // Empty string
            'expose_php' => '0',
            'display_errors' => '0',
            'display_startup_errors' => '0',
            'log_errors' => '1',
            'ignore_repeated_errors' => '0',
        ]);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();

        // allow_url_fopen should NOT have an issue (correctly disabled with '0')
        $hasAllowUrlFopenIssue = false;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'allow_url_fopen')) {
                $hasAllowUrlFopenIssue = true;
                break;
            }
        }
        $this->assertFalse($hasAllowUrlFopenIssue, 'allow_url_fopen = 0 should be valid (not ambiguous)');

        // allow_url_include SHOULD have an issue (ambiguous empty string)
        $allowUrlIncludeIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'allow_url_include')) {
                $allowUrlIncludeIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($allowUrlIncludeIssue, 'Empty string should be flagged as ambiguous');
        $this->assertStringContainsString('ambiguous', $allowUrlIncludeIssue->message);
    }

    public function test_it_handles_false_vs_zero_correctly(): void
    {
        $iniPath = $this->createPhpIniFixture([
            'expose_php = 0',
            'display_errors = 0',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        $analyzer->setIniValues([
            'allow_url_fopen' => false,  // ini_get() returned false (doesn't exist)
            'allow_url_include' => '0',  // Explicitly set to '0'
            'expose_php' => '0',
            'display_errors' => '0',
            'display_startup_errors' => '0',
            'log_errors' => '1',
            'ignore_repeated_errors' => '0',
        ]);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();

        // allow_url_fopen should have "not configured" issue
        $allowUrlFopenIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'allow_url_fopen')) {
                $allowUrlFopenIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($allowUrlFopenIssue);
        $this->assertStringContainsString('not configured', $allowUrlFopenIssue->message);
        $this->assertEquals('missing_setting', $allowUrlFopenIssue->metadata['issue_type']);

        // allow_url_include should NOT have an issue (properly disabled with '0')
        $hasAllowUrlIncludeIssue = false;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'allow_url_include')) {
                $hasAllowUrlIncludeIssue = true;
                break;
            }
        }
        $this->assertFalse($hasAllowUrlIncludeIssue, 'allow_url_include = 0 should be valid');
    }

    // ── Vapor / Serverless Tests ──────────────────────────────────────

    public function test_vapor_platform_adjusts_recommendations(): void
    {
        $tempDir = $this->createVaporFixture(
            iniLines: ['display_errors = On'],
        );

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($tempDir.'/php.ini');
        $analyzer->setBasePath($tempDir);
        $analyzer->setDeploymentPlatform('vapor');
        $analyzer->setIniValues($this->secureIniValues([
            'display_errors' => '1',
        ]));

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        $displayErrorsIssue = $this->findIssueContaining('display_errors', $issues);
        $this->assertNotNull($displayErrorsIssue, 'Should have an issue for display_errors');

        // Vapor recommendation should point to project conf.d, not system php.ini
        $this->assertStringContainsString('php/conf.d/php.ini', $displayErrorsIssue->recommendation);
        $this->assertStringContainsString('Laravel Vapor', $displayErrorsIssue->recommendation);
        $this->assertStringNotContainsString('WARNING', $displayErrorsIssue->recommendation);
    }

    public function test_traditional_platform_keeps_existing_recommendations(): void
    {
        $iniPath = $this->createPhpIniFixture([
            'display_errors = On',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($iniPath);
        $analyzer->setBasePath(dirname($iniPath));
        // No setDeploymentPlatform() — traditional platform
        $analyzer->setIniValues($this->secureIniValues([
            'display_errors' => '1',
        ]));

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        $displayErrorsIssue = $this->findIssueContaining('display_errors', $issues);
        $this->assertNotNull($displayErrorsIssue);

        // Traditional recommendations should mention main php.ini
        $this->assertStringContainsString('main php.ini', $displayErrorsIssue->recommendation);
        $this->assertStringNotContainsString('Laravel Vapor', $displayErrorsIssue->recommendation);
    }

    public function test_vapor_checks_project_conf_d_for_settings(): void
    {
        $tempDir = $this->createVaporFixture(
            iniLines: ['expose_php = Off'],
            confDLines: ['display_errors = On'],
        );

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($tempDir.'/php.ini');
        $analyzer->setBasePath($tempDir);
        $analyzer->setDeploymentPlatform('vapor');
        $analyzer->setIniValues($this->secureIniValues([
            'display_errors' => '1',
        ]));

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        $displayErrorsIssue = $this->findIssueContaining('display_errors', $issues);
        $this->assertNotNull($displayErrorsIssue, 'Should detect display_errors from project conf.d');

        // Should find it in the project conf.d file and note it as project override
        $this->assertStringContainsString('project override for Laravel Vapor', $displayErrorsIssue->recommendation);

        // Metadata should show the conf.d file as actual source
        $this->assertNotNull($displayErrorsIssue->metadata['actual_source']);
        $actualSource = $displayErrorsIssue->metadata['actual_source'];
        $this->assertIsArray($actualSource);
        /** @var array{file: string, type: string, line: int} $actualSource */
        $this->assertStringContainsString(
            'php/conf.d/php.ini',
            $actualSource['file']
        );
    }

    public function test_vapor_recommendation_when_setting_not_in_any_file(): void
    {
        $tempDir = $this->createVaporFixture(
            iniLines: ['expose_php = Off'],
        );

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($tempDir.'/php.ini');
        $analyzer->setBasePath($tempDir);
        $analyzer->setDeploymentPlatform('vapor');
        // allow_url_fopen is enabled at runtime but not defined in any file
        $analyzer->setIniValues($this->secureIniValues([
            'allow_url_fopen' => '1',
        ]));

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        $allowUrlFopenIssue = $this->findIssueContaining('allow_url_fopen', $issues);
        $this->assertNotNull($allowUrlFopenIssue, 'Should have an issue for allow_url_fopen');

        // Vapor: should recommend project conf.d, NOT show WARNING about htaccess/nginx
        $this->assertStringContainsString('php/conf.d/php.ini', $allowUrlFopenIssue->recommendation);
        $this->assertStringContainsString('read-only on Laravel Vapor', $allowUrlFopenIssue->recommendation);
        $this->assertStringContainsString('Redeploy', $allowUrlFopenIssue->recommendation);
        $this->assertStringNotContainsString('WARNING', $allowUrlFopenIssue->recommendation);
    }

    public function test_deployment_platform_included_in_metadata(): void
    {
        $tempDir = $this->createVaporFixture(
            iniLines: ['display_errors = On'],
        );

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($tempDir.'/php.ini');
        $analyzer->setBasePath($tempDir);
        $analyzer->setDeploymentPlatform('vapor');
        $analyzer->setIniValues($this->secureIniValues([
            'display_errors' => '1',
        ]));

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));

        foreach ($issues as $issue) {
            $this->assertArrayHasKey('deployment_platform', $issue->metadata);
            $this->assertEquals('vapor', $issue->metadata['deployment_platform']);
        }
    }

    public function test_vapor_passes_when_all_settings_secure(): void
    {
        $tempDir = $this->createVaporFixture(
            iniLines: [
                'allow_url_fopen = Off',
                'allow_url_include = Off',
                'expose_php = Off',
                'display_errors = Off',
                'display_startup_errors = Off',
                'log_errors = On',
                'ignore_repeated_errors = Off',
            ],
        );

        $analyzer = $this->createAnalyzer();
        $analyzer->setPhpIniPath($tempDir.'/php.ini');
        $analyzer->setBasePath($tempDir);
        $analyzer->setDeploymentPlatform('vapor');
        $analyzer->setIniValues($this->secureIniValues());

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertIssueCount(0, $result);
    }

    // ── Helpers ─────────────────────────────────────────────────────

    /**
     * Find an issue whose message contains a given string.
     *
     * @param  array<int, Issue>  $issues
     */
    private function findIssueContaining(string $needle, array $issues): ?Issue
    {
        foreach ($issues as $issue) {
            if (str_contains($issue->message, $needle)) {
                return $issue;
            }
        }

        return null;
    }

    /**
     * Create a temp directory simulating a Vapor project.
     *
     * @param  array<int, string>  $iniLines  Lines for the main php.ini
     * @param  array<int, string>  $confDLines  Lines for php/conf.d/php.ini (if provided)
     */
    private function createVaporFixture(array $iniLines, array $confDLines = []): string
    {
        $files = [
            '.env' => "APP_ENV=production\n",
            'php.ini' => implode(PHP_EOL, $iniLines),
            'vapor.yml' => "id: 12345\nname: my-app\n",
        ];

        if ($confDLines !== []) {
            $files['php/conf.d/php.ini'] = implode(PHP_EOL, $confDLines);
        }

        return $this->createTempDirectory($files);
    }

    /**
     * @param  array<string, string>  $overrides
     * @return array<string, string>
     */
    private function secureIniValues(array $overrides = []): array
    {
        $base = [
            'allow_url_fopen' => '0',
            'allow_url_include' => '0',
            'expose_php' => '0',
            'display_errors' => '0',
            'display_startup_errors' => '0',
            'log_errors' => '1',
            'ignore_repeated_errors' => '0',
            'disable_functions' => 'exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source',
            'open_basedir' => '/var/www/html',
            'error_reporting' => (string) (E_ALL & ~E_STRICT & ~E_DEPRECATED & ~E_NOTICE),
        ];

        return array_merge($base, $overrides);
    }
}
