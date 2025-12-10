<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\PHPIniAnalyzer;
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
            'shieldci.php_configuration.secure_settings' => [
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
