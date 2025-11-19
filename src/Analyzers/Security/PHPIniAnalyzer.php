<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Validates PHP configuration (php.ini) security settings.
 *
 * Checks for:
 * - allow_url_fopen disabled
 * - allow_url_include disabled
 * - expose_php disabled
 * - display_errors disabled in production
 * - log_errors enabled
 * - Proper error reporting settings
 */
class PHPIniAnalyzer extends AbstractFileAnalyzer
{
    /**
     * PHP ini settings checks are environment-specific and not applicable in CI.
     */
    public static bool $runInCI = false;

    /**
     * This analyzer is only relevant in production and staging environments.
     *
     * In local/development, developers may have different PHP ini settings
     * for debugging purposes, which is acceptable.
     *
     * @var array<string>
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    private array $secureSettings = [
        'allow_url_fopen' => false,
        'allow_url_include' => false,
        'expose_php' => false,
        'display_errors' => false,
        'display_startup_errors' => false,
        'log_errors' => true,
        'ignore_repeated_errors' => false,
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'php-ini-security',
            name: 'PHP Configuration Security Analyzer',
            description: 'Validates that PHP ini settings are configured securely',
            category: Category::Security,
            severity: Severity::High,
            tags: ['php', 'configuration', 'ini', 'security', 'server'],
            docsUrl: 'https://www.php.net/manual/en/ini.list.php'
        );
    }

    public function shouldRun(): bool
    {
        return $this->isRelevantForCurrentEnvironment();
    }

    public function getSkipReason(): string
    {
        if (! $this->isRelevantForCurrentEnvironment()) {
            $currentEnv = $this->getEnvironment();
            $relevantEnvs = implode(', ', $this->relevantEnvironments ?? []);

            return "Not relevant in '{$currentEnv}' environment (only relevant in: {$relevantEnvs})";
        }

        return 'Analyzer is not applicable in current context';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check PHP ini settings
        $this->checkPhpIniSettings($issues);

        // Check for insecure functions enabled
        $this->checkDisabledFunctions($issues);

        // Check open_basedir
        $this->checkOpenBasedir($issues);

        if (empty($issues)) {
            return $this->passed('PHP configuration is secure');
        }

        return $this->failed(
            sprintf('Found %d PHP configuration security issues', count($issues)),
            $issues
        );
    }

    /**
     * Check PHP ini settings.
     */
    private function checkPhpIniSettings(array &$issues): void
    {
        foreach ($this->secureSettings as $setting => $expectedValue) {
            $currentValue = ini_get($setting);

            // Normalize values
            $isEnabled = in_array(strtolower($currentValue), ['1', 'on', 'yes', 'true']);
            $isDisabled = in_array(strtolower($currentValue), ['0', 'off', '', 'no', 'false']);

            $expected = $expectedValue ? 'enabled' : 'disabled';
            $actual = $isEnabled ? 'enabled' : ($isDisabled ? 'disabled' : $currentValue);

            // Check if current value matches expected
            if ($expectedValue && ! $isEnabled) {
                $issues[] = $this->createIssue(
                    message: sprintf('PHP ini setting "%s" should be enabled but is %s', $setting, $actual),
                    location: new Location(
                        'php.ini',
                        1
                    ),
                    severity: $this->getSeverityForSetting($setting),
                    recommendation: sprintf('Set %s = On in php.ini', $setting),
                    code: sprintf('%s = %s (should be On)', $setting, $actual)
                );
            } elseif (! $expectedValue && $isEnabled) {
                $issues[] = $this->createIssue(
                    message: sprintf('PHP ini setting "%s" should be disabled but is %s', $setting, $actual),
                    location: new Location(
                        'php.ini',
                        1
                    ),
                    severity: $this->getSeverityForSetting($setting),
                    recommendation: sprintf('Set %s = Off in php.ini', $setting),
                    code: sprintf('%s = %s (should be Off)', $setting, $actual)
                );
            }
        }
    }

    /**
     * Get severity level for specific PHP ini setting.
     */
    private function getSeverityForSetting(string $setting): Severity
    {
        $criticalSettings = ['allow_url_include', 'expose_php'];
        $highSettings = ['allow_url_fopen', 'display_errors', 'display_startup_errors'];

        if (in_array($setting, $criticalSettings)) {
            return Severity::Critical;
        }

        if (in_array($setting, $highSettings)) {
            return Severity::High;
        }

        return Severity::Medium;
    }

    /**
     * Check for disabled dangerous functions.
     *
     * @param  array<\ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function checkDisabledFunctions(array &$issues): void
    {
        $disabledFunctions = ini_get('disable_functions');

        // Dangerous functions that should ideally be disabled
        $dangerousFunctions = [
            'exec',
            'passthru',
            'shell_exec',
            'system',
            'proc_open',
            'popen',
            'curl_exec',
            'curl_multi_exec',
            'parse_ini_file',
            'show_source',
        ];

        if (empty($disabledFunctions)) {
            $issues[] = $this->createIssue(
                message: 'No dangerous PHP functions are disabled',
                location: new Location(
                    'php.ini',
                    1
                ),
                severity: Severity::Medium,
                recommendation: sprintf(
                    'Consider disabling dangerous functions in php.ini: disable_functions = %s',
                    implode(',', $dangerousFunctions)
                ),
                code: 'disable_functions = (empty)'
            );
        } else {
            // Check which dangerous functions are still enabled
            $disabledList = array_map('trim', explode(',', $disabledFunctions));
            $enabledDangerous = array_diff($dangerousFunctions, $disabledList);

            if (! empty($enabledDangerous) && count($enabledDangerous) > 5) {
                $issues[] = $this->createIssue(
                    message: sprintf(
                        '%d potentially dangerous PHP functions are still enabled',
                        count($enabledDangerous)
                    ),
                    location: new Location(
                        'php.ini',
                        1
                    ),
                    severity: Severity::Low,
                    recommendation: sprintf(
                        'Consider disabling: %s',
                        implode(', ', array_slice($enabledDangerous, 0, 5))
                    ),
                    code: sprintf('Enabled: %s', implode(', ', array_slice($enabledDangerous, 0, 3)))
                );
            }
        }
    }

    /**
     * Check open_basedir restriction.
     */
    private function checkOpenBasedir(array &$issues): void
    {
        $openBasedir = ini_get('open_basedir');

        if (empty($openBasedir)) {
            $issues[] = $this->createIssue(
                message: 'open_basedir restriction is not configured',
                location: new Location(
                    'php.ini',
                    1
                ),
                severity: Severity::Low,
                recommendation: 'Consider setting open_basedir to restrict file access to specific directories',
                code: 'open_basedir = (not set)'
            );
        }
    }
}
