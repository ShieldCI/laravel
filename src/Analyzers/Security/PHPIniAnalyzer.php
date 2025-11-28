<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
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

    /**
     * Default secure values for php.ini directives.
     *
     * @var array<string, bool>
     */
    private array $defaultSecureSettings = [
        'allow_url_fopen' => false,
        'allow_url_include' => false,
        'expose_php' => false,
        'display_errors' => false,
        'display_startup_errors' => false,
        'log_errors' => true,
        'ignore_repeated_errors' => false,
    ];

    /**
     * Default list of dangerous functions that should be disabled.
     *
     * @var array<int, string>
     */
    private array $defaultDangerousFunctions = [
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

    /**
     * @var array<string, string|int|bool>|null
     */
    private ?array $iniValueOverrides = null;

    /**
     * @var array<int, string>|null
     */
    private ?array $dangerousFunctionsOverride = null;

    private ?string $phpIniPathOverride = null;

    private ?string $cachedPhpIniPath = null;

    /** @var array<int, string>|null */
    private ?array $phpIniLinesCache = null;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'php-ini-security',
            name: 'PHP Configuration Security Analyzer',
            description: 'Validates that PHP ini settings are configured securely',
            category: Category::Security,
            severity: Severity::High,
            tags: ['php', 'configuration', 'ini', 'security', 'server'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/php-ini-security',
            timeToFix: 15
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
        $phpIniPath = $this->getPhpIniPath();
        $configuration = $this->getConfiguration();

        // Check PHP ini settings
        $this->checkPhpIniSettings($issues, $phpIniPath, $configuration['secure_settings']);

        // Check for insecure functions enabled
        $this->checkDisabledFunctions($issues, $phpIniPath, $configuration['dangerous_functions']);

        // Check open_basedir
        $this->checkOpenBasedir($issues, $phpIniPath);

        // Check error_reporting verbosity
        $this->checkErrorReporting($issues, $phpIniPath, $configuration['error_reporting']);

        if (empty($issues)) {
            return $this->passed('PHP configuration is secure');
        }

        return $this->resultBySeverity(
            sprintf('Found %d PHP configuration issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Check PHP ini settings.
     */
    /**
     * @param  array<int, Issue>  $issues
     * @param  array<string, bool>  $secureSettings
     */
    private function checkPhpIniSettings(array &$issues, string $phpIniPath, array $secureSettings): void
    {
        foreach ($secureSettings as $setting => $expectedValue) {
            $currentValue = $this->getIniValue($setting);

            // Normalize values
            $normalized = strtolower($currentValue);
            $isEnabled = in_array($normalized, ['1', 'on', 'yes', 'true'], true);
            $isDisabled = in_array($normalized, ['0', 'off', '', 'no', 'false'], true);

            $expected = $expectedValue ? 'enabled' : 'disabled';
            $actual = $isEnabled ? 'enabled' : ($isDisabled ? 'disabled' : $currentValue);

            $line = $this->getSettingLine($phpIniPath, $setting);
            $snippet = FileParser::getCodeSnippet($phpIniPath, $line);

            // Check if current value matches expected
            if ($expectedValue && ! $isEnabled) {
                $issues[] = $this->createIssue(
                    message: sprintf('PHP ini setting "%s" should be enabled but is %s', $setting, $actual),
                    location: new Location($phpIniPath, $line),
                    severity: $this->getSeverityForSetting($setting),
                    recommendation: sprintf('Set %s = On in php.ini', $setting),
                    code: $snippet,
                    metadata: [
                        'setting' => $setting,
                        'current_value' => $currentValue,
                        'expected_value' => $expected,
                    ]
                );
            } elseif (! $expectedValue && $isEnabled) {
                $issues[] = $this->createIssue(
                    message: sprintf('PHP ini setting "%s" should be disabled but is %s', $setting, $actual),
                    location: new Location($phpIniPath, $line),
                    severity: $this->getSeverityForSetting($setting),
                    recommendation: sprintf('Set %s = Off in php.ini', $setting),
                    code: $snippet,
                    metadata: [
                        'setting' => $setting,
                        'current_value' => $currentValue,
                        'expected_value' => $expected,
                    ]
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
     * @param  array<Issue>  $issues
     * @param  array<int, string>  $dangerousFunctions
     */
    private function checkDisabledFunctions(array &$issues, string $phpIniPath, array $dangerousFunctions): void
    {
        $disabledFunctions = $this->getIniValue('disable_functions');
        $line = $this->getSettingLine($phpIniPath, 'disable_functions');
        $snippet = FileParser::getCodeSnippet($phpIniPath, $line);

        if (empty($disabledFunctions)) {
            $issues[] = $this->createIssue(
                message: 'No dangerous PHP functions are disabled',
                location: new Location($phpIniPath, $line),
                severity: Severity::Medium,
                recommendation: sprintf(
                    'Consider disabling dangerous functions in php.ini: disable_functions = %s',
                    implode(',', $dangerousFunctions)
                ),
                code: $snippet,
                metadata: [
                    'dangerous_functions' => $dangerousFunctions,
                    'current_value' => $disabledFunctions,
                ]
            );
        } else {
            // Check which dangerous functions are still enabled
            $disabledList = array_map('trim', explode(',', $disabledFunctions));
            $enabledDangerous = array_diff($dangerousFunctions, $disabledList);

            if (! empty($enabledDangerous)) {
                $examples = array_slice(array_values($enabledDangerous), 0, 3);
                $displayExamples = array_slice(array_values($enabledDangerous), 0, 5);

                $issues[] = $this->createIssue(
                    message: sprintf(
                        '%d potentially dangerous PHP functions are still enabled',
                        count($enabledDangerous)
                    ),
                    location: new Location($phpIniPath, $line),
                    severity: Severity::Medium,
                    recommendation: sprintf(
                        'Update disable_functions to include: %s',
                        implode(', ', $examples)
                    ),
                    code: $snippet,
                    metadata: [
                        'enabled_count' => count($enabledDangerous),
                        'examples' => $displayExamples,
                        'enabled_dangerous_functions' => array_values($enabledDangerous),
                        'current_value' => $disabledFunctions,
                    ]
                );
            }
        }
    }

    /**
     * Check open_basedir restriction.
     */
    private function checkOpenBasedir(array &$issues, string $phpIniPath): void
    {
        $openBasedir = $this->getIniValue('open_basedir');

        if ($openBasedir === '') {
            $line = $this->getSettingLine($phpIniPath, 'open_basedir');
            $issues[] = $this->createIssue(
                message: 'open_basedir restriction is not configured',
                location: new Location($phpIniPath, $line),
                severity: Severity::Medium,
                recommendation: 'Consider setting open_basedir to restrict file access to specific directories',
                code: FileParser::getCodeSnippet($phpIniPath, $line),
                metadata: [
                    'current_value' => $openBasedir,
                ]
            );
        }
    }

    /**
     * Check error_reporting verbosity.
     *
     * @param  array<string, mixed>  $errorConfig
     */
    private function checkErrorReporting(array &$issues, string $phpIniPath, array $errorConfig): void
    {
        $value = $this->getIniValueInt('error_reporting');

        if ($value === null) {
            return;
        }

        $line = $this->getSettingLine($phpIniPath, 'error_reporting');
        $snippet = FileParser::getCodeSnippet($phpIniPath, $line);

        $disallowedRaw = $errorConfig['disallowed_values'] ?? [];
        $disallowedValues = array_map(
            static function (mixed $value): int {
                if (is_int($value)) {
                    return $value;
                }

                if (is_string($value)) {
                    if (is_numeric($value)) {
                        return (int) $value;
                    }

                    if ($value !== '' && defined($value)) {
                        $constant = constant($value);
                        if (is_int($constant)) {
                            return $constant;
                        }
                    }
                }

                return 0;
            },
            is_array($disallowedRaw) ? $disallowedRaw : []
        );
        if (! empty($disallowedValues) && in_array($value, $disallowedValues, true)) {
            $issues[] = $this->createIssue(
                message: 'error_reporting is too verbose for production environments',
                location: new Location($phpIniPath, $line),
                severity: Severity::Medium,
                recommendation: 'Adjust error_reporting to exclude verbose levels (e.g., use E_ALL & ~E_DEPRECATED & ~E_STRICT).',
                code: $snippet,
                metadata: [
                    'current_value' => $value,
                ]
            );

            return;
        }

        $resolvedFlags = $this->resolveErrorReportingFlags(
            is_array($errorConfig['forbidden_flags'] ?? null)
                ? $errorConfig['forbidden_flags']
                : []
        );
        if (empty($resolvedFlags)) {
            return;
        }

        $offendingFlags = [];
        foreach ($resolvedFlags as $name => $flagValue) {
            if (($value & $flagValue) === $flagValue) {
                $offendingFlags[] = $name;
            }
        }

        if (! empty($offendingFlags)) {
            $issues[] = $this->createIssue(
                message: sprintf('error_reporting includes verbose flags: %s', implode(', ', $offendingFlags)),
                location: new Location($phpIniPath, $line),
                severity: Severity::Medium,
                recommendation: 'Remove verbose error_reporting flags in production environments.',
                code: $snippet,
                metadata: [
                    'current_value' => $value,
                    'offending_flags' => $offendingFlags,
                ]
            );
        }
    }

    /**
     * Provide overrides for ini values (testing only).
     *
     * @param  array<string, string|int|bool>  $values
     */
    public function setIniValues(array $values): void
    {
        $this->iniValueOverrides = $values;
    }

    /**
     * Provide custom dangerous functions list (testing only).
     *
     * @param  array<int, string>  $functions
     */
    public function setDangerousFunctions(array $functions): void
    {
        $this->dangerousFunctionsOverride = $functions;
    }

    public function setPhpIniPath(string $phpIniPath): void
    {
        $this->phpIniPathOverride = $phpIniPath;
        $this->cachedPhpIniPath = null;
        $this->phpIniLinesCache = null;
    }

    /**
     * @return array{
     *     ini_path: string|null,
     *     secure_settings: array<string, bool>,
     *     dangerous_functions: array<int, string>,
     *     error_reporting: array{
     *         disallowed_values: array<int>,
     *         forbidden_flags: array<int|string>
     *     }
     * }
     */
    private function getConfiguration(): array
    {
        $defaults = [
            'ini_path' => null,
            'secure_settings' => $this->defaultSecureSettings,
            'dangerous_functions' => $this->dangerousFunctionsOverride ?? $this->defaultDangerousFunctions,
            'error_reporting' => [
                'disallowed_values' => [E_ALL, -1],
                'forbidden_flags' => ['E_STRICT', 'E_DEPRECATED'],
            ],
        ];

        if (function_exists('config')) {
            $config = config('shieldci.php_configuration', []);
            if (is_array($config)) {
                /** @var array{ini_path?: string|null, secure_settings?: array<string, bool>, dangerous_functions?: array<int, string>, error_reporting?: array{disallowed_values?: array<int>, forbidden_flags?: array<int|string>}} $config */
                $merged = array_replace_recursive($defaults, $config);
                $merged['dangerous_functions'] = $this->dangerousFunctionsOverride ?? $merged['dangerous_functions'];

                return [
                    'ini_path' => $merged['ini_path'],
                    'secure_settings' => $merged['secure_settings'],
                    'dangerous_functions' => array_values($merged['dangerous_functions']),
                    'error_reporting' => [
                        'disallowed_values' => array_values($merged['error_reporting']['disallowed_values']),
                        'forbidden_flags' => array_values($merged['error_reporting']['forbidden_flags']),
                    ],
                ];
            }
        }

        $defaults['dangerous_functions'] = $this->dangerousFunctionsOverride ?? $defaults['dangerous_functions'];

        return [
            'ini_path' => $defaults['ini_path'],
            'secure_settings' => $defaults['secure_settings'],
            'dangerous_functions' => array_values($defaults['dangerous_functions']),
            'error_reporting' => [
                'disallowed_values' => array_values($defaults['error_reporting']['disallowed_values']),
                'forbidden_flags' => array_values($defaults['error_reporting']['forbidden_flags']),
            ],
        ];
    }

    private function getPhpIniPath(): string
    {
        if (is_string($this->phpIniPathOverride) && $this->phpIniPathOverride !== '') {
            return $this->phpIniPathOverride;
        }

        $configPath = null;
        if (function_exists('config')) {
            $configPath = config('shieldci.php_configuration.ini_path');
        }

        if (is_string($configPath) && $configPath !== '') {
            return $configPath;
        }

        $phpIniPath = php_ini_loaded_file();

        return $phpIniPath !== false && is_string($phpIniPath) ? $phpIniPath : 'php.ini';
    }

    private function getIniValue(string $setting): string
    {
        if (is_array($this->iniValueOverrides) && array_key_exists($setting, $this->iniValueOverrides)) {
            return $this->normalizeIniValue($this->iniValueOverrides[$setting]);
        }

        $value = ini_get($setting);

        return $this->normalizeIniValue($value);
    }

    private function getIniValueInt(string $setting): ?int
    {
        $value = $this->getIniValue($setting);

        if ($value === '') {
            return null;
        }

        if (is_numeric($value)) {
            return (int) $value;
        }

        if (defined($value)) {
            $constantValue = constant($value);
            if (is_int($constantValue)) {
                return $constantValue;
            }
        }

        return null;
    }

    /**
     * @param  array<int|string, int|string>  $flags
     * @return array<string, int>
     */
    private function resolveErrorReportingFlags(array $flags): array
    {
        /** @var array<string, int> $resolved */
        $resolved = [];

        foreach ($flags as $flag) {
            if (is_string($flag) && defined($flag)) {
                $value = constant($flag);
                if (is_int($value)) {
                    $resolved[$flag] = $value;
                }

                continue;
            }

            if (is_int($flag)) {
                $resolved['flag_'.$flag] = $flag;
            }
        }

        return $resolved;
    }

    private function normalizeIniValue(mixed $value): string
    {
        if (is_string($value)) {
            return trim($value);
        }

        if (is_bool($value)) {
            return $value ? '1' : '0';
        }

        if (is_scalar($value)) {
            return trim((string) $value);
        }

        return '';
    }

    private function getSettingLine(string $phpIniPath, string $setting): int
    {
        $lines = $this->getPhpIniLines($phpIniPath);

        foreach ($lines as $index => $line) {
            if (is_string($line) && stripos($line, $setting) !== false) {
                return $index + 1;
            }
        }

        return 1;
    }

    /**
     * @return array<int, string>
     */
    private function getPhpIniLines(string $phpIniPath): array
    {
        if ($this->cachedPhpIniPath !== $phpIniPath) {
            $this->phpIniLinesCache = null;
            $this->cachedPhpIniPath = $phpIniPath;
        }

        if ($this->phpIniLinesCache === null) {
            $this->phpIniLinesCache = FileParser::getLines($phpIniPath);
        }

        return $this->phpIniLinesCache ?? [];
    }
}
