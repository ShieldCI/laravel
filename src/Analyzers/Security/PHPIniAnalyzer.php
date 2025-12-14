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
     * @var array<string, string|int|bool>|null
     */
    private ?array $iniValueOverrides = null;

    private ?string $phpIniPathOverride = null;

    private ?string $cachedPhpIniPath = null;

    /** @var array<int, string>|null */
    private ?array $phpIniLinesCache = null;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'php-ini',
            name: 'PHP Configuration Analyzer',
            description: 'Validates that PHP ini settings are configured securely',
            category: Category::Security,
            severity: Severity::High,
            tags: ['php', 'configuration', 'ini', 'security', 'server'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/php-ini',
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

            // Check if current value matches expected
            if ($expectedValue && ! $isEnabled) {
                $issues[] = $this->createPhpIniIssue(
                    phpIniPath: $phpIniPath,
                    setting: $setting,
                    message: sprintf('PHP ini setting "%s" should be enabled but is %s', $setting, $actual),
                    recommendation: sprintf('Set %s = On in php.ini', $setting),
                    severity: $this->getSeverityForSetting($setting),
                    metadata: [
                        'setting' => $setting,
                        'current_value' => $currentValue,
                        'expected_value' => $expected,
                    ]
                );
            } elseif (! $expectedValue && $isEnabled) {
                $issues[] = $this->createPhpIniIssue(
                    phpIniPath: $phpIniPath,
                    setting: $setting,
                    message: sprintf('PHP ini setting "%s" should be disabled but is %s', $setting, $actual),
                    recommendation: sprintf('Set %s = Off in php.ini', $setting),
                    severity: $this->getSeverityForSetting($setting),
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
     * Provide overrides for ini values (testing only).
     *
     * @param  array<string, string|int|bool>  $values
     */
    public function setIniValues(array $values): void
    {
        $this->iniValueOverrides = $values;
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
     *     secure_settings: array<string, bool>
     * }
     */
    private function getConfiguration(): array
    {
        $defaults = [
            'ini_path' => null,
            'secure_settings' => $this->defaultSecureSettings,
        ];

        if (function_exists('config')) {
            $config = config('shieldci.php_configuration', []);
            if (is_array($config)) {
                /** @var array{ini_path?: string|null, secure_settings?: array<string, bool>} $config */
                $merged = array_replace_recursive($defaults, $config);

                return [
                    'ini_path' => $merged['ini_path'],
                    'secure_settings' => $merged['secure_settings'],
                ];
            }
        }

        return [
            'ini_path' => $defaults['ini_path'],
            'secure_settings' => $defaults['secure_settings'],
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

    /**
     * Create an issue for a PHP ini setting with automatic location and code snippet.
     *
     * @param  array<string, mixed>  $metadata
     */
    private function createPhpIniIssue(
        string $phpIniPath,
        string $setting,
        string $message,
        string $recommendation,
        Severity $severity,
        array $metadata = []
    ): Issue {
        $line = $this->getSettingLine($phpIniPath, $setting);

        return $this->createIssue(
            message: $message,
            location: new Location($phpIniPath, $line),
            severity: $severity,
            recommendation: $recommendation,
            code: FileParser::getCodeSnippet($phpIniPath, $line),
            metadata: $metadata
        );
    }

    private function getSettingLine(string $phpIniPath, string $setting): int
    {
        $lines = $this->getPhpIniLines($phpIniPath);
        $commentedLine = null;

        foreach ($lines as $index => $line) {
            if (! is_string($line)) {
                continue;
            }

            // First, check for active (uncommented) settings
            $lineWithoutComments = preg_replace('/[;#].*$/', '', $line);
            $lineWithoutComments = preg_replace('/\/\/.*$/', '', $lineWithoutComments ?? '');

            $pattern = '/^\s*'.preg_quote($setting, '/').'\s*=/i';
            if (preg_match($pattern, $lineWithoutComments ?? '') === 1) {
                return $index + 1;
            }

            // Also check for commented settings (as fallback)
            if ($commentedLine === null) {
                $commentedPattern = '/^\s*[;#]\s*'.preg_quote($setting, '/').'\s*=/i';
                if (preg_match($commentedPattern, $line) === 1) {
                    $commentedLine = $index + 1;
                }
            }
        }

        // Return commented line if found, otherwise default to 1
        return $commentedLine ?? 1;
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
            // Try to read the file, but handle open_basedir restrictions gracefully
            try {
                $this->phpIniLinesCache = FileParser::getLines($phpIniPath);
            } catch (\Throwable $e) {
                // If we can't read the file (e.g., due to open_basedir restrictions), return empty array
                $this->phpIniLinesCache = [];
            }
        }

        return $this->phpIniLinesCache ?? [];
    }
}
