<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Detects debug mode and debugging-related security issues.
 *
 * Checks for:
 * - APP_DEBUG=true in .env or config files
 * - dd(), dump(), var_dump() in production code
 * - print_r(), var_export() exposing data
 * - Debug bar or telescope in production
 * - Stack traces exposed to users
 */
class DebugModeAnalyzer extends AbstractFileAnalyzer
{
    private const HIGH_SEVERITY_FUNCTIONS = ['dd', 'dump', 'var_dump', 'print_r'];

    private array $debugFunctions = [
        'dd',
        'dump',
        'var_dump',
        'print_r',
        'var_export',
        'debug_backtrace',
        'debug_print_backtrace',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'debug-mode',
            name: 'Debug Mode Analyzer',
            description: 'Detects debug mode enabled and debugging functions that expose sensitive information',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['debug', 'information-disclosure', 'security', 'configuration'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/debug-mode',
            timeToFix: 5
        );
    }

    public function shouldRun(): bool
    {
        $envFile = $this->buildPath('.env');
        $configDir = $this->buildPath('config');
        $composerFile = $this->buildPath('composer.json');

        return file_exists($envFile) ||
               is_dir($configDir) ||
               file_exists($composerFile) ||
               ! empty($this->getPhpFiles());
    }

    public function getSkipReason(): string
    {
        return 'No configuration files, environment files, or PHP code found to analyze';
    }

    protected function runAnalysis(): ResultInterface
    {
        $basePath = $this->getBasePath();

        $issues = [];

        // Check .env files for APP_DEBUG=true
        $this->checkEnvFiles($issues);

        // Check config files for debug settings
        $this->checkConfigFiles($issues);

        // Check for debug functions in code
        $this->checkDebugFunctions($issues);

        // Check for debug packages in composer.json
        $this->checkDebugPackages($issues);

        $summary = empty($issues)
            ? 'No debug mode security issues detected'
            : sprintf('Found %d debug mode security issue%s', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check .env files for debug mode enabled.
     */
    private function checkEnvFiles(array &$issues): void
    {
        $envFile = $this->buildPath('.env');

        if (! file_exists($envFile)) {
            return;
        }

        $lines = FileParser::getLines($envFile);

        // First, determine the APP_ENV value
        $appEnv = $this->getEnvValue($lines, 'APP_ENV');

        // Skip check for development environments
        if ($this->isLocalEnvironment($appEnv)) {
            return;
        }

        // Check for APP_DEBUG=true
        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            if (preg_match('/^APP_DEBUG\s*=\s*true/i', trim($line))) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'Debug mode is enabled (APP_DEBUG=true) in '.($appEnv ?: 'unknown').' environment',
                    filePath: $envFile,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Critical,
                    recommendation: 'Set APP_DEBUG=false in production/staging environments to prevent information disclosure',
                    metadata: [
                        'file' => basename($envFile),
                        'env_var' => 'APP_DEBUG',
                        'value' => 'true',
                        'app_env' => $appEnv,
                    ]
                );
            }
        }
    }

    /**
     * Get environment variable value from .env lines.
     *
     * @param  array<int, string>  $lines
     */
    private function getEnvValue(array $lines, string $varName): ?string
    {
        foreach ($lines as $line) {
            if (! is_string($line)) {
                continue;
            }

            // Match: APP_ENV=production or APP_ENV="production" or APP_ENV='production'
            if (preg_match('/^'.preg_quote($varName, '/').'\\s*=\\s*["\']?([^"\'\s]+)["\']?/i', trim($line), $matches)) {
                return $matches[1];
            }
        }

        return null;
    }

    /**
     * Check if environment is local/development.
     */
    private function isLocalEnvironment(?string $env): bool
    {
        if ($env === null) {
            return false;
        }

        return in_array(strtolower($env), ['local', 'development', 'testing'], true);
    }

    /**
     * Check config files for debug settings.
     */
    private function checkConfigFiles(array &$issues): void
    {
        $basePath = $this->getBasePath();

        // Check app.php for hardcoded debug=true
        $appConfig = ConfigFileHelper::getConfigPath($basePath, 'app.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);
        if (file_exists($appConfig)) {
            $lines = FileParser::getLines($appConfig);

            foreach ($lines as $lineNumber => $line) {
                if (! is_string($line)) {
                    continue;
                }

                if (preg_match('/["\']debug["\']\s*=>\s*env\s*\(/i', $line)) {
                    continue;
                }

                if (preg_match('/["\']debug["\']\s*=>\s*true\b/i', $line)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Debug mode hardcoded to true in config/app.php',
                        filePath: $appConfig,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::Critical,
                        recommendation: 'Use env("APP_DEBUG", false) instead of hardcoded true',
                        metadata: [
                            'file' => 'app.php',
                            'config_key' => 'debug',
                            'value' => 'true',
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check for debug functions in code.
     */
    private function checkDebugFunctions(array &$issues): void
    {
        foreach ($this->getPhpFiles() as $file) {
            // Skip test files and development helpers
            if ($this->isTestFile($file) || $this->isDevelopmentFile($file)) {
                continue;
            }

            $lines = FileParser::getLines($file);

            foreach ($lines as $lineNumber => $line) {
                if (! is_string($line)) {
                    continue;
                }

                // Skip comments
                if (preg_match('/^\s*\/\/|^\s*\/\*|^\s*\*/', $line)) {
                    continue;
                }

                foreach ($this->debugFunctions as $func) {
                    // Match function calls
                    if (preg_match('/\b'.preg_quote($func, '/').'\s*\(/i', $line)) {
                        $severity = in_array($func, self::HIGH_SEVERITY_FUNCTIONS, true)
                            ? Severity::High
                            : Severity::Medium;

                        $issues[] = $this->createIssueWithSnippet(
                            message: sprintf('Debug function %s() found in production code', $func),
                            filePath: $file,
                            lineNumber: $lineNumber + 1,
                            severity: $severity,
                            recommendation: sprintf('Remove %s() calls before deploying to production or use proper logging instead', $func),
                            metadata: [
                                'function' => $func,
                                'file' => basename($file),
                            ]
                        );

                        break; // One issue per line
                    }
                }

                // Check for Ray debugging tool
                if (preg_match('/(?<!->)\bray\s*\(/i', $line)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Ray debugging function found in code',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Remove ray() calls before deploying to production',
                        metadata: [
                            'function' => 'ray',
                            'file' => basename($file),
                        ]
                    );
                }

                // Check for error_reporting(E_ALL)
                if (preg_match('/error_reporting\s*\(\s*E_ALL/i', $line)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Verbose error reporting enabled',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::Medium,
                        recommendation: 'Let Laravel handle error reporting through APP_DEBUG configuration',
                        metadata: [
                            'function' => 'error_reporting',
                            'file' => basename($file),
                        ]
                    );
                }

                // Check for ini_set('display_errors')
                if (preg_match('/ini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']?1["\']?\s*\)/i', $line)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Display errors enabled with ini_set()',
                        filePath: $file,
                        lineNumber: $lineNumber + 1,
                        severity: Severity::High,
                        recommendation: 'Remove ini_set("display_errors") and use Laravel\'s error handling',
                        metadata: [
                            'function' => 'ini_set',
                            'parameter' => 'display_errors',
                            'file' => basename($file),
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check for debug packages that shouldn't be in production.
     */
    private function checkDebugPackages(array &$issues): void
    {
        $composerFile = $this->buildPath('composer.json');

        if (! file_exists($composerFile)) {
            return;
        }

        $content = FileParser::readFile($composerFile);
        if ($content === null) {
            return;
        }

        $debugPackages = [
            'barryvdh/laravel-debugbar' => 'Laravel Debugbar',
            'laravel/telescope' => 'Laravel Telescope',
            'spatie/laravel-ray' => 'Spatie Ray',
            'beyondcode/laravel-dump-server' => 'Laravel Dump Server',
        ];

        // Use json_decode for more reliable parsing
        $composerData = json_decode($content, true);

        if (! is_array($composerData) || ! isset($composerData['require']) || ! is_array($composerData['require'])) {
            return;
        }

        $lines = FileParser::getLines($composerFile);

        foreach ($debugPackages as $package => $name) {
            if (array_key_exists($package, $composerData['require'])) {
                // Find the line number where this package appears
                $lineNumber = 0;
                foreach ($lines as $idx => $line) {
                    if (is_string($line) && str_contains($line, $package)) {
                        $lineNumber = $idx;
                        break;
                    }
                }

                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf("%s package in 'require' section (should be in 'require-dev')", $name),
                    filePath: $composerFile,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Medium,
                    recommendation: sprintf("Move %s to 'require-dev' section to exclude from production", $package),
                    metadata: [
                        'package' => $package,
                        'package_name' => $name,
                    ]
                );
            }
        }
    }

    /**
     * Check if file is a test file.
     */
    private function isTestFile(string $file): bool
    {
        return str_contains($file, '/tests/') ||
               str_contains($file, '/Tests/') ||
               str_ends_with($file, 'Test.php');
    }

    /**
     * Check if file is a development helper file.
     */
    private function isDevelopmentFile(string $file): bool
    {
        return str_contains($file, '/database/seeders/') ||
               str_contains($file, '/database/factories/') ||
               str_contains($file, 'Seeder.php') ||
               str_contains($file, 'Factory.php');
    }
}
