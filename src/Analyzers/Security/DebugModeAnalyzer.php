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
use ShieldCI\AnalyzersCore\ValueObjects\Location;

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
            name: 'Debug Mode Security Analyzer',
            description: 'Detects debug mode enabled and debugging functions that expose sensitive information',
            category: Category::Security,
            severity: Severity::High,
            tags: ['debug', 'information-disclosure', 'security', 'configuration'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/debug-mode',
            timeToFix: 5
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check .env files for APP_DEBUG=true
        $this->checkEnvFiles($issues);

        // Check config files for debug settings
        $this->checkConfigFiles($issues);

        // Check for debug functions in code
        $this->checkDebugFunctions($issues);

        // Check for debug packages in composer.json
        $this->checkDebugPackages($issues);

        if (empty($issues)) {
            return $this->passed('No debug mode security issues detected');
        }

        return $this->failed(
            sprintf('Found %d debug mode security issues', count($issues)),
            $issues
        );
    }

    /**
     * Check .env files for debug mode enabled.
     */
    private function checkEnvFiles(array &$issues): void
    {
        $envFiles = [
            $this->basePath.'/.env',
            $this->basePath.'/.env.production',
            $this->basePath.'/.env.prod',
        ];

        foreach ($envFiles as $envFile) {
            if (! file_exists($envFile)) {
                continue;
            }

            $lines = FileParser::getLines($envFile);

            foreach ($lines as $lineNumber => $line) {
                // Check for APP_DEBUG=true
                if (preg_match('/^APP_DEBUG\s*=\s*true/i', trim($line))) {
                    $severity = str_contains($envFile, 'production') || str_contains($envFile, 'prod')
                        ? Severity::Critical
                        : Severity::High;

                    $issues[] = $this->createIssue(
                        message: 'Debug mode is enabled (APP_DEBUG=true)',
                        location: new Location(
                            $this->getRelativePath($envFile),
                            $lineNumber + 1
                        ),
                        severity: $severity,
                        recommendation: 'Set APP_DEBUG=false in production environments to prevent information disclosure',
                        code: trim($line)
                    );
                }
            }
        }
    }

    /**
     * Check config files for debug settings.
     */
    private function checkConfigFiles(array &$issues): void
    {
        // Check app.php for hardcoded debug=true
        $appConfig = ConfigFileHelper::getConfigPath($this->basePath, 'app.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);
        if (file_exists($appConfig)) {
            $lines = FileParser::getLines($appConfig);

            foreach ($lines as $lineNumber => $line) {
                if (preg_match('/["\']debug["\']\s*=>\s*true/i', $line)) {
                    $issues[] = $this->createIssue(
                        message: 'Debug mode hardcoded to true in config/app.php',
                        location: new Location(
                            $this->getRelativePath($appConfig),
                            $lineNumber + 1
                        ),
                        severity: Severity::Critical,
                        recommendation: 'Use env("APP_DEBUG", false) instead of hardcoded true',
                        code: trim($line)
                    );
                }
            }

            // Check for missing debug_hide or debug_blacklist when debug is enabled
            $this->checkDebugHideConfiguration($appConfig, $lines, $issues);
        }

        // Check logging.php for debug channels
        $loggingConfig = ConfigFileHelper::getConfigPath($this->basePath, 'logging.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);
        if (file_exists($loggingConfig)) {
            $content = FileParser::readFile($loggingConfig);

            if ($content !== null && preg_match('/["\']level["\']\s*=>\s*["\']debug["\']/i', $content)) {
                $issues[] = $this->createIssue(
                    message: 'Debug logging level configured in logging.php',
                    location: new Location(
                        $this->getRelativePath($loggingConfig),
                        1
                    ),
                    severity: Severity::Low,
                    recommendation: 'Use environment variables for log levels: env("LOG_LEVEL", "error")',
                    code: 'Debug logging configured'
                );
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
                // Skip comments
                if (preg_match('/^\s*\/\/|^\s*\/\*|^\s*\*/', $line)) {
                    continue;
                }

                foreach ($this->debugFunctions as $func) {
                    // Match function calls
                    if (preg_match('/\b'.preg_quote($func, '/').'\s*\(/i', $line)) {
                        $severity = in_array($func, ['dd', 'dump', 'var_dump', 'print_r'])
                            ? Severity::High
                            : Severity::Medium;

                        $issues[] = $this->createIssue(
                            message: "Debug function {$func}() found in production code",
                            location: new Location(
                                $this->getRelativePath($file),
                                $lineNumber + 1
                            ),
                            severity: $severity,
                            recommendation: "Remove {$func}() calls before deploying to production or use proper logging instead",
                            code: trim($line)
                        );

                        break; // One issue per line
                    }
                }

                // Check for Ray debugging tool
                if (preg_match('/\bray\s*\(/i', $line)) {
                    $issues[] = $this->createIssue(
                        message: 'Ray debugging function found in code',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Medium,
                        recommendation: 'Remove ray() calls before deploying to production',
                        code: trim($line)
                    );
                }

                // Check for error_reporting(E_ALL)
                if (preg_match('/error_reporting\s*\(\s*E_ALL/i', $line)) {
                    $issues[] = $this->createIssue(
                        message: 'Verbose error reporting enabled',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::Medium,
                        recommendation: 'Let Laravel handle error reporting through APP_DEBUG configuration',
                        code: trim($line)
                    );
                }

                // Check for ini_set('display_errors')
                if (preg_match('/ini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']?1["\']?\s*\)/i', $line)) {
                    $issues[] = $this->createIssue(
                        message: 'Display errors enabled with ini_set()',
                        location: new Location(
                            $this->getRelativePath($file),
                            $lineNumber + 1
                        ),
                        severity: Severity::High,
                        recommendation: 'Remove ini_set("display_errors") and use Laravel\'s error handling',
                        code: trim($line)
                    );
                }
            }
        }
    }

    /**
     * Check for missing debug_hide or debug_blacklist configuration.
     */
    private function checkDebugHideConfiguration(string $appConfig, array $lines, array &$issues): void
    {
        $hasDebugEnabled = false;
        $hasDebugHide = false;
        $hasDebugBlacklist = false;
        $appEnv = 'production'; // Default assumption

        foreach ($lines as $lineNumber => $line) {
            // Check if debug is enabled
            if (preg_match('/["\']debug["\']\s*=>\s*(?:true|env\(["\']APP_DEBUG["\']\s*,\s*true\))/i', $line)) {
                $hasDebugEnabled = true;
            }

            // Check APP_ENV
            if (preg_match('/["\']env["\']\s*=>\s*env\(["\']APP_ENV["\']\s*,\s*["\'](\w+)["\']/i', $line, $matches)) {
                $appEnv = $matches[1];
            }

            // Check for debug_hide or debug_blacklist
            if (preg_match('/["\']debug_hide["\']\s*=>\s*\[/i', $line)) {
                $hasDebugHide = true;
            }
            if (preg_match('/["\']debug_blacklist["\']\s*=>\s*\[/i', $line)) {
                $hasDebugBlacklist = true;
            }
        }

        // If debug is enabled in non-local environments without hiding sensitive vars
        if ($hasDebugEnabled && $appEnv !== 'local' && ! $hasDebugHide && ! $hasDebugBlacklist) {
            $issues[] = $this->createIssue(
                message: 'Debug mode enabled without hiding sensitive environment variables',
                location: new Location(
                    $this->getRelativePath($appConfig),
                    1
                ),
                severity: Severity::Critical,
                recommendation: 'Add "debug_hide" or "debug_blacklist" configuration to hide sensitive variables like passwords, API keys, etc.',
                code: 'Missing debug_hide or debug_blacklist configuration'
            );
        }
    }

    /**
     * Check for debug packages that shouldn't be in production.
     */
    private function checkDebugPackages(array &$issues): void
    {
        $composerFile = $this->basePath.'/composer.json';

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

        $lines = FileParser::getLines($composerFile);
        $inRequireSection = false;

        foreach ($lines as $lineNumber => $line) {
            if (preg_match('/^\s*"require"\s*:\s*{/', $line)) {
                $inRequireSection = true;

                continue;
            }

            if ($inRequireSection && preg_match('/^\s*}/', $line)) {
                $inRequireSection = false;
            }

            if ($inRequireSection) {
                foreach ($debugPackages as $package => $name) {
                    if (str_contains($line, $package)) {
                        $issues[] = $this->createIssue(
                            message: "{$name} package in 'require' section (should be in 'require-dev')",
                            location: new Location(
                                $this->getRelativePath($composerFile),
                                $lineNumber + 1
                            ),
                            severity: Severity::Medium,
                            recommendation: "Move {$package} to 'require-dev' section to exclude from production",
                            code: trim($line)
                        );
                    }
                }
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
