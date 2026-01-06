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
        'ray',
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

        // Get APP_DEBUG
        $debugValue = $this->getEnvValue($lines, 'APP_DEBUG');

        // Check for APP_DEBUG=true - only report on the actual line where it's set
        if ($debugValue !== null && in_array(strtolower($debugValue), ['true', '1', 'yes', 'on'], true)) {
            // Find the line number where APP_DEBUG is set
            $debugLineNumber = null;
            foreach ($lines as $lineNumber => $line) {
                if (! is_string($line)) {
                    continue;
                }

                // Match: APP_DEBUG=true or APP_DEBUG="true" or APP_DEBUG='true'
                if (preg_match('/^APP_DEBUG\s*=\s*["\']?(true|1|yes|on)["\']?/i', trim($line))) {
                    $debugLineNumber = $lineNumber + 1;
                    break;
                }
            }

            // Create issue only once for the line where APP_DEBUG is actually set
            $issues[] = $this->createIssueWithSnippet(
                message: 'Debug mode is enabled (APP_DEBUG=true) in '.($appEnv ?: 'unknown').' environment',
                filePath: $envFile,
                lineNumber: $debugLineNumber ?? 1, // Fallback to line 1 if not found (shouldn't happen)
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
     * Check for debug functions in code using PHP tokens.
     */
    private function checkDebugFunctions(array &$issues): void
    {
        foreach ($this->getPhpFiles() as $file) {
            // Skip test files and development helpers
            if ($this->isTestFile($file) || $this->isDevelopmentFile($file)) {
                continue;
            }

            $code = FileParser::readFile($file);
            if ($code === null) {
                continue;
            }

            $tokens = token_get_all($code);
            $tokenCount = count($tokens);

            for ($i = 0; $i < $tokenCount; $i++) {
                $token = $tokens[$i];

                // Only interested in identifiers (function names)
                if (! is_array($token) || $token[0] !== T_STRING) {
                    continue;
                }

                $functionName = strtolower($token[1]);

                if (! in_array($functionName, $this->debugFunctions, true)) {
                    continue;
                }

                // Ignore function definitions: function dump() {}
                $prev = $this->previousMeaningfulToken($tokens, $i);
                if ($prev !== null && is_array($prev) && $prev[0] === T_FUNCTION) {
                    continue;
                }

                // Ignore method calls: $obj->dump()
                if ($prev === '->' || $prev === '::') {
                    continue;
                }

                // Ensure this is actually a function call (next token is "(")
                $next = $this->nextMeaningfulToken($tokens, $i);
                if ($next !== '(') {
                    continue;
                }

                $severity = match ($functionName) {
                    'ray' => Severity::High,
                    default => in_array($functionName, self::HIGH_SEVERITY_FUNCTIONS, true)
                        ? Severity::High
                        : Severity::Medium,
                };

                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf(
                        'Debug function %s() found in production code',
                        $functionName
                    ),
                    filePath: $file,
                    lineNumber: $token[2],
                    severity: $severity,
                    recommendation: sprintf(
                        'Remove %s() calls before deploying to production or replace with structured logging',
                        $functionName
                    ),
                    metadata: [
                        'function' => $functionName,
                        'file' => basename($file),
                    ]
                );
            }

            // Extra checks that are easier at the string level
            $this->checkDebugIniSettings($file, $issues);
        }
    }

    /**
     * Get the previous non-whitespace/comment token.
     *
     * @param  array<int, array<int, int|string>|string>  $tokens
     */
    private function previousMeaningfulToken(array $tokens, int $index): mixed
    {
        for ($i = $index - 1; $i >= 0; $i--) {
            $token = $tokens[$i];

            if (is_array($token)) {
                if (in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }

                return $token;
            }

            return $token;
        }

        return null;
    }

    /**
     * Get the next non-whitespace/comment token.
     *
     * @param  array<int, array<int, int|string>|string>  $tokens
     */
    private function nextMeaningfulToken(array $tokens, int $index): mixed
    {
        $count = count($tokens);

        for ($i = $index + 1; $i < $count; $i++) {
            $token = $tokens[$i];

            if (is_array($token)) {
                if (in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }

                return $token;
            }

            return $token;
        }

        return null;
    }

    private function checkDebugIniSettings(string $file, array &$issues): void
    {
        $lines = FileParser::getLines($file);

        foreach ($lines as $lineNumber => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Skip full-line comments
            if (preg_match('/^\s*(\/\/|#)/', $line)) {
                continue;
            }

            if (preg_match('/error_reporting\s*\(\s*(E_ALL|-1)/i', $line)) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'Verbose error reporting enabled',
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Medium,
                    recommendation: 'Control error reporting via APP_DEBUG and framework configuration',
                    metadata: [
                        'function' => 'error_reporting',
                        'file' => basename($file),
                    ]
                );
            }

            if (preg_match(
                '/ini_set\s*\(\s*[\'"]display_(startup_)?errors[\'"]\s*,\s*(1|true|on|yes)/i',
                $line
            )) {
                $issues[] = $this->createIssueWithSnippet(
                    message: 'PHP display_errors enabled',
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::High,
                    recommendation: 'Disable display_errors in production environments',
                    metadata: [
                        'function' => 'ini_set',
                        'parameter' => 'display_errors',
                        'file' => basename($file),
                    ]
                );
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
