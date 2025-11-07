<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Validates that the application encryption key is properly configured.
 *
 * Checks for:
 * - APP_KEY is set in .env files
 * - APP_KEY is not the default/example value
 * - APP_KEY follows proper format (base64: prefix)
 * - config/app.php has proper key configuration
 */
class AppKeyAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'app-key-security',
            name: 'Application Key Security Analyzer',
            description: 'Validates that the application encryption key is properly configured and secure',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['encryption', 'app-key', 'security', 'configuration'],
            docsUrl: 'https://laravel.com/docs/encryption'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check .env files for APP_KEY
        $this->checkEnvFiles($issues);

        // Check config/app.php
        $this->checkAppConfig($issues);

        if (empty($issues)) {
            return $this->passed('Application encryption key is properly configured');
        }

        return $this->failed(
            sprintf('Found %d application key security issues', count($issues)),
            $issues
        );
    }

    /**
     * Check .env files for APP_KEY configuration.
     */
    private function checkEnvFiles(array &$issues): void
    {
        $envFiles = [
            $this->basePath.'/.env',
            $this->basePath.'/.env.example',
            $this->basePath.'/.env.production',
            $this->basePath.'/.env.prod',
        ];

        foreach ($envFiles as $envFile) {
            if (! file_exists($envFile)) {
                continue;
            }

            $content = FileParser::readFile($envFile);
            if ($content === null) {
                continue;
            }

            $lines = FileParser::getLines($envFile);
            $hasAppKey = false;
            $appKeyValue = null;

            foreach ($lines as $lineNumber => $line) {
                // Check for APP_KEY setting
                if (preg_match('/^APP_KEY\s*=\s*(.*)$/i', trim($line), $matches)) {
                    $hasAppKey = true;
                    $appKeyValue = trim($matches[1]);

                    // Check if APP_KEY is empty
                    if (empty($appKeyValue)) {
                        $issues[] = $this->createIssue(
                            message: 'APP_KEY is not set or is empty',
                            location: new Location(
                                $this->getRelativePath($envFile),
                                $lineNumber + 1
                            ),
                            severity: Severity::Critical,
                            recommendation: 'Run "php artisan key:generate" to generate a secure application key',
                            code: trim($line)
                        );
                    }
                    // Check if APP_KEY is a placeholder
                    elseif (in_array($appKeyValue, ['base64:your-key-here', 'SomeRandomString', 'null', '""', "''"])) {
                        $issues[] = $this->createIssue(
                            message: 'APP_KEY is set to a placeholder/example value',
                            location: new Location(
                                $this->getRelativePath($envFile),
                                $lineNumber + 1
                            ),
                            severity: Severity::Critical,
                            recommendation: 'Run "php artisan key:generate" to generate a secure application key',
                            code: trim($line)
                        );
                    }
                    // Check if APP_KEY format is correct
                    elseif (! str_starts_with($appKeyValue, 'base64:') && strlen($appKeyValue) < 32) {
                        $issues[] = $this->createIssue(
                            message: 'APP_KEY does not follow the expected format or is too short',
                            location: new Location(
                                $this->getRelativePath($envFile),
                                $lineNumber + 1
                            ),
                            severity: Severity::High,
                            recommendation: 'Ensure APP_KEY is properly generated with "php artisan key:generate"',
                            code: trim($line)
                        );
                    }
                }
            }

            // Only flag missing APP_KEY in actual .env files, not examples
            if (! $hasAppKey && ! str_contains($envFile, '.example')) {
                $issues[] = $this->createIssue(
                    message: 'APP_KEY is not defined in environment file',
                    location: new Location(
                        $this->getRelativePath($envFile),
                        1
                    ),
                    severity: Severity::Critical,
                    recommendation: 'Add APP_KEY to your .env file and run "php artisan key:generate"',
                    code: 'Missing APP_KEY configuration'
                );
            }
        }
    }

    /**
     * Check config/app.php for key configuration.
     */
    private function checkAppConfig(array &$issues): void
    {
        $appConfig = $this->basePath.'/config/app.php';

        if (! file_exists($appConfig)) {
            return;
        }

        $content = FileParser::readFile($appConfig);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($appConfig);

        foreach ($lines as $lineNumber => $line) {
            // Check for hardcoded key (security issue)
            if (preg_match('/["\']key["\']\s*=>\s*["\'](?!env\()/i', $line) &&
                ! str_contains($line, 'env(')) {

                // Check if it's a real hardcoded key (not a comment or documentation)
                if (! preg_match('/^\s*\/\/|^\s*\*/', $line)) {
                    $issues[] = $this->createIssue(
                        message: 'Application key is hardcoded in config/app.php instead of using environment variable',
                        location: new Location(
                            $this->getRelativePath($appConfig),
                            $lineNumber + 1
                        ),
                        severity: Severity::Critical,
                        recommendation: 'Use env("APP_KEY") to reference the key from .env file',
                        code: trim($line)
                    );
                }
            }

            // Check for insecure cipher configuration
            if (preg_match('/["\']cipher["\']\s*=>\s*["\']([^"\']+)["\']/i', $line, $matches)) {
                $cipher = strtolower($matches[1]);

                // Laravel supports AES-128-CBC and AES-256-CBC
                if (! in_array($cipher, ['aes-128-cbc', 'aes-256-cbc'])) {
                    $issues[] = $this->createIssue(
                        message: "Unsupported or weak cipher algorithm: {$cipher}",
                        location: new Location(
                            $this->getRelativePath($appConfig),
                            $lineNumber + 1
                        ),
                        severity: Severity::High,
                        recommendation: 'Use "AES-256-CBC" or "AES-128-CBC" cipher',
                        code: trim($line)
                    );
                }
            }
        }
    }
}
