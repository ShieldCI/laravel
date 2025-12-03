<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Checks if .env file exists in the application.
 *
 * Checks for:
 * - Presence of .env file
 * - Critical for application functionality
 */
class EnvFileAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'env-file-exists',
            name: 'Environment File Existence',
            description: 'Ensures .env file exists for application configuration',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['environment', 'configuration', 'deployment'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/env-file-exists',
            timeToFix: 5
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $basePath = $this->getBasePath();

        $envPath = $this->getEnvPath($basePath);

        // Check if .env is a broken symlink (must check before file_exists)
        if (is_link($envPath) && ! file_exists($envPath)) {
            $target = readlink($envPath);

            return $this->failed(
                'Application .env symlink is broken',
                [$this->createIssue(
                    message: 'The .env file is a broken symlink',
                    location: new Location('.env', 1),
                    severity: Severity::Critical,
                    recommendation: sprintf('Fix the broken symlink. Target: %s', $target ?: 'unknown'),
                    code: null,
                    metadata: [
                        'env_path' => $envPath,
                        'is_symlink' => true,
                        'symlink_target' => $target ?: null,
                        'target_exists' => false,
                    ]
                )]
            );
        }

        // Check if .env exists
        if (! file_exists($envPath)) {
            return $this->createMissingEnvIssue($envPath, $basePath);
        }

        // Check if .env is readable
        if (! is_readable($envPath)) {
            return $this->failed(
                'Application .env file is not readable',
                [$this->createIssue(
                    message: 'The .env file exists but is not readable',
                    location: new Location('.env', 1),
                    severity: Severity::Critical,
                    recommendation: 'Fix file permissions to make .env readable. Run: chmod 644 .env',
                    code: null,
                    metadata: [
                        'env_path' => $envPath,
                        'is_readable' => false,
                    ]
                )]
            );
        }

        // Check if .env is empty
        $fileSize = @filesize($envPath);
        if ($fileSize !== false && $fileSize === 0) {
            return $this->failed(
                'Application .env file is empty',
                [$this->createIssue(
                    message: 'The .env file exists but contains no configuration',
                    location: new Location('.env', 1),
                    severity: Severity::High,
                    recommendation: 'Add environment variables to your .env file. At minimum, configure: APP_KEY, APP_ENV, APP_DEBUG, DB_CONNECTION',
                    code: null,
                    metadata: [
                        'env_path' => $envPath,
                        'is_empty' => true,
                    ]
                )]
            );
        }

        return $this->passed('.env file exists and is valid');
    }

    /**
     * Create issue for missing .env file.
     */
    private function createMissingEnvIssue(string $envPath, string $basePath): ResultInterface
    {
        $envExamplePath = $this->getEnvExamplePath($basePath);
        $envExampleExists = file_exists($envExamplePath);

        return $this->failed(
            'Application .env file is missing',
            [$this->createIssue(
                message: 'The .env file does not exist',
                location: new Location('.env', 1),
                severity: Severity::Critical,
                recommendation: $this->buildRecommendation($envExampleExists),
                code: null,
                metadata: [
                    'env_path' => $envPath,
                    'env_example_exists' => $envExampleExists,
                ]
            )]
        );
    }

    /**
     * Get the .env file path.
     */
    private function getEnvPath(string $basePath): string
    {
        if ($basePath === '') {
            return '.env';
        }

        return rtrim($basePath, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.'.env';
    }

    /**
     * Get the .env.example file path.
     */
    private function getEnvExamplePath(string $basePath): string
    {
        if ($basePath === '') {
            return '.env.example';
        }

        return rtrim($basePath, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.'.env.example';
    }

    /**
     * Build recommendation message based on whether .env.example exists.
     */
    private function buildRecommendation(bool $envExampleExists): string
    {
        if ($envExampleExists) {
            return sprintf(
                <<<'RECOMMENDATION'
Create a .env file in your application root directory by copying .env.example.

Unix/Linux:
  %s

Windows:
  %s

After creating the file, configure your environment variables with appropriate values for your environment.

Without a .env file, your application cannot load configuration and will fail to run.
RECOMMENDATION,
                'cp .env.example .env',
                'copy .env.example .env'
            );
        }

        return <<<'RECOMMENDATION'
Create a .env file in your application root directory.

1. Create a new file named ".env" in your application root
2. Add your environment variables in the format: KEY=value
3. Include at minimum: APP_KEY, APP_ENV, APP_DEBUG, DB_CONNECTION, DB_HOST, DB_PORT, DB_DATABASE, DB_USERNAME, DB_PASSWORD

Without a .env file, your application cannot load configuration and will fail to run.

Note: Consider creating a .env.example file as a template for your team members.
RECOMMENDATION;
    }
}
