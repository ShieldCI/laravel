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
 * Checks that all environment variables from .env.example are defined in .env.
 *
 * Checks for:
 * - .env file exists
 * - All variables from .env.example are present in .env
 * - No missing required configuration
 */
class EnvVariableAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'env-variables-complete',
            name: 'Environment Variables Complete',
            description: 'Ensures all required environment variables from .env.example are defined in .env',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['environment', 'configuration', 'reliability', 'deployment'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/env-variables-complete',
            timeToFix: 20
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $basePath = $this->getBasePath();
        $envExamplePath = $this->getEnvExamplePath($basePath);
        $envPath = $this->getEnvPath($basePath);

        // Check if .env.example exists
        if (! file_exists($envExamplePath)) {
            return $this->warning('.env.example file not found - cannot verify environment variables');
        }

        // Check if .env exists
        if (! file_exists($envPath)) {
            return $this->failed(
                '.env file not found',
                [$this->createIssue(
                    message: '.env file is missing',
                    location: new Location('.env', 1),
                    severity: Severity::Critical,
                    recommendation: $this->buildMissingEnvFileRecommendation(),
                    code: null,
                    metadata: []
                )]
            );
        }

        // Parse both files
        $exampleVars = $this->parseEnvFile($envExamplePath);
        $actualVars = $this->parseEnvFile($envPath);

        // Find missing variables
        $missingVars = array_diff_key($exampleVars, $actualVars);

        if (empty($missingVars)) {
            return $this->passed('All environment variables from .env.example are present in .env');
        }

        return $this->failed(
            sprintf('Found %d missing environment variable(s)', count($missingVars)),
            [$this->createIssue(
                message: 'Missing environment variables',
                location: new Location('.env', 1),
                severity: Severity::High,
                recommendation: $this->buildMissingVariablesRecommendation($missingVars),
                code: FileParser::getCodeSnippet($envPath, 1),
                metadata: [
                    'missing_count' => count($missingVars),
                    'missing_variables' => array_keys($missingVars),
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
     * Build recommendation message for missing .env file.
     */
    private function buildMissingEnvFileRecommendation(): string
    {
        return sprintf(
            <<<'RECOMMENDATION'
Create a .env file by copying .env.example.

Unix/Linux:
  %s

Windows:
  %s

After creating the file, configure the environment variables with appropriate values for your environment.
RECOMMENDATION,
            'cp .env.example .env',
            'copy .env.example .env'
        );
    }

    /**
     * Build recommendation message for missing environment variables.
     *
     * @param  array<string, string>  $missingVars
     */
    private function buildMissingVariablesRecommendation(array $missingVars): string
    {
        $missingKeys = array_keys($missingVars);
        $variablesList = implode(', ', $missingKeys);

        return sprintf(
            <<<'RECOMMENDATION'
Add the following environment variables to your .env file: %s

These variables are defined in .env.example and may be required for the application to function correctly.

To fix:
1. Open .env.example and locate these variables
2. Copy the variable definitions to your .env file
3. Set appropriate values for your environment (do not use placeholder values in production)

Example:
  %s=your_value_here
RECOMMENDATION,
            $variablesList,
            $missingKeys[0] ?? 'VARIABLE_NAME'
        );
    }

    /**
     * Parse environment file and return key-value pairs.
     *
     * @return array<string, string>
     */
    private function parseEnvFile(string $filePath): array
    {
        if (! file_exists($filePath) || ! is_readable($filePath)) {
            return [];
        }

        try {
            $lines = FileParser::getLines($filePath);
        } catch (\Throwable $e) {
            return [];
        }

        if (! is_array($lines) || empty($lines)) {
            return [];
        }

        $variables = [];

        foreach ($lines as $line) {
            if (! is_string($line)) {
                continue;
            }

            $line = trim($line);

            // Skip empty lines and comments
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            // Parse KEY=VALUE format
            if (preg_match('/^([A-Z_][A-Z0-9_]*)\s*=/', $line, $matches)) {
                $key = $matches[1];
                $variables[$key] = $line;
            }
        }

        return $variables;
    }
}
