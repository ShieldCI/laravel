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
 * Checks that all environment variables from .env are documented in .env.example.
 *
 * Checks for:
 * - All variables from .env are present in .env.example
 * - Ensures .env.example serves as proper documentation
 * - Helps with team onboarding and deployment
 */
class EnvExampleAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'env-example-documented',
            name: 'Environment Example Documentation Analyzer',
            description: 'Ensures all environment variables used in .env are documented in .env.example',
            category: Category::Reliability,
            severity: Severity::Low,
            tags: ['environment', 'configuration', 'documentation', 'team-collaboration'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/env-example-documented',
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $basePath = $this->getBasePath();
        $envPath = $this->getEnvPath($basePath);
        $envExamplePath = $this->getEnvExamplePath($basePath);

        // Check if .env exists
        if (! file_exists($envPath)) {
            return $this->warning('.env file not found - cannot verify documentation');
        }

        // Check if .env.example exists
        if (! file_exists($envExamplePath)) {
            return $this->failed(
                '.env.example file not found',
                [$this->createIssue(
                    message: '.env.example file is missing',
                    location: new Location('.env.example'),
                    severity: Severity::High,
                    recommendation: $this->buildMissingExampleFileRecommendation(),
                    metadata: []
                )]
            );
        }

        // Parse both files
        $envVars = $this->parseEnvFile($envPath);
        $exampleVars = $this->parseEnvFile($envExamplePath);

        // Find undocumented variables (in .env but not in .env.example)
        $undocumentedVars = array_diff_key($envVars, $exampleVars);

        if (empty($undocumentedVars)) {
            return $this->passed('All environment variables are documented in .env.example');
        }

        return $this->failed(
            sprintf('Found %d undocumented environment variable(s)', count($undocumentedVars)),
            [$this->createIssueWithSnippet(
                message: 'Undocumented environment variables',
                filePath: $envExamplePath,
                lineNumber: 1,
                severity: Severity::Low,
                recommendation: $this->buildUndocumentedVariablesRecommendation($undocumentedVars),
                column: null,
                contextLines: null,
                code: 'undocumented-variables',
                metadata: [
                    'undocumented_count' => count($undocumentedVars),
                    'undocumented_variables' => array_keys($undocumentedVars),
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
     * Build recommendation message for missing .env.example file.
     */
    private function buildMissingExampleFileRecommendation(): string
    {
        return <<<'RECOMMENDATION'
Create a .env.example file to document all environment variables used in your application.
RECOMMENDATION;
    }

    /**
     * Build recommendation message for undocumented variables.
     *
     * @param  array<string, string>  $undocumentedVars
     */
    private function buildUndocumentedVariablesRecommendation(array $undocumentedVars): string
    {
        $undocumentedKeys = array_keys($undocumentedVars);
        $variablesList = implode(', ', $undocumentedKeys);

        return sprintf(
            <<<'RECOMMENDATION'
Add the following environment variables to your .env.example file: %s

These variables are currently used in .env but not documented in .env.example.
This makes it harder for team members to know what variables are required.
RECOMMENDATION,
            $variablesList,
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
