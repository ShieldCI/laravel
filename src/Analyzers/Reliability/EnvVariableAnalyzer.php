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
            name: 'Environment Variables Complete Analyzer',
            description: 'Ensures all required environment variables from .env.example are defined in .env',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['environment', 'configuration', 'reliability', 'deployment'],
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
            return $this->resultBySeverity(
                '.env file not found',
                [$this->createIssue(
                    message: '.env file is missing',
                    location: new Location($this->getRelativePath($envPath)),
                    severity: Severity::Critical,
                    recommendation: $this->buildMissingEnvFileRecommendation(),
                    code: 'missing-env',
                )]
            );
        }

        // Parse both files and track errors
        $exampleResult = $this->parseEnvFileWithErrors($envExamplePath);
        $actualResult = $this->parseEnvFileWithErrors($envPath);
        $commentedResult = $this->parseCommentedVariablesWithErrors($envPath);

        // Handle parsing failures
        if ($exampleResult['error'] !== null) {
            return $this->resultBySeverity(
                'Failed to parse .env.example file',
                [$this->createIssue(
                    message: 'Unable to parse .env.example file',
                    location: new Location($this->getRelativePath($envExamplePath)),
                    severity: Severity::Critical,
                    recommendation: sprintf(
                        "The .env.example file could not be parsed. Error: %s\n\nEnsure the file is readable and properly formatted.",
                        $exampleResult['error']
                    ),
                    code: 'parse-error-example',
                    metadata: ['error' => $exampleResult['error']]
                )]
            );
        }

        if ($actualResult['error'] !== null) {
            return $this->resultBySeverity(
                'Failed to parse .env file',
                [$this->createIssue(
                    message: 'Unable to parse .env file',
                    location: new Location($this->getRelativePath($envPath)),
                    severity: Severity::High,
                    recommendation: sprintf(
                        "The .env file could not be parsed. Error: %s\n\nEnsure the file is readable and properly formatted.",
                        $actualResult['error']
                    ),
                    code: 'parse-error-env',
                    metadata: ['error' => $actualResult['error']]
                )]
            );
        }

        $exampleVars = $exampleResult['variables'];
        $actualVars = $actualResult['variables'];
        $commentedVars = $commentedResult['variables'];

        // Find variables that are missing (not active and not commented)
        $missingVars = [];
        $commentedOnlyVars = [];

        foreach ($exampleVars as $key => $value) {
            // Variable is active in .env
            if (isset($actualVars[$key])) {
                continue;
            }

            // Variable is commented out in .env
            if (isset($commentedVars[$key])) {
                $commentedOnlyVars[$key] = $value;

                continue;
            }

            // Variable is completely absent from .env
            $missingVars[$key] = $value;
        }

        // All variables are present (either active or commented)
        if (empty($missingVars) && empty($commentedOnlyVars)) {
            return $this->passed('All environment variables from .env.example are defined and enabled in .env');
        }

        // Only commented variables, no truly missing ones
        if (empty($missingVars) && ! empty($commentedOnlyVars)) {
            return $this->warning(
                sprintf('Found %d commented environment variable(s)', count($commentedOnlyVars)),
                [$this->createIssue(
                    message: 'Environment variables are commented out',
                    location: new Location($this->getRelativePath($envPath)),
                    severity: Severity::Low,
                    recommendation: $this->buildCommentedVariablesRecommendation($commentedOnlyVars),
                    code: 'commented-variables',
                    metadata: [
                        'commented_count' => count($commentedOnlyVars),
                        'commented_variables' => array_keys($commentedOnlyVars),
                    ]
                )]
            );
        }

        // Build issues for missing and/or commented variables
        $issues = [];

        if (! empty($missingVars)) {
            $issues[] = $this->createIssue(
                message: 'Missing environment variables',
                location: new Location($this->getRelativePath($envPath)),
                severity: Severity::High,
                recommendation: $this->buildMissingVariablesRecommendation($missingVars),
                code: 'missing-variables',
                metadata: [
                    'missing_count' => count($missingVars),
                    'missing_variables' => array_keys($missingVars),
                ]
            );
        }

        if (! empty($commentedOnlyVars)) {
            $issues[] = $this->createIssue(
                message: 'Environment variables are commented out',
                location: new Location($this->getRelativePath($envPath)),
                severity: Severity::Low,
                recommendation: $this->buildCommentedVariablesRecommendation($commentedOnlyVars),
                code: 'commented-variables',
                metadata: [
                    'commented_count' => count($commentedOnlyVars),
                    'commented_variables' => array_keys($commentedOnlyVars),
                ]
            );
        }

        $totalCount = count($missingVars) + count($commentedOnlyVars);

        return $this->resultBySeverity(
            sprintf('Found %d environment variable issue(s)', $totalCount),
            $issues
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

RECOMMENDATION,
            $variablesList,
        );
    }

    /**
     * Build recommendation message for commented environment variables.
     *
     * @param  array<string, string>  $commentedVars
     */
    private function buildCommentedVariablesRecommendation(array $commentedVars): string
    {
        $commentedKeys = array_keys($commentedVars);
        $variablesList = implode(', ', $commentedKeys);

        return sprintf(
            <<<'RECOMMENDATION'
The following environment variables are commented out in .env: %s

These variables are defined in .env.example. If they're intentionally disabled, this is fine.
If they should be active, uncomment them in your .env file.

RECOMMENDATION,
            $variablesList,
        );
    }

    /**
     * Parse environment file and return key-value pairs with error tracking.
     *
     * @return array{variables: array<string, string>, error: string|null}
     */
    private function parseEnvFileWithErrors(string $filePath): array
    {
        if (! file_exists($filePath)) {
            return ['variables' => [], 'error' => 'File does not exist'];
        }

        if (! is_readable($filePath)) {
            return ['variables' => [], 'error' => 'File is not readable'];
        }

        try {
            $lines = FileParser::getLines($filePath);
        } catch (\Throwable $e) {
            return ['variables' => [], 'error' => $e->getMessage()];
        }

        if (! is_array($lines)) {
            return ['variables' => [], 'error' => 'Failed to read file lines'];
        }

        if (empty($lines)) {
            // Empty file is valid, not an error
            return ['variables' => [], 'error' => null];
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

        return ['variables' => $variables, 'error' => null];
    }

    /**
     * Parse environment file and return commented-out variables with error tracking.
     *
     * Note: Parsing errors for commented variables are non-critical and ignored.
     *
     * @return array{variables: array<string, string>, error: string|null}
     */
    private function parseCommentedVariablesWithErrors(string $filePath): array
    {
        if (! file_exists($filePath) || ! is_readable($filePath)) {
            // Not an error - file might not exist yet or have permission issues already reported
            return ['variables' => [], 'error' => null];
        }

        try {
            $lines = FileParser::getLines($filePath);
        } catch (\Throwable $e) {
            // Not an error - if we can't read the file for commented vars, it's already reported elsewhere
            return ['variables' => [], 'error' => null];
        }

        if (! is_array($lines) || empty($lines)) {
            return ['variables' => [], 'error' => null];
        }

        $commentedVars = [];

        foreach ($lines as $line) {
            if (! is_string($line)) {
                continue;
            }

            $line = trim($line);

            // Skip empty lines
            if ($line === '') {
                continue;
            }

            // Look for commented variable definitions: # KEY=VALUE or #KEY=VALUE
            if (preg_match('/^#\s*([A-Z_][A-Z0-9_]*)\s*=/', $line, $matches)) {
                $key = $matches[1];
                $commentedVars[$key] = $line;
            }
        }

        return ['variables' => $commentedVars, 'error' => null];
    }
}
