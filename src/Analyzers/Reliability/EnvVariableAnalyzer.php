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
        $envExamplePath = $this->basePath.'/.env.example';
        $envPath = $this->basePath.'/.env';

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
                    location: new Location($this->basePath, 0),
                    severity: Severity::Critical,
                    recommendation: 'Create a .env file by copying .env.example: "cp .env.example .env". Then configure the environment variables with appropriate values for your environment.',
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
                location: new Location($envPath, 1),
                severity: Severity::High,
                recommendation: 'Add the following environment variables to your .env file: '.implode(', ', array_keys($missingVars)).'. '.
                               'These variables are defined in .env.example and may be required for the application to function correctly. '.
                               'Copy them from .env.example and set appropriate values.',
                metadata: [
                    'missing_count' => count($missingVars),
                    'missing_variables' => array_keys($missingVars),
                ]
            )]
        );
    }

    /**
     * Parse environment file and return key-value pairs.
     *
     * @return array<string, string>
     */
    private function parseEnvFile(string $filePath): array
    {
        $lines = FileParser::getLines($filePath);

        if (empty($lines)) {
            return [];
        }
        $variables = [];

        foreach ($lines as $line) {
            $line = trim($line);

            // Skip empty lines and comments
            if (empty($line) || str_starts_with($line, '#')) {
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
