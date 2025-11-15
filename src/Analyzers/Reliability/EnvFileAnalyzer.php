<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
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
            docsUrl: 'https://laravel.com/docs/configuration#environment-configuration'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $envPath = $this->basePath.'/.env';

        if (! file_exists($envPath)) {
            return $this->failed(
                'Application .env file is missing',
                [$this->createIssue(
                    message: 'The .env file does not exist',
                    location: new Location($this->basePath, 0),
                    severity: Severity::Critical,
                    recommendation: 'Create a .env file in your application root directory. Copy .env.example to .env and configure your environment variables. Without a .env file, your application cannot load configuration and will fail to run. Run: cp .env.example .env',
                    metadata: [
                        'env_path' => $envPath,
                        'env_example_exists' => file_exists($this->basePath.'/.env.example'),
                    ]
                )]
            );
        }

        return $this->passed('.env file exists');
    }
}
