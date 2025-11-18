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
 * Validates composer.json file integrity.
 *
 * Checks for:
 * - Valid JSON syntax in composer.json
 * - Required fields are present
 * - Composer validate command passes
 */
class ComposerValidationAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'composer-validation',
            name: 'Composer Validation',
            description: 'Ensures composer.json file is valid and follows best practices',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['composer', 'dependencies', 'reliability', 'configuration'],
            docsUrl: 'https://getcomposer.org/doc/03-cli.md#validate'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $composerJsonPath = $this->basePath.'/composer.json';

        if (! file_exists($composerJsonPath)) {
            return $this->failed(
                'composer.json file not found',
                [$this->createIssue(
                    message: 'composer.json file is missing',
                    location: new Location($this->basePath, 0),
                    severity: Severity::Critical,
                    recommendation: 'Create a composer.json file in the root of your project. Run "composer init" to create one interactively.',
                    metadata: []
                )]
            );
        }

        // Check if composer.json is valid JSON
        $content = FileParser::readFile($composerJsonPath);
        if ($content === null) {
            return $this->failed('Unable to read composer.json file');
        }

        json_decode($content);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return $this->failed(
                'composer.json contains invalid JSON',
                [$this->createIssue(
                    message: 'composer.json is not valid JSON: '.json_last_error_msg(),
                    location: new Location($composerJsonPath, 1),
                    severity: Severity::Critical,
                    recommendation: 'Fix the JSON syntax errors in composer.json. Use a JSON validator or run "composer validate" to see specific errors. Common issues: missing commas, trailing commas, unescaped quotes.',
                    metadata: [
                        'json_error' => json_last_error_msg(),
                    ]
                )]
            );
        }

        // Run composer validate command
        $currentDir = getcwd();
        if ($currentDir === false) {
            return $this->warning('Unable to determine current directory');
        }

        chdir($this->basePath);

        $output = shell_exec('composer validate --no-check-publish 2>&1');

        chdir($currentDir);

        if ($output === null || $output === false) {
            return $this->warning('Unable to run composer validate command');
        }

        // Check if validation passed
        if (! str_contains((string) $output, 'is valid')) {
            return $this->failed(
                'composer.json validation failed',
                [$this->createIssue(
                    message: 'composer validate command reported issues',
                    location: new Location($composerJsonPath, 1),
                    severity: Severity::High,
                    recommendation: 'Run "composer validate" to see detailed validation errors. Fix the reported issues in composer.json. Common issues: invalid version constraints, deprecated fields, missing required fields.',
                    metadata: [
                        'composer_output' => trim($output),
                    ]
                )]
            );
        }

        return $this->passed('composer.json is valid');
    }
}
