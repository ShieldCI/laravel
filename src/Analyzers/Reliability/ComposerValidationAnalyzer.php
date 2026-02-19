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
use ShieldCI\Support\ComposerValidator;

/**
 * Validates composer.json file integrity.
 *
 * Checks for:
 * - Valid JSON syntax in composer.json
 * - Composer validate command passes
 */
class ComposerValidationAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ComposerValidator $composerValidator = new ComposerValidator
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'composer-validation',
            name: 'Composer Validation Analyzer',
            description: 'Ensures composer.json file is valid and follows best practices',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['composer', 'dependencies', 'reliability', 'configuration'],
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $composerJsonPath = $this->buildPath('composer.json');

        if (! file_exists($composerJsonPath)) {
            return $this->resultBySeverity(
                'composer.json file not found',
                [$this->createIssue(
                    message: 'composer.json file is missing',
                    location: new Location('composer.json'),
                    severity: $this->metadata()->severity,
                    recommendation: 'Create a composer.json file in the root of your project. Run "composer init" to create one interactively.',
                    metadata: []
                )]
            );
        }

        // Check if composer.json is valid JSON
        $jsonValidationResult = $this->validateJsonSyntax($composerJsonPath);
        if ($jsonValidationResult !== null) {
            return $jsonValidationResult;
        }

        $basePath = $this->getBasePath();
        $result = $this->composerValidator->validate($basePath);

        if (! $result->successful) {
            return $this->resultBySeverity(
                'composer.json validation failed',
                [$this->createIssue(
                    message: 'composer validate command reported issues',
                    location: new Location($this->getRelativePath($composerJsonPath)),
                    severity: $this->metadata()->severity,
                    recommendation: 'Run "composer validate" to see full details and resolve the reported issues. Ensure version constraints and schema match Composer expectations.',
                    code: null,
                    metadata: ['composer_output' => trim($result->output)],
                )]
            );
        }

        return $this->passed('composer.json is valid');
    }

    /**
     * Validate JSON syntax of composer.json file.
     * Returns null if valid, or a ResultInterface with error if invalid.
     */
    private function validateJsonSyntax(string $composerJsonPath): ?ResultInterface
    {
        $content = FileParser::readFile($composerJsonPath);
        if ($content === null) {
            return $this->resultBySeverity(
                'Unable to read composer.json file',
                [$this->createIssue(
                    message: 'composer.json file exists but cannot be read',
                    location: new Location($this->getRelativePath($composerJsonPath)),
                    severity: $this->metadata()->severity,
                    recommendation: 'Check file permissions on composer.json. Ensure the file is readable by the web server user.',
                    metadata: []
                )]
            );
        }

        $decoded = json_decode($content, true);
        $jsonError = json_last_error();

        if ($jsonError !== JSON_ERROR_NONE) {
            return $this->resultBySeverity(
                'composer.json contains invalid JSON',
                [$this->createIssue(
                    message: 'composer.json is not valid JSON: '.json_last_error_msg(),
                    location: new Location($this->getRelativePath($composerJsonPath)),
                    severity: $this->metadata()->severity,
                    recommendation: 'Fix the JSON syntax errors in composer.json. Use a JSON validator or run "composer validate" to see specific errors. Common issues: missing commas, trailing commas, unescaped quotes.',
                    code: null,
                    metadata: [
                        'json_error' => json_last_error_msg(),
                    ]
                )]
            );
        }

        // Validate that decoded JSON is an object (composer.json should be an object, not an array or primitive)
        // Note: array_is_list([]) returns true, but empty objects are valid, so check non-empty arrays only
        if (! is_array($decoded) || (! empty($decoded) && array_is_list($decoded))) {
            return $this->resultBySeverity(
                'composer.json is not a valid JSON object',
                [$this->createIssue(
                    message: 'composer.json must be a JSON object, not a primitive value or array',
                    location: new Location($this->getRelativePath($composerJsonPath)),
                    severity: $this->metadata()->severity,
                    recommendation: 'composer.json must be a valid JSON object. Ensure the root element is an object (wrapped in curly braces {}), not an array (square brackets []).',
                    code: null,
                    metadata: []
                )]
            );
        }

        return null;
    }
}
