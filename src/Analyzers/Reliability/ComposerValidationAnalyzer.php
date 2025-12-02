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
 * - Required fields are present
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
            name: 'Composer Validation',
            description: 'Ensures composer.json file is valid and follows best practices',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['composer', 'dependencies', 'reliability', 'configuration'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/composer-validation',
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $composerJsonPath = $this->buildPath('composer.json');

        if (! file_exists($composerJsonPath)) {
            $basePath = $this->getBasePath();

            return $this->failed(
                'composer.json file not found',
                [$this->createIssue(
                    message: 'composer.json file is missing',
                    location: new Location($basePath, 1),
                    severity: Severity::Critical,
                    recommendation: 'Create a composer.json file in the root of your project. Run "composer init" to create one interactively.',
                    code: FileParser::getCodeSnippet($basePath, 1),
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
            return $this->failed(
                'composer.json validation failed',
                [$this->createIssue(
                    message: 'composer validate command reported issues',
                    location: new Location($composerJsonPath, 1),
                    severity: Severity::High,
                    recommendation: 'Run "composer validate" to see full details and resolve the reported issues. Ensure version constraints and schema match Composer expectations.',
                    code: FileParser::getCodeSnippet($composerJsonPath, 1),
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
            return $this->failed('Unable to read composer.json file');
        }

        $decoded = json_decode($content, true);
        $jsonError = json_last_error();

        if ($jsonError !== JSON_ERROR_NONE) {
            return $this->failed(
                'composer.json contains invalid JSON',
                [$this->createIssue(
                    message: 'composer.json is not valid JSON: '.json_last_error_msg(),
                    location: new Location($composerJsonPath, 1),
                    severity: Severity::Critical,
                    recommendation: 'Fix the JSON syntax errors in composer.json. Use a JSON validator or run "composer validate" to see specific errors. Common issues: missing commas, trailing commas, unescaped quotes.',
                    code: FileParser::getCodeSnippet($composerJsonPath, 1),
                    metadata: [
                        'json_error' => json_last_error_msg(),
                    ]
                )]
            );
        }

        // Validate that decoded JSON is an array/object (composer.json should be an object)
        if (! is_array($decoded)) {
            return $this->failed(
                'composer.json is not a valid JSON object',
                [$this->createIssue(
                    message: 'composer.json must be a JSON object, not a primitive value or array',
                    location: new Location($composerJsonPath, 1),
                    severity: Severity::Critical,
                    recommendation: 'composer.json must be a valid JSON object. Ensure the root element is an object (wrapped in curly braces {}).',
                    code: FileParser::getCodeSnippet($composerJsonPath, 1),
                    metadata: []
                )]
            );
        }

        return null;
    }
}
