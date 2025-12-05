<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\ParsesPHPStanResults;
use ShieldCI\Support\PHPStanRunner;

/**
 * Detects references to non-existent Eloquent model relations.
 *
 * Checks for:
 * - Calls to undefined model relations
 * - Typos in relation names
 * - Missing relationship methods
 */
class MissingModelRelationAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanResults;

    /**
     * PHPStan patterns for detecting missing model relations.
     *
     * @var array<string>
     */
    private const MISSING_MODEL_RELATION_PATTERNS = [
        'Relation * is not found in * model*',
        'Call to an undefined method *Model::*',
        'Access to an undefined property *Model::$*',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'missing-model-relation',
            name: 'Missing Model Relations Analyzer',
            description: 'Detects references to non-existent Eloquent model relations using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'eloquent', 'relations', 'models'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/missing-model-relation',
            timeToFix: 20
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $basePath = $this->getBasePath();

        $runner = new PHPStanRunner($basePath);

        // Check if PHPStan is available
        if (! $runner->isAvailable()) {
            return $this->warning(
                'PHPStan is not available',
                [$this->createIssue(
                    message: 'PHPStan binary not found',
                    location: new Location($basePath, 1),
                    severity: Severity::Medium,
                    recommendation: 'PHPStan is included with ShieldCI. If you\'re seeing this error, ensure you\'ve run `composer install` to install all dependencies. If the issue persists, verify that `vendor/bin/phpstan` exists in your project.',
                    metadata: []
                )]
            );
        }

        try {
            // Run PHPStan on app directory
            $runner->analyze('app', 5);

            // Filter for model relation issues
            $issues = $runner->filterByPattern(self::MISSING_MODEL_RELATION_PATTERNS);

            // Additionally filter by text to catch relation-specific messages
            $relationIssues = $runner->filterByText('relation');

            // Merge unique issues
            $allIssues = $this->mergeUniqueIssues($issues, $relationIssues);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                []
            );
        }

        if ($allIssues->isEmpty()) {
            return $this->passed('No missing model relations detected');
        }

        // Use trait method to create issues
        $issueObjects = $this->createIssuesFromPHPStanResults(
            issues: $allIssues,
            issueMessage: 'Missing or invalid model relation detected',
            severity: Severity::High,
            recommendationCallback: fn (string $message) => $this->getRecommendation($message)
        );

        $totalCount = $allIssues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage(
            totalCount: $totalCount,
            displayedCount: $displayedCount,
            issueType: 'missing model relation(s)'
        );

        return $this->failed($message, $issueObjects);
    }

    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'Relation') && str_contains($message, 'not found')) {
            return 'Define the missing relation method in your Eloquent model. This is likely a typo in the relation name or a missing relationship method. Check your model class for the correct relation name. PHPStan message: '.$message;
        }

        if (str_contains($message, 'undefined method') && str_contains($message, 'Model')) {
            return 'The relation method does not exist on the model. Either define the relationship method (hasMany, belongsTo, etc.) or fix the typo in the relation name. PHPStan message: '.$message;
        }

        if (str_contains($message, 'undefined property') && str_contains($message, 'Model')) {
            return 'Accessing an undefined property on the model. This might be a dynamic relation property. Ensure the relation method exists in the model. PHPStan message: '.$message;
        }

        return 'Fix the model relation issue. Ensure the relationship method is defined in the Eloquent model and the name is spelled correctly. PHPStan message: '.$message;
    }

    /**
     * Merge and deduplicate issues from pattern and text filters.
     *
     * @param  \Illuminate\Support\Collection<int, array{file: string, line: int, message: string}>  $patternIssues
     * @param  \Illuminate\Support\Collection<int, array{file: string, line: int, message: string}>  $textIssues
     * @return \Illuminate\Support\Collection<int, array{file: string, line: int, message: string}>
     */
    private function mergeUniqueIssues(
        \Illuminate\Support\Collection $patternIssues,
        \Illuminate\Support\Collection $textIssues
    ): \Illuminate\Support\Collection {
        $uniqueIssues = [];
        $seenKeys = [];

        foreach ($patternIssues->merge($textIssues) as $issue) {
            // Validate issue structure
            if (! isset($issue['file'], $issue['line'], $issue['message'])) {
                continue;
            }

            // Create unique key
            $key = $issue['file'].':'.$issue['line'].':'.$issue['message'];

            if (! isset($seenKeys[$key])) {
                $seenKeys[$key] = true;
                $uniqueIssues[] = $issue;
            }
        }

        return collect($uniqueIssues);
    }
}
