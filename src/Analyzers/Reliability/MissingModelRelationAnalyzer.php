<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
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
    /**
     * @var array<string>
     */
    private array $patterns = [
        'Relation * is not found in * model*',
        'Call to an undefined method *Model::*',
        'Access to an undefined property *Model::$*',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'missing-model-relation',
            name: 'Missing Model Relations',
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
        $runner = new PHPStanRunner($this->basePath);

        // Run PHPStan on app directory at level 5
        $runner->analyze('app', 5);

        // Filter for model relation issues
        $issues = $runner->filterByPattern($this->patterns);

        // Additionally filter by text to catch relation-specific messages
        $relationIssues = $runner->filterByText('relation');

        // Merge unique issues
        $allIssues = $issues->merge($relationIssues)->unique(function ($issue) {
            return $issue['file'].$issue['line'].$issue['message'];
        });

        if ($allIssues->isEmpty()) {
            return $this->passed('No missing model relations detected');
        }

        $issueObjects = [];

        foreach ($allIssues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Missing or invalid model relation detected',
                location: new Location($issue['file'], $issue['line']),
                severity: Severity::High,
                recommendation: $this->getRecommendation($issue['message']),
                metadata: [
                    'phpstan_message' => $issue['message'],
                    'file' => $issue['file'],
                    'line' => $issue['line'],
                ]
            );
        }

        $totalCount = $allIssues->count();
        $displayedCount = count($issueObjects);

        $message = $totalCount > $displayedCount
            ? "Found {$totalCount} missing model relations (showing first {$displayedCount})"
            : "Found {$totalCount} missing model relation(s)";

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
}
