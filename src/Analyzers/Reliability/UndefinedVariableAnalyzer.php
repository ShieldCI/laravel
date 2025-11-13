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
 * Detects usage of undefined variables in user's application code.
 *
 * Checks for:
 * - References to undefined variables
 * - Variables that might not be defined
 * - Potential typos in variable names
 */
class UndefinedVariableAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<string>
     */
    private array $patterns = [
        'Undefined variable*',
        'Variable * might not be defined*',
        'Variable * in isset* always exists*',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'undefined-variable',
            name: 'Undefined Variable Usage',
            description: 'Detects references to undefined variables using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'variables', 'type-safety'],
            docsUrl: 'https://phpstan.org/user-guide/getting-started'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $runner = new PHPStanRunner($this->basePath);

        // Run PHPStan on app directory at level 5
        $runner->analyze('app', 5);

        // Filter for undefined variable issues
        $issues = $runner->filterByPattern($this->patterns);

        if ($issues->isEmpty()) {
            return $this->passed('No undefined variables detected');
        }

        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Undefined variable detected',
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

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $totalCount > $displayedCount
            ? "Found {$totalCount} undefined variables (showing first {$displayedCount})"
            : "Found {$totalCount} undefined variable(s)";

        return $this->failed($message, $issueObjects);
    }

    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'might not be defined')) {
            return 'Variable might not be defined in all code paths. Ensure the variable is initialized before use in all possible execution paths (e.g., in both if/else branches). PHPStan message: '.$message;
        }

        if (str_contains($message, 'Undefined variable')) {
            return 'Variable is used before being defined. Initialize the variable before using it, or check for typos in the variable name. PHPStan message: '.$message;
        }

        if (str_contains($message, 'always exists')) {
            return 'Remove unnecessary isset() check - the variable is guaranteed to exist at this point. This check is redundant. PHPStan message: '.$message;
        }

        return 'Fix the undefined variable issue. Ensure all variables are properly initialized before use. PHPStan message: '.$message;
    }
}
