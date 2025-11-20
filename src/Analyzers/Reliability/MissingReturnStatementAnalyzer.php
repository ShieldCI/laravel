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
 * Detects missing return statements in user's application code.
 *
 * Checks for:
 * - Methods/functions with return types that don't return values in all paths
 * - Missing return statements in non-void methods
 * - Code paths that don't return expected values
 */
class MissingReturnStatementAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<string>
     */
    private array $patterns = [
        '* return statement is missing*',
        'Method * should return * but return statement is missing*',
        'Function * should return * but return statement is missing*',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'missing-return-statement',
            name: 'Missing Return Statements',
            description: 'Detects missing return statements in methods and functions using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'return-types', 'type-safety'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/missing-return-statement',
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $runner = new PHPStanRunner($this->basePath);

        // Run PHPStan on app directory at level 5
        $runner->analyze('app', 5);

        // Filter for missing return statement issues
        $issues = $runner->filterByPattern($this->patterns);

        if ($issues->isEmpty()) {
            return $this->passed('No missing return statements detected');
        }

        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Missing return statement detected',
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
            ? "Found {$totalCount} missing return statements (showing first {$displayedCount})"
            : "Found {$totalCount} missing return statement(s)";

        return $this->failed($message, $issueObjects);
    }

    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'Method') && str_contains($message, 'should return')) {
            return 'Add a return statement to the method. The method declares a return type but not all code paths return a value. Ensure every possible execution path returns the expected type, or change the return type to void if no value should be returned. PHPStan message: '.$message;
        }

        if (str_contains($message, 'Function') && str_contains($message, 'should return')) {
            return 'Add a return statement to the function. The function declares a return type but not all code paths return a value. Ensure every possible execution path returns the expected type. PHPStan message: '.$message;
        }

        if (str_contains($message, 'return statement is missing')) {
            return 'Add missing return statement. A return type is declared but the code does not return a value in all execution paths. Check if/else branches, switch cases, and exception handling to ensure all paths return the expected type. PHPStan message: '.$message;
        }

        return 'Fix the missing return statement. Ensure the method/function returns a value in all possible code paths. PHPStan message: '.$message;
    }
}
