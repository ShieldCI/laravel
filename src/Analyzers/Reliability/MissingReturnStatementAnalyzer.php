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
 * Detects missing return statements in user's application code.
 *
 * Checks for:
 * - Methods/functions with return types that don't return values in all paths
 * - Missing return statements in non-void methods
 * - Code paths that don't return expected values
 */
class MissingReturnStatementAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanResults;

    /**
     * PHPStan patterns for detecting missing return statements.
     *
     * @var array<string>
     */
    private const MISSING_RETURN_STATEMENT_PATTERNS = [
        '* return statement is missing*',
        'Method * should return * but return statement is missing*',
        'Function * should return * but return statement is missing*',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'missing-return-statement',
            name: 'Missing Return Statements Analyzer',
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
                    recommendation: 'Install PHPStan to enable missing return statement detection. Run: composer require --dev phpstan/phpstan',
                    metadata: []
                )]
            );
        }

        try {
            // Run PHPStan on app directory
            $runner->analyze('app', 5);

            // Filter for missing return statement issues
            $issues = $runner->filterByPattern(self::MISSING_RETURN_STATEMENT_PATTERNS);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                []
            );
        }

        if ($issues->isEmpty()) {
            return $this->passed('No missing return statements detected');
        }

        // Use trait method to create issues
        $issueObjects = $this->createIssuesFromPHPStanResults(
            issues: $issues,
            issueMessage: 'Missing return statement detected',
            severity: Severity::High,
            recommendationCallback: fn (string $message) => $this->getRecommendation($message)
        );

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage(
            totalCount: $totalCount,
            displayedCount: $displayedCount,
            issueType: 'missing return statement(s)'
        );

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
