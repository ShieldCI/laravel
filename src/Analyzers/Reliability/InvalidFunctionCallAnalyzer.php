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
 * Detects invalid function calls in user's application code.
 *
 * Checks for:
 * - Calls to undefined functions
 * - Invalid function signatures
 * - Type mismatches in function parameters
 * - Missing or unknown parameters
 */
class InvalidFunctionCallAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanResults;

    /**
     * PHPStan patterns for detecting invalid function calls.
     *
     * @var array<string>
     */
    private const INVALID_FUNCTION_CALL_PATTERNS = [
        'Function * not found*',
        'Function * invoked with * parameter*',
        'Parameter * of function * expects*',
        'Missing parameter * in call to function *',
        'Unknown parameter * in call to function *',
        'Parameter * of * expects * given*',
        'Result of function * (void) is used*',
        'Cannot call function * on *',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'invalid-function-calls',
            name: 'Invalid Function Calls Analyzer',
            description: 'Detects invalid function calls in application code using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'functions', 'type-safety'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/invalid-function-calls',
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
                    location: new Location($basePath),
                    severity: Severity::Medium,
                    recommendation: 'PHPStan is included with ShieldCI. If you\'re seeing this error, ensure you\'ve run `composer install` to install all dependencies. If the issue persists, verify that `vendor/bin/phpstan` exists in your project.',
                    metadata: []
                )]
            );
        }

        try {
            // Run PHPStan on app directory
            $runner->analyze('app', 5);

            // Filter for function call issues
            $issues = $runner->filterByPattern(self::INVALID_FUNCTION_CALL_PATTERNS);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                []
            );
        }

        if ($issues->isEmpty()) {
            return $this->passed('No invalid function calls detected');
        }

        // Use trait method to create issues
        $issueObjects = $this->createIssuesFromPHPStanResults(
            issues: $issues,
            issueMessage: 'Invalid function call detected',
            severity: Severity::High,
            recommendationCallback: fn (string $message) => $this->getRecommendation($message)
        );

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage(
            totalCount: $totalCount,
            displayedCount: $displayedCount,
            issueType: 'invalid function call(s)'
        );

        return $this->failed($message, $issueObjects);
    }

    /**
     * Get recommendation message based on PHPStan message.
     */
    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'not found')) {
            return 'Fix the function call - the function does not exist. Check for typos in the function name, ensure the function is defined, or verify the required extension/library is installed. PHPStan message: '.$message;
        }

        if (str_contains($message, 'Parameter') || str_contains($message, 'parameter')) {
            return 'Fix the function parameters - they do not match the function signature. Check the parameter types, order, and count. PHPStan message: '.$message;
        }

        if (str_contains($message, 'void')) {
            return 'The function returns void - you cannot use its return value. Remove the code that attempts to use the return value. PHPStan message: '.$message;
        }

        return 'Fix the function call issue detected by PHPStan. PHPStan message: '.$message;
    }
}
