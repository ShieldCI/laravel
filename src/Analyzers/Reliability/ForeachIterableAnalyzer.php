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
 * Detects invalid foreach usage in user's application code.
 *
 * Checks for:
 * - Non-iterable values in foreach loops
 * - Type mismatches in foreach arguments
 * - Incorrect foreach usage patterns
 */
class ForeachIterableAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanResults;

    /**
     * PHPStan patterns for detecting invalid foreach usage.
     *
     * @var array<string>
     */
    private const FOREACH_ITERABLE_PATTERNS = [
        'Argument of an invalid type * supplied for foreach*',
        'Cannot use * in a foreach loop*',
        'Iterating over * but * does not specify*',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'foreach-iterable',
            name: 'Foreach Iterable Validation',
            description: 'Detects invalid foreach usage with non-iterable values using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'foreach', 'type-safety'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/foreach-iterable',
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
                    recommendation: 'PHPStan is included with ShieldCI. If you\'re seeing this error, ensure you\'ve run `composer install` to install all dependencies. If the issue persists, verify that `vendor/bin/phpstan` exists in your project.',
                    metadata: []
                )]
            );
        }

        try {
            // Run PHPStan on app directory
            $runner->analyze('app', 5);

            // Filter for foreach iterable issues
            $issues = $runner->filterByPattern(self::FOREACH_ITERABLE_PATTERNS);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                []
            );
        }

        if ($issues->isEmpty()) {
            return $this->passed('No invalid foreach usage detected');
        }

        // Use trait method to create issues
        $issueObjects = $this->createIssuesFromPHPStanResults(
            issues: $issues,
            issueMessage: 'Invalid foreach usage detected',
            severity: Severity::High,
            recommendationCallback: fn (string $message) => $this->getRecommendation($message)
        );

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage(
            totalCount: $totalCount,
            displayedCount: $displayedCount,
            issueType: 'invalid foreach usage(s)'
        );

        return $this->failed($message, $issueObjects);
    }

    /**
     * Get recommendation message based on PHPStan message.
     */
    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'invalid type')) {
            return 'Fix the foreach loop - the variable being iterated is not of an iterable type. Ensure the variable is an array, Traversable, or Iterator before using it in a foreach loop. PHPStan message: '.$message;
        }

        if (str_contains($message, 'Cannot use')) {
            return 'Fix the foreach loop - the value cannot be used in a foreach loop. Check the type of the variable and ensure it implements Traversable or is an array. PHPStan message: '.$message;
        }

        if (str_contains($message, 'does not specify')) {
            return 'Fix the foreach loop - the type does not specify that it is iterable. Add proper type hints or ensure the variable is iterable before using it in a foreach loop. PHPStan message: '.$message;
        }

        return 'Fix the foreach loop - ensure the variable being iterated is iterable (array, Traversable, or Iterator). Check the type of the variable before using it in a foreach loop. PHPStan message: '.$message;
    }
}
