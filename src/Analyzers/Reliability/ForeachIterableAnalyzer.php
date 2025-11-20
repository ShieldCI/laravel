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
 * Detects invalid foreach usage in user's application code.
 *
 * Checks for:
 * - Non-iterable values in foreach loops
 * - Type mismatches in foreach arguments
 * - Incorrect foreach usage patterns
 */
class ForeachIterableAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<string>
     */
    private array $patterns = [
        'Argument of an invalid type * supplied for foreach*',
        'Cannot use * in a foreach loop*',
        'Iterating over * but * does not specify*',
        'Argument * supplied for foreach is*',
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
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/foreach-iterable'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $runner = new PHPStanRunner($this->basePath);

        // Run PHPStan on app directory at level 5
        $runner->analyze('app', 5);

        // Filter for foreach iterable issues
        $issues = $runner->filterByPattern($this->patterns);

        if ($issues->isEmpty()) {
            return $this->passed('No invalid foreach usage detected');
        }

        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Invalid foreach usage detected',
                location: new Location($issue['file'], $issue['line']),
                severity: Severity::High,
                recommendation: 'Fix the foreach loop - ensure the variable being iterated is iterable (array, Traversable, or Iterator). Check the type of the variable before using it in a foreach loop. PHPStan message: '.$issue['message'],
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
            ? "Found {$totalCount} invalid foreach usages (showing first {$displayedCount})"
            : "Found {$totalCount} invalid foreach usage(s)";

        return $this->failed($message, $issueObjects);
    }
}
