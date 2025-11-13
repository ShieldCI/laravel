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
 * Detects dead code in user's application code.
 *
 * Checks for:
 * - Unreachable statements
 * - Unused variables and parameters
 * - Empty code blocks
 * - Code that doesn't do anything
 */
class DeadCodeAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<string>
     */
    private array $patterns = [
        '*does not do anything*',
        'Unreachable statement*',
        '* is unused*',
        'Empty array passed*',
        'Dead catch*',
        '*has no effect*',
        '*will never be executed*',
        'Left side of && is always *',
        'Left side of || is always *',
        'Right side of && is always *',
        'Right side of || is always *',
        'Result of && is always *',
        'Result of || is always *',
        'Negated boolean expression is always *',
        'Strict comparison using * will always evaluate to *',
        'Comparison operation * between * and * is always *',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'dead-code',
            name: 'Dead Code Detection',
            description: 'Detects unreachable code, unused variables, and statements that have no effect using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::Medium,
            tags: ['phpstan', 'static-analysis', 'dead-code', 'code-quality'],
            docsUrl: 'https://phpstan.org/user-guide/getting-started'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $runner = new PHPStanRunner($this->basePath);

        // Run PHPStan on app directory at level 5
        $runner->analyze('app', 5);

        // Filter for dead code issues
        $issues = $runner->filterByPattern($this->patterns);

        if ($issues->isEmpty()) {
            return $this->passed('No dead code detected');
        }

        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Dead code detected',
                location: new Location($issue['file'], $issue['line']),
                severity: Severity::Medium,
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
            ? "Found {$totalCount} dead code issues (showing first {$displayedCount})"
            : "Found {$totalCount} dead code issue(s)";

        return $this->failed($message, $issueObjects);
    }

    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'Unreachable statement')) {
            return 'Remove unreachable code - this statement will never be executed. Check for early returns, throws, or exits before this code. PHPStan message: '.$message;
        }

        if (str_contains($message, 'is unused')) {
            return 'Remove unused code - this variable, parameter, or import is never used. Clean up your code by removing it. PHPStan message: '.$message;
        }

        if (str_contains($message, 'does not do anything')) {
            return 'This statement has no effect - it does not modify state or return a value. Either use the result or remove the statement. PHPStan message: '.$message;
        }

        if (str_contains($message, 'always')) {
            return 'Remove redundant condition - this expression always evaluates to the same value. Simplify your logic or remove the dead branch. PHPStan message: '.$message;
        }

        return 'Fix the dead code issue detected by PHPStan. PHPStan message: '.$message;
    }
}
