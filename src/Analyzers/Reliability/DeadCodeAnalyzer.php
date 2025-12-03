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
     * PHPStan patterns for detecting dead code.
     *
     * @var array<string>
     */
    private const DEAD_CODE_PATTERNS = [
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
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/dead-code',
            timeToFix: 5
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
                    recommendation: 'Install PHPStan to enable dead code detection. Run: composer require --dev phpstan/phpstan',
                    metadata: []
                )]
            );
        }

        try {
            // Run PHPStan on app directory
            $runner->analyze('app', 5);

            // Filter for dead code issues
            $issues = $runner->filterByPattern(self::DEAD_CODE_PATTERNS);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                [
                    'exception' => get_class($e),
                    'error_message' => $e->getMessage(),
                ]
            );
        }

        if ($issues->isEmpty()) {
            return $this->passed('No dead code detected');
        }

        $issueObjects = $this->createIssuesFromPHPStanResults($issues);

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage($totalCount, $displayedCount);

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

    /**
     * Create issue objects from PHPStan results.
     *
     * @param  \Illuminate\Support\Collection<int, array{file: string, line: int, message: string}>  $issues
     * @return array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>
     */
    private function createIssuesFromPHPStanResults(\Illuminate\Support\Collection $issues): array
    {
        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            // Validate issue structure
            if (! isset($issue['file'], $issue['line'], $issue['message'])) {
                continue;
            }

            $file = $issue['file'];
            $line = $issue['line'];
            $message = $issue['message'];

            // Validate types
            if (! is_string($file) || ! is_string($message)) {
                continue;
            }

            // Validate line number
            if (! is_int($line) || $line < 1) {
                $line = 1;
            }

            $issueObjects[] = $this->createIssue(
                message: 'Dead code detected',
                location: new Location($file, $line),
                severity: Severity::Medium,
                recommendation: $this->getRecommendation($message),
                code: $this->getCodeSnippetSafely($file, $line),
                metadata: [
                    'phpstan_message' => $message,
                    'file' => $file,
                    'line' => $line,
                ]
            );
        }

        return $issueObjects;
    }

    /**
     * Safely get code snippet, handling missing files.
     */
    private function getCodeSnippetSafely(string $file, int $line): ?string
    {
        if (! file_exists($file)) {
            return null;
        }

        return FileParser::getCodeSnippet($file, $line);
    }

    /**
     * Format the issue count message.
     */
    private function formatIssueCountMessage(int $totalCount, int $displayedCount): string
    {
        if ($totalCount > $displayedCount) {
            return sprintf(
                'Found %d dead code issues (showing first %d)',
                $totalCount,
                $displayedCount
            );
        }

        return sprintf('Found %d dead code issue(s)', $totalCount);
    }
}
