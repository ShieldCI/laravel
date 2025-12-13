<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Enums\Severity;

/**
 * Shared functionality for analyzers that parse PHPStan results.
 *
 * This trait eliminates code duplication across analyzers that use PHPStan
 * for static analysis (DeadCodeAnalyzer, DeprecatedCodeAnalyzer, etc.).
 */
trait ParsesPHPStanResults
{
    /**
     * Create issue objects from PHPStan results.
     *
     * @param  Collection<int, array{file: string, line: int, message: string}>  $issues
     * @param  string  $issueMessage  The message to display for each issue
     * @param  Severity  $severity  The severity level for issues
     * @param  callable(string): string  $recommendationCallback  Callback to generate recommendations
     * @return array<int, \ShieldCI\AnalyzersCore\ValueObjects\Issue>
     */
    protected function createIssuesFromPHPStanResults(
        Collection $issues,
        string $issueMessage,
        Severity $severity,
        callable $recommendationCallback
    ): array {
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

            $issueObjects[] = $this->createIssueWithSnippet(
                message: $issueMessage,
                filePath: $file,
                lineNumber: $line,
                severity: $severity,
                recommendation: $recommendationCallback($message),
                code: 'phpstan',
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
     * Format the issue count message.
     *
     * @param  int  $totalCount  Total number of issues found
     * @param  int  $displayedCount  Number of issues being displayed
     * @param  string  $issueType  Type of issue (e.g., 'dead code issues', 'deprecated code usages')
     */
    protected function formatIssueCountMessage(int $totalCount, int $displayedCount, string $issueType): string
    {
        if ($totalCount > $displayedCount) {
            return sprintf(
                'Found %d %s (showing first %d)',
                $totalCount,
                $issueType,
                $displayedCount
            );
        }

        return sprintf('Found %d %s', $totalCount, $issueType);
    }

    /**
     * Abstract method that must be implemented by the using class.
     * This is provided by AbstractAnalyzer.
     *
     * @param  array<string, mixed>  $metadata
     */
    abstract protected function createIssueWithSnippet(
        string $message,
        string $filePath,
        int $lineNumber,
        Severity $severity,
        string $recommendation,
        ?int $column = null,
        ?int $contextLines = null,
        ?string $code = null,
        array $metadata = []
    ): \ShieldCI\AnalyzersCore\ValueObjects\Issue;
}
