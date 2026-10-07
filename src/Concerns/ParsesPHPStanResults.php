<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;

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
     * The identifier and tip keys are deliberately optional: this trait only needs
     * file/line/message, so accepting a wider shape than PHPStanRunner produces keeps
     * callers that build issues by hand working unchanged.
     *
     * @param  Collection<int, array{file: string, line: int, message: string, identifier?: string|null, tip?: string|null}>  $issues
     * @param  string  $issueMessage  The message to display for each issue
     * @param  Severity  $severity  The severity level for issues
     * @param  callable(string, ?string): string  $recommendationCallback  Callback to generate recommendations from the message and identifier
     * @return array<int, Issue>
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

            $identifier = isset($issue['identifier']) && is_string($issue['identifier']) ? $issue['identifier'] : null;
            $tip = isset($issue['tip']) && is_string($issue['tip']) ? $issue['tip'] : null;

            // PHPStan's own tip is often the actionable half of the error, and it is the
            // only guidance available for issues we could not categorise.
            $recommendation = $recommendationCallback($message, $identifier);

            if ($tip !== null) {
                $recommendation .= ' PHPStan tip: '.$tip;
            }

            $issueObjects[] = $this->createIssueWithSnippet(
                message: $issueMessage,
                filePath: $file,
                lineNumber: $line,
                severity: $severity,
                recommendation: $recommendation,
                metadata: [
                    'phpstan_message' => $message,
                    'phpstan_identifier' => $identifier,
                    'phpstan_tip' => $tip,
                    'file' => $file,
                    'line' => $line,
                    'code' => 'phpstan',
                ]
            );
        }

        return $issueObjects;
    }

    /**
     * Condense analysis errors into one bounded clause for a result message.
     *
     * A reportUnmatchedIgnoredErrors run can produce dozens of these. The full list always
     * reaches the caller through the analysis_errors metadata key; the message quotes the
     * leaders and counts the rest.
     *
     * The cap is a parameter rather than a constant because constants in traits need
     * PHP 8.2 and this package supports 8.1.
     *
     * @param  list<string>  $analysisErrors
     */
    protected function summarizeAnalysisErrors(array $analysisErrors, int $limit = 3): string
    {
        $quoted = array_slice($analysisErrors, 0, $limit);
        $summary = implode(' | ', $quoted);
        $remaining = count($analysisErrors) - count($quoted);

        if ($remaining > 0) {
            $summary .= sprintf(' (and %d more)', $remaining);
        }

        return $summary;
    }

    /**
     * Describe a run that reported errors it could not attach to a file.
     *
     * @param  list<string>  $analysisErrors
     */
    protected function describeAnalysisErrors(array $analysisErrors): string
    {
        return sprintf(
            'PHPStan reported %d analysis error(s): %s',
            count($analysisErrors),
            $this->summarizeAnalysisErrors($analysisErrors)
        );
    }

    /**
     * Note on a findings message that the run behind it did not complete cleanly.
     *
     * PHPStan throws away the file results when it hits an internal error, so findings
     * that arrive next to one are a partial view and have to say so. Returns the message
     * untouched when the run was clean.
     *
     * @param  list<string>  $analysisErrors
     */
    protected function appendAnalysisErrorNotice(string $message, array $analysisErrors): string
    {
        if ($analysisErrors === []) {
            return $message;
        }

        return $message.sprintf(
            '. PHPStan also reported %d analysis error(s), so these findings may be incomplete: %s',
            count($analysisErrors),
            $this->summarizeAnalysisErrors($analysisErrors)
        );
    }

    /**
     * Name each file PHPStan stopped at, once, by its first error.
     *
     * php-parser recovers from a syntax error and reports the next, so one broken file
     * can carry several errors. The line is dropped when PHPStan had none to give, as for
     * a reflection error.
     *
     * @param  Collection<int, array{file: string, line: int, message: string, identifier?: string|null, tip?: string|null}>  $runStoppingErrors
     * @return list<string>
     */
    protected function stoppedAtFiles(Collection $runStoppingErrors): array
    {
        return array_values($runStoppingErrors
            ->unique('file')
            ->map(function (array $issue): string {
                $path = $this->getRelativePath($issue['file']);

                return $issue['line'] > 0 ? $path.':'.$issue['line'] : $path;
            })
            ->all());
    }

    /**
     * Describe a run that PHPStan cut short at files it could not process.
     *
     * @param  list<string>  $stoppedAt
     */
    protected function describeIncompleteRun(array $stoppedAt): string
    {
        return sprintf(
            'PHPStan stopped at %d file(s) it could not process, so the rest of the project was not analysed: %s',
            count($stoppedAt),
            $this->summarizeAnalysisErrors($stoppedAt)
        );
    }

    /**
     * Note on a findings message that PHPStan never reached the rest of the project.
     *
     * Returns the message untouched when PHPStan covered the project.
     *
     * @param  list<string>  $stoppedAt
     */
    protected function appendIncompleteRunNotice(string $message, array $stoppedAt): string
    {
        if ($stoppedAt === []) {
            return $message;
        }

        return $message.'. '.$this->describeIncompleteRun($stoppedAt);
    }

    /**
     * Describe a run that left nothing to report but did not complete.
     *
     * @param  list<string>  $analysisErrors
     * @param  list<string>  $stoppedAt
     */
    protected function describeIncompleteRunWithoutFindings(array $analysisErrors, array $stoppedAt): string
    {
        $parts = [];

        if ($stoppedAt !== []) {
            $parts[] = $this->describeIncompleteRun($stoppedAt);
        }

        if ($analysisErrors !== []) {
            $parts[] = $this->describeAnalysisErrors($analysisErrors);
        }

        return implode('. ', $parts);
    }

    /**
     * Result metadata for a run that did not complete, each key present only when it has entries.
     *
     * @param  list<string>  $analysisErrors
     * @param  list<string>  $stoppedAt
     * @return array{analysis_errors?: list<string>, stopped_at?: list<string>}
     */
    protected function incompleteRunMetadata(array $analysisErrors, array $stoppedAt): array
    {
        $metadata = [];

        if ($analysisErrors !== []) {
            $metadata['analysis_errors'] = $analysisErrors;
        }

        if ($stoppedAt !== []) {
            $metadata['stopped_at'] = $stoppedAt;
        }

        return $metadata;
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
        ?int $lineNumber,
        Severity $severity,
        string $recommendation,
        ?int $column = null,
        ?int $contextLines = null,
        array $metadata = []
    ): Issue;

    /**
     * Provided by AbstractAnalyzer.
     */
    abstract protected function getRelativePath(string $file): string;
}
