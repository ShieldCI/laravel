<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\CodeQuality;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Finds TODO/FIXME/HACK comments in code.
 *
 * Checks for:
 * - TODO, FIXME, HACK, XXX, BUG keywords
 * - Case-insensitive matching
 * - Reports location and context
 */
class TodoCommentAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Comment keywords to detect.
     *
     * @var array<string, array{severity: string, description: string}>
     */
    private array $keywords = [
        'TODO' => [
            'severity' => 'low',
            'description' => 'Planned work that needs to be done',
        ],
        'FIXME' => [
            'severity' => 'medium',
            'description' => 'Code that needs to be fixed',
        ],
        'HACK' => [
            'severity' => 'high',
            'description' => 'Temporary workaround that should be refactored',
        ],
        'XXX' => [
            'severity' => 'high',
            'description' => 'Warning or important note',
        ],
        'BUG' => [
            'severity' => 'high',
            'description' => 'Known bug that needs attention',
        ],
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'todo-comment',
            name: 'Todo Comment',
            description: 'Finds TODO/FIXME/HACK comments that should be addressed or tracked in issue tracker',
            category: Category::CodeQuality,
            severity: Severity::Low,
            tags: ['maintainability', 'code-quality', 'technical-debt', 'comments'],
            docsUrl: 'https://wiki.c2.com/?TodoCommentsConsideredHarmful'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            $content = file_get_contents($file);

            if ($content === false) {
                continue;
            }

            $lines = explode("\n", $content);

            foreach ($lines as $lineNumber => $line) {
                foreach ($this->keywords as $keyword => $config) {
                    // Case-insensitive search for keyword
                    if (preg_match('/\b'.$keyword.'\b/i', $line, $matches)) {
                        $context = trim($line);

                        // Remove comment markers for cleaner display
                        $context = preg_replace('/^\s*\/\/\s*/', '', $context) ?? $context;
                        $context = preg_replace('/^\s*\/\*+\s*/', '', $context) ?? $context;
                        $context = preg_replace('/^\s*\*+\s*/', '', $context) ?? $context;
                        $context = trim($context);

                        $issues[] = $this->createIssue(
                            message: "{$keyword} comment found: {$context}",
                            location: new Location($file, $lineNumber + 1),
                            severity: $this->mapSeverity($config['severity']),
                            recommendation: $this->getRecommendation($keyword, $context, $config['description']),
                            metadata: [
                                'keyword' => $keyword,
                                'comment' => $context,
                                'type' => $config['description'],
                                'file' => $file,
                            ]
                        );

                        // Only report first keyword found on each line
                        break;
                    }
                }
            }
        }

        if (empty($issues)) {
            return $this->passed('No TODO/FIXME/HACK comments detected');
        }

        $totalIssues = count($issues);
        $summary = $this->getSummary($issues);

        return $this->warning(
            "Found {$totalIssues} TODO/FIXME/HACK comment(s): {$summary}",
            $issues
        );
    }

    /**
     * Map severity string to enum.
     */
    private function mapSeverity(string $severity): Severity
    {
        return match ($severity) {
            'critical' => Severity::Critical,
            'high' => Severity::High,
            'medium' => Severity::Medium,
            'low' => Severity::Low,
            default => Severity::Low,
        };
    }

    /**
     * Get recommendation based on keyword type.
     */
    private function getRecommendation(string $keyword, string $context, string $description): string
    {
        $base = "{$description}. ";

        $recommendations = match ($keyword) {
            'TODO' => [
                'Create a GitHub/Jira issue to track this work',
                'Include the issue reference in the comment if keeping it',
                'Consider if this work should be completed before deployment',
                'Remove TODO comments for completed work',
            ],
            'FIXME' => [
                'This indicates broken or suboptimal code that needs fixing',
                'Prioritize fixing this before deploying to production',
                'Create an issue with high priority',
                'Document why it needs fixing and the impact',
            ],
            'HACK' => [
                'This is a temporary workaround that should be refactored',
                'Schedule time to implement a proper solution',
                'Document why the hack was necessary',
                'Hacks should not reach production code',
            ],
            'XXX', 'BUG' => [
                'This requires immediate attention',
                'Create a high-priority issue',
                'Do not deploy code with known bugs',
                'Add tests to prevent regression',
            ],
            default => [
                'Track this in your issue management system',
                'Remove comment once addressed',
            ],
        };

        return $base.'Actions: '.implode('; ', $recommendations).'.';
    }

    /**
     * Get summary of comment types found.
     *
     * @param  array<\ShieldCI\AnalyzersCore\ValueObjects\Issue>  $issues
     */
    private function getSummary(array $issues): string
    {
        $counts = [];

        foreach ($issues as $issue) {
            $keyword = $issue->metadata['keyword'] ?? 'UNKNOWN';
            $counts[$keyword] = ($counts[$keyword] ?? 0) + 1;
        }

        $parts = [];
        foreach ($counts as $keyword => $count) {
            $parts[] = "{$count} {$keyword}";
        }

        return implode(', ', $parts);
    }
}
