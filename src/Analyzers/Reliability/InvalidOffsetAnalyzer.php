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
 * Detects invalid array offset access in user's application code.
 *
 * Checks for:
 * - Invalid array offset types
 * - Access to non-existent array keys
 * - Offset access on non-array types
 * - Undefined array offsets
 */
class InvalidOffsetAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<string>
     */
    private array $patterns = [
        'Cannot assign * offset * to *',
        'Cannot access offset * on *',
        'Offset * does not exist on *',
        'Offset * might not exist on *',
        'Offset * on * always exists*',
        'Cannot unset offset * on *',
        'Offset * on * does not accept type *',
        'Offset string on * in isset*',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'invalid-offset-access',
            name: 'Invalid Offset Access',
            description: 'Detects invalid array offset access and type mismatches using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'arrays', 'type-safety'],
            docsUrl: 'https://phpstan.org/user-guide/getting-started'
        );
    }

    public function shouldRun(): bool
    {
        // Check if PHPStan is available
        $runner = new PHPStanRunner($this->basePath);

        return $runner->isAvailable();
    }

    protected function runAnalysis(): ResultInterface
    {
        $runner = new PHPStanRunner($this->basePath);

        // Run PHPStan on app directory at level 5
        $runner->analyze('app', 5);

        // Filter for offset access issues
        $issues = $runner->filterByPattern($this->patterns);

        if ($issues->isEmpty()) {
            return $this->passed('No invalid offset access detected');
        }

        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Invalid offset access detected',
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
            ? "Found {$totalCount} invalid offset accesses (showing first {$displayedCount})"
            : "Found {$totalCount} invalid offset access(es)";

        return $this->failed($message, $issueObjects);
    }

    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'Cannot access offset') || str_contains($message, 'Cannot assign')) {
            return 'Fix the offset access - you cannot use array offset syntax on this type. Ensure the variable is an array or implements ArrayAccess. PHPStan message: '.$message;
        }

        if (str_contains($message, 'does not exist') || str_contains($message, 'might not exist')) {
            return 'Check if the offset exists before accessing it - use isset() or array_key_exists() to verify the key exists, or use null coalescing operator (??). PHPStan message: '.$message;
        }

        if (str_contains($message, 'does not accept type')) {
            return 'Fix the offset type - the offset type does not match the expected type for this array/ArrayAccess object. PHPStan message: '.$message;
        }

        return 'Fix the offset access issue detected by PHPStan. Ensure you are accessing valid array offsets with correct types. PHPStan message: '.$message;
    }
}
