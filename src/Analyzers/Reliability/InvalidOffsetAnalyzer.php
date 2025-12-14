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
    use ParsesPHPStanResults;

    /**
     * PHPStan patterns for detecting invalid offset access.
     *
     * @var array<string>
     */
    private const INVALID_OFFSET_PATTERNS = [
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
            name: 'Invalid Offset Access Analyzer',
            description: 'Detects invalid array offset access and type mismatches using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'arrays', 'type-safety'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/invalid-offset-access',
            timeToFix: 15
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $basePath = $this->getBasePath();

        if ($basePath === '') {
            return $this->error('Unable to determine base path for PHPStan analysis');
        }

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

            // Filter for offset access issues
            $issues = $runner->filterByPattern(self::INVALID_OFFSET_PATTERNS);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                []
            );
        }

        if ($issues->isEmpty()) {
            return $this->passed('No invalid offset access detected');
        }

        // Use trait method to create issues
        $issueObjects = $this->createIssuesFromPHPStanResults(
            issues: $issues,
            issueMessage: 'Invalid offset access detected',
            severity: Severity::High,
            recommendationCallback: fn (string $message) => $this->getRecommendation($message)
        );

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage(
            totalCount: $totalCount,
            displayedCount: $displayedCount,
            issueType: 'invalid offset access(es)'
        );

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
