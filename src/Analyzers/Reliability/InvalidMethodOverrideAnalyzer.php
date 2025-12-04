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
 * Detects invalid method overrides in user's application code.
 *
 * Checks for:
 * - Incompatible method signatures in overrides
 * - Return type mismatches
 * - Parameter type mismatches
 * - Visibility violations (narrowing)
 */
class InvalidMethodOverrideAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanResults;

    /**
     * PHPStan patterns for detecting invalid method overrides.
     *
     * @var array<string>
     */
    private const INVALID_METHOD_OVERRIDE_PATTERNS = [
        'Return type * of method *::* is not covariant with*',
        'Parameter * of method *::* is not contravariant with*',
        'Method *::* overrides method *::* but is missing parameter *',
        'Method *::* has parameter * with no type*',
        'Overridden method *::* is deprecated*',
        'Method *::* with return type * returns * but should return *',
        'Method *::* extends method *::* but changes visibility from *',
        'Method *::* overrides *::* with different parameter *',
        'Method *::* is not compatible with *::*',
        'Method *::* never returns * so it can be removed from*',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'invalid-method-overrides',
            name: 'Invalid Method Overrides',
            description: 'Detects incompatible method overrides with incorrect signatures using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'inheritance', 'type-safety'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/invalid-method-overrides',
            timeToFix: 20
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

            // Filter for method override issues
            $issues = $runner->filterByPattern(self::INVALID_METHOD_OVERRIDE_PATTERNS);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                []
            );
        }

        if ($issues->isEmpty()) {
            return $this->passed('No invalid method overrides detected');
        }

        // Use trait method to create issues
        $issueObjects = $this->createIssuesFromPHPStanResults(
            issues: $issues,
            issueMessage: 'Invalid method override detected',
            severity: Severity::High,
            recommendationCallback: fn (string $message) => $this->getRecommendation($message)
        );

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage(
            totalCount: $totalCount,
            displayedCount: $displayedCount,
            issueType: 'invalid method override(s)'
        );

        return $this->failed($message, $issueObjects);
    }

    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'covariant')) {
            return 'Fix the return type - the overridden method must have a return type that is the same or more specific (covariant) than the parent method. PHPStan message: '.$message;
        }

        if (str_contains($message, 'contravariant')) {
            return 'Fix the parameter type - the overridden method must have parameter types that are the same or less specific (contravariant) than the parent method. PHPStan message: '.$message;
        }

        if (str_contains($message, 'visibility')) {
            return 'Fix the method visibility - you cannot narrow visibility when overriding a method (e.g., from public to protected). PHPStan message: '.$message;
        }

        if (str_contains($message, 'missing parameter')) {
            return 'Fix the method signature - the overridden method is missing a required parameter from the parent method signature. PHPStan message: '.$message;
        }

        if (str_contains($message, 'deprecated')) {
            return 'The parent method being overridden is deprecated. Consider updating your code to avoid overriding deprecated methods. PHPStan message: '.$message;
        }

        return 'Fix the method override to match the parent method signature. Ensure return types, parameter types, and visibility are compatible. PHPStan message: '.$message;
    }
}
