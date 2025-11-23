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
    /**
     * @var array<string>
     */
    private array $patterns = [
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
        $runner = new PHPStanRunner($this->basePath);

        // Run PHPStan on app directory at level 5
        $runner->analyze('app', 5);

        // Filter for method override issues
        $issues = $runner->filterByPattern($this->patterns);

        if ($issues->isEmpty()) {
            return $this->passed('No invalid method overrides detected');
        }

        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Invalid method override detected',
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
            ? "Found {$totalCount} invalid method overrides (showing first {$displayedCount})"
            : "Found {$totalCount} invalid method override(s)";

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
