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
 * Detects usage of undefined variables in user's application code.
 *
 * Checks for:
 * - References to undefined variables
 * - Variables that might not be defined
 * - Potential typos in variable names
 */
class UndefinedVariableAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanResults;

    /**
     * PHPStan patterns for detecting undefined variables.
     *
     * @var array<string>
     */
    private const UNDEFINED_VARIABLE_PATTERNS = [
        'Undefined variable*',
        'Variable * might not be defined*',
        'Variable * in isset* always exists*',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'undefined-variable',
            name: 'Undefined Variable Usage Analyzer',
            description: 'Detects references to undefined variables using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'variables', 'type-safety'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/undefined-variable',
            timeToFix: 10
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

            // Filter for undefined variable issues
            $issues = $runner->filterByPattern(self::UNDEFINED_VARIABLE_PATTERNS);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                []
            );
        }

        if ($issues->isEmpty()) {
            return $this->passed('No undefined variables detected');
        }

        // Use trait method to create issues
        $issueObjects = $this->createIssuesFromPHPStanResults(
            issues: $issues,
            issueMessage: 'Undefined variable detected',
            severity: Severity::High,
            recommendationCallback: fn (string $message) => $this->getRecommendation($message)
        );

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage(
            totalCount: $totalCount,
            displayedCount: $displayedCount,
            issueType: 'undefined variable(s)'
        );

        return $this->failed($message, $issueObjects);
    }

    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'might not be defined')) {
            return 'Variable might not be defined in all code paths. Ensure the variable is initialized before use in all possible execution paths (e.g., in both if/else branches). PHPStan message: '.$message;
        }

        if (str_contains($message, 'Undefined variable')) {
            return 'Variable is used before being defined. Initialize the variable before using it, or check for typos in the variable name. PHPStan message: '.$message;
        }

        if (str_contains($message, 'always exists')) {
            return 'Remove unnecessary isset() check - the variable is guaranteed to exist at this point. This check is redundant. PHPStan message: '.$message;
        }

        return 'Fix the undefined variable issue. Ensure all variables are properly initialized before use. PHPStan message: '.$message;
    }
}
