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
 * Detects invalid method calls in user's application code.
 *
 * Checks for:
 * - Calls to undefined methods
 * - Invalid method signatures
 * - Scope violations (private/protected)
 * - Type mismatches in method parameters
 */
class InvalidMethodCallAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanResults;

    /**
     * PHPStan patterns for detecting invalid method calls.
     *
     * @var array<string>
     */
    private const INVALID_METHOD_CALL_PATTERNS = [
        'Method * invoked with *',
        'Parameter * of method * is passed by reference, so *',
        'Unable to resolve the template *',
        'Missing parameter * in call to *',
        'Unknown parameter * in call to *',
        'Call to method * on an unknown class *',
        'Cannot call method * on *',
        'Call to private method * of parent class *',
        'Call to an undefined method *',
        'Call to * method * of class *',
        'Call to an undefined static method *',
        'Static call to instance method *',
        'Calling *::* outside of class scope*',
        '*::* calls parent::* but *',
        'Call to static method * on an unknown class *',
        'Cannot call static method * on *',
        'Cannot call abstract* method *::*',
        '* invoked with * parameter* required*',
        'Parameter * of * expects * given*',
        'Result of * (void) is used*',
        'Result of method *',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'invalid-method-calls',
            name: 'Invalid Method Calls',
            description: 'Detects invalid method calls in application code using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['phpstan', 'static-analysis', 'methods', 'type-safety'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/invalid-method-calls',
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

            // Filter for method call issues
            $issues = $runner->filterByPattern(self::INVALID_METHOD_CALL_PATTERNS);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                []
            );
        }

        if ($issues->isEmpty()) {
            return $this->passed('No invalid method calls detected');
        }

        // Use trait method to create issues
        $issueObjects = $this->createIssuesFromPHPStanResults(
            issues: $issues,
            issueMessage: 'Invalid method call detected',
            severity: Severity::Critical,
            recommendationCallback: fn (string $message) => $this->getRecommendation($message)
        );

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage(
            totalCount: $totalCount,
            displayedCount: $displayedCount,
            issueType: 'invalid method call(s)'
        );

        return $this->failed($message, $issueObjects);
    }

    /**
     * Get recommendation message based on PHPStan message.
     */
    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'undefined method')) {
            return 'Fix the method call - the method does not exist on this class. Check for typos in the method name or ensure the method is defined. PHPStan message: '.$message;
        }

        if (str_contains($message, 'Parameter')) {
            return 'Fix the method parameters - they do not match the method signature. Check the parameter types, order, and count. PHPStan message: '.$message;
        }

        if (str_contains($message, 'private') || str_contains($message, 'protected')) {
            return 'Fix the method visibility - you are calling a private/protected method outside its scope. PHPStan message: '.$message;
        }

        return 'Fix the method call issue detected by PHPStan. PHPStan message: '.$message;
    }
}
