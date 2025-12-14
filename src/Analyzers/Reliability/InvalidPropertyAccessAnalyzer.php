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
 * Detects invalid property access in user's application code.
 *
 * Checks for:
 * - Access to undefined properties
 * - Access to private/protected properties from wrong scope
 * - Property access on non-objects
 * - Type mismatches in property assignments
 */
class InvalidPropertyAccessAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanResults;

    /**
     * PHPStan patterns for detecting invalid property access.
     *
     * @var array<string>
     */
    private const INVALID_PROPERTY_ACCESS_PATTERNS = [
        'Access to * property *',
        'Cannot access property * on *',
        'Access to an undefined property *',
        'Access to undefined property *',
        'Property * of class * is unused*',
        'Property * does not accept *',
        'Static property * does not exist*',
        'Access to static property * on *',
        'Property * on * is not defined*',
        'Property * in * is not readable*',
        'Property * in * is not writable*',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'invalid-property-access',
            name: 'Invalid Property Access Analyzer',
            description: 'Detects invalid property access and visibility violations using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'properties', 'type-safety'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/invalid-property-access',
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

            // Filter for property access issues
            $issues = $runner->filterByPattern(self::INVALID_PROPERTY_ACCESS_PATTERNS);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                []
            );
        }

        if ($issues->isEmpty()) {
            return $this->passed('No invalid property access detected');
        }

        // Use trait method to create issues
        $issueObjects = $this->createIssuesFromPHPStanResults(
            issues: $issues,
            issueMessage: 'Invalid property access detected',
            severity: Severity::High,
            recommendationCallback: fn (string $message) => $this->getRecommendation($message)
        );

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage(
            totalCount: $totalCount,
            displayedCount: $displayedCount,
            issueType: 'invalid property access(es)'
        );

        return $this->failed($message, $issueObjects);
    }

    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'undefined property')) {
            return 'Fix the property access - the property does not exist on this class. Check for typos in the property name, ensure the property is defined, or use the __get() magic method. PHPStan message: '.$message;
        }

        if (str_contains($message, 'private') || str_contains($message, 'protected')) {
            return 'Fix the property visibility - you are accessing a private/protected property outside its scope. Make the property public, add a getter method, or access it from within the class. PHPStan message: '.$message;
        }

        if (str_contains($message, 'Cannot access property')) {
            return 'Fix the property access - you cannot access properties on this type. Ensure the variable is an object of the correct class. PHPStan message: '.$message;
        }

        if (str_contains($message, 'does not accept')) {
            return 'Fix the property assignment - the value type does not match the property type. Ensure you are assigning a value of the correct type. PHPStan message: '.$message;
        }

        if (str_contains($message, 'not readable') || str_contains($message, 'not writable')) {
            return 'Fix the property access - the property is not readable or writable. Check the property visibility and whether getter/setter methods are defined. PHPStan message: '.$message;
        }

        return 'Fix the property access issue detected by PHPStan. PHPStan message: '.$message;
    }
}
