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
    /**
     * @var array<string>
     */
    private array $patterns = [
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
            name: 'Invalid Property Access',
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
        $runner = new PHPStanRunner($this->basePath);

        // Run PHPStan on app directory at level 5
        $runner->analyze('app', 5);

        // Filter for property access issues
        $issues = $runner->filterByPattern($this->patterns);

        if ($issues->isEmpty()) {
            return $this->passed('No invalid property access detected');
        }

        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Invalid property access detected',
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
            ? "Found {$totalCount} invalid property accesses (showing first {$displayedCount})"
            : "Found {$totalCount} invalid property access(es)";

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
