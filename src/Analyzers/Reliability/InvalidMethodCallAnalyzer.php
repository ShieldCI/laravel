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
    /**
     * @var array<string>
     */
    private array $patterns = [
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

        // Run PHPStan on app directory at level 5 (good balance)
        $runner->analyze('app', 5);

        // Filter for method call issues
        $issues = $runner->filterByPattern($this->patterns);

        if ($issues->isEmpty()) {
            return $this->passed('No invalid method calls detected');
        }

        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Invalid method call detected',
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
            ? "Found {$totalCount} invalid method calls (showing first {$displayedCount})"
            : "Found {$totalCount} invalid method call(s)";

        return $this->failed($message, $issueObjects);
    }

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
