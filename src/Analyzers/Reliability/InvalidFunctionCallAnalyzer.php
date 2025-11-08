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
 * Detects invalid function calls in user's application code.
 *
 * Checks for:
 * - Calls to undefined functions
 * - Invalid function signatures
 * - Type mismatches in function parameters
 * - Missing or unknown parameters
 */
class InvalidFunctionCallAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<string>
     */
    private array $patterns = [
        'Function * not found*',
        'Function * invoked with * parameter*',
        'Parameter * of function * expects*',
        'Missing parameter * in call to function *',
        'Unknown parameter * in call to function *',
        'Parameter * of * expects * given*',
        'Result of function * (void) is used*',
        'Cannot call function * on *',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'invalid-function-calls',
            name: 'Invalid Function Calls',
            description: 'Detects invalid function calls in application code using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'functions', 'type-safety'],
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

        // Filter for function call issues
        $issues = $runner->filterByPattern($this->patterns);

        if ($issues->isEmpty()) {
            return $this->passed('No invalid function calls detected');
        }

        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Invalid function call detected',
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
            ? "Found {$totalCount} invalid function calls (showing first {$displayedCount})"
            : "Found {$totalCount} invalid function call(s)";

        return $this->failed($message, $issueObjects);
    }

    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'not found')) {
            return 'Fix the function call - the function does not exist. Check for typos in the function name, ensure the function is defined, or verify the required extension/library is installed. PHPStan message: '.$message;
        }

        if (str_contains($message, 'Parameter') || str_contains($message, 'parameter')) {
            return 'Fix the function parameters - they do not match the function signature. Check the parameter types, order, and count. PHPStan message: '.$message;
        }

        if (str_contains($message, 'void')) {
            return 'The function returns void - you cannot use its return value. Remove the code that attempts to use the return value. PHPStan message: '.$message;
        }

        return 'Fix the function call issue detected by PHPStan. PHPStan message: '.$message;
    }
}
