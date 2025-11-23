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
 * Detects usage of undefined constants in user's application code.
 *
 * Checks for:
 * - References to undefined constants
 * - Class constants used outside scope
 * - Constants on unknown classes
 */
class UndefinedConstantAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<string>
     */
    private array $patterns = [
        '* undefined constant *',
        'Using * outside of class scope*',
        'Access to constant * on an unknown class *',
        'Constant * does not exist*',
        'Class constant * not found*',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'undefined-constant',
            name: 'Undefined Constant Usage',
            description: 'Detects references to undefined constants using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'constants', 'type-safety'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/undefined-constant',
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $runner = new PHPStanRunner($this->basePath);

        // Run PHPStan on app directory at level 5
        $runner->analyze('app', 5);

        // Filter for undefined constant issues
        $issues = $runner->filterByPattern($this->patterns);

        if ($issues->isEmpty()) {
            return $this->passed('No undefined constants detected');
        }

        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Undefined constant detected',
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
            ? "Found {$totalCount} undefined constants (showing first {$displayedCount})"
            : "Found {$totalCount} undefined constant(s)";

        return $this->failed($message, $issueObjects);
    }

    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'outside of class scope')) {
            return 'Class constant is being used outside of its scope. Use the fully qualified class name (e.g., ClassName::CONSTANT_NAME) or ensure you are within the correct class context. PHPStan message: '.$message;
        }

        if (str_contains($message, 'unknown class')) {
            return 'Attempting to access a constant on a class that does not exist. Verify the class name is correct and the class is imported/autoloaded. PHPStan message: '.$message;
        }

        if (str_contains($message, 'undefined constant')) {
            return 'Constant is not defined. Check for typos in the constant name, ensure it is defined before use, or use the define() function to create it. PHPStan message: '.$message;
        }

        if (str_contains($message, 'does not exist') || str_contains($message, 'not found')) {
            return 'Constant does not exist on the specified class. Verify the constant name is correct and is defined in the class. PHPStan message: '.$message;
        }

        return 'Fix the undefined constant issue. Ensure all constants are properly defined before use. PHPStan message: '.$message;
    }
}
