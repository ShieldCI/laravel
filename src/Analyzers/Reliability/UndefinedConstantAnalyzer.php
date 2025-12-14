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
 * Detects usage of undefined constants in user's application code.
 *
 * Checks for:
 * - References to undefined constants
 * - Class constants used outside scope
 * - Constants on unknown classes
 */
class UndefinedConstantAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanResults;

    /**
     * PHPStan patterns for detecting undefined constants.
     *
     * @var array<string>
     */
    private const UNDEFINED_CONSTANT_PATTERNS = [
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
            name: 'Undefined Constant Usage Analyzer',
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
                    recommendation: 'Install PHPStan to enable undefined constant detection. Run: composer require --dev phpstan/phpstan',
                    metadata: []
                )]
            );
        }

        try {
            // Run PHPStan on app directory
            $runner->analyze('app', 5);

            // Filter for undefined constant issues
            $issues = $runner->filterByPattern(self::UNDEFINED_CONSTANT_PATTERNS);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                []
            );
        }

        if ($issues->isEmpty()) {
            return $this->passed('No undefined constants detected');
        }

        // Use trait method to create issues
        $issueObjects = $this->createIssuesFromPHPStanResults(
            issues: $issues,
            issueMessage: 'Undefined constant detected',
            severity: Severity::High,
            recommendationCallback: fn (string $message) => $this->getRecommendation($message)
        );

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage(
            totalCount: $totalCount,
            displayedCount: $displayedCount,
            issueType: 'undefined constant(s)'
        );

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
