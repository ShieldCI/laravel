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
 * Detects invalid imports/use statements in user's application code.
 *
 * Checks for:
 * - Imports of non-existent classes
 * - Imports of non-existent interfaces
 * - Imports of non-existent traits
 * - Missing or incorrect use statements
 */
class InvalidImportAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanResults;

    /**
     * PHPStan patterns for detecting invalid imports.
     *
     * @var array<string>
     */
    private const INVALID_IMPORT_PATTERNS = [
        'Used * not found*',
        'Class * not found*',
        'Interface * not found*',
        'Trait * not found*',
        'Instantiated class * not found*',
        'Reflection class * does not exist*',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'invalid-imports',
            name: 'Invalid Imports',
            description: 'Detects invalid imports and use statements for non-existent classes using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['phpstan', 'static-analysis', 'imports', 'autoloading'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/invalid-imports',
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

            // Filter for import issues
            $issues = $runner->filterByPattern(self::INVALID_IMPORT_PATTERNS);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                []
            );
        }

        if ($issues->isEmpty()) {
            return $this->passed('No invalid imports detected');
        }

        // Use trait method to create issues
        $issueObjects = $this->createIssuesFromPHPStanResults(
            issues: $issues,
            issueMessage: 'Invalid import detected',
            severity: Severity::Critical,
            recommendationCallback: fn (string $message) => $this->getRecommendation($message)
        );

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage(
            totalCount: $totalCount,
            displayedCount: $displayedCount,
            issueType: 'invalid import(s)'
        );

        return $this->failed($message, $issueObjects);
    }

    /**
     * Get recommendation message based on PHPStan message.
     */
    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'not found')) {
            return 'Fix the import statement - the class, interface, or trait does not exist. Check for typos in the namespace/class name, ensure the file exists, verify composer autoload is up to date (run composer dump-autoload), and confirm the required package is installed. PHPStan message: '.$message;
        }

        if (str_contains($message, 'Reflection')) {
            return 'The class used in reflection does not exist. Verify the class name is correct and the class is autoloadable. PHPStan message: '.$message;
        }

        return 'Fix the import issue detected by PHPStan. PHPStan message: '.$message;
    }
}
