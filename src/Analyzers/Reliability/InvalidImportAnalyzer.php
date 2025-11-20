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
    /**
     * @var array<string>
     */
    private array $patterns = [
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
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/invalid-imports'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $runner = new PHPStanRunner($this->basePath);

        // Run PHPStan on app directory at level 5
        $runner->analyze('app', 5);

        // Filter for import issues
        $issues = $runner->filterByPattern($this->patterns);

        if ($issues->isEmpty()) {
            return $this->passed('No invalid imports detected');
        }

        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Invalid import detected',
                location: new Location($issue['file'], $issue['line']),
                severity: Severity::Critical,
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
            ? "Found {$totalCount} invalid imports (showing first {$displayedCount})"
            : "Found {$totalCount} invalid import(s)";

        return $this->failed($message, $issueObjects);
    }

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
