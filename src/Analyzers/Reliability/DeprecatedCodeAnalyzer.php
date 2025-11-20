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
 * Detects usage of deprecated code in user's application.
 *
 * Checks for:
 * - Deprecated methods and functions
 * - Deprecated classes and interfaces
 * - Deprecated constants
 * - Any code marked with @deprecated tag
 */
class DeprecatedCodeAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'deprecated-code',
            name: 'Deprecated Code Usage',
            description: 'Detects usage of deprecated methods, classes, and functions using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'deprecated', 'compatibility'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/deprecated-code'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $runner = new PHPStanRunner($this->basePath);

        // Run PHPStan on app directory at level 5
        $runner->analyze('app', 5);

        // Filter for deprecated code issues using regex
        $issues = $runner->filterByRegex('#\s*deprecated\s*#i');

        if ($issues->isEmpty()) {
            return $this->passed('No deprecated code usage detected');
        }

        $issueObjects = [];

        foreach ($issues->take(50) as $issue) {
            $issueObjects[] = $this->createIssue(
                message: 'Deprecated code usage detected',
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
            ? "Found {$totalCount} deprecated code usages (showing first {$displayedCount})"
            : "Found {$totalCount} deprecated code usage(s)";

        return $this->failed($message, $issueObjects);
    }

    private function getRecommendation(string $message): string
    {
        if (str_contains($message, 'method')) {
            return 'Replace deprecated method - this method is marked as deprecated and may be removed in future versions. Check the documentation for the recommended alternative. PHPStan message: '.$message;
        }

        if (str_contains($message, 'class') || str_contains($message, 'interface')) {
            return 'Replace deprecated class/interface - this type is marked as deprecated. Migrate to the recommended alternative to ensure compatibility with future versions. PHPStan message: '.$message;
        }

        if (str_contains($message, 'function')) {
            return 'Replace deprecated function - this function is marked as deprecated. Use the recommended alternative function. PHPStan message: '.$message;
        }

        if (str_contains($message, 'constant')) {
            return 'Replace deprecated constant - this constant is marked as deprecated. Use the recommended alternative constant. PHPStan message: '.$message;
        }

        return 'Replace deprecated code - this code is marked as deprecated and should be replaced with the recommended alternative. PHPStan message: '.$message;
    }
}
