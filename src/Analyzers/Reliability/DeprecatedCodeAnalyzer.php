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
    use ParsesPHPStanResults;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'deprecated-code',
            name: 'Deprecated Code Analyzer',
            description: 'Detects usage of deprecated methods, classes, and functions using PHPStan static analysis',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'deprecated', 'compatibility'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/deprecated-code',
            timeToFix: 15
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

            // Filter for deprecated code issues using regex
            $issues = $runner->filterByRegex('#\s*deprecated\s*#i');
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                [
                    'exception' => get_class($e),
                    'error_message' => $e->getMessage(),
                ]
            );
        }

        if ($issues->isEmpty()) {
            return $this->passed('No deprecated code usage detected');
        }

        $issueObjects = $this->createIssuesFromPHPStanResults(
            $issues,
            'Deprecated code usage detected',
            Severity::High,
            fn (string $message) => $this->getRecommendation($message)
        );

        $totalCount = $issues->count();
        $displayedCount = count($issueObjects);

        $message = $this->formatIssueCountMessage($totalCount, $displayedCount, 'deprecated code usage(s)');

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
