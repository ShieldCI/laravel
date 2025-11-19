<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Support\PHPStan;

/**
 * Provides methods for parsing PHPStan analysis results.
 */
trait ParsesPHPStanAnalysis
{
    /**
     * Parse the PHPStan analysis and add issues for the errors.
     *
     * @param  string|array<int, string>  $search
     * @param  array<int, mixed>  $issues
     */
    protected function parsePHPStanAnalysis(PHPStan $phpStan, string|array $search, array &$issues): void
    {
        foreach ($phpStan->parseAnalysis($search) as $trace) {
            $issues[] = $this->createIssue(
                message: $trace['message'],
                location: new Location($trace['path'], $trace['line']),
                severity: Severity::High,
                recommendation: $this->getRecommendationFromMessage($trace['message']),
                code: FileParser::getCodeSnippet($trace['path'], $trace['line']),
                metadata: [
                    'phpstan_message' => $trace['message'],
                    'detection_method' => 'phpstan',
                ]
            );
        }
    }

    /**
     * Parse the PHPStan analysis using pattern matching.
     *
     * @param  string|array<int, string>  $pattern
     * @param  array<int, mixed>  $issues
     */
    protected function matchPHPStanAnalysis(PHPStan $phpStan, string|array $pattern, array &$issues): void
    {
        foreach ($phpStan->match($pattern) as $trace) {
            $issues[] = $this->createIssue(
                message: $trace['message'],
                location: new Location($trace['path'], $trace['line']),
                severity: Severity::High,
                recommendation: $this->getRecommendationFromMessage($trace['message']),
                code: FileParser::getCodeSnippet($trace['path'], $trace['line']),
                metadata: [
                    'phpstan_message' => $trace['message'],
                    'detection_method' => 'phpstan',
                ]
            );
        }
    }

    /**
     * Parse the PHPStan analysis using regex pattern matching.
     *
     * @param  array<int, mixed>  $issues
     */
    protected function pregMatchPHPStanAnalysis(PHPStan $phpStan, string $pattern, array &$issues): void
    {
        foreach ($phpStan->pregMatch($pattern) as $trace) {
            $issues[] = $this->createIssue(
                message: $trace['message'],
                location: new Location($trace['path'], $trace['line']),
                severity: Severity::High,
                recommendation: $this->getRecommendationFromMessage($trace['message']),
                code: FileParser::getCodeSnippet($trace['path'], $trace['line']),
                metadata: [
                    'phpstan_message' => $trace['message'],
                    'detection_method' => 'phpstan',
                ]
            );
        }
    }

    /**
     * Get a recommendation message from PHPStan message.
     */
    protected function getRecommendationFromMessage(string $message): string
    {
        // Extract collection method from PHPStan message
        if (preg_match('/Method ([^:]+)::([a-z]+)\(\) should be used instead/', $message, $matches)) {
            return "Use {$matches[1]}::{$matches[2]}() to perform this operation at the database level instead of loading all records into memory.";
        }

        if (str_contains($message, 'could have been retrieved as a query')) {
            return 'Perform this aggregation at the database query level instead of the collection level for better performance. This avoids loading unnecessary data into memory.';
        }

        return 'Optimize this operation to run at the database level instead of in PHP for better performance.';
    }
}
