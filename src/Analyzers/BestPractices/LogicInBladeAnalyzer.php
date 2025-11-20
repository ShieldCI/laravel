<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects business logic in Blade templates.
 *
 * Finds:
 * - Complex @php blocks (> 10 lines)
 * - Foreach with business logic inside
 * - Calculations and transformations in views
 * - DB queries in Blade files
 */
class LogicInBladeAnalyzer extends AbstractFileAnalyzer
{
    private const MAX_PHP_BLOCK_LINES = 10;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'logic-in-blade',
            name: 'Logic in Blade Detector',
            description: 'Finds business logic in Blade templates that should be moved to controllers or view composers',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['laravel', 'blade', 'mvc', 'views', 'architecture'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/logic-in-blade',
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Only set default paths if not already set (allows tests to override)
        if (empty($this->paths)) {
            $this->setBasePath(base_path());
            $this->setPaths(['resources/views']);
        }

        $bladeFiles = $this->getBladeFiles();

        foreach ($bladeFiles as $file) {
            try {
                $this->analyzeBladeFile($file, $issues);
            } catch (\Throwable $e) {
                // Skip files with read errors
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('No business logic found in Blade templates');
        }

        return $this->failed(
            sprintf('Found %d Blade template(s) with business logic', count($issues)),
            $issues
        );
    }

    private function getBladeFiles(): array
    {
        $files = [];

        foreach ($this->getFilesToAnalyze() as $file) {
            if (str_ends_with($file->getFilename(), '.blade.php')) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    private function analyzeBladeFile(string $file, array &$issues): void
    {
        $content = FileParser::readFile($file);
        if ($content === null) {
            return;
        }

        $lines = FileParser::getLines($file);

        // Track PHP blocks
        $inPhpBlock = false;
        $phpBlockStart = 0;
        $phpBlockLines = 0;

        foreach ($lines as $lineNumber => $line) {
            $trimmed = trim($line);

            // Check for @php block start
            if (preg_match('/@php\b/', $trimmed)) {
                $inPhpBlock = true;
                $phpBlockStart = $lineNumber + 1;
                $phpBlockLines = 0;
            }

            // Count lines in PHP block
            if ($inPhpBlock) {
                $phpBlockLines++;
            }

            // Check for @php block end
            if (preg_match('/@endphp\b/', $trimmed)) {
                if ($phpBlockLines > self::MAX_PHP_BLOCK_LINES) {
                    $issues[] = $this->createIssue(
                        message: sprintf(
                            'PHP block has %d lines (max recommended: %d). Move logic to controller or view composer',
                            $phpBlockLines,
                            self::MAX_PHP_BLOCK_LINES
                        ),
                        location: new Location($this->getRelativePath($file), $phpBlockStart),
                        severity: Severity::Medium,
                        recommendation: 'Move complex PHP logic to controllers, view composers, or presenter classes. Blade templates should focus on presentation only',
                        code: null,
                    );
                }
                $inPhpBlock = false;
            }

            // Check for DB queries
            if ($this->hasDbQuery($line)) {
                $issues[] = $this->createIssue(
                    message: 'Database query found in Blade template',
                    location: new Location($this->getRelativePath($file), $lineNumber + 1),
                    severity: Severity::Critical,
                    recommendation: 'Never query the database from Blade templates. Load all required data in the controller and pass it to the view',
                    code: $trimmed,
                );
            }

            // Check for complex calculations
            if ($this->hasComplexCalculation($line)) {
                $issues[] = $this->createIssue(
                    message: 'Complex calculation found in Blade template',
                    location: new Location($this->getRelativePath($file), $lineNumber + 1),
                    severity: Severity::Low,
                    recommendation: 'Move calculations to controller, view composer, or model accessor. Blade should only display pre-calculated values',
                    code: $trimmed,
                );
            }

            // Check for business logic patterns in Blade directives
            if ($this->hasBusinessLogicInDirective($line)) {
                $issues[] = $this->createIssue(
                    message: 'Business logic found in Blade directive',
                    location: new Location($this->getRelativePath($file), $lineNumber + 1),
                    severity: Severity::Medium,
                    recommendation: 'Extract business logic to controllers or services. Use simple conditionals in views for presentation logic only',
                    code: $trimmed,
                );
            }
        }
    }

    private function hasDbQuery(string $line): bool
    {
        $patterns = [
            '/\bDB::/',                    // DB facade
            '/::where\s*\(/',              // Eloquent where
            '/::find\s*\(/',               // Eloquent find
            '/::all\s*\(/',                // Eloquent all
            '/::get\s*\(/',                // Eloquent get
            '/::first\s*\(/',              // Eloquent first
            '/::create\s*\(/',             // Eloquent create
            '/::update\s*\(/',             // Eloquent update
            '/::delete\s*\(/',             // Eloquent delete
            '/->save\s*\(/',               // Model save
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $line)) {
                return true;
            }
        }

        return false;
    }

    private function hasComplexCalculation(string $line): bool
    {
        // Skip simple variable outputs
        if (preg_match('/^\{\{\s*\$\w+\s*\}\}$/', trim($line))) {
            return false;
        }

        // Detect mathematical operations in output
        if (preg_match('/\{\{.*[\+\-\*\/\%].*\}\}/', $line)) {
            // Check if it's a complex calculation (multiple operations)
            if (preg_match_all('/[\+\-\*\/\%]/', $line, $matches) && count($matches[0]) > 1) {
                return true;
            }
        }

        // Detect calculations in @php blocks or inline PHP
        if (preg_match('/\$([\w]+)\s*[\+\-\*\/\%]=/', $line)) {
            return true;
        }

        // Detect complex expressions with function calls and math
        if (preg_match('/\{\{.*\(.*\).*[\+\-\*\/]/', $line)) {
            return true;
        }

        return false;
    }

    private function hasBusinessLogicInDirective(string $line): bool
    {
        // Check for complex @if conditions with business logic
        if (preg_match('/@if\s*\(.*&&.*&&/', $line)) {
            return true; // Multiple AND conditions might indicate business logic
        }

        // Check for loops with transformations
        if (preg_match('/@foreach\s*\(.*->filter\(/', $line)) {
            return true; // Filtering in foreach
        }

        if (preg_match('/@foreach\s*\(.*->map\(/', $line)) {
            return true; // Mapping in foreach
        }

        if (preg_match('/@foreach\s*\(.*->transform\(/', $line)) {
            return true; // Transforming in foreach
        }

        // Check for array_* functions (data manipulation)
        $arrayFunctions = [
            'array_filter', 'array_map', 'array_reduce', 'array_walk',
            'array_merge', 'array_combine', 'array_diff',
        ];

        foreach ($arrayFunctions as $func) {
            if (str_contains($line, $func)) {
                return true;
            }
        }

        return false;
    }
}
