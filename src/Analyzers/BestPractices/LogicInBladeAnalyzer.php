<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Detects business logic in Blade templates.
 *
 * Finds:
 * - Complex @php blocks (> configurable lines)
 * - Database queries in Blade files
 * - Complex calculations and transformations in views
 * - Business logic patterns in Blade directives
 * - API calls in templates
 */
class LogicInBladeAnalyzer extends AbstractFileAnalyzer
{
    public const DEFAULT_MAX_PHP_BLOCK_LINES = 10;

    /** @var array<string> */
    private const DB_QUERY_PATTERNS = [
        '/\bDB::/',                    // DB facade
        '/::where\s*\(/',              // Eloquent where
        '/::find\s*\(/',               // Eloquent find
        '/::all\s*\(/',                // Eloquent all
        '/::first\s*\(/',              // Eloquent first
        '/::create\s*\(/',             // Eloquent create
        '/::update\s*\(/',             // Eloquent update
        '/::delete\s*\(/',             // Eloquent delete
        '/::insert\s*\(/',             // Eloquent insert
        '/::upsert\s*\(/',             // Eloquent upsert
        '/->query\s*\(/',              // Query builder
    ];

    /** @var array<string> */
    private const BUSINESS_LOGIC_FUNCTIONS = [
        'array_filter', 'array_map', 'array_reduce', 'array_walk',
        'array_merge', 'array_combine', 'array_diff',
    ];

    /** @var array<string> Non-database get methods to exclude */
    private const NON_DB_GET_METHODS = [
        'config()',
        'session()',
        'cache()',
        'request()',
        'cookie()',
    ];

    private int $maxPhpBlockLines;

    /** @var array<int, true> Track reported lines to avoid duplicates */
    private array $reportedLines = [];

    public function __construct(private Config $config) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'logic-in-blade',
            name: 'Logic in Blade Analyzer',
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
        // Load configuration
        $analyzerConfig = $this->config->get('shieldci.analyzers.best-practices.logic-in-blade', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->maxPhpBlockLines = $analyzerConfig['max_php_block_lines'] ?? self::DEFAULT_MAX_PHP_BLOCK_LINES;

        $issues = [];

        // Only set default paths if not already set (allows tests to override)
        if (empty($this->paths)) {
            $this->setBasePath(base_path());
            $this->setPaths(['resources/views']);
        }

        $bladeFiles = $this->getBladeFiles();

        foreach ($bladeFiles as $file) {
            try {
                // Reset reported lines for each file
                $this->reportedLines = [];
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

            // Skip if we've already reported an issue for this line
            if (isset($this->reportedLines[$lineNumber])) {
                continue;
            }

            // Check for @php block start
            if (preg_match('/@php\b/', $trimmed)) {
                $inPhpBlock = true;
                $phpBlockStart = $lineNumber + 1;
                $phpBlockLines = 0;

                // Don't count the @php line itself - continue to next line
                continue;
            }

            // Check for @php block end (before counting)
            if (preg_match('/@endphp\b/', $trimmed)) {
                // Don't count the @endphp line itself
                if ($phpBlockLines > $this->maxPhpBlockLines) {
                    $this->reportedLines[$phpBlockStart - 1] = true;

                    $issues[] = $this->createIssueWithSnippet(
                        message: sprintf(
                            'PHP block has %d lines (max recommended: %d)',
                            $phpBlockLines,
                            $this->maxPhpBlockLines
                        ),
                        filePath: $file,
                        lineNumber: $phpBlockStart,
                        severity: Severity::Medium,
                        recommendation: 'Move complex PHP logic to controllers, view composers, or presenter classes. Blade templates should focus on presentation only',
                        code: 'blade-php-block-too-long',
                        metadata: [
                            'block_lines' => $phpBlockLines,
                            'max_lines' => $this->maxPhpBlockLines,
                            'block_start' => $phpBlockStart,
                        ]
                    );
                }
                $inPhpBlock = false;

                continue;
            }

            // Count lines in PHP block (only lines between @php and @endphp)
            if ($inPhpBlock) {
                $phpBlockLines++;
            }

            if (preg_match('/<\?php/', $line)) {
                $this->reportedLines[$lineNumber] = true;

                $issues[] = $this->createIssueWithSnippet(
                    message: 'Inline PHP found in Blade template',
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Medium,
                    recommendation: 'Use Blade directives (@php...@endphp) instead of inline PHP for consistency',
                    code: 'blade-inline-php',
                    metadata: ['line' => $lineNumber + 1]
                );
            }

            // Check for DB queries (highest priority)
            if ($this->hasDbQuery($line)) {
                $this->reportedLines[$lineNumber] = true;

                $issues[] = $this->createIssueWithSnippet(
                    message: 'Database query found in Blade template',
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Critical,
                    recommendation: 'Never query the database from Blade templates. Load all required data in the controller and pass it to the view',
                    code: 'blade-has-db-query',
                    metadata: ['line' => $lineNumber + 1]
                );

                continue; // Don't check other patterns if we found a DB query
            }

            // Check for API calls
            if ($this->hasApiCall($line)) {
                $this->reportedLines[$lineNumber] = true;

                $issues[] = $this->createIssueWithSnippet(
                    message: 'API call found in Blade template',
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::High,
                    recommendation: 'Make API calls in controllers or services, not in views. Views should only display pre-fetched data',
                    code: 'blade-has-api-call',
                    metadata: ['line' => $lineNumber + 1]
                );

                continue;
            }

            // Check for business logic patterns in Blade directives
            if ($this->hasBusinessLogicInDirective($line)) {
                $this->reportedLines[$lineNumber] = true;

                $issues[] = $this->createIssueWithSnippet(
                    message: 'Business logic found in Blade directive',
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Medium,
                    recommendation: 'Extract business logic to controllers or services. Use simple conditionals in views for presentation logic only',
                    code: 'blade-has-business-logic',
                    metadata: ['line' => $lineNumber + 1]
                );

                continue;
            }

            // Check for complex calculations (lowest priority)
            if ($this->hasComplexCalculation($line)) {
                $this->reportedLines[$lineNumber] = true;

                $issues[] = $this->createIssueWithSnippet(
                    message: 'Complex calculation found in Blade template',
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Low,
                    recommendation: 'Move calculations to controller, view composer, or model accessor. Blade should only display pre-calculated values',
                    code: 'blade-has-calculation',
                    metadata: ['line' => $lineNumber + 1]
                );
            }
        }

        // Check for unclosed PHP blocks
        if ($inPhpBlock) {
            $issues[] = $this->createIssueWithSnippet(
                message: 'Unclosed @php block detected',
                filePath: $file,
                lineNumber: $phpBlockStart,
                severity: Severity::High,
                recommendation: 'Every @php directive must have a matching @endphp',
                code: 'blade-unclosed-php-block',
                metadata: [
                    'block_start' => $phpBlockStart,
                    'lines_counted' => $phpBlockLines,
                ]
            );
        }
    }

    private function hasDbQuery(string $line): bool
    {
        // First, check if this is a non-database get method
        foreach (self::NON_DB_GET_METHODS as $nonDbMethod) {
            if (str_contains($line, $nonDbMethod) && str_contains($line, '->get(')) {
                return false; // It's config/session/cache/request()->get(), not a DB query
            }
        }

        foreach (self::DB_QUERY_PATTERNS as $pattern) {
            if (preg_match($pattern, $line)) {
                return true;
            }
        }

        // Check for model save (but exclude file uploads)
        if (preg_match('/\$\w+->save\s*\(/', $line)) {
            // Exclude common file upload patterns
            if (preg_match('/\$(file|upload|image|photo|document|attachment)->save/', $line)) {
                return false;
            }

            return true; // Likely a model save
        }

        // Check for relationship queries
        if (preg_match('/\$\w+->(\w+)\(\)->get\(/', $line)) {
            return true; // Likely $user->posts()->get()
        }

        return false;
    }

    private function hasApiCall(string $line): bool
    {
        $patterns = [
            '/Http::/',                // Laravel HTTP client
            '/\bGuzzle\b/',            // Guzzle client
            '/\bcurl_/',               // cURL functions
            '/file_get_contents\s*\(\s*[\'"]https?:\/\//', // file_get_contents with URL
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

        // Skip helper function calls (config, session, cache, etc.)
        if (preg_match('/\{\{\s*(config|session|cache|request|cookie|auth)\s*\(\s*\)/', $line)) {
            return false; // {{ config()->get() }} is acceptable
        }

        // Skip facade calls (Config::, Session::, Cache::, etc.)
        if (preg_match('/\{\{\s*(Config|Session|Cache|Request|Cookie|Auth)::/', $line)) {
            return false; // {{ Config::get() }} is acceptable
        }

        // Skip simple single operations (these are often acceptable)
        if (preg_match('/\{\{\s*\$\w+\s*[\+\-\*\/]\s*\$\w+\s*\}\}/', $line)) {
            return false; // {{ $price * $quantity }} is acceptable
        }

        // Detect complex calculations (multiple operations)
        if (preg_match('/\{\{.*[\+\-\*\/\%].*\}\}/', $line)) {
            // Count operations
            if (preg_match_all('/[\+\-\*\/\%]/', $line, $matches) && count($matches[0]) >= 2) {
                return true; // Multiple operations = complex
            }
        }

        // Detect calculations in @php blocks or inline PHP
        if (preg_match('/\$[\w]+\s*[\+\-\*\/\%]=/', $line)) {
            return true;
        }

        // Detect complex expressions with function calls and math
        if (preg_match('/\{\{.*\(.*\).*[\+\*\/]/', $line)) {
            return true;
        }

        return false;
    }

    private function hasBusinessLogicInDirective(string $line): bool
    {
        // Check for overly complex @if conditions (4+ conditions, not 3+)
        if (preg_match('/@if\s*\(/', $line)) {
            // Count && and || operators
            $andCount = substr_count($line, '&&');
            $orCount = substr_count($line, '||');
            if ($andCount + $orCount >= 3) {
                return true; // 4+ conditions indicates business logic
            }
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

        if (preg_match('/@foreach\s*\(.*->sortBy\(/', $line)) {
            return true; // Sorting in foreach
        }

        // Check for array_* functions (data manipulation)
        foreach (self::BUSINESS_LOGIC_FUNCTIONS as $func) {
            if (str_contains($line, $func)) {
                return true;
            }
        }

        return false;
    }
}
