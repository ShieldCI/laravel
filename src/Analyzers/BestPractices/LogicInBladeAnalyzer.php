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

    /** @var array<string> Patterns that are definitely database operations */
    private const DEFINITE_DB_PATTERNS = [
        '/\bDB::/',                    // DB facade - always database
        '/->query\s*\(/',              // Query builder - always database
    ];

    /**
     * @var array<string> Self-terminal patterns - the static call IS the final operation.
     *
     * These patterns don't need a chained terminal method because they ARE terminal.
     * Example: User::all(), User::find(1), User::first()
     * Skipped if class is in NON_ELOQUENT_CLASSES (e.g., Arr::first, Factory::create).
     */
    private const SELF_TERMINAL_DB_PATTERNS = [
        '/::find\s*\(/',               // Model::find(1) - terminal
        '/::all\s*\(/',                // Model::all() - terminal
        '/::first\s*\(/',              // Model::first() - terminal (but also Arr::first)
        '/::create\s*\(/',             // Model::create([]) - terminal (but also Factory/Carbon)
        '/::update\s*\(/',             // Model::update([]) - terminal
        '/::delete\s*\(/',             // Model::delete() - terminal
        '/::insert\s*\(/',             // Model::insert([]) - terminal
        '/::upsert\s*\(/',             // Model::upsert([]) - terminal
    ];

    /**
     * @var array<string> Chain patterns - require terminal method OR FQCN to confirm DB query.
     *
     * These patterns start a query chain but don't execute it.
     * Example: User::where('x', 'y') - needs ->get(), ->first(), etc. to execute
     * Without terminal, we can't be sure if it's a DB query or a custom class.
     */
    private const CHAIN_DB_PATTERNS = [
        '/::where\s*\(/',              // Could be Eloquent chain or Collection/Arr/custom class
    ];

    /** @var array<string> Terminal methods that confirm a DB query chain */
    private const TERMINAL_DB_METHODS = [
        '->get(',
        '->first(',
        '->find(',
        '->count(',
        '->exists(',
        '->pluck(',
        '->sum(',
        '->avg(',
        '->min(',
        '->max(',
        '->paginate(',
    ];

    /** @var array<string> Namespace indicators for Model classes */
    private const MODEL_NAMESPACE_INDICATORS = [
        '\\Models\\',
        '\\Model\\',
    ];

    /** @var array<string> Variable name patterns that suggest collections, not models */
    private const COLLECTION_VARIABLE_PATTERNS = [
        'collection',
        'items',
        'list',
        'array',
        'data',
        'results',
        'rows',
        'records',
        'entries',
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

    /** @var array<string> Extended list of non-database save method variable names */
    private const NON_DB_SAVE_VARIABLES = [
        'file',
        'upload',
        'image',
        'photo',
        'document',
        'attachment',
        'pdf',
        'excel',
        'csv',
        'export',
        'cache',
        'temp',
        'storage',
    ];

    /** @var array<string> Additional collection methods that indicate business logic */
    private const COLLECTION_MANIPULATION_METHODS = [
        'pluck',
        'unique',
        'chunk',
        'groupBy',
        'keyBy',
        'reverse',
        'shuffle',
        'values',
        'keys',
    ];

    /** @var array<string> Expensive string processing functions */
    private const EXPENSIVE_STRING_FUNCTIONS = [
        'preg_match', 'preg_replace', 'preg_match_all', 'preg_split',
        'str_replace', 'str_ireplace', 'substr_replace', 'mb_ereg_replace',
    ];

    /** @var array<string> Expensive collection methods on large datasets */
    private const EXPENSIVE_COLLECTION_METHODS = [
        '->toArray(', '->all(', '->toJson(', '->jsonSerialize(',
    ];

    /** @var array<string> Non-Eloquent classes with DB-like method names */
    private const NON_ELOQUENT_CLASSES = [
        'Collection',
        'Arr',
        'Carbon',
        'CarbonImmutable',
        'DateTime',
        'DateTimeImmutable',
        'Factory',
        'Str',
        'Validator',
    ];

    /**
     * @var array<string> Class name suffixes that are NEVER Eloquent models.
     *
     * These suffixes indicate classes that definitively cannot be Eloquent models,
     * so we skip them unconditionally.
     */
    private const DEFINITE_NON_MODEL_SUFFIXES = [
        'Service',
        'Repository',
        'Helper',
        'Handler',
        'Provider',
        'Facade',
        'Controller',
        'Middleware',
        'Policy',
        'Event',
        'Listener',
        'Job',
        'Mail',
        'Notification',
        'Command',
        'Request',
        'Rule',
        'Exception',
        'Trait',
        'Interface',
        'Contract',
        'Test',
        'Seeder',
        'Migration',
        'Observer',
        'Scope',
        'Cast',
        'Enum',
        'Factory',
        'Action',
    ];

    /**
     * @var array<string> Class name suffixes that MIGHT be Eloquent models.
     *
     * These suffixes are ambiguous - they could be model names like "OrderResource"
     * or non-model classes like "ApiResource". We only skip them if there's NO
     * terminal method present. If a terminal method IS present, we flag it.
     */
    private const AMBIGUOUS_SUFFIXES = [
        'Resource',
        'Manager',
        'Builder',
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
        $foreachDepth = 0;

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

            // Track @foreach depth for nested loop detection
            if (preg_match('/@foreach\b/', $trimmed)) {
                $foreachDepth++;
            }
            if (preg_match('/@endforeach\b/', $trimmed)) {
                $foreachDepth = max(0, $foreachDepth - 1);
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

            // Check for expensive computation
            if ($this->hasExpensiveComputation($line, $foreachDepth)) {
                $this->reportedLines[$lineNumber] = true;

                $issues[] = $this->createIssueWithSnippet(
                    message: 'Expensive computation found in Blade template',
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Medium,
                    recommendation: 'Move expensive operations to controllers or services. Use computed properties or view composers for complex transformations',
                    code: 'blade-expensive-computation',
                    metadata: ['line' => $lineNumber + 1]
                );

                continue;
            }

            // Check for nested @foreach
            if ($foreachDepth >= 2 && preg_match('/@foreach\b/', $trimmed)) {
                $this->reportedLines[$lineNumber] = true;

                $issues[] = $this->createIssueWithSnippet(
                    message: sprintf('Nested @foreach detected (depth: %d) - potential performance issue', $foreachDepth),
                    filePath: $file,
                    lineNumber: $lineNumber + 1,
                    severity: Severity::Medium,
                    recommendation: 'Flatten nested data in the controller using eager loading or collection methods. Deeply nested loops in Blade can cause O(n²) or worse rendering performance',
                    code: 'blade-nested-foreach',
                    metadata: ['line' => $lineNumber + 1, 'depth' => $foreachDepth]
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

        // Check definite DB patterns first (always flag)
        foreach (self::DEFINITE_DB_PATTERNS as $pattern) {
            if (preg_match($pattern, $line, $matches, PREG_OFFSET_CAPTURE)) {
                if ($this->isInsideStringOrComment($line, $matches[0][1])) {
                    continue;
                }

                return true;
            }
        }

        // Check self-terminal patterns (::all(), ::find(), ::first(), ::create(), etc.)
        // These ARE terminal operations - they don't need a chained method
        foreach (self::SELF_TERMINAL_DB_PATTERNS as $pattern) {
            if (preg_match($pattern, $line, $matches, PREG_OFFSET_CAPTURE)) {
                if ($this->isInsideStringOrComment($line, $matches[0][1])) {
                    continue;
                }

                // Skip known non-Eloquent static calls (Arr::first, Carbon::create, Factory::create, etc.)
                if ($this->isNonEloquentStaticCall($line, $matches[0][1])) {
                    continue;
                }

                // Self-terminal patterns are flagged unless whitelisted
                return true;
            }
        }

        // Check chain patterns (::where() etc.) - require terminal method OR FQCN
        foreach (self::CHAIN_DB_PATTERNS as $pattern) {
            if (preg_match($pattern, $line, $matches, PREG_OFFSET_CAPTURE)) {
                // Check if the match is inside a string or comment
                if ($this->isInsideStringOrComment($line, $matches[0][1])) {
                    continue;
                }

                // Skip known non-Eloquent static calls (Collection::where, Arr::where)
                if ($this->isNonEloquentStaticCall($line, $matches[0][1])) {
                    continue;
                }

                // Check if FQCN contains Models namespace - definitely a model
                if ($this->isFromModelsNamespace($line, $matches[0][1])) {
                    return true;
                }

                // For short class names, require terminal method to confirm it's a DB query
                if ($this->hasTerminalMethod($line)) {
                    return true;
                }

                // Uncertain case: short class name without terminal method
                // Don't flag to avoid false positives (e.g., SomeQueryBuilder::where('x', 'y'))
                continue;
            }
        }

        // Check for model save (but exclude file uploads and other non-DB patterns)
        if (preg_match('/\$(\w+)->save\s*\(/', $line, $matches, PREG_OFFSET_CAPTURE)) {
            // Check if the match is inside a string or comment
            if ($this->isInsideStringOrComment($line, $matches[0][1])) {
                return false;
            }

            // Exclude common non-database save patterns
            $variableName = $matches[1][0];
            if (in_array($variableName, self::NON_DB_SAVE_VARIABLES, true)) {
                return false;
            }

            return true; // Likely a model save
        }

        // Check for relationship queries with various terminal methods
        if (preg_match('/\$(\w+)->(\w+)\(\)->(get|first|find|count|exists|pluck|sum|avg|min|max)\s*\(/', $line, $matches, PREG_OFFSET_CAPTURE)) {
            // Check if the match is inside a string or comment
            if ($this->isInsideStringOrComment($line, $matches[0][1])) {
                return false;
            }

            // Check if variable name suggests a collection, not a model
            $variableName = strtolower($matches[1][0]);
            foreach (self::COLLECTION_VARIABLE_PATTERNS as $collectionPattern) {
                if (str_contains($variableName, $collectionPattern)) {
                    return false; // Likely a collection, not a model relationship
                }
            }

            return true; // Likely $user->posts()->get(), $user->posts()->first(), etc.
        }

        return false;
    }

    /**
     * Check if the class in a static call comes from a Models namespace.
     */
    private function isFromModelsNamespace(string $line, int $matchPosition): bool
    {
        $beforeMatch = substr($line, 0, $matchPosition);

        foreach (self::MODEL_NAMESPACE_INDICATORS as $indicator) {
            if (str_contains($beforeMatch, $indicator)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the line contains a terminal method that confirms a DB query.
     */
    private function hasTerminalMethod(string $line): bool
    {
        foreach (self::TERMINAL_DB_METHODS as $terminal) {
            if (str_contains($line, $terminal)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a static method call is from a non-Eloquent class.
     *
     * Classes like Collection, Arr, Carbon have methods (where, first, all, create)
     * that look like Eloquent queries but are not database operations.
     */
    private function isNonEloquentStaticCall(string $line, int $matchPosition): bool
    {
        $beforeMatch = substr($line, 0, $matchPosition);
        $trimmed = rtrim($beforeMatch);

        // Dynamic class resolution - uncertain, so don't flag
        // e.g., ($foo ? Arr : Model)::where(), $class::where()
        if (str_ends_with($trimmed, ')') || preg_match('/\$\w+$/', $trimmed)) {
            return true;
        }

        // Extract class name from FQCN: \Illuminate\Support\Collection -> Collection
        // Handles: Collection, \Collection, Some\Namespace\Collection
        if (preg_match('/\\\\?(?:[A-Za-z_][A-Za-z0-9_]*\\\\)*([A-Za-z_][A-Za-z0-9_]*)$/', $trimmed, $matches)) {
            $className = $matches[1];

            // Check exact class name match
            if (in_array($className, self::NON_ELOQUENT_CLASSES, true)) {
                return true;
            }

            // Check definite non-model suffixes (always skip)
            foreach (self::DEFINITE_NON_MODEL_SUFFIXES as $suffix) {
                if (str_ends_with($className, $suffix)) {
                    return true;
                }
            }

            // Check ambiguous suffixes (only skip if NO terminal method present)
            // e.g., OrderResource::where('x', 'y')->get() should be FLAGGED
            // e.g., OrderResource::where('x', 'y') without terminal should NOT be flagged
            foreach (self::AMBIGUOUS_SUFFIXES as $suffix) {
                if (str_ends_with($className, $suffix)) {
                    if ($this->hasTerminalMethod($line)) {
                        return false; // Has terminal method = likely DB query, DO flag
                    }

                    return true; // No terminal = uncertain, skip to avoid false positive
                }
            }

            return false;
        }

        // Fallback to original behavior
        foreach (self::NON_ELOQUENT_CLASSES as $class) {
            if (str_ends_with($beforeMatch, $class)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a match position is inside a string literal or comment.
     */
    private function isInsideStringOrComment(string $line, int $matchPosition): bool
    {
        $beforeMatch = substr($line, 0, $matchPosition);

        // Check for single-line comment before match position
        $singleCommentPos = strpos($beforeMatch, '//');
        if ($singleCommentPos !== false) {
            return true;
        }

        // Check if we're inside a string literal by counting quotes
        $inSingleQuote = false;
        $inDoubleQuote = false;

        for ($i = 0; $i < $matchPosition; $i++) {
            $char = $line[$i];
            $prevChar = $i > 0 ? $line[$i - 1] : '';

            // Skip escaped quotes
            if ($prevChar === '\\') {
                continue;
            }

            if ($char === "'" && ! $inDoubleQuote) {
                $inSingleQuote = ! $inSingleQuote;
            } elseif ($char === '"' && ! $inSingleQuote) {
                $inDoubleQuote = ! $inDoubleQuote;
            }
        }

        return $inSingleQuote || $inDoubleQuote;
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
            if (preg_match($pattern, $line, $matches, PREG_OFFSET_CAPTURE)) {
                // Check if the match is inside a string or comment
                if ($this->isInsideStringOrComment($line, $matches[0][1])) {
                    continue;
                }

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

        // Skip null coalescing operators ({{ $value ?? 0 }})
        if (preg_match('/\{\{\s*\$\w+(?:->\w+)?\s*\?\?\s*(?:\d+|[\'"][^\'"]*[\'"]|null)\s*\}\}/', $line)) {
            return false;
        }

        // Skip simple single operations including object properties (these are often acceptable)
        // Matches: {{ $price * $quantity }}, {{ $item->price * $qty }}, {{ $a + $b->value }}
        if (preg_match('/\{\{\s*\$\w+(?:->\w+)?\s*[\+\-\*\/]\s*\$\w+(?:->\w+)?\s*\}\}/', $line)) {
            return false; // {{ $price * $quantity }} or {{ $item->price * $qty }} is acceptable
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

    /**
     * Check for expensive computation patterns in Blade.
     *
     * Detects:
     * - Regex/string processing inside foreach loops
     * - Expensive collection methods (->toArray(), ->all()) anywhere
     */
    private function hasExpensiveComputation(string $line, int $foreachDepth): bool
    {
        // Check for expensive string functions inside loops
        if ($foreachDepth >= 1) {
            foreach (self::EXPENSIVE_STRING_FUNCTIONS as $func) {
                if (preg_match('/\b'.preg_quote($func, '/').'\s*\(/', $line)) {
                    return true;
                }
            }
        }

        // Check for expensive collection methods anywhere
        foreach (self::EXPENSIVE_COLLECTION_METHODS as $method) {
            if (str_contains($line, $method)) {
                $methodPos = strpos($line, $method);
                if ($methodPos !== false && ! $this->isInsideStringOrComment($line, $methodPos)) {
                    return true;
                }
            }
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

        // Check for additional collection methods in foreach
        $collectionMethods = implode('|', self::COLLECTION_MANIPULATION_METHODS);
        if (preg_match('/@foreach\s*\(.*->('.$collectionMethods.')\(/', $line)) {
            return true; // Collection manipulation in foreach
        }

        // Handle collect() helper with collection methods
        if (preg_match('/@foreach\s*\(\s*collect\s*\(.*\)->(filter|map|transform|sortBy|'.$collectionMethods.')\(/', $line)) {
            return true; // collect($items)->filter() in foreach
        }

        // Check for array_* functions (data manipulation) using word boundary regex
        foreach (self::BUSINESS_LOGIC_FUNCTIONS as $func) {
            if (preg_match('/\b'.preg_quote($func, '/').'\s*\(/', $line)) {
                return true;
            }
        }

        return false;
    }
}
