<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Detects business logic in route files.
 *
 * Finds closures in routes with > 5 lines, DB queries,
 * and business logic that should be in controllers/actions.
 */
class LogicInRoutesAnalyzer extends AbstractFileAnalyzer
{
    public const DEFAULT_MAX_CLOSURE_LINES = 5;

    public const DEFAULT_ALLOW_SIMPLE_READS = true;

    private int $maxClosureLines;

    private bool $allowSimpleReads;

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'logic-in-routes',
            name: 'Logic in Routes Analyzer',
            description: 'Detects business logic in route files that should be moved to controllers or action classes',
            category: Category::BestPractices,
            severity: Severity::High,
            tags: ['laravel', 'routes', 'mvc', 'architecture', 'best-practices'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/logic-in-routes',
            timeToFix: 20
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration
        $analyzerConfig = $this->config->get('shieldci.analyzers.best-practices.logic-in-routes', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->maxClosureLines = $analyzerConfig['max_closure_lines'] ?? self::DEFAULT_MAX_CLOSURE_LINES;
        $this->allowSimpleReads = $analyzerConfig['allow_simple_reads'] ?? self::DEFAULT_ALLOW_SIMPLE_READS;

        $issues = [];

        // Only set default paths if not already set (allows tests to override)
        if (empty($this->paths)) {
            $this->setBasePath(base_path());
            $this->setPaths(['routes']);
        }

        $routeFiles = $this->getPhpFiles();

        foreach ($routeFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new LogicInRoutesVisitor($this->maxClosureLines, $this->allowSimpleReads);
                $traverser = new NodeTraverser;
                $traverser->addVisitor(new NameResolver);
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: $issue['message'],
                        filePath: $file,
                        lineNumber: $issue['line'],
                        severity: $issue['severity'],
                        recommendation: $issue['recommendation'],
                        code: $issue['code'],
                        metadata: $issue['metadata'] ?? []
                    );
                }
            } catch (\Throwable $e) {
                // Skip files with parse errors
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('No business logic found in route files');
        }

        return $this->failed(
            sprintf('Found %d route(s) with business logic that should be moved to controllers', count($issues)),
            $issues
        );
    }
}

/**
 * Visitor to detect logic in route closures.
 */
class LogicInRoutesVisitor extends NodeVisitorAbstract
{
    /** @var list<string> Functions that indicate business logic */
    private const BUSINESS_LOGIC_FUNCTIONS = [
        'dispatch', 'dispatch_sync', 'dispatch_now',  // Jobs
        'event',                                       // Events
        'report', 'rescue',                           // Error handling
        'broadcast',                                   // Broadcasting
        'app', 'resolve',                             // Service container
        'retry',                                       // Retry logic
    ];

    /** @var list<string> Facades that indicate business logic */
    private const BUSINESS_LOGIC_FACADES = [
        'Mail',
        'Notification',
        'Queue',
        'Event',
        'Bus',
        'Broadcast',
        'Illuminate\\Support\\Facades\\Mail',
        'Illuminate\\Support\\Facades\\Notification',
        'Illuminate\\Support\\Facades\\Queue',
        'Illuminate\\Support\\Facades\\Event',
        'Illuminate\\Support\\Facades\\Bus',
        'Illuminate\\Support\\Facades\\Broadcast',
    ];

    /** @var list<string> Service container methods */
    private const SERVICE_CONTAINER_METHODS = ['make', 'makeWith', 'call', 'get'];

    /** @var list<string> Known query methods on Eloquent models (includes both read and write) */
    private const QUERY_METHODS = [
        'where', 'find', 'all', 'first', 'create', 'query',
        'findOrFail', 'firstOrFail', 'get', 'pluck', 'count',
        'exists', 'doesntExist', 'with', 'without',
    ];

    /** @var list<string> Write methods that indicate business logic (mutations) */
    private const WRITE_METHODS = [
        'create', 'insert', 'insertOrIgnore', 'insertGetId',
        'update', 'updateOrCreate', 'updateOrInsert',
        'delete', 'destroy', 'forceDelete', 'truncate',
        'save', 'push', 'touch', 'increment', 'decrement',
        'upsert', 'firstOrCreate', 'firstOrNew',
    ];

    /** @var list<string> Eloquent static query methods (entry points) */
    private const STATIC_QUERY_METHODS = ['where', 'find', 'all', 'first', 'query'];

    /** @var list<string> Terminal read methods that complete a query chain */
    private const TERMINAL_READ_METHODS = [
        'first', 'firstOrFail', 'find', 'findOrFail', 'get', 'pluck',
        'count', 'exists', 'sole', 'soleOrFail', 'value',
    ];

    /** @var list<string> Utility classes that are NOT business logic */
    private const UTILITY_CLASSES = [
        'Carbon', 'Collection', 'Validator', 'Cache', 'Log',
        'Session', 'Cookie', 'Request', 'Response', 'View',
        'Config', 'Str', 'Arr', 'File', 'Storage', 'Hash',
        'Crypt', 'Route', 'URL', 'Redirect', 'DB', 'App',
        'Auth', 'Gate', 'Password', 'RateLimiter', 'Schema',
    ];

    /** @var list<string> Laravel helper functions that support safe fluent chaining */
    private const SAFE_FLUENT_HELPER_FUNCTIONS = [
        'view',
        'response',
        'redirect',
        'back',
        'to_route',
        'request',
        'collect',
        'cookie',
        'url',
        'asset',
        'route',
        'action',
        'now',
        'today',
    ];

    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string, metadata: array<string, mixed>}> */
    private array $issues = [];

    /** @var array<int, true> Track which positions already have issues to avoid duplicates */
    private array $reportedPositions = [];

    public function __construct(
        private int $maxClosureLines,
        private bool $allowSimpleReads = true
    ) {}

    public function leaveNode(Node $node): ?Node
    {
        // Detect Route::* method calls
        // We use leaveNode instead of enterNode so that NameResolver has already
        // processed all child nodes (including closure contents) by this point.
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name && $this->isRouteFacade($node->class)) {
                $this->analyzeRouteCall($node);
            }
        }

        return null;
    }

    /**
     * Check if the class name is the Route facade.
     *
     * Handles both short names (Route) and fully qualified names
     * (Illuminate\Support\Facades\Route) after NameResolver processing.
     */
    private function isRouteFacade(Node\Name $name): bool
    {
        // After NameResolver, get the resolved name
        $resolvedName = $name->getAttribute('resolvedName');
        $className = $resolvedName instanceof Node\Name\FullyQualified
            ? $resolvedName->toString()
            : $name->toString();

        // Normalize (remove leading backslash)
        $className = ltrim($className, '\\');

        // Check for Route facade (FQN or short name)
        return $className === 'Illuminate\\Support\\Facades\\Route'
            || $className === 'Route';
    }

    /**
     * @return array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string, metadata: array<string, mixed>}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }

    /**
     * Determine if a class name likely represents an Eloquent model.
     *
     * Uses fully qualified name from NameResolver when available.
     * After NameResolver runs, class names are resolved to FullyQualified nodes
     * containing the complete namespace (e.g., "Product" becomes "App\Models\Product").
     *
     * This method is public static so anonymous visitor classes can call it.
     *
     * @param  list<string>  $utilityClasses
     *
     * @internal
     */
    public static function isLikelyModel(Node\Name $name, array $utilityClasses): bool
    {
        // After NameResolver, the name itself is the FQN (as FullyQualified node)
        // or if not resolved, just the short name
        $fqn = $name->toString();
        $normalized = ltrim($fqn, '\\');

        // Extract short class name for utility check
        $parts = explode('\\', $normalized);
        $shortName = end($parts) ?: $normalized;

        // Quick rejection: known utility classes
        if (in_array($shortName, $utilityClasses, true)) {
            return false;
        }

        // Check model namespace patterns (from resolved FQN)
        if (str_starts_with($normalized, 'App\\Models\\') ||
            str_starts_with($normalized, 'App\\Model\\')) {
            return true;
        }

        // Domain-driven patterns: any namespace containing \Models\
        if (str_contains($normalized, '\\Models\\')) {
            return true;
        }

        // Class name ends with Model suffix
        if (str_ends_with($normalized, 'Model')) {
            return true;
        }

        // Cannot determine from namespace - assume NOT a model
        return false;
    }

    private function analyzeRouteCall(Node\Expr\StaticCall $node): void
    {
        if (empty($node->args)) {
            return;
        }

        // Check each argument for closures
        foreach ($node->args as $arg) {
            if ($arg->value instanceof Node\Expr\Closure || $arg->value instanceof Node\Expr\ArrowFunction) {
                $this->analyzeClosure($arg->value);
            }
        }
    }

    private function analyzeClosure(Node\Expr\Closure|Node\Expr\ArrowFunction $closure): void
    {
        $line = $closure->getStartLine();
        $position = $closure->getStartFilePos();

        // Skip if we've already reported an issue for this position
        if (isset($this->reportedPositions[$position])) {
            return;
        }

        // Collect all problems with this closure
        $problems = [];
        $maxSeverity = Severity::Low;

        // Analyze database queries with granular classification
        $queryInfo = $this->analyzeDbQueries($closure);

        if ($queryInfo['has_writes']) {
            $problems[] = 'database write operations';
            $maxSeverity = Severity::High;
        } elseif ($queryInfo['has_raw_queries']) {
            $problems[] = 'raw database queries';
            $maxSeverity = Severity::High;
        } elseif ($queryInfo['has_complex_reads']) {
            $problems[] = 'complex database queries';
            if ($maxSeverity->level() < Severity::Medium->level()) {
                $maxSeverity = Severity::Medium;
            }
        } elseif ($queryInfo['has_simple_reads'] && ! $this->allowSimpleReads) {
            $problems[] = 'database queries (strict mode)';
            $maxSeverity = Severity::Low;
        }
        // Note: simple reads with allowSimpleReads=true are not flagged

        // Check for complex business logic
        if ($this->hasComplexBusinessLogic($closure)) {
            $problems[] = 'complex business logic';
            if ($maxSeverity->level() < Severity::High->level()) {
                $maxSeverity = Severity::High;
            }
        }

        // Count lines in closure
        $lineCount = $closure->getEndLine() - $closure->getStartLine() + 1;
        if ($lineCount > $this->maxClosureLines) {
            $problems[] = sprintf('%d lines (max: %d)', $lineCount, $this->maxClosureLines);
            if ($maxSeverity->level() < Severity::Medium->level()) {
                $maxSeverity = Severity::Medium;
            }
        }

        // If any problems found, create a consolidated issue
        if (! empty($problems)) {
            $this->reportedPositions[$position] = true;

            $problemList = implode(', ', $problems);
            $code = $this->determineIssueCode($problems, $queryInfo);

            $this->issues[] = [
                'message' => "Route closure contains {$problemList}",
                'line' => $line,
                'severity' => $maxSeverity,
                'recommendation' => $this->getRecommendation($problems, $queryInfo),
                'code' => $code,
                'metadata' => [
                    'problems' => $problems,
                    'line_count' => $lineCount,
                    'has_db_queries' => $queryInfo['has_writes'] || $queryInfo['has_raw_queries'] || $queryInfo['has_complex_reads'] || $queryInfo['has_simple_reads'],
                    'has_write_queries' => $queryInfo['has_writes'],
                    'has_raw_queries' => $queryInfo['has_raw_queries'],
                    'has_complex_reads' => $queryInfo['has_complex_reads'],
                    'has_simple_reads' => $queryInfo['has_simple_reads'],
                    'has_business_logic' => in_array('complex business logic', $problems),
                ],
            ];
        }
    }

    /**
     * @param  array<string>  $problems
     * @param  array{has_writes: bool, has_raw_queries: bool, has_complex_reads: bool, has_simple_reads: bool, chain_length: int}  $queryInfo
     */
    private function determineIssueCode(array $problems, array $queryInfo): string
    {
        // Prioritize codes by severity
        if (in_array('database write operations', $problems)) {
            return 'route-has-db-writes';
        }

        if (in_array('raw database queries', $problems)) {
            return 'route-has-raw-queries';
        }

        if (in_array('complex database queries', $problems)) {
            return 'route-has-complex-queries';
        }

        if (in_array('database queries (strict mode)', $problems)) {
            return 'route-has-db-queries';
        }

        if (in_array('complex business logic', $problems)) {
            return 'route-has-business-logic';
        }

        // Must be line count issue
        return 'route-closure-too-long';
    }

    /**
     * @param  array<string>  $problems
     * @param  array{has_writes: bool, has_raw_queries: bool, has_complex_reads: bool, has_simple_reads: bool, chain_length: int}  $queryInfo
     */
    private function getRecommendation(array $problems, array $queryInfo): string
    {
        if (in_array('database write operations', $problems)) {
            return 'Database write operations (create, update, delete) should not be in route files. Move this logic to a controller method where you can properly handle validation, authorization, and error handling.';
        }

        if (in_array('raw database queries', $problems)) {
            return 'Raw database queries using the DB facade should not be in route files. Move this logic to a controller method and consider using Eloquent models for type safety.';
        }

        if (in_array('complex database queries', $problems)) {
            return 'Complex database queries with method chaining should be moved to a controller or repository. Consider using route model binding for simple lookups.';
        }

        if (in_array('database queries (strict mode)', $problems)) {
            return 'Database queries are discouraged in route files (strict mode enabled). Consider using route model binding or moving the query to a controller.';
        }

        if (in_array('complex business logic', $problems)) {
            return 'Complex business logic should be in service classes or controllers, not in route files. Route files should only define routes.';
        }

        return 'Move route logic to a controller method or single-action controller. Route files should only define routes, not contain implementation details.';
    }

    /**
     * Analyze database queries in the closure and classify them.
     *
     * @return array{has_writes: bool, has_raw_queries: bool, has_complex_reads: bool, has_simple_reads: bool, chain_length: int}
     */
    private function analyzeDbQueries(Node\Expr\Closure|Node\Expr\ArrowFunction $closure): array
    {
        $result = [
            'has_writes' => false,
            'has_raw_queries' => false,
            'has_complex_reads' => false,
            'has_simple_reads' => false,
            'chain_length' => 0,
        ];

        $visitor = new class($result, self::WRITE_METHODS, self::STATIC_QUERY_METHODS, self::UTILITY_CLASSES, self::TERMINAL_READ_METHODS) extends NodeVisitorAbstract
        {
            /** @var array<int, true> Track StaticCalls that are roots of method chains */
            private array $processedChainRoots = [];

            /**
             * @param  array{has_writes: bool, has_raw_queries: bool, has_complex_reads: bool, has_simple_reads: bool, chain_length: int}  $result
             * @param  list<string>  $writeMethods
             * @param  list<string>  $staticQueryMethods
             * @param  list<string>  $utilityClasses
             * @param  list<string>  $terminalReadMethods
             */
            public function __construct(
                private array &$result,
                private array $writeMethods,
                private array $staticQueryMethods,
                private array $utilityClasses,
                private array $terminalReadMethods
            ) {}

            public function enterNode(Node $node): ?Node
            {
                // Check for DB facade calls (raw queries - always flagged)
                if ($node instanceof Node\Expr\StaticCall) {
                    if ($node->class instanceof Node\Name && $this->isDbFacade($node->class)) {
                        $this->result['has_raw_queries'] = true;

                        return null;
                    }
                }

                // Process MethodCalls - walk DOWN via ->var to analyze Eloquent chains
                if ($node instanceof Node\Expr\MethodCall) {
                    $chainInfo = $this->analyzeMethodCallChain($node);

                    if ($chainInfo['is_eloquent_chain']) {
                        // Mark the root StaticCall as processed so it's not double-counted
                        if ($chainInfo['root_position'] !== null) {
                            $this->processedChainRoots[$chainInfo['root_position']] = true;
                        }

                        if ($chainInfo['has_writes']) {
                            $this->result['has_writes'] = true;
                        } elseif ($chainInfo['chain_length'] >= 3) {
                            $this->result['has_complex_reads'] = true;
                            $this->result['chain_length'] = max($this->result['chain_length'], $chainInfo['chain_length']);
                        } elseif ($chainInfo['chain_length'] === 2) {
                            // 2 method chain - check if it ends with a terminal read
                            // e.g., User::where('slug', $slug)->first() is a simple read
                            // but User::where('slug', $slug)->orderBy('name') is incomplete/complex
                            $lastMethod = end($chainInfo['methods']);
                            if ($lastMethod !== false && in_array($lastMethod, $this->terminalReadMethods, true)) {
                                $this->result['has_simple_reads'] = true;
                            } else {
                                $this->result['has_complex_reads'] = true;
                            }
                        }
                        // Note: chain_length === 1 with MethodCall means the static method
                        // returned something that had a method called on it - this is handled
                        // by the StaticCall branch below for simple reads
                    }

                    // Check for SQL-specific methods that indicate complex queries
                    if ($node->name instanceof Node\Identifier) {
                        $method = $node->name->toString();

                        // SQL-specific methods (not found on Collections)
                        $queryBuilderMethods = [
                            'orWhere', 'whereIn', 'whereNotIn', 'whereBetween', 'whereNull',
                            'join', 'leftJoin', 'rightJoin', 'crossJoin',
                            'having', 'havingRaw', 'groupBy',
                            'union', 'unionAll',
                            'lockForUpdate', 'sharedLock',
                        ];
                        if (in_array($method, $queryBuilderMethods, true)) {
                            $this->result['has_complex_reads'] = true;
                        }
                    }

                    return null;
                }

                // Handle direct StaticCalls on models (no method chain following)
                // e.g., User::create([...]), User::find($id), User::all()
                if ($node instanceof Node\Expr\StaticCall) {
                    // Skip if this StaticCall was already processed as part of a method chain
                    $position = $node->getStartFilePos();
                    if (isset($this->processedChainRoots[$position])) {
                        return null;
                    }

                    if ($node->name instanceof Node\Identifier && $node->class instanceof Node\Name) {
                        $method = $node->name->toString();

                        // Check if this is likely an Eloquent model
                        if (! $this->isLikelyModel($node->class)) {
                            return null;
                        }

                        // Direct write method (e.g., User::create([...]))
                        if (in_array($method, $this->writeMethods, true)) {
                            $this->result['has_writes'] = true;

                            return null;
                        }

                        // Query starter methods or simple reads
                        if (in_array($method, $this->staticQueryMethods, true)) {
                            if ($this->isDirectSimpleRead($method)) {
                                $this->result['has_simple_reads'] = true;
                            } else {
                                // Query starters like 'query', 'where' that return a builder
                                // These indicate database query usage even without chaining
                                // (the query builder will be used somewhere)
                                $this->result['has_complex_reads'] = true;
                            }
                        }
                    }
                }

                return null;
            }

            /**
             * Check if the class name is the DB facade.
             */
            private function isDbFacade(Node\Name $name): bool
            {
                $resolvedName = $name->getAttribute('resolvedName');
                $className = $resolvedName instanceof Node\Name\FullyQualified
                    ? $resolvedName->toString()
                    : $name->toString();

                $className = ltrim($className, '\\');

                return $className === 'Illuminate\\Support\\Facades\\DB'
                    || $className === 'DB';
            }

            /**
             * Determine if a class name likely represents an Eloquent model.
             */
            private function isLikelyModel(Node\Name $name): bool
            {
                return LogicInRoutesVisitor::isLikelyModel($name, $this->utilityClasses);
            }

            /**
             * Check if a static method is a direct simple read (returns data without chaining).
             */
            private function isDirectSimpleRead(string $method): bool
            {
                $directReadMethods = ['find', 'findOrFail', 'findOr', 'findMany', 'all', 'first', 'firstOrFail'];

                return in_array($method, $directReadMethods, true);
            }

            /**
             * Walk DOWN via ->var to analyze a method call chain.
             *
             * This approach walks from the outermost MethodCall down through
             * the chain to find if the root is a model StaticCall.
             *
             * @return array{is_eloquent_chain: bool, chain_length: int, has_writes: bool, methods: list<string>, root_position: int|null}
             */
            private function analyzeMethodCallChain(Node\Expr\MethodCall $node): array
            {
                $methods = [];
                $hasWrites = false;
                $current = $node;
                $rootPosition = null;

                // Walk down through the method call chain
                while ($current instanceof Node\Expr\MethodCall) {
                    if ($current->name instanceof Node\Identifier) {
                        $method = $current->name->toString();
                        array_unshift($methods, $method); // Prepend to maintain order
                        if (in_array($method, $this->writeMethods, true)) {
                            $hasWrites = true;
                        }
                    }
                    $current = $current->var;
                }

                // Check if root is a StaticCall on a model
                $isEloquentChain = false;
                if ($current instanceof Node\Expr\StaticCall
                    && $current->class instanceof Node\Name
                    && $this->isLikelyModel($current->class)) {
                    $isEloquentChain = true;
                    $rootPosition = $current->getStartFilePos();

                    // Include the static method in the chain count
                    if ($current->name instanceof Node\Identifier) {
                        $method = $current->name->toString();
                        array_unshift($methods, $method);
                        if (in_array($method, $this->writeMethods, true)) {
                            $hasWrites = true;
                        }
                    }
                }

                return [
                    'is_eloquent_chain' => $isEloquentChain,
                    'chain_length' => count($methods),
                    'has_writes' => $hasWrites,
                    'methods' => $methods,
                    'root_position' => $rootPosition,
                ];
            }
        };

        // No longer need ParentConnectingVisitor - we walk down via ->var
        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse([$closure]);

        return $result;
    }

    private function hasComplexBusinessLogic(Node\Expr\Closure|Node\Expr\ArrowFunction $closure): bool
    {
        $hasComplexLogic = false;
        $ifDepth = 0;
        $hasLoops = false;

        $visitor = new class($hasComplexLogic, $ifDepth, $hasLoops, self::BUSINESS_LOGIC_FUNCTIONS, self::BUSINESS_LOGIC_FACADES, self::SERVICE_CONTAINER_METHODS, self::QUERY_METHODS, self::UTILITY_CLASSES, self::SAFE_FLUENT_HELPER_FUNCTIONS) extends NodeVisitorAbstract
        {
            /**
             * @param  list<string>  $businessLogicFunctions
             * @param  list<string>  $businessLogicFacades
             * @param  list<string>  $serviceContainerMethods
             * @param  list<string>  $queryMethods
             * @param  list<string>  $utilityClasses
             * @param  list<string>  $safeFluentHelperFunctions
             */
            public function __construct(
                private bool &$hasComplexLogic,
                private int &$ifDepth,
                private bool &$hasLoops,
                private array $businessLogicFunctions,
                private array $businessLogicFacades,
                private array $serviceContainerMethods,
                private array $queryMethods,
                private array $utilityClasses,
                private array $safeFluentHelperFunctions
            ) {}

            public function enterNode(Node $node): ?Node
            {
                if ($this->hasComplexLogic) {
                    return null;
                }

                // 1. Check for business logic function calls
                if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
                    $funcName = $node->name->toString();
                    if (in_array($funcName, $this->businessLogicFunctions, true)) {
                        $this->hasComplexLogic = true;

                        return null;
                    }
                }

                // 2. Check for business logic facade calls and service container
                if ($node instanceof Node\Expr\StaticCall && $node->class instanceof Node\Name) {
                    $className = $this->resolveClassName($node->class);

                    // Business facades (Mail, Notification, Queue, Event, Bus, Broadcast)
                    if (in_array($className, $this->businessLogicFacades, true)) {
                        $this->hasComplexLogic = true;

                        return null;
                    }

                    // Service container calls: App::make(), App::call(), etc.
                    if (($className === 'App' || $className === 'Illuminate\\Support\\Facades\\App')
                        && $node->name instanceof Node\Identifier
                        && in_array($node->name->toString(), $this->serviceContainerMethods, true)) {
                        $this->hasComplexLogic = true;

                        return null;
                    }

                    // Non-query model methods (e.g., User::sendWelcomeEmail())
                    if ($node->name instanceof Node\Identifier) {
                        $method = $node->name->toString();

                        // Only flag if it's a model with a non-query method
                        if ($this->isLikelyModel($node->class)
                            && ! in_array($method, $this->queryMethods, true)) {
                            $this->hasComplexLogic = true;

                            return null;
                        }
                    }
                }

                // 3. Check for heavy method chains (3+ calls)
                if ($node instanceof Node\Expr\MethodCall) {
                    $chainLength = $this->countMethodChain($node);
                    if ($chainLength >= 3) {
                        // Skip if chain starts from safe fluent API helper
                        if (! $this->isChainFromSafeFluentRoot($node)) {
                            $this->hasComplexLogic = true;

                            return null;
                        }
                    }
                }

                // Track loops (complex only if they contain calculations)
                if ($node instanceof Node\Stmt\Foreach_
                    || $node instanceof Node\Stmt\For_
                    || $node instanceof Node\Stmt\While_
                    || $node instanceof Node\Stmt\Do_
                ) {
                    $this->hasLoops = true;
                    // Don't return null - continue traversing to find arithmetic inside
                }

                // Track nested conditionals (nested if = complex)
                if ($node instanceof Node\Stmt\If_) {
                    $this->ifDepth++;
                    if ($this->ifDepth > 1) {
                        // Nested if statements indicate complexity
                        $this->hasComplexLogic = true;
                    }
                }

                // Check for complex calculations (only in loops or nested logic)
                if ($this->hasLoops || $this->ifDepth > 1) {
                    // Binary arithmetic operators
                    if ($node instanceof Node\Expr\BinaryOp\Plus
                        || $node instanceof Node\Expr\BinaryOp\Minus
                        || $node instanceof Node\Expr\BinaryOp\Mul
                        || $node instanceof Node\Expr\BinaryOp\Div
                    ) {
                        $this->hasComplexLogic = true;
                    }
                    // Compound assignment operators (+=, -=, *=, /=)
                    if ($node instanceof Node\Expr\AssignOp\Plus
                        || $node instanceof Node\Expr\AssignOp\Minus
                        || $node instanceof Node\Expr\AssignOp\Mul
                        || $node instanceof Node\Expr\AssignOp\Div
                    ) {
                        $this->hasComplexLogic = true;
                    }
                }

                return null;
            }

            public function leaveNode(Node $node): ?Node
            {
                // Track when leaving if statements
                if ($node instanceof Node\Stmt\If_) {
                    $this->ifDepth--;
                }

                return null;
            }

            /**
             * Resolve class name from a Node\Name, handling FQN and aliases.
             */
            private function resolveClassName(Node\Name $name): string
            {
                $resolvedName = $name->getAttribute('resolvedName');
                $className = $resolvedName instanceof Node\Name\FullyQualified
                    ? $resolvedName->toString()
                    : $name->toString();

                return ltrim($className, '\\');
            }

            /**
             * Determine if a class name likely represents an Eloquent model.
             */
            private function isLikelyModel(Node\Name $name): bool
            {
                return LogicInRoutesVisitor::isLikelyModel($name, $this->utilityClasses);
            }

            /**
             * Count the length of a method call chain.
             */
            private function countMethodChain(Node\Expr\MethodCall $node): int
            {
                $count = 1;
                $current = $node->var;
                while ($current instanceof Node\Expr\MethodCall) {
                    $count++;
                    $current = $current->var;
                }

                return $count;
            }

            /**
             * Get the root expression of a method chain.
             */
            private function getChainRoot(Node\Expr\MethodCall $node): Node\Expr
            {
                $current = $node->var;
                while ($current instanceof Node\Expr\MethodCall) {
                    $current = $current->var;
                }

                return $current;
            }

            /**
             * Check if a method chain starts from a safe fluent API helper function.
             */
            private function isChainFromSafeFluentRoot(Node\Expr\MethodCall $node): bool
            {
                $root = $this->getChainRoot($node);

                if ($root instanceof Node\Expr\FuncCall && $root->name instanceof Node\Name) {
                    return in_array($root->name->toString(), $this->safeFluentHelperFunctions, true);
                }

                return false;
            }
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse([$closure]);

        return $hasComplexLogic;
    }
}
