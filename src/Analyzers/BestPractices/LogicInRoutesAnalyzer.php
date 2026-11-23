<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\ErrorHandler;
use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Concerns\ReadsConfigArrays;
use ShieldCI\Support\EloquentModelDetector;

/**
 * Detects business logic in route files.
 *
 * Finds closures in routes with > 5 lines, DB queries,
 * and business logic that should be in controllers/actions.
 */
class LogicInRoutesAnalyzer extends AbstractFileAnalyzer
{
    use ReadsConfigArrays;

    public const DEFAULT_MAX_CLOSURE_LINES = 5;

    public const DEFAULT_ALLOW_SIMPLE_READS = true;

    private int $maxClosureLines;

    private bool $allowSimpleReads;

    private ?EloquentModelDetector $modelDetector = null;

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
            timeToFix: 20
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration
        $analyzerConfig = $this->config->get('shieldci.analyzers.best-practices.logic-in-routes', []);

        $this->maxClosureLines = $this->configInt($analyzerConfig, 'max_closure_lines', self::DEFAULT_MAX_CLOSURE_LINES);
        $this->allowSimpleReads = $this->configBool($analyzerConfig, 'allow_simple_reads', self::DEFAULT_ALLOW_SIMPLE_READS);

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

                $visitor = new LogicInRoutesVisitor($this->maxClosureLines, $this->allowSimpleReads, $this->declaresModel($ast));
                $traverser = new NodeTraverser;
                // replaceNodes stays off because parseFile() hands back a shared, cached AST;
                // the visitor reads the resolvedName attribute instead. A colliding import is
                // recorded and ignored rather than thrown, so the file is not dropped by the
                // catch below.
                $traverser->addVisitor(new NameResolver(new ErrorHandler\Collecting, ['replaceNodes' => false]));
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: $issue['message'],
                        filePath: $file,
                        lineNumber: $issue['line'],
                        severity: $issue['severity'],
                        recommendation: $issue['recommendation'],
                        metadata: array_merge($issue['metadata'] ?? [], ['code' => $issue['code']])
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

        return $this->resultBySeverity(
            sprintf('Found %d route(s) with business logic that should be moved to controllers', count($issues)),
            $issues
        );
    }

    /**
     * The Eloquent verdict for a class referenced in the route file, read off its declaration
     * under app/ and memoised per class name: true or false when the declaration settles it,
     * null when it cannot be read (missing file, vendor parent, outside app/).
     *
     * The detector needs the concrete AstParser. The container binds ParserInterface to the
     * shared AstParser singleton, so this reuses it and its cache; any other parser gets a
     * private AstParser that only reads the declarations.
     *
     * @param  array<Node>  $ast  AST of the route file, whose imports resolve a short name
     * @return \Closure(string): ?bool
     */
    private function declaresModel(array $ast): \Closure
    {
        $detector = $this->modelDetector ??= new EloquentModelDetector(
            $this->parser instanceof AstParser ? $this->parser : new AstParser
        );
        $basePath = $this->getBasePath();
        $verdicts = [];

        return static function (string $className) use ($detector, $ast, $basePath, &$verdicts): ?bool {
            if (! array_key_exists($className, $verdicts)) {
                $verdicts[$className] = $detector->verdictForClassName($className, $ast, $basePath);
            }

            return $verdicts[$className];
        };
    }
}

/**
 * Visitor to detect logic in route closures.
 */
class LogicInRoutesVisitor extends NodeVisitorAbstract
{
    /** @var list<string> Route methods that define handlers (closures with business logic) */
    private const ROUTE_HANDLER_METHODS = [
        'get', 'post', 'put', 'patch', 'delete', 'options', 'any', 'match', 'fallback',
    ];

    /** @var list<string> Functions that indicate business logic */
    private const BUSINESS_LOGIC_FUNCTIONS = [
        'dispatch', 'dispatch_sync', 'dispatch_now',  // Jobs
        'event',                                       // Events
        'report', 'rescue',                           // Error handling
        'broadcast',                                   // Broadcasting
        'app', 'resolve',                             // Service container
        'retry',                                       // Retry logic
    ];

    /** @var list<string> Facades that indicate business logic (short names only - use getShortClassName for comparison) */
    private const BUSINESS_LOGIC_FACADES = [
        'Mail', 'Notification', 'Queue', 'Event', 'Bus', 'Broadcast',
    ];

    /** @var list<string> Static entry points of the Dispatchable trait (jobs and events): `SendDigest::dispatch()` */
    private const DISPATCHABLE_STATIC_METHODS = [
        'dispatch', 'dispatchSync', 'dispatchNow', 'dispatchIf', 'dispatchUnless',
        'dispatchAfterResponse', 'withChain',
    ];

    /** @var list<string> Methods of the Notifiable trait that send a notification: `$user->notify(...)` */
    private const NOTIFY_METHODS = ['notify', 'notifyNow'];

    /** @var list<string> Service container methods */
    private const SERVICE_CONTAINER_METHODS = ['make', 'makeWith', 'call', 'get'];

    /** @var list<string> Known query methods on Eloquent models (includes both read and write) */
    private const QUERY_METHODS = [
        'where', 'find', 'all', 'first', 'query',
        'findOrFail', 'firstOrFail', 'get', 'pluck', 'count',
        'exists', 'doesntExist', 'with', 'without',
    ];

    /** @var list<string> Write methods that indicate business logic (mutations) */
    private const WRITE_METHODS = [
        'create', 'insert', 'insertOrIgnore', 'insertGetId',
        'update', 'updateOrCreate', 'updateOrInsert',
        'delete', 'destroy', 'forceDelete', 'truncate',
        'save', 'push', 'touch', 'increment', 'decrement',
        'upsert', 'firstOrCreate', 'firstOrNew', 'restore',
        'insertUsing', 'insertOrIgnoreUsing', 'createOrFirst',
        'updateOrFail', 'saveOrFail', 'deleteOrFail', 'forceDestroy',
        'incrementEach', 'decrementEach',
        'forceCreate', 'createMany', 'saveMany',
        // Relation writes on pivot rows
        'sync', 'syncWithoutDetaching', 'syncWithPivotValues',
        'attach', 'detach', 'toggle', 'updateExistingPivot',
        // Quiet variants skip model events but still write
        'createQuietly', 'forceCreateQuietly', 'createManyQuietly', 'saveManyQuietly',
        'saveQuietly', 'updateQuietly', 'deleteQuietly', 'forceDeleteQuietly',
        'restoreQuietly', 'incrementQuietly', 'decrementQuietly', 'touchQuietly',
        'pushQuietly',
    ];

    /** @var list<string> Write methods that save only when called without arguments: Model::push() saves, Collection::push($value) does not */
    private const ARGUMENTLESS_WRITE_METHODS = ['push'];

    /** @var list<string> File extensions that make a string argument to attach() a mail attachment path */
    private const ATTACHMENT_EXTENSIONS = [
        'pdf', 'csv', 'tsv', 'txt', 'md', 'rtf', 'doc', 'docx', 'xls', 'xlsx', 'ods', 'odt',
        'ppt', 'pptx', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'zip', 'gz', 'tar', 'ics',
        'vcf', 'xml', 'json', 'html', 'htm', 'eml', 'mp3', 'mp4', 'wav',
    ];

    /** @var list<string> Eloquent static query methods (entry points) */
    private const STATIC_QUERY_METHODS = [
        'where', 'find', 'all', 'first', 'query',
        'findMany', 'findOr', 'firstOr', 'firstWhere', 'sole', 'value',
        'paginate', 'simplePaginate', 'cursorPaginate',
        'sum', 'avg', 'min', 'max', 'cursor', 'lazy',
    ];

    /**
     * Terminal read methods that complete a query chain. chunk() and each() are left out:
     * their callback runs per row and can do anything.
     *
     * @var list<string>
     */
    private const TERMINAL_READ_METHODS = [
        'first', 'firstOrFail', 'find', 'findOrFail', 'get', 'pluck',
        'count', 'exists', 'sole', 'soleOrFail', 'value',
        'doesntExist', 'findMany', 'findOr', 'firstOr', 'firstWhere',
        'paginate', 'simplePaginate', 'cursorPaginate',
        'sum', 'avg', 'min', 'max', 'cursor', 'lazy',
    ];

    /** @var list<string> Paginator and serialisation calls that may follow a read terminal and leave it a read */
    private const READ_RESULT_TAIL_METHODS = [
        'withQueryString', 'appends', 'fragment', 'withPath', 'onEachSide',
        'toArray', 'toJson', 'values', 'keys', 'all', 'items',
    ];

    /**
     * Methods that take a callback by contract, which may be an array callable, a function
     * name or an invokable object as well as a closure.
     *
     * @var list<string>
     */
    private const CALLBACK_METHODS = [
        'each', 'eachSpread', 'map', 'mapSpread', 'mapWithKeys', 'mapToGroups', 'flatMap',
        'filter', 'reject', 'reduce', 'partition', 'sortBy', 'sortByDesc',
        'tap', 'pipe', 'pipeInto', 'pipeThrough', 'transform', 'when', 'unless',
        'chunk', 'chunkById', 'chunkMap', 'eachById',
    ];

    /** @var list<string> Collection higher-order proxies (->each->...), which act on every row */
    private const HIGHER_ORDER_PROXIES = [
        'average', 'avg', 'contains', 'doesntContain', 'each', 'every', 'filter', 'first',
        'flatMap', 'groupBy', 'keyBy', 'map', 'max', 'min', 'partition', 'percentage',
        'reject', 'skipUntil', 'skipWhile', 'some', 'sortBy', 'sortByDesc', 'sum',
        'takeUntil', 'takeWhile', 'unique', 'unless', 'until', 'when',
    ];

    /**
     * SQL-specific builder methods that make a read complex. A null check is a plain where
     * clause, so neither whereNull nor whereNotNull is listed.
     *
     * @var list<string>
     */
    private const SQL_BUILDER_METHODS = [
        'orWhere', 'whereIn', 'whereNotIn', 'whereBetween',
        'join', 'leftJoin', 'rightJoin', 'crossJoin',
        'having', 'havingRaw', 'groupBy',
        'union', 'unionAll',
        'lockForUpdate', 'sharedLock',
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
        'cache',
        'session',
    ];

    /**
     * Builder methods, beside the where* and orWhere* families, that only build a query, so a
     * chain of them assigned to a variable, such as `$query = Article::latest();`, is a read
     * once a later statement continues it.
     *
     * @var list<string>
     */
    private const BUILDER_METHODS = [
        'query', 'has', 'orHas', 'doesntHave', 'orDoesntHave', 'with', 'withCount', 'without',
        'latest', 'oldest', 'orderBy', 'orderByDesc', 'reorder',
        'limit', 'take', 'skip', 'offset', 'select', 'addSelect', 'distinct',
        'withTrashed', 'onlyTrashed', 'withoutTrashed',
        'join', 'leftJoin', 'rightJoin', 'crossJoin', 'on', 'orOn',
        'groupBy', 'having', 'when', 'unless',
    ];

    /**
     * CALLBACK_METHODS names that the query builder itself defines (BuildsQueries and
     * Conditionable), so a model static call of one is forwarded to the builder, never a scope.
     *
     * @var list<string>
     */
    private const BUILDER_CALLBACK_METHODS = ['each', 'tap', 'pipe', 'chunk', 'chunkById', 'chunkMap', 'eachById', 'when', 'unless'];

    /** @var list<string> Builder callback methods whose callback is handed the builder itself */
    private const BUILDER_RECEIVING_CALLBACK_METHODS = ['when', 'unless', 'tap'];

    /** @var list<string> Request methods that read input */
    private const REQUEST_INPUT_METHODS = [
        'input', 'query', 'string', 'str', 'integer', 'boolean', 'float', 'date', 'enum',
        'get', 'only', 'except', 'all', 'has', 'filled', 'route', 'header', 'cookie',
    ];

    /**
     * Collection classes whose whereIn() and kin filter in memory.
     *
     * @var list<string>
     *
     * @internal public so the anonymous query visitor can read it
     */
    public const COLLECTION_CLASSES = [
        'Illuminate\\Support\\Collection', 'Illuminate\\Database\\Eloquent\\Collection', 'Illuminate\\Support\\LazyCollection',
    ];

    /**
     * Collection methods that return a collection, so a whereIn() after them still filters in
     * memory.
     *
     * @var list<string>
     *
     * @internal public so the anonymous query visitor can read it
     */
    public const COLLECTION_METHODS = [
        'where', 'whereStrict', 'whereIn', 'whereInStrict', 'whereNotIn', 'whereNotInStrict',
        'whereBetween', 'whereNotBetween', 'whereNull', 'whereNotNull', 'whereInstanceOf',
        'filter', 'reject', 'map', 'mapWithKeys', 'flatMap', 'flatten', 'collapse',
        'sort', 'sortDesc', 'sortBy', 'sortByDesc', 'sortKeys', 'sortKeysDesc',
        'values', 'keys', 'merge', 'concat', 'unique', 'uniqueStrict', 'reverse',
        'take', 'skip', 'slice', 'only', 'except', 'keyBy', 'groupBy', 'pluck',
        'diff', 'diffKeys', 'intersect', 'intersectByKeys',
    ];

    /**
     * Model static and builder calls that return a collection of models (a lazy one for lazy()
     * and cursor()).
     *
     * @var list<string>
     *
     * @internal public so the anonymous query visitor can read it
     */
    public const MODEL_COLLECTION_READS = ['get', 'all', 'lazy', 'lazyById', 'lazyByIdDesc', 'cursor'];

    /**
     * Static constructors of a collection class, lowercased.
     *
     * @var list<string>
     *
     * @internal public so the anonymous query visitor can read it
     */
    public const COLLECTION_FACTORY_METHODS = ['make', 'wrap', 'times', 'range', 'empty'];

    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string, metadata: array<string, mixed>}> */
    private array $issues = [];

    /** @var array<int, true> Track which positions already have issues to avoid duplicates */
    private array $reportedPositions = [];

    /** @var array<int, true> Uses, by spl_object_id, of route parameters bound to a model, which root a read */
    private array $readRootVariables = [];

    /** @var array<string, array{expr: Node\Expr, calls: array<int, true>}> Read chains assigned to a variable earlier in the closure body */
    private array $assignedReadChains = [];

    /** @var array<int, Node\Expr> Variable uses, by spl_object_id, that stand for an assigned read chain */
    private array $readContinuations = [];

    /** @var array<int, true> Calls of an assigned read chain that a later chain continues */
    private array $continuedCalls = [];

    /** @var array<int, true> Assigned read chains, by spl_object_id, that a later chain continues */
    private array $continuedChains = [];

    /**
     * @param  \Closure(string): ?bool  $declaresModel  Eloquent verdict of a class's declaration under app/, null when unreadable
     */
    public function __construct(
        private int $maxClosureLines,
        private bool $allowSimpleReads,
        private \Closure $declaresModel
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

        // Detect Route::middleware(...)->get(...) and other RouteRegistrar chains, where
        // the handler sits on the last call of a chain rooted at the Route facade.
        if ($node instanceof Node\Expr\MethodCall && $this->isRegistrarChainOnRouteFacade($node)) {
            $this->analyzeRouteCall($node);
        }

        return null;
    }

    /**
     * Check if a method call ends a chain whose root is a static call on the Route facade.
     */
    private function isRegistrarChainOnRouteFacade(Node\Expr\MethodCall $node): bool
    {
        $current = $node->var;
        while ($current instanceof Node\Expr\MethodCall) {
            $current = $current->var;
        }

        return $current instanceof Node\Expr\StaticCall
            && $current->class instanceof Node\Name
            && $this->isRouteFacade($current->class);
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
     * After NameResolver runs, each class name carries a resolvedName attribute
     * holding the complete namespace (e.g., "Product" resolves to "App\Models\Product").
     *
     * This method is public static so anonymous visitor classes can call it.
     *
     * @param  list<string>  $utilityClasses
     * @param  \Closure(string): ?bool  $declaresModel  Eloquent verdict of a class's declaration under app/, null when unreadable
     * @param  bool  $unknownIsModel  what a Model-suffixed class whose declaration cannot be read counts as
     *
     * @internal
     */
    public static function isLikelyModel(Node\Name $name, array $utilityClasses, \Closure $declaresModel, bool $unknownIsModel = true): bool
    {
        // After NameResolver, get the resolved name if available
        $resolvedName = $name->getAttribute('resolvedName');
        $fqn = $resolvedName instanceof Node\Name\FullyQualified
            ? $resolvedName->toString()
            : $name->toString();
        $normalized = ltrim($fqn, '\\');

        // Extract short class name for utility check
        $shortName = self::getShortClassName($name);

        // Quick rejection: known utility classes
        if (in_array($shortName, $utilityClasses, true)) {
            return false;
        }

        // Check model namespace patterns (from resolved FQN)
        if (self::isInModelsNamespace($name)) {
            return true;
        }

        // A Model suffix outside a models namespace is not a model when its declaration under
        // app/ extends no Eloquent class, as an App\ViewModels view model does not
        if (str_ends_with($normalized, 'Model')) {
            return $declaresModel($normalized) ?? $unknownIsModel;
        }

        // Cannot determine from namespace - assume NOT a model
        return false;
    }

    /**
     * Determine if a class is an Eloquent model for write detection.
     *
     * Unlike isLikelyModel(), an explicit models namespace wins over the utility short-name
     * rejection, so a write on App\Models\File is seen while the File facade, which resolves
     * under Illuminate\Support\Facades, is still rejected.
     *
     * @param  list<string>  $utilityClasses
     * @param  \Closure(string): ?bool  $declaresModel
     *
     * @internal
     */
    public static function isModelClass(Node\Name $name, array $utilityClasses, \Closure $declaresModel): bool
    {
        return self::isInModelsNamespace($name) || self::isLikelyModel($name, $utilityClasses, $declaresModel);
    }

    /**
     * Check whether the resolved class name sits under App\Models\, App\Model\ or any \Models\ namespace.
     *
     * @internal
     */
    public static function isInModelsNamespace(Node\Name $name): bool
    {
        $resolvedName = $name->getAttribute('resolvedName');
        $fqn = $resolvedName instanceof Node\Name\FullyQualified
            ? $resolvedName->toString()
            : $name->toString();
        $normalized = ltrim($fqn, '\\');

        return str_starts_with($normalized, 'App\\Models\\')
            || str_starts_with($normalized, 'App\\Model\\')
            // Domain-driven patterns: any namespace containing \Models\
            || str_contains($normalized, '\\Models\\');
    }

    /**
     * Extract short class name from a Node\Name, using resolved FQN if available.
     *
     * @internal
     */
    public static function getShortClassName(Node\Name $name): string
    {
        $resolvedName = $name->getAttribute('resolvedName');
        $fqn = $resolvedName instanceof Node\Name\FullyQualified
            ? $resolvedName->toString()
            : $name->toString();
        $normalized = ltrim($fqn, '\\');

        $parts = explode('\\', $normalized);

        return end($parts) ?: $normalized;
    }

    private function analyzeRouteCall(Node\Expr\StaticCall|Node\Expr\MethodCall $node): void
    {
        if (empty($node->args)) {
            return;
        }

        // Only analyze closures in route handler methods (get, post, etc.)
        // Skip grouping methods (group, middleware, prefix, etc.) whose closures
        // contain route definitions, not business logic.
        if ($node->name instanceof Node\Identifier) {
            if (! in_array($node->name->toString(), self::ROUTE_HANDLER_METHODS, true)) {
                return;
            }
        }

        // Check each argument for closures
        foreach ($node->args as $arg) {
            // A first-class callable yields a VariadicPlaceholder, which has no value.
            if ($arg instanceof Node\Arg
                && ($arg->value instanceof Node\Expr\Closure || $arg->value instanceof Node\Expr\ArrowFunction)) {
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

        $boundModels = $this->modelParameterUses($closure) + $this->signedInUserVariableUses($closure);
        $readBody = $this->readBody($closure, $boundModels);

        // Analyze database queries with granular classification
        $queryInfo = $this->analyzeDbQueries($closure, $boundModels, $readBody['continuations'], $readBody['continued']);

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
        if ($this->hasComplexBusinessLogic($closure, $readBody['calls'], $queryInfo['has_writes'] || $queryInfo['has_raw_queries'])) {
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
     * @param  array<int, true>  $rootVariables  variable uses, by spl_object_id, that hold a model and root a write
     * @param  array<int, Node\Expr>  $continuations  variable uses that stand for the read chain assigned to them
     * @param  array<int, true>  $continuedCalls  calls of an assigned read chain, graded where a later chain continues it
     * @return array{has_writes: bool, has_raw_queries: bool, has_complex_reads: bool, has_simple_reads: bool, chain_length: int}
     */
    private function analyzeDbQueries(Node\Expr\Closure|Node\Expr\ArrowFunction $closure, array $rootVariables, array $continuations, array $continuedCalls): array
    {
        $result = [
            'has_writes' => false,
            'has_raw_queries' => false,
            'has_complex_reads' => false,
            'has_simple_reads' => false,
            'chain_length' => 0,
        ];

        // Route closure parameters type-hinted Illuminate\Http\Request, whose file() is an upload
        $requestVariables = [];
        foreach ($closure->params as $param) {
            $type = $param->type instanceof Node\Name ? $param->type->getAttribute('resolvedName') : null;
            if ($type instanceof Node\Name\FullyQualified
                && $type->toString() === 'Illuminate\\Http\\Request'
                && $param->var instanceof Node\Expr\Variable
                && is_string($param->var->name)) {
                $requestVariables[] = $param->var->name;
            }
        }

        $visitor = new class($result, self::WRITE_METHODS, self::STATIC_QUERY_METHODS, self::UTILITY_CLASSES, self::TERMINAL_READ_METHODS, self::SQL_BUILDER_METHODS, self::READ_RESULT_TAIL_METHODS, self::ARGUMENTLESS_WRITE_METHODS, self::ATTACHMENT_EXTENSIONS, $requestVariables, $this->declaresModel, $rootVariables, $continuations, $continuedCalls) extends NodeVisitorAbstract
        {
            /** @var array<int, true> Track StaticCalls that are roots of method chains */
            private array $processedChainRoots = [];

            /** @var array<int, true> Variable uses that hold a model: bound route parameters, then the parameters of callbacks passed along a rooted chain */
            private array $rootVariables;

            /**
             * Variables last assigned a collection, true when it holds models read from the
             * database, per function scope: a nested closure sees only what it captures with
             * use, an arrow function all of its parent's, and a parameter hides its name.
             *
             * @var non-empty-list<array<string, bool>>
             */
            private array $collectionScopes = [[]];

            /** @var array<int, true> Calls followed in their chain by a per-row callback or a higher-order proxy */
            private array $perRowChainCalls = [];

            /**
             * @param  array{has_writes: bool, has_raw_queries: bool, has_complex_reads: bool, has_simple_reads: bool, chain_length: int}  $result
             * @param  list<string>  $writeMethods
             * @param  list<string>  $staticQueryMethods
             * @param  list<string>  $utilityClasses
             * @param  list<string>  $terminalReadMethods
             * @param  list<string>  $sqlBuilderMethods
             * @param  list<string>  $readResultTailMethods
             * @param  list<string>  $argumentlessWriteMethods
             * @param  list<string>  $attachmentExtensions
             * @param  list<string>  $requestVariables
             * @param  \Closure(string): ?bool  $declaresModel
             * @param  array<int, true>  $boundVariables  uses of route parameters bound to a model
             * @param  array<int, Node\Expr>  $continuations
             * @param  array<int, true>  $continuedCalls
             */
            public function __construct(
                private array &$result,
                private array $writeMethods,
                private array $staticQueryMethods,
                private array $utilityClasses,
                private array $terminalReadMethods,
                private array $sqlBuilderMethods,
                private array $readResultTailMethods,
                private array $argumentlessWriteMethods,
                private array $attachmentExtensions,
                private array $requestVariables,
                private \Closure $declaresModel,
                private array $boundVariables,
                private array $continuations,
                private array $continuedCalls
            ) {
                $this->rootVariables = $boundVariables;
            }

            public function enterNode(Node $node): ?Node
            {
                if ($node instanceof Node\Expr\Closure || $node instanceof Node\Expr\ArrowFunction) {
                    $this->enterFunctionScope($node);
                }

                // A variable assigned a collection: $c = collect(...)
                if ($node instanceof Node\Expr\Assign && $node->var instanceof Node\Expr\Variable && is_string($node->var->name)) {
                    $scope = array_key_last($this->collectionScopes);
                    $holdsModels = $this->collectionKind($node->expr);
                    if ($holdsModels !== null) {
                        $this->collectionScopes[$scope][$node->var->name] = $holdsModels;
                    } else {
                        unset($this->collectionScopes[$scope][$node->var->name]);
                    }
                }

                // A per-row callback or a higher-order proxy (->each->) marks every call before it
                // in the chain; entered before them, as the chain's outer node
                if (($node instanceof Node\Expr\MethodCall && LogicInRoutesVisitor::takesCallback($node))
                    || (($node instanceof Node\Expr\PropertyFetch || $node instanceof Node\Expr\NullsafePropertyFetch)
                        && $node->name instanceof Node\Identifier
                        && LogicInRoutesVisitor::isHigherOrderProxy($node->name->toString()))) {
                    $this->markPerRowChain($node->var);
                }

                // Check for DB facade calls (raw queries - always flagged)
                if ($node instanceof Node\Expr\StaticCall) {
                    if ($node->class instanceof Node\Name && $this->isDbFacade($node->class)) {
                        $this->result['has_raw_queries'] = true;

                        return null;
                    }
                }

                // Process MethodCalls (nullsafe included) - walk DOWN via ->var to analyze Eloquent chains
                if ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\NullsafeMethodCall) {
                    // A call of an assigned read chain is graded where a later chain continues it,
                    // as the single chain it stands for
                    $chainInfo = isset($this->continuedCalls[spl_object_id($node)])
                        ? ['is_eloquent_chain' => false, 'is_write_only_chain' => false, 'is_root_read' => false, 'chain_length' => 0, 'has_writes' => false, 'methods' => [], 'root_position' => null]
                        : $this->analyzeMethodCallChain($node);

                    // A collection method on a collection, such as Article::all()->whereIn(...), filters
                    // in memory: the read that made the collection is graded on its own
                    $isCollectionCall = $node->name instanceof Node\Identifier
                        && LogicInRoutesVisitor::isMethodIn($node->name->toString(), LogicInRoutesVisitor::COLLECTION_METHODS)
                        && ! isset($this->perRowChainCalls[spl_object_id($node)])
                        && $this->collectionKind($node->var) !== null;
                    if ($isCollectionCall && $chainInfo['has_writes']) {
                        $this->result['has_writes'] = true;
                    }

                    // A read on the signed-in user or a bound model is a simple read, so only
                    // strict mode reports it
                    if ($chainInfo['is_root_read']) {
                        $this->result['has_simple_reads'] = true;
                    }

                    // A chain rooted at the signed-in user, reaching its model through a property
                    // or a ?-> link, or rooted at a model known only by its namespace counts only
                    // for its writes, so its reads keep their verdict.
                    if ($chainInfo['is_write_only_chain'] && $chainInfo['has_writes']) {
                        $this->result['has_writes'] = true;
                    }

                    if ($chainInfo['is_eloquent_chain'] && ! $isCollectionCall) {
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
                        } elseif ($chainInfo['chain_length'] === 1 && $this->isDirectSimpleRead($chainInfo['methods'][0])) {
                            // A direct read followed only by result calls,
                            // e.g. User::paginate(15)->withQueryString()
                            $this->result['has_simple_reads'] = true;
                        }

                        // The root StaticCall is skipped below, so its own method is checked
                        // here: Model::whereIn(...)->get() is as complex as ->whereIn(...)
                        if (in_array($chainInfo['methods'][0] ?? '', $this->sqlBuilderMethods, true)) {
                            $this->result['has_complex_reads'] = true;
                        }
                    }

                    // Check for SQL-specific methods that indicate complex queries; on a collection
                    // they filter in memory
                    if ($node instanceof Node\Expr\MethodCall
                        && $node->name instanceof Node\Identifier
                        && in_array($node->name->toString(), $this->sqlBuilderMethods, true)
                        && ! $isCollectionCall) {
                        $this->result['has_complex_reads'] = true;
                    }

                    return null;
                }

                // Handle direct StaticCalls on models (no method chain following)
                // e.g., User::create([...]), User::find($id), User::all()
                if ($node instanceof Node\Expr\StaticCall) {
                    // Skip if this StaticCall was already processed as part of a method chain
                    $position = $node->getStartFilePos();
                    if (isset($this->processedChainRoots[$position]) || isset($this->continuedCalls[spl_object_id($node)])) {
                        return null;
                    }

                    if ($node->name instanceof Node\Identifier && $node->class instanceof Node\Name) {
                        $method = $node->name->toString();

                        // Check if this is likely an Eloquent model
                        if (! $this->isModelClass($node->class)) {
                            return null;
                        }

                        $this->addCallbackParameterRoots([$node]);

                        // Direct write method (e.g., User::create([...]))
                        if ($this->isWriteCall($method, $node)) {
                            $this->result['has_writes'] = true;

                            return null;
                        }

                        // A model known only by its namespace (App\Models\Config) counts for writes only
                        if (! $this->isLikelyModel($node->class)) {
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

                            return null;
                        }

                        // SQL-specific builder method called statically (e.g., User::whereIn(...))
                        if (in_array($method, $this->sqlBuilderMethods, true)) {
                            $this->result['has_complex_reads'] = true;
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
                $className = ltrim($this->resolvedClassName($name), '\\');

                return $className === 'Illuminate\\Support\\Facades\\DB'
                    || $className === 'DB';
            }

            private function resolvedClassName(Node\Name $name): string
            {
                $resolvedName = $name->getAttribute('resolvedName');

                return $resolvedName instanceof Node\Name\FullyQualified
                    ? $resolvedName->toString()
                    : $name->toString();
            }

            public function leaveNode(Node $node): ?Node
            {
                if (($node instanceof Node\Expr\Closure || $node instanceof Node\Expr\ArrowFunction) && count($this->collectionScopes) > 1) {
                    array_pop($this->collectionScopes);
                }

                return null;
            }

            private function enterFunctionScope(Node\Expr\Closure|Node\Expr\ArrowFunction $function): void
            {
                $outer = $this->collectionScopes[array_key_last($this->collectionScopes)];
                $scope = [];
                if ($function instanceof Node\Expr\ArrowFunction) {
                    $scope = $outer;
                } else {
                    foreach ($function->uses as $use) {
                        if (is_string($use->var->name) && isset($outer[$use->var->name])) {
                            $scope[$use->var->name] = $outer[$use->var->name];
                        }
                    }
                }

                foreach ($function->params as $param) {
                    if ($param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                        unset($scope[$param->var->name]);
                    }
                }

                $this->collectionScopes[] = $scope;
            }

            private function markPerRowChain(Node\Expr $expr): void
            {
                while ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\NullsafeMethodCall
                    || $expr instanceof Node\Expr\PropertyFetch || $expr instanceof Node\Expr\NullsafePropertyFetch) {
                    $this->perRowChainCalls[spl_object_id($expr)] = true;
                    $expr = $expr->var;
                }
            }

            /**
             * Whether an expression is a collection: collect(...), a static constructor or new of
             * a collection class, a model read of a collection (Article::all(),
             * Article::latest()->get()), or a variable assigned one, followed only by
             * COLLECTION_METHODS calls that take no callback. Null when it is not; otherwise
             * whether it holds models read from the database.
             */
            private function collectionKind(Node\Expr $expr): ?bool
            {
                while ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\NullsafeMethodCall) {
                    if (! $expr->name instanceof Node\Identifier) {
                        return null;
                    }

                    $method = $expr->name->toString();
                    if (LogicInRoutesVisitor::isMethodIn($method, LogicInRoutesVisitor::MODEL_COLLECTION_READS) && $this->isModelQuery($expr->var)) {
                        return true;
                    }

                    if (! LogicInRoutesVisitor::isMethodIn($method, LogicInRoutesVisitor::COLLECTION_METHODS)
                        || ($expr instanceof Node\Expr\MethodCall && LogicInRoutesVisitor::takesCallback($expr))) {
                        return null;
                    }

                    $expr = $expr->var;
                }

                if ($expr instanceof Node\Expr\Variable) {
                    return is_string($expr->name)
                        ? $this->collectionScopes[array_key_last($this->collectionScopes)][$expr->name] ?? null
                        : null;
                }

                if ($expr instanceof Node\Expr\FuncCall) {
                    return $expr->name instanceof Node\Name && ltrim($expr->name->toLowerString(), '\\') === 'collect' ? false : null;
                }

                if ($expr instanceof Node\Expr\StaticCall) {
                    if (! $expr->class instanceof Node\Name || ! $expr->name instanceof Node\Identifier) {
                        return null;
                    }

                    if ($this->isCollectionClass($expr->class)) {
                        return in_array($expr->name->toLowerString(), LogicInRoutesVisitor::COLLECTION_FACTORY_METHODS, true) ? false : null;
                    }

                    return LogicInRoutesVisitor::isMethodIn($expr->name->toString(), LogicInRoutesVisitor::MODEL_COLLECTION_READS) && $this->isLikelyModel($expr->class)
                        ? true
                        : null;
                }

                return $expr instanceof Node\Expr\New_ && $expr->class instanceof Node\Name && $this->isCollectionClass($expr->class)
                    ? false
                    : null;
            }

            /**
             * Check whether an expression is a query chain down to a static call on a model.
             */
            private function isModelQuery(Node\Expr $expr): bool
            {
                while ($expr instanceof Node\Expr\MethodCall) {
                    $expr = $expr->var;
                }

                return $expr instanceof Node\Expr\StaticCall
                    && $expr->class instanceof Node\Name
                    && $this->isLikelyModel($expr->class);
            }

            private function isCollectionClass(Node\Name $name): bool
            {
                return in_array(ltrim($this->resolvedClassName($name), '\\'), LogicInRoutesVisitor::COLLECTION_CLASSES, true);
            }

            /**
             * Determine if a class name likely represents an Eloquent model.
             */
            private function isLikelyModel(Node\Name $name): bool
            {
                return LogicInRoutesVisitor::isLikelyModel($name, $this->utilityClasses, $this->declaresModel);
            }

            /**
             * Determine if a class is an Eloquent model, letting a models namespace win over a utility short name.
             */
            private function isModelClass(Node\Name $name): bool
            {
                return LogicInRoutesVisitor::isModelClass($name, $this->utilityClasses, $this->declaresModel);
            }

            /**
             * Check if a static method is a direct simple read (returns data without chaining).
             */
            private function isDirectSimpleRead(string $method): bool
            {
                $directReadMethods = [
                    'find', 'findOrFail', 'findOr', 'findMany', 'all', 'first', 'firstOrFail',
                    'firstOr', 'firstWhere', 'sole', 'value',
                    'paginate', 'simplePaginate', 'cursorPaginate',
                    'sum', 'avg', 'min', 'max', 'cursor', 'lazy',
                ];

                return in_array($method, $directReadMethods, true);
            }

            /**
             * Check whether a call is a write; push() writes only without arguments, attach()
             * with a file-shaped first argument is a mail attachment, and a first-class
             * callable (delete(...)) only builds a Closure.
             */
            private function isWriteCall(string $method, Node\Expr\CallLike $call): bool
            {
                if ($call->isFirstClassCallable() || ! in_array($method, $this->writeMethods, true)) {
                    return false;
                }

                if ($method === 'attach' && $this->isMailAttachment($call)) {
                    return false;
                }

                return $call->getRawArgs() === [] || ! in_array($method, $this->argumentlessWriteMethods, true);
            }

            /**
             * Whether attach() is Mailable::attach() or MailMessage::attach(): it has a named file
             * argument, or its first argument is file-shaped. Anything else, a bare variable or a
             * string key such as a UUID included, may be a pivot id and stays a write.
             */
            private function isMailAttachment(Node\Expr\CallLike $call): bool
            {
                $args = $call->getRawArgs();

                foreach ($args as $arg) {
                    if ($arg instanceof Node\Arg && $arg->name !== null && $arg->name->toString() === 'file') {
                        return true;
                    }
                }

                $first = $args[0] ?? null;

                return $first instanceof Node\Arg
                    && $first->name === null
                    && ! $first->unpack
                    && $this->isFileShaped($first->value);
            }

            /**
             * Whether an expression is a file: a path-like string, a string that starts at an
             * absolute path or __DIR__ or ends in an attachment extension, a Laravel path helper,
             * a Storage path(), an uploaded file from file(), an Attachment with or without a
             * fluent tail, or a ternary whose branches all are.
             */
            private function isFileShaped(Node\Expr $expr): bool
            {
                if ($expr instanceof Node\Scalar\String_) {
                    return $this->isPathLikeString($expr->value);
                }

                if ($expr instanceof Node\Scalar\InterpolatedString) {
                    $first = $expr->parts[0] ?? null;
                    $last = $expr->parts[count($expr->parts) - 1] ?? null;

                    return ($first instanceof Node\InterpolatedStringPart && str_starts_with($first->value, '/'))
                        || ($last instanceof Node\InterpolatedStringPart && $this->hasAttachmentExtension($last->value));
                }

                if ($expr instanceof Node\Expr\BinaryOp\Concat) {
                    if ($expr->right instanceof Node\Scalar\String_ && $this->hasAttachmentExtension($expr->right->value)) {
                        return true;
                    }

                    $leftmost = $expr->left;
                    while ($leftmost instanceof Node\Expr\BinaryOp\Concat) {
                        $leftmost = $leftmost->left;
                    }

                    if ($leftmost instanceof Node\Scalar\MagicConst\Dir) {
                        return true;
                    }

                    return $leftmost instanceof Node\Scalar\String_
                        ? str_starts_with($leftmost->value, '/')
                        : $this->isFileShaped($leftmost);
                }

                if ($expr instanceof Node\Expr\Ternary) {
                    return $this->isFileShaped($expr->if ?? $expr->cond) && $this->isFileShaped($expr->else);
                }

                if ($expr instanceof Node\Expr\FuncCall) {
                    return in_array($this->globalFunctionName($expr), [
                        'storage_path', 'public_path', 'base_path', 'resource_path',
                        'app_path', 'database_path', 'lang_path', 'config_path',
                    ], true);
                }

                // file() on request() or a Request-typed route closure parameter is an UploadedFile
                if ($expr instanceof Node\Expr\MethodCall
                    && $expr->name instanceof Node\Identifier
                    && $expr->name->toLowerString() === 'file'
                    && (($expr->var instanceof Node\Expr\Variable
                            && is_string($expr->var->name)
                            && in_array($expr->var->name, $this->requestVariables, true))
                        || ($expr->var instanceof Node\Expr\FuncCall && $this->globalFunctionName($expr->var) === 'request'))) {
                    return true;
                }

                $isPathCall = ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\StaticCall)
                    && $expr->name instanceof Node\Identifier
                    && $expr->name->toLowerString() === 'path';

                $root = $expr;
                while ($root instanceof Node\Expr\MethodCall) {
                    $root = $root->var;
                }

                if (! ($root instanceof Node\Expr\StaticCall || $root instanceof Node\Expr\New_)
                    || ! $root->class instanceof Node\Name) {
                    return false;
                }

                $className = ltrim($this->resolvedClassName($root->class), '\\');

                if (in_array($className, ['Illuminate\\Mail\\Mailables\\Attachment', 'Illuminate\\Mail\\Attachment'], true)) {
                    return true;
                }

                return $isPathCall && in_array($className, ['Illuminate\\Support\\Facades\\Storage', 'Storage'], true);
            }

            /**
             * A string reads as a path when it is absolute or ends in an attachment extension;
             * a dotted key such as vue.js, example.com or v1.2 does not.
             */
            private function isPathLikeString(string $value): bool
            {
                return str_starts_with($value, '/') || $this->hasAttachmentExtension($value);
            }

            private function hasAttachmentExtension(string $value): bool
            {
                return preg_match('/\.([A-Za-z0-9]+)$/', $value, $matches) === 1
                    && in_array(strtolower($matches[1]), $this->attachmentExtensions, true);
            }

            /**
             * The lowercased global function a call reaches, or '' for a namespaced function or a
             * dynamic name; an unqualified name without a resolvedName falls back to the global one.
             */
            private function globalFunctionName(Node\Expr\FuncCall $call): string
            {
                if (! $call->name instanceof Node\Name) {
                    return '';
                }

                $resolvedName = $call->name->getAttribute('resolvedName');

                if ($resolvedName instanceof Node\Name\FullyQualified) {
                    return $resolvedName->toLowerString();
                }

                return $call->name->isUnqualified() ? $call->name->toLowerString() : '';
            }

            /**
             * Walk DOWN via ->var to analyze a method call chain.
             *
             * This approach walks from the outermost MethodCall down through
             * the chain to find if the root is a model StaticCall.
             *
             * @return array{is_eloquent_chain: bool, is_write_only_chain: bool, is_root_read: bool, chain_length: int, has_writes: bool, methods: list<string>, root_position: int|null}
             */
            private function analyzeMethodCallChain(Node\Expr\MethodCall|Node\Expr\NullsafeMethodCall $node): array
            {
                $methods = [];
                $hasWrites = false;
                $current = $node;
                $rootPosition = null;
                $crossesProperty = false;
                $crossesNullsafe = false;
                $isUserRoot = false;
                $walkedCalls = [];

                // Walk down through the method call chain, across ?-> links and property
                // hops (->author->, higher-order ->each->) as well, and through a variable
                // that stands for the read chain assigned to it
                while (true) {
                    if ($current instanceof Node\Expr\Variable && isset($this->continuations[spl_object_id($current)])) {
                        $current = $this->continuations[spl_object_id($current)];

                        continue;
                    }

                    if ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\NullsafeMethodCall) {
                        if (LogicInRoutesVisitor::isSignedInUser($current)) {
                            $isUserRoot = true;

                            break;
                        }

                        if ($current instanceof Node\Expr\NullsafeMethodCall) {
                            $crossesNullsafe = true;
                        }

                        $walkedCalls[] = $current;
                        if ($current->name instanceof Node\Identifier) {
                            $method = $current->name->toString();
                            array_unshift($methods, $method); // Prepend to maintain order
                            if ($this->isWriteCall($method, $current)) {
                                $hasWrites = true;
                            }
                        }
                        $current = $current->var;

                        continue;
                    }

                    if ($current instanceof Node\Expr\PropertyFetch || $current instanceof Node\Expr\NullsafePropertyFetch) {
                        if ($current instanceof Node\Expr\NullsafePropertyFetch) {
                            $crossesNullsafe = true;
                        }

                        $crossesProperty = true;
                        $current = $current->var;

                        continue;
                    }

                    break;
                }

                // Auth::user() and Auth::guard(...)->user() are the signed-in user as well
                if ($current instanceof Node\Expr\StaticCall && LogicInRoutesVisitor::isSignedInUser($current)) {
                    $isUserRoot = true;
                }

                // A route parameter bound to a model, or the parameter of a callback passed along
                // a rooted chain, holds a model
                $isVariableRoot = $current instanceof Node\Expr\Variable && isset($this->rootVariables[spl_object_id($current)]);

                // Check if root is a StaticCall on a model
                $isEloquentChain = false;
                if (! $isUserRoot
                    && $current instanceof Node\Expr\StaticCall
                    && $current->class instanceof Node\Name
                    && $this->isModelClass($current->class)) {
                    $isEloquentChain = true;
                    $rootPosition = $current->getStartFilePos();
                    $walkedCalls[] = $current;

                    // Include the static method in the chain count
                    if ($current->name instanceof Node\Identifier) {
                        $method = $current->name->toString();
                        array_unshift($methods, $method);
                        if ($this->isWriteCall($method, $current)) {
                            $hasWrites = true;
                        }
                    }
                }

                // The first parameter of a callback passed along the chain is a builder or a
                // model of it, so a write on it is a write: ->when($x, fn ($q) => $q->delete())
                // A variable holding models read from the database roots its per-row callbacks too:
                // $articles->each(fn ($a) => $a->update([...]))
                $isModelCollectionRoot = $current instanceof Node\Expr\Variable && $this->collectionKind($current) === true;

                if ($isUserRoot || $isVariableRoot || $isEloquentChain || $isModelCollectionRoot) {
                    $this->addCallbackParameterRoots($walkedCalls);
                }

                // Paginator or serialisation calls after a read terminal leave it the same read,
                // e.g. User::latest()->paginate(15)->withQueryString()
                $readMethods = $methods;
                while (count($readMethods) > 1 && in_array(end($readMethods), $this->readResultTailMethods, true)) {
                    array_pop($readMethods);
                }
                $endsInRead = in_array(end($readMethods), $this->terminalReadMethods, true);
                if ($endsInRead) {
                    $methods = $readMethods;
                }

                $isBoundRoot = $current instanceof Node\Expr\Variable && isset($this->boundVariables[spl_object_id($current)]);

                // Reads are graded only on a plain chain from a model recognised by its short
                // name, as before; any other chain counts for its writes only
                $gradesReads = $isEloquentChain
                    && ! $crossesProperty
                    && ! $crossesNullsafe
                    && $current instanceof Node\Expr\StaticCall
                    && $current->class instanceof Node\Name
                    && $this->isLikelyModel($current->class);

                return [
                    'is_eloquent_chain' => $gradesReads,
                    'is_write_only_chain' => $isUserRoot || $isVariableRoot || ($isEloquentChain && ! $gradesReads),
                    'is_root_read' => ($isUserRoot || $isBoundRoot) && $endsInRead && ! $hasWrites,
                    'chain_length' => count($methods),
                    'has_writes' => $hasWrites,
                    'methods' => $methods,
                    'root_position' => $rootPosition,
                ];
            }

            /**
             * Record the uses of the first parameter of each closure or arrow function passed to
             * the calls, directly or as an array value (with(['tags' => fn ($q) => ...])), as
             * write roots. The chain is entered before its arguments, so they are known before
             * the callback bodies are visited.
             *
             * @param  list<Node\Expr\MethodCall|Node\Expr\NullsafeMethodCall|Node\Expr\StaticCall>  $calls
             */
            private function addCallbackParameterRoots(array $calls): void
            {
                foreach ($calls as $call) {
                    if ($call->isFirstClassCallable()) {
                        continue;
                    }

                    foreach ($call->getArgs() as $arg) {
                        $values = $arg->value instanceof Node\Expr\Array_
                            ? array_map(static fn (Node\ArrayItem $item): Node\Expr => $item->value, array_filter($arg->value->items))
                            : [$arg->value];

                        foreach ($values as $callback) {
                            if (! ($callback instanceof Node\Expr\Closure || $callback instanceof Node\Expr\ArrowFunction)) {
                                continue;
                            }

                            $parameter = $callback->params[0]->var ?? null;
                            if ($parameter instanceof Node\Expr\Variable && is_string($parameter->name)) {
                                $this->rootVariables += LogicInRoutesVisitor::variableUses($callback, $parameter->name);
                            }
                        }
                    }
                }
            }
        };

        // No longer need ParentConnectingVisitor - we walk down via ->var
        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse([$closure]);

        return $result;
    }

    /**
     * @param  array<int, true>  $readChainCalls  the calls of a read-only body (see readBody()), which are
     *                                            graded by analyzeDbQueries alone and skipped by the
     *                                            model-method and heavy-chain checks below
     * @param  bool  $closureHasWrites  whether analyzeDbQueries() found a database write or a DB facade query in the closure
     */
    private function hasComplexBusinessLogic(Node\Expr\Closure|Node\Expr\ArrowFunction $closure, array $readChainCalls, bool $closureHasWrites): bool
    {
        $hasComplexLogic = false;
        $ifDepth = 0;
        $hasLoops = false;

        $visitor = new class($hasComplexLogic, $ifDepth, $hasLoops, self::BUSINESS_LOGIC_FUNCTIONS, self::BUSINESS_LOGIC_FACADES, self::SERVICE_CONTAINER_METHODS, self::QUERY_METHODS, self::UTILITY_CLASSES, self::SAFE_FLUENT_HELPER_FUNCTIONS, $readChainCalls, array_map('strtolower', self::DISPATCHABLE_STATIC_METHODS), array_map('strtolower', self::NOTIFY_METHODS), $this->declaresModel, $closureHasWrites) extends NodeVisitorAbstract
        {
            /** @var list<string> Container methods that resolve, beyond SERVICE_CONTAINER_METHODS */
            private const EXTRA_RESOLUTION_METHODS = ['offsetGet', 'build', 'factory'];

            /** @var array<int, true> Bare app() calls whose parent method call only reads application info */
            private array $exemptAppCalls = [];

            /**
             * @param  list<string>  $businessLogicFunctions
             * @param  list<string>  $businessLogicFacades
             * @param  list<string>  $serviceContainerMethods
             * @param  list<string>  $queryMethods
             * @param  list<string>  $utilityClasses
             * @param  list<string>  $safeFluentHelperFunctions
             * @param  array<int, true>  $readChainCalls
             * @param  list<string>  $dispatchableStaticMethods  lowercased, since PHP method names are case-insensitive
             * @param  list<string>  $notifyMethods  lowercased, since PHP method names are case-insensitive
             * @param  \Closure(string): ?bool  $declaresModel
             * @param  bool  $closureHasWrites  whether the closure writes to the database
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
                private array $safeFluentHelperFunctions,
                private array $readChainCalls,
                private array $dispatchableStaticMethods,
                private array $notifyMethods,
                private \Closure $declaresModel,
                private bool $closureHasWrites
            ) {}

            public function enterNode(Node $node): ?Node
            {
                if ($this->hasComplexLogic) {
                    return null;
                }

                // A bare app() is the application itself; a method called on it directly
                // (app()->getLocale()) is not container resolution unless that method resolves
                if ($node instanceof Node\Expr\MethodCall
                    && $node->var instanceof Node\Expr\FuncCall
                    && $this->isBareAppCall($node->var)
                    && $node->name instanceof Node\Identifier
                    && ! $this->isContainerResolutionMethod($node->name->toLowerString())) {
                    $this->exemptAppCalls[spl_object_id($node->var)] = true;
                }

                // 1. Check for business logic function calls
                if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
                    $funcName = $node->name->toString();
                    if (in_array($funcName, $this->businessLogicFunctions, true)
                        && ! isset($this->exemptAppCalls[spl_object_id($node)])) {
                        $this->hasComplexLogic = true;

                        return null;
                    }
                }

                // 2. Check for business logic facade calls and service container
                if ($node instanceof Node\Expr\StaticCall && $node->class instanceof Node\Name) {
                    $shortClassName = LogicInRoutesVisitor::getShortClassName($node->class);

                    // Business facades (Mail, Notification, Queue, Event, Bus, Broadcast); a model
                    // that shares the short name (App\Models\Event) is not one
                    if (in_array($shortClassName, $this->businessLogicFacades, true)
                        && ! LogicInRoutesVisitor::isInModelsNamespace($node->class)) {
                        $this->hasComplexLogic = true;

                        return null;
                    }

                    // Dispatchable jobs and events: SendDigest::dispatch(), ::dispatchSync(),
                    // ::withChain([...])->dispatch(). Utility facades are skipped, so
                    // Route::dispatch($request), which forwards a request, stays clean.
                    if ($node->name instanceof Node\Identifier
                        && in_array($node->name->toLowerString(), $this->dispatchableStaticMethods, true)
                        && ! in_array($shortClassName, $this->utilityClasses, true)) {
                        $this->hasComplexLogic = true;

                        return null;
                    }

                    // Artisan commands: Artisan::call(), Artisan::queue(). Matched by resolved
                    // name, so a model or other class whose short name is Artisan stays clean.
                    if ($this->isArtisanFacade($node->class)) {
                        $this->hasComplexLogic = true;

                        return null;
                    }

                    // Service container calls: App::make(), App::call(), etc.
                    if ($shortClassName === 'App'
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
                            && ! in_array($method, $this->queryMethods, true)
                            && ! isset($this->readChainCalls[spl_object_id($node)])) {
                            $this->hasComplexLogic = true;

                            return null;
                        }
                    }
                }

                // 3. Notifications sent through the Notifiable trait: $user->notify(...)
                if (($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\NullsafeMethodCall)
                    && $node->name instanceof Node\Identifier
                    && in_array($node->name->toLowerString(), $this->notifyMethods, true)) {
                    $this->hasComplexLogic = true;

                    return null;
                }

                // 4. Check for heavy method chains (3+ calls)
                if ($node instanceof Node\Expr\MethodCall) {
                    $chainLength = $this->countMethodChain($node);
                    if ($chainLength >= 3) {
                        // Skip if chain starts from safe fluent API helper, or is the read chain
                        if (! $this->isChainFromSafeFluentRoot($node)
                            && ! isset($this->readChainCalls[spl_object_id($node)])) {
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
             * Determine if a class name likely represents an Eloquent model. A Model-suffixed
             * class whose declaration cannot be read counts only when the closure writes to the
             * database or queries it through the DB facade, so a read-only non-query static call (DashboardViewModel::make()) is not
             * business logic.
             */
            private function isLikelyModel(Node\Name $name): bool
            {
                return LogicInRoutesVisitor::isLikelyModel(
                    $name,
                    $this->utilityClasses,
                    $this->declaresModel,
                    unknownIsModel: $this->closureHasWrites
                );
            }

            /**
             * Determine if a call is app() with no arguments, which returns the application instance.
             */
            private function isBareAppCall(Node\Expr\FuncCall $node): bool
            {
                return $node->name instanceof Node\Name
                    && $node->name->toLowerString() === 'app'
                    && $node->args === [];
            }

            /**
             * Determine if a method called on the container resolves from it.
             */
            private function isContainerResolutionMethod(string $lowerMethod): bool
            {
                foreach ([...$this->serviceContainerMethods, ...self::EXTRA_RESOLUTION_METHODS] as $method) {
                    if (strtolower($method) === $lowerMethod) {
                        return true;
                    }
                }

                return false;
            }

            /**
             * Check if the class name is the Artisan facade: imported (under any alias),
             * fully qualified, or the unimported global alias.
             */
            private function isArtisanFacade(Node\Name $name): bool
            {
                $resolvedName = $name->getAttribute('resolvedName');
                $className = $resolvedName instanceof Node\Name\FullyQualified
                    ? $resolvedName->toString()
                    : $name->toString();

                $className = ltrim($className, '\\');

                return $className === 'Illuminate\\Support\\Facades\\Artisan'
                    || $className === 'Artisan';
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

    /**
     * The read-only body of a closure: the calls of its read chains, by spl_object_id, and how
     * a variable holding an assigned read chain continues it. Empty when the body is anything
     * else.
     *
     * The body is an arrow function's read chain, or a closure whose statements are each on an
     * allow-list, ending in `return <read chain>;`:
     * - `$var = <read chain>;`, where the chain ends in a read terminal, or only builds a query
     *   (Article::latest(), $team->members()->where(...)) that a later chain continues;
     * - `$var = <plain value>;`: a literal, a constant, a request input read or a config() read;
     * - a session() helper call.
     * The returned chain may continue a variable assigned a read chain before.
     *
     * A read chain is a read terminal, optionally followed by paginator or serialisation calls,
     * over named method calls and relation property hops down to a model static call, the
     * signed-in user or a route parameter bound to a model. No call along it may be a write,
     * and each callback it passes must be a query callback (see callbacksAreReads()).
     *
     * @param  array<int, true>  $readRoots  uses of route parameters bound to a model
     * @return array{calls: array<int, true>, continuations: array<int, Node\Expr>, continued: array<int, true>}
     */
    private function readBody(Node\Expr\Closure|Node\Expr\ArrowFunction $closure, array $readRoots): array
    {
        $this->readRootVariables = $readRoots;
        $this->assignedReadChains = [];
        $this->readContinuations = [];
        $this->continuedCalls = [];
        $this->continuedChains = [];
        $none = ['calls' => [], 'continuations' => [], 'continued' => []];

        $requestVariables = $this->requestParameterNames($closure);

        if ($closure instanceof Node\Expr\ArrowFunction) {
            $calls = $this->returnedReadCalls($closure->expr, $requestVariables, []);

            return $calls === null ? $none : ['calls' => $calls, 'continuations' => [], 'continued' => []];
        }

        // A comment after the last statement is parsed as a Nop statement
        $statements = array_values(array_filter($closure->stmts, static fn (Node\Stmt $stmt): bool => ! $stmt instanceof Node\Stmt\Nop));
        $return = array_pop($statements);
        if (! $return instanceof Node\Stmt\Return_ || $return->expr === null) {
            return $none;
        }

        $calls = [];
        $builders = [];
        $plainVariables = [];
        foreach ($statements as $statement) {
            if (! $statement instanceof Node\Stmt\Expression) {
                return $none;
            }

            $expr = $statement->expr;
            if ($expr instanceof Node\Expr\Assign
                && $expr->var instanceof Node\Expr\Variable
                && is_string($expr->var->name)) {
                // A plain value, or the signed-in user, whose uses root reads (see signedInUserVariableUses())
                if ($this->isPlainValue($expr->expr, $requestVariables) || self::isSignedInUser($expr->expr)) {
                    unset($this->assignedReadChains[$expr->var->name]);
                    $plainVariables[$expr->var->name] = true;

                    continue;
                }

                if (! ($expr->expr instanceof Node\Expr\MethodCall || $expr->expr instanceof Node\Expr\StaticCall)) {
                    return $none;
                }

                $assignedCalls = $this->readChainCalls($expr->expr, requireTerminal: false);
                if ($assignedCalls === null) {
                    return $none;
                }

                // A chain that does not end in a read must only build a query, for a later chain to read
                if (! $this->endsInReadTerminal($expr->expr)) {
                    if (! $this->isQueryBuilding($expr->expr)) {
                        return $none;
                    }
                    $builders[spl_object_id($expr->expr)] = true;
                }

                $calls += $assignedCalls;
                $this->assignedReadChains[$expr->var->name] = ['expr' => $expr->expr, 'calls' => $assignedCalls];
                unset($plainVariables[$expr->var->name]);

                continue;
            }

            if (! $this->isSessionHelperCall($expr, $requestVariables)) {
                return $none;
            }
        }

        $returnCalls = $this->returnedReadCalls($return->expr, $requestVariables, $plainVariables);
        if ($returnCalls === null) {
            return $none;
        }

        if (array_diff_key($builders, $this->continuedChains) !== []) {
            return $none;
        }

        return ['calls' => $calls + $returnCalls, 'continuations' => $this->readContinuations, 'continued' => $this->continuedCalls];
    }

    /**
     * The calls of a returned read: a read chain, or view(<name>, <data>) whose data array
     * holds only read chains, plain values and variables assigned a read chain or a plain
     * value, or compact() of such variables. Null when the expression is not one.
     *
     * @param  list<string>  $requestVariables
     * @param  array<string, true>  $plainVariables
     * @return array<int, true>|null
     */
    private function returnedReadCalls(Node\Expr $expr, array $requestVariables, array $plainVariables): ?array
    {
        if (! $expr instanceof Node\Expr\FuncCall || ! self::isHelperCall($expr, ['view'])) {
            return $this->readChainCalls($expr, requireTerminal: true);
        }

        $args = $expr->getRawArgs();
        if ($args === [] || count($args) > 2) {
            return null;
        }

        $values = [];
        foreach ($args as $arg) {
            if (! $arg instanceof Node\Arg || $arg->unpack || $arg->byRef || $arg->name !== null) {
                return null;
            }
            $values[] = $arg->value;
        }

        if (! $this->isPlainValue($values[0], $requestVariables)) {
            return null;
        }

        $data = $values[1] ?? new Node\Expr\Array_;
        $isVariable = fn (string $name): bool => isset($this->assignedReadChains[$name]) || isset($plainVariables[$name]);

        if ($data instanceof Node\Expr\FuncCall && self::isHelperCall($data, ['compact'])) {
            foreach ($data->getRawArgs() as $arg) {
                if (! $arg instanceof Node\Arg || ! $arg->value instanceof Node\Scalar\String_ || ! $isVariable($arg->value->value)) {
                    return null;
                }
            }

            return [];
        }

        if (! $data instanceof Node\Expr\Array_) {
            return null;
        }

        $calls = [];
        foreach ($data->items as $item) {
            if ($item->byRef || $item->unpack || ($item->key !== null && ! $this->isPlainValue($item->key, $requestVariables))) {
                return null;
            }

            $value = $item->value;
            if ($this->isPlainValue($value, $requestVariables)
                || ($value instanceof Node\Expr\Variable && is_string($value->name) && $isVariable($value->name))) {
                continue;
            }

            $valueCalls = $this->readChainCalls($value, requireTerminal: true);
            if ($valueCalls === null) {
                return null;
            }
            $calls += $valueCalls;
        }

        return $calls;
    }

    /**
     * The calls of a read chain, by spl_object_id, or null when the expression is not one.
     *
     * @return array<int, true>|null
     */
    private function readChainCalls(Node\Expr $current, bool $requireTerminal): ?array
    {
        $spine = [];
        // A variable that is the whole expression (return $articles;) continues no chain, so
        // the assigned chain keeps its own grade
        $current = $this->continueAssignedChain($current, continued: false);

        while ($current instanceof Node\Expr\MethodCall
            && $current->name instanceof Node\Identifier
            && self::isMethodIn($current->name->toString(), self::READ_RESULT_TAIL_METHODS)) {
            $spine[] = $current;
            $current = $this->continueAssignedChain($current->var);
        }

        if ($requireTerminal && ! $this->isTerminalReadCall($current)) {
            return null;
        }

        while (true) {
            if ($current instanceof Node\Expr\PropertyFetch
                && $current->name instanceof Node\Identifier
                && ! self::isMethodIn($current->name->toString(), self::HIGHER_ORDER_PROXIES)) {
                $current = $this->continueAssignedChain($current->var);

                continue;
            }

            if ($current instanceof Node\Expr\Variable && isset($this->readRootVariables[spl_object_id($current)])) {
                return $this->spineCalls($spine);
            }

            if (! ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\StaticCall)
                || ! $current->name instanceof Node\Identifier
                || self::isMethodIn($current->name->toString(), self::WRITE_METHODS)) {
                return null;
            }

            $spine[] = $current;

            if (self::isSignedInUser($current)) {
                return $this->spineCalls($spine);
            }

            // The root is matched on its name alone, without reading its declaration: a
            // Model-suffixed class that is not Eloquent still roots a plain read chain
            if ($current instanceof Node\Expr\StaticCall) {
                return $current->class instanceof Node\Name && self::isLikelyModel($current->class, self::UTILITY_CLASSES, static fn (): ?bool => null)
                    ? $this->spineCalls($spine)
                    : null;
            }

            $current = $this->continueAssignedChain($current->var);
        }
    }

    /**
     * The calls of a read chain's spine, listed from its top down to its root, with those of the
     * query callbacks it passes; null when a callback is not a read. A query callback is taken
     * only before the first read terminal: after it, a closure runs per row of the result, as
     * in ->get()->first(fn ($a) => ...).
     *
     * @param  list<Node\Expr\MethodCall|Node\Expr\StaticCall>  $spine
     * @return array<int, true>|null
     */
    private function spineCalls(array $spine): ?array
    {
        $calls = [];
        $afterTerminal = false;
        foreach (array_reverse($spine) as $call) {
            $afterTerminal = $afterTerminal || $this->isTerminalReadCall($call) || $this->isResultTailCall($call);
            if (! $this->callbacksAreReads($call, $calls, allowClosures: ! $afterTerminal)) {
                return null;
            }

            $calls[spl_object_id($call)] = true;
        }

        return $calls;
    }

    private function isResultTailCall(Node\Expr $expr): bool
    {
        return $expr instanceof Node\Expr\MethodCall
            && $expr->name instanceof Node\Identifier
            && self::isMethodIn($expr->name->toString(), self::READ_RESULT_TAIL_METHODS);
    }

    /**
     * Whether a method name is in the list; PHP method names are case-insensitive.
     *
     * @param  list<string>  $methods
     *
     * @internal
     */
    public static function isMethodIn(string $method, array $methods): bool
    {
        $method = strtolower($method);
        foreach ($methods as $candidate) {
            if (strtolower($candidate) === $method) {
                return true;
            }
        }

        return false;
    }

    private function isTerminalReadCall(Node\Expr $expr): bool
    {
        return ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\StaticCall)
            && $expr->name instanceof Node\Identifier
            && self::isMethodIn($expr->name->toString(), self::TERMINAL_READ_METHODS);
    }

    /**
     * Whether a chain ends in a read terminal, optionally followed by paginator or serialisation calls.
     */
    private function endsInReadTerminal(Node\Expr $expr): bool
    {
        while ($this->isResultTailCall($expr)) {
            $expr = $expr->var;
        }

        return $this->isTerminalReadCall($expr);
    }

    /**
     * Whether a chain only builds a query: builder methods (where*, orWhere*, BUILDER_METHODS)
     * down to a model static builder call, a variable holding an assigned read chain, or one
     * relation call on the signed-in user or a bound model.
     */
    private function isQueryBuilding(Node\Expr $current): bool
    {
        while (true) {
            if ($current instanceof Node\Expr\Variable) {
                return is_string($current->name) && isset($this->assignedReadChains[$current->name]);
            }

            if (! ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\StaticCall)
                || ! $current->name instanceof Node\Identifier) {
                return false;
            }

            if ($current instanceof Node\Expr\StaticCall) {
                return self::isBuilderMethod($current->name->toString());
            }

            // The relation call itself: $team->members(), auth()->user()->orders()
            $receiver = $current->var;
            if (($receiver instanceof Node\Expr\Variable && isset($this->readRootVariables[spl_object_id($receiver)]))
                || self::isSignedInUser($receiver)) {
                return true;
            }

            if (! self::isBuilderMethod($current->name->toString())) {
                return false;
            }

            $current = $receiver;
        }
    }

    private static function isBuilderMethod(string $method): bool
    {
        $lower = strtolower($method);

        return str_starts_with($lower, 'where')
            || str_starts_with($lower, 'orwhere')
            || self::isMethodIn($method, self::BUILDER_METHODS);
    }

    /**
     * Whether an assigned value is plain data: a literal, a constant, an array of them, a
     * request input read (request('q'), request()->input('q'), $request->string('q')) or a
     * config() read, with plain arguments.
     *
     * @param  list<string>  $requestVariables
     */
    private function isPlainValue(Node\Expr $expr, array $requestVariables): bool
    {
        if ($expr instanceof Node\Scalar\Int_ || $expr instanceof Node\Scalar\Float_ || $expr instanceof Node\Scalar\String_
            || $expr instanceof Node\Expr\ConstFetch
            || ($expr instanceof Node\Expr\ClassConstFetch && $expr->class instanceof Node\Name)) {
            return true;
        }

        if ($expr instanceof Node\Expr\Array_) {
            foreach ($expr->items as $item) {
                if ($item->byRef || $item->unpack
                    || ($item->key !== null && ! $this->isPlainValue($item->key, $requestVariables))
                    || ! $this->isPlainValue($item->value, $requestVariables)) {
                    return false;
                }
            }

            return true;
        }

        // request('q') or config('key', $default); request() alone is the request object
        if ($expr instanceof Node\Expr\FuncCall) {
            return self::isHelperCall($expr, ['request', 'config'])
                && $expr->getRawArgs() !== []
                && $this->hasPlainArguments($expr, $requestVariables);
        }

        // Request::input('q') on the facade
        if ($expr instanceof Node\Expr\StaticCall) {
            return $expr->class instanceof Node\Name
                && $expr->name instanceof Node\Identifier
                && self::isMethodIn($expr->name->toString(), self::REQUEST_INPUT_METHODS)
                && in_array(ltrim(self::resolvedName($expr->class), '\\'), ['Illuminate\\Support\\Facades\\Request', 'Request'], true)
                && $this->hasPlainArguments($expr, $requestVariables);
        }

        if ($expr instanceof Node\Expr\MethodCall
            && $expr->name instanceof Node\Identifier
            && self::isMethodIn($expr->name->toString(), self::REQUEST_INPUT_METHODS)
            && $this->hasPlainArguments($expr, $requestVariables)) {
            $receiver = $expr->var;

            return ($receiver instanceof Node\Expr\FuncCall && self::isHelperCall($receiver, ['request']) && $receiver->getRawArgs() === [])
                || ($receiver instanceof Node\Expr\Variable && in_array($receiver->name, $requestVariables, true));
        }

        return false;
    }

    /**
     * @param  list<string>  $requestVariables
     */
    private function hasPlainArguments(Node\Expr\FuncCall|Node\Expr\MethodCall|Node\Expr\StaticCall $call, array $requestVariables): bool
    {
        foreach ($call->getRawArgs() as $arg) {
            if (! $arg instanceof Node\Arg || $arg->unpack || ! $this->isPlainValue($arg->value, $requestVariables)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Names of the closure's parameters typed as the HTTP request: Illuminate\Http\Request,
     * Illuminate\Foundation\Http\FormRequest, or a form request in an Http\Requests namespace
     * (App\Http\Requests\StoreArticleRequest). A short name ending in Request alone is not
     * enough: Illuminate\Http\Client\PendingRequest sends HTTP requests.
     *
     * @return list<string>
     */
    private function requestParameterNames(Node\Expr\Closure|Node\Expr\ArrowFunction $closure): array
    {
        $names = [];
        foreach ($closure->params as $param) {
            if (! $param->type instanceof Node\Name || ! $param->var instanceof Node\Expr\Variable || ! is_string($param->var->name)) {
                continue;
            }

            $type = ltrim(self::resolvedName($param->type), '\\');
            if (in_array($type, ['Illuminate\\Http\\Request', 'Illuminate\\Foundation\\Http\\FormRequest', 'Request'], true)
                || str_contains($type, '\\Http\\Requests\\')) {
                $names[] = $param->var->name;
            }
        }

        return $names;
    }

    /**
     * The read chain a variable was assigned earlier in the body, recorded as continued there;
     * any other expression unchanged. A use is bound to the assignment before it on its first
     * walk, so `$q = $q->where(...)` continues the earlier `$q`.
     */
    private function continueAssignedChain(Node\Expr $expr, bool $continued = true): Node\Expr
    {
        if (isset($this->readContinuations[spl_object_id($expr)])) {
            return $this->readContinuations[spl_object_id($expr)];
        }

        if (! $expr instanceof Node\Expr\Variable || ! is_string($expr->name) || ! isset($this->assignedReadChains[$expr->name])) {
            return $expr;
        }

        $assigned = $this->assignedReadChains[$expr->name];
        if ($continued) {
            $this->readContinuations[spl_object_id($expr)] = $assigned['expr'];
            $this->continuedCalls += $assigned['calls'];
            $this->continuedChains[spl_object_id($assigned['expr'])] = true;
        }

        return $assigned['expr'];
    }

    /**
     * Whether the expression is a call on the session() helper, such as session()->increment('views'),
     * or session([...]), with plain arguments to every call.
     *
     * @param  list<string>  $requestVariables
     */
    private function isSessionHelperCall(Node\Expr $expr, array $requestVariables): bool
    {
        while ($expr instanceof Node\Expr\MethodCall) {
            if (! $this->hasPlainArguments($expr, $requestVariables)) {
                return false;
            }
            $expr = $expr->var;
        }

        return $expr instanceof Node\Expr\FuncCall
            && self::isHelperCall($expr, ['session'])
            && $this->hasPlainArguments($expr, $requestVariables);
    }

    /**
     * Whether the callbacks a call on a read chain passes keep it a read, adding the calls of
     * each query callback's body to $calls.
     *
     * A closure or arrow function argument must be a query callback, and so must one that is a
     * value of an array passed to an eager-load method (with(['tags' => fn ($q) => ...])).
     * Any other argument holding a callback, or a first-class callable, is not a read. Of the
     * methods that take a callback by contract, only the builder's when(), unless() and tap()
     * hand their closure the builder; the others run it per row.
     *
     * Called without a closure, such a method is a read only as a model static call that the
     * builder does not define, where it is a local scope (Article::filter(...)), or as when()
     * or unless() with a single argument, which returns a proxy for the next call. Anywhere
     * else its argument may be an array callable, a function name or an invokable.
     *
     * @param  array<int, true>  $calls
     * @param  bool  $allowClosures  false after the read terminal, where a closure runs per row
     */
    private function callbacksAreReads(Node\Expr\MethodCall|Node\Expr\StaticCall $call, array &$calls, bool $allowClosures = true): bool
    {
        if ($call->isFirstClassCallable() || ! $call->name instanceof Node\Identifier) {
            return false;
        }

        $method = $call->name->toString();
        $passesClosure = false;
        foreach ($call->getArgs() as $arg) {
            $values = $arg->value instanceof Node\Expr\Array_ && self::isEagerLoadMethod($method)
                ? $arg->value->items
                : [$arg->value];

            foreach ($values as $value) {
                if ($value instanceof Node\ArrayItem) {
                    if ($value->key !== null && self::containsCallback($value->key)) {
                        return false;
                    }
                    $value = $value->value;
                }

                if ($value instanceof Node\Expr\Closure || $value instanceof Node\Expr\ArrowFunction) {
                    $callbackCalls = $allowClosures ? $this->queryCallbackCalls($value) : null;
                    if ($callbackCalls === null) {
                        return false;
                    }

                    $calls += $callbackCalls;
                    $passesClosure = true;

                    continue;
                }

                if (self::containsCallback($value)) {
                    return false;
                }
            }
        }

        if (! self::isMethodIn($method, self::CALLBACK_METHODS)) {
            return true;
        }

        if ($passesClosure) {
            return self::isMethodIn($method, self::BUILDER_RECEIVING_CALLBACK_METHODS);
        }

        if (self::isMethodIn($method, ['when', 'unless']) && count($call->getArgs()) === 1) {
            return true;
        }

        return $call instanceof Node\Expr\StaticCall && ! self::isMethodIn($method, self::BUILDER_CALLBACK_METHODS);
    }

    private static function isEagerLoadMethod(string $method): bool
    {
        $lower = strtolower($method);

        return str_starts_with($lower, 'with') || str_starts_with($lower, 'load');
    }

    /**
     * Whether a call is handed a callable: it is a first-class callable, or an argument holds a
     * closure, an arrow function or a first-class callable. A callback method (CALLBACK_METHODS)
     * also counts an argument that may be a callable: a variable, an array, a string or a new
     * invokable, except that sortBy() and sortByDesc() take a string or an array as the key.
     * Without such an argument, as in sortBy('name') or filter(), no callback runs per row.
     *
     * @internal
     */
    public static function takesCallback(Node\Expr\MethodCall $call): bool
    {
        if ($call->isFirstClassCallable()) {
            return true;
        }

        $method = $call->name instanceof Node\Identifier ? $call->name->toString() : null;
        $isCallbackMethod = $method === null || self::isMethodIn($method, self::CALLBACK_METHODS);
        $takesKeys = $method !== null && self::isMethodIn($method, ['sortBy', 'sortByDesc']);

        foreach ($call->getArgs() as $arg) {
            $value = $arg->value;
            if (self::containsCallback($value)) {
                return true;
            }

            if ($isCallbackMethod
                && ($value instanceof Node\Expr\Variable
                    || $value instanceof Node\Expr\New_
                    || (! $takesKeys && ($value instanceof Node\Expr\Array_ || $value instanceof Node\Scalar\String_)))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @internal
     */
    public static function isHigherOrderProxy(string $property): bool
    {
        return self::isMethodIn($property, self::HIGHER_ORDER_PROXIES);
    }

    private static function containsCallback(Node\Expr $expr): bool
    {
        return (new NodeFinder)->findFirst($expr, static function (Node $node): bool {
            return $node instanceof Node\Expr\Closure
                || $node instanceof Node\Expr\ArrowFunction
                || ($node instanceof Node\Expr\CallLike && $node->isFirstClassCallable());
        }) !== null;
    }

    /**
     * The calls of a query callback's body, or null when it is not one. A query callback, such
     * as whereHas('tags', fn ($q) => $q->where('name', 'php')), only constrains the builder it
     * is handed: its body is one chain, returned or not, of method calls on its first
     * parameter. A call may be a constraint or a local scope, but not a write, a read terminal
     * or its result call, a notification or a dispatch, and its own callbacks must be query
     * callbacks.
     *
     * @return array<int, true>|null
     */
    private function queryCallbackCalls(Node\Expr\Closure|Node\Expr\ArrowFunction $callback): ?array
    {
        $parameter = $callback->params[0]->var ?? null;
        if (! $parameter instanceof Node\Expr\Variable || ! is_string($parameter->name)) {
            return null;
        }

        if ($callback instanceof Node\Expr\ArrowFunction) {
            $current = $callback->expr;
        } else {
            $statements = array_values(array_filter($callback->stmts, static fn (Node\Stmt $stmt): bool => ! $stmt instanceof Node\Stmt\Nop));
            if (count($statements) !== 1
                || ! ($statements[0] instanceof Node\Stmt\Return_ || $statements[0] instanceof Node\Stmt\Expression)
                || $statements[0]->expr === null) {
                return null;
            }
            $current = $statements[0]->expr;
        }

        $calls = [];
        while (true) {
            if ($current instanceof Node\Expr\Variable && $current->name === $parameter->name) {
                return $calls;
            }

            if (! $current instanceof Node\Expr\MethodCall
                || ! $current->name instanceof Node\Identifier
                || ! self::isQueryConstraintMethod($current->name->toString())
                || ! $this->callbacksAreReads($current, $calls)) {
                return null;
            }

            $calls[spl_object_id($current)] = true;
            $current = $current->var;
        }
    }

    private static function isQueryConstraintMethod(string $method): bool
    {
        return ! self::isMethodIn($method, self::WRITE_METHODS)
            && ! self::isMethodIn($method, self::TERMINAL_READ_METHODS)
            && ! self::isMethodIn($method, self::READ_RESULT_TAIL_METHODS)
            && ! self::isMethodIn($method, self::NOTIFY_METHODS)
            && ! self::isMethodIn($method, self::DISPATCHABLE_STATIC_METHODS);
    }

    /**
     * Uses, by spl_object_id, of the closure's parameters whose type is a model, as route model
     * binding fills them. They root both reads and writes; as for writes on static calls, a
     * class in a models namespace counts though its short name is a utility's (App\Models\File).
     *
     * @return array<int, true>
     */
    private function modelParameterUses(Node\Expr\Closure|Node\Expr\ArrowFunction $closure): array
    {
        $uses = [];
        foreach ($closure->params as $param) {
            if ($param->type !== null
                && $param->var instanceof Node\Expr\Variable
                && is_string($param->var->name)
                && $this->isModelType($param->type)) {
                $uses += self::variableUses($closure, $param->var->name);
            }
        }

        return $uses;
    }

    /**
     * Whether a parameter type is a model: a model class, nullable or not, or a union whose
     * every member other than null is one.
     */
    private function isModelType(Node\ComplexType|Node\Identifier|Node\Name $type): bool
    {
        if ($type instanceof Node\NullableType) {
            $type = $type->type;
        }

        if ($type instanceof Node\UnionType) {
            $members = array_filter($type->types, static fn (Node $member): bool => ! ($member instanceof Node\Identifier && $member->toLowerString() === 'null'));

            return $members !== [] && array_filter($members, fn (Node $member): bool => ! $this->isModelType($member)) === [];
        }

        return $type instanceof Node\Name && self::isModelClass($type, self::UTILITY_CLASSES, $this->declaresModel);
    }

    /**
     * Uses, by spl_object_id, of a variable a top-level statement of the closure assigns the
     * signed-in user, as in `$user = auth()->user();`.
     *
     * @return array<int, true>
     */
    private function signedInUserVariableUses(Node\Expr\Closure|Node\Expr\ArrowFunction $closure): array
    {
        if (! $closure instanceof Node\Expr\Closure) {
            return [];
        }

        $uses = [];
        foreach ($closure->stmts as $statement) {
            if ($statement instanceof Node\Stmt\Expression
                && $statement->expr instanceof Node\Expr\Assign
                && $statement->expr->var instanceof Node\Expr\Variable
                && is_string($statement->expr->var->name)
                && self::isSignedInUser($statement->expr->expr)) {
                $uses += self::variableUses($closure, $statement->expr->var->name);
            }
        }

        return $uses;
    }

    /**
     * Uses, by spl_object_id, of a closure's variable in its body, including nested closures that
     * capture it and nested arrow functions, but not those that declare a parameter of that name.
     *
     * @return array<int, true>
     *
     * @internal
     */
    public static function variableUses(Node\Expr\Closure|Node\Expr\ArrowFunction $closure, string $name): array
    {
        $uses = [];
        self::collectVariableUses($closure instanceof Node\Expr\ArrowFunction ? [$closure->expr] : $closure->stmts, $name, $uses);

        return $uses;
    }

    /**
     * @param  array<mixed>  $nodes
     * @param  array<int, true>  $uses
     */
    private static function collectVariableUses(array $nodes, string $name, array &$uses): void
    {
        foreach ($nodes as $node) {
            if (is_array($node)) {
                self::collectVariableUses($node, $name, $uses);

                continue;
            }

            if (! $node instanceof Node) {
                continue;
            }

            if ($node instanceof Node\Expr\Variable && $node->name === $name) {
                $uses[spl_object_id($node)] = true;

                continue;
            }

            if ($node instanceof Node\Expr\Closure || $node instanceof Node\Expr\ArrowFunction) {
                foreach ($node->params as $param) {
                    if ($param->var instanceof Node\Expr\Variable && $param->var->name === $name) {
                        continue 2;
                    }
                }

                if ($node instanceof Node\Expr\ArrowFunction) {
                    self::collectVariableUses([$node->expr], $name, $uses);

                    continue;
                }

                foreach ($node->uses as $use) {
                    if ($use->var->name === $name) {
                        self::collectVariableUses($node->stmts, $name, $uses);
                    }
                }

                continue;
            }

            // A named function or a class has a scope of its own
            if ($node instanceof Node\FunctionLike || $node instanceof Node\Stmt\ClassLike) {
                continue;
            }

            foreach ($node->getSubNodeNames() as $subNodeName) {
                self::collectVariableUses([$node->$subNodeName], $name, $uses);
            }
        }
    }

    /**
     * Whether the expression is the signed-in user: user() on auth(), auth('api'), request() or
     * a variable, on a guard (auth()->guard('api'), Auth::guard('api')), Auth::user() or Request::user().
     *
     * @internal
     */
    public static function isSignedInUser(Node\Expr $expr): bool
    {
        if (! ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\NullsafeMethodCall || $expr instanceof Node\Expr\StaticCall)
            || ! $expr->name instanceof Node\Identifier
            || $expr->name->toString() !== 'user') {
            return false;
        }

        if ($expr instanceof Node\Expr\StaticCall) {
            return $expr->class instanceof Node\Name
                && in_array(ltrim(self::resolvedName($expr->class), '\\'), ['Illuminate\\Support\\Facades\\Auth', 'Auth', 'Illuminate\\Support\\Facades\\Request', 'Request'], true);
        }

        $receiver = $expr->var;

        // A guard: auth()->guard('api') or Auth::guard('api')
        if (($receiver instanceof Node\Expr\MethodCall || $receiver instanceof Node\Expr\StaticCall)
            && $receiver->name instanceof Node\Identifier
            && $receiver->name->toString() === 'guard') {
            return $receiver instanceof Node\Expr\StaticCall
                ? $receiver->class instanceof Node\Name && self::isAuthFacade($receiver->class)
                : self::isHelperCall($receiver->var, ['auth']);
        }

        return $receiver instanceof Node\Expr\Variable || self::isHelperCall($receiver, ['auth', 'request']);
    }

    /**
     * @param  list<string>  $helpers
     */
    private static function isHelperCall(Node\Expr $expr, array $helpers): bool
    {
        return $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && in_array($expr->name->toString(), $helpers, true);
    }

    private static function isAuthFacade(Node\Name $name): bool
    {
        return in_array(ltrim(self::resolvedName($name), '\\'), ['Illuminate\\Support\\Facades\\Auth', 'Auth'], true);
    }

    /**
     * The class name NameResolver resolved, or the name as written when it could not.
     */
    private static function resolvedName(Node\Name $name): string
    {
        $resolvedName = $name->getAttribute('resolvedName');

        return $resolvedName instanceof Node\Name\FullyQualified
            ? $resolvedName->toString()
            : $name->toString();
    }
}
