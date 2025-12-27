<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use PhpParser\Node;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Detects mass assignment vulnerabilities in Eloquent models.
 *
 * Checks for:
 * - Models without $fillable or $guarded
 * - Models with empty $guarded = []
 * - create() or update() with request()->all()
 * - fill() with unfiltered request data
 * - Query builder operations with request data
 */
class MassAssignmentAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Dangerous Eloquent model static methods.
     */
    private const MODEL_STATIC_METHODS = [
        'create',
        'forceCreate',
        'firstOrCreate',
        'updateOrCreate',
        'firstOrNew',
        'make',
        'insert',
        'upsert',
        'insertOrIgnore',
    ];

    /**
     * Dangerous Eloquent model instance methods.
     */
    private const MODEL_INSTANCE_METHODS = [
        'fill',
        'forceFill',
        'update',
    ];

    /**
     * Dangerous query builder methods.
     */
    private const BUILDER_METHODS = [
        'update',
        'insert',
        'upsert',
        'insertOrIgnore',
        'insertUsing',
        'insertGetId',
        'updateOrInsert',
    ];

    /**
     * Request data retrieval methods that are dangerous (unfiltered).
     */
    private const REQUEST_DATA_METHODS = [
        'all',
        'input',
        'post',
        'get',
        'query',
        'json',
    ];

    /**
     * Request data methods using blacklist filtering (less safe than whitelist).
     *
     * These methods DO filter data, but use negative filtering (blacklist)
     * rather than positive filtering (whitelist). New fields are automatically
     * included, making them less safe than only() or validated().
     */
    private const BLACKLIST_REQUEST_METHODS = [
        'except',
    ];

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'mass-assignment-vulnerabilities',
            name: 'Mass Assignment Vulnerabilities Analyzer',
            description: 'Detects mass assignment vulnerabilities in Eloquent models and query builders',
            category: Category::Security,
            severity: Severity::High,
            tags: ['mass-assignment', 'eloquent', 'security', 'models', 'sql-injection'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/mass-assignment-vulnerabilities',
            timeToFix: 25
        );
    }

    public function shouldRun(): bool
    {
        $modelsPath = $this->getBasePath().DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Models';

        return is_dir($modelsPath);
    }

    public function getSkipReason(): string
    {
        return 'No app/Models directory found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            // Check models for proper protection
            $classes = $this->parser->findClasses($ast);
            foreach ($classes as $class) {
                if ($this->isEloquentModel($file, $class)) {
                    $this->checkModelProtection($file, $class, $issues);
                }
            }

            // Check for dangerous method calls with request data
            $this->checkDangerousMethodCalls($file, $ast, $issues);

            // Check for dangerous query builder calls
            $this->checkQueryBuilderCalls($file, $ast, $issues);
        }

        $summary = empty($issues)
            ? 'No mass assignment vulnerabilities detected'
            : sprintf('Found %d potential mass assignment vulnerabilit%s', count($issues), count($issues) === 1 ? 'y' : 'ies');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check if a class is an Eloquent model.
     */
    private function isEloquentModel(string $file, Node\Stmt\Class_ $class): bool
    {
        // First check if extends Model (most reliable)
        if ($class->extends !== null) {
            $parentClass = $class->extends->toString();
            if ($parentClass === 'Model' || str_ends_with($parentClass, '\\Model')) {
                return true;
            }
        }

        // Secondary check: namespace
        $content = FileParser::readFile($file);
        if ($content === null) {
            return false;
        }

        if (str_contains($content, 'namespace App\\Models')) {
            return true;
        }

        return false;
    }

    /**
     * Check if model has proper mass assignment protection.
     */
    private function checkModelProtection(string $file, Node\Stmt\Class_ $class, array &$issues): void
    {
        $hasFillable = false;
        $hasGuarded = false;
        $hasEmptyGuarded = false;

        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Property) {
                foreach ($stmt->props as $prop) {
                    if ($prop->name->toString() === 'fillable') {
                        $hasFillable = true;
                    }

                    if ($prop->name->toString() === 'guarded') {
                        $hasGuarded = true;

                        // Check if $guarded = []
                        if ($prop->default instanceof Node\Expr\Array_ && empty($prop->default->items)) {
                            $hasEmptyGuarded = true;
                        }
                    }
                }
            }
        }

        $modelName = $class->name ? $class->name->toString() : 'Unknown';

        // Issue if neither fillable nor guarded is set
        if (! $hasFillable && ! $hasGuarded) {
            $issues[] = $this->createIssueWithSnippet(
                message: "Model '{$modelName}' lacks mass assignment protection (\$fillable or \$guarded)",
                filePath: $file,
                lineNumber: $class->getLine(),
                severity: Severity::High,
                recommendation: 'Add protected $fillable = [...] or protected $guarded = ["*"] to the model',
                metadata: [
                    'model' => $modelName,
                    'issue_type' => 'missing_model_protection',
                ]
            );
        }

        // Issue if guarded is empty array (allows all)
        if ($hasEmptyGuarded) {
            $issues[] = $this->createIssueWithSnippet(
                message: "Model '{$modelName}' has \$guarded = [] which allows mass assignment of all attributes",
                filePath: $file,
                lineNumber: $class->getLine(),
                severity: Severity::Critical,
                recommendation: 'Either specify fillable attributes or use $guarded = ["*"] to protect all',
                metadata: [
                    'model' => $modelName,
                    'issue_type' => 'empty_guarded_array',
                ]
            );
        }
    }

    /**
     * Check for dangerous Eloquent method calls with request data.
     */
    private function checkDangerousMethodCalls(string $file, array $ast, array &$issues): void
    {
        // Check static method calls (e.g., User::create())
        foreach (self::MODEL_STATIC_METHODS as $method) {
            $calls = $this->findStaticMethodCalls($ast, $method);

            foreach ($calls as $call) {
                // Only check if it's likely a model class to avoid false positives
                if ($this->isLikelyModelClass($call, $file)) {
                    $this->checkCallForRequestData($call, $method, 'static', $file, $issues);
                }
            }
        }

        // Check instance method calls (e.g., $model->update())
        foreach (self::MODEL_INSTANCE_METHODS as $method) {
            $calls = $this->parser->findMethodCalls($ast, $method);

            foreach ($calls as $call) {
                if ($call instanceof Node\Expr\MethodCall) {
                    // Skip if this is already being handled by query builder check
                    // e.g., User::where()->update() should be handled by builder check, not instance check
                    if ($this->isQueryBuilderCall($call, $file)) {
                        continue; // Already handled by checkQueryBuilderCalls
                    }

                    $this->checkCallForRequestData($call, $method, 'instance', $file, $issues);
                }
            }
        }
    }

    /**
     * Check if a static call is likely on an Eloquent model.
     *
     * This reduces false positives by filtering out service classes, factories, etc.
     * that might have create() methods but aren't Eloquent models.
     */
    private function isLikelyModelClass(Node\Expr\StaticCall $call, string $file): bool
    {
        if (! $call->class instanceof Node\Name) {
            return false;
        }

        $className = $call->class->toString();

        // Handle fully-qualified class names like \App\Models\User
        if (str_starts_with($className, '\\')) {
            // Remove leading backslash for checking
            $normalizedClassName = ltrim($className, '\\');

            // Check if it's in App\Models namespace
            if (str_starts_with($normalizedClassName, 'App\\Models\\') ||
                str_starts_with($normalizedClassName, 'App\\Model\\')) {
                return true;
            }

            // Check if it matches common model namespaces
            if (str_contains($normalizedClassName, '\\Models\\') ||
                str_contains($normalizedClassName, '\\Model\\')) {
                return true;
            }
        }

        // For unqualified names, check if the model exists in app/Models
        $modelsPath = $this->getBasePath().DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'Models';
        $modelFile = $modelsPath.DIRECTORY_SEPARATOR.$className.'.php';

        if (file_exists($modelFile)) {
            return true;
        }

        // Check if the file has a use statement importing this class from Models namespace
        $content = FileParser::readFile($file);
        if ($content !== null) {
            $quotedClassName = preg_quote($className, '/');

            // Match: use App\Models\ClassName;
            if (preg_match('/use\s+App\\\\Models\\\\'.$quotedClassName.'\s*;/i', $content)) {
                return true;
            }

            // Match: use App\Model\ClassName;
            if (preg_match('/use\s+App\\\\Model\\\\'.$quotedClassName.'\s*;/i', $content)) {
                return true;
            }

            // Match any namespace with Models in it
            if (preg_match('/use\s+[\w\\\\]+\\\\Models\\\\'.$quotedClassName.'\s*;/i', $content)) {
                return true;
            }
        }

        // Check if the file has a use statement importing from known non-model namespaces
        if ($content !== null) {
            // Match use statements for common non-model namespaces
            $nonModelNamespacePatterns = [
                '/use\s+App\\\\Services\\\\'.$quotedClassName.'\s*;/i',
                '/use\s+App\\\\Repositories\\\\'.$quotedClassName.'\s*;/i',
                '/use\s+App\\\\Actions\\\\'.$quotedClassName.'\s*;/i',
                '/use\s+App\\\\Jobs\\\\'.$quotedClassName.'\s*;/i',
                '/use\s+App\\\\Handlers\\\\'.$quotedClassName.'\s*;/i',
                '/use\s+App\\\\Helpers\\\\'.$quotedClassName.'\s*;/i',
                '/use\s+App\\\\Support\\\\'.$quotedClassName.'\s*;/i',
                '/use\s+[\w\\\\]+\\\\Services\\\\'.$quotedClassName.'\s*;/i',
                '/use\s+[\w\\\\]+\\\\Repositories\\\\'.$quotedClassName.'\s*;/i',
            ];

            foreach ($nonModelNamespacePatterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    return false;
                }
            }
        }

        // Check if class name follows common non-model naming patterns
        // Services, Repositories, Jobs, etc. are unlikely to be models
        $nonModelSuffixes = [
            'Service',
            'Repository',
            'Action',
            'Job',
            'Handler',
            'Helper',
            'Facade',
            'Provider',
            'Middleware',
            'Command',
            'Rule',
            'Policy',
            'Resource',
            'Request',
            'Controller',
        ];

        foreach ($nonModelSuffixes as $suffix) {
            if (str_ends_with($className, $suffix)) {
                return false;
            }
        }

        // If we can't determine it's NOT a model, be conservative and check it
        // This ensures we don't miss actual models while reducing obvious false positives
        // Only skip if it's clearly a known non-model class
        $nonModelPatterns = [
            'DB',
            'Cache',
            'Session',
            'Auth',
            'Hash',
            'Crypt',
            'Storage',
            'File',
            'Queue',
            'Event',
            'Mail',
            'Notification',
            'Log',
            'Validator',
            'Factory',
            'Seeder',
        ];

        if (in_array($className, $nonModelPatterns, true)) {
            return false;
        }

        // Default to true for unknown classes to avoid missing models
        // Better to have occasional false positive than miss actual vulnerabilities
        return true;
    }

    /**
     * Check for dangerous query builder calls with request data.
     */
    private function checkQueryBuilderCalls(string $file, array $ast, array &$issues): void
    {
        foreach (self::BUILDER_METHODS as $method) {
            // Find all method calls with this name
            $calls = $this->parser->findMethodCalls($ast, $method);

            foreach ($calls as $call) {
                // Check if it's called on a query builder
                if ($call instanceof Node\Expr\MethodCall && $this->isQueryBuilderCall($call, $file)) {
                    $this->checkCallForRequestData($call, $method, 'builder', $file, $issues);
                }
            }
        }
    }

    /**
     * Find static method calls in AST.
     */
    private function findStaticMethodCalls(array $ast, string $methodName): array
    {
        $calls = [];

        $traverse = function (array $nodes) use (&$traverse, &$calls, $methodName): void {
            foreach ($nodes as $node) {
                if ($node instanceof Node\Expr\StaticCall) {
                    if ($node->name instanceof Node\Identifier && $node->name->toString() === $methodName) {
                        $calls[] = $node;
                    }
                }

                // Recursively traverse child nodes
                foreach ($node->getSubNodeNames() as $subNodeName) {
                    $subNode = $node->$subNodeName;
                    if (is_array($subNode)) {
                        $traverse($subNode);
                    } elseif ($subNode instanceof Node) {
                        $traverse([$subNode]);
                    }
                }
            }
        };

        $traverse($ast);

        return $calls;
    }

    /**
     * Check if a method call is on a query builder.
     *
     * Detects:
     * - DB::table()->update()
     * - User::query()->update()
     * - User::where()->update()
     * - User::whereIn()->orderBy()->update()
     */
    private function isQueryBuilderCall(Node\Expr\MethodCall $call, string $file): bool
    {
        return $this->isQueryBuilderChain($call->var, $file);
    }

    /**
     * Recursively check if a node represents a query builder chain.
     *
     * This traverses the method chain to detect query builder origins:
     * - Static calls to Model classes with query builder methods
     * - DB facade calls
     * - Common query builder method chains
     *
     * @param  string  $file  The file being analyzed (for model verification)
     */
    private function isQueryBuilderChain(Node\Expr $node, string $file = ''): bool
    {
        // Check if called on DB facade
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name) {
                $className = $node->class->toString();
                if ($className === 'DB' || str_ends_with($className, '\\DB')) {
                    return true;
                }
            }

            // Check if it's a static call to a query builder method on a model
            // e.g., User::where(), User::whereIn(), User::find()
            if ($node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();
                if ($this->isQueryBuilderMethod($methodName)) {
                    // IMPORTANT: Verify this is actually a model class to avoid false positives
                    // SomeService::where() should NOT be treated as a query builder
                    if ($this->isLikelyModelClass($node, $file)) {
                        return true;
                    }
                }
            }
        }

        // Check if it's a method call in a chain
        if ($node instanceof Node\Expr\MethodCall) {
            if ($node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();

                // If it's a known query builder method, recursively check the chain
                if ($this->isQueryBuilderMethod($methodName)) {
                    return $this->isQueryBuilderChain($node->var, $file);
                }
            }
        }

        return false;
    }

    /**
     * Check if a method name is a query builder method.
     *
     * These methods return a query builder instance and can be chained.
     */
    private function isQueryBuilderMethod(string $methodName): bool
    {
        $queryBuilderMethods = [
            // Query builder initiators
            'query',
            'table',
            'newQuery',

            // Where clauses
            'where',
            'whereIn',
            'whereNotIn',
            'whereBetween',
            'whereNotBetween',
            'whereNull',
            'whereNotNull',
            'whereDate',
            'whereMonth',
            'whereDay',
            'whereYear',
            'whereTime',
            'whereColumn',
            'whereExists',
            'whereNotExists',
            'whereRaw',
            'orWhere',
            'orWhereIn',
            'orWhereNotIn',
            'orWhereBetween',
            'orWhereNotBetween',
            'orWhereNull',
            'orWhereNotNull',

            // Joins
            'join',
            'leftJoin',
            'rightJoin',
            'crossJoin',
            'joinSub',
            'leftJoinSub',
            'rightJoinSub',

            // Ordering and grouping
            'orderBy',
            'orderByDesc',
            'orderByRaw',
            'groupBy',
            'groupByRaw',
            'having',
            'havingRaw',
            'orHaving',
            'orHavingRaw',

            // Limiting
            'limit',
            'offset',
            'skip',
            'take',
            'forPage',

            // Selects
            'select',
            'selectRaw',
            'selectSub',
            'addSelect',
            'distinct',

            // Locking
            'lockForUpdate',
            'sharedLock',

            // Other common methods
            'with',
            'withCount',
            'withTrashed',
            'onlyTrashed',
            'latest',
            'oldest',
            'when',
            'unless',
        ];

        return in_array($methodName, $queryBuilderMethods, true);
    }

    /**
     * Check if a call contains request data in its arguments.
     */
    private function checkCallForRequestData(
        Node\Expr\MethodCall|Node\Expr\StaticCall $call,
        string $method,
        string $callType,
        string $file,
        array &$issues
    ): void {
        if (empty($call->args)) {
            return;
        }

        foreach ($call->args as $arg) {
            // Recursively check for blacklist filtering first (except)
            if ($this->containsBlacklistRequestData($arg->value)) {
                $callTypeLabel = match ($callType) {
                    'static' => 'Static call to',
                    'instance' => 'Instance call to',
                    'builder' => 'Query builder call to',
                    default => 'Call to',
                };

                $issues[] = $this->createIssueWithSnippet(
                    message: "{$callTypeLabel} {$method}() uses blacklist filtering (except) which may allow unintended fields",
                    filePath: $file,
                    lineNumber: $call->getLine(),
                    severity: Severity::High,
                    recommendation: 'Use request()->only([...]) or request()->validated() instead of except() for better security. Whitelist (only) is safer than blacklist (except) as new fields are excluded by default',
                    metadata: [
                        'method' => $method,
                        'call_type' => $callType,
                        'filtering_type' => 'blacklist',
                        'issue_type' => 'dangerous_method_with_blacklist_filtering',
                    ]
                );

                return; // Don't double-report
            }

            // Recursively check for unfiltered request data
            if ($this->containsRequestData($arg->value)) {
                $callTypeLabel = match ($callType) {
                    'static' => 'Static call to',
                    'instance' => 'Instance call to',
                    'builder' => 'Query builder call to',
                    default => 'Call to',
                };

                $issues[] = $this->createIssueWithSnippet(
                    message: "{$callTypeLabel} {$method}() with unfiltered request data may result in mass assignment vulnerability",
                    filePath: $file,
                    lineNumber: $call->getLine(),
                    severity: Severity::Critical,
                    recommendation: 'Use request()->only([...]) or request()->validated() to specify allowed fields explicitly',
                    metadata: [
                        'method' => $method,
                        'call_type' => $callType,
                        'filtering_type' => 'none',
                        'issue_type' => 'dangerous_method_with_request_data',
                    ]
                );

                // Only report once per method call
                break;
            }
        }
    }

    /**
     * Recursively check if a node or its children contain blacklist-filtered request data.
     *
     * This traverses the entire expression tree to find nested request data patterns
     * like: ['name' => $request->except(['password'])['name']]
     */
    private function containsBlacklistRequestData(Node $node): bool
    {
        // Direct check: is this node itself blacklist request data?
        if ($this->isBlacklistRequestData($node)) {
            return true;
        }

        // Traverse arrays: check all array items
        if ($node instanceof Node\Expr\Array_) {
            foreach ($node->items as $item) {
                if ($item === null) {
                    continue;
                }

                // Check both key and value
                if ($item->key !== null && $this->containsBlacklistRequestData($item->key)) {
                    return true;
                }

                if ($this->containsBlacklistRequestData($item->value)) {
                    return true;
                }
            }
        }

        // Traverse array dimension access: $request->except()['name']
        if ($node instanceof Node\Expr\ArrayDimFetch) {
            if ($this->containsBlacklistRequestData($node->var)) {
                return true;
            }

            if ($node->dim !== null && $this->containsBlacklistRequestData($node->dim)) {
                return true;
            }
        }

        // Traverse ternary expressions: condition ? true : false
        if ($node instanceof Node\Expr\Ternary) {
            if ($this->containsBlacklistRequestData($node->cond)) {
                return true;
            }

            if ($node->if !== null && $this->containsBlacklistRequestData($node->if)) {
                return true;
            }

            if ($this->containsBlacklistRequestData($node->else)) {
                return true;
            }
        }

        // Traverse binary operations: $a . $b, $a + $b, etc.
        if ($node instanceof Node\Expr\BinaryOp) {
            if ($this->containsBlacklistRequestData($node->left)) {
                return true;
            }

            if ($this->containsBlacklistRequestData($node->right)) {
                return true;
            }
        }

        // Traverse cast expressions: (string) $request->except()
        if ($node instanceof Node\Expr\Cast) {
            if ($this->containsBlacklistRequestData($node->expr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Recursively check if a node or its children contain unfiltered request data.
     *
     * This traverses the entire expression tree to find nested request data patterns
     * like: ['name' => $request->all()['name']]
     */
    private function containsRequestData(Node $node): bool
    {
        // Direct check: is this node itself request data?
        if ($this->isRequestData($node)) {
            return true;
        }

        // Traverse arrays: check all array items
        if ($node instanceof Node\Expr\Array_) {
            foreach ($node->items as $item) {
                if ($item === null) {
                    continue;
                }

                // Check both key and value
                if ($item->key !== null && $this->containsRequestData($item->key)) {
                    return true;
                }

                if ($this->containsRequestData($item->value)) {
                    return true;
                }
            }
        }

        // Traverse array dimension access: $request->all()['name']
        if ($node instanceof Node\Expr\ArrayDimFetch) {
            if ($this->containsRequestData($node->var)) {
                return true;
            }

            if ($node->dim !== null && $this->containsRequestData($node->dim)) {
                return true;
            }
        }

        // Traverse ternary expressions: condition ? true : false
        if ($node instanceof Node\Expr\Ternary) {
            if ($this->containsRequestData($node->cond)) {
                return true;
            }

            if ($node->if !== null && $this->containsRequestData($node->if)) {
                return true;
            }

            if ($this->containsRequestData($node->else)) {
                return true;
            }
        }

        // Traverse binary operations: $a . $b, $a + $b, etc.
        if ($node instanceof Node\Expr\BinaryOp) {
            if ($this->containsRequestData($node->left)) {
                return true;
            }

            if ($this->containsRequestData($node->right)) {
                return true;
            }
        }

        // Traverse cast expressions: (string) $request->all()
        if ($node instanceof Node\Expr\Cast) {
            if ($this->containsRequestData($node->expr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a node represents blacklist-filtered request data (except).
     *
     * These methods DO filter, but use blacklist approach which is less safe.
     */
    private function isBlacklistRequestData(Node $node): bool
    {
        // Check for request()->except() patterns
        if ($node instanceof Node\Expr\MethodCall) {
            if ($node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();

                // Check if it's a blacklist request method
                if (in_array($methodName, self::BLACKLIST_REQUEST_METHODS, true)) {
                    // Called on request() function
                    if ($node->var instanceof Node\Expr\FuncCall) {
                        if ($node->var->name instanceof Node\Name && $node->var->name->toString() === 'request') {
                            // Only flag if except() has arguments (it should always have args)
                            // except() with no args would be meaningless and return all data
                            return true;
                        }
                    }

                    // Called on $request variable
                    if ($node->var instanceof Node\Expr\Variable && $node->var->name === 'request') {
                        return true;
                    }

                    // Called on Request facade or type-hinted parameter
                    if ($node->var instanceof Node\Expr\Variable) {
                        // This could be a FormRequest or Request parameter
                        return true;
                    }
                }
            }
        }

        // Check for Request::except() static calls
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();

                if (in_array($methodName, self::BLACKLIST_REQUEST_METHODS, true)) {
                    if ($node->class instanceof Node\Name) {
                        $className = $node->class->toString();
                        if (str_contains($className, 'Request')) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check if a node represents request data (all dangerous forms).
     */
    private function isRequestData(Node $node): bool
    {
        // Check for request()->method() patterns
        if ($node instanceof Node\Expr\MethodCall) {
            if ($node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();

                // Check if it's a dangerous request method
                if (in_array($methodName, self::REQUEST_DATA_METHODS, true)) {
                    // Called on request() function
                    if ($node->var instanceof Node\Expr\FuncCall) {
                        if ($node->var->name instanceof Node\Name && $node->var->name->toString() === 'request') {
                            // Check if no arguments (e.g., request()->input() with no args = all input)
                            // These methods are only dangerous when called without arguments
                            if (in_array($methodName, ['input', 'get', 'post', 'query', 'json'], true)) {
                                // If has args, it's filtering to a specific key - OK
                                if (! empty($node->args)) {
                                    return false;
                                }
                            }

                            return true;
                        }
                    }

                    // Called on $request variable
                    if ($node->var instanceof Node\Expr\Variable && $node->var->name === 'request') {
                        // Same logic for instance methods
                        if (in_array($methodName, ['input', 'get', 'post', 'query', 'json'], true)) {
                            if (! empty($node->args)) {
                                return false;
                            }
                        }

                        return true;
                    }
                }

                // Check for ->only() or ->validated() - these are safe
                if (in_array($methodName, ['only', 'validated', 'safe'], true)) {
                    return false;
                }
            }
        }

        // Check for Request::all() static calls
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();

                if (in_array($methodName, self::REQUEST_DATA_METHODS, true)) {
                    if ($node->class instanceof Node\Name) {
                        $className = $node->class->toString();
                        if (str_contains($className, 'Request')) {
                            return true;
                        }
                    }
                }
            }
        }

        // Check for Input::all() facade (legacy)
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name) {
                $className = $node->class->toString();
                if ($className === 'Input' || str_ends_with($className, '\\Input')) {
                    if ($node->name instanceof Node\Identifier) {
                        if (in_array($node->name->toString(), self::REQUEST_DATA_METHODS, true)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }
}
