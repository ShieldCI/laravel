<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use PhpParser\Node;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Concerns\TracksImportedNames;
use ShieldCI\Support\EloquentModelDetector;
use ShieldCI\Support\EloquentModelHelper;

/**
 * Detects mass assignment vulnerabilities in Eloquent models.
 *
 * Checks for:
 * - Models with empty $guarded = []
 * - Models without $hidden attributes for sensitive data
 * - create() or update() with request()->all()
 * - fill() with unfiltered request data
 * - Query builder operations with request data
 * - Relationship operations (sync, attach, etc.) with unfiltered data
 * - Nested mass assignment patterns (dot notation)
 * - Relationship security (verifying related models have protection)
 */
class MassAssignmentAnalyzer extends AbstractFileAnalyzer
{
    use TracksImportedNames;

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

    /**
     * Methods that fill relationship data with potentially unsafe input.
     */
    private const RELATIONSHIP_FILL_METHODS = [
        'associate', 'dissociate', 'attach', 'detach', 'sync', 'syncWithoutDetaching',
        'toggle', 'updateExistingPivot', 'syncWithPivotValues',
    ];

    /**
     * Sensitive fields that should be hidden from JSON serialization.
     *
     * These fields contain sensitive data that should never be exposed
     * in API responses or JSON output.
     */
    private const SENSITIVE_FIELDS = [
        'password',
        'password_hash',
        'remember_token',
        'api_token',
        'secret',
        'two_factor_secret',
        'two_factor_recovery_codes',
    ];

    public function __construct(
        private AstParser $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'mass-assignment-vulnerabilities',
            name: 'Mass Assignment Vulnerabilities Analyzer',
            description: 'Detects mass assignment vulnerabilities in Eloquent models and query builders',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['mass-assignment', 'eloquent', 'security', 'models', 'sql-injection'],
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
        $detector = new EloquentModelDetector($this->parser);

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                continue;
            }

            // Check models for proper protection
            $classes = $this->parser->findClasses($ast);
            foreach ($classes as $class) {
                if ($detector->isModel($class, $ast, $this->getBasePath())) {
                    // Resolve attribute names through the imports in effect at this class, so
                    // an aliased #[Fillable] is Laravel's and an App\Attributes\Fillable is not.
                    $this->startTrackingImports();
                    $this->trackImportsUntil($ast, $class);

                    $resolve = $this->resolvedClassFqn(...);

                    $this->checkModelProtection($file, $class, $resolve, $issues);
                    $this->checkHiddenAttributes($file, $class, $resolve, $issues);
                    $this->checkRelationshipSecurity($file, $class, $issues);
                }
            }

            // Check for dangerous method calls with request data
            $this->checkDangerousMethodCalls($file, $ast, $issues);

            // Check for dangerous query builder calls
            $this->checkQueryBuilderCalls($file, $ast, $issues);

            // Check for dangerous relationship operations
            $this->checkRelationshipOperations($file, $ast, $issues);

            // Check for nested mass assignment
            $this->checkNestedMassAssignment($file, $ast, $issues);
        }

        $summary = empty($issues)
            ? 'No mass assignment vulnerabilities detected'
            : sprintf('Found %d potential mass assignment vulnerabilit%s', count($issues), count($issues) === 1 ? 'y' : 'ies');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Base classes that leave every Model default in place: Model itself, Authenticatable,
     * which adds nothing to it, and `Eloquent`, Laravel's default global alias of Model.
     */
    private const MODEL_BASES = [
        'Illuminate\\Database\\Eloquent\\Model',
        'Illuminate\\Foundation\\Auth\\User',
        'Eloquent',
    ];

    /**
     * Base classes that change only `$guarded`, to `[]`, and keep Model's `$hidden` and
     * `$visible` defaults.
     */
    private const PIVOT_BASES = [
        'Illuminate\\Database\\Eloquent\\Relations\\Pivot',
        'Illuminate\\Database\\Eloquent\\Relations\\MorphPivot',
    ];

    /**
     * Check whether the model opens every attribute to mass assignment, with `$guarded = []`
     * or, while the property keeps its default, with `#[Unguarded]` or `#[Guarded([])]`.
     *
     * A model that declares none of these is not reported. One extending Model inherits
     * `$guarded = ['*']` and is totally guarded; Pivot and MorphPivot declare `$guarded = []`
     * on purpose, for the pivot rows Eloquent writes itself.
     *
     * A class extending Pivot or MorphPivot directly is not reported for `$guarded = []`: it
     * restates the parent's own default, and a Pivot that declares nothing behaves the same.
     *
     * A model that lists fillable columns is not reported either: fill() keeps only those
     * columns whatever $guarded says.
     *
     * @param  \Closure(Node\Name): string  $resolve  The fully qualified name a reference resolves to
     * @param  array<int, Issue>  &$issues
     */
    private function checkModelProtection(string $file, Node\Stmt\Class_ $class, \Closure $resolve, array &$issues): void
    {
        $parentKind = $this->parentKind($class, $resolve);

        // A $fillable whose default is not an array literal, such as a constant, still lists
        // columns; only their names are unknown.
        if ($parentKind === 'pivot'
            || EloquentModelHelper::extractFillableFields($class, $resolve) !== []
            || $this->declaresNonLiteralProperty($class, 'fillable')) {
            return;
        }

        $hasEmptyGuarded = false;
        // GuardsAttributes applies #[Unguarded]/#[Guarded] only while $guarded is still ['*'].
        $attributesApply = true;

        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Property) {
                foreach ($stmt->props as $prop) {
                    if ($prop->name->toString() !== 'guarded') {
                        continue;
                    }

                    if ($prop->default instanceof Node\Expr\Array_ && empty($prop->default->items)) {
                        $hasEmptyGuarded = true;
                    }

                    if (! $this->isWildcardArray($prop->default)) {
                        $attributesApply = false;
                    }
                }
            }
        }

        $modelName = $class->name ? $class->name->toString() : 'Unknown';

        // Issue if guarded is empty array (allows all)
        if ($hasEmptyGuarded) {
            $issues[] = $this->createIssueWithSnippet(
                message: "Model '{$modelName}' has \$guarded = [] which allows mass assignment of all attributes",
                filePath: $file,
                lineNumber: $class->getLine(),
                severity: Severity::Critical,
                recommendation: 'Either specify which attributes are fillable, or set guarded to a wildcard to deny all attributes by default.',
                metadata: [
                    'model' => $modelName,
                    'issue_type' => 'empty_guarded_array',
                ]
            );

            return;
        }

        // The attribute only replaces a $guarded that is still ['*'], which an unread parent
        // or a Pivot's own [] may not be.
        $attribute = $attributesApply && $parentKind === 'model'
            ? EloquentModelHelper::unguardingAttribute($class, $resolve)
            : null;

        if ($attribute !== null) {
            $writtenAs = $attribute === 'Unguarded' ? '#[Unguarded]' : '#[Guarded([])]';

            $issues[] = $this->createIssueWithSnippet(
                message: "Model '{$modelName}' has {$writtenAs} which allows mass assignment of all attributes",
                filePath: $file,
                lineNumber: $class->getLine(),
                severity: Severity::Critical,
                recommendation: 'Remove the attribute and either specify which attributes are fillable, or leave guarded at its wildcard default to deny all attributes.',
                metadata: [
                    'model' => $modelName,
                    'issue_type' => 'empty_guarded_array',
                    'attribute' => $attribute,
                ]
            );
        }
    }

    /**
     * True for an array literal equal to `['*']`, the value Eloquent's own `$guarded` default
     * holds, including the `[0 => '*']` spelling.
     */
    private function isWildcardArray(?Node\Expr $expr): bool
    {
        if (! $expr instanceof Node\Expr\Array_ || count($expr->items) !== 1) {
            return false;
        }

        $item = $expr->items[0];
        if (! $item instanceof Node\Expr\ArrayItem || $item->byRef || $item->unpack) {
            return false;
        }

        $keyIsZero = $item->key === null
            || ($item->key instanceof Node\Scalar\Int_ && $item->key->value === 0)
            || ($item->key instanceof Node\Scalar\String_ && $item->key->value === '0');

        return $keyIsZero && $item->value instanceof Node\Scalar\String_ && $item->value->value === '*';
    }

    /**
     * Which defaults the model inherits for what it does not override: `model` when it extends
     * Model, Authenticatable or the global `Eloquent` alias directly, `pivot` when it extends
     * Pivot or MorphPivot directly, null for any other parent.
     *
     * The model's own configuration is authoritative only for what it overrides. A `pivot`
     * keeps Model's `$hidden` and `$visible` defaults but has `$guarded = []` of its own. A
     * project base class may declare anything, and this analyzer does not read its file, so a
     * finding whose truth turns on an inherited value is not made under one: the attribute
     * form of the unguarded finding, which needs an inherited `$guarded = ['*']` and so a
     * `model` parent, and the missing-`$hidden` finding, which a parent's `$hidden` or
     * `$visible` may answer. What the model declares as a property itself, `$guarded = []` or
     * a `$hidden` list that replaces the parent's, is still reported.
     *
     * @param  \Closure(Node\Name): string  $resolve
     * @return 'model'|'pivot'|null
     */
    private function parentKind(Node\Stmt\Class_ $class, \Closure $resolve): ?string
    {
        if ($class->extends === null) {
            return null;
        }

        $parent = $resolve($class->extends);

        foreach (['model' => self::MODEL_BASES, 'pivot' => self::PIVOT_BASES] as $kind => $bases) {
            foreach ($bases as $base) {
                if (strcasecmp($parent, $base) === 0) {
                    return $kind;
                }
            }
        }

        return null;
    }

    /**
     * True if the class body declares the named property with a default that is not an array
     * literal, so the list it holds cannot be read here.
     */
    private function declaresNonLiteralProperty(Node\Stmt\Class_ $class, string $name): bool
    {
        foreach ($class->getProperties() as $property) {
            foreach ($property->props as $prop) {
                if ($prop->name->toString() === $name
                    && $prop->default !== null
                    && ! $prop->default instanceof Node\Expr\Array_) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * True if the class body declares the named property itself.
     */
    private function declaresProperty(Node\Stmt\Class_ $class, string $name): bool
    {
        foreach ($class->getProperties() as $property) {
            foreach ($property->props as $prop) {
                if ($prop->name->toString() === $name) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check for dangerous Eloquent method calls with request data.
     *
     * @param  array<int, Node>  $ast
     * @param  array<int, Issue>  &$issues
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
                '/use\s+App\\\\Models\\\\Scopes\\\\'.$quotedClassName.'\s*;/i',
                '/use\s+App\\\\Models\\\\Observers\\\\'.$quotedClassName.'\s*;/i',
                '/use\s+App\\\\Models\\\\Casts\\\\'.$quotedClassName.'\s*;/i',
                '/use\s+App\\\\Models\\\\Collections\\\\'.$quotedClassName.'\s*;/i',
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
            'Scope',
            'Observer',
            'Cast',
            'Collection',
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
     *
     * @param  array<int, Node>  $ast
     * @param  array<int, Issue>  &$issues
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
     *
     * @param  array<int, Node>  $ast
     * @return array<int, Node\Expr\StaticCall>
     */
    private function findStaticMethodCalls(array $ast, string $methodName): array
    {
        $calls = [];

        $traverse = function (array $nodes) use (&$traverse, &$calls, $methodName): void {
            foreach ($nodes as $node) {
                // Sub-node arrays can hold null slots (e.g. skipped destructuring
                // targets: [, , $x] = ...), which must not reach getSubNodeNames().
                if (! $node instanceof Node) {
                    continue;
                }

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
     *
     * @param  array<int, Issue>  $issues
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
            // First-class callable syntax (foo(...)) yields a VariadicPlaceholder
            // rather than an Arg, which has no ->value to inspect.
            if (! $arg instanceof Node\Arg) {
                continue;
            }

            // A column set fixed by literal keys cannot mass-assign
            // attacker-chosen columns, wherever its values come from.
            if ($this->isClosedLiteralKeyArray($arg->value)) {
                continue;
            }

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
                    recommendation: 'Use whitelist filtering to specify only the fields you expect, rather than blacklist filtering with except(). A FormRequest with validated data is the strongest approach as new fields are excluded by default.',
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
                    recommendation: 'Filter the request to only the fields you expect before passing data to Eloquent. A FormRequest validates and whitelists fields in one step, providing the strongest protection.',
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
     * True when the node is an array literal whose column set is fixed in source:
     * every element has a literal string key, with no spread (...$data) and no
     * dynamic/computed key. Such an array cannot mass-assign attacker-chosen
     * columns regardless of where its values come from.
     */
    private function isClosedLiteralKeyArray(Node $node): bool
    {
        if (! $node instanceof Node\Expr\Array_) {
            return false;
        }

        foreach ($node->items as $item) {
            // php-parser 4.x leaves null slots for empty array elements.
            if ($item === null || $item->unpack) {
                return false;
            }

            // A positional element or computed key means the column name is
            // not fixed at author time.
            if (! $item->key instanceof Node\Scalar\String_) {
                return false;
            }
        }

        return true;
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

                    // IMPORTANT: Catch ANY variable with Request-specific methods
                    // This handles: function store(Request $r) { User::create($r->all()); }
                    // Methods like all(), input(), post(), query(), json() are very Request-specific
                    // so we can safely assume any variable using them is a Request instance
                    if ($node->var instanceof Node\Expr\Variable) {
                        // Same argument filtering logic
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

        // Check for direct request() helper function calls (with or without args)
        // For relationship methods, even request('single_key') is potentially unsafe
        if ($node instanceof Node\Expr\FuncCall) {
            if ($node->name instanceof Node\Name && $node->name->toString() === 'request') {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if model has proper $hidden attributes for sensitive data.
     *
     * @param  \Closure(Node\Name): string  $resolve  The fully qualified name a reference resolves to
     * @param  array<int, Issue>  &$issues
     */
    private function checkHiddenAttributes(string $file, Node\Stmt\Class_ $class, \Closure $resolve, array &$issues): void
    {
        // Read configuration from either properties or #[Fillable]/#[Guarded]/#[Hidden] attributes.
        $hasHidden = EloquentModelHelper::hasHidden($class, $resolve);
        $hasFillable = EloquentModelHelper::hasFillable($class, $resolve);
        $hiddenFields = EloquentModelHelper::extractHiddenFields($class, $resolve);
        $guardedFields = EloquentModelHelper::extractGuardedFields($class, $resolve);
        $fillableFields = EloquentModelHelper::extractFillableFields($class, $resolve);
        // A non-empty $visible is an allow-list: a field it leaves out is never serialized.
        $visibleFields = EloquentModelHelper::extractVisibleFields($class, $resolve);

        $modelName = $class->name ? $class->name->toString() : 'Unknown';
        // Pivot and MorphPivot keep Model's $hidden and $visible defaults.
        $inheritsModelDefaults = $this->parentKind($class, $resolve) !== null;

        // Check if password-related fields in $fillable are hidden
        // Fields in $guarded are not mass-assignable, so they're less critical to hide
        // Under any other parent, an inherited $hidden or $visible may already cover them.
        if ($inheritsModelDefaults && $hasFillable && ! $hasHidden && ! empty($fillableFields)) {
            $exposedSensitiveFields = array_intersect($fillableFields, self::SENSITIVE_FIELDS);

            if ($visibleFields !== []) {
                $exposedSensitiveFields = array_intersect($exposedSensitiveFields, $visibleFields);
            }

            if (! empty($exposedSensitiveFields)) {
                $issues[] = $this->createIssueWithSnippet(
                    message: "Model '{$modelName}' has sensitive fields in \$fillable but no \$hidden attributes",
                    filePath: $file,
                    lineNumber: $class->getLine(),
                    severity: Severity::Medium,
                    recommendation: 'Add the following sensitive fields to the hidden property to prevent them from appearing in JSON serialization: '.implode(', ', $exposedSensitiveFields).'.',
                    metadata: [
                        'model' => $modelName,
                        'issue_type' => 'missing_hidden_attributes',
                        'exposed_fields' => $exposedSensitiveFields,
                    ]
                );
            }
        }

        // Check if sensitive fields are missing from $hidden when they appear to be accessible
        // A $hidden property replaces the parent's list; a #[Hidden] attribute merges into it.
        if ($hasHidden && ! empty($hiddenFields)
            && ($inheritsModelDefaults || $this->declaresProperty($class, 'hidden'))) {
            foreach (self::SENSITIVE_FIELDS as $field) {
                // Skip if field is already hidden or guarded, or left out of a $visible allow-list
                if (in_array($field, $hiddenFields, true) || in_array($field, $guardedFields, true)
                    || ($visibleFields !== [] && ! in_array($field, $visibleFields, true))) {
                    continue;
                }

                // Check if field appears in fillable (most critical)
                if (in_array($field, $fillableFields, true)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: "Model '{$modelName}' has '{$field}' in \$fillable but doesn't hide it from JSON output",
                        filePath: $file,
                        lineNumber: $class->getLine(),
                        severity: Severity::Medium,
                        recommendation: "Add the {$field} field to the hidden property to prevent it from appearing in JSON serialization and API responses.",
                        metadata: [
                            'model' => $modelName,
                            'missing_field' => $field,
                            'issue_type' => 'fillable_field_not_hidden',
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check relationship security in Eloquent models.
     *
     * NOTE: This check is intentionally conservative to avoid false positives.
     * It only warns when there's evidence of actual mass assignment usage
     * with relationships in the codebase.
     *
     * @param  array<int, Issue>  &$issues
     */
    private function checkRelationshipSecurity(string $file, Node\Stmt\Class_ $class, array &$issues): void
    {
        // Skip this check for now - too noisy and relationship operations are checked separately
        // The checkRelationshipOperations method handles the actual dangerous patterns

    }

    /**
     * Check for dangerous relationship fill operations with request data.
     *
     * @param  array<int, Node>  $ast
     * @param  array<int, Issue>  &$issues
     */
    private function checkRelationshipOperations(string $file, array $ast, array &$issues): void
    {
        foreach (self::RELATIONSHIP_FILL_METHODS as $method) {
            $calls = $this->parser->findMethodCalls($ast, $method);

            foreach ($calls as $call) {
                if (! $call instanceof Node\Expr\MethodCall) {
                    continue;
                }

                if (empty($call->args)) {
                    continue;
                }

                // Check if any argument contains request data
                foreach ($call->args as $arg) {
                    if (! $arg instanceof Node\Arg) {
                        continue;
                    }

                    if ($this->containsRequestData($arg->value)) {
                        $issues[] = $this->createIssueWithSnippet(
                            message: "Relationship {$method}() with unfiltered request data",
                            filePath: $file,
                            lineNumber: $call->getLine(),
                            severity: Severity::High,
                            recommendation: 'Filter the request to only the expected fields before passing data to relationship methods. A FormRequest with validated data provides the strongest protection.',
                            metadata: [
                                'method' => $method,
                                'issue_type' => 'relationship_mass_assignment',
                            ]
                        );
                        break; // Only report once per call
                    }
                }
            }
        }
    }

    /**
     * Check for nested mass assignment patterns.
     *
     * Detects patterns like: $request->input('user.profile.bio')
     *
     * @param  array<int, Node>  $ast
     * @param  array<int, Issue>  &$issues
     */
    private function checkNestedMassAssignment(string $file, array $ast, array &$issues): void
    {
        // Find all method calls that accept data
        $dangerousMethods = array_merge(
            self::MODEL_STATIC_METHODS,
            self::MODEL_INSTANCE_METHODS
        );

        foreach ($dangerousMethods as $methodName) {
            $methodCalls = $this->parser->findMethodCalls($ast, $methodName);

            foreach ($methodCalls as $call) {
                if (! $call instanceof Node\Expr\MethodCall && ! $call instanceof Node\Expr\StaticCall) {
                    continue;
                }

                if (empty($call->args)) {
                    continue;
                }

                // First-class callable syntax (foo(...)) puts a VariadicPlaceholder
                // here instead of an Arg, which has no ->value.
                if (! $call->args[0] instanceof Node\Arg) {
                    continue;
                }

                $firstArg = $call->args[0]->value;

                // Check for nested request data patterns
                if ($this->hasNestedRequestData($firstArg)) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: 'Nested mass assignment detected - may expose relationship data unintentionally',
                        filePath: $file,
                        lineNumber: $call->getLine(),
                        severity: Severity::High,
                        recommendation: 'Explicitly define allowed nested attributes or use nested validation rules. Avoid dot notation in mass assignment',
                        metadata: [
                            'method' => $methodName,
                            'issue_type' => 'nested_mass_assignment',
                        ]
                    );
                }
            }
        }
    }

    /**
     * Check if a node contains nested request data (dot notation).
     */
    private function hasNestedRequestData(Node $node): bool
    {
        // Check for patterns like $request->input('user.profile')
        if ($node instanceof Node\Expr\MethodCall) {
            if ($node->var instanceof Node\Expr\Variable || $node->var instanceof Node\Expr\FuncCall) {
                if (! empty($node->args)) {
                    $argNode = $node->args[0];
                    $arg = $argNode instanceof Node\Arg ? $argNode->value : null;
                    if ($arg instanceof Node\Scalar\String_) {
                        // Check for dot notation indicating nested data
                        if (str_contains($arg->value, '.')) {
                            return true;
                        }
                    }
                }
            }
        }

        // Check for array access on request data with nested keys
        if ($node instanceof Node\Expr\ArrayDimFetch) {
            if ($this->containsRequestData($node->var)) {
                if ($node->dim instanceof Node\Scalar\String_ && str_contains($node->dim->value, '.')) {
                    return true;
                }
            }
        }

        // Recursively check subnodes
        foreach ($node->getSubNodeNames() as $name) {
            $subNode = $node->$name;
            if ($subNode instanceof Node && $this->hasNestedRequestData($subNode)) {
                return true;
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node && $this->hasNestedRequestData($item)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
