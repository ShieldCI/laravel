<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Support\Str;
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
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects mixing Query Builder and Eloquent for the same model.
 *
 * Checks for:
 * - Model::where() mixed with DB::table('models') for same model
 * - Inconsistent query approach across repository/service
 * - Global scopes bypassed by using Query Builder
 */
class MixedQueryBuilderEloquentAnalyzer extends AbstractFileAnalyzer
{
    /** @var array<string> Whitelisted classes allowed to mix Query Builder and Eloquent */
    private array $whitelist = [];

    /** @var bool Whether to treat toBase()/getQuery() as Query Builder usage */
    private bool $treatToBaseAsQueryBuilder = true;

    /** @var int Threshold for flagging significant mixing (count of Query Builder tables) */
    private int $mixingThreshold = 2;

    /** @var array<string, string|null> Model FQCN => table name (null means infer with Str::plural) */
    private array $tableRegistry = [];

    /** @var array<string> Directories to scan for models */
    private array $modelPaths = ['app/Models'];

    /** @var array<string, array<string, string|null>> Static cache: cacheKey => tableRegistry */
    private static array $tableRegistryCache = [];

    /** @var array<string, string|null> Child FQCN => Parent FQCN (for inheritance resolution) */
    private array $inheritanceMap = [];

    /** @var array<string, bool> Resolved models: FQCN => true if it's an Eloquent model */
    private array $resolvedModels = [];

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    /**
     * Set whitelisted classes (for testing).
     *
     * @param  array<string>  $whitelist
     */
    public function setWhitelist(array $whitelist): void
    {
        $this->whitelist = $whitelist;
    }

    /**
     * Clear the static table registry cache (for testing).
     */
    public static function clearRegistryCache(): void
    {
        self::$tableRegistryCache = [];
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'mixed-query-builder-eloquent',
            name: 'Mixed Query Builder and Eloquent Analyzer',
            description: 'Detects inconsistent mixing of Query Builder and Eloquent ORM in the same codebase',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['laravel', 'eloquent', 'query-builder', 'consistency'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/mixed-query-builder-eloquent',
            timeToFix: 30
        );
    }

    /**
     * Load configuration from config repository.
     */
    private function loadConfiguration(): void
    {
        // Default empty whitelist (no classes whitelisted by default)
        $defaultWhitelist = [];

        // Load from config
        $configWhitelist = $this->config->get('shieldci.analyzers.best-practices.mixed-query-builder-eloquent.whitelist', []);

        // Ensure configWhitelist is an array
        if (! is_array($configWhitelist)) {
            $configWhitelist = [];
        }

        // Merge config with defaults, ensuring no duplicates
        $this->whitelist = array_values(array_unique(array_merge($defaultWhitelist, $configWhitelist)));

        // Load toBase/getQuery configuration
        $treatToBaseConfig = $this->config->get('shieldci.analyzers.best-practices.mixed-query-builder-eloquent.treat_tobase_as_query_builder');
        if (is_bool($treatToBaseConfig)) {
            $this->treatToBaseAsQueryBuilder = $treatToBaseConfig;
        }

        // Load mixing threshold configuration
        $thresholdConfig = $this->config->get('shieldci.analyzers.best-practices.mixed-query-builder-eloquent.mixing_threshold');
        if (is_int($thresholdConfig) && $thresholdConfig >= 0) {
            $this->mixingThreshold = $thresholdConfig;
        }

        // Load model paths for scanning
        $modelPathsConfig = $this->config->get('shieldci.analyzers.best-practices.mixed-query-builder-eloquent.model_paths');
        if (is_array($modelPathsConfig) && count($modelPathsConfig) > 0) {
            $this->modelPaths = $modelPathsConfig;
        }

        // Load explicit table mappings (highest priority - overrides scanning)
        $tableMappings = $this->config->get('shieldci.analyzers.best-practices.mixed-query-builder-eloquent.table_mappings', []);
        if (is_array($tableMappings)) {
            foreach ($tableMappings as $modelClass => $tableName) {
                if (is_string($modelClass) && is_string($tableName)) {
                    $this->tableRegistry[ltrim($modelClass, '\\')] = $tableName;
                }
            }
        }
    }

    /**
     * Build table registry by scanning model directories.
     *
     * Uses a static cache keyed by basePath + modelPaths to avoid
     * rescanning the filesystem on every analysis run.
     *
     * This method uses multi-pass inheritance resolution to correctly
     * identify models that extend custom base classes (e.g., User extends BaseModel extends Model).
     */
    private function buildTableRegistry(): void
    {
        $cacheKey = md5($this->basePath.':'.implode(',', $this->modelPaths));

        if (isset(self::$tableRegistryCache[$cacheKey])) {
            // Merge cached registry (config mappings already loaded take precedence)
            $this->tableRegistry = array_merge(
                self::$tableRegistryCache[$cacheKey],
                $this->tableRegistry
            );

            return;
        }

        // Phase 1: Collect all class info (FQCN, parent, table)
        /** @var array<string, array{parent: string|null, table: string|null}> $classInfo */
        $classInfo = [];

        foreach ($this->modelPaths as $modelPath) {
            $fullPath = $this->basePath.'/'.$modelPath;
            if (! is_dir($fullPath)) {
                continue;
            }

            $this->scanModelDirectoryPhase1($fullPath, $classInfo);
        }

        // Phase 2: Build inheritance map
        $this->inheritanceMap = [];
        foreach ($classInfo as $fqcn => $info) {
            $this->inheritanceMap[$fqcn] = $info['parent'];
        }

        // Phase 3: Resolve which classes are Eloquent models
        $this->resolveEloquentModels();

        // Phase 4: Build table registry from resolved models
        /** @var array<string, string|null> $scannedRegistry */
        $scannedRegistry = [];

        foreach ($classInfo as $fqcn => $info) {
            if (isset($this->resolvedModels[$fqcn])) {
                $scannedRegistry[$fqcn] = $info['table'];
            }
        }

        self::$tableRegistryCache[$cacheKey] = $scannedRegistry;
        $this->tableRegistry = array_merge($scannedRegistry, $this->tableRegistry);
    }

    /**
     * Recursively scan a directory for PHP files and collect class info.
     *
     * @param  array<string, array{parent: string|null, table: string|null}>  $classInfo
     */
    private function scanModelDirectoryPhase1(string $directory, array &$classInfo): void
    {
        $items = scandir($directory);
        if ($items === false) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $path = $directory.'/'.$item;

            if (is_dir($path)) {
                $this->scanModelDirectoryPhase1($path, $classInfo);
            } elseif (str_ends_with($item, '.php')) {
                $this->extractClassInfo($path, $classInfo);
            }
        }
    }

    /**
     * Extract class information (FQCN, parent, table) from a PHP file.
     *
     * @param  array<string, array{parent: string|null, table: string|null}>  $classInfo
     */
    private function extractClassInfo(string $file, array &$classInfo): void
    {
        try {
            $ast = $this->parser->parseFile($file);
            if (empty($ast)) {
                return;
            }

            $traverser = new NodeTraverser;
            $traverser->addVisitor(new NameResolver);
            $visitor = new TableExtractorVisitor;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            $fqcn = $visitor->getRawClassName();
            if ($fqcn === null) {
                return;
            }

            $classInfo[$fqcn] = [
                'parent' => $visitor->getParentClassName(),
                'table' => $visitor->getTableName(),
            ];
        } catch (\Throwable) {
            // Skip files with parse errors
        }
    }

    /**
     * Resolve which classes are Eloquent models using inheritance chain resolution.
     *
     * This method iteratively resolves inheritance chains to handle patterns like:
     * - User extends BaseModel extends Model
     * - TenantUser extends TenantModel extends BaseModel extends Model
     */
    private function resolveEloquentModels(): void
    {
        $this->resolvedModels = [];

        // Known Eloquent base classes (fully qualified)
        $eloquentBases = [
            'Illuminate\\Database\\Eloquent\\Model',
            'Illuminate\\Foundation\\Auth\\User',
            'Illuminate\\Database\\Eloquent\\Relations\\Pivot',
            'Illuminate\\Database\\Eloquent\\Relations\\MorphPivot',
        ];

        // Mark known bases as models
        foreach ($eloquentBases as $base) {
            $this->resolvedModels[$base] = true;
        }

        // Iteratively resolve inheritance chains
        // Continue until no new models are discovered
        $changed = true;
        $maxIterations = 100; // Safety limit for potential cycles
        $iteration = 0;

        while ($changed && $iteration < $maxIterations) {
            $changed = false;
            $iteration++;

            foreach ($this->inheritanceMap as $class => $parent) {
                // Skip if already resolved
                if (isset($this->resolvedModels[$class])) {
                    continue;
                }

                if ($parent === null) {
                    continue;
                }

                // Check if parent is a known model (resolved or base)
                if (isset($this->resolvedModels[$parent])) {
                    $this->resolvedModels[$class] = true;
                    $changed = true;

                    continue;
                }

                // Check if parent matches a known Eloquent base pattern
                if ($this->matchesEloquentBase($parent)) {
                    $this->resolvedModels[$class] = true;
                    $changed = true;
                }
            }
        }
    }

    /**
     * Check if a class name matches a known Eloquent base class pattern.
     */
    private function matchesEloquentBase(string $className): bool
    {
        $normalized = ltrim($className, '\\');

        // Direct Eloquent Model
        if ($normalized === 'Model' || str_ends_with($normalized, '\\Model')) {
            return true;
        }

        // Common Laravel model base classes
        $baseModels = ['Authenticatable', 'Pivot', 'MorphPivot'];
        foreach ($baseModels as $base) {
            if ($normalized === $base || str_ends_with($normalized, '\\'.$base)) {
                return true;
            }
        }

        return false;
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration
        $this->loadConfiguration();

        // Build table registry by scanning models
        $this->buildTableRegistry();

        $issues = [];

        // Only set default paths if not already set (allows tests to override)
        if (empty($this->paths)) {
            $this->setBasePath(base_path());
            $this->setPaths(['app/Repositories', 'app/Services', 'app/Http/Controllers']);
        }

        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new MixedQueryVisitor(
                    $this->whitelist,
                    $this->treatToBaseAsQueryBuilder,
                    $this->mixingThreshold,
                    $this->tableRegistry
                );
                $traverser = new NodeTraverser;
                $traverser->addVisitor(new NameResolver);
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssue(
                        message: $issue['message'],
                        location: new Location($this->getRelativePath($file), $issue['line']),
                        severity: $issue['severity'],
                        recommendation: $issue['recommendation'],
                        code: $issue['code'] ?? null,
                    );
                }
            } catch (\Throwable $e) {
                // Skip files with parse errors
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('Consistent use of Eloquent or Query Builder');
        }

        return $this->failed(
            sprintf('Found %d file(s) mixing Query Builder and Eloquent inconsistently', count($issues)),
            $issues
        );
    }
}

/**
 * Visitor to detect mixed query approaches.
 */
class MixedQueryVisitor extends NodeVisitorAbstract
{
    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    /** @var array<string, array{type: string, line: int}> */
    private array $tableUsage = [];

    /** @var array<string> Whitelisted classes */
    private array $whitelist = [];

    /** @var bool Whether to treat toBase()/getQuery() as Query Builder usage */
    private bool $treatToBaseAsQueryBuilder;

    /** @var int Threshold for flagging significant mixing */
    private int $mixingThreshold;

    /** @var array<string, string|null> Model FQCN => table name (null means infer with Str::plural) */
    private array $tableRegistry = [];

    /** @var array<string, string> Track variable assignments to models/QB ($varName => modelClass) */
    private array $variableTracking = [];

    private ?string $currentClassName = null;

    private bool $currentClassSuppressed = false;

    /**
     * @param  array<string>  $whitelist
     * @param  array<string, string|null>  $tableRegistry
     */
    public function __construct(
        array $whitelist = [],
        bool $treatToBaseAsQueryBuilder = true,
        int $mixingThreshold = 2,
        array $tableRegistry = []
    ) {
        $this->whitelist = $whitelist;
        $this->treatToBaseAsQueryBuilder = $treatToBaseAsQueryBuilder;
        $this->mixingThreshold = $mixingThreshold;
        $this->tableRegistry = $tableRegistry;
    }

    public function enterNode(Node $node): ?Node
    {
        // Track current class
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClassName = $node->name?->toString();
            $this->currentClassSuppressed = $this->hasSuppressionComment($node);
        }

        // Reset variable tracking at method boundaries for proper scoping
        if ($node instanceof Node\Stmt\ClassMethod) {
            $this->variableTracking = [];
        }

        // Detect DB::table() calls
        // After NameResolver, DB may be resolved to Illuminate\Support\Facades\DB
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name && $this->isDbFacade($node->class)) {
                if ($node->name instanceof Node\Identifier && $node->name->toString() === 'table') {
                    $this->trackDbTableCall($node);
                }
            }

            // Detect Model::where/find/etc calls
            if ($node->class instanceof Node\Name) {
                if ($this->looksLikeModel($node->class)) {
                    $className = $node->class->toString();
                    if ($node->name instanceof Node\Identifier) {
                        $method = $node->name->toString();

                        // P2.10: Detect QB-via-model patterns (toBase, getQuery) - configurable
                        if ($this->treatToBaseAsQueryBuilder && in_array($method, ['toBase', 'getQuery'], true)) {
                            $tableName = $this->modelToTableName($className);
                            $this->tableUsage[$tableName] = [
                                'type' => 'query_builder',
                                'line' => $node->getLine(),
                            ];

                            return null;
                        }

                        // Skip 'query' method as it's just a builder starter, not actual Eloquent usage
                        if ($method === 'query') {
                            return null;
                        }

                        $eloquentMethods = [
                            // Query methods
                            'where', 'orWhere', 'whereIn', 'whereNotIn', 'whereBetween',
                            'whereNull', 'whereNotNull', 'whereDate', 'whereTime',
                            'whereColumn', 'whereExists', 'whereHas', 'whereDoesntHave',
                            'whereRaw', 'orWhereRaw',
                            // Retrieval methods
                            'find', 'findOrFail', 'findMany', 'findOr',
                            'first', 'firstOrFail', 'firstOr', 'firstWhere',
                            'get', 'all', 'cursor', 'lazy', 'lazyById',
                            'value', 'pluck', 'sole',
                            // Aggregate methods
                            'count', 'sum', 'avg', 'average', 'min', 'max',
                            'exists', 'doesntExist',
                            // Insert/Update methods
                            'create', 'insert', 'insertGetId', 'insertOrIgnore', 'insertUsing',
                            'update', 'updateOrCreate', 'updateOrInsert', 'upsert',
                            'firstOrCreate', 'firstOrNew',
                            // Delete methods
                            'delete', 'destroy', 'forceDelete', 'restore',
                            // Other query methods
                            'latest', 'oldest', 'orderBy', 'reorder',
                            'limit', 'take', 'skip', 'offset',
                            'with', 'withCount', 'withSum', 'withAvg', 'withMin', 'withMax',
                            'without', 'withOnly', 'withTrashed', 'onlyTrashed',
                            'select', 'selectRaw', 'addSelect',
                            'join', 'leftJoin', 'rightJoin', 'crossJoin',
                            'having', 'havingRaw', 'orHaving',
                            'groupBy', 'distinct',
                            'chunk', 'chunkById', 'each', 'chunkMap',
                            'when', 'unless', 'tap',
                        ];
                        if (in_array($method, $eloquentMethods, true)) {
                            $this->trackEloquentCall($className, $node->getLine());
                        }
                    }
                }
            }
        }

        // P2.8: Detect relationship query patterns ($user->posts()->where())
        if ($node instanceof Node\Expr\MethodCall) {
            // Note: toBase()/getQuery() detection moved to leaveNode() so that
            // NameResolver has processed all child nodes first

            // P3.11: Check if method is called on a tracked variable ($query->get())
            if ($node->var instanceof Node\Expr\Variable && is_string($node->var->name)) {
                $varName = $node->var->name;
                if (isset($this->variableTracking[$varName])) {
                    $modelClass = $this->variableTracking[$varName];
                    if ($node->name instanceof Node\Identifier) {
                        $method = $node->name->toString();
                        $eloquentMethods = ['where', 'get', 'first', 'count', 'update', 'delete', 'find'];
                        if (in_array($method, $eloquentMethods, true)) {
                            $this->trackEloquentCall($modelClass, $node->getLine());
                        }
                    }
                }
            }

            // Note: Relationship chain detection ($user->posts()->where()) removed due to
            // high false positive rate. Without proper type inference, we cannot reliably
            // determine if a method call chain represents a relationship query.
        }

        // P3.11: Track variable assignments ($query = User::where(...))
        if ($node instanceof Node\Expr\Assign) {
            if ($node->var instanceof Node\Expr\Variable && is_string($node->var->name)) {
                // Check if RHS is a static call to a model
                if ($node->expr instanceof Node\Expr\StaticCall) {
                    if ($node->expr->class instanceof Node\Name) {
                        if ($this->looksLikeModel($node->expr->class)) {
                            // Track this variable as being associated with this model
                            $this->variableTracking[$node->var->name] = $node->expr->class->toString();
                        }
                    }
                }
            }
        }

        // P3.12: Detect dynamic model references ($modelClass::where())
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Expr\Variable && is_string($node->class->name)) {
                // This is a dynamic static call like $modelClass::where()
                $varName = $node->class->name;
                if (isset($this->variableTracking[$varName])) {
                    $modelClass = $this->variableTracking[$varName];
                    if ($node->name instanceof Node\Identifier) {
                        $method = $node->name->toString();
                        $eloquentMethods = ['where', 'find', 'all', 'get', 'first', 'create', 'update'];
                        if (in_array($method, $eloquentMethods, true)) {
                            $this->trackEloquentCall($modelClass, $node->getLine());
                        }
                    }
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node): ?Node
    {
        // P2.10: Detect toBase() or getQuery() on model method calls (User::query()->toBase())
        // We use leaveNode so that NameResolver has already processed all child nodes
        if ($node instanceof Node\Expr\MethodCall) {
            if ($this->treatToBaseAsQueryBuilder && $node->name instanceof Node\Identifier) {
                $method = $node->name->toString();
                if (in_array($method, ['toBase', 'getQuery'], true)) {
                    // Walk up method chain to find the root static call (e.g., User::query()->where()->toBase())
                    $rootStaticCall = $this->findRootStaticCall($node->var);
                    if ($rootStaticCall !== null && $rootStaticCall->class instanceof Node\Name) {
                        if ($this->looksLikeModel($rootStaticCall->class)) {
                            $className = $rootStaticCall->class->toString();
                            $tableName = $this->modelToTableName($className);

                            // Check if table already tracked as eloquent
                            if (isset($this->tableUsage[$tableName]) && $this->tableUsage[$tableName]['type'] === 'eloquent') {
                                // Mark as mixed
                                $this->tableUsage[$tableName]['type'] = 'mixed';
                            } else {
                                $this->tableUsage[$tableName] = [
                                    'type' => 'query_builder',
                                    'line' => $node->getLine(),
                                ];
                            }
                        }
                    }
                }
            }
        }

        // When leaving a class, check for mixed usage
        if ($node instanceof Node\Stmt\Class_) {
            // Skip check if class is suppressed or whitelisted
            $isWhitelisted = $this->currentClassName && in_array($this->currentClassName, $this->whitelist, true);

            if (! $this->currentClassSuppressed && ! $isWhitelisted) {
                $this->checkMixedUsage();
            }
            $this->tableUsage = []; // Reset for next class
            $this->variableTracking = []; // Reset variable tracking
            $this->currentClassSuppressed = false;
        }

        return null;
    }

    /**
     * @return array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }

    private function trackDbTableCall(Node\Expr\StaticCall $node): void
    {
        if (empty($node->args)) {
            return;
        }

        $arg = $node->args[0];
        if ($arg->value instanceof Node\Scalar\String_) {
            $tableName = $arg->value->value;
            $tableName = explode(' ', $tableName)[0];
            // Check if table already tracked as eloquent
            if (isset($this->tableUsage[$tableName]) && $this->tableUsage[$tableName]['type'] === 'eloquent') {
                // Mark as mixed by changing type
                $this->tableUsage[$tableName]['type'] = 'mixed';
            } else {
                $this->tableUsage[$tableName] = [
                    'type' => 'query_builder',
                    'line' => $node->getLine(),
                ];
            }
        }
    }

    private function trackEloquentCall(string $modelName, int $line): void
    {
        $tableName = $this->modelToTableName($modelName);

        if (! isset($this->tableUsage[$tableName])) {
            $this->tableUsage[$tableName] = [
                'type' => 'eloquent',
                'line' => $line,
            ];
        } elseif ($this->tableUsage[$tableName]['type'] === 'query_builder') {
            // Mark as mixed
            $this->tableUsage[$tableName]['type'] = 'mixed';
        }
        // If already eloquent or mixed, do nothing
    }

    private function checkMixedUsage(): void
    {
        $eloquentTables = [];
        $queryBuilderTables = [];
        $mixedTables = [];

        foreach ($this->tableUsage as $table => $usage) {
            if ($usage['type'] === 'eloquent') {
                $eloquentTables[$table] = $usage['line'];
            } elseif ($usage['type'] === 'mixed') {
                $mixedTables[$table] = $usage;
            } else {
                $queryBuilderTables[$table] = $usage['line'];
            }
        }

        // Report tables marked as mixed (used with both Eloquent and Query Builder)
        foreach ($mixedTables as $table => $usage) {
            $this->issues[] = [
                'message' => sprintf(
                    'Class "%s" uses both Eloquent and Query Builder for table "%s"',
                    $this->currentClassName ?? 'Unknown',
                    $table
                ),
                'line' => $usage['line'],
                'severity' => Severity::High,
                'recommendation' => 'Mixing Eloquent and Query Builder for the same table may bypass global scopes (soft deletes, tenant isolation), model events, and attribute casts. If this model uses scopes or events, use Eloquent consistently.',
                'code' => null,
            ];
        }

        // Also check if class has significant use of both (even on different tables)
        // Only count Query Builder tables that have corresponding models (excludes system tables like jobs, cache, sessions)
        $modeledQbTables = array_filter(
            array_keys($queryBuilderTables),
            fn (string $table): bool => $this->tableHasModel($table)
        );

        if (count($eloquentTables) > 0 && count($modeledQbTables) > $this->mixingThreshold) {
            $firstQbLine = min($queryBuilderTables);
            $this->issues[] = [
                'message' => sprintf(
                    'Class "%s" mixes Eloquent and Query Builder approaches (%d Eloquent, %d Query Builder)',
                    $this->currentClassName ?? 'Unknown',
                    count($eloquentTables),
                    count($modeledQbTables)
                ),
                'line' => $firstQbLine,
                'severity' => Severity::Low,
                'recommendation' => 'Consider using a consistent approach throughout the class. If using Eloquent elsewhere, continue with Eloquent for consistency',
                'code' => null,
            ];
        }
    }

    /**
     * Check if a table name has a corresponding model in the registry.
     *
     * This helps distinguish business tables (users, posts) from system tables
     * (jobs, cache, sessions) that legitimately use Query Builder.
     */
    private function tableHasModel(string $tableName): bool
    {
        foreach ($this->tableRegistry as $modelFqcn => $table) {
            // Get the inferred table name (use explicit $table property or Str::plural inference)
            $inferredTable = $table ?? Str::plural(Str::snake(class_basename($modelFqcn)));
            if ($inferredTable === $tableName) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a class has suppression comment.
     */
    private function hasSuppressionComment(Node\Stmt\Class_ $classNode): bool
    {
        $docComment = $classNode->getDocComment();
        if (! $docComment) {
            return false;
        }

        $commentText = $docComment->getText();

        // Check for general suppression or specific analyzer suppression
        if (preg_match('/@shieldci-ignore\s+(mixed-query-builder-eloquent|all)/i', $commentText)) {
            return true;
        }

        // Check for general @shieldci-ignore without specific analyzer
        if (preg_match('/@shieldci-ignore\s*$/m', $commentText)) {
            return true;
        }

        return false;
    }

    /**
     * Check if a class name represents the DB facade.
     *
     * After NameResolver runs, DB may be resolved to Illuminate\Support\Facades\DB.
     */
    private function isDbFacade(Node\Name $name): bool
    {
        $fqn = $name->toString();
        $normalized = ltrim($fqn, '\\');

        // Check for short name (when no use statement) or fully qualified name
        return $normalized === 'DB'
            || $normalized === 'Illuminate\\Support\\Facades\\DB';
    }

    /**
     * Determine if a class name likely represents an Eloquent model.
     *
     * Uses positive matching (checks if it IS a model) instead of negative matching
     * (excluding non-models). This reduces false positives for Controllers, Services, etc.
     */
    private function looksLikeModel(Node\Name $name): bool
    {
        // After NameResolver runs, the name is already fully qualified
        // NameResolver replaces Name nodes with FullyQualified nodes directly
        $fqn = $name->toString();
        $normalized = ltrim($fqn, '\\');

        // Extract short class name
        $parts = explode('\\', $normalized);
        $shortName = end($parts);

        // Quick rejection: known non-model classes (facades, utilities)
        $excludedClasses = [
            'DB', 'Cache', 'Log', 'Event', 'Mail', 'Queue',
            'Route', 'Artisan', 'Config', 'Session', 'Request',
            'Response', 'Validator', 'Hash', 'Auth', 'Gate',
            'Storage', 'File', 'View', 'Redirect', 'URL',
            'Factory', 'Builder', 'Collection', 'Carbon', 'Str', 'Arr',
            'Schema', 'Blueprint', 'Migration', 'Seeder', 'Console',
            'Bus', 'Notification', 'Broadcast', 'Password', 'RateLimiter',
            'Http', 'Process', 'Pipeline', 'Container', 'App',
        ];

        if (in_array($shortName, $excludedClasses, true)) {
            return false;
        }

        // POSITIVE CHECK 0: Class exists in table registry (scanned or configured)
        // Use array_key_exists because null values (models without $table property) are valid
        if (array_key_exists($normalized, $this->tableRegistry)) {
            return true;
        }

        // POSITIVE CHECK 1: Model namespace patterns
        if (str_starts_with($normalized, 'App\\Models\\') ||
            str_starts_with($normalized, 'App\\Model\\')) {
            return true;
        }

        // POSITIVE CHECK 2: Domain-driven patterns (e.g., Domain\Users\Models\User)
        if (str_contains($normalized, '\\Models\\')) {
            return true;
        }

        // POSITIVE CHECK 3: Class name ends with "Model" suffix
        if (str_ends_with($shortName, 'Model')) {
            return true;
        }

        // Cannot determine from namespace - assume NOT a model
        // This is the key change: default to false instead of true
        return false;
    }

    /**
     * Walk up method call chain to find the root static call.
     *
     * For User::query()->where()->toBase(), this finds the User::query() StaticCall.
     */
    private function findRootStaticCall(Node\Expr $expr): ?Node\Expr\StaticCall
    {
        while ($expr instanceof Node\Expr\MethodCall) {
            $expr = $expr->var;
        }

        return $expr instanceof Node\Expr\StaticCall ? $expr : null;
    }

    /**
     * Convert model class name to table name.
     *
     * Uses table registry first (from scanned models and config overrides),
     * then falls back to Laravel's Str::plural() for accurate inference.
     */
    private function modelToTableName(string $modelName): string
    {
        $normalized = ltrim($modelName, '\\');

        // 1. Check registry first (includes config overrides + scanned models)
        if (array_key_exists($normalized, $this->tableRegistry)) {
            $table = $this->tableRegistry[$normalized];
            if ($table !== null) {
                return $table;
            }
        }

        // 2. Fallback: Use Str::plural() for Laravel-accurate inference
        $parts = explode('\\', $normalized);
        $className = end($parts);

        return Str::plural(Str::snake($className));
    }
}

/**
 * Visitor to extract $table property from model files.
 */
class TableExtractorVisitor extends NodeVisitorAbstract
{
    private ?string $className = null;

    private ?string $namespace = null;

    private ?string $tableName = null;

    private ?string $parentClass = null;

    public function enterNode(Node $node): ?Node
    {
        if ($node instanceof Node\Stmt\Namespace_) {
            $this->namespace = $node->name?->toString();
        }

        if ($node instanceof Node\Stmt\Class_) {
            $this->className = $node->name?->toString();
            $this->parentClass = $node->extends?->toString();
        }

        // Look for: protected $table = 'table_name';
        if ($node instanceof Node\Stmt\Property) {
            foreach ($node->props as $prop) {
                if ($prop->name->toString() === 'table') {
                    if ($prop->default instanceof Node\Scalar\String_) {
                        $this->tableName = $prop->default->value;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Get fully qualified class name only if it directly extends a known Eloquent base.
     *
     * @deprecated Use getRawClassName() and let the analyzer resolve inheritance.
     */
    public function getClassName(): ?string
    {
        if (! $this->className || ! $this->isEloquentModel()) {
            return null;
        }

        return $this->namespace
            ? $this->namespace.'\\'.$this->className
            : $this->className;
    }

    /**
     * Get fully qualified class name regardless of parent class.
     *
     * This method returns the FQCN without checking if it's a model,
     * allowing the caller to determine model status via inheritance resolution.
     */
    public function getRawClassName(): ?string
    {
        if (! $this->className) {
            return null;
        }

        return $this->namespace
            ? $this->namespace.'\\'.$this->className
            : $this->className;
    }

    /**
     * Get the fully qualified parent class name.
     *
     * Resolves the parent class to FQCN using the same namespace if not qualified.
     */
    public function getParentClassName(): ?string
    {
        if ($this->parentClass === null || $this->className === null) {
            return null;
        }

        $normalized = ltrim($this->parentClass, '\\');

        // If already fully qualified (contains backslash), use as-is
        if (str_contains($normalized, '\\')) {
            return $normalized;
        }

        // Otherwise, assume same namespace as current class
        return $this->namespace
            ? $this->namespace.'\\'.$normalized
            : $normalized;
    }

    public function getTableName(): ?string
    {
        return $this->tableName;
    }

    /**
     * Check if the class directly extends a known Eloquent model base.
     *
     * Note: This method only checks direct inheritance. For resolving
     * custom base classes (e.g., User extends BaseModel extends Model),
     * use the multi-pass resolution in MixedQueryBuilderEloquentAnalyzer.
     */
    private function isEloquentModel(): bool
    {
        if ($this->parentClass === null) {
            return false;
        }

        $normalized = ltrim($this->parentClass, '\\');

        // Direct Eloquent Model
        if ($normalized === 'Model' || str_ends_with($normalized, '\\Model')) {
            return true;
        }

        // Common Laravel model base classes
        $baseModels = ['Authenticatable', 'Pivot', 'MorphPivot'];
        foreach ($baseModels as $base) {
            if ($normalized === $base || str_ends_with($normalized, '\\'.$base)) {
                return true;
            }
        }

        return false;
    }
}
