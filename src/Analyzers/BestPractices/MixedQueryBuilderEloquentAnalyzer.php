<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use PhpParser\NodeTraverser;
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
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration
        $this->loadConfiguration();

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
                    $this->mixingThreshold
                );
                $traverser = new NodeTraverser;
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

    /** @var array<string, string> Cache of model class -> custom table name */
    private array $customTableNames = [];

    /** @var array<string> Whitelisted classes */
    private array $whitelist = [];

    /** @var bool Whether to treat toBase()/getQuery() as Query Builder usage */
    private bool $treatToBaseAsQueryBuilder;

    /** @var int Threshold for flagging significant mixing */
    private int $mixingThreshold;

    /** @var array<string, string> Track variable assignments to models/QB ($varName => modelClass) */
    private array $variableTracking = [];

    private ?string $currentClassName = null;

    private bool $currentClassSuppressed = false;

    /**
     * @param  array<string>  $whitelist
     */
    public function __construct(
        array $whitelist = [],
        bool $treatToBaseAsQueryBuilder = true,
        int $mixingThreshold = 2
    ) {
        $this->whitelist = $whitelist;
        $this->treatToBaseAsQueryBuilder = $treatToBaseAsQueryBuilder;
        $this->mixingThreshold = $mixingThreshold;
    }

    public function enterNode(Node $node): ?Node
    {
        // Track current class
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClassName = $node->name?->toString();
            $this->currentClassSuppressed = $this->hasSuppressionComment($node);
            $this->extractCustomTableName($node);
        }

        // Reset variable tracking at method boundaries for proper scoping
        if ($node instanceof Node\Stmt\ClassMethod) {
            $this->variableTracking = [];
        }

        // Detect DB::table() calls
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name && $node->class->toString() === 'DB') {
                if ($node->name instanceof Node\Identifier && $node->name->toString() === 'table') {
                    $this->trackDbTableCall($node);
                }
            }

            // Detect Model::where/find/etc calls
            if ($node->class instanceof Node\Name) {
                $className = $node->class->toString();
                if ($this->looksLikeModel($className)) {
                    if ($node->name instanceof Node\Identifier) {
                        $method = $node->name->toString();

                        // P2.10: Detect QB-via-model patterns (toBase, getQuery) - configurable
                        if ($this->treatToBaseAsQueryBuilder && in_array($method, ['toBase', 'getQuery'], true)) {
                            $tableName = $this->customTableNames[$className] ?? $this->modelToTableName($className);
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
            // P2.10: Detect toBase() or getQuery() on model method calls (User::query()->toBase()) - configurable
            if ($this->treatToBaseAsQueryBuilder && $node->name instanceof Node\Identifier) {
                $method = $node->name->toString();
                if (in_array($method, ['toBase', 'getQuery'], true)) {
                    // Check if this is called on a static call to a model
                    if ($node->var instanceof Node\Expr\StaticCall) {
                        if ($node->var->class instanceof Node\Name) {
                            $className = $node->var->class->toString();
                            if ($this->looksLikeModel($className)) {
                                $tableName = $this->customTableNames[$className] ?? $this->modelToTableName($className);

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
                        $className = $node->expr->class->toString();
                        if ($this->looksLikeModel($className)) {
                            // Track this variable as being associated with this model
                            $this->variableTracking[$node->var->name] = $className;
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
        // Check if model has custom table name
        $tableName = $this->customTableNames[$modelName] ?? $this->modelToTableName($modelName);

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
                'recommendation' => 'CRITICAL: Mixing Eloquent and Query Builder for the same table bypasses global scopes (tenant isolation, soft deletes, published status), relationships, and model events. This can cause data leaks in multi-tenant applications and break business logic. Use Eloquent consistently for this model.',
                'code' => null,
            ];
        }

        // Also check if class has significant use of both (even on different tables)
        if (count($eloquentTables) > 0 && count($queryBuilderTables) > $this->mixingThreshold) {
            $firstQbLine = min($queryBuilderTables);
            $this->issues[] = [
                'message' => sprintf(
                    'Class "%s" mixes Eloquent and Query Builder approaches (%d Eloquent, %d Query Builder)',
                    $this->currentClassName ?? 'Unknown',
                    count($eloquentTables),
                    count($queryBuilderTables)
                ),
                'line' => $firstQbLine,
                'severity' => Severity::Low,
                'recommendation' => 'Consider using a consistent approach throughout the class. If using Eloquent elsewhere, continue with Eloquent for consistency',
                'code' => null,
            ];
        }
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
     * Extract custom table name from Model class if defined.
     */
    private function extractCustomTableName(Node\Stmt\Class_ $classNode): void
    {
        if (! $this->currentClassName) {
            return;
        }

        // Check if class extends Model
        if (! $this->extendsModel($classNode)) {
            return;
        }

        // Look for protected $table property
        foreach ($classNode->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Property) {
                foreach ($stmt->props as $prop) {
                    if ($prop->name->toString() === 'table') {
                        // Extract the table name value
                        if ($prop->default instanceof Node\Scalar\String_) {
                            $this->customTableNames[$this->currentClassName] = $prop->default->value;
                        }
                    }
                }
            }
        }
    }

    /**
     * Check if a class extends Model (directly or indirectly).
     */
    private function extendsModel(Node\Stmt\Class_ $classNode): bool
    {
        if (! $classNode->extends) {
            return false;
        }

        $parentClass = $classNode->extends->toString();

        // Check common Model parent classes
        $modelParents = [
            'Model',
            'Eloquent',
            'Illuminate\Database\Eloquent\Model',
            '\Illuminate\Database\Eloquent\Model',
        ];

        foreach ($modelParents as $modelParent) {
            if (str_ends_with($parentClass, $modelParent)) {
                return true;
            }
        }

        return false;
    }

    private function looksLikeModel(string $className): bool
    {
        // Simple heuristic: capitalized single word or namespaced class
        // that looks like a model name
        $parts = explode('\\', $className);
        $lastPart = end($parts);

        // Model names are typically capitalized
        if (! ctype_upper($lastPart[0] ?? '')) {
            return false;
        }

        // Exclude common non-model classes (facades, utilities, framework classes)
        $excludedClasses = [
            // Laravel Facades
            'DB', 'Cache', 'Log', 'Event', 'Mail', 'Queue',
            'Route', 'Artisan', 'Config', 'Session', 'Request',
            'Response', 'Validator', 'Hash', 'Auth', 'Gate',
            'Storage', 'File', 'View', 'Redirect', 'URL',
            // Common utility classes
            'Factory', 'Builder', 'Collection', 'Carbon', 'Str', 'Arr',
            // Database/Migration classes
            'Schema', 'Blueprint', 'Migration', 'Seeder', 'Console',
            // Additional Laravel classes
            'Bus', 'Notification', 'Broadcast', 'Password', 'RateLimiter',
            'Http', 'Process', 'Pipeline', 'Container', 'App',
            // Architecture patterns (often suffixed)
            'Facade', 'ServiceProvider', 'Manager', 'Repository',
            'Service', 'Helper', 'Util', 'Utils', 'Helpers',
            // Testing
            'TestCase', 'Feature', 'Unit',
        ];

        return ! in_array($lastPart, $excludedClasses, true);
    }

    private function modelToTableName(string $modelName): string
    {
        $parts = explode('\\', $modelName);
        $className = end($parts);

        // Convert PascalCase to snake_case
        $snakeCase = strtolower(preg_replace('/(?<!^)[A-Z]/', '_$0', $className) ?? $className);

        // Handle irregular plurals (common Laravel model names)
        $irregulars = [
            'person' => 'people',
            'child' => 'children',
            'man' => 'men',
            'woman' => 'women',
            'tooth' => 'teeth',
            'foot' => 'feet',
            'mouse' => 'mice',
            'goose' => 'geese',
        ];

        if (isset($irregulars[$snakeCase])) {
            return $irregulars[$snakeCase];
        }

        // Words that don't change in plural form
        $uncountable = ['equipment', 'information', 'rice', 'money', 'species', 'series', 'fish', 'sheep', 'deer'];
        if (in_array($snakeCase, $uncountable, true)) {
            return $snakeCase;
        }

        // Handle words ending in 'y' (but not vowel + y)
        if (str_ends_with($snakeCase, 'y') && ! preg_match('/[aeiou]y$/', $snakeCase)) {
            return substr($snakeCase, 0, -1).'ies';
        }

        // Handle words ending in 's', 'ss', 'sh', 'ch', 'x', 'z', 'o'
        if (preg_match('/(s|ss|sh|ch|x|z)$/', $snakeCase)) {
            return $snakeCase.'es';
        }

        if (str_ends_with($snakeCase, 'o') && ! preg_match('/[aeiou]o$/', $snakeCase)) {
            return $snakeCase.'es';
        }

        // Handle words ending in 'f' or 'fe'
        if (str_ends_with($snakeCase, 'f')) {
            return substr($snakeCase, 0, -1).'ves';
        }

        if (str_ends_with($snakeCase, 'fe')) {
            return substr($snakeCase, 0, -2).'ves';
        }

        // Default: add 's'
        return $snakeCase.'s';
    }
}
