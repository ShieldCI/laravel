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

/**
 * Detects models with too much business logic (fat models).
 *
 * Checks for:
 * - Models with excessive public methods (> 15 excluding scopes, relations, accessors/mutators)
 * - Models with high lines of code (> 300)
 * - Methods with high complexity (> 10)
 */
class FatModelAnalyzer extends AbstractFileAnalyzer
{
    public const METHOD_THRESHOLD = 15;

    public const LOC_THRESHOLD = 300;

    public const COMPLEXITY_THRESHOLD = 10;

    private int $methodThreshold;

    private int $locThreshold;

    private int $complexityThreshold;

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'fat-model',
            name: 'Fat Model Analyzer',
            description: 'Detects Eloquent models with too much business logic that should be extracted to services',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['laravel', 'eloquent', 'architecture', 'solid', 'srp'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/fat-model',
            timeToFix: 45
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration from config file (best-practices.fat-model)
        $analyzerConfig = $this->config->get('shieldci.analyzers.best-practices.fat-model', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->methodThreshold = $analyzerConfig['method_threshold'] ?? self::METHOD_THRESHOLD;
        $this->locThreshold = $analyzerConfig['loc_threshold'] ?? self::LOC_THRESHOLD;
        $this->complexityThreshold = $analyzerConfig['complexity_threshold'] ?? self::COMPLEXITY_THRESHOLD;

        $issues = [];

        // Only set default paths if not already set (allows tests to override)
        if (empty($this->paths)) {
            $this->setBasePath(base_path());
            $this->setPaths(['app/Models']);
        }

        $modelFiles = $this->getPhpFiles();
        $affectedModels = [];

        foreach ($modelFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                // Extract use statements for alias resolution
                $useStatements = $this->extractUseStatements($ast);

                $visitor = new FatModelVisitor($this->methodThreshold, $this->locThreshold, $this->complexityThreshold, $useStatements);
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: $issue['message'],
                        filePath: $file,
                        lineNumber: $issue['line'],
                        severity: $issue['severity'],
                        recommendation: $issue['recommendation'],
                        code: $issue['code'] ?? null,
                    );
                    $affectedModels[$file] = true;
                }
            } catch (\Throwable $e) {
                // Skip files with parse errors
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('All models have appropriate size and complexity');
        }

        return $this->failed(
            sprintf(
                'Found %d issue(s) across %d fat model(s) that should be refactored',
                count($issues),
                count($affectedModels)
            ),
            $issues
        );
    }

    /**
     * Extract use statements from AST to build alias mapping.
     *
     * @param  array<Node>  $ast
     * @return array<string, string> Map of alias => fully qualified name
     */
    private function extractUseStatements(array $ast): array
    {
        $useStatements = [];

        /** @var array<Node\Stmt\Use_> $uses */
        $uses = $this->parser->findNodes($ast, Node\Stmt\Use_::class);

        foreach ($uses as $use) {
            foreach ($use->uses as $useUse) {
                $fullyQualifiedName = $useUse->name->toString();
                $alias = $useUse->alias !== null
                    ? $useUse->alias->toString()
                    : $useUse->name->getLast();

                $useStatements[$alias] = $fullyQualifiedName;
            }
        }

        /** @var array<Node\Stmt\GroupUse> $groupUses */
        $groupUses = $this->parser->findNodes($ast, Node\Stmt\GroupUse::class);

        foreach ($groupUses as $groupUse) {
            $prefix = $groupUse->prefix->toString();

            foreach ($groupUse->uses as $useUse) {
                $fullyQualifiedName = $prefix.'\\'.$useUse->name->toString();
                $alias = $useUse->alias !== null
                    ? $useUse->alias->toString()
                    : $useUse->name->getLast();

                $useStatements[$alias] = $fullyQualifiedName;
            }
        }

        return $useStatements;
    }
}

/**
 * Visitor to detect fat models.
 */
class FatModelVisitor extends NodeVisitorAbstract
{
    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    private ?string $currentClassName = null;

    private int $classStartLine = 0;

    /**
     * @param  array<string, string>  $useStatements  Map of alias => fully qualified name
     */
    public function __construct(
        private readonly int $methodThreshold,
        private readonly int $locThreshold,
        private readonly int $complexityThreshold,
        private readonly array $useStatements = []
    ) {}

    public function enterNode(Node $node): ?Node
    {
        // Detect class extending Model
        if ($node instanceof Node\Stmt\Class_) {
            if ($this->extendsModel($node)) {
                $this->currentClassName = $node->name?->toString();
                $this->classStartLine = $node->getStartLine();
                $this->analyzeModel($node);
            }
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

    private function extendsModel(Node\Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $parentClass = $class->extends->toString();

        // Resolve alias through use statements
        $resolvedClass = $this->resolveClassName($parentClass);

        // Standard Eloquent Model
        if ($resolvedClass === 'Model'
            || str_ends_with($resolvedClass, '\\Model')
            || $resolvedClass === 'Illuminate\\Database\\Eloquent\\Model') {
            return true;
        }

        // Custom base models (common patterns in Laravel apps)
        if (str_ends_with($resolvedClass, 'BaseModel')
            || str_contains($resolvedClass, '\\Models\\Base')
            || preg_match('/Base[A-Z]\w*Model/', $resolvedClass)) {
            return true;
        }

        // Pivot models
        if ($resolvedClass === 'Pivot'
            || str_ends_with($resolvedClass, '\\Pivot')
            || $resolvedClass === 'Illuminate\\Database\\Eloquent\\Relations\\Pivot') {
            return true;
        }

        // MorphPivot models
        if ($resolvedClass === 'MorphPivot'
            || str_ends_with($resolvedClass, '\\MorphPivot')
            || $resolvedClass === 'Illuminate\\Database\\Eloquent\\Relations\\MorphPivot') {
            return true;
        }

        // Authenticatable (User model base)
        if ($resolvedClass === 'Authenticatable'
            || str_ends_with($resolvedClass, '\\Authenticatable')
            || $resolvedClass === 'Illuminate\\Foundation\\Auth\\User') {
            return true;
        }

        return false;
    }

    /**
     * Resolve a class name through use statements.
     *
     * Handles:
     * - Fully qualified names: \Illuminate\Database\Eloquent\Model
     * - Simple aliases: Model (when `use ... as Model` or `use ...\Model`)
     * - Namespace-relative paths: Foundation\Auth\User (when `use Illuminate\Foundation`)
     */
    private function resolveClassName(string $className): string
    {
        // If it's already fully qualified (starts with \), return without leading \
        if (str_starts_with($className, '\\')) {
            return ltrim($className, '\\');
        }

        // Check if it's a direct alias in use statements
        if (isset($this->useStatements[$className])) {
            return $this->useStatements[$className];
        }

        // Handle namespace-relative paths like Foundation\Auth\User
        // where Foundation might be imported via `use Illuminate\Foundation`
        if (str_contains($className, '\\')) {
            $parts = explode('\\', $className);
            $firstPart = $parts[0];

            // Check if the first segment is imported
            if (isset($this->useStatements[$firstPart])) {
                // Replace first segment with the imported namespace
                $parts[0] = $this->useStatements[$firstPart];

                return implode('\\', $parts);
            }
        }

        // Return as-is (might be short name like 'Model')
        return $className;
    }

    private function analyzeModel(Node\Stmt\Class_ $class): void
    {
        $methods = [];
        $businessMethods = 0;

        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\ClassMethod) {
                if ($this->isBusinessMethod($stmt)) {
                    $businessMethods++;
                    $methods[] = $stmt;
                }
            }
        }

        // Check method count with dynamic severity
        if ($businessMethods > $this->methodThreshold) {
            $excess = $businessMethods - $this->methodThreshold;
            $severity = match (true) {
                $excess >= 15 => Severity::High,    // 30+ methods (threshold + 15)
                $excess >= 5 => Severity::Medium,   // 20-29 methods (threshold + 5)
                default => Severity::Low,            // 16-19 methods
            };

            $this->issues[] = [
                'message' => sprintf(
                    'Model "%s" has %d business methods (threshold: %d). Consider extracting logic to service classes',
                    $this->currentClassName,
                    $businessMethods,
                    $this->methodThreshold
                ),
                'line' => $this->classStartLine,
                'severity' => $severity,
                'recommendation' => 'Move business logic to service classes. Models should focus on data representation, relationships, and simple accessors/mutators. Extract complex operations to dedicated service classes',
                'code' => null,
            ];
        }

        // Check statement lines (properties + methods span) with dynamic severity
        $statementLines = $this->countStatementLines($class);
        if ($statementLines > $this->locThreshold) {
            $excess = $statementLines - $this->locThreshold;
            $severity = match (true) {
                $excess >= 200 => Severity::High,  // 500+ lines (threshold + 200)
                $excess >= 100 => Severity::Medium, // 400-499 lines (threshold + 100)
                default => Severity::Low,           // 301-399 lines
            };

            $this->issues[] = [
                'message' => sprintf(
                    'Model "%s" has %d statement lines (threshold: %d). Model is too large',
                    $this->currentClassName,
                    $statementLines,
                    $this->locThreshold
                ),
                'line' => $this->classStartLine,
                'severity' => $severity,
                'recommendation' => 'Large models are hard to maintain. Consider: 1) Extracting business logic to services, 2) Using traits for reusable functionality, 3) Moving query logic to repositories',
                'code' => null,
            ];
        }

        // Check method complexity
        foreach ($methods as $method) {
            $complexity = $this->calculateComplexity($method);
            if ($complexity > $this->complexityThreshold) {
                $excess = $complexity - $this->complexityThreshold;
                $severity = match (true) {
                    $excess >= 15 => Severity::High,   // 25+ complexity (threshold + 15)
                    $excess >= 5 => Severity::Medium,  // 15-24 complexity (threshold + 5)
                    default => Severity::Low,          // 11-14 complexity
                };

                $this->issues[] = [
                    'message' => sprintf(
                        'Method "%s::%s()" has complexity of %d (threshold: %d)',
                        $this->currentClassName,
                        $method->name->toString(),
                        $complexity,
                        $this->complexityThreshold
                    ),
                    'line' => $method->getStartLine(),
                    'severity' => $severity,
                    'recommendation' => 'Complex methods in models indicate business logic that should be extracted to service classes',
                    'code' => null,
                ];
            }
        }
    }

    /**
     * Count statement lines (properties + methods span).
     * Note: Includes docblocks and comments within the span.
     */
    private function countStatementLines(Node\Stmt\Class_ $class): int
    {
        $loc = 0;

        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Property || $stmt instanceof Node\Stmt\ClassMethod) {
                $loc += $stmt->getEndLine() - $stmt->getStartLine() + 1;
            }
        }

        return $loc;
    }

    private function isBusinessMethod(Node\Stmt\ClassMethod $method): bool
    {
        $name = $method->name->toString();

        // Exclude Laravel magic methods and common Eloquent patterns
        $excluded = [
            // Lifecycle hooks
            'boot', 'booting', 'booted',
            // Casting (Laravel 11+)
            'casts',
            // Eloquent customization
            'newEloquentBuilder', 'newCollection', 'newFactory',
            // Route model binding (UrlRoutable)
            'resolveRouteBinding', 'resolveChildRouteBinding',
            'getRouteKeyName', 'getRouteKey',
            // Serialization (Arrayable, Jsonable)
            'toArray', 'toJson',
            // Broadcasting
            'broadcastOn', 'broadcastWith', 'broadcastAs',
            // Prunable
            'prunable',
            // Scout searchable
            'shouldBeSearchable', 'toSearchableArray', 'searchableAs',
        ];

        if (in_array($name, $excluded, true)) {
            return false;
        }

        // Exclude scopes
        if (str_starts_with($name, 'scope')) {
            return false;
        }

        // Exclude accessors/mutators (Laravel 9+ uses *Attribute)
        if (str_ends_with($name, 'Attribute')) {
            return false;
        }

        // Exclude old-style accessors/mutators
        if (preg_match('/^(get|set)[A-Z].*Attribute$/', $name)) {
            return false;
        }

        // Exclude relationship methods (improved detection)
        if ($this->isRelationshipMethod($method)) {
            return false;
        }

        // Exclude protected/private methods (usually internal)
        if ($method->isPrivate() || $method->isProtected()) {
            return false;
        }

        return true;
    }

    /**
     * Detect if a method is a relationship definition.
     * Handles multi-line relationships and type-hinted relationships.
     */
    private function isRelationshipMethod(Node\Stmt\ClassMethod $method): bool
    {
        // Check return type hint first (Laravel 8+)
        if ($method->returnType !== null) {
            $typeNames = $this->extractTypeNames($method->returnType);
            $relationshipTypes = [
                // Base relation type (common generic type hint)
                'Relation',
                // Specific relation types
                'HasOne', 'HasMany', 'BelongsTo', 'BelongsToMany',
                'MorphTo', 'MorphOne', 'MorphMany', 'MorphToMany',
                'HasOneThrough', 'HasManyThrough', 'MorphedByMany',
            ];

            foreach ($typeNames as $typeName) {
                foreach ($relationshipTypes as $relationType) {
                    if (str_ends_with($typeName, $relationType)) {
                        return true;
                    }
                }
            }
        }

        // Check method body for relationship calls
        if (! $method->stmts) {
            return false;
        }

        $relationshipMethods = [
            'hasOne', 'hasMany', 'belongsTo', 'belongsToMany',
            'morphTo', 'morphOne', 'morphMany', 'morphToMany',
            'hasOneThrough', 'hasManyThrough', 'morphedByMany',
        ];

        // Find the last return statement (handles multi-line method bodies)
        foreach (array_reverse($method->stmts) as $stmt) {
            if ($stmt instanceof Node\Stmt\Return_ && $stmt->expr) {
                return $this->containsRelationshipCall($stmt->expr, $relationshipMethods);
            }
        }

        return false;
    }

    /**
     * Extract type names from a type node (handles Name, NullableType, UnionType, FullyQualified).
     *
     * @return array<int, string>
     */
    private function extractTypeNames(Node $typeNode): array
    {
        $names = [];

        if ($typeNode instanceof Node\NullableType) {
            // ?HasMany -> extract HasMany
            $names = array_merge($names, $this->extractTypeNames($typeNode->type));
        } elseif ($typeNode instanceof Node\UnionType) {
            // HasMany|BelongsTo -> extract both
            foreach ($typeNode->types as $type) {
                $names = array_merge($names, $this->extractTypeNames($type));
            }
        } elseif ($typeNode instanceof Node\IntersectionType) {
            // Handle intersection types (PHP 8.1+)
            foreach ($typeNode->types as $type) {
                $names = array_merge($names, $this->extractTypeNames($type));
            }
        } elseif ($typeNode instanceof Node\Name\FullyQualified) {
            // \Illuminate\Database\Eloquent\Relations\HasMany
            $names[] = $typeNode->toString();
        } elseif ($typeNode instanceof Node\Name) {
            // HasMany or Illuminate\Database\Eloquent\Relations\HasMany
            $names[] = $typeNode->toString();
        } elseif ($typeNode instanceof Node\Identifier) {
            // Built-in types like string, int, etc. (not relationships)
            $names[] = $typeNode->toString();
        }

        return $names;
    }

    /**
     * Recursively check if an expression contains a relationship method call.
     * Handles chained method calls like $this->hasMany()->where()->orderBy().
     *
     * @param  array<int, string>  $methods
     */
    private function containsRelationshipCall(Node\Expr $expr, array $methods): bool
    {
        if ($expr instanceof Node\Expr\MethodCall) {
            // Check if this call is a relationship method
            if ($expr->name instanceof Node\Identifier) {
                if (in_array($expr->name->toString(), $methods, true)) {
                    return true;
                }
            }

            // Check chained calls (e.g., $this->hasMany()->where())
            if ($expr->var instanceof Node\Expr\MethodCall) {
                return $this->containsRelationshipCall($expr->var, $methods);
            }
        }

        return false;
    }

    /**
     * Calculate cyclomatic complexity of a method.
     *
     * Cyclomatic complexity measures the number of linearly independent paths through code.
     * Formula: Base complexity (1) + decision points
     *
     * Decision points:
     * - Control structures: if, elseif, case, for, foreach, while, do, catch, ternary
     * - Logical operators: &&, ||, and, or
     */
    private function calculateComplexity(Node\Stmt\ClassMethod $method): int
    {
        $visitor = new ComplexityVisitor;
        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($method->stmts ?? []);

        return $visitor->getComplexity();
    }
}

/**
 * Visitor to calculate cyclomatic complexity.
 */
class ComplexityVisitor extends NodeVisitorAbstract
{
    private int $complexity = 1; // Base complexity

    public function getComplexity(): int
    {
        return $this->complexity;
    }

    public function enterNode(Node $node): ?Node
    {
        // Increment for control structures
        if ($node instanceof Node\Stmt\If_
            || $node instanceof Node\Stmt\ElseIf_
            || $node instanceof Node\Stmt\Case_
            || $node instanceof Node\Stmt\For_
            || $node instanceof Node\Stmt\Foreach_
            || $node instanceof Node\Stmt\While_
            || $node instanceof Node\Stmt\Do_
            || $node instanceof Node\Stmt\Catch_
            || $node instanceof Node\Expr\Ternary
        ) {
            $this->complexity++;
        }

        // Increment for logical operators
        if ($node instanceof Node\Expr\BinaryOp\BooleanAnd
            || $node instanceof Node\Expr\BinaryOp\BooleanOr
            || $node instanceof Node\Expr\BinaryOp\LogicalAnd
            || $node instanceof Node\Expr\BinaryOp\LogicalOr
        ) {
            $this->complexity++;
        }

        // Null coalesce operator (??)
        if ($node instanceof Node\Expr\BinaryOp\Coalesce) {
            $this->complexity++;
        }

        // PHP 8 match expression
        if ($node instanceof Node\Expr\Match_) {
            $this->complexity++;
        }

        // Each match arm with conditions adds complexity
        if ($node instanceof Node\MatchArm && $node->conds !== null) {
            $this->complexity += count($node->conds);
        }

        return null;
    }
}
