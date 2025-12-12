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
        // Load configuration from config file (best_practices.fat-model)
        $analyzerConfig = $this->config->get('shieldci.analyzers.best_practices.fat-model', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->methodThreshold = $analyzerConfig['method_threshold'] ?? self::METHOD_THRESHOLD;
        $this->locThreshold = $analyzerConfig['loc_threshold'] ?? self::LOC_THRESHOLD;
        $this->complexityThreshold = $analyzerConfig['complexity_threshold'] ?? self::COMPLEXITY_THRESHOLD;

        $issues = [];

        // Only set default paths if not already set (allows tests to override)
        if (empty($this->paths)) {
            $this->setBasePath(base_path());
            $this->setPaths(['app/Models', 'app']);
        }

        $modelFiles = $this->getPhpFiles();

        foreach ($modelFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new FatModelVisitor($this->methodThreshold, $this->locThreshold, $this->complexityThreshold);
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
            return $this->passed('All models have appropriate size and complexity');
        }

        return $this->failed(
            sprintf('Found %d fat model(s) that should be refactored', count($issues)),
            $issues
        );
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

    public function __construct(
        private int $methodThreshold,
        private int $locThreshold,
        private int $complexityThreshold
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

        // Standard Eloquent Model
        if ($parentClass === 'Model'
            || str_ends_with($parentClass, '\\Model')
            || $parentClass === 'Illuminate\\Database\\Eloquent\\Model') {
            return true;
        }

        // Custom base models (common patterns in Laravel apps)
        if (str_ends_with($parentClass, 'BaseModel')
            || str_contains($parentClass, '\\Models\\Base')
            || preg_match('/Base[A-Z]\w*Model/', $parentClass)) {
            return true;
        }

        // Pivot models
        if ($parentClass === 'Pivot'
            || str_ends_with($parentClass, '\\Pivot')
            || $parentClass === 'Illuminate\\Database\\Eloquent\\Relations\\Pivot') {
            return true;
        }

        return false;
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

        // Check lines of code with dynamic severity
        $loc = $this->countActualLOC($class);
        if ($loc > $this->locThreshold) {
            $excess = $loc - $this->locThreshold;
            $severity = match (true) {
                $excess >= 200 => Severity::High,  // 500+ lines (threshold + 200)
                $excess >= 100 => Severity::Medium, // 400-499 lines (threshold + 100)
                default => Severity::Low,           // 301-399 lines
            };

            $this->issues[] = [
                'message' => sprintf(
                    'Model "%s" has %d lines of code (threshold: %d). Model is too large',
                    $this->currentClassName,
                    $loc,
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
                $this->issues[] = [
                    'message' => sprintf(
                        'Method "%s::%s()" has complexity of %d (threshold: %d)',
                        $this->currentClassName,
                        $method->name->toString(),
                        $complexity,
                        $this->complexityThreshold
                    ),
                    'line' => $method->getStartLine(),
                    'severity' => Severity::Low,
                    'recommendation' => 'Complex methods in models indicate business logic that should be extracted to service classes',
                    'code' => null,
                ];
            }
        }
    }

    /**
     * Count actual lines of code (properties + methods), excluding blank lines and pure comment blocks.
     */
    private function countActualLOC(Node\Stmt\Class_ $class): int
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
        if ($method->returnType instanceof Node\Name) {
            $returnType = $method->returnType->toString();
            $relationshipTypes = [
                'HasOne', 'HasMany', 'BelongsTo', 'BelongsToMany',
                'MorphTo', 'MorphOne', 'MorphMany', 'MorphToMany',
                'HasOneThrough', 'HasManyThrough',
            ];

            foreach ($relationshipTypes as $type) {
                if (str_ends_with($returnType, $type)) {
                    return true;
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
            'hasOneThrough', 'hasManyThrough',
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

        return null;
    }
}
