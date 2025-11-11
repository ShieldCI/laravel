<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

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

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'fat-model',
            name: 'Fat Model Detector',
            description: 'Detects Eloquent models with too much business logic that should be extracted to services',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['laravel', 'eloquent', 'architecture', 'solid', 'srp'],
            docsUrl: 'https://docs.shieldci.com/analyzers/fat-model',
        );
    }

    protected function runAnalysis(): ResultInterface
    {
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

                $visitor = new FatModelVisitor;
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

    private int $classEndLine = 0;

    public function enterNode(Node $node): ?Node
    {
        // Detect class extending Model
        if ($node instanceof Node\Stmt\Class_) {
            if ($this->extendsModel($node)) {
                $this->currentClassName = $node->name?->toString();
                $this->classStartLine = $node->getStartLine();
                $this->classEndLine = $node->getEndLine();
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

        return $parentClass === 'Model'
            || str_ends_with($parentClass, '\\Model')
            || $parentClass === 'Illuminate\\Database\\Eloquent\\Model';
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

        // Check method count
        if ($businessMethods > FatModelAnalyzer::METHOD_THRESHOLD) {
            $this->issues[] = [
                'message' => sprintf(
                    'Model "%s" has %d business methods (threshold: %d). Consider extracting logic to service classes',
                    $this->currentClassName,
                    $businessMethods,
                    FatModelAnalyzer::METHOD_THRESHOLD
                ),
                'line' => $this->classStartLine,
                'severity' => Severity::Medium,
                'recommendation' => 'Move business logic to service classes. Models should focus on data representation, relationships, and simple accessors/mutators. Extract complex operations to dedicated service classes',
                'code' => null,
            ];
        }

        // Check lines of code
        $loc = $this->classEndLine - $this->classStartLine;
        if ($loc > FatModelAnalyzer::LOC_THRESHOLD) {
            $this->issues[] = [
                'message' => sprintf(
                    'Model "%s" has %d lines (threshold: %d). Model is too large',
                    $this->currentClassName,
                    $loc,
                    FatModelAnalyzer::LOC_THRESHOLD
                ),
                'line' => $this->classStartLine,
                'severity' => Severity::Medium,
                'recommendation' => 'Large models are hard to maintain. Consider: 1) Extracting business logic to services, 2) Using traits for reusable functionality, 3) Moving query logic to repositories',
                'code' => null,
            ];
        }

        // Check method complexity
        foreach ($methods as $method) {
            $complexity = $this->calculateComplexity($method);
            if ($complexity > FatModelAnalyzer::COMPLEXITY_THRESHOLD) {
                $this->issues[] = [
                    'message' => sprintf(
                        'Method "%s::%s()" has complexity of %d (threshold: %d)',
                        $this->currentClassName,
                        $method->name->toString(),
                        $complexity,
                        FatModelAnalyzer::COMPLEXITY_THRESHOLD
                    ),
                    'line' => $method->getStartLine(),
                    'severity' => Severity::Low,
                    'recommendation' => 'Complex methods in models indicate business logic that should be extracted to service classes',
                    'code' => null,
                ];
            }
        }
    }

    private function isBusinessMethod(Node\Stmt\ClassMethod $method): bool
    {
        $name = $method->name->toString();

        // Exclude Laravel magic methods and common Eloquent patterns
        $excluded = [
            // Lifecycle hooks
            'boot', 'booting', 'booted',
            // Scopes (start with 'scope')
            // Relationships (common names)
            // Accessors/Mutators (end with 'Attribute')
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

        // Exclude common relationship method patterns
        $relationshipMethods = [
            'hasOne', 'hasMany', 'belongsTo', 'belongsToMany',
            'morphTo', 'morphOne', 'morphMany', 'morphToMany',
            'hasOneThrough', 'hasManyThrough',
        ];

        // Check if method body only contains a relationship call
        if ($method->stmts && count($method->stmts) === 1) {
            $stmt = $method->stmts[0];
            if ($stmt instanceof Node\Stmt\Return_ && $stmt->expr instanceof Node\Expr\MethodCall) {
                $returnCall = $stmt->expr;
                if ($returnCall->name instanceof Node\Identifier) {
                    $methodName = $returnCall->name->toString();
                    if (in_array($methodName, $relationshipMethods, true)) {
                        return false;
                    }
                }
            }
        }

        // Exclude protected/private methods (usually internal)
        if ($method->isPrivate() || $method->isProtected()) {
            return false;
        }

        return true;
    }

    private function calculateComplexity(Node\Stmt\ClassMethod $method): int
    {
        $complexity = 1; // Base complexity

        $visitor = new class($complexity) extends NodeVisitorAbstract
        {
            public function __construct(private int &$complexity) {}

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
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($method->stmts ?? []);

        return $complexity;
    }
}
