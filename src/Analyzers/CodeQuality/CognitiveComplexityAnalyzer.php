<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\CodeQuality;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
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
 * Measures cognitive complexity of methods.
 *
 * Cognitive complexity differs from cyclomatic complexity by considering:
 * - Nesting depth (increases mental effort)
 * - Structural breaks (break/continue add complexity)
 * - Binary logical operators in different contexts
 * - More human-centric than mathematical
 *
 * Based on: https://www.sonarsource.com/docs/CognitiveComplexity.pdf
 */
class CognitiveComplexityAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Maximum cognitive complexity threshold.
     */
    private int $threshold = 15;

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'cognitive-complexity',
            name: 'Cognitive Complexity',
            description: 'Measures cognitive complexity focusing on human comprehension rather than mathematical metrics',
            category: Category::CodeQuality,
            severity: Severity::Medium,
            tags: ['complexity', 'maintainability', 'code-quality', 'readability', 'cognitive-load'],
            docsUrl: 'https://www.sonarsource.com/docs/CognitiveComplexity.pdf'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $threshold = $this->threshold;

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new CognitiveComplexityVisitor($threshold);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Method '{$issue['method']}' has cognitive complexity of {$issue['complexity']} (threshold: {$threshold})",
                    location: new Location($file, $issue['line']),
                    severity: $this->getSeverityForComplexity($issue['complexity'], $threshold),
                    recommendation: $this->getRecommendation($issue['method'], $issue['complexity'], $threshold),
                    metadata: [
                        'method' => $issue['method'],
                        'class' => $issue['class'],
                        'complexity' => $issue['complexity'],
                        'threshold' => $threshold,
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('All methods have acceptable cognitive complexity');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} method(s) with high cognitive complexity",
            $issues
        );
    }

    /**
     * Get severity based on complexity excess.
     */
    private function getSeverityForComplexity(int $complexity, int $threshold): Severity
    {
        $excess = $complexity - $threshold;

        if ($excess >= 15) {
            return Severity::High;
        }

        if ($excess >= 10) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Get recommendation for cognitive complexity.
     */
    private function getRecommendation(string $method, int $complexity, int $threshold): string
    {
        $excess = $complexity - $threshold;
        $base = "Method '{$method}' has cognitive complexity of {$complexity}, which is {$excess} point(s) above the threshold. High cognitive complexity makes code difficult to understand and maintain. ";

        $strategies = [
            'Extract nested conditions and loops into well-named private methods',
            'Use early returns (guard clauses) to reduce nesting',
            'Replace complex conditionals with polymorphism or strategy pattern',
            'Simplify boolean expressions using De Morgan\'s laws',
            'Break down long methods into smaller, focused methods',
            'Use descriptive method names that reveal intent',
            'Consider using design patterns for complex logic flows',
        ];

        $example = <<<'PHP'

// Problem - High cognitive complexity (15+):
public function processOrder($order)
{
    if ($order->isValid()) {                    // +1
        if ($order->hasCustomer()) {            // +2 (nested)
            if ($order->customer->isActive()) { // +3 (nested)
                foreach ($order->items as $item) { // +4 (nested)
                    if ($item->inStock()) {     // +5 (nested)
                        if ($item->price > 0) { // +6 (nested)
                            // Process item
                        } else if ($item->isFree()) { // +7 (nested)
                            // Process free item
                        }
                    } else if ($item->canBackorder()) { // +8 (nested)
                        // Backorder
                    }
                }
            } else {
                return false;                   // +2 (nested)
            }
        }
    } else {
        throw new InvalidOrderException();      // +1
    }
    // Total: 15+
}

// Solution - Reduced cognitive complexity (5):
public function processOrder($order)
{
    if (!$order->isValid()) {                   // +1
        throw new InvalidOrderException();
    }

    if (!$this->canProcessOrder($order)) {     // +1
        return false;
    }

    return $this->processOrderItems($order);
}

private function canProcessOrder($order): bool
{
    return $order->hasCustomer()
        && $order->customer->isActive();
}

private function processOrderItems($order)
{
    foreach ($order->items as $item) {          // +1
        $this->processItem($item);
    }
}

private function processItem($item)
{
    if (!$item->inStock()) {                    // +1
        return $this->handleOutOfStock($item);
    }

    if ($item->price > 0) {                     // +1
        $this->processPaidItem($item);
    } else if ($item->isFree()) {
        $this->processFreeItem($item);
    }
}
// Total: 5
PHP;

        return $base.'Refactoring strategies: '.implode('; ', $strategies).". Example:{$example}";
    }
}

/**
 * Visitor to calculate cognitive complexity.
 */
class CognitiveComplexityVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{method: string, class: string, complexity: int, line: int}>
     */
    private array $issues = [];

    /**
     * Current class name.
     */
    private ?string $currentClass = null;

    /**
     * Current method name.
     */
    private ?string $currentMethod = null;

    /**
     * Current nesting level.
     */
    private int $nestingLevel = 0;

    /**
     * Cognitive complexity for current method.
     */
    private int $currentComplexity = 0;

    /**
     * Start line of current method.
     */
    private int $currentMethodLine = 0;

    public function __construct(
        private int $threshold
    ) {}

    public function enterNode(Node $node)
    {
        // Track class entry
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = $node->name ? $node->name->toString() : 'Anonymous';

            return null;
        }

        // Track method entry
        if ($node instanceof Stmt\ClassMethod || $node instanceof Stmt\Function_) {
            $this->currentMethod = $node->name->toString();
            $this->currentMethodLine = $node->getStartLine();
            $this->nestingLevel = 0;
            $this->currentComplexity = 0;

            return null;
        }

        // Only measure inside methods
        if ($this->currentMethod === null) {
            return null;
        }

        // Calculate cognitive complexity increments
        $increment = $this->getCognitiveIncrement($node);
        $this->currentComplexity += $increment;

        // Track nesting level
        if ($this->isNestingConstruct($node)) {
            $this->nestingLevel++;
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Decrease nesting level
        if ($this->currentMethod !== null && $this->isNestingConstruct($node)) {
            $this->nestingLevel--;
        }

        // Check complexity on method exit
        if ($node instanceof Stmt\ClassMethod || $node instanceof Stmt\Function_) {
            if ($this->currentComplexity > $this->threshold) {
                $this->issues[] = [
                    'method' => ($this->currentClass ?? 'global').'::'.$this->currentMethod,
                    'class' => $this->currentClass ?? 'global',
                    'complexity' => $this->currentComplexity,
                    'line' => $this->currentMethodLine,
                ];
            }

            $this->currentMethod = null;
            $this->nestingLevel = 0;
            $this->currentComplexity = 0;
        }

        // Clear class context on exit
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = null;
        }

        return null;
    }

    /**
     * Calculate cognitive complexity increment for a node.
     */
    private function getCognitiveIncrement(Node $node): int
    {
        $increment = 0;

        // Control structures: +1 + nesting level
        if ($node instanceof Stmt\If_ ||
            $node instanceof Stmt\ElseIf_ ||
            $node instanceof Stmt\For_ ||
            $node instanceof Stmt\Foreach_ ||
            $node instanceof Stmt\While_ ||
            $node instanceof Stmt\Do_ ||
            $node instanceof Stmt\Case_ ||
            $node instanceof Stmt\Catch_) {
            $increment = 1 + $this->nestingLevel;
        }

        // Ternary: +1 + nesting level
        if ($node instanceof Expr\Ternary) {
            $increment = 1 + $this->nestingLevel;
        }

        // Binary logical operators in conditions
        if ($node instanceof Expr\BinaryOp\BooleanAnd ||
            $node instanceof Expr\BinaryOp\BooleanOr ||
            $node instanceof Expr\BinaryOp\LogicalAnd ||
            $node instanceof Expr\BinaryOp\LogicalOr) {
            // Only count if not in a sequence of same operator
            $increment = 1;
        }

        // Jumps in loops: +1
        if (($node instanceof Stmt\Break_ || $node instanceof Stmt\Continue_) && $this->nestingLevel > 0) {
            $increment = 1;
        }

        // Recursion: +1
        if ($node instanceof Expr\FuncCall || $node instanceof Expr\MethodCall) {
            // Would need semantic analysis to detect recursion
            // Skipping for now as it requires more complex analysis
        }

        // Goto: +1
        if ($node instanceof Stmt\Goto_) {
            $increment = 1 + $this->nestingLevel;
        }

        return $increment;
    }

    /**
     * Check if node is a nesting construct.
     */
    private function isNestingConstruct(Node $node): bool
    {
        return $node instanceof Stmt\If_
            || $node instanceof Stmt\For_
            || $node instanceof Stmt\Foreach_
            || $node instanceof Stmt\While_
            || $node instanceof Stmt\Do_
            || $node instanceof Stmt\Switch_
            || $node instanceof Stmt\TryCatch
            || $node instanceof Stmt\Catch_
            || $node instanceof Expr\Ternary;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{method: string, class: string, complexity: int, line: int}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
