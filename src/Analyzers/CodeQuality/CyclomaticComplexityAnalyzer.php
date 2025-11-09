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
 * Detects methods with high cyclomatic complexity (McCabe metric).
 *
 * Checks for:
 * - Methods with complexity > threshold (default: 10)
 * - Decision points: if, while, for, case, catch, &&, ||, ?:
 * - Formula: M = E - N + 2P (E=edges, N=nodes, P=connected components)
 */
class CyclomaticComplexityAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Default complexity threshold.
     */
    private int $threshold = 10;

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'cyclomatic-complexity',
            name: 'Cyclomatic Complexity',
            description: 'Detects methods with high cyclomatic complexity using McCabe metric',
            category: Category::CodeQuality,
            severity: Severity::Medium,
            tags: ['complexity', 'maintainability', 'code-quality', 'metrics'],
            docsUrl: 'https://en.wikipedia.org/wiki/Cyclomatic_complexity'
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

            $visitor = new ComplexityVisitor($threshold);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Method '{$issue['method']}' has cyclomatic complexity of {$issue['complexity']} (threshold: {$threshold})",
                    location: new Location($file, $issue['line']),
                    severity: $this->getSeverityForComplexity($issue['complexity'], $threshold),
                    recommendation: $this->getRecommendation($issue['complexity'], $threshold),
                    metadata: [
                        'method' => $issue['method'],
                        'complexity' => $issue['complexity'],
                        'threshold' => $threshold,
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No methods with high cyclomatic complexity detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} method(s) with high cyclomatic complexity",
            $issues
        );
    }

    /**
     * Get severity based on complexity level.
     */
    private function getSeverityForComplexity(int $complexity, int $threshold): Severity
    {
        $ratio = $complexity / $threshold;

        if ($ratio >= 2.0) {
            return Severity::High;
        }

        if ($ratio >= 1.5) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Get recommendation based on complexity.
     */
    private function getRecommendation(int $complexity, int $threshold): string
    {
        $excess = $complexity - $threshold;

        $base = "This method has {$excess} decision points above the recommended threshold. ";

        $recommendations = [
            'Break this method into smaller, focused functions',
            'Extract conditional logic into well-named helper methods',
            'Use early returns to reduce nesting',
            'Consider using polymorphism to replace complex conditionals',
            'Apply the Single Responsibility Principle',
        ];

        if ($complexity >= $threshold * 2) {
            $base .= 'This is critically complex and should be refactored immediately. ';
        } elseif ($complexity >= $threshold * 1.5) {
            $base .= 'This requires significant refactoring. ';
        }

        return $base.'Recommended actions: '.implode('; ', $recommendations);
    }
}

/**
 * Visitor to calculate cyclomatic complexity.
 */
class ComplexityVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{method: string|null, complexity: int, line: int}>
     */
    private array $issues = [];

    private ?string $currentMethod = null;

    private int $currentComplexity = 1;

    private int $currentLine = 0;

    public function __construct(
        private int $threshold
    ) {}

    public function enterNode(Node $node)
    {
        // Track method/function entry
        if ($node instanceof Stmt\Function_ || $node instanceof Stmt\ClassMethod) {
            $this->currentMethod = $node->name->toString();
            $this->currentComplexity = 1; // Base complexity
            $this->currentLine = $node->getStartLine();

            return null;
        }

        // Only count complexity inside methods
        if ($this->currentMethod === null) {
            return null;
        }

        // Count decision points
        $this->currentComplexity += $this->getComplexityIncrement($node);

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Method/function exit - check if complexity exceeds threshold
        if ($node instanceof Stmt\Function_ || $node instanceof Stmt\ClassMethod) {
            if ($this->currentComplexity > $this->threshold) {
                $this->issues[] = [
                    'method' => $this->currentMethod,
                    'complexity' => $this->currentComplexity,
                    'line' => $this->currentLine,
                ];
            }

            $this->currentMethod = null;
            $this->currentComplexity = 1;
            $this->currentLine = 0;
        }

        return null;
    }

    /**
     * Calculate complexity increment for a node.
     */
    private function getComplexityIncrement(Node $node): int
    {
        $increment = 0;

        // Control structures (+1 each)
        if ($node instanceof Stmt\If_) {
            $increment = 1;
        } elseif ($node instanceof Stmt\ElseIf_) {
            $increment = 1;
        } elseif ($node instanceof Stmt\While_) {
            $increment = 1;
        } elseif ($node instanceof Stmt\For_) {
            $increment = 1;
        } elseif ($node instanceof Stmt\Foreach_) {
            $increment = 1;
        } elseif ($node instanceof Stmt\Do_) {
            $increment = 1;
        } elseif ($node instanceof Stmt\Switch_) {
            $increment = 1;
        } elseif ($node instanceof Stmt\Case_) {
            // Each case in switch adds complexity
            if ($node->cond !== null) {
                $increment = 1;
            }
        } elseif ($node instanceof Stmt\Catch_) {
            $increment = 1;
        } elseif ($node instanceof Expr\Ternary) {
            $increment = 1;
        } elseif ($node instanceof Expr\BinaryOp\BooleanAnd) {
            $increment = 1;
        } elseif ($node instanceof Expr\BinaryOp\BooleanOr) {
            $increment = 1;
        } elseif ($node instanceof Expr\BinaryOp\LogicalAnd) {
            $increment = 1;
        } elseif ($node instanceof Expr\BinaryOp\LogicalOr) {
            $increment = 1;
        } elseif ($node instanceof Expr\BinaryOp\Coalesce) {
            $increment = 1;
        }

        return $increment;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{method: string|null, complexity: int, line: int}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
