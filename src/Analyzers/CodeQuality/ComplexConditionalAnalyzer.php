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
 * Identifies overly complex conditional expressions.
 *
 * Checks for:
 * - Multiple logical operators (&&, ||) in single expression
 * - Threshold: > 3 logical operators
 * - Nested ternary operators
 * - Complex boolean logic that should be extracted
 */
class ComplexConditionalAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Maximum allowed logical operators in a single condition.
     */
    private int $threshold = 3;

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'complex-conditional',
            name: 'Complex Conditional',
            description: 'Identifies overly complex conditional expressions that should be simplified or extracted',
            category: Category::CodeQuality,
            severity: Severity::Medium,
            tags: ['complexity', 'readability', 'maintainability', 'code-quality', 'refactoring'],
            docsUrl: 'https://docs.shieldci.com/analyzers/code-quality/complex-conditional',
            timeToFix: 20
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

            $visitor = new ComplexConditionalVisitor($threshold);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Complex conditional with {$issue['operators']} logical operators in '{$issue['context']}'",
                    location: new Location($file, $issue['line']),
                    severity: $this->getSeverityForComplexity($issue['operators'], $threshold),
                    recommendation: $this->getRecommendation($issue['operators'], $issue['context'], $issue['type']),
                    metadata: [
                        'operators' => $issue['operators'],
                        'threshold' => $threshold,
                        'context' => $issue['context'],
                        'type' => $issue['type'],
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No complex conditionals detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} complex conditional(s)",
            $issues
        );
    }

    /**
     * Get severity based on complexity.
     */
    private function getSeverityForComplexity(int $operators, int $threshold): Severity
    {
        $excess = $operators - $threshold;

        if ($excess >= 4) {
            return Severity::High;
        }

        if ($excess >= 2) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Get recommendation for complex conditional.
     */
    private function getRecommendation(int $operators, string $context, string $type): string
    {
        $base = "This conditional expression contains {$operators} logical operators, making it difficult to understand and maintain. ";

        $strategies = [
            'Extract complex conditions into well-named boolean variables',
            'Create separate methods with descriptive names for compound conditions',
            'Use guard clauses to simplify nested conditions',
            'Apply De Morgan\'s laws to simplify boolean logic',
            'Break down complex ternary operators into if-else statements',
            'Consider using the Strategy or State pattern for complex business rules',
        ];

        $example = match ($type) {
            'nested_ternary' => <<<'PHP'

// Problem - Nested ternary:
$discount = $user->isPremium() ? ($order->total > 100 ? 0.20 : 0.10) : ($order->total > 100 ? 0.05 : 0);

// Solution - Extract to method:
private function calculateDiscount(User $user, Order $order): float
{
    if ($user->isPremium()) {
        return $order->total > 100 ? 0.20 : 0.10;
    }

    return $order->total > 100 ? 0.05 : 0;
}
PHP,
            default => <<<'PHP'

// Problem - Complex condition:
if ($user->isActive() && !$user->isBanned() && ($user->hasRole('admin') || $user->hasRole('moderator')) && $user->emailVerified && $resource->isPublic()) {
    // Complex logic is hard to follow
}

// Solution - Extract to variables:
$isEligibleUser = $user->isActive() && !$user->isBanned() && $user->emailVerified;
$hasModeratorAccess = $user->hasRole('admin') || $user->hasRole('moderator');
$canAccessResource = $resource->isPublic();

if ($isEligibleUser && $hasModeratorAccess && $canAccessResource) {
    // Much clearer intent
}

// Better - Extract to method:
if ($this->canUserAccessResource($user, $resource)) {
    // Intention revealed through method name
}

private function canUserAccessResource(User $user, Resource $resource): bool
{
    return $this->isEligibleUser($user)
        && $this->hasModeratorAccess($user)
        && $resource->isPublic();
}

private function isEligibleUser(User $user): bool
{
    return $user->isActive() && !$user->isBanned() && $user->emailVerified;
}

private function hasModeratorAccess(User $user): bool
{
    return $user->hasRole('admin') || $user->hasRole('moderator');
}
PHP,
        };

        return $base.'Refactoring strategies: '.implode('; ', $strategies).". Example:{$example}";
    }
}

/**
 * Visitor to detect complex conditional expressions.
 */
class ComplexConditionalVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{operators: int, line: int, context: string, type: string}>
     */
    private array $issues = [];

    /**
     * Current method/function name.
     */
    private ?string $currentContext = null;

    public function __construct(
        private int $threshold
    ) {}

    public function enterNode(Node $node)
    {
        // Track method/function entry
        if ($node instanceof Stmt\Function_ || $node instanceof Stmt\ClassMethod) {
            $this->currentContext = $node->name->toString();

            return null;
        }

        // Check if statements
        if ($node instanceof Stmt\If_) {
            $operators = $this->countLogicalOperators($node->cond);

            if ($operators > $this->threshold) {
                $this->issues[] = [
                    'operators' => $operators,
                    'line' => $node->getStartLine(),
                    'context' => $this->currentContext ?? 'global scope',
                    'type' => 'if_condition',
                ];
            }

            return null;
        }

        // Check while loops
        if ($node instanceof Stmt\While_) {
            $operators = $this->countLogicalOperators($node->cond);

            if ($operators > $this->threshold) {
                $this->issues[] = [
                    'operators' => $operators,
                    'line' => $node->getStartLine(),
                    'context' => $this->currentContext ?? 'global scope',
                    'type' => 'while_condition',
                ];
            }

            return null;
        }

        // Check for loops
        if ($node instanceof Stmt\For_) {
            foreach ($node->cond as $cond) {
                $operators = $this->countLogicalOperators($cond);

                if ($operators > $this->threshold) {
                    $this->issues[] = [
                        'operators' => $operators,
                        'line' => $node->getStartLine(),
                        'context' => $this->currentContext ?? 'global scope',
                        'type' => 'for_condition',
                    ];
                    break; // Only report once per for loop
                }
            }

            return null;
        }

        // Check ternary operators
        if ($node instanceof Expr\Ternary) {
            // Check for nested ternary
            if ($this->hasNestedTernary($node)) {
                $this->issues[] = [
                    'operators' => $this->countLogicalOperators($node->cond) + 1, // +1 for ternary itself
                    'line' => $node->getStartLine(),
                    'context' => $this->currentContext ?? 'global scope',
                    'type' => 'nested_ternary',
                ];
            } else {
                // Check ternary condition complexity
                $operators = $this->countLogicalOperators($node->cond);

                if ($operators > $this->threshold) {
                    $this->issues[] = [
                        'operators' => $operators,
                        'line' => $node->getStartLine(),
                        'context' => $this->currentContext ?? 'global scope',
                        'type' => 'ternary_condition',
                    ];
                }
            }

            return null;
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Reset context when leaving method/function
        if ($node instanceof Stmt\Function_ || $node instanceof Stmt\ClassMethod) {
            $this->currentContext = null;
        }

        return null;
    }

    /**
     * Count logical operators in expression.
     */
    private function countLogicalOperators(Node $node): int
    {
        $count = 0;

        // Count binary logical operators
        if ($node instanceof Expr\BinaryOp\BooleanAnd ||
            $node instanceof Expr\BinaryOp\BooleanOr ||
            $node instanceof Expr\BinaryOp\LogicalAnd ||
            $node instanceof Expr\BinaryOp\LogicalOr ||
            $node instanceof Expr\BinaryOp\LogicalXor) {
            $count = 1;

            // Recursively count in left and right operands
            $count += $this->countLogicalOperators($node->left);
            $count += $this->countLogicalOperators($node->right);
        }

        // Count unary logical operators
        if ($node instanceof Expr\BooleanNot) {
            $count = 1;
            if ($node->expr !== null) {
                $count += $this->countLogicalOperators($node->expr);
            }
        }

        // Recursively check nested expressions
        if ($node instanceof Expr\Ternary) {
            if ($node->cond !== null) {
                $count += $this->countLogicalOperators($node->cond);
            }
            if ($node->if !== null) {
                $count += $this->countLogicalOperators($node->if);
            }
            if ($node->else !== null) {
                $count += $this->countLogicalOperators($node->else);
            }
        }

        return $count;
    }

    /**
     * Check if ternary has nested ternary operators.
     */
    private function hasNestedTernary(Expr\Ternary $node): bool
    {
        // Check if condition contains ternary
        if ($this->containsTernary($node->cond)) {
            return true;
        }

        // Check if true branch contains ternary
        if ($node->if !== null && $this->containsTernary($node->if)) {
            return true;
        }

        // Check if false branch contains ternary
        if ($node->else !== null && $this->containsTernary($node->else)) {
            return true;
        }

        return false;
    }

    /**
     * Check if node contains ternary operator.
     */
    private function containsTernary(Node $node): bool
    {
        if ($node instanceof Expr\Ternary) {
            return true;
        }

        // Check child nodes
        foreach ($node->getSubNodeNames() as $name) {
            $subNode = $node->$name;

            if ($subNode instanceof Node && $this->containsTernary($subNode)) {
                return true;
            }

            if (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node && $this->containsTernary($item)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{operators: int, line: int, context: string, type: string}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
