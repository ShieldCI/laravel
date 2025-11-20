<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\CodeQuality;

use PhpParser\Node;
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
 * Identifies deeply nested code blocks.
 *
 * Checks for:
 * - Nesting levels for if/else, loops, try/catch
 * - Threshold: depth > 4 (configurable)
 * - Tracks maximum depth per method
 */
class NestingDepthAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Default nesting depth threshold.
     */
    private int $threshold = 4;

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'nesting-depth',
            name: 'Nesting Depth',
            description: 'Identifies deeply nested code blocks that reduce readability and maintainability',
            category: Category::CodeQuality,
            severity: Severity::Medium,
            tags: ['complexity', 'maintainability', 'code-quality', 'readability'],
            docsUrl: 'https://docs.shieldci.com/analyzers/code-quality/nesting-depth'
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

            $visitor = new NestingDepthVisitor($threshold);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Code block has nesting depth of {$issue['depth']} (threshold: {$threshold}) in '{$issue['context']}'",
                    location: new Location($file, $issue['line']),
                    severity: $this->getSeverityForDepth($issue['depth'], $threshold),
                    recommendation: $this->getRecommendation($issue['depth'], $threshold),
                    metadata: [
                        'depth' => $issue['depth'],
                        'threshold' => $threshold,
                        'context' => $issue['context'],
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No deeply nested code blocks detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} deeply nested code block(s)",
            $issues
        );
    }

    /**
     * Get severity based on nesting depth.
     */
    private function getSeverityForDepth(int $depth, int $threshold): Severity
    {
        $excess = $depth - $threshold;

        if ($excess >= 3) {
            return Severity::High;
        }

        if ($excess >= 2) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Get recommendation based on nesting depth.
     */
    private function getRecommendation(int $depth, int $threshold): string
    {
        $excess = $depth - $threshold;

        $base = "This code has {$excess} level(s) of nesting beyond the recommended maximum. Deeply nested code is difficult to read, understand, and maintain. ";

        $strategies = [
            'Use guard clauses and early returns to reduce nesting',
            'Extract nested logic into separate, well-named methods',
            'Replace nested conditionals with polymorphism or strategy pattern',
            'Combine related conditions using logical operators',
            'Consider using ternary operators for simple conditions',
            'Invert conditional logic to eliminate else blocks',
        ];

        $example = <<<'PHP'

// Problem (depth 5):
if ($user) {
    if ($user->isActive()) {
        foreach ($user->roles as $role) {
            if ($role->hasPermission('edit')) {
                if (!$resource->isLocked()) {
                    // Deep nesting - hard to follow
                }
            }
        }
    }
}

// Solution with guard clauses (depth 2):
if (!$user || !$user->isActive()) {
    return;
}

foreach ($user->roles as $role) {
    if (!$role->hasPermission('edit') || $resource->isLocked()) {
        continue;
    }
    // Much clearer
}
PHP;

        return $base.'Refactoring strategies: '.implode('; ', $strategies).". Example:{$example}";
    }
}

/**
 * Visitor to track nesting depth.
 */
class NestingDepthVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{depth: int, line: int, context: string}>
     */
    private array $issues = [];

    /**
     * Current nesting depth.
     */
    private int $currentDepth = 0;

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

        // Track nesting structures
        if ($this->isNestingStructure($node)) {
            $this->currentDepth++;

            // Check if depth exceeds threshold
            if ($this->currentDepth > $this->threshold) {
                $this->issues[] = [
                    'depth' => $this->currentDepth,
                    'line' => $node->getStartLine(),
                    'context' => $this->currentContext ?? 'global scope',
                ];
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Decrease depth when leaving nesting structures
        if ($this->isNestingStructure($node)) {
            $this->currentDepth--;
        }

        // Reset context when leaving method/function
        if ($node instanceof Stmt\Function_ || $node instanceof Stmt\ClassMethod) {
            $this->currentContext = null;
            $this->currentDepth = 0;
        }

        return null;
    }

    /**
     * Check if node creates nesting.
     */
    private function isNestingStructure(Node $node): bool
    {
        return $node instanceof Stmt\If_
            || $node instanceof Stmt\ElseIf_
            || $node instanceof Stmt\Else_
            || $node instanceof Stmt\While_
            || $node instanceof Stmt\Do_
            || $node instanceof Stmt\For_
            || $node instanceof Stmt\Foreach_
            || $node instanceof Stmt\Switch_
            || $node instanceof Stmt\TryCatch
            || $node instanceof Stmt\Catch_;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{depth: int, line: int, context: string}>
     */
    public function getIssues(): array
    {
        // Deduplicate - only report max depth per location
        $unique = [];
        $seen = [];

        foreach ($this->issues as $issue) {
            $key = $issue['line'];
            if (! isset($seen[$key]) || $issue['depth'] > $seen[$key]) {
                $unique[$key] = $issue;
                $seen[$key] = $issue['depth'];
            }
        }

        return array_values($unique);
    }
}
