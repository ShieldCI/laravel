<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\CodeQuality;

use Illuminate\Contracts\Config\Repository as Config;
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
    public const DEFAULT_THRESHOLD = 4;

    private int $threshold;

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'nesting-depth',
            name: 'Nesting Depth Analyzer',
            description: 'Identifies deeply nested code blocks that reduce readability and maintainability',
            category: Category::CodeQuality,
            severity: Severity::Medium,
            tags: ['complexity', 'maintainability', 'code-quality', 'readability'],
            docsUrl: 'https://docs.shieldci.com/analyzers/code-quality/nesting-depth',
            timeToFix: 20
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration from config file (code_quality.nesting-depth)
        $analyzerConfig = $this->config->get('shieldci.analyzers.code_quality.nesting-depth', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->threshold = $analyzerConfig['threshold'] ?? self::DEFAULT_THRESHOLD;

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
                    location: new Location($this->getRelativePath($file), $issue['line']),
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

        return $base.'Refactoring strategies: '.implode('; ', $strategies);
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

    /**
     * Stack of contexts for nested functions/closures.
     *
     * @var array<string>
     */
    private array $contextStack = [];

    /**
     * Stack of depths for nested functions/closures.
     *
     * @var array<int>
     */
    private array $depthStack = [];

    public function __construct(
        private int $threshold
    ) {}

    public function enterNode(Node $node)
    {
        // Track method/function/closure entry
        if ($node instanceof Stmt\Function_ || $node instanceof Stmt\ClassMethod || $node instanceof Node\Expr\Closure) {
            // Save current context and depth
            if ($this->currentContext !== null) {
                $this->contextStack[] = $this->currentContext;
                $this->depthStack[] = $this->currentDepth;
            }

            // Set new context
            if ($node instanceof Node\Expr\Closure) {
                $this->currentContext = '{closure}';
            } else {
                $this->currentContext = $node->name->toString();
            }

            // Reset depth for new function scope
            $this->currentDepth = 0;

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

        // Restore context when leaving method/function/closure
        if ($node instanceof Stmt\Function_ || $node instanceof Stmt\ClassMethod || $node instanceof Node\Expr\Closure) {
            // Restore previous context if we were in a nested function
            if (! empty($this->contextStack)) {
                $this->currentContext = array_pop($this->contextStack);
                $this->currentDepth = array_pop($this->depthStack) ?? 0;
            } else {
                $this->currentContext = null;
                $this->currentDepth = 0;
            }
        }

        return null;
    }

    /**
     * Check if node creates nesting.
     *
     * Note: ElseIf and Else are NOT counted as separate nesting levels
     * because they are continuations of the if statement, not new nesting.
     * Similarly, Catch blocks are part of TryCatch and don't add nesting.
     */
    private function isNestingStructure(Node $node): bool
    {
        return $node instanceof Stmt\If_
            || $node instanceof Stmt\While_
            || $node instanceof Stmt\Do_
            || $node instanceof Stmt\For_
            || $node instanceof Stmt\Foreach_
            || $node instanceof Stmt\Switch_
            || $node instanceof Stmt\Case_
            || $node instanceof Stmt\TryCatch;
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
