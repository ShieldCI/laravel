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
use ShieldCI\Concerns\ClassifiesFiles;

/**
 * Flags methods and functions exceeding recommended line count.
 *
 * Checks for:
 * - Methods and functions with > threshold lines (default: 50)
 * - Counts physical lines (from declaration to closing brace)
 * - Excludes simple getter/setter patterns (get*, set*, is*, has*) only if ≤ 10 lines
 * - Large methods matching exclude patterns are still flagged (prevents hiding real problems)
 * - Skips development/data files (seeders, migrations, factories, tests) where method
 *   length measures data/schema volume rather than code complexity
 * - Differentiates between global functions and class methods in messaging
 */
class MethodLengthAnalyzer extends AbstractFileAnalyzer
{
    use ClassifiesFiles;

    public const DEFAULT_THRESHOLD = 50;

    /** @var array<string> */
    public const DEFAULT_EXCLUDED_PATTERNS = ['get*', 'set*', 'is*', 'has*'];

    /**
     * Maximum lines for a method/function to be considered a "simple" getter/setter.
     * Methods matching exclude patterns but exceeding this will still be flagged.
     */
    public const SIMPLE_ACCESSOR_MAX_LINES = 10;

    /**
     * Maximum number of top-level statements a method may have to still qualify as a
     * declarative fluent-builder (e.g. Filament form()/table()/panel(), migration up()).
     * Such methods derive their length from configuration size, not branching logic.
     */
    public const MAX_DECLARATIVE_STATEMENTS = 5;

    private int $threshold;

    /** @var array<string> */
    private array $excludedPatterns;

    private int $simpleAccessorMaxLines;

    private bool $ignoreFluentChains;

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'method-length',
            name: 'Method Length Analyzer',
            description: 'Flags methods exceeding recommended line count for better maintainability',
            category: Category::CodeQuality,
            severity: Severity::Low,
            tags: ['complexity', 'maintainability', 'code-quality', 'readability'],
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration from config file (code-quality.method-length)
        $analyzerConfig = $this->config->get('shieldci.analyzers.code-quality.method-length', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $thresholdVal = $analyzerConfig['threshold'] ?? self::DEFAULT_THRESHOLD;
        $this->threshold = is_int($thresholdVal) ? $thresholdVal : self::DEFAULT_THRESHOLD;
        $excludePatterns = $analyzerConfig['exclude_patterns'] ?? null;
        $this->excludedPatterns = is_array($excludePatterns) ? array_values(array_filter($excludePatterns, 'is_string')) : self::DEFAULT_EXCLUDED_PATTERNS;
        $simpleAccessorVal = $analyzerConfig['simple_accessor_max_lines'] ?? self::SIMPLE_ACCESSOR_MAX_LINES;
        $this->simpleAccessorMaxLines = is_int($simpleAccessorVal) ? $simpleAccessorVal : self::SIMPLE_ACCESSOR_MAX_LINES;
        $ignoreFluentVal = $analyzerConfig['ignore_fluent_chains'] ?? true;
        $this->ignoreFluentChains = is_bool($ignoreFluentVal) ? $ignoreFluentVal : true;

        $issues = [];
        $threshold = $this->threshold;
        $excludePatterns = $this->excludedPatterns;
        $simpleAccessorMaxLines = $this->simpleAccessorMaxLines;
        $ignoreFluentChains = $this->ignoreFluentChains;

        foreach ($this->getPhpFiles() as $file) {
            // Skip development/data files (seeders, migrations, factories, tests):
            // their methods are data dumps or schema definitions whose length reflects
            // data volume, not code complexity — flagging them is noise.
            if ($this->isTestFile($file) || $this->isDevelopmentFile($file)) {
                continue;
            }

            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new MethodLengthVisitor($threshold, $excludePatterns, $simpleAccessorMaxLines, $ignoreFluentChains);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $type = ucfirst($issue['type']); // 'function' -> 'Function', 'method' -> 'Method'
                $issues[] = $this->createIssueWithSnippet(
                    message: "{$type} '{$issue['name']}' has {$issue['lines']} lines (threshold: {$threshold})",
                    filePath: $file,
                    lineNumber: $issue['line'],
                    severity: $this->getSeverityForLength($issue['lines'], $threshold),
                    recommendation: $this->getRecommendation($issue['lines'], $threshold, $issue['type']),
                    column: null,
                    contextLines: null,
                    metadata: [
                        'name' => $issue['name'],
                        'type' => $issue['type'],
                        'lines' => $issue['lines'],
                        'threshold' => $threshold,
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No methods or functions exceeding length threshold detected');
        }

        $totalIssues = count($issues);

        return $this->resultBySeverity(
            "Found {$totalIssues} method(s) or function(s) exceeding recommended length",
            $issues
        );
    }

    /**
     * Get severity based on length.
     */
    private function getSeverityForLength(int $lines, int $threshold): Severity
    {
        $threshold = max(1, $threshold);
        $ratio = $lines / $threshold;

        if ($ratio >= 3.0) {
            return Severity::High;
        }
        if ($ratio >= 2.0) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Get recommendation based on function/method length.
     */
    private function getRecommendation(int $lines, int $threshold, string $type): string
    {
        $excess = $lines - $threshold;
        $typeLabel = $type === 'function' ? 'function' : 'method';

        $base = "This {$typeLabel} has {$excess} lines above the recommended threshold. ";

        $recommendations = [
            'Extract logical steps into separate, well-named methods',
            'Apply the Single Responsibility Principle',
            'Look for repeated code blocks that can be extracted',
            'Consider if this method is doing more than one thing',
            'Refactor to make the code more maintainable and testable',
        ];

        if ($lines >= $threshold * 2) {
            $base .= 'This is excessively long and should be refactored. ';
        }

        return $base.'Recommended actions: '.implode('; ', $recommendations).". Maximum recommended length: {$threshold} lines.";
    }
}

/**
 * Visitor to count method and function lines.
 */
class MethodLengthVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{name: string, lines: int, line: int, type: string}>
     */
    private array $issues = [];

    /**
     * @param  array<string>  $excludePatterns
     * @param  int  $simpleAccessorMaxLines  Maximum lines for a method to be considered a simple accessor
     * @param  bool  $ignoreFluentChains  Skip declarative single-expression builder methods
     */
    public function __construct(
        private int $threshold,
        private array $excludePatterns = [],
        private int $simpleAccessorMaxLines = MethodLengthAnalyzer::SIMPLE_ACCESSOR_MAX_LINES,
        private bool $ignoreFluentChains = true
    ) {}

    public function enterNode(Node $node)
    {
        if ($node instanceof Stmt\Function_ || $node instanceof Stmt\ClassMethod) {
            $name = $node->name->toString();
            $type = $node instanceof Stmt\Function_ ? 'function' : 'method';
            $startLine = $node->getStartLine();

            // Count physical lines (from start to end)
            $physicalLines = $this->countPhysicalLines($node);

            // Only exclude if it matches pattern AND is small (simple accessor)
            if ($this->shouldExclude($name, $physicalLines)) {
                return null;
            }

            // Declarative fluent-builder methods (Filament form()/table(), migration
            // up(), route definitions) get their length from configuration size, not
            // branching complexity — exclude them when enabled.
            if ($this->ignoreFluentChains && $this->isDeclarativeFluentMethod($node)) {
                return null;
            }

            if ($physicalLines > $this->threshold) {
                $this->issues[] = [
                    'name' => $name,
                    'lines' => $physicalLines,
                    'line' => $startLine,
                    'type' => $type,
                ];
            }
        }

        return null;
    }

    /**
     * Check if function/method should be excluded.
     *
     * Only excludes if:
     * 1. Name matches exclude patterns (get*, set*, is*, has*)
     * 2. AND is small enough to be a simple accessor (configurable threshold)
     *
     * This prevents large methods like getUsersWithComplexFiltering() from being excluded.
     */
    private function shouldExclude(string $name, int $lines): bool
    {
        // If it's large, never exclude it (even if it matches a pattern)
        if ($lines > $this->simpleAccessorMaxLines) {
            return false;
        }

        foreach ($this->excludePatterns as $pattern) {
            // Convert glob pattern to regex (escape special chars, then replace * with .*)
            $escaped = preg_quote($pattern, '/');
            $regex = '/^'.str_replace('\\*', '.*', $escaped).'$/i';
            if (preg_match($regex, $name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether a method/function is a declarative fluent-builder.
     *
     * These methods consist of a handful of top-level statements that build or
     * return a fluent chain / nested array (e.g. Filament form()/table()/panel(),
     * a migration's Schema::create() call, or a route group). Their physical length
     * tracks how much configuration they declare, not branching logic, so counting
     * lines produces noise. Control flow nested inside callback closures (e.g.
     * ->action(fn () => ...) or the Blueprint closure) is intentionally ignored —
     * only the method's own top-level statements are inspected.
     */
    private function isDeclarativeFluentMethod(Node $node): bool
    {
        if (! $node instanceof Stmt\Function_ && ! $node instanceof Stmt\ClassMethod) {
            return false;
        }

        $stmts = $node->stmts;
        if ($stmts === null || $stmts === []) {
            return false;
        }

        if (count($stmts) > MethodLengthAnalyzer::MAX_DECLARATIVE_STATEMENTS) {
            return false;
        }

        $hasChainOrArray = false;

        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Return_) {
                $expr = $stmt->expr;
            } elseif ($stmt instanceof Stmt\Expression) {
                $expr = $stmt->expr;
            } else {
                // Any other top-level statement (control flow, echo, etc.) means the
                // method is not a pure declarative builder.
                return false;
            }

            if ($expr === null) {
                return false;
            }

            // Unwrap assignments to inspect the assigned value.
            if ($expr instanceof Node\Expr\Assign) {
                $expr = $expr->expr;
            }

            if (! $this->isBuilderExpression($expr)) {
                return false;
            }

            if ($this->isFluentChainOrArray($expr)) {
                $hasChainOrArray = true;
            }
        }

        return $hasChainOrArray;
    }

    /**
     * A builder expression is a call, instantiation, or array literal — the kinds of
     * expressions a declarative method is built from. Scalars, variables, and
     * operators disqualify the statement.
     */
    private function isBuilderExpression(Node\Expr $expr): bool
    {
        return $expr instanceof Node\Expr\MethodCall
            || $expr instanceof Node\Expr\StaticCall
            || $expr instanceof Node\Expr\New_
            || $expr instanceof Node\Expr\Array_;
    }

    /**
     * Detect the signature of a builder DSL: a fluent method chain (a call chained
     * off another call) or a call carrying an array/closure argument (e.g.
     * $form->schema([...]) or Schema::create('t', fn () => ...)).
     */
    private function isFluentChainOrArray(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\Array_) {
            return true;
        }

        if (
            $expr instanceof Node\Expr\MethodCall
            && ($expr->var instanceof Node\Expr\MethodCall || $expr->var instanceof Node\Expr\StaticCall)
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\StaticCall) {
            foreach ($expr->args as $arg) {
                if (! $arg instanceof Node\Arg) {
                    continue;
                }

                $value = $arg->value;
                if (
                    $value instanceof Node\Expr\Array_
                    || $value instanceof Node\Expr\Closure
                    || $value instanceof Node\Expr\ArrowFunction
                ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Count physical lines in function or method.
     *
     * Counts the actual number of lines from the declaration
     * to the closing brace, matching what developers see in their editor.
     */
    private function countPhysicalLines(Node $node): int
    {
        if (! $node instanceof Stmt\Function_ && ! $node instanceof Stmt\ClassMethod) {
            return 0;
        }

        $startLine = $node->getStartLine();
        $endLine = $node->getEndLine();

        // Return the number of lines (inclusive)
        return $endLine - $startLine + 1;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{name: string, lines: int, line: int, type: string}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
