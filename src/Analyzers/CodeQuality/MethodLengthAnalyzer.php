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
 * Flags methods exceeding recommended line count.
 *
 * Checks for:
 * - Methods with > threshold lines (default: 50)
 * - Counts logical lines (excluding comments/whitespace)
 * - Excludes simple getter/setter methods
 */
class MethodLengthAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Default line count threshold.
     */
    private int $threshold = 50;

    /**
     * @var array<string>
     */
    private array $excludedPatterns = ['get*', 'set*', 'is*', 'has*'];

    public function __construct(
        private ParserInterface $parser
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
            docsUrl: 'https://docs.shieldci.com/analyzers/code-quality/method-length',
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $threshold = $this->threshold;
        $excludePatterns = $this->excludedPatterns;

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new MethodLengthVisitor($threshold, $excludePatterns);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Method '{$issue['method']}' has {$issue['lines']} lines (threshold: {$threshold})",
                    location: new Location($file, $issue['line']),
                    severity: $this->getSeverityForLength($issue['lines'], $threshold),
                    recommendation: $this->getRecommendation($issue['lines'], $threshold),
                    metadata: [
                        'method' => $issue['method'],
                        'lines' => $issue['lines'],
                        'threshold' => $threshold,
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No methods exceeding length threshold detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} method(s) exceeding recommended length",
            $issues
        );
    }

    /**
     * Get severity based on length.
     */
    private function getSeverityForLength(int $lines, int $threshold): Severity
    {
        $ratio = $lines / $threshold;

        if ($ratio >= 2.0) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Get recommendation based on method length.
     */
    private function getRecommendation(int $lines, int $threshold): string
    {
        $excess = $lines - $threshold;

        $base = "This method has {$excess} lines above the recommended threshold. ";

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

        return $base.'Recommended actions: '.implode('; ', $recommendations).'. Maximum recommended length: 30-50 lines.';
    }
}

/**
 * Visitor to count method lines.
 */
class MethodLengthVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{method: string, lines: int, line: int}>
     */
    private array $issues = [];

    /**
     * @param  array<string>  $excludePatterns
     */
    public function __construct(
        private int $threshold,
        private array $excludePatterns = []
    ) {}

    public function enterNode(Node $node)
    {
        if ($node instanceof Stmt\Function_ || $node instanceof Stmt\ClassMethod) {
            $methodName = $node->name->toString();

            // Check if method matches exclude patterns
            if ($this->shouldExclude($methodName)) {
                return null;
            }

            $startLine = $node->getStartLine();

            // Count logical lines (statements)
            $logicalLines = $this->countLogicalLines($node);

            if ($logicalLines > $this->threshold) {
                $this->issues[] = [
                    'method' => $methodName,
                    'lines' => $logicalLines,
                    'line' => $startLine,
                ];
            }
        }

        return null;
    }

    /**
     * Check if method name matches exclude patterns.
     */
    private function shouldExclude(string $methodName): bool
    {
        foreach ($this->excludePatterns as $pattern) {
            // Convert glob pattern to regex (escape special chars, then replace * with .*)
            $escaped = preg_quote($pattern, '/');
            $regex = '/^'.str_replace('\\*', '.*', $escaped).'$/i';
            if (preg_match($regex, $methodName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Count logical lines (statements) in method.
     */
    private function countLogicalLines(Node $node): int
    {
        if (! $node instanceof Stmt\Function_ && ! $node instanceof Stmt\ClassMethod) {
            return 0;
        }

        $stmts = $node->stmts;
        if ($stmts === null) {
            return 0;
        }

        return $this->countStatements($stmts);
    }

    /**
     * Recursively count statements.
     *
     * @param  array<Node\Stmt>  $stmts
     */
    private function countStatements(array $stmts): int
    {
        $count = 0;

        foreach ($stmts as $stmt) {
            $count++; // Count this statement

            // Count nested statements
            if ($stmt instanceof Stmt\If_) {
                $count += $this->countStatements($stmt->stmts);
                foreach ($stmt->elseifs as $elseif) {
                    $count += $this->countStatements($elseif->stmts);
                }
                if ($stmt->else !== null) {
                    $count += $this->countStatements($stmt->else->stmts);
                }
            } elseif ($stmt instanceof Stmt\While_) {
                $count += $this->countStatements($stmt->stmts);
            } elseif ($stmt instanceof Stmt\Do_) {
                $count += $this->countStatements($stmt->stmts);
            } elseif ($stmt instanceof Stmt\For_) {
                $count += $this->countStatements($stmt->stmts);
            } elseif ($stmt instanceof Stmt\Foreach_) {
                $count += $this->countStatements($stmt->stmts);
            } elseif ($stmt instanceof Stmt\Switch_) {
                foreach ($stmt->cases as $case) {
                    $count += $this->countStatements($case->stmts);
                }
            } elseif ($stmt instanceof Stmt\TryCatch) {
                $count += $this->countStatements($stmt->stmts);
                foreach ($stmt->catches as $catch) {
                    $count += $this->countStatements($catch->stmts);
                }
                if ($stmt->finally !== null) {
                    $count += $this->countStatements($stmt->finally->stmts);
                }
            }
        }

        return $count;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{method: string, lines: int, line: int}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
