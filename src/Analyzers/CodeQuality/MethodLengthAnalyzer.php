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

/**
 * Flags methods exceeding recommended line count.
 *
 * Checks for:
 * - Methods with > threshold lines (default: 50)
 * - Counts physical lines (from opening brace to closing brace)
 * - Excludes simple getter/setter methods
 */
class MethodLengthAnalyzer extends AbstractFileAnalyzer
{
    public const DEFAULT_THRESHOLD = 50;

    /** @var array<string> */
    public const DEFAULT_EXCLUDED_PATTERNS = ['get*', 'set*', 'is*', 'has*'];

    private int $threshold;

    /** @var array<string> */
    private array $excludedPatterns;

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
            docsUrl: 'https://docs.shieldci.com/analyzers/code-quality/method-length',
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration from config file (code-quality.method-length)
        $analyzerConfig = $this->config->get('shieldci.analyzers.code-quality.method-length', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->threshold = $analyzerConfig['threshold'] ?? self::DEFAULT_THRESHOLD;
        $excludePatterns = $analyzerConfig['exclude_patterns'] ?? null;
        $this->excludedPatterns = is_array($excludePatterns) ? $excludePatterns : self::DEFAULT_EXCLUDED_PATTERNS;

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
                $issues[] = $this->createIssueWithSnippet(
                    message: "Method '{$issue['method']}' has {$issue['lines']} lines (threshold: {$threshold})",
                    filePath: $file,
                    lineNumber: $issue['line'],
                    severity: $this->getSeverityForLength($issue['lines'], $threshold),
                    recommendation: $this->getRecommendation($issue['lines'], $threshold),
                    column: null,
                    contextLines: null,
                    code: $issue['method'],
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
     * Get recommendation based on function/method length.
     */
    private function getRecommendation(int $lines, int $threshold, string $type): string
    {
        $excess = $lines - $threshold;
        $typeLabel = $type === 'function' ? 'function' : 'method';

        $base = "This {$typeLabel} has {$excess} lines above the recommended threshold. ";

        if ($lines >= $threshold * 2) {
            $base .= 'This is excessively long and should be refactored. ';
        }

        return $base."Maximum recommended length: {$threshold} lines.";
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

            // Count physical lines (from start to end of method)
            $physicalLines = $this->countPhysicalLines($node);

            if ($physicalLines > $this->threshold) {
                $this->issues[] = [
                    'method' => $methodName,
                    'lines' => $physicalLines,
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
     * Count physical lines in method.
     *
     * Counts the actual number of lines from the method declaration
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
     * @return array<int, array{method: string, lines: int, line: int}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
