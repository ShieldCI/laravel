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
 * Detects duplicate or very similar code blocks.
 *
 * Checks for:
 * - Consecutive similar lines (threshold: 6+ lines)
 * - Similar method implementations
 * - AST-based similarity comparison
 */
class DuplicateCodeAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Minimum number of consecutive similar lines to flag.
     */
    private int $minLines = 6;

    /**
     * Similarity threshold (0-100).
     */
    private float $similarityThreshold = 85.0;

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'duplicate-code',
            name: 'Duplicate Code',
            description: 'Detects duplicate or very similar code blocks that should be refactored into reusable methods',
            category: Category::CodeQuality,
            severity: Severity::Medium,
            tags: ['duplication', 'maintainability', 'code-quality', 'dry', 'refactoring'],
            docsUrl: 'https://refactoring.guru/smells/duplicate-code'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $minLines = $this->minLines;
        $similarityThreshold = $this->similarityThreshold;

        // Collect all method bodies for comparison
        $methods = [];

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new DuplicateCodeVisitor($file);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getMethods() as $method) {
                $methods[] = $method;
            }
        }

        // Compare methods for duplication
        $compared = [];
        foreach ($methods as $i => $method1) {
            foreach ($methods as $j => $method2) {
                // Skip self-comparison and already compared pairs
                if ($i >= $j) {
                    continue;
                }

                $key = min($i, $j).'_'.max($i, $j);
                if (isset($compared[$key])) {
                    continue;
                }
                $compared[$key] = true;

                // Skip if same file and method name (same method)
                if ($method1['file'] === $method2['file'] && $method1['name'] === $method2['name']) {
                    continue;
                }

                // Calculate similarity
                $similarity = $this->calculateSimilarity($method1['normalized'], $method2['normalized']);

                if ($similarity >= $similarityThreshold && $method1['lineCount'] >= $minLines) {
                    $issues[] = $this->createIssue(
                        message: "Duplicate code detected: '{$method1['name']}' and '{$method2['name']}' are {$similarity}% similar",
                        location: new Location($method1['file'], $method1['line']),
                        severity: $this->getSeverityForSimilarity($similarity, $method1['lineCount']),
                        recommendation: $this->getRecommendation($method1['name'], $method2['name'], $similarity, $method1['lineCount']),
                        metadata: [
                            'method1' => $method1['name'],
                            'method2' => $method2['name'],
                            'file1' => $method1['file'],
                            'file2' => $method2['file'],
                            'line1' => $method1['line'],
                            'line2' => $method2['line'],
                            'similarity' => $similarity,
                            'lineCount' => $method1['lineCount'],
                        ]
                    );
                }
            }
        }

        if (empty($issues)) {
            return $this->passed('No duplicate code blocks detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} duplicate code block(s)",
            $issues
        );
    }

    /**
     * Calculate similarity between two code blocks.
     */
    private function calculateSimilarity(string $code1, string $code2): float
    {
        if (empty($code1) || empty($code2)) {
            return 0.0;
        }

        // Use Levenshtein distance for small strings, similar_text for larger ones
        $len1 = strlen($code1);
        $len2 = strlen($code2);

        if ($len1 > 255 || $len2 > 255) {
            // Use similar_text for longer strings
            similar_text($code1, $code2, $percent);

            return round($percent, 2);
        }

        // Use Levenshtein distance
        $distance = levenshtein($code1, $code2);
        $maxLen = max($len1, $len2);

        if ($maxLen === 0) {
            return 100.0;
        }

        $similarity = (1 - ($distance / $maxLen)) * 100;

        return round(max(0, $similarity), 2);
    }

    /**
     * Get severity based on similarity and line count.
     */
    private function getSeverityForSimilarity(float $similarity, int $lineCount): Severity
    {
        // High similarity in many lines is more severe
        if ($similarity >= 95 && $lineCount >= 20) {
            return Severity::High;
        }

        if ($similarity >= 90 || $lineCount >= 30) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Get recommendation for duplicate code.
     */
    private function getRecommendation(string $method1, string $method2, float $similarity, int $lineCount): string
    {
        $base = "Methods '{$method1}' and '{$method2}' contain {$lineCount} lines of {$similarity}% similar code. This violates the DRY (Don't Repeat Yourself) principle. ";

        $strategies = [
            'Extract the common logic into a shared private method',
            'Create a base class with the shared functionality if methods are in related classes',
            'Use composition or strategy pattern for varying behavior',
            'Consider creating a service class for shared business logic',
            'If the similarity is in data structure, create a value object or DTO',
            'Use template method pattern if the overall algorithm is same but steps differ',
        ];

        $example = <<<'PHP'

// Problem - Duplicate code:
class OrderProcessor {
    public function processOnlineOrder($order) {
        $this->validateOrder($order);
        $this->calculateTax($order);
        $this->applyDiscount($order);
        $this->processPayment($order);
        $this->sendConfirmation($order);
    }

    public function processPhoneOrder($order) {
        $this->validateOrder($order);
        $this->calculateTax($order);
        $this->applyDiscount($order);
        $this->processPayment($order);
        $this->sendConfirmation($order);
    }
}

// Solution - Extract common logic:
class OrderProcessor {
    public function processOnlineOrder($order) {
        $this->processOrder($order);
        // Online-specific logic
    }

    public function processPhoneOrder($order) {
        $this->processOrder($order);
        // Phone-specific logic
    }

    private function processOrder($order) {
        $this->validateOrder($order);
        $this->calculateTax($order);
        $this->applyDiscount($order);
        $this->processPayment($order);
        $this->sendConfirmation($order);
    }
}
PHP;

        return $base.'Refactoring strategies: '.implode('; ', $strategies).". Example:{$example}";
    }
}

/**
 * Visitor to collect method bodies for duplication analysis.
 */
class DuplicateCodeVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{name: string, file: string, line: int, code: string, normalized: string, lineCount: int}>
     */
    private array $methods = [];

    /**
     * Current class name.
     */
    private ?string $currentClass = null;

    public function __construct(
        private string $file
    ) {}

    public function enterNode(Node $node)
    {
        // Track class entry
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = $node->name ? $node->name->toString() : 'Anonymous';

            return null;
        }

        // Collect method bodies
        if ($node instanceof Stmt\ClassMethod) {
            $methodName = $node->name->toString();

            // Skip magic methods and very short methods
            if (str_starts_with($methodName, '__')) {
                return null;
            }

            if ($node->stmts === null || count($node->stmts) < 3) {
                return null;
            }

            $code = $this->getMethodCode($node);
            $normalized = $this->normalizeCode($code);
            $lineCount = $this->countLogicalLines($node);

            $this->methods[] = [
                'name' => ($this->currentClass ?? 'Unknown').'::'.$methodName,
                'file' => $this->file,
                'line' => $node->getStartLine(),
                'code' => $code,
                'normalized' => $normalized,
                'lineCount' => $lineCount,
            ];
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Clear class context on exit
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = null;
        }

        return null;
    }

    /**
     * Get method code as string.
     */
    private function getMethodCode(Stmt\ClassMethod $node): string
    {
        if ($node->stmts === null) {
            return '';
        }

        $code = [];
        foreach ($node->stmts as $stmt) {
            $code[] = $this->nodeToString($stmt);
        }

        return implode("\n", $code);
    }

    /**
     * Convert AST node to string representation.
     */
    private function nodeToString(Node $node): string
    {
        // Simplified serialization - in production, use PrettyPrinter
        return serialize($node);
    }

    /**
     * Normalize code for comparison.
     */
    private function normalizeCode(string $code): string
    {
        // Remove whitespace variations
        $normalized = preg_replace('/\s+/', ' ', $code) ?? $code;

        // Remove comments
        $normalized = preg_replace('/\/\*.*?\*\//s', '', $normalized) ?? $normalized;
        $normalized = preg_replace('/\/\/.*$/m', '', $normalized) ?? $normalized;

        // Normalize variable names (replace with placeholders)
        $normalized = preg_replace('/\$[a-zA-Z_]\w*/', '$var', $normalized) ?? $normalized;

        // Normalize string literals
        $normalized = preg_replace('/"[^"]*"/', '"str"', $normalized) ?? $normalized;
        $normalized = preg_replace("/'[^']*'/", "'str'", $normalized) ?? $normalized;

        // Normalize numbers
        $normalized = preg_replace('/\b\d+\b/', '0', $normalized) ?? $normalized;

        return trim($normalized);
    }

    /**
     * Count logical lines (statements).
     */
    private function countLogicalLines(Stmt\ClassMethod $node): int
    {
        if ($node->stmts === null) {
            return 0;
        }

        return count($node->stmts);
    }

    /**
     * Get collected methods.
     *
     * @return array<int, array{name: string, file: string, line: int, code: string, normalized: string, lineCount: int}>
     */
    public function getMethods(): array
    {
        return $this->methods;
    }
}
