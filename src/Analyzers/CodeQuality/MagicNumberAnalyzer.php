<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\CodeQuality;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\ParentConnectingVisitor;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects hard-coded numbers that should be constants.
 *
 * Checks for:
 * - Numeric literals that aren't common values (0, 1, -1, 100)
 * - Excludes array indices and increments
 * - Flags numbers used multiple times
 */
class MagicNumberAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Numbers to exclude from detection (common values).
     *
     * @var array<int|float>
     */
    private array $excludedNumbers = [0, 1, -1, 2, 10, 100, 1000];

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'magic-number',
            name: 'Magic Number',
            description: 'Detects hard-coded numbers that should be named constants for better maintainability',
            category: Category::CodeQuality,
            severity: Severity::Low,
            tags: ['maintainability', 'code-quality', 'readability', 'constants'],
            docsUrl: 'https://refactoring.guru/replace-magic-number-with-symbolic-constant'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $excludedNumbers = $this->excludedNumbers;

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new MagicNumberVisitor($excludedNumbers);
            $traverser = new NodeTraverser;
            $traverser->addVisitor(new ParentConnectingVisitor); // Connect parent nodes
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Magic number '{$issue['value']}' found in {$issue['context']}",
                    location: new Location($file, $issue['line']),
                    severity: $issue['count'] > 2 ? Severity::Medium : Severity::Low,
                    recommendation: $this->getRecommendation($issue['value'], $issue['count']),
                    metadata: [
                        'value' => $issue['value'],
                        'context' => $issue['context'],
                        'usage_count' => $issue['count'],
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No magic numbers detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} magic number(s) that should be constants",
            $issues
        );
    }

    /**
     * Get recommendation for magic number.
     */
    private function getRecommendation(string|int|float $value, int $count): string
    {
        $base = 'Replace this magic number with a named constant. ';

        if ($count > 2) {
            $base .= "This number appears {$count} times in the file, making it especially important to use a constant. ";
        }

        $examples = [
            "Example: const MAX_RETRIES = {$value};",
            "Or use a configuration value: config('app.setting_name')",
            'Named constants improve code readability and maintainability',
            'Changes to the value only need to be made in one place',
        ];

        return $base.implode('. ', $examples).'.';
    }
}

/**
 * Visitor to detect magic numbers.
 */
class MagicNumberVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{value: int|float|string, line: int, context: string, count: int}>
     */
    private array $issues = [];

    /**
     * Track number occurrences.
     *
     * @var array<int|string, int>
     */
    private array $numberCounts = [];

    /**
     * Track number locations.
     *
     * @var array<int|string, array{line: int, context: string}>
     */
    private array $numberLocations = [];

    /**
     * @param  array<int|float>  $excludedNumbers
     */
    public function __construct(
        private array $excludedNumbers = []
    ) {}

    public function enterNode(Node $node)
    {
        // Look for numeric literals
        if ($node instanceof Scalar\LNumber || $node instanceof Scalar\DNumber) {
            $value = $node->value;

            // Skip excluded numbers
            if (in_array($value, $this->excludedNumbers, true)) {
                return null;
            }

            // Skip if used as array key/index
            if ($this->isArrayIndex($node)) {
                return null;
            }

            // Skip if used in increment/decrement
            if ($this->isIncrementDecrement($node)) {
                return null;
            }

            // Skip if in a default parameter value
            if ($this->isDefaultParameter($node)) {
                return null;
            }

            // Skip if in a constant declaration
            if ($this->isConstantDeclaration($node)) {
                return null;
            }

            $key = (string) $value;
            $context = $this->getContext($node);

            // Track occurrence
            if (! isset($this->numberCounts[$key])) {
                $this->numberCounts[$key] = 0;
                $this->numberLocations[$key] = [
                    'line' => $node->getStartLine(),
                    'context' => $context,
                ];
            }
            $this->numberCounts[$key]++;
        }

        return null;
    }

    public function afterTraverse(array $nodes)
    {
        // Report all magic numbers found
        foreach ($this->numberCounts as $value => $count) {
            $location = $this->numberLocations[$value];
            $this->issues[] = [
                'value' => $value,
                'line' => $location['line'],
                'context' => $location['context'],
                'count' => $count,
            ];
        }

        return null;
    }

    /**
     * Check if number is used as array index.
     */
    private function isArrayIndex(Node $node): bool
    {
        $parent = $node->getAttribute('parent');

        if ($parent instanceof Expr\ArrayDimFetch) {
            return $parent->dim === $node;
        }

        return false;
    }

    /**
     * Check if number is used in increment/decrement.
     */
    private function isIncrementDecrement(Node $node): bool
    {
        $parent = $node->getAttribute('parent');

        if ($parent instanceof Expr\AssignOp\Plus || $parent instanceof Expr\AssignOp\Minus) {
            return true;
        }

        if ($parent instanceof Expr\BinaryOp\Plus || $parent instanceof Expr\BinaryOp\Minus) {
            // Check if it's a simple +1 or -1 operation
            if (($node instanceof Scalar\LNumber || $node instanceof Scalar\DNumber) &&
                ($node->value === 1 || $node->value === -1)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if number is a default parameter value.
     */
    private function isDefaultParameter(Node $node): bool
    {
        $parent = $node->getAttribute('parent');

        return $parent instanceof Node\Param;
    }

    /**
     * Check if number is in a constant declaration.
     */
    private function isConstantDeclaration(Node $node): bool
    {
        $parent = $node->getAttribute('parent');

        // Check if direct parent is a constant declaration
        if ($parent instanceof Node\Stmt\ClassConst || $parent instanceof Node\Stmt\Const_) {
            return true;
        }

        // Check if parent is a ConstConst (the const item within ClassConst)
        if ($parent instanceof Node\Const_) {
            return true;
        }

        return false;
    }

    /**
     * Get context description for the number.
     */
    private function getContext(Node $node): string
    {
        $parent = $node->getAttribute('parent');

        if ($parent instanceof Expr\BinaryOp) {
            return 'binary operation';
        }

        if ($parent instanceof Expr\FuncCall || $parent instanceof Expr\MethodCall) {
            return 'function/method call';
        }

        if ($parent instanceof Expr\Assign) {
            return 'assignment';
        }

        if ($parent instanceof Node\Stmt\Return_) {
            return 'return statement';
        }

        if ($parent instanceof Expr\Ternary) {
            return 'ternary expression';
        }

        return 'expression';
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{value: int|float|string, line: int, context: string, count: int}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
