<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Detects large dataset queries without chunking.
 */
class ChunkMissingAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'chunk-missing',
            name: 'Missing Chunk Analyzer',
            description: 'Detects queries on large datasets without chunk() or cursor() for memory efficiency',
            category: Category::BestPractices,
            severity: Severity::High,
            tags: ['laravel', 'performance', 'memory', 'eloquent', 'optimization'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/chunk-missing',
            timeToFix: 15
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new ChunkMissingVisitor;
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: $issue['message'],
                        filePath: $file,
                        lineNumber: $issue['line'],
                        severity: $issue['severity'],
                        recommendation: $issue['recommendation'],
                        code: $issue['code'] ?? null,
                    );
                }
            } catch (\Throwable $e) {
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('Large dataset queries use chunking appropriately');
        }

        $count = count($issues);
        $message = sprintf(
            'Found %d %s that should use chunking',
            $count,
            $count === 1 ? 'query' : 'queries'
        );

        return $this->failed($message, $issues);
    }
}

class ChunkMissingVisitor extends NodeVisitorAbstract
{
    private array $issues = [];

    /** @var array<string, Node\Expr> Track variable assignments */
    private array $variableAssignments = [];

    public function enterNode(Node $node): ?Node
    {
        // Track variable assignments with ->all() or ->get()
        if ($node instanceof Node\Expr\Assign) {
            if ($node->var instanceof Node\Expr\Variable && is_string($node->var->name)) {
                $name = $node->var->name;
                if ($this->isAllOrGetCall($node->expr)) {
                    $this->variableAssignments[$name] = $node->expr;
                } else {
                    unset($this->variableAssignments[$name]);
                }
            }
        }

        // Check foreach loops for ->all() or ->get() calls without chunking
        if ($node instanceof Node\Stmt\Foreach_) {
            $loopIterator = $node->expr;

            // Check if iterator is a direct ->all() or ->get() call
            if ($this->isAllOrGetCall($loopIterator)) {
                $this->issues[] = [
                    'message' => 'Looping over ->all() or ->get() without chunk() can cause memory issues on large datasets',
                    'line' => $node->getLine(),
                    'severity' => Severity::High,
                    'recommendation' => 'Use Model::chunk(200, function($records) { ... }) or Model::cursor() for memory-efficient iteration over large datasets. chunk() processes records in batches, cursor() uses a generator',
                    'code' => $this->getCodeSnippet($loopIterator),
                ];
            }
            // Check if iterator is a variable that was assigned with ->all() or ->get()
            elseif ($loopIterator instanceof Node\Expr\Variable && is_string($loopIterator->name)) {
                if (isset($this->variableAssignments[$loopIterator->name])) {
                    $this->issues[] = [
                        'message' => 'Looping over a variable assigned with ->all() or ->get() can cause memory issues on large datasets',
                        'line' => $node->getLine(),
                        'severity' => Severity::High,
                        'recommendation' => 'Use Model::chunk(200, function($records) { ... }) or Model::cursor() for memory-efficient iteration. Alternatively, use Model::lazy() which returns a generator',
                        'code' => $this->getCodeSnippet($loopIterator),
                    ];
                }
            }
        }

        return null;
    }

    private function isAllOrGetCall(?Node\Expr $expr): bool
    {
        if ($expr === null) {
            return false;
        }

        if (! $expr instanceof Node\Expr\MethodCall && ! $expr instanceof Node\Expr\StaticCall) {
            return false;
        }

        // Check method chain for ->all() or ->get()
        $methods = $this->getMethodChain($expr);

        if (empty($methods)) {
            return false;
        }

        // Check if chain contains all() or get() ANYWHERE (not just at end)
        // This catches: User::all()->sortBy('name'), User::get()->filter(...)
        $hasFetchMethod = in_array('all', $methods, true) || in_array('get', $methods, true);

        if (! $hasFetchMethod) {
            return false;
        }

        // If single method chain (just 'all' or 'get') and NOT a static call, skip.
        // This filters out $request->all(), $config->get(), collect()->all(), etc.
        // Eloquent calls are either static (User::all()) or have query methods (->where()->get())
        if (count($methods) === 1 && ! $this->isStaticCallChain($expr)) {
            return false;
        }

        // Safe chunking/pagination methods that handle memory efficiently
        $safeChunkingMethods = [
            'chunk', 'chunkById', 'cursor', 'lazy', 'lazyById',
            'paginate', 'simplePaginate', 'cursorPaginate',
        ];
        $hasChunking = ! empty(array_intersect($methods, $safeChunkingMethods));

        // Single-record or limited-result methods (small dataset)
        $smallDatasetMethods = [
            'limit', 'take', 'first', 'firstOrFail', 'firstWhere',
            'find', 'findOrFail', 'findOr', 'sole', 'soleOrFail', 'value',
        ];
        $hasSmallDatasetModifier = ! empty(array_intersect($methods, $smallDatasetMethods));

        return ! $hasChunking && ! $hasSmallDatasetModifier;
    }

    /**
     * Check if the expression chain originates from a static call (e.g., User::all()).
     * This helps distinguish Eloquent calls from instance method calls like $request->all().
     */
    private function isStaticCallChain(Node\Expr $expr): bool
    {
        $current = $expr;

        while ($current instanceof Node\Expr\MethodCall) {
            $current = $current->var;
        }

        return $current instanceof Node\Expr\StaticCall;
    }

    private function getMethodChain(Node\Expr $expr): array
    {
        $chain = [];
        $current = $expr;

        while ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\StaticCall) {
            if ($current->name instanceof Node\Identifier) {
                array_unshift($chain, $current->name->toString());
            }

            if ($current instanceof Node\Expr\MethodCall) {
                $current = $current->var;
            } elseif ($current instanceof Node\Expr\StaticCall) {
                // For static calls, check if the class itself is a method chain
                // e.g., SomeClass::method()->anotherMethod()
                if ($current->class instanceof Node\Expr\StaticCall || $current->class instanceof Node\Expr\MethodCall) {
                    $current = $current->class;
                } else {
                    // Reached the base class (e.g., User::where()->get())
                    break;
                }
            } else {
                break;
            }
        }

        return $chain;
    }

    /**
     * Get a code snippet from a node for display purposes.
     */
    private function getCodeSnippet(Node\Expr $expr): string
    {
        $printer = new \PhpParser\PrettyPrinter\Standard;

        return $printer->prettyPrintExpr($expr);
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}
