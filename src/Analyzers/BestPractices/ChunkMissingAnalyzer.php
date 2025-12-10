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
use ShieldCI\AnalyzersCore\ValueObjects\Location;

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
            name: 'Missing Chunk Detector',
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
                    $issues[] = $this->createIssue(
                        message: $issue['message'],
                        location: new Location($this->getRelativePath($file), $issue['line']),
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

        return $this->failed(
            sprintf('Found %d query/queries that should use chunking', count($issues)),
            $issues
        );
    }
}

class ChunkMissingVisitor extends NodeVisitorAbstract
{
    private array $issues = [];

    public function enterNode(Node $node): ?Node
    {
        // Check foreach loops for ->all() or ->get() calls without chunking
        if ($node instanceof Node\Stmt\Foreach_) {
            $loopIterator = $node->expr;

            // Check if iterator is a ->all() or ->get() call without chunk/cursor
            if ($this->isAllOrGetCall($loopIterator)) {
                $this->issues[] = [
                    'message' => 'Looping over ->all() or ->get() without chunk() can cause memory issues on large datasets',
                    'line' => $node->getLine(),
                    'severity' => Severity::High,
                    'recommendation' => 'Use Model::chunk(200, function($records) { ... }) or Model::cursor() for memory-efficient iteration over large datasets. chunk() processes records in batches, cursor() uses a generator',
                    'code' => null,
                ];
            }
        }

        return null;
    }

    private function isAllOrGetCall(?Node\Expr $expr): bool
    {
        if (! $expr instanceof Node\Expr\MethodCall && ! $expr instanceof Node\Expr\StaticCall) {
            return false;
        }

        // Check method chain for ->all() or ->get()
        $methods = $this->getMethodChain($expr);

        // If chain ends with all() or get() and doesn't have chunk/cursor
        $endsWithFetch = in_array(end($methods), ['all', 'get'], true);
        $hasChunking = in_array('chunk', $methods, true) || in_array('cursor', $methods, true) || in_array('lazy', $methods, true);

        return $endsWithFetch && ! $hasChunking;
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
            } else {
                break;
            }
        }

        return $chain;
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}
