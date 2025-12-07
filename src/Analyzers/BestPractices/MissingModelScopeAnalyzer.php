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
 * Detects repeated where() clauses that should be scopes.
 */
class MissingModelScopeAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'missing-model-scope',
            name: 'Missing Model Scope Detector',
            description: 'Detects repeated query patterns that should be extracted to model scopes',
            category: Category::BestPractices,
            severity: Severity::Low,
            tags: ['laravel', 'eloquent', 'reusability', 'dry'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/missing-model-scope',
            timeToFix: 15
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $queryPatterns = [];

        $phpFiles = $this->getPhpFiles();

        // First pass: collect query patterns
        foreach ($phpFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new ModelScopeCollector;
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getPatterns() as $pattern) {
                    $key = $pattern['signature'];
                    if (! isset($queryPatterns[$key])) {
                        $queryPatterns[$key] = [
                            'count' => 0,
                            'locations' => [],
                            'pattern' => $pattern['pattern'],
                        ];
                    }
                    $queryPatterns[$key]['count']++;
                    $queryPatterns[$key]['locations'][] = [
                        'file' => $file,
                        'line' => $pattern['line'],
                    ];
                }
            } catch (\Throwable $e) {
                continue;
            }
        }

        // Second pass: report repeated patterns
        foreach ($queryPatterns as $signature => $data) {
            if ($data['count'] >= 2) {
                $firstLocation = $data['locations'][0];
                $issues[] = $this->createIssue(
                    message: sprintf(
                        'Query pattern "%s" appears %d times across the codebase',
                        $data['pattern'],
                        $data['count']
                    ),
                    location: new Location(
                        $this->getRelativePath($firstLocation['file']),
                        $firstLocation['line']
                    ),
                    severity: Severity::Low,
                    recommendation: sprintf(
                        'Extract this query pattern to a model scope for reusability. Found %d occurrences at: %s',
                        $data['count'],
                        implode(', ', array_slice(array_map(fn ($loc) => basename($loc['file']).':'.$loc['line'], $data['locations']), 0, 3))
                    ),
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No repeated query patterns detected');
        }

        return $this->failed(
            sprintf('Found %d repeated query pattern(s) that should be scopes', count($issues)),
            $issues
        );
    }
}

class ModelScopeCollector extends NodeVisitorAbstract
{
    private array $patterns = [];

    public function enterNode(Node $node): ?Node
    {
        // Detect chained where() calls
        if ($node instanceof Node\Expr\MethodCall) {
            // Skip if this node itself is a where-related method
            // (it will be captured when we visit the terminal method like get(), first(), etc.)
            if ($node->name instanceof Node\Identifier) {
                $method = $node->name->toString();
                if (str_starts_with($method, 'where') || $method === 'orWhere') {
                    return null;
                }
            }

            $chain = $this->getWhereChain($node);
            if (! empty($chain)) {
                // Generate patterns for all sub-chains of length >= 2
                // This helps detect common patterns even when they appear with additional clauses
                $chainLength = count($chain);
                for ($start = 0; $start < $chainLength; $start++) {
                    for ($length = 2; $start + $length <= $chainLength; $length++) {
                        $subChain = array_slice($chain, $start, $length);
                        $signature = $this->createSignature($subChain);
                        $pattern = $this->createPattern($subChain);

                        $this->patterns[] = [
                            'signature' => $signature,
                            'pattern' => $pattern,
                            'line' => $node->getLine(),
                        ];
                    }
                }
            }
        }

        return null;
    }

    private function getWhereChain(Node\Expr\MethodCall $node): array
    {
        $chain = [];
        $current = $node;

        // Walk up the chain (handle both MethodCall and StaticCall)
        while ($current !== null) {
            if ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\StaticCall) {
                if ($current->name instanceof Node\Identifier) {
                    $method = $current->name->toString();

                    // Only collect where-related methods
                    if (str_starts_with($method, 'where') || in_array($method, ['orWhere'], true)) {
                        $args = [];
                        foreach ($current->args as $arg) {
                            if ($arg->value instanceof Node\Scalar\String_ || $arg->value instanceof Node\Scalar\LNumber) {
                                $args[] = $arg->value->value;
                            } elseif ($arg->value instanceof Node\Expr\ConstFetch) {
                                $args[] = $arg->value->name->toString();
                            }
                        }

                        array_unshift($chain, [
                            'method' => $method,
                            'args' => $args,
                        ]);
                    }
                }

                // Get the next node in the chain
                // MethodCall has 'var', StaticCall doesn't continue the chain
                $current = $current instanceof Node\Expr\MethodCall ? $current->var : null;
            } else {
                break;
            }
        }

        // Only return if we have multiple where clauses
        return count($chain) >= 2 ? $chain : [];
    }

    /**
     * @param  array<int, array{method: string, args: array<int, string|int>}>  $chain
     */
    private function createSignature(array $chain): string
    {
        $parts = [];
        foreach ($chain as $call) {
            $parts[] = $call['method'].'('.implode(',', $call['args']).')';
        }

        return implode('->', $parts);
    }

    /**
     * @param  array<int, array{method: string, args: array<int, string|int>}>  $chain
     */
    private function createPattern(array $chain): string
    {
        $parts = [];
        foreach ($chain as $call) {
            if (empty($call['args'])) {
                $parts[] = $call['method'].'(...)';
            } else {
                $parts[] = $call['method'].'(\''.implode('\', \'', array_slice($call['args'], 0, 2)).'\', ...)';
            }
        }

        return implode('->', $parts);
    }

    public function getPatterns(): array
    {
        return $this->patterns;
    }
}
