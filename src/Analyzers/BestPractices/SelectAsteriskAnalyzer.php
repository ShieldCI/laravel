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
 * Detects SELECT * (implicit in Eloquent) when only few columns needed.
 */
class SelectAsteriskAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'select-asterisk',
            name: 'Select Asterisk Detector',
            description: 'Detects queries fetching all columns when only specific columns are needed',
            category: Category::BestPractices,
            severity: Severity::Low,
            tags: ['laravel', 'performance', 'database', 'optimization'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/select-asterisk',
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

                $visitor = new SelectAsteriskVisitor;
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
            return $this->passed('Queries select only needed columns');
        }

        return $this->failed(
            sprintf('Found %d query/queries that could benefit from column selection', count($issues)),
            $issues
        );
    }
}

class SelectAsteriskVisitor extends NodeVisitorAbstract
{
    private array $issues = [];

    public function enterNode(Node $node): ?Node
    {
        // Detect Model::all(), Model::get(), etc. without ->select()
        if ($node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall) {
            if ($node->name instanceof Node\Identifier) {
                $method = $node->name->toString();

                // Check for fetch methods
                if (in_array($method, ['all', 'get', 'first', 'find'], true)) {
                    $chain = $this->getMethodChain($node);

                    // If no 'select' in chain, might be fetching all columns
                    if (! in_array('select', $chain, true)) {
                        $this->issues[] = [
                            'message' => sprintf('Query using ->%s() without ->select() fetches all columns', $method),
                            'line' => $node->getLine(),
                            'severity' => Severity::Low,
                            'recommendation' => 'Use ->select([\'col1\', \'col2\']) to fetch only needed columns. This reduces memory usage and network transfer, especially important for tables with many columns or BLOB/TEXT fields',
                            'code' => null,
                        ];
                    }
                }
            }
        }

        return null;
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
