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
 * Detects catching generic Exception instead of specific types.
 */
class GenericExceptionCatchAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'generic-exception-catch',
            name: 'Generic Exception Catch Analyzer',
            description: 'Detects catching generic Exception class instead of specific exception types',
            category: Category::BestPractices,
            severity: Severity::Low,
            tags: ['laravel', 'exceptions', 'error-handling', 'specificity'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/generic-exception-catch',
            timeToFix: 20
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

                $visitor = new GenericExceptionVisitor;
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
            return $this->passed('All exception catches use specific exception types');
        }

        return $this->failed(
            sprintf('Found %d generic exception catch(es)', count($issues)),
            $issues
        );
    }
}

class GenericExceptionVisitor extends NodeVisitorAbstract
{
    private array $issues = [];

    public function enterNode(Node $node): ?Node
    {
        if ($node instanceof Node\Stmt\TryCatch) {
            foreach ($node->catches as $catch) {
                foreach ($catch->types as $type) {
                    $typeName = $type->toString();
                    if ($typeName === 'Exception' || $typeName === '\\Exception' || $typeName === 'Throwable' || $typeName === '\\Throwable') {
                        $this->issues[] = [
                            'message' => sprintf('Catching generic %s instead of specific exception type', $typeName),
                            'line' => $catch->getLine(),
                            'severity' => Severity::Low,
                            'recommendation' => 'Catch specific exception types (e.g., ModelNotFoundException, ValidationException) for better error handling and to avoid catching unexpected errors',
                            'code' => null,
                        ];
                    }
                }
            }
        }

        return null;
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}
