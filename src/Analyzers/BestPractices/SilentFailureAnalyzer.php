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
 * Detects empty catch blocks and error suppression.
 */
class SilentFailureAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'silent-failure',
            name: 'Silent Failure Analyzer',
            description: 'Detects empty catch blocks and error suppression that hide failures',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['laravel', 'exceptions', 'error-handling', 'debugging', 'monitoring'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/silent-failure',
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

                $visitor = new SilentFailureVisitor;
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
            return $this->passed('No silent failures detected');
        }

        return $this->failed(
            sprintf('Found %d silent failure(s)', count($issues)),
            $issues
        );
    }
}

class SilentFailureVisitor extends NodeVisitorAbstract
{
    private array $issues = [];

    public function enterNode(Node $node): ?Node
    {
        // Check for empty catch blocks
        if ($node instanceof Node\Stmt\TryCatch) {
            foreach ($node->catches as $catch) {
                if (empty($catch->stmts)) {
                    $this->issues[] = [
                        'message' => 'Empty catch block silently swallows exceptions',
                        'line' => $catch->getLine(),
                        'severity' => Severity::High,
                        'recommendation' => 'Never use empty catch blocks. At minimum, log the exception. If you truly need to ignore an exception, add a comment explaining why',
                        'code' => null,
                    ];
                } else {
                    // Check if catch block only has comments or minimal content
                    $hasLogging = false;
                    $hasRethrow = false;

                    foreach ($catch->stmts as $stmt) {
                        // Check for logging
                        if ($this->isLoggingStatement($stmt)) {
                            $hasLogging = true;
                        }

                        // Check for rethrow
                        if ($stmt instanceof Node\Stmt\Throw_) {
                            $hasRethrow = true;
                        }
                    }

                    if (! $hasLogging && ! $hasRethrow) {
                        $this->issues[] = [
                            'message' => 'Catch block does not log exception or rethrow',
                            'line' => $catch->getLine(),
                            'severity' => Severity::Medium,
                            'recommendation' => 'Always log caught exceptions using Log::error() or rethrow them. Silent failures make debugging extremely difficult',
                            'code' => null,
                        ];
                    }
                }
            }
        }

        // Check for error suppression operator (@)
        if ($node instanceof Node\Expr\ErrorSuppress) {
            $this->issues[] = [
                'message' => 'Error suppression operator (@) hides errors',
                'line' => $node->getLine(),
                'severity' => Severity::Medium,
                'recommendation' => 'Avoid using @ operator. Handle errors explicitly with try-catch or check return values. Error suppression makes debugging difficult',
                'code' => null,
            ];
        }

        return null;
    }

    private function isLoggingStatement(Node $stmt): bool
    {
        // Check for Log::* calls
        if ($stmt instanceof Node\Stmt\Expression) {
            $expr = $stmt->expr;
            if ($expr instanceof Node\Expr\StaticCall) {
                if ($expr->class instanceof Node\Name && $expr->class->toString() === 'Log') {
                    return true;
                }
            }

            // Check for logger() helper
            if ($expr instanceof Node\Expr\FuncCall) {
                if ($expr->name instanceof Node\Name && $expr->name->toString() === 'logger') {
                    return true;
                }
            }

            // Check for method calls like $logger->error()
            if ($expr instanceof Node\Expr\MethodCall) {
                if ($expr->name instanceof Node\Identifier) {
                    $method = $expr->name->toString();
                    if (in_array($method, ['error', 'warning', 'info', 'debug', 'log'], true)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}
