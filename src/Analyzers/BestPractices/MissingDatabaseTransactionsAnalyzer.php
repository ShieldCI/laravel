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
 * Detects multiple database write operations without transactions.
 *
 * Checks for:
 * - 2+ write operations (create, update, delete, save) in method
 * - No DB::transaction() wrapper
 * - Risk of partial data updates on failure
 */
class MissingDatabaseTransactionsAnalyzer extends AbstractFileAnalyzer
{
    public const WRITE_OPERATION_THRESHOLD = 2;

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'missing-database-transactions',
            name: 'Missing Database Transactions Detector',
            description: 'Detects multiple database write operations without transaction protection',
            category: Category::BestPractices,
            severity: Severity::High,
            tags: ['laravel', 'database', 'transactions', 'data-integrity', 'acid'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/missing-database-transactions',
            timeToFix: 25
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

                $visitor = new TransactionVisitor;
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
                // Skip files with parse errors
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('All multiple write operations are properly wrapped in transactions');
        }

        return $this->failed(
            sprintf('Found %d method(s) with multiple writes missing transaction protection', count($issues)),
            $issues
        );
    }
}

/**
 * Visitor to detect missing transactions.
 */
class TransactionVisitor extends NodeVisitorAbstract
{
    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    private ?string $currentMethodName = null;

    private ?string $currentClassName = null;

    private int $writeOperations = 0;

    private bool $hasTransaction = false;

    private int $methodStartLine = 0;

    private array $writeOperationLines = [];

    public function enterNode(Node $node): ?Node
    {
        // Track current class
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClassName = $node->name?->toString();
        }

        // Track current method
        if ($node instanceof Node\Stmt\ClassMethod) {
            $this->currentMethodName = $node->name->toString();
            $this->methodStartLine = $node->getStartLine();
            $this->writeOperations = 0;
            $this->hasTransaction = false;
            $this->writeOperationLines = [];
        }

        // Check for DB::transaction
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name && $node->class->toString() === 'DB') {
                if ($node->name instanceof Node\Identifier && $node->name->toString() === 'transaction') {
                    $this->hasTransaction = true;
                }
            }
        }

        // Check for DB::beginTransaction
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name && $node->class->toString() === 'DB') {
                if ($node->name instanceof Node\Identifier && $node->name->toString() === 'beginTransaction') {
                    $this->hasTransaction = true;
                }
            }
        }

        // Detect write operations
        if ($this->isWriteOperation($node)) {
            $this->writeOperations++;
            $this->writeOperationLines[] = $node->getLine();
        }

        return null;
    }

    public function leaveNode(Node $node): ?Node
    {
        // When leaving a method, check if we need transactions
        if ($node instanceof Node\Stmt\ClassMethod) {
            if ($this->writeOperations >= MissingDatabaseTransactionsAnalyzer::WRITE_OPERATION_THRESHOLD
                && ! $this->hasTransaction
            ) {
                $this->issues[] = [
                    'message' => sprintf(
                        'Method "%s::%s()" has %d write operations without transaction protection',
                        $this->currentClassName ?? 'Unknown',
                        $this->currentMethodName ?? 'unknown',
                        $this->writeOperations
                    ),
                    'line' => $this->methodStartLine,
                    'severity' => Severity::High,
                    'recommendation' => sprintf(
                        'Wrap multiple write operations in DB::transaction() to ensure data integrity. '.
                        'If any operation fails, all changes will be rolled back. '.
                        'Write operations found at lines: %s',
                        implode(', ', $this->writeOperationLines)
                    ),
                    'code' => null,
                ];
            }
        }

        return null;
    }

    /**
     * @return array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }

    private function isWriteOperation(Node $node): bool
    {
        // Static method calls: Model::create(), Model::update(), etc.
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->name instanceof Node\Identifier) {
                $method = $node->name->toString();
                $writeMethods = ['create', 'insert', 'update', 'delete', 'forceDelete', 'upsert'];
                if (in_array($method, $writeMethods, true)) {
                    return true;
                }
            }
        }

        // Method calls: $model->save(), $model->delete(), etc.
        if ($node instanceof Node\Expr\MethodCall) {
            if ($node->name instanceof Node\Identifier) {
                $method = $node->name->toString();
                $writeMethods = [
                    'save', 'delete', 'forceDelete', 'update',
                    'increment', 'decrement', 'touch',
                    'create', 'insert', 'updateOrCreate', 'firstOrCreate',
                ];
                if (in_array($method, $writeMethods, true)) {
                    return true;
                }
            }
        }

        // Relationship sync/attach/detach
        if ($node instanceof Node\Expr\MethodCall) {
            if ($node->name instanceof Node\Identifier) {
                $method = $node->name->toString();
                $relationMethods = ['sync', 'attach', 'detach', 'toggle', 'syncWithoutDetaching'];
                if (in_array($method, $relationMethods, true)) {
                    return true;
                }
            }
        }

        return false;
    }
}
