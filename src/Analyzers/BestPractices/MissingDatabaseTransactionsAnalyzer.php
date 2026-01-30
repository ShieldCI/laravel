<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
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
    public const DEFAULT_THRESHOLD = 2;

    private int $threshold;

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'missing-database-transactions',
            name: 'Missing Database Transactions Analyzer',
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
        // Load configuration from config file (best-practices.missing-database-transactions)
        $analyzerConfig = $this->config->get('shieldci.analyzers.best-practices.missing-database-transactions', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->threshold = $analyzerConfig['threshold'] ?? self::DEFAULT_THRESHOLD;

        $issues = [];

        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            // Skip test and development files
            if ($this->isTestFile($file) || $this->isDevelopmentFile($file)) {
                continue;
            }

            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new TransactionVisitor($this->threshold);
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

    /**
     * Check if file is a test file.
     */
    private function isTestFile(string $file): bool
    {
        return str_contains($file, '/tests/') ||
               str_contains($file, '/Tests/') ||
               str_ends_with($file, 'Test.php');
    }

    /**
     * Check if file is a development helper file.
     */
    private function isDevelopmentFile(string $file): bool
    {
        return str_contains($file, '/database/seeders/') ||
               str_contains($file, '/database/factories/') ||
               str_contains($file, '/database/migrations/') ||
               str_ends_with($file, 'Seeder.php') ||
               str_ends_with($file, 'Factory.php');
    }
}

/**
 * Visitor to detect missing transactions.
 */
class TransactionVisitor extends NodeVisitorAbstract
{
    /**
     * Facades that have methods looking like DB writes but aren't database operations.
     */
    private const NON_DB_FACADES = [
        'Cache', 'Redis', 'RateLimiter', 'Session', 'Storage', 'Queue',
    ];

    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    private ?string $currentMethodName = null;

    private ?string $currentClassName = null;

    private int $writeOperations = 0;

    private int $writeOperationsInTransaction = 0;

    private bool $hasTransaction = false;

    private int $methodStartLine = 0;

    /** @var list<int> */
    private array $writeOperationLines = [];

    private int $transactionDepth = 0;

    private int $manualTransactionDepth = 0;

    /**
     * Track file positions of closures passed directly to DB::transaction().
     *
     * @var array<int, true>
     */
    private array $transactionClosurePositions = [];

    public function __construct(
        private int $threshold
    ) {}

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
            $this->writeOperationsInTransaction = 0;
            $this->hasTransaction = false;
            $this->writeOperationLines = [];
            $this->transactionDepth = 0;
            $this->manualTransactionDepth = 0;
            $this->transactionClosurePositions = [];
        }

        // Check for DB::transaction or DB::beginTransaction
        if ($node instanceof Node\Expr\StaticCall) {
            if ($this->isTransactionCall($node)) {
                $this->hasTransaction = true;

                // If it's beginTransaction, mark that we're in a manual transaction
                // (it's typically called before a try block)
                if ($node->name instanceof Node\Identifier) {
                    $methodName = $node->name->toString();
                    if ($methodName === 'beginTransaction') {
                        $this->manualTransactionDepth++;
                    } elseif ($methodName === 'transaction' && ! empty($node->args)) {
                        // Track the closure passed to DB::transaction()
                        $firstArg = $node->args[0]->value;
                        if ($firstArg instanceof Node\Expr\Closure || $firstArg instanceof Node\Expr\ArrowFunction) {
                            $this->transactionClosurePositions[$firstArg->getStartFilePos()] = true;
                        }
                    }
                }
            }

            // Check for transaction end (commit/rollBack)
            // If we see commit/rollBack, it proves transactions are being used
            // (even if beginTransaction is in another method/class)
            if ($this->isTransactionEndCall($node)) {
                $this->hasTransaction = true;
                if ($this->manualTransactionDepth > 0) {
                    $this->manualTransactionDepth--;
                }
            }
        }

        // Track entering transaction closure (only closures actually passed to DB::transaction)
        if ($node instanceof Node\Expr\Closure || $node instanceof Node\Expr\ArrowFunction) {
            $pos = $node->getStartFilePos();
            if (isset($this->transactionClosurePositions[$pos])) {
                $this->transactionDepth++;
            }
        }

        // Detect write operations
        if ($this->isWriteOperation($node)) {
            $this->writeOperations++;
            $this->writeOperationLines[] = $node->getLine();

            // Track if write is inside a transaction
            // Writes are protected if:
            // 1. Inside a DB::transaction() closure, OR
            // 2. After DB::beginTransaction() was called (with or without try-catch)
            if ($this->transactionDepth > 0 || $this->manualTransactionDepth > 0) {
                $this->writeOperationsInTransaction++;
            }
        }

        return null;
    }

    public function leaveNode(Node $node): ?Node
    {
        // Track leaving transaction closure (only decrement for closures actually in transaction)
        if ($node instanceof Node\Expr\Closure || $node instanceof Node\Expr\ArrowFunction) {
            $pos = $node->getStartFilePos();
            if (isset($this->transactionClosurePositions[$pos]) && $this->transactionDepth > 0) {
                $this->transactionDepth--;
            }
        }

        // When leaving a method, check if we need transactions
        if ($node instanceof Node\Stmt\ClassMethod) {
            // Calculate unprotected writes (writes outside transaction scope)
            $unprotectedWrites = $this->writeOperations - $this->writeOperationsInTransaction;

            // Report issue if:
            // 1. Total writes >= threshold AND no transaction exists, OR
            // 2. Transaction exists but unprotected writes >= threshold
            if ($this->writeOperations >= $this->threshold) {
                if (! $this->hasTransaction || $unprotectedWrites >= $this->threshold) {
                    $this->issues[] = [
                        'message' => sprintf(
                            'Method "%s::%s()" has %d write operations without transaction protection',
                            $this->currentClassName ?? 'Unknown',
                            $this->currentMethodName ?? 'unknown',
                            $unprotectedWrites > 0 ? $unprotectedWrites : $this->writeOperations
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

    private function isTransactionCall(Node\Expr\StaticCall $node): bool
    {
        if ($node->class instanceof Node\Name) {
            $className = $node->class->toString();
            if ($className === 'DB') {
                if ($node->name instanceof Node\Identifier) {
                    $method = $node->name->toString();

                    return in_array($method, ['transaction', 'beginTransaction'], true);
                }
            }
        }

        return false;
    }

    /**
     * Check if the call is a transaction end (commit or rollBack).
     */
    private function isTransactionEndCall(Node\Expr\StaticCall $node): bool
    {
        if ($node->class instanceof Node\Name) {
            $className = $node->class->toString();
            if ($className === 'DB') {
                if ($node->name instanceof Node\Identifier) {
                    $method = $node->name->toString();

                    return in_array($method, ['commit', 'rollBack'], true);
                }
            }
        }

        return false;
    }

    /**
     * Extract short class name from a Node\Name, using resolved FQN if available.
     */
    private function getShortClassName(Node\Name $name): string
    {
        $resolvedName = $name->getAttribute('resolvedName');
        $fqn = $resolvedName instanceof Node\Name\FullyQualified
            ? $resolvedName->toString()
            : $name->toString();
        $normalized = ltrim($fqn, '\\');

        $parts = explode('\\', $normalized);

        return end($parts) ?: $normalized;
    }

    /**
     * Check if a static call is on a non-database facade.
     */
    private function isNonDbFacadeCall(Node\Expr\StaticCall $node): bool
    {
        if ($node->class instanceof Node\Name) {
            $shortName = $this->getShortClassName($node->class);

            return in_array($shortName, self::NON_DB_FACADES, true);
        }

        return false;
    }

    /**
     * Check if a method call chain originates from a non-database facade.
     */
    private function isNonDbFacadeChain(Node\Expr\MethodCall $node): bool
    {
        $current = $node->var;

        // Walk up the chain to find the root
        while ($current instanceof Node\Expr\MethodCall) {
            $current = $current->var;
        }

        // Check if root is a static call on a non-DB facade
        if ($current instanceof Node\Expr\StaticCall && $current->class instanceof Node\Name) {
            $shortName = $this->getShortClassName($current->class);

            return in_array($shortName, self::NON_DB_FACADES, true);
        }

        return false;
    }

    private function isWriteOperation(Node $node): bool
    {
        // Static method calls
        if ($node instanceof Node\Expr\StaticCall) {
            // Skip non-database facades (Cache, Redis, etc.)
            if ($this->isNonDbFacadeCall($node)) {
                return false;
            }

            if ($node->name instanceof Node\Identifier) {
                $method = $node->name->toString();

                // First check if this is a DB class method
                if ($node->class instanceof Node\Name && $node->class->toString() === 'DB') {
                    // Exclude transaction management methods
                    if (in_array($method, ['transaction', 'beginTransaction', 'commit', 'rollBack'], true)) {
                        return false;
                    }

                    // Check for DB facade write methods
                    $dbWriteMethods = ['insert', 'update', 'delete', 'statement'];
                    if (in_array($method, $dbWriteMethods, true)) {
                        return true;
                    }
                }

                // Check for Model static write methods
                $writeMethods = [
                    'create', 'insert', 'update', 'delete', 'forceDelete',
                    'upsert', 'updateOrInsert', 'updateOrCreate', 'firstOrCreate',
                ];
                if (in_array($method, $writeMethods, true)) {
                    return true;
                }
            }
        }

        // Method calls: $model->save(), $model->delete(), etc.
        // Also includes query builder chained calls like DB::table()->update()
        if ($node instanceof Node\Expr\MethodCall) {
            // Skip method calls on non-database facade chains
            if ($this->isNonDbFacadeChain($node)) {
                return false;
            }

            if ($node->name instanceof Node\Identifier) {
                $method = $node->name->toString();
                $writeMethods = [
                    'save', 'delete', 'forceDelete', 'update',
                    'increment', 'decrement', 'touch',
                    'create', 'insert', 'updateOrCreate', 'firstOrCreate', 'updateOrInsert',
                    'upsert',
                ];
                if (in_array($method, $writeMethods, true)) {
                    return true;
                }

                // Relationship sync/attach/detach
                $relationMethods = ['sync', 'attach', 'detach', 'toggle', 'syncWithoutDetaching'];
                if (in_array($method, $relationMethods, true)) {
                    return true;
                }
            }
        }

        return false;
    }
}
