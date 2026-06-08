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
use ShieldCI\Concerns\ClassifiesFiles;

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
    use ClassifiesFiles;

    /**
     * Minimum number of writes that require full transactional atomicity.
     */
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

        // Phase 0: Build Eloquent model registry from all project PHP files.
        $modelScanner = new EloquentModelScanner;
        foreach ($phpFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }
                $ast = $this->parser->resolveNames($ast, ['replaceNodes' => false]);
                $registryTraverser = new NodeTraverser;
                $registryTraverser->addVisitor($modelScanner);
                $registryTraverser->traverse($ast);
            } catch (\Throwable) {
                continue;
            }
        }
        $classParents = $modelScanner->getParents();

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

                $ast = $this->parser->resolveNames($ast, ['replaceNodes' => false]);

                $scanner = new TransactionDelegatedMethodScanner;
                $preScanTraverser = new NodeTraverser;
                $preScanTraverser->addVisitor($scanner);
                $preScanTraverser->traverse($ast);

                $visitor = new TransactionVisitor($this->threshold, $scanner->getDelegatedMethods(), $classParents);
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

        return $this->resultBySeverity(
            sprintf('Found %d location(s) with multiple writes missing transaction protection', count($issues)),
            $issues
        );
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

    private int $methodStartLine = 0;

    /** @var list<int> */
    private array $unprotectedWriteLines = [];

    private int $transactionDepth = 0;

    private int $manualTransactionDepth = 0;

    private int $isolatedWrites = 0;

    private int $earlyExitIfDepth = 0;

    /**
     * Heaviest sibling-closure contribution for the current scope. Independent
     * callback closures (e.g. Filament ->action(fn...)) are mutually-exclusive
     * dispatch paths that never co-execute, so — like if/else branches — only the
     * heaviest one counts toward the enclosing scope, not the sum of all of them.
     */
    private int $maxClosureWrites = 0;

    private int $maxClosureUnprotected = 0;

    /** @var list<int> Unprotected write lines of the heaviest sibling closure. */
    private array $maxClosureLines = [];

    /** Declaration line of the heaviest sibling closure, used to locate the issue. */
    private int $maxClosureLine = 0;

    /**
     * Stack of saved parent-scope counters while traversing a callback closure.
     * Each callback closure is its own write-counting unit; on entry we snapshot
     * and reset the counters, on exit we restore them and fold the closure in as a
     * sibling (max), never summing across siblings.
     *
     * @var list<array{
     *   writeOperations: int,
     *   writeOperationsInTransaction: int,
     *   unprotectedWriteLines: list<int>,
     *   isolatedWrites: int,
     *   earlyExitIfDepth: int,
     *   earlyExitIfPositions: array<int, true>,
     *   guardClauseElsePositions: array<int, true>,
     *   ifElseBranchStack: list<array{pos: int, elsePos: int, inElse: bool, ifWrites: int, elseWrites: int, ifLines: list<int>, elseLines: list<int>}>,
     *   maxClosureWrites: int,
     *   maxClosureUnprotected: int,
     *   maxClosureLines: list<int>,
     *   maxClosureLine: int
     * }>
     */
    private array $closureScopeStack = [];

    /**
     * Track file positions of closures passed directly to DB::transaction().
     *
     * @var array<int, true>
     */
    private array $transactionClosurePositions = [];

    /**
     * Track file start positions of guard-clause if-blocks.
     *
     * @var array<int, true>
     */
    private array $earlyExitIfPositions = [];

    /**
     * Track file start positions of else-blocks that belong to a guard-clause if.
     * Writes inside these elses are in the main flow (the if-body terminated early).
     *
     * @var array<int, true>
     */
    private array $guardClauseElsePositions = [];

    /**
     * Stack for tracking plain if/else branches (no elseif, if-body does not terminate).
     * Because only one branch executes per request, we count only the heavier branch
     * (max write count) toward the threshold rather than summing both branches.
     *
     * Each frame:
     *   pos        — file start position of the If_ node
     *   elsePos    — file start position of the Else_ node
     *   inElse     — whether we are currently traversing the else-body
     *   ifWrites   — total write count in the if-body (protected + unprotected)
     *   elseWrites — total write count in the else-body
     *   ifLines    — unprotected write lines in the if-body
     *   elseLines  — unprotected write lines in the else-body
     *
     * @var list<array{pos: int, elsePos: int, inElse: bool, ifWrites: int, elseWrites: int, ifLines: list<int>, elseLines: list<int>}>
     */
    private array $ifElseBranchStack = [];

    /**
     * @param  array<string, true>  $transactionDelegatedMethods
     * @param  array<string, string|null>  $classParents
     */
    public function __construct(
        private int $threshold,
        private array $transactionDelegatedMethods = [],
        private array $classParents = [],
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
            $this->unprotectedWriteLines = [];
            // Start inside a virtual transaction if this method is exclusively called
            // from within DB::transaction() closures (determined by the pre-scan).
            $this->transactionDepth = isset($this->transactionDelegatedMethods[$this->currentMethodName]) ? 1 : 0;
            $this->manualTransactionDepth = 0;
            $this->isolatedWrites = 0;
            $this->earlyExitIfDepth = 0;
            $this->transactionClosurePositions = [];
            $this->earlyExitIfPositions = [];
            $this->guardClauseElsePositions = [];
            $this->ifElseBranchStack = [];
            $this->maxClosureWrites = 0;
            $this->maxClosureUnprotected = 0;
            $this->maxClosureLines = [];
            $this->maxClosureLine = 0;
            $this->closureScopeStack = [];
        }

        // Check for DB::transaction or DB::beginTransaction
        if ($node instanceof Node\Expr\StaticCall) {
            if ($this->isTransactionCall($node)) {
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
            if ($this->isTransactionEndCall($node)) {
                if ($this->manualTransactionDepth > 0) {
                    $this->manualTransactionDepth--;
                }
            }
        }

        // Track entering a closure. A closure passed directly to DB::transaction()
        // marks protection (transactionDepth). Any other callback closure is an
        // independent execution unit (e.g. a Filament ->action(fn...) handler that
        // fires on a separate request) and gets its own write-counting scope.
        if ($node instanceof Node\Expr\Closure || $node instanceof Node\Expr\ArrowFunction) {
            $pos = $node->getStartFilePos();
            if (isset($this->transactionClosurePositions[$pos])) {
                $this->transactionDepth++;
            } else {
                $this->pushClosureScope();
            }
        }

        // Track guard clause if-blocks (early-exit ifs — if-body always terminates)
        if ($node instanceof Node\Stmt\If_ && $this->isGuardClauseIf($node)) {
            $this->earlyExitIfPositions[$node->getStartFilePos()] = true;
            $this->earlyExitIfDepth++;
            // If there is an else, writes inside it are in the main flow (not isolated),
            // so we record it to temporarily reduce depth when we enter that else.
            if ($node->else !== null) {
                $this->guardClauseElsePositions[$node->else->getStartFilePos()] = true;
            }
        }

        // When entering an else that belongs to a guard-clause if: temporarily reduce depth
        // so that writes inside the else are counted as main-flow writes.
        if ($node instanceof Node\Stmt\Else_) {
            $pos = $node->getStartFilePos();
            if (isset($this->guardClauseElsePositions[$pos])) {
                $this->earlyExitIfDepth--;
            }
        }

        // Track plain if/else branches (if-body does not terminate, has no elseif).
        // Only push when outside a guard clause, transaction, and other tracked branch so
        // that the simpler existing mechanisms handle those cases without interference.
        if (
            $node instanceof Node\Stmt\If_
            && ! $this->isGuardClauseIf($node)
            && $node->else !== null
            && empty($node->elseifs)
            && $this->earlyExitIfDepth === 0
            && $this->transactionDepth === 0
            && $this->manualTransactionDepth === 0
        ) {
            $this->ifElseBranchStack[] = [
                'pos' => $node->getStartFilePos(),
                'elsePos' => $node->else->getStartFilePos(),
                'inElse' => false,
                'ifWrites' => 0,
                'elseWrites' => 0,
                'ifLines' => [],
                'elseLines' => [],
            ];
        }

        // When entering the else-body of a tracked if/else: switch the active branch.
        if ($node instanceof Node\Stmt\Else_ && $this->ifElseBranchStack !== []) {
            $lastIdx = count($this->ifElseBranchStack) - 1;
            if ($this->ifElseBranchStack[$lastIdx]['elsePos'] === $node->getStartFilePos()) {
                $this->ifElseBranchStack[$lastIdx]['inElse'] = true;
            }
        }

        // Detect write operations
        if ($this->isWriteOperation($node)) {
            if ($this->transactionDepth > 0 || $this->manualTransactionDepth > 0) {
                // Protected write. Always tally in writeOperationsInTransaction.
                // If inside a tracked if/else branch, defer the writeOperations increment
                // to frame-pop so only the heavier branch counts; otherwise count now.
                $this->writeOperationsInTransaction++;
                if ($this->ifElseBranchStack !== []) {
                    $lastIdx = count($this->ifElseBranchStack) - 1;
                    if ($this->ifElseBranchStack[$lastIdx]['inElse']) {
                        $this->ifElseBranchStack[$lastIdx]['elseWrites']++;
                    } else {
                        $this->ifElseBranchStack[$lastIdx]['ifWrites']++;
                    }
                } else {
                    $this->writeOperations++;
                }
            } elseif ($this->earlyExitIfDepth > 0) {
                // Inside a guard-clause if-body: isolated from all subsequent writes.
                $this->writeOperations++;
                $this->isolatedWrites++;
            } elseif ($this->ifElseBranchStack !== []) {
                // Unprotected write inside a tracked if/else branch: defer accounting.
                $lastIdx = count($this->ifElseBranchStack) - 1;
                if ($this->ifElseBranchStack[$lastIdx]['inElse']) {
                    $this->ifElseBranchStack[$lastIdx]['elseWrites']++;
                    $this->ifElseBranchStack[$lastIdx]['elseLines'][] = $node->getLine();
                } else {
                    $this->ifElseBranchStack[$lastIdx]['ifWrites']++;
                    $this->ifElseBranchStack[$lastIdx]['ifLines'][] = $node->getLine();
                }
            } else {
                // Normal unprotected main-flow write.
                $this->writeOperations++;
                $this->unprotectedWriteLines[] = $node->getLine();
            }
        }

        return null;
    }

    public function leaveNode(Node $node): ?Node
    {
        // Track leaving a closure: decrement transaction depth for a DB::transaction()
        // closure, otherwise fold the independent callback closure back into its
        // parent scope as a sibling (max, not sum).
        if ($node instanceof Node\Expr\Closure || $node instanceof Node\Expr\ArrowFunction) {
            $pos = $node->getStartFilePos();
            if (isset($this->transactionClosurePositions[$pos])) {
                if ($this->transactionDepth > 0) {
                    $this->transactionDepth--;
                }
            } else {
                $this->popClosureScope($node);
            }
        }

        // Decrement guard clause depth when leaving an early-exit if-block
        if ($node instanceof Node\Stmt\If_) {
            $pos = $node->getStartFilePos();
            if (isset($this->earlyExitIfPositions[$pos])) {
                $this->earlyExitIfDepth--;
                unset($this->earlyExitIfPositions[$pos]);
            }
        }

        // Pop a plain if/else frame on leaving its If_ node. Commit only the heavier branch
        // (by write count) to the parent frame or the main-flow counters, discarding the
        // writes of the lighter branch that can never co-execute on the same request.
        if ($node instanceof Node\Stmt\If_ && $this->ifElseBranchStack !== []) {
            $lastIdx = count($this->ifElseBranchStack) - 1;
            if ($this->ifElseBranchStack[$lastIdx]['pos'] === $node->getStartFilePos()) {
                $frame = $this->ifElseBranchStack[$lastIdx];
                array_pop($this->ifElseBranchStack);

                $effectiveWrites = max($frame['ifWrites'], $frame['elseWrites']);
                // Use the heavier branch's unprotected lines for the recommendation.
                $effectiveLines = $frame['ifWrites'] >= $frame['elseWrites']
                    ? $frame['ifLines']
                    : $frame['elseLines'];

                if ($this->ifElseBranchStack !== []) {
                    // Nested inside another tracked branch: propagate into that branch.
                    $parentIdx = count($this->ifElseBranchStack) - 1;
                    if ($this->ifElseBranchStack[$parentIdx]['inElse']) {
                        $this->ifElseBranchStack[$parentIdx]['elseWrites'] += $effectiveWrites;
                        $this->ifElseBranchStack[$parentIdx]['elseLines'] = array_merge(
                            $this->ifElseBranchStack[$parentIdx]['elseLines'],
                            $effectiveLines
                        );
                    } else {
                        $this->ifElseBranchStack[$parentIdx]['ifWrites'] += $effectiveWrites;
                        $this->ifElseBranchStack[$parentIdx]['ifLines'] = array_merge(
                            $this->ifElseBranchStack[$parentIdx]['ifLines'],
                            $effectiveLines
                        );
                    }
                } else {
                    // Top-level: commit to main-flow counters.
                    $this->writeOperations += $effectiveWrites;
                    $this->unprotectedWriteLines = array_merge(
                        $this->unprotectedWriteLines,
                        $effectiveLines
                    );
                }
            }
        }

        // Restore depth when leaving the else of a guard-clause if
        if ($node instanceof Node\Stmt\Else_) {
            $pos = $node->getStartFilePos();
            if (isset($this->guardClauseElsePositions[$pos])) {
                $this->earlyExitIfDepth++;
                unset($this->guardClauseElsePositions[$pos]);
            }
        }

        // When leaving a method, check if we need transactions
        if ($node instanceof Node\Stmt\ClassMethod) {
            // Isolated writes are in guard clauses (early-exit branches) that can never
            // co-execute with writes in the main flow, so exclude them from the threshold.
            $mainFlowWrites = $this->writeOperations - $this->isolatedWrites;
            $mainFlowUnprotected = $mainFlowWrites - $this->writeOperationsInTransaction;

            // Fold in the heaviest sibling callback closure. Main-flow writes co-execute
            // with whichever single callback fires, so we add the heaviest closure's
            // counts; sibling closures never co-execute with each other, so they are
            // not summed (only the max is kept).
            $effectiveWrites = $mainFlowWrites + $this->maxClosureWrites;
            $effectiveUnprotected = $mainFlowUnprotected + $this->maxClosureUnprotected;

            // If all effective writes are protected, no issue
            if ($effectiveUnprotected <= 0) {
                return null;
            }

            // If effective writes >= threshold, they should be protected
            if ($effectiveWrites >= $this->threshold) {
                // When every unprotected write lives inside a callback closure (the
                // method's own body has none), attribute the issue to that closure's
                // location instead of the method declaration. Otherwise a long Filament
                // table()/form() would be reported at its signature line, far from the
                // offending callback (e.g. an ->action(fn ...) handler).
                $closureDriven = $mainFlowUnprotected <= 0 && $this->maxClosureLine > 0;

                $subject = $closureDriven
                    ? sprintf('Closure in "%s::%s()"', $this->currentClassName ?? 'Unknown', $this->currentMethodName ?? 'unknown')
                    : sprintf('Method "%s::%s()"', $this->currentClassName ?? 'Unknown', $this->currentMethodName ?? 'unknown');

                $this->issues[] = [
                    'message' => sprintf(
                        '%s has %d database write operation(s) outside transaction protection',
                        $subject,
                        $effectiveUnprotected
                    ),
                    'line' => $closureDriven ? $this->maxClosureLine : $this->methodStartLine,
                    'severity' => Severity::High,
                    'recommendation' => sprintf(
                        'Wrap all related write operations in a database transaction to ensure atomicity. '.
                        'Unprotected write operations at lines: %s',
                        implode(', ', array_merge($this->unprotectedWriteLines, $this->maxClosureLines))
                    ),
                    'code' => null,
                ];
            }
        }

        return null;
    }

    /**
     * Snapshot the current scope's write counters and reset them so the callback
     * closure body is counted as its own independent unit. Transaction depth is
     * intentionally inherited, so a synchronous closure inside DB::transaction()
     * remains protected.
     */
    private function pushClosureScope(): void
    {
        $this->closureScopeStack[] = [
            'writeOperations' => $this->writeOperations,
            'writeOperationsInTransaction' => $this->writeOperationsInTransaction,
            'unprotectedWriteLines' => $this->unprotectedWriteLines,
            'isolatedWrites' => $this->isolatedWrites,
            'earlyExitIfDepth' => $this->earlyExitIfDepth,
            'earlyExitIfPositions' => $this->earlyExitIfPositions,
            'guardClauseElsePositions' => $this->guardClauseElsePositions,
            'ifElseBranchStack' => $this->ifElseBranchStack,
            'maxClosureWrites' => $this->maxClosureWrites,
            'maxClosureUnprotected' => $this->maxClosureUnprotected,
            'maxClosureLines' => $this->maxClosureLines,
            'maxClosureLine' => $this->maxClosureLine,
        ];

        $this->writeOperations = 0;
        $this->writeOperationsInTransaction = 0;
        $this->unprotectedWriteLines = [];
        $this->isolatedWrites = 0;
        $this->earlyExitIfDepth = 0;
        $this->earlyExitIfPositions = [];
        $this->guardClauseElsePositions = [];
        $this->ifElseBranchStack = [];
        $this->maxClosureWrites = 0;
        $this->maxClosureUnprotected = 0;
        $this->maxClosureLines = [];
        $this->maxClosureLine = 0;
    }

    /**
     * Restore the parent scope's counters and fold this closure in as a sibling:
     * its effective writes (own main flow + its own heaviest child closure)
     * contribute to the parent via max(), never summed across siblings.
     */
    private function popClosureScope(Node $closure): void
    {
        if ($this->closureScopeStack === []) {
            return;
        }

        // Effective metrics for the closure we are leaving (mirror the method check).
        $closureMainWrites = $this->writeOperations - $this->isolatedWrites;
        $closureMainUnprotected = $closureMainWrites - $this->writeOperationsInTransaction;
        $effClosureWrites = $closureMainWrites + $this->maxClosureWrites;
        $effClosureUnprotected = $closureMainUnprotected + $this->maxClosureUnprotected;
        $effClosureLines = array_merge($this->unprotectedWriteLines, $this->maxClosureLines);

        $frame = array_pop($this->closureScopeStack);

        $this->writeOperations = $frame['writeOperations'];
        $this->writeOperationsInTransaction = $frame['writeOperationsInTransaction'];
        $this->unprotectedWriteLines = $frame['unprotectedWriteLines'];
        $this->isolatedWrites = $frame['isolatedWrites'];
        $this->earlyExitIfDepth = $frame['earlyExitIfDepth'];
        $this->earlyExitIfPositions = $frame['earlyExitIfPositions'];
        $this->guardClauseElsePositions = $frame['guardClauseElsePositions'];
        $this->ifElseBranchStack = $frame['ifElseBranchStack'];
        $this->maxClosureWrites = $frame['maxClosureWrites'];
        $this->maxClosureUnprotected = $frame['maxClosureUnprotected'];
        $this->maxClosureLines = $frame['maxClosureLines'];
        $this->maxClosureLine = $frame['maxClosureLine'];

        // Fold the just-left closure into the restored parent as the heaviest sibling.
        // Only closures that contain unprotected writes can add transaction risk to the
        // parent; fully-protected closures (e.g. an ->action() that wraps its writes in
        // DB::transaction()) contribute nothing. Among the unprotected siblings we keep
        // the heaviest (by write count) as a COHERENT unit — its own writes, unprotected
        // count, lines and declaration line are kept together. Metrics are never mixed
        // across siblings, which never co-execute on the same request: doing so would,
        // for example, pair a protected sibling's write count with another sibling's lone
        // unprotected write and report a phantom multi-write transaction gap.
        if ($effClosureUnprotected > 0 && $effClosureWrites > $this->maxClosureWrites) {
            $this->maxClosureWrites = $effClosureWrites;
            $this->maxClosureUnprotected = $effClosureUnprotected;
            $this->maxClosureLines = $effClosureLines;
            // Record this closure's declaration line so the issue can point at it.
            $this->maxClosureLine = $closure->getStartLine();
        }
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

        // Two or more levels of property access (e.g. $this->stripe->customers->update())
        // indicates an external service client, not a query builder chain.
        // One level ($this->model->update()) is intentionally left flaggable.
        if (
            $current instanceof Node\Expr\PropertyFetch
            && $current->var instanceof Node\Expr\PropertyFetch
        ) {
            return true;
        }

        return false;
    }

    /**
     * Detect a fluent builder chain rooted at a `SomeComponent::make(...)` static call
     * — the universal factory convention for Filament/Livewire/Forms builders. Methods
     * such as ->toggle()/->sync() on such a chain configure UI; they are not Eloquent
     * relationship writes. A real relationship op is rooted on a model instance
     * (e.g. $user->roles()->toggle()) or a query (User::find($id)->roles()->sync()),
     * neither of which has a `make` root.
     */
    private function isFluentMakeBuilderChain(Node\Expr\MethodCall $node): bool
    {
        $current = $node->var;

        while ($current instanceof Node\Expr\MethodCall) {
            $current = $current->var;
        }

        return $current instanceof Node\Expr\StaticCall
            && $current->name instanceof Node\Identifier
            && $current->name->toString() === 'make';
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
                    if ($node->class instanceof Node\Name && ! $this->isLikelyDatabaseClass($node->class)) {
                        return false;
                    }

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
                    // Skip fluent builder chains like Filament's
                    // Filter::make('x')->...->toggle(), which configure UI and are not
                    // Eloquent relationship writes.
                    if ($this->isFluentMakeBuilderChain($node)) {
                        return false;
                    }

                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Returns true if the class Name likely descends from Illuminate\Database\Eloquent\Model.
     *
     * Three-tier strategy:
     * 1. Reflection (class_exists + is_a) — accurate when the Laravel autoloader is active.
     * 2. AST parent registry — follows up to 3 levels for project-file classes.
     * 3. Namespace heuristics — fallback for test contexts where model files are not
     *    present in the scanned directory and the autoloader cannot resolve them.
     */
    private function isLikelyDatabaseClass(Node\Name $name): bool
    {
        $resolvedName = $name->getAttribute('resolvedName');

        if (! ($resolvedName instanceof Node\Name\FullyQualified)) {
            return true; // Cannot resolve FQN — assume may be a model (conservative)
        }

        $fqn = ltrim($resolvedName->toString(), '\\');

        if (! str_contains($fqn, '\\')) {
            return true; // Unnamespaced class — conservative
        }

        $eloquentBase = 'Illuminate\\Database\\Eloquent\\Model';

        // Tier 1: reflection covers the full hierarchy in one call (project + vendor)
        if (class_exists($fqn, false) || class_exists($fqn)) {
            return is_a($fqn, $eloquentBase, true);
        }

        // Tier 2: AST registry — follow parent chain up to 3 levels
        $current = $fqn;
        for ($depth = 0; $depth < 3; $depth++) {
            if ($current === $eloquentBase) {
                return true;
            }

            if (! array_key_exists($current, $this->classParents)) {
                break; // Not in registry — fall through to heuristics
            }

            $parent = $this->classParents[$current];
            if ($parent === null) {
                break;
            }

            $current = $parent;
        }

        // Tier 3: namespace heuristics — catches App\Models\* and *\Models\* patterns
        // (handles test contexts where models are not in the scanned temp directory)
        return str_starts_with($fqn, 'App\\Models\\')
            || str_starts_with($fqn, 'App\\Model\\')
            || str_contains($fqn, '\\Models\\');
    }

    /**
     * A "guard clause" if is one whose body always terminates (return/throw).
     * Elseif branches are not allowed (complex control flow), but a plain else
     * is fine — the if-body still terminates early, so writes inside it are
     * isolated. Writes in the else are in the main flow and handled separately.
     */
    private function isGuardClauseIf(Node\Stmt\If_ $node): bool
    {
        if (! empty($node->elseifs)) {
            return false;
        }
        if (empty($node->stmts)) {
            return false;
        }
        $last = end($node->stmts);

        // PHP-Parser 5.x: throw is an expression (Node\Expr\Throw_) wrapped in Node\Stmt\Expression
        if ($last instanceof Node\Stmt\Expression && $last->expr instanceof Node\Expr\Throw_) {
            return true;
        }

        return $last instanceof Node\Stmt\Return_ || $last instanceof Node\Expr\Throw_;
    }
}

/**
 * Pre-scan visitor that identifies private/protected methods exclusively called
 * from within DB::transaction() closures in the same class.
 *
 * These "transaction-delegated" methods should not be flagged for missing
 * transaction protection because every execution path runs inside a transaction.
 */
class TransactionDelegatedMethodScanner extends NodeVisitorAbstract
{
    /** @var array<int, true> File positions of closures passed directly to DB::transaction(). */
    private array $transactionClosurePositions = [];

    private int $transactionDepth = 0;

    /** @var array<string, true> Method names called from within a transaction closure. */
    private array $calledInsideTransaction = [];

    /** @var array<string, true> Method names called outside any transaction closure. */
    private array $calledOutsideTransaction = [];

    public function enterNode(Node $node): ?Node
    {
        // Record closures passed directly to DB::transaction().
        if ($node instanceof Node\Expr\StaticCall
            && $node->class instanceof Node\Name
            && $node->class->toString() === 'DB'
            && $node->name instanceof Node\Identifier
            && $node->name->toString() === 'transaction'
            && ! empty($node->args)
        ) {
            $firstArg = $node->args[0]->value;
            if ($firstArg instanceof Node\Expr\Closure || $firstArg instanceof Node\Expr\ArrowFunction) {
                $this->transactionClosurePositions[$firstArg->getStartFilePos()] = true;
            }
        }

        // Track entering a recorded transaction closure.
        if ($node instanceof Node\Expr\Closure || $node instanceof Node\Expr\ArrowFunction) {
            if (isset($this->transactionClosurePositions[$node->getStartFilePos()])) {
                $this->transactionDepth++;
            }
        }

        // Collect $this->method() calls and partition by transaction context.
        if (
            $node instanceof Node\Expr\MethodCall
            && $node->var instanceof Node\Expr\Variable
            && $node->var->name === 'this'
            && $node->name instanceof Node\Identifier
        ) {
            $methodName = $node->name->toString();
            if ($this->transactionDepth > 0) {
                $this->calledInsideTransaction[$methodName] = true;
            } else {
                $this->calledOutsideTransaction[$methodName] = true;
            }
        }

        return null;
    }

    public function leaveNode(Node $node): ?Node
    {
        if ($node instanceof Node\Expr\Closure || $node instanceof Node\Expr\ArrowFunction) {
            if (isset($this->transactionClosurePositions[$node->getStartFilePos()]) && $this->transactionDepth > 0) {
                $this->transactionDepth--;
            }
        }

        return null;
    }

    /**
     * Returns method names that are called exclusively from within DB::transaction() closures.
     *
     * @return array<string, true>
     */
    public function getDelegatedMethods(): array
    {
        return array_diff_key($this->calledInsideTransaction, $this->calledOutsideTransaction);
    }
}

/**
 * Pre-scan that records every class's direct parent FQN from AST.
 *
 * Requires NameResolver to have run first so that resolvedName attributes
 * and namespacedName are populated on class and name nodes.
 */
class EloquentModelScanner extends NodeVisitorAbstract
{
    /** @var array<string, string|null> class FQN → parent FQN (null if no parent) */
    private array $parents = [];

    public function enterNode(Node $node): ?Node
    {
        if (! ($node instanceof Node\Stmt\Class_)) {
            return null;
        }

        // NameResolver sets namespacedName on class definitions
        $namespacedName = $node->getAttribute('namespacedName');
        $className = $namespacedName instanceof Node\Name
            ? $namespacedName->toString()
            : $node->name?->toString();

        if ($className === null) {
            return null;
        }

        $parentFqn = null;
        if ($node->extends !== null) {
            $resolved = $node->extends->getAttribute('resolvedName');
            $parentFqn = $resolved instanceof Node\Name\FullyQualified
                ? ltrim($resolved->toString(), '\\')
                : ltrim($node->extends->toString(), '\\');
        }

        $this->parents[$className] = $parentFqn;

        return null;
    }

    /** @return array<string, string|null> */
    public function getParents(): array
    {
        return $this->parents;
    }
}
