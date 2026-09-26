<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Modifiers;
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
use ShieldCI\Concerns\ReadsConfigArrays;
use ShieldCI\Concerns\ResolvesClassNames;

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
    use ReadsConfigArrays;
    use ResolvesClassNames;

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

        $this->threshold = $this->configInt($analyzerConfig, 'threshold', self::DEFAULT_THRESHOLD);

        $issues = [];

        $phpFiles = $this->getPhpFiles();

        // Phase 0: index every class-like declaration in the project, so that the pass
        // below can ask about declarations it is not itself looking at.
        $classScanner = new ClassHierarchyScanner;
        foreach ($phpFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }
                $ast = $this->resolveNamesForMatching($this->parser, $ast);
                $registryTraverser = new NodeTraverser;
                $registryTraverser->addVisitor($classScanner);
                $registryTraverser->traverse($ast);
            } catch (\Throwable) {
                continue;
            }
        }

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

                $ast = $this->resolveNamesForMatching($this->parser, $ast);

                $scanner = new TransactionDelegatedMethodScanner;
                $preScanTraverser = new NodeTraverser;
                $preScanTraverser->addVisitor($scanner);
                $preScanTraverser->traverse($ast);

                $visitor = new TransactionVisitor($this->threshold, $scanner->getDelegatedMethods(), $classScanner);
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
 *
 * @phpstan-type IfElseFrame array{pos: int, elsePos: int, inElse: bool, ifWrites: int, elseWrites: int, ifLines: list<int>, elseLines: list<int>}
 * @phpstan-type ClosureScopeFrame array{
 *   writeOperations: int,
 *   writeOperationsInTransaction: int,
 *   unprotectedWriteLines: list<int>,
 *   isolatedWrites: int,
 *   earlyExitIfDepth: int,
 *   earlyExitIfPositions: array<int, true>,
 *   guardClauseElsePositions: array<int, true>,
 *   ifElseBranchStack: list<IfElseFrame>,
 *   maxClosureWrites: int,
 *   maxClosureUnprotected: int,
 *   maxClosureLines: list<int>,
 *   maxClosureLine: int,
 *   nonDbVariables: array<string, true>
 * }
 * @phpstan-type MethodScopeFrame array{
 *   currentMethodName: string|null,
 *   methodStartLine: int,
 *   writeOperations: int,
 *   writeOperationsInTransaction: int,
 *   unprotectedWriteLines: list<int>,
 *   transactionDepth: int,
 *   manualTransactionDepth: int,
 *   isolatedWrites: int,
 *   earlyExitIfDepth: int,
 *   transactionClosurePositions: array<int, true>,
 *   earlyExitIfPositions: array<int, true>,
 *   guardClauseElsePositions: array<int, true>,
 *   ifElseBranchStack: list<IfElseFrame>,
 *   maxClosureWrites: int,
 *   maxClosureUnprotected: int,
 *   maxClosureLines: list<int>,
 *   maxClosureLine: int,
 *   closureScopeStack: list<ClosureScopeFrame>,
 *   nonDbVariables: array<string, true>
 * }
 */
class TransactionVisitor extends NodeVisitorAbstract
{
    /**
     * Facades that have methods looking like DB writes but aren't database operations.
     */
    private const NON_DB_FACADES = [
        'Cache', 'Redis', 'RateLimiter', 'Session', 'Storage', 'Queue',
    ];

    /**
     * The same six as fully qualified names, for the receiver-marking path where a short
     * name match is unsafe: marking a variable suppresses every later write on it, so an
     * application model named Session or Queue would silence real writes.
     *
     * @var array<int, string>
     */
    private const NON_DB_FACADE_FQNS = [
        'Illuminate\Support\Facades\Cache',
        'Illuminate\Support\Facades\Redis',
        'Illuminate\Support\Facades\RateLimiter',
        'Illuminate\Support\Facades\Session',
        'Illuminate\Support\Facades\Storage',
        'Illuminate\Support\Facades\Queue',
    ];

    /**
     * The same six services in their injected-contract spelling. A property declared as
     * one of these holds a cache, filesystem, queue, session or Redis client, so its
     * delete()/save()/update() never reaches the database.
     *
     * Deliberately an explicit list rather than "does not extend Eloquent\Model": an
     * injected repository or service wrapping several writes does not extend Model
     * either, and those are exactly what this rule is meant to catch.
     *
     * @var array<string>
     */
    private const NON_DB_CLIENT_TYPES = [
        'Psr\SimpleCache\CacheInterface',
        'Psr\Cache\CacheItemPoolInterface',
        'Illuminate\Contracts\Cache\Repository',
        'Illuminate\Contracts\Cache\Factory',
        'Illuminate\Contracts\Filesystem\Filesystem',
        'Illuminate\Contracts\Filesystem\Cloud',
        'Illuminate\Contracts\Filesystem\Factory',
        'Illuminate\Filesystem\Filesystem',
        // What Storage::disk() actually hands back, so a property typed at the concrete
        // return type is covered as well as one typed at the contract.
        'Illuminate\Filesystem\FilesystemAdapter',
        'Illuminate\Contracts\Queue\Queue',
        'Illuminate\Contracts\Queue\Factory',
        'Illuminate\Contracts\Queue\Job',
        'Illuminate\Contracts\Session\Session',
        'Illuminate\Session\Store',
        'Illuminate\Contracts\Redis\Factory',
        'Illuminate\Redis\Connections\Connection',
        'Illuminate\Cache\RateLimiter',
        'Predis\Client',
        'Redis',
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
     * @var list<ClosureScopeFrame>
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
     * @var list<IfElseFrame>
     */
    private array $ifElseBranchStack = [];

    /**
     * Variables holding a non-database facade, e.g. $disk = Storage::disk('s3').
     * Writes on such a receiver are filesystem/cache/queue calls, not database writes.
     *
     * @var array<string, true>
     */
    private array $nonDbVariables = [];

    /**
     * Declared type of each property of the current class, keyed by property name.
     * Covers plain declarations and constructor-promoted parameters alike.
     *
     * @var array<string, string>
     */
    private array $propertyTypes = [];

    /**
     * Saved property maps of enclosing class-like declarations, pushed on the way in and
     * popped on the way out so that a nested declaration cannot leave the outer map
     * behind. Without it an anonymous class inside a method hands back the very false
     * positive this suppression exists to remove.
     *
     * @var array<int, array<string, string>>
     */
    private array $propertyTypeStack = [];

    /**
     * Saved names of enclosing classes, popped in step with $propertyTypeStack so that
     * an anonymous class no longer leaves the enclosing method reported as "Unknown".
     *
     * @var array<int, string|null>
     */
    private array $classNameStack = [];

    /**
     * Saved method scopes, pushed on entering a method and popped on leaving it. A method
     * body can declare a class of its own, whose methods are entered like any other; without
     * this the inner method's tally would be handed to the enclosing method, which then
     * reports writes it never performs under a name it does not have.
     *
     * Every field pushMethodScope() resets belongs here, the same duty $closureScopeStack
     * carries: a new method-scoped field has to be added in all three lists at once.
     *
     * @var list<MethodScopeFrame>
     */
    private array $methodScopeStack = [];

    /**
     * @param  array<string, true>  $transactionDelegatedMethods
     */
    public function __construct(
        private int $threshold,
        private array $transactionDelegatedMethods,
        private ClassHierarchyScanner $classes,
    ) {}

    public function enterNode(Node $node): ?Node
    {
        // Track the current class-like declaration. A trait declares properties the same
        // way a class does and its methods are visited without any Stmt\Class_ ever being
        // entered, so it has to be handled here too or an injected cache client in a trait
        // inherits whatever map a previously visited class left behind.
        //
        // Pushed rather than assigned: an anonymous class declared inside a method is a
        // Stmt\Class_ like any other, and would otherwise take the enclosing class's
        // property map with it for the rest of the method.
        if ($node instanceof Node\Stmt\ClassLike) {
            $this->classNameStack[] = $this->currentClassName;
            $this->propertyTypeStack[] = $this->propertyTypes;
            $this->currentClassName = $node->name?->toString();
            // Own declarations first: array + array keeps the left-hand entry, so a
            // property the class redeclares wins over the one it would have inherited.
            // Own properties are read from the node, and the inherited half is seeded
            // from it too, because an anonymous class has no name for the registry to
            // have filed it under.
            $this->propertyTypes = ClassHierarchyScanner::propertyTypesOf($node)
                + $this->classes->inheritedPropertyTypesFor($node);
        }

        // Track current method
        if ($node instanceof Node\Stmt\ClassMethod) {
            $this->pushMethodScope($node);
        }

        // Remember variables holding a non-database facade ($disk = Storage::disk('s3')).
        // Any other assignment drops the marker, so $user = User::find($id) stays flaggable.
        if ($node instanceof Node\Expr\Assign
            && $node->var instanceof Node\Expr\Variable
            && is_string($node->var->name)
        ) {
            if ($this->isNonDbFacadeRooted($node->expr)) {
                $this->nonDbVariables[$node->var->name] = true;
            } else {
                unset($this->nonDbVariables[$node->var->name]);
            }
        }

        // Check for DB::transaction or DB::beginTransaction, in either the direct static
        // spelling or the connection-scoped one (DB::connection('tenant')->transaction()).
        if ($node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall) {
            if ($this->isTransactionCall($node)) {
                // If it's beginTransaction, mark that we're in a manual transaction
                // (it's typically called before a try block)
                if ($node->name instanceof Node\Identifier) {
                    $methodName = $node->name->toString();
                    if ($methodName === 'beginTransaction') {
                        $this->manualTransactionDepth++;
                    } elseif ($methodName === 'transaction' && ! empty($node->args)) {
                        // Track the closure passed to DB::transaction()
                        $firstArgNode = $node->args[0];
                        $firstArg = $firstArgNode instanceof Node\Arg ? $firstArgNode->value : null;
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
                $this->pushClosureScope($node);
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
        // Restore the enclosing declaration's context on the way out. Must mirror the
        // ClassLike push in enterNode() exactly, or the stacks drift apart.
        if ($node instanceof Node\Stmt\ClassLike) {
            $this->propertyTypes = array_pop($this->propertyTypeStack) ?? [];
            $this->currentClassName = array_pop($this->classNameStack);
        }

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

            // An issue only when some effective write is unprotected and the method carries
            // at least the threshold number of writes.
            if ($effectiveUnprotected > 0 && $effectiveWrites >= $this->threshold) {
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

            $this->popMethodScope();
        }

        return null;
    }

    /**
     * Snapshot the enclosing method's scope and start a fresh one for this method.
     * A class declared inside a method body brings methods of its own, and each of
     * them is a counting unit in its own right.
     */
    private function pushMethodScope(Node\Stmt\ClassMethod $node): void
    {
        $this->methodScopeStack[] = [
            'currentMethodName' => $this->currentMethodName,
            'methodStartLine' => $this->methodStartLine,
            'writeOperations' => $this->writeOperations,
            'writeOperationsInTransaction' => $this->writeOperationsInTransaction,
            'unprotectedWriteLines' => $this->unprotectedWriteLines,
            'transactionDepth' => $this->transactionDepth,
            'manualTransactionDepth' => $this->manualTransactionDepth,
            'isolatedWrites' => $this->isolatedWrites,
            'earlyExitIfDepth' => $this->earlyExitIfDepth,
            'transactionClosurePositions' => $this->transactionClosurePositions,
            'earlyExitIfPositions' => $this->earlyExitIfPositions,
            'guardClauseElsePositions' => $this->guardClauseElsePositions,
            'ifElseBranchStack' => $this->ifElseBranchStack,
            'maxClosureWrites' => $this->maxClosureWrites,
            'maxClosureUnprotected' => $this->maxClosureUnprotected,
            'maxClosureLines' => $this->maxClosureLines,
            'maxClosureLine' => $this->maxClosureLine,
            'closureScopeStack' => $this->closureScopeStack,
            'nonDbVariables' => $this->nonDbVariables,
        ];

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
        $this->nonDbVariables = [];
    }

    /**
     * Hand the enclosing method back the scope it had before this one was entered.
     * Nothing is folded outward: sibling methods are separate units already, and a
     * method of a nested class is no different.
     */
    private function popMethodScope(): void
    {
        if ($this->methodScopeStack === []) {
            return;
        }

        $frame = array_pop($this->methodScopeStack);

        $this->currentMethodName = $frame['currentMethodName'];
        $this->methodStartLine = $frame['methodStartLine'];
        $this->writeOperations = $frame['writeOperations'];
        $this->writeOperationsInTransaction = $frame['writeOperationsInTransaction'];
        $this->unprotectedWriteLines = $frame['unprotectedWriteLines'];
        $this->transactionDepth = $frame['transactionDepth'];
        $this->manualTransactionDepth = $frame['manualTransactionDepth'];
        $this->isolatedWrites = $frame['isolatedWrites'];
        $this->earlyExitIfDepth = $frame['earlyExitIfDepth'];
        $this->transactionClosurePositions = $frame['transactionClosurePositions'];
        $this->earlyExitIfPositions = $frame['earlyExitIfPositions'];
        $this->guardClauseElsePositions = $frame['guardClauseElsePositions'];
        $this->ifElseBranchStack = $frame['ifElseBranchStack'];
        $this->maxClosureWrites = $frame['maxClosureWrites'];
        $this->maxClosureUnprotected = $frame['maxClosureUnprotected'];
        $this->maxClosureLines = $frame['maxClosureLines'];
        $this->maxClosureLine = $frame['maxClosureLine'];
        $this->closureScopeStack = $frame['closureScopeStack'];
        $this->nonDbVariables = $frame['nonDbVariables'];
    }

    /**
     * Snapshot the current scope's write counters and reset them so the callback
     * closure body is counted as its own independent unit. Transaction depth is
     * intentionally inherited, so a synchronous closure inside DB::transaction()
     * remains protected.
     */
    private function pushClosureScope(Node\Expr\Closure|Node\Expr\ArrowFunction $closure): void
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
            // A closure parameter shadows the enclosing variable of the same name, so a
            // facade marker must not follow $disk into function ($disk) { ... }.
            'nonDbVariables' => $this->nonDbVariables,
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

        // A marker reached by `use ($disk)` stays, because the closure really is looking
        // at the same handle. A parameter of the same name is a different variable, so
        // its marker is dropped for the body of the closure.
        foreach ($closure->params as $param) {
            if ($param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                unset($this->nonDbVariables[$param->var->name]);
            }
        }
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
        $this->nonDbVariables = $frame['nonDbVariables'];

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

    /**
     * Return the method name of a call made on the DB facade, in either spelling:
     * the direct static call DB::transaction(), or the connection-scoped chain
     * DB::connection('tenant')->transaction(). The latter is the only way to open a
     * transaction on a non-default connection, so it has to count as one.
     */
    private function dbFacadeMethod(Node\Expr\StaticCall|Node\Expr\MethodCall $node): ?string
    {
        if (! $node->name instanceof Node\Identifier) {
            return null;
        }

        $root = $node;
        while ($root instanceof Node\Expr\MethodCall) {
            $root = $root->var;
        }

        if (! $root instanceof Node\Expr\StaticCall || ! $root->class instanceof Node\Name) {
            return null;
        }

        return $root->class->toString() === 'DB' ? $node->name->toString() : null;
    }

    private function isTransactionCall(Node\Expr\StaticCall|Node\Expr\MethodCall $node): bool
    {
        return in_array($this->dbFacadeMethod($node), ['transaction', 'beginTransaction'], true);
    }

    /**
     * Check if the call is a transaction end (commit or rollBack).
     */
    private function isTransactionEndCall(Node\Expr\StaticCall|Node\Expr\MethodCall $node): bool
    {
        return in_array($this->dbFacadeMethod($node), ['commit', 'rollBack'], true);
    }

    /**
     * Extract short class name from a Node\Name, using resolved FQN if available.
     */
    private function getShortClassName(Node\Name $name): string
    {
        $fqn = ClassHierarchyScanner::nameFqn($name);

        $parts = explode('\\', $fqn);

        return end($parts) ?: $fqn;
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

        // A variable holding a non-database facade, e.g. $disk = Storage::disk('s3').
        if ($current instanceof Node\Expr\Variable
            && is_string($current->name)
            && isset($this->nonDbVariables[$current->name])
        ) {
            return true;
        }

        // A single level of property access is flaggable unless the property is declared
        // as a cache/filesystem/queue/session/Redis client. That keeps $this->model->update()
        // reported while $this->cache->delete() is not.
        if ($current instanceof Node\Expr\PropertyFetch
            && $current->var instanceof Node\Expr\Variable
            && $current->var->name === 'this'
            && $current->name instanceof Node\Identifier
        ) {
            $type = $this->propertyTypes[$current->name->toString()] ?? null;

            return $type !== null && in_array($type, self::NON_DB_CLIENT_TYPES, true);
        }

        return false;
    }

    /**
     * True when a chain bottoms out in a static call on a non-database facade,
     * e.g. the right-hand side of $disk = Storage::disk('s3').
     *
     * Matched on the fully qualified name, not the short one. Marking a variable
     * suppresses every later write on it, so an application model named Session or
     * Queue would otherwise silence real writes that were reported before the marker
     * existed. The AST reaching this visitor is always name-resolved (see
     * MissingDatabaseTransactionsAnalyzer::runAnalysis), so the FQN is available.
     */
    private function isNonDbFacadeRooted(Node\Expr $expr): bool
    {
        $current = $expr;

        while ($current instanceof Node\Expr\MethodCall) {
            $current = $current->var;
        }

        return $current instanceof Node\Expr\StaticCall
            && $current->class instanceof Node\Name
            && $this->isNonDbFacadeName($current->class);
    }

    /**
     * True when a class reference names one of the non-database facades, matched on the
     * fully qualified name. An unqualified single-segment name falls back to the short
     * name, which is the container alias spelling (`Storage::disk()` in a file with no
     * namespace); a resolved App\Models\Session must not borrow that exemption.
     */
    private function isNonDbFacadeName(Node\Name $class): bool
    {
        $fqn = ClassHierarchyScanner::nameFqn($class);

        if (in_array($fqn, self::NON_DB_FACADE_FQNS, true)) {
            return true;
        }

        return ! str_contains($fqn, '\\')
            && in_array($fqn, self::NON_DB_FACADES, true);
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
                    // Raw DDL/DML. DB::statement() counts as a write in the static branch
                    // above, so DB::connection('tenant')->statement() has to count here.
                    'statement',
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

            $parent = $this->classes->parentOf($current);
            if ($parent === null) {
                break; // Unknown, or known with no parent: fall through to heuristics
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
 * Pre-scan visitor that identifies methods whose every execution path runs
 * inside a DB::transaction() — and which therefore should not be flagged for
 * missing transaction protection.
 *
 * Protection is resolved transitively over the intra-class `$this->method()`
 * call graph. A method is "delegated" when, for every call site:
 *   - the call sits lexically inside a DB::transaction() closure, OR
 *   - the caller is itself a delegated *private/protected* method (so it has
 *     no externally-reachable entry point that could bypass the transaction).
 *
 * The visibility gate matters only for transitive propagation: a public
 * intermediary may be invoked externally without a transaction, so protection
 * never flows *through* it. A method whose call sites are *all* directly inside
 * transaction closures is delegated regardless of its own visibility.
 */
class TransactionDelegatedMethodScanner extends NodeVisitorAbstract
{
    /** @var array<int, true> File positions of closures passed directly to DB::transaction(). */
    private array $transactionClosurePositions = [];

    private int $transactionDepth = 0;

    private ?string $currentMethodName = null;

    /**
     * Saved names of enclosing methods. A method body can declare a class of its own, and
     * without this the call edges recorded after that inner method carry no caller, which
     * breaks the chain protection propagates along.
     *
     * @var list<string|null>
     */
    private array $methodNameStack = [];

    /** @var array<string, bool> Method name → whether it is declared private or protected. */
    private array $methodIsHidden = [];

    /**
     * Intra-class call edges keyed by callee method name.
     *
     * @var array<string, list<array{caller: string|null, inTx: bool}>>
     */
    private array $edgesByCallee = [];

    public function enterNode(Node $node): ?Node
    {
        // Track the method we are currently inside (and its visibility).
        if ($node instanceof Node\Stmt\ClassMethod) {
            $this->methodNameStack[] = $this->currentMethodName;
            $this->currentMethodName = $node->name->toString();
            $this->methodIsHidden[$this->currentMethodName] = $node->isPrivate() || $node->isProtected();
        }

        // Record closures passed directly to DB::transaction(), including the
        // connection-scoped spelling DB::connection('tenant')->transaction().
        if (($node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall)
            && $this->isDbTransactionCall($node)
            && ! empty($node->args)
        ) {
            $firstArgNode = $node->args[0];
            $firstArg = $firstArgNode instanceof Node\Arg ? $firstArgNode->value : null;
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

        // Record each $this->method() call edge with its caller and transaction context.
        if (
            $node instanceof Node\Expr\MethodCall
            && $node->var instanceof Node\Expr\Variable
            && $node->var->name === 'this'
            && $node->name instanceof Node\Identifier
        ) {
            $this->edgesByCallee[$node->name->toString()][] = [
                'caller' => $this->currentMethodName,
                'inTx' => $this->transactionDepth > 0,
            ];
        }

        return null;
    }

    /**
     * True when the call opens a transaction on the DB facade, either as DB::transaction()
     * or through a connection chain such as DB::connection('tenant')->transaction().
     */
    private function isDbTransactionCall(Node\Expr\StaticCall|Node\Expr\MethodCall $node): bool
    {
        if (! $node->name instanceof Node\Identifier || $node->name->toString() !== 'transaction') {
            return false;
        }

        $root = $node;
        while ($root instanceof Node\Expr\MethodCall) {
            $root = $root->var;
        }

        return $root instanceof Node\Expr\StaticCall
            && $root->class instanceof Node\Name
            && $root->class->toString() === 'DB';
    }

    public function leaveNode(Node $node): ?Node
    {
        if ($node instanceof Node\Stmt\ClassMethod) {
            $this->currentMethodName = array_pop($this->methodNameStack);
        }

        if ($node instanceof Node\Expr\Closure || $node instanceof Node\Expr\ArrowFunction) {
            if (isset($this->transactionClosurePositions[$node->getStartFilePos()]) && $this->transactionDepth > 0) {
                $this->transactionDepth--;
            }
        }

        return null;
    }

    /**
     * Returns method names whose every call path runs inside a transaction,
     * resolved to a fixed point over the intra-class call graph.
     *
     * @return array<string, true>
     */
    public function getDelegatedMethods(): array
    {
        /** @var array<string, true> $delegated */
        $delegated = [];

        do {
            $changed = false;

            foreach ($this->edgesByCallee as $callee => $edges) {
                if (isset($delegated[$callee])) {
                    continue;
                }

                $allInTx = true;
                $allProtected = true;

                foreach ($edges as $edge) {
                    if ($edge['inTx']) {
                        continue;
                    }
                    $allInTx = false;

                    // A non-transaction edge is only protected when the caller is
                    // itself a delegated private/protected method (no external entry).
                    $caller = $edge['caller'];
                    $safeCaller = $caller !== null
                        && isset($delegated[$caller])
                        && ($this->methodIsHidden[$caller] ?? false);

                    if (! $safeCaller) {
                        $allProtected = false;
                    }
                }

                // Direct case: every call site is inside a transaction closure
                // (preserves prior behavior, regardless of the callee's visibility).
                // Transitive case: protection only propagates to a private/protected
                // callee, since a public callee may be reached externally without one.
                if ($allInTx || ($allProtected && ($this->methodIsHidden[$callee] ?? false))) {
                    $delegated[$callee] = true;
                    $changed = true;
                }
            }
        } while ($changed);

        return $delegated;
    }
}

/**
 * Pre-scan that indexes every named class-like declaration in the project: what it
 * extends, which traits it uses, and the declared type of each property it holds.
 *
 * The declaration a later pass needs is often not the one it is standing in. A service
 * that writes to an injected cache client routinely inherits that property from an
 * abstract base in another file, or picks it up from a trait, and a visitor reading only
 * the node it entered can see neither.
 *
 * Requires NameResolver to have run first. Note that `namespacedName` is a public
 * property on ClassLike rather than an attribute, and a typed one with no default: read
 * through getAttribute() it silently yields null, and read directly it throws when the
 * resolver did not run. Both reads here go through isset() for that reason.
 *
 * Keys are case folded throughout, because PHP resolves a class name without regard to
 * case and a reference spelled differently from its declaration names the same class.
 *
 * @internal
 */
class ClassHierarchyScanner extends NodeVisitorAbstract
{
    /** @var array<string, string|null> class key => parent FQN (null if no parent) */
    private array $parents = [];

    /** @var array<string, list<string>> class or trait key => FQNs of the traits it uses */
    private array $traitUses = [];

    /** @var array<string, array<string, string>> class or trait key => property name => type FQN */
    private array $propertyTypes = [];

    /** @var array<string, array<string, string>> class key => flattened inherited property types */
    private array $inheritedCache = [];

    public function enterNode(Node $node): ?Node
    {
        if (! ($node instanceof Node\Stmt\ClassLike)) {
            return null;
        }

        $fqn = self::declarationFqn($node);
        if ($fqn === null) {
            // An anonymous class, which nothing elsewhere can name to ask about, or a
            // declaration whose file NameResolver could not finish. Filing the latter
            // under the short name left to it would hand its properties to whatever
            // global-namespace class genuinely bears that name.
            return null;
        }

        $key = self::key($fqn);

        if ($node instanceof Node\Stmt\Class_) {
            $this->parents[$key] = $node->extends !== null ? self::nameFqn($node->extends) : null;
        }

        $traits = [];
        foreach ($node->getTraitUses() as $use) {
            foreach ($use->traits as $trait) {
                $traits[] = self::nameFqn($trait);
            }
        }
        if ($traits !== []) {
            $this->traitUses[$key] = $traits;
        }

        // Written whatever it holds, so a name declared twice cannot leave one
        // declaration's parent standing beside another declaration's properties.
        $this->propertyTypes[$key] = self::propertyTypesOf($node, skipPrivate: true);

        return null;
    }

    public function parentOf(string $fqn): ?string
    {
        return $this->parents[self::key($fqn)] ?? null;
    }

    /**
     * The declared property types a declaration holds without declaring them itself.
     *
     * Takes the node rather than a name so that an anonymous class is covered too. The
     * registry could not file one under a key, but the extends clause and trait uses
     * sitting on the node name the declarations it draws from just as well.
     *
     * @return array<string, string>
     */
    public function inheritedPropertyTypesFor(Node\Stmt\ClassLike $class): array
    {
        $fqn = self::declarationFqn($class);

        return $fqn !== null
            ? $this->inheritedPropertyTypes($fqn)
            : $this->gather(self::declaredAncestorsOf($class), []);
    }

    /**
     * The declared property types $fqn holds without declaring them itself, gathered from
     * the traits it uses and the classes it extends.
     *
     * Memoized, because every sibling under a shared base would otherwise re-flatten the
     * same ancestors once per declaration the second pass enters.
     *
     * @return array<string, string>
     */
    public function inheritedPropertyTypes(string $fqn): array
    {
        $key = self::key($fqn);

        return $this->inheritedCache[$key] ??= $this->gather($this->ancestorsOf($fqn), [$key => true]);
    }

    /**
     * Breadth first from the given declarations outwards, so that a declaration nearer the
     * child wins: array + array keeps the entry already present. The visited set makes the
     * walk terminate on a hierarchy that refers back to itself, which an AST can express
     * even though PHP could not load it.
     *
     * @param  list<string>  $queue
     * @param  array<string, true>  $seen
     * @return array<string, string>
     */
    private function gather(array $queue, array $seen): array
    {
        $types = [];

        while ($queue !== []) {
            $ancestor = self::key(array_shift($queue));

            if (isset($seen[$ancestor])) {
                continue;
            }
            $seen[$ancestor] = true;

            $types += $this->propertyTypes[$ancestor] ?? [];

            foreach ($this->ancestorsOf($ancestor) as $next) {
                $queue[] = $next;
            }
        }

        return $types;
    }

    /**
     * The declarations $fqn draws members from directly. Traits come first because that is
     * PHP's own precedence: a trait a class uses overrides what it would have inherited.
     *
     * @return list<string>
     */
    private function ancestorsOf(string $fqn): array
    {
        $key = self::key($fqn);

        $ancestors = $this->traitUses[$key] ?? [];

        $parent = $this->parents[$key] ?? null;
        if ($parent !== null) {
            $ancestors[] = $parent;
        }

        return $ancestors;
    }

    /**
     * The same question asked of a node instead of the registry, for a declaration the
     * registry has no key for.
     *
     * @return list<string>
     */
    private static function declaredAncestorsOf(Node\Stmt\ClassLike $class): array
    {
        $ancestors = [];

        foreach ($class->getTraitUses() as $use) {
            foreach ($use->traits as $trait) {
                $ancestors[] = self::nameFqn($trait);
            }
        }

        if ($class instanceof Node\Stmt\Class_ && $class->extends !== null) {
            $ancestors[] = self::nameFqn($class->extends);
        }

        return $ancestors;
    }

    /**
     * The key a name is filed under. Folded because PHP resolves a class name without
     * regard to case, so a reference spelled differently is still the same class.
     */
    private static function key(string $fqn): string
    {
        return strtolower($fqn);
    }

    /**
     * The fully qualified name of a class-like declaration, or null when it has none to
     * give: an anonymous class, or one in a file NameResolver could not finish.
     *
     * The short name is deliberately not a fallback. NameResolver sets namespacedName on
     * every declaration it reaches, the global namespace included, so an unset one means
     * the resolver stopped rather than that the class is unqualified.
     */
    public static function declarationFqn(Node\Stmt\ClassLike $class): ?string
    {
        return isset($class->namespacedName)
            ? ltrim($class->namespacedName->toString(), '\\')
            : null;
    }

    /**
     * The fully qualified name behind a class reference, preferring the attribute
     * NameResolver leaves behind when it runs with ['replaceNodes' => false], and falling
     * back to the name as written when it has not run.
     */
    public static function nameFqn(Node\Name $name): string
    {
        $resolved = $name->getAttribute('resolvedName');

        $fqn = $resolved instanceof Node\Name\FullyQualified
            ? $resolved->toString()
            : $name->toString();

        return ltrim($fqn, '\\');
    }

    /**
     * Map every property a declaration holds itself to its declared type FQN, covering
     * plain declarations and constructor-promoted parameters alike. Properties with no
     * type, or a scalar or composite type, are omitted so they stay conservative
     * (flaggable).
     *
     * $skipPrivate leaves out what another declaration could not see. A class reads its
     * own private properties, so the node being entered keeps them; the registry, which
     * exists to answer what a different declaration inherits, does not.
     *
     * @return array<string, string>
     */
    public static function propertyTypesOf(Node\Stmt\ClassLike $class, bool $skipPrivate = false): array
    {
        $types = [];

        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Property) {
                if ($skipPrivate && $stmt->isPrivate()) {
                    continue;
                }

                $type = self::typeFqn($stmt->type);
                if ($type !== null) {
                    foreach ($stmt->props as $prop) {
                        $types[$prop->name->toString()] = $type;
                    }
                }

                continue;
            }

            if (! $stmt instanceof Node\Stmt\ClassMethod || $stmt->name->toString() !== '__construct') {
                continue;
            }

            foreach ($stmt->params as $param) {
                if ($skipPrivate && ($param->flags & Modifiers::PRIVATE) !== 0) {
                    continue;
                }

                $type = self::typeFqn($param->type);
                if ($param->flags !== 0
                    && $type !== null
                    && $param->var instanceof Node\Expr\Variable
                    && is_string($param->var->name)
                ) {
                    $types[$param->var->name] = $type;
                }
            }
        }

        return $types;
    }

    /**
     * Resolve a declared type to its fully-qualified name, or null when it is not a plain
     * class name (scalar, union, intersection, or absent).
     */
    private static function typeFqn(?Node $type): ?string
    {
        if ($type instanceof Node\NullableType) {
            $type = $type->type;
        }

        if (! $type instanceof Node\Name) {
            return null;
        }

        return self::nameFqn($type);
    }
}
