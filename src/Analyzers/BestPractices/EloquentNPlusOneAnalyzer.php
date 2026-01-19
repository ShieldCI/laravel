<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Identifies missing eager loading that causes N+1 query problems.
 *
 * Checks for:
 * - Relationship access inside loops
 * - Missing with() or load() calls
 * - Common patterns like $post->user in foreach
 */
class EloquentNPlusOneAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'eloquent-n-plus-one',
            name: 'Eloquent N+1 Query Analyzer',
            description: 'Identifies missing eager loading that causes N+1 query performance problems',
            category: Category::BestPractices,
            severity: Severity::High,
            tags: ['performance', 'eloquent', 'database', 'n+1', 'optimization'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/eloquent-n-plus-one',
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            try {
                $ast = $this->parser->parseFile($file);

                if (empty($ast)) {
                    continue;
                }

                $visitor = new NPlusOneVisitor;
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: "Potential N+1 query: accessing '{$issue['relationship']}' inside loop",
                        filePath: $file,
                        lineNumber: $issue['line'],
                        severity: Severity::High,
                        recommendation: $this->getRecommendation($issue['relationship'], $issue['loop_type']),
                        metadata: [
                            'relationship' => $issue['relationship'],
                            'loop_type' => $issue['loop_type'],
                            'variable' => $issue['variable'],
                            'file' => $file,
                        ]
                    );
                }

                // Process query-inside-loop issues
                foreach ($visitor->getQueryIssues() as $issue) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: "N+1 query: executing '{$issue['query']}' inside loop",
                        filePath: $file,
                        lineNumber: $issue['line'],
                        severity: Severity::High,
                        recommendation: $this->getQueryRecommendation($issue['query'], $issue['loop_type']),
                        metadata: [
                            'query' => $issue['query'],
                            'loop_type' => $issue['loop_type'],
                            'file' => $file,
                        ]
                    );
                }
            } catch (\Throwable $e) {
                // Skip files that can't be parsed
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('No potential N+1 query issues detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} potential N+1 query issue(s)",
            $issues
        );
    }

    /**
     * Get recommendation for relationship N+1 issue.
     */
    private function getRecommendation(string $relationship, string $loopType): string
    {
        return "Accessing the '{$relationship}' relationship inside a {$loopType} will trigger a separate database query for each iteration, causing an N+1 query problem. ";
    }

    /**
     * Get recommendation for query-inside-loop N+1 issue.
     */
    private function getQueryRecommendation(string $query, string $loopType): string
    {
        return "Executing '{$query}' inside a {$loopType} triggers a separate database query for each iteration. Consider fetching all required data before the loop using whereIn() or eager loading, then filter in-memory.";
    }
}

/**
 * Visitor to detect N+1 query patterns.
 */
class NPlusOneVisitor extends NodeVisitorAbstract
{
    /** @var string Loop type constants */
    private const LOOP_TYPE_FOREACH = 'foreach';

    private const LOOP_TYPE_FOR = 'for';

    private const LOOP_TYPE_WHILE = 'while';

    private const LOOP_TYPE_DO_WHILE = 'do-while';

    /** @var array<string> Common model properties that are not relationships */
    private const EXCLUDED_PROPERTIES = [
        // Primary keys and identifiers
        'id', 'uuid', 'key', 'code', 'token', 'hash', 'reference',
        // Timestamps
        'created_at', 'updated_at', 'deleted_at', 'published_at', 'expires_at',
        'verified_at', 'email_verified_at', 'started_at', 'ended_at', 'sent_at',
        // Authentication
        'password', 'remember_token', 'api_token', 'secret',
        // Common string fields
        'name', 'title', 'label', 'slug', 'email', 'username', 'nickname',
        'description', 'content', 'body', 'text', 'summary', 'excerpt', 'message',
        // URLs and paths
        'url', 'path', 'link', 'href', 'src', 'route',
        // Media
        'image', 'avatar', 'photo', 'picture', 'icon', 'thumbnail', 'logo', 'file',
        // Contact info
        'phone', 'address', 'street', 'city', 'state', 'country', 'zip', 'postal_code',
        // Localization
        'locale', 'timezone', 'currency', 'lang', 'language',
        // Numeric values
        'count', 'total', 'amount', 'price', 'quantity', 'balance', 'score', 'rating',
        'order', 'position', 'sort', 'rank', 'level', 'priority', 'weight', 'size',
        // Status and flags (values, not prefixed booleans)
        'status', 'state', 'type', 'kind', 'category', 'role', 'group',
        'active', 'enabled', 'visible', 'published', 'approved', 'verified',
        // JSON/array fields
        'data', 'meta', 'metadata', 'settings', 'options', 'config', 'attributes',
        'properties', 'payload', 'extra', 'info', 'details', 'preferences',
        // Miscellaneous
        'value', 'result', 'output', 'input', 'response', 'request',
        'color', 'format', 'version', 'note', 'notes', 'comment', 'reason',
    ];

    /** @var array<string> Common methods that are not relationship accessors */
    private const EXCLUDED_METHODS = [
        // Eloquent model methods
        'save', 'delete', 'update', 'refresh', 'replicate', 'touch',
        'toarray', 'tojson', 'tobase', 'jsonserialize',
        'getkey', 'getkeyname', 'getkeytype', 'getqualifiedkeyname',
        'getattribute', 'setattribute', 'getattributes', 'getoriginal',
        'getdirty', 'getchanges', 'getrelations', 'getrelation',
        'isdirty', 'isclean', 'waschanged', 'getraworiginal',
        'only', 'except', 'makevisible', 'makehidden',
        'append', 'setappends', 'getappends',
        'fill', 'forcefill', 'qualify', 'qualifycolumn',
        'relationloaded', // Checks if relation is loaded (not a relationship itself)
        // Common accessors/mutators patterns
        'getformattedattribute', 'format', 'formatted',
        // Collection/array methods
        'first', 'last', 'get', 'all', 'pluck', 'map', 'filter', 'each',
        'count', 'sum', 'avg', 'min', 'max', 'isempty', 'isnotempty',
        // Validation and checks
        'validate', 'isvalid', 'exists',
        // String representation
        'tostring', '__tostring', 'render', 'display',
    ];

    /** @var array<string> Facades/classes that have query-like methods but are NOT database queries */
    private const NON_QUERY_CLASSES = [
        // Laravel facades
        'cache', 'config', 'session', 'storage', 'cookie', 'auth',
        'log', 'mail', 'event', 'queue', 'broadcast', 'notification',
        'gate', 'validator', 'view', 'response', 'request', 'redirect',
        'url', 'file', 'hash', 'crypt', 'artisan', 'bus', 'http',
        // Common non-Eloquent classes
        'arr', 'str', 'collection', 'carbon', 'datetime',
    ];

    /** @var array<string> Methods that are batch operations (solutions, not N+1 problems) */
    private const BATCH_OPERATION_METHODS = [
        'chunk', 'chunkbyid', 'each', 'eachbyid', 'cursor', 'lazy', 'lazybychunksof',
    ];

    /**
     * @var array<int, array{relationship: string, line: int, loop_type: string, variable: string}>
     */
    private array $issues = [];

    /**
     * @var array<int, array{query: string, line: int, loop_type: string}>
     */
    private array $queryIssues = [];

    /**
     * Stack of loop contexts (for nested loop support).
     *
     * @var array<int, array{variables: array<string>, type: string}>
     */
    private array $loopStack = [];

    /**
     * Track variables and their eager loaded relationships.
     *
     * @var array<string, array<string>>
     */
    private array $eagerLoadedRelationships = [];

    /**
     * Track relationships checked with relationLoaded() per loop variable.
     * Key format: "loopVariable:relationship"
     *
     * @var array<string, bool>
     */
    private array $relationLoadedChecks = [];

    public function __construct() {}

    public function enterNode(Node $node)
    {
        // Track variable assignments to detect eager loading
        if ($node instanceof Expr\Assign) {
            if ($node->var instanceof Expr\Variable && is_string($node->var->name)) {
                // Check if the assignment uses with() or load() for eager loading
                $this->trackEagerLoading($node->expr, $node->var->name);
            }

            return null;
        }

        // Track load() calls on existing variables: $posts->load('user')
        if ($node instanceof Expr\MethodCall) {
            if ($node->var instanceof Expr\Variable &&
                is_string($node->var->name) &&
                $node->name instanceof Node\Identifier &&
                in_array($node->name->toString(), ['load', 'loadMissing'], true)) {

                $varName = $node->var->name;
                $relationships = $this->extractRelationshipsFromEagerLoadCall($node);

                if (! empty($relationships)) {
                    // Merge with existing eager loaded relationships
                    if (isset($this->eagerLoadedRelationships[$varName])) {
                        $this->eagerLoadedRelationships[$varName] = array_values(array_unique(array_merge(
                            $this->eagerLoadedRelationships[$varName],
                            $relationships
                        )));
                    } else {
                        $this->eagerLoadedRelationships[$varName] = $relationships;
                    }
                }
            }
        }

        // Track loop entry
        if ($node instanceof Stmt\Foreach_) {
            $loopVariable = null;

            // Get loop variable name and source variable
            if ($node->valueVar instanceof Expr\Variable && is_string($node->valueVar->name)) {
                $loopVariable = $node->valueVar->name;

                // Check if iterating over a variable with eager loaded relationships
                if ($node->expr instanceof Expr\Variable && is_string($node->expr->name)) {
                    $sourceVar = $node->expr->name;
                    // Copy eager loaded relationships to loop variable context
                    if (isset($this->eagerLoadedRelationships[$sourceVar])) {
                        $this->eagerLoadedRelationships[$loopVariable] =
                            $this->eagerLoadedRelationships[$sourceVar];
                    }
                }
            }

            $this->loopStack[] = [
                'variables' => $loopVariable !== null ? [$loopVariable] : [],
                'type' => self::LOOP_TYPE_FOREACH,
            ];

            return null;
        }

        if ($node instanceof Stmt\For_) {
            $loopVar = $this->extractForLoopVariable($node);
            $this->loopStack[] = [
                'variables' => $loopVar !== null ? [$loopVar] : [],
                'type' => self::LOOP_TYPE_FOR,
            ];

            return null;
        }

        if ($node instanceof Stmt\While_) {
            $condVars = $this->extractConditionVariables($node->cond);
            $this->loopStack[] = [
                'variables' => $condVars,
                'type' => self::LOOP_TYPE_WHILE,
            ];

            return null;
        }

        if ($node instanceof Stmt\Do_) {
            $condVars = $this->extractConditionVariables($node->cond);
            $this->loopStack[] = [
                'variables' => $condVars,
                'type' => self::LOOP_TYPE_DO_WHILE,
            ];

            return null;
        }

        // Detect relationship access inside loops (only foreach loops track relationship access)
        $currentLoop = $this->getCurrentLoop();
        if ($currentLoop !== null && ! empty($currentLoop['variables']) && $currentLoop['type'] === self::LOOP_TYPE_FOREACH) {
            $loopVariable = $currentLoop['variables'][0];
            $loopType = $currentLoop['type'];

            // Track relationLoaded() calls as defensive patterns
            if ($node instanceof Expr\MethodCall &&
                $node->var instanceof Expr\Variable &&
                is_string($node->var->name) &&
                $node->var->name === $loopVariable &&
                $node->name instanceof Node\Identifier &&
                $node->name->toString() === 'relationLoaded' &&
                ! empty($node->args) &&
                $node->args[0]->value instanceof Node\Scalar\String_) {

                $relationship = $node->args[0]->value->value;
                $this->relationLoadedChecks[$loopVariable.':'.$relationship] = true;
            }

            // Look for property access like $post->user, $post->comments, or $post->user->team
            if ($node instanceof Expr\PropertyFetch) {
                // Build full relationship chain (e.g., ['user', 'team'] for $post->user->team)
                $chain = $this->buildRelationshipChain($node, $loopVariable);

                if ($chain !== null && count($chain) > 0) {
                    // Build dot notation path: 'user.team'
                    $relationshipPath = implode('.', $chain);
                    /** @var string $lastProperty */
                    $lastProperty = end($chain);

                    // Check if the last property looks like a relationship
                    if ($this->looksLikeRelationship($lastProperty)) {
                        // Get the first relationship in the chain (e.g., 'user' from 'user.team')
                        $firstRelationship = $chain[0];

                        // Only flag if NOT eager loaded AND NOT checked with relationLoaded()
                        if (! $this->isEagerLoaded($loopVariable, $relationshipPath) &&
                            ! $this->isRelationLoadedChecked($loopVariable, $firstRelationship)) {
                            $this->issues[] = [
                                'relationship' => $relationshipPath,
                                'line' => $node->getStartLine(),
                                'loop_type' => $loopType,
                                'variable' => $loopVariable,
                            ];
                        }
                    }
                }
            }

            // Look for method calls like $post->user() or $post->comments()
            if ($node instanceof Expr\MethodCall) {
                if ($node->var instanceof Expr\Variable &&
                    is_string($node->var->name) &&
                    $node->var->name === $loopVariable &&
                    $node->name instanceof Node\Identifier) {

                    $methodName = $node->name->toString();

                    // Check if this looks like a relationship method
                    if ($this->looksLikeRelationshipMethod($methodName)) {
                        // Only flag if NOT eager loaded AND NOT checked with relationLoaded()
                        if (! $this->isEagerLoaded($loopVariable, $methodName) &&
                            ! $this->isRelationLoadedChecked($loopVariable, $methodName)) {
                            $this->issues[] = [
                                'relationship' => $methodName,
                                'line' => $node->getStartLine(),
                                'loop_type' => $loopType,
                                'variable' => $loopVariable,
                            ];
                        }
                    }
                }
            }
        }

        // Detect queries inside loops (classic N+1 pattern)
        if (! empty($this->loopStack)) {
            $currentLoop = $this->getCurrentLoop();
            $loopType = $currentLoop !== null ? $currentLoop['type'] : 'loop';

            // Check for static method calls that execute queries: Model::where()->get(), Model::find(), etc.
            if ($node instanceof Expr\StaticCall && $node->class instanceof Node\Name) {
                $className = $node->class->getLast();

                // Skip DB facade - handled separately
                if ($className !== 'DB' && $node->name instanceof Node\Identifier) {
                    // Skip non-query facades (Cache, Config, Session, etc.)
                    if (in_array(strtolower($className), self::NON_QUERY_CLASSES, true)) {
                        return null;
                    }

                    $methodName = $node->name->toString();

                    // Direct query execution methods
                    if ($this->isQueryExecutionMethod($methodName)) {
                        // Only flag if query depends on loop variable (true N+1 pattern)
                        if ($this->queryDependsOnLoop($node, $currentLoop)) {
                            $this->queryIssues[] = [
                                'query' => "{$className}::{$methodName}()",
                                'line' => $node->getStartLine(),
                                'loop_type' => $loopType,
                            ];
                        }
                    }
                }
            }

            // Check for method chains ending in query execution: Model::where()->get()
            if ($node instanceof Expr\MethodCall && $node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();

                if ($this->isQueryExecutionMethod($methodName)) {
                    // Walk up the chain to find if it starts with a static call (Model::)
                    $queryDescription = $this->getQueryChainDescription($node);
                    if ($queryDescription !== null) {
                        // Only flag if query depends on loop variable (true N+1 pattern)
                        if ($this->queryDependsOnLoop($node, $currentLoop)) {
                            $this->queryIssues[] = [
                                'query' => $queryDescription,
                                'line' => $node->getStartLine(),
                                'loop_type' => $loopType,
                            ];
                        }
                    }
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Track loop exit - pop from stack and clear relationLoaded checks
        if ($node instanceof Stmt\Foreach_ || $node instanceof Stmt\For_ ||
            $node instanceof Stmt\While_ || $node instanceof Stmt\Do_) {

            // Clear relationLoaded checks for the loop variable being exited
            if ($node instanceof Stmt\Foreach_ &&
                $node->valueVar instanceof Expr\Variable &&
                is_string($node->valueVar->name)) {
                $loopVar = $node->valueVar->name;
                $this->clearRelationLoadedChecks($loopVar);
            }

            array_pop($this->loopStack);
        }

        return null;
    }

    /**
     * Clear relationLoaded checks for a specific loop variable.
     */
    private function clearRelationLoadedChecks(string $varName): void
    {
        $prefix = $varName.':';
        foreach (array_keys($this->relationLoadedChecks) as $key) {
            if (str_starts_with($key, $prefix)) {
                unset($this->relationLoadedChecks[$key]);
            }
        }
    }

    /**
     * Extract loop variable from for loop init expression.
     *
     * e.g., for ($i = 0; ...) returns 'i'
     */
    private function extractForLoopVariable(Stmt\For_ $node): ?string
    {
        if (empty($node->init)) {
            return null;
        }

        // Look for: $i = 0 or $i = ...
        foreach ($node->init as $init) {
            if ($init instanceof Expr\Assign &&
                $init->var instanceof Expr\Variable &&
                is_string($init->var->name)) {
                return $init->var->name;
            }
        }

        return null;
    }

    /**
     * Extract variables from while/do-while condition.
     *
     * e.g., while ($page < $total) returns ['page', 'total']
     *
     * @return array<string>
     */
    private function extractConditionVariables(Node $condition): array
    {
        $variables = [];
        $this->collectVariables($condition, $variables);

        return array_unique($variables);
    }

    /**
     * Recursively collect variable names from an AST node.
     *
     * @param  array<string>  $variables
     */
    private function collectVariables(Node $node, array &$variables): void
    {
        if ($node instanceof Expr\Variable && is_string($node->name)) {
            $variables[] = $node->name;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $subNode = $node->{$name};
            if ($subNode instanceof Node) {
                $this->collectVariables($subNode, $variables);
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node) {
                        $this->collectVariables($item, $variables);
                    }
                }
            }
        }
    }

    /**
     * Check if a query chain depends on loop iteration.
     *
     * @param  array{variables: array<string>, type: string}|null  $loop
     */
    private function queryDependsOnLoop(Node $node, ?array $loop): bool
    {
        if ($loop === null) {
            return false;
        }

        $loopVariables = $loop['variables'];

        // If no loop variables tracked, can't determine dependency - don't flag
        if (empty($loopVariables)) {
            return false;
        }

        // Check if query references any loop variable
        foreach ($loopVariables as $varName) {
            if ($this->chainReferencesVariable($node, $varName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the current loop context (innermost loop).
     *
     * @return array{variables: array<string>, type: string}|null
     */
    private function getCurrentLoop(): ?array
    {
        if (empty($this->loopStack)) {
            return null;
        }

        return end($this->loopStack);
    }

    /**
     * Track eager loading from an expression.
     */
    private function trackEagerLoading(Node $expr, string $varName): void
    {
        // Look for chain like: Post::with(['user', 'comments'])->get()
        // We need to recursively check the chain for with() calls
        $relationships = $this->extractEagerLoadedRelationships($expr);

        if (! empty($relationships)) {
            $this->eagerLoadedRelationships[$varName] = $relationships;
        }
    }

    /**
     * Extract relationships from with() or load() calls in an expression chain.
     *
     * @return array<string>
     */
    private function extractEagerLoadedRelationships(Node $expr): array
    {
        $relationships = [];

        // Check if this is a method call
        if ($expr instanceof Expr\MethodCall) {
            $relationships = $this->extractRelationshipsFromEagerLoadCall($expr);

            // Recursively check the chain (e.g., Post::query()->with()->get())
            $relationships = array_merge(
                $relationships,
                $this->extractEagerLoadedRelationships($expr->var)
            );
        }

        // Check if this is a static call (e.g., Post::with())
        if ($expr instanceof Expr\StaticCall) {
            $relationships = $this->extractRelationshipsFromEagerLoadCall($expr);
        }

        return $relationships;
    }

    /**
     * Extract relationships from a with() or load() method/static call.
     *
     * @return array<string>
     */
    private function extractRelationshipsFromEagerLoadCall(Expr\MethodCall|Expr\StaticCall $expr): array
    {
        // Check if the method is 'with' or 'load'
        if (! ($expr->name instanceof Node\Identifier)) {
            return [];
        }

        $methodName = $expr->name->toString();
        if (! in_array($methodName, ['with', 'load', 'loadMissing'], true)) {
            return [];
        }

        // Extract relationships from all arguments (Laravel supports variadic: with('user', 'comments'))
        if (empty($expr->args)) {
            return [];
        }

        $relationships = [];
        foreach ($expr->args as $arg) {
            $relationships = array_merge(
                $relationships,
                $this->parseRelationshipArgument($arg->value)
            );
        }

        return array_unique($relationships);
    }

    /**
     * Parse relationship argument (string or array).
     *
     * Expands dot notation so 'user.team' becomes ['user', 'user.team'].
     *
     * Handles both simple arrays and closure-keyed arrays:
     * - with(['user', 'comments']) - relationship names as values
     * - with(['user' => fn($q) => $q->select('id'), 'comments']) - relationship names as keys
     *
     * @return array<string>
     */
    private function parseRelationshipArgument(Node $arg): array
    {
        $rawRelationships = [];

        // Handle array of relationships: with(['user', 'comments']) or with(['user' => fn() => ...])
        if ($arg instanceof Expr\Array_) {
            foreach ($arg->items as $item) {
                if ($item === null) {
                    continue;
                }

                // Check if relationship name is in the key (closure-keyed arrays)
                // e.g., ['user' => fn($q) => $q->select('id')]
                if ($item->key instanceof Node\Scalar\String_) {
                    $rawRelationships[] = $item->key->value;
                }
                // Check if relationship name is in the value (simple arrays)
                // e.g., ['user', 'comments']
                elseif ($item->value instanceof Node\Scalar\String_) {
                    $rawRelationships[] = $item->value->value;
                }
            }
        }

        // Handle single relationship: with('user')
        if ($arg instanceof Node\Scalar\String_) {
            $rawRelationships[] = $arg->value;
        }

        // Expand dot notation relationships
        $expanded = [];
        foreach ($rawRelationships as $relationship) {
            $expanded = array_merge($expanded, $this->expandDotNotation($relationship));
        }

        return array_unique($expanded);
    }

    /**
     * Check if a relationship is eager loaded for a variable.
     */
    private function isEagerLoaded(string $varName, string $relationship): bool
    {
        if (! isset($this->eagerLoadedRelationships[$varName])) {
            return false;
        }

        return in_array($relationship, $this->eagerLoadedRelationships[$varName], true);
    }

    /**
     * Check if a relationship was checked with relationLoaded() for a variable.
     *
     * This indicates the developer is aware of the potential N+1 issue
     * and has implemented defensive checking.
     */
    private function isRelationLoadedChecked(string $varName, string $relationship): bool
    {
        return isset($this->relationLoadedChecks[$varName.':'.$relationship]);
    }

    /**
     * Build relationship chain from nested PropertyFetch nodes.
     *
     * Example: $post->user->team returns ['user', 'team']
     *
     * @return array<string>|null Array of property names in order, or null if not starting with loop variable
     */
    private function buildRelationshipChain(Expr\PropertyFetch $node, string $loopVariable): ?array
    {
        $chain = [];
        /** @var Node $current */
        $current = $node;

        // Walk up the PropertyFetch chain
        while ($current instanceof Expr\PropertyFetch) {
            if ($current->name instanceof Node\Identifier) {
                array_unshift($chain, $current->name->toString());
            } else {
                return null; // Dynamic property access, can't analyze
            }
            $current = $current->var;
        }

        // Check if chain starts with loop variable
        if ($current instanceof Expr\Variable &&
            is_string($current->name) &&
            $current->name === $loopVariable) {
            return $chain;
        }

        return null;
    }

    /**
     * Expand dot notation relationship into all intermediate paths.
     *
     * Example: 'user.team.company' returns ['user', 'user.team', 'user.team.company']
     *
     * @return array<string>
     */
    private function expandDotNotation(string $relationship): array
    {
        $parts = explode('.', $relationship);
        $expanded = [];
        $path = '';

        foreach ($parts as $part) {
            $path = $path === '' ? $part : $path.'.'.$part;
            $expanded[] = $path;
        }

        return $expanded;
    }

    /**
     * Check if property name looks like an Eloquent relationship.
     */
    private function looksLikeRelationship(string $name): bool
    {
        $lowerName = strtolower($name);

        // Exclude common non-relationship properties
        if (in_array($lowerName, self::EXCLUDED_PROPERTIES, true)) {
            return false;
        }

        // Exclude naming convention patterns that indicate non-relationships

        // Foreign key pattern: *_id (user_id, post_id, etc.)
        if (str_ends_with($lowerName, '_id')) {
            return false;
        }

        // Timestamp pattern: *_at (published_at, verified_at, etc.)
        if (str_ends_with($lowerName, '_at')) {
            return false;
        }

        // Boolean prefix patterns: is_*, has_*, can_*, should_*, was_*, will_*
        if (preg_match('/^(is|has|can|should|was|will)_/', $lowerName)) {
            return false;
        }

        // Count/total suffix patterns: *_count, *_total, *_sum, *_avg
        if (preg_match('/_(count|total|sum|avg|min|max)$/', $lowerName)) {
            return false;
        }

        // Raw/original prefix patterns: raw_*, original_*
        if (preg_match('/^(raw|original)_/', $lowerName)) {
            return false;
        }

        // Cached/computed prefix patterns: cached_*, computed_*
        if (preg_match('/^(cached|computed|calculated)_/', $lowerName)) {
            return false;
        }

        // Single character names are unlikely to be relationships
        if (strlen($name) === 1) {
            return false;
        }

        // Names starting with underscore are typically internal
        if (str_starts_with($name, '_')) {
            return false;
        }

        // Relationships are typically nouns - this is a heuristic
        return true;
    }

    /**
     * Check if method name looks like a relationship accessor method.
     */
    private function looksLikeRelationshipMethod(string $name): bool
    {
        $lowerName = strtolower($name);

        // Exclude known non-relationship methods
        if (in_array($lowerName, self::EXCLUDED_METHODS, true)) {
            return false;
        }

        // Exclude getter/setter patterns: get*, set*
        if (preg_match('/^(get|set)[A-Z]/', $name)) {
            return false;
        }

        // Exclude accessor attribute pattern: *Attribute (Laravel accessor convention)
        if (str_ends_with($name, 'Attribute')) {
            return false;
        }

        // Exclude scope methods: scope*
        if (str_starts_with($lowerName, 'scope')) {
            return false;
        }

        // Exclude boot/booted methods
        if (str_starts_with($lowerName, 'boot')) {
            return false;
        }

        // Apply same property heuristics
        return $this->looksLikeRelationship($name);
    }

    /**
     * Check if a method name executes a database query.
     */
    private function isQueryExecutionMethod(string $methodName): bool
    {
        $lowerMethodName = strtolower($methodName);

        // Batch operations are intentional solutions to N+1, not problems
        if (in_array($lowerMethodName, self::BATCH_OPERATION_METHODS, true)) {
            return false;
        }

        $executionMethods = [
            // Retrieval methods
            'get', 'first', 'find', 'findorfail', 'findormany', 'findornew',
            'firstor', 'firstorfail', 'firstornew', 'firstorcreate', 'firstwhere',
            'sole', 'all', 'value', 'pluck',
            // Aggregates
            'count', 'sum', 'avg', 'average', 'min', 'max', 'exists', 'doesntexist',
            // Modification methods that also query
            'updateorcreate', 'upsert',
        ];

        return in_array($lowerMethodName, $executionMethods, true);
    }

    /**
     * Get a description of a query chain starting from a static call.
     *
     * Walks up the method chain to find if it starts with Model::query() or Model::where() etc.
     */
    private function getQueryChainDescription(Expr\MethodCall $node): ?string
    {
        $current = $node->var;

        // Walk up the chain
        while ($current instanceof Expr\MethodCall) {
            $current = $current->var;
        }

        // Check if chain starts with a static call (Model::where, Model::query, etc.)
        if ($current instanceof Expr\StaticCall && $current->class instanceof Node\Name) {
            $className = $current->class->getLast();

            // Skip DB facade
            if ($className === 'DB') {
                return null;
            }

            // Skip non-query facades (Cache, Config, Session, etc.)
            if (in_array(strtolower($className), self::NON_QUERY_CLASSES, true)) {
                return null;
            }

            if ($current->name instanceof Node\Identifier) {
                $startMethod = $current->name->toString();
                $endMethod = $node->name instanceof Node\Identifier ? $node->name->toString() : 'unknown';

                return "{$className}::{$startMethod}()->...{$endMethod}()";
            }
        }

        return null;
    }

    /**
     * Check if a method call chain references a specific variable in its arguments.
     */
    private function chainReferencesVariable(Node $node, string $varName): bool
    {
        // Walk the entire method chain checking all arguments
        $current = $node;

        while ($current instanceof Expr\MethodCall) {
            foreach ($current->args as $arg) {
                if ($this->expressionReferencesVariable($arg->value, $varName)) {
                    return true;
                }
            }
            $current = $current->var;
        }

        // Check static call arguments at the root
        if ($current instanceof Expr\StaticCall) {
            foreach ($current->args as $arg) {
                if ($this->expressionReferencesVariable($arg->value, $varName)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Recursively check if an expression references a variable.
     */
    private function expressionReferencesVariable(Node $expr, string $varName): bool
    {
        // Direct variable reference: $user
        if ($expr instanceof Expr\Variable && $expr->name === $varName) {
            return true;
        }

        // Property fetch: $user->id, $user->name
        if ($expr instanceof Expr\PropertyFetch) {
            return $this->expressionReferencesVariable($expr->var, $varName);
        }

        // Method call: $user->getId()
        if ($expr instanceof Expr\MethodCall) {
            if ($this->expressionReferencesVariable($expr->var, $varName)) {
                return true;
            }
            // Check method arguments too
            foreach ($expr->args as $arg) {
                if ($this->expressionReferencesVariable($arg->value, $varName)) {
                    return true;
                }
            }
        }

        // Array access: $user['id'] or $array[$user->id]
        if ($expr instanceof Expr\ArrayDimFetch) {
            if ($this->expressionReferencesVariable($expr->var, $varName)) {
                return true;
            }

            return $expr->dim !== null && $this->expressionReferencesVariable($expr->dim, $varName);
        }

        // Ternary: $user ? $user->id : null
        if ($expr instanceof Expr\Ternary) {
            return $this->expressionReferencesVariable($expr->cond, $varName) ||
                   ($expr->if !== null && $this->expressionReferencesVariable($expr->if, $varName)) ||
                   $this->expressionReferencesVariable($expr->else, $varName);
        }

        // Binary operations: $user->id === 1
        if ($expr instanceof Expr\BinaryOp) {
            return $this->expressionReferencesVariable($expr->left, $varName) ||
                   $this->expressionReferencesVariable($expr->right, $varName);
        }

        // Array items: [$user->id, $user->name]
        if ($expr instanceof Expr\Array_) {
            foreach ($expr->items as $item) {
                if ($item !== null && $this->expressionReferencesVariable($item->value, $varName)) {
                    return true;
                }
            }
        }

        // Closure: function() use ($user) { ... }
        if ($expr instanceof Expr\Closure) {
            // Check if the variable is actually used in the closure body,
            // not just captured in use(). Capture alone doesn't mean the query
            // depends on the variable.
            foreach ($expr->stmts as $stmt) {
                if ($this->nodeContainsVariableReference($stmt, $varName)) {
                    return true;
                }
            }
        }

        // Arrow function: fn() => $user->id
        if ($expr instanceof Expr\ArrowFunction) {
            return $this->expressionReferencesVariable($expr->expr, $varName);
        }

        return false;
    }

    /**
     * Recursively check if any node in the subtree references a variable.
     */
    private function nodeContainsVariableReference(Node $node, string $varName): bool
    {
        // Direct variable reference
        if ($node instanceof Expr\Variable && $node->name === $varName) {
            return true;
        }

        // Recursively check all sub-nodes
        foreach ($node->getSubNodeNames() as $subNodeName) {
            $subNode = $node->{$subNodeName};

            if ($subNode instanceof Node) {
                if ($this->nodeContainsVariableReference($subNode, $varName)) {
                    return true;
                }
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node && $this->nodeContainsVariableReference($item, $varName)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{relationship: string, line: int, loop_type: string, variable: string}>
     */
    public function getIssues(): array
    {
        // Deduplicate issues (same variable accessing same relationship)
        $unique = [];
        $seen = [];

        foreach ($this->issues as $issue) {
            // Include variable name to prevent false deduplication across different variables
            // Don't include line to deduplicate same relationship accessed multiple times
            $key = $issue['variable'].'_'.$issue['relationship'];
            if (! isset($seen[$key])) {
                $unique[] = $issue;
                $seen[$key] = true;
            }
        }

        return $unique;
    }

    /**
     * Get collected query issues (queries executed inside loops).
     *
     * @return array<int, array{query: string, line: int, loop_type: string}>
     */
    public function getQueryIssues(): array
    {
        // Deduplicate by query description and line
        $unique = [];
        $seen = [];

        foreach ($this->queryIssues as $issue) {
            $key = $issue['query'].'_'.$issue['line'];
            if (! isset($seen[$key])) {
                $unique[] = $issue;
                $seen[$key] = true;
            }
        }

        return $unique;
    }
}
