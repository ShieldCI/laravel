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
     * Get recommendation for N+1 issue.
     */
    private function getRecommendation(string $relationship, string $loopType): string
    {
        return "Accessing the '{$relationship}' relationship inside a {$loopType} will trigger a separate database query for each iteration, causing an N+1 query problem. ";
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
        'relationloaded', // Defensive N+1 check method
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

    /**
     * @var array<int, array{relationship: string, line: int, loop_type: string, variable: string}>
     */
    private array $issues = [];

    /**
     * Stack of loop contexts (for nested loop support).
     *
     * @var array<int, array{variable: string|null, type: string}>
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
                        $this->eagerLoadedRelationships[$varName] = array_merge(
                            $this->eagerLoadedRelationships[$varName],
                            $relationships
                        );
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
                'variable' => $loopVariable,
                'type' => self::LOOP_TYPE_FOREACH,
            ];

            return null;
        }

        if ($node instanceof Stmt\For_) {
            $this->loopStack[] = [
                'variable' => null,
                'type' => self::LOOP_TYPE_FOR,
            ];

            return null;
        }

        if ($node instanceof Stmt\While_) {
            $this->loopStack[] = [
                'variable' => null,
                'type' => self::LOOP_TYPE_WHILE,
            ];

            return null;
        }

        if ($node instanceof Stmt\Do_) {
            $this->loopStack[] = [
                'variable' => null,
                'type' => self::LOOP_TYPE_DO_WHILE,
            ];

            return null;
        }

        // Detect relationship access inside loops
        $currentLoop = $this->getCurrentLoop();
        if ($currentLoop !== null && $currentLoop['variable'] !== null) {
            $loopVariable = $currentLoop['variable'];
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
     * Get the current loop context (innermost loop).
     *
     * @return array{variable: string|null, type: string}|null
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

        // Extract relationships from the argument
        if (empty($expr->args)) {
            return [];
        }

        return $this->parseRelationshipArgument($expr->args[0]->value);
    }

    /**
     * Parse relationship argument (string or array).
     *
     * Expands dot notation so 'user.team' becomes ['user', 'user.team'].
     *
     * @return array<string>
     */
    private function parseRelationshipArgument(Node $arg): array
    {
        $rawRelationships = [];

        // Handle array of relationships: with(['user', 'comments'])
        if ($arg instanceof Expr\Array_) {
            foreach ($arg->items as $item) {
                if ($item !== null && $item->value instanceof Node\Scalar\String_) {
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
}
