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
 * Detects PHP-side filtering patterns not covered by Larastan.
 *
 * This analyzer complements CollectionCallAnalyzer by detecting unique patterns
 * that Larastan's noUnnecessaryCollectionCall rule doesn't cover:
 *
 * Checks for:
 * - ->all()->filter() / ->get()->filter() - Custom filtering with closures
 * - ->all()->reject() / ->get()->reject() - Inverse filtering
 * - ->all()->whereIn() / ->get()->whereIn() - Array-based filtering
 * - ->all()->whereNotIn() / ->get()->whereNotIn() - Inverse array filtering
 *
 * Note: Patterns like ->get()->where(), ->get()->first(), etc. are detected by
 * CollectionCallAnalyzer (via Larastan) and are not checked here.
 */
class PhpSideFilteringAnalyzer extends AbstractFileAnalyzer
{
    /** @var array<string> */
    private array $whitelist = [];

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'php-side-filtering',
            name: 'PHP-Side Collection Filtering Analyzer',
            description: 'Detects filter(), reject(), whereIn(), and whereNotIn() usage after database fetch (patterns not covered by Larastan)',
            category: Category::BestPractices,
            severity: Severity::Critical,
            tags: ['laravel', 'performance', 'database', 'memory', 'optimization', 'collections'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/php-side-filtering',
            timeToFix: 15
        );
    }

    /**
     * Load configuration from config repository.
     */
    private function loadConfiguration(): void
    {
        // Default whitelist (empty)
        $defaultWhitelist = [];

        // Load from config
        $configWhitelist = $this->config->get('shieldci.analyzers.best-practices.php-side-filtering.whitelist', []);

        // Ensure configWhitelist is an array
        if (! is_array($configWhitelist)) {
            $configWhitelist = [];
        }

        // Merge defaults with config (config takes precedence)
        $this->whitelist = array_values(array_unique(array_merge($defaultWhitelist, $configWhitelist)));
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration
        $this->loadConfiguration();

        $issues = [];

        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            // Check whitelist
            $relativePath = $this->getRelativePath($file);
            if ($this->isWhitelisted($relativePath)) {
                continue;
            }

            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new PhpFilteringVisitor;
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssue(
                        message: $issue['message'],
                        location: new Location($relativePath, $issue['line']),
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
            return $this->passed('No PHP-side filtering detected (filter/reject/whereIn/whereNotIn after fetch)');
        }

        return $this->failed(
            sprintf('Found %d instance(s) of PHP-side filtering that should be done in database', count($issues)),
            $issues
        );
    }

    /**
     * Check if a file path is whitelisted.
     *
     * Supports:
     * - Exact filename match (without extension): "LegacyUserService"
     * - Glob patterns: "app/Legacy/*", "app/Services/Legacy/**\/*.php"
     * - Directory segment matching: "Legacy" matches "Services/Legacy/UserService.php"
     */
    private function isWhitelisted(string $path): bool
    {
        foreach ($this->whitelist as $pattern) {
            // Exact full path match
            if ($path === $pattern) {
                return true;
            }

            // Glob pattern matching (supports * and **)
            if (str_contains($pattern, '*')) {
                if (fnmatch($pattern, $path)) {
                    return true;
                }

                continue;
            }

            // Path segment matching (must match full path segment)
            // Pattern "User" matches "Services/User.php" or "User/Service.php"
            // but NOT "SuperUserService.php"
            $segments = explode('/', $path);
            $fileWithoutExt = pathinfo(end($segments), PATHINFO_FILENAME);

            // Exact filename match (without extension)
            if ($fileWithoutExt === $pattern) {
                return true;
            }

            // Directory segment matching
            if (in_array($pattern, $segments, true)) {
                return true;
            }
        }

        return false;
    }
}

/**
 * Visitor to detect PHP-side filtering.
 */
class PhpFilteringVisitor extends NodeVisitorAbstract
{
    /**
     * Eloquent methods that fetch data from the database and return collections.
     *
     * @var array<string>
     */
    private const FETCH_METHODS = [
        'get',
        'all',
        'paginate',
        'simplePaginate',
        'cursorPaginate',
        'cursor',        // Returns LazyCollection
        'pluck',         // Returns collection of values
        'find',          // Can return collection with array of IDs
        'findMany',      // Always returns collection
    ];

    /**
     * PHP-side filtering methods that indicate filtering after database fetch.
     *
     * @var array<string>
     */
    private const FILTER_METHODS = [
        'filter',
        'reject',
        'whereIn',
        'whereNotIn',
    ];

    /**
     * Classes that are not Eloquent models/queries.
     * Static calls on these classes should not be flagged.
     *
     * @var array<string>
     */
    private const EXCLUDED_CLASSES = [
        'Collection',
        'Arr',
        'Str',
        'Carbon',
        'CarbonImmutable',
        'DateTime',
        'DateTimeImmutable',
        'Config',
        'Session',
        'Request',
        'Cache',
        'Cookie',
        'Http',
        'Response',
        'Log',
        'Event',
        'Mail',
        'Queue',
        'Storage',
        'File',
        'Validator',
        'Route',
        'URL',
        'View',
        'Redirect',
        'Gate',
        'Bus',
        'Notification',
        'Password',
        'RateLimiter',
        'Broadcast',
    ];

    /**
     * Common model properties that are NOT relationships.
     * Borrowed from EloquentNPlusOneAnalyzer.
     *
     * @var array<string>
     */
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
        // Status and flags
        'status', 'state', 'type', 'kind', 'category', 'role', 'group',
        'active', 'enabled', 'visible', 'published', 'approved', 'verified',
        // JSON/array fields
        'data', 'meta', 'metadata', 'settings', 'options', 'config', 'attributes',
        'properties', 'payload', 'extra', 'info', 'details', 'preferences',
        // Miscellaneous
        'value', 'result', 'output', 'input', 'response', 'request',
        'color', 'format', 'version', 'note', 'notes', 'comment', 'reason',
        // Service/dependency injection properties (commonly on $this)
        'service', 'client', 'repository', 'handler', 'factory', 'manager',
        'provider', 'driver', 'adapter', 'gateway', 'connector', 'dispatcher',
        'resolver', 'builder', 'validator', 'transformer', 'serializer', 'parser',
        'logger', 'cache', 'session', 'queue', 'mailer', 'notifier', 'broadcaster',
    ];

    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    public function enterNode(Node $node): ?Node
    {
        // Detect chained method calls
        if ($node instanceof Node\Expr\MethodCall) {
            $this->analyzeMethodChain($node);
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

    private function analyzeMethodChain(Node\Expr\MethodCall $node): void
    {
        // Get the full chain of methods
        $chain = $this->getMethodChain($node);

        // Skip if root is not an Eloquent source (false positive prevention)
        $root = $this->getRootExpression($node);
        if (! $this->isEloquentSource($root, $chain)) {
            return;
        }

        // Check for problematic patterns
        if ($this->hasPhpSideFiltering($chain)) {
            $pattern = implode('->', $chain);
            $severity = $this->determineSeverity($chain);
            $severityLabel = $severity === Severity::Critical ? 'CRITICAL' : 'WARNING';

            $this->issues[] = [
                'message' => sprintf(
                    '%s: Filtering data in PHP instead of database: %s',
                    $severityLabel,
                    $pattern
                ),
                'line' => $node->getLine(),
                'severity' => $severity,
                'recommendation' => $this->getRecommendation($chain),
                'code' => null,
            ];
        }
    }

    /**
     * Traverse up the method chain to find the original expression.
     */
    private function getRootExpression(Node\Expr\MethodCall $node): Node\Expr
    {
        $current = $node;
        while ($current instanceof Node\Expr\MethodCall) {
            $current = $current->var;
        }

        return $current;
    }

    /**
     * Check if the root expression is likely an Eloquent query source.
     *
     * Uses POSITIVE IDENTIFICATION: only returns true for patterns we can
     * confidently identify as Eloquent sources. This prevents false positives
     * for API clients, services, and other non-Eloquent sources.
     *
     * @param  array<string>  $chain  Method chain for heuristic detection
     */
    private function isEloquentSource(Node\Expr $expr, array $chain = []): bool
    {
        // Case 1: Static call - check if it's a model-like class
        if ($expr instanceof Node\Expr\StaticCall && $expr->class instanceof Node\Name) {
            return $this->looksLikeModel($expr->class);
        }

        // Case 2: Function call - only helper functions, all are non-Eloquent
        // (request, config, collect, cache, session, etc.)
        if ($expr instanceof Node\Expr\FuncCall) {
            return false;
        }

        // Case 3: Property fetch - check if looks like relationship
        // $this->service->all() - likely NOT Eloquent (returns false)
        // $user->posts - likely relationship (returns true if posts looks like relationship)
        if ($expr instanceof Node\Expr\PropertyFetch) {
            if ($expr->name instanceof Node\Identifier) {
                return $this->looksLikeRelationship($expr->name->toString());
            }

            return false;
        }

        // Case 4: Variable - use heuristic: if chain has BOTH fetch and filter,
        // it's likely an Eloquent query being filtered in PHP
        // e.g., $query->get()->filter() where $query = User::where(...)
        if ($expr instanceof Node\Expr\Variable) {
            return $this->hasLikelyEloquentPattern($chain);
        }

        // Case 5: Method call as root - check if it originates from model-like static call
        if ($expr instanceof Node\Expr\MethodCall) {
            return $this->chainStartsWithModel($expr, $chain);
        }

        // Default: Cannot determine source type - don't flag
        return false;
    }

    /**
     * Check if a class name looks like an Eloquent model.
     *
     * Uses positive identification patterns:
     * - App\Models\* namespace
     * - Domain\*\Models\* namespace (DDD patterns)
     * - *Model suffix
     */
    private function looksLikeModel(Node\Name $name): bool
    {
        $fqn = $name->toString();
        $normalized = ltrim($fqn, '\\');
        $parts = explode('\\', $normalized);
        $shortName = end($parts);

        // Quick rejection: known non-model classes
        if (in_array($shortName, self::EXCLUDED_CLASSES, true)) {
            return false;
        }

        // POSITIVE CHECK 1: Model namespace patterns
        if (str_starts_with($normalized, 'App\\Models\\') ||
            str_starts_with($normalized, 'App\\Model\\')) {
            return true;
        }

        // POSITIVE CHECK 2: Domain-driven patterns (e.g., Domain\Users\Models\User)
        if (str_contains($normalized, '\\Models\\')) {
            return true;
        }

        // POSITIVE CHECK 3: Class name ends with "Model" suffix
        if (str_ends_with($shortName, 'Model')) {
            return true;
        }

        // POSITIVE CHECK 4: Short name only (no namespace) - assume it's a model
        // When developers write User::all(), Order::get(), etc. without namespace,
        // it's almost always a model reference (use statement imports it)
        if (! str_contains($normalized, '\\')) {
            return true;
        }

        // Cannot determine - default to NOT a model
        return false;
    }

    /**
     * Check if method chain has both fetch and filter methods (Eloquent heuristic).
     *
     * When a variable is used as the root (e.g., $query->get()->filter()),
     * we can't know the variable's type. However, if the chain contains
     * BOTH a fetch method (get, all, paginate, etc.) AND a filter method
     * (filter, reject, whereIn, whereNotIn), it strongly indicates an
     * Eloquent query being filtered in PHP.
     *
     * @param  array<string>  $chain
     */
    private function hasLikelyEloquentPattern(array $chain): bool
    {
        $hasFetch = false;
        $hasFilter = false;

        foreach ($chain as $method) {
            if (in_array($method, self::FETCH_METHODS, true)) {
                $hasFetch = true;
            }
            if (in_array($method, self::FILTER_METHODS, true)) {
                $hasFilter = true;
            }
        }

        return $hasFetch && $hasFilter;
    }

    /**
     * Traverse method chain to check if it starts with a model-like static call.
     *
     * @param  array<string>  $chain  Method chain for heuristic detection when variable is found
     */
    private function chainStartsWithModel(Node\Expr\MethodCall $expr, array $chain = []): bool
    {
        $current = $expr;
        while ($current instanceof Node\Expr\MethodCall) {
            $current = $current->var;
        }

        if ($current instanceof Node\Expr\StaticCall && $current->class instanceof Node\Name) {
            return $this->looksLikeModel($current->class);
        }

        // Variable at root of subchain - use heuristic
        if ($current instanceof Node\Expr\Variable) {
            return $this->hasLikelyEloquentPattern($chain);
        }

        return false;
    }

    /**
     * Check if property name looks like an Eloquent relationship.
     *
     * Uses heuristic exclusion patterns from EloquentNPlusOneAnalyzer.
     */
    private function looksLikeRelationship(string $name): bool
    {
        $lowerName = strtolower($name);

        // Exclude common non-relationship properties
        if (in_array($lowerName, self::EXCLUDED_PROPERTIES, true)) {
            return false;
        }

        // Foreign key pattern: *_id
        if (str_ends_with($lowerName, '_id')) {
            return false;
        }

        // Timestamp pattern: *_at
        if (str_ends_with($lowerName, '_at')) {
            return false;
        }

        // Boolean prefix patterns: is_*, has_*, can_*, should_*, was_*, will_*
        if (preg_match('/^(is|has|can|should|was|will)_/', $lowerName) === 1) {
            return false;
        }

        // Count/total suffix patterns: *_count, *_total, *_sum, *_avg, *_min, *_max
        if (preg_match('/_(count|total|sum|avg|min|max)$/', $lowerName) === 1) {
            return false;
        }

        // Raw/original prefix patterns: raw_*, original_*, cached_*, computed_*, calculated_*
        if (preg_match('/^(raw|original|cached|computed|calculated)_/', $lowerName) === 1) {
            return false;
        }

        // Service/dependency injection patterns (camelCase): *Service, *Client, *Repository, etc.
        // These are typically injected dependencies, not Eloquent relationships
        if (preg_match('/(service|client|repository|handler|factory|manager|provider|driver|adapter|gateway|connector|api)$/i', $name) === 1) {
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

        // Assume it's a relationship (heuristic)
        return true;
    }

    /**
     * Get the full method chain including static call class name for context.
     *
     * For `User::where()->get()->filter()`, returns:
     * ['User', 'where', 'get', 'filter']
     *
     * @return array<string>
     */
    private function getMethodChain(Node\Expr\MethodCall $node): array
    {
        $chain = [];
        $current = $node;

        while ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\StaticCall) {
            if ($current->name instanceof Node\Identifier) {
                array_unshift($chain, $current->name->toString());
            }

            if ($current instanceof Node\Expr\MethodCall) {
                $current = $current->var;
            } elseif ($current instanceof Node\Expr\StaticCall) {
                // Include class name in chain for context
                if ($current->class instanceof Node\Name) {
                    array_unshift($chain, $current->class->toString());
                }
                break;
            } else {
                break;
            }
        }

        return $chain;
    }

    /**
     * Check if a method chain has PHP-side filtering after a database fetch.
     *
     * Detects patterns NOT covered by Larastan:
     * - filter() - Custom filtering with closures
     * - reject() - Inverse of filter
     * - whereIn() - Array-based filtering
     * - whereNotIn() - Inverse of whereIn
     *
     * Patterns like where(), first(), last(), take(), skip() are
     * detected by CollectionCallAnalyzer (via Larastan)
     *
     * @param  array<string>  $chain
     */
    private function hasPhpSideFiltering(array $chain): bool
    {
        $fetchIndex = $this->findLastFetchMethod($chain);

        // Standard pattern: Model::get()->filter()
        if ($fetchIndex !== null) {
            for ($i = $fetchIndex + 1; $i < count($chain); $i++) {
                if (in_array($chain[$i], self::FILTER_METHODS, true)) {
                    return true;
                }
            }

            return false;
        }

        // Relationship pattern: $model->relationship->filter()
        // No fetch method, but has filter method
        foreach ($chain as $method) {
            if (in_array($method, self::FILTER_METHODS, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Find the index of the last fetch method in the chain.
     *
     * @param  array<string>  $chain
     */
    private function findLastFetchMethod(array $chain): ?int
    {
        for ($i = count($chain) - 1; $i >= 0; $i--) {
            if (in_array($chain[$i], self::FETCH_METHODS, true)) {
                return $i;
            }
        }

        return null;
    }

    /**
     * Find the fetch method used in the chain (for severity determination).
     *
     * @param  array<string>  $chain
     */
    private function getFetchMethod(array $chain): ?string
    {
        $fetchIndex = $this->findLastFetchMethod($chain);

        return $fetchIndex !== null ? $chain[$fetchIndex] : null;
    }

    /**
     * Determine severity based on the fetch method used.
     *
     * - paginate/simplePaginate/cursorPaginate: Medium (controlled dataset size)
     * - cursor: Medium (lazy loading, memory efficient)
     * - pluck: Medium (single column, smaller memory footprint)
     * - relationship (no fetch method): Medium (scoped by foreign key)
     * - get/all/find/findMany: Critical (can fetch entire table)
     *
     * @param  array<string>  $chain
     */
    private function determineSeverity(array $chain): Severity
    {
        $fetchMethod = $this->getFetchMethod($chain);

        // Pagination methods: controlled dataset size
        if (in_array($fetchMethod, ['paginate', 'simplePaginate', 'cursorPaginate'], true)) {
            return Severity::Medium;
        }

        // Cursor: lazy loading, memory efficient
        if ($fetchMethod === 'cursor') {
            return Severity::Medium;
        }

        // Pluck: single column, smaller memory footprint
        if ($fetchMethod === 'pluck') {
            return Severity::Medium;
        }

        // Relationship pattern (no fetch method in chain)
        // e.g., $user->posts->filter() has no get()/all() call
        // Relationship collections are scoped by foreign key, less dangerous
        if ($fetchMethod === null) {
            return Severity::Medium;
        }

        // get(), all(), find(), findMany(): can potentially fetch entire table
        return Severity::Critical;
    }

    /**
     * @param  array<string>  $chain
     */
    private function getRecommendation(array $chain): string
    {
        $pattern = implode('->', $chain);
        $fetchMethod = $this->getFetchMethod($chain);

        // Relationship pattern (no fetch method means direct property access)
        if ($fetchMethod === null) {
            $relationshipRecommendations = [
                'filter' => 'Use constrained eager loading instead: User::with([\'relationship\' => fn($q) => $q->where(...)])->get(). Or query the relationship directly: $model->relationship()->where(...)->get().',
                'reject' => 'Use constrained eager loading with whereNot conditions: User::with([\'relationship\' => fn($q) => $q->whereNot(...)])->get(). Or query directly: $model->relationship()->whereNot(...)->get().',
                'whereIn' => 'Use constrained eager loading: User::with([\'relationship\' => fn($q) => $q->whereIn(...)])->get(). Or query directly: $model->relationship()->whereIn(...)->get().',
                'whereNotIn' => 'Use constrained eager loading: User::with([\'relationship\' => fn($q) => $q->whereNotIn(...)])->get(). Or query directly: $model->relationship()->whereNotIn(...)->get().',
            ];

            foreach ($relationshipRecommendations as $method => $recommendation) {
                if (in_array($method, $chain, true)) {
                    return sprintf(
                        '%s Current pattern "%s" filters an already-loaded collection in PHP memory instead of at the database level.',
                        $recommendation,
                        $pattern
                    );
                }
            }
        }

        // Standard recommendations for static model patterns
        $recommendations = [
            'filter' => 'Replace filter() with where() clauses before get()/all() to filter at database level. For complex filtering logic, consider database computed columns or raw where clauses.',
            'reject' => 'Replace reject() with where() or whereNot() clauses before get()/all() to filter at database level. The inverse logic can be expressed with whereNot() or negative where conditions.',
            'whereIn' => 'Replace whereIn() with whereIn() in the query builder before get()/all(). Move this filtering to the database query.',
            'whereNotIn' => 'Replace whereNotIn() with whereNotIn() in the query builder before get()/all(). Move this filtering to the database query.',
        ];

        // Find which filter method is being used
        foreach ($recommendations as $method => $recommendation) {
            if (in_array($method, $chain, true)) {
                return sprintf(
                    '%s Current pattern "%s" loads all data into memory before filtering, which is extremely inefficient and can cause memory exhaustion on large datasets.',
                    $recommendation,
                    $pattern
                );
            }
        }

        return sprintf(
            'Move filtering logic to database queries. Current pattern "%s" loads all data into memory before filtering, which is inefficient and dangerous.',
            $pattern
        );
    }
}
