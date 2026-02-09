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

    /** @var array<string> */
    private array $modelNamespaces = ['App\\Models', 'App\\Model'];

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

        // Load model namespaces from config
        $configModelNamespaces = $this->config->get(
            'shieldci.analyzers.best-practices.php-side-filtering.model_namespaces'
        );
        if (is_array($configModelNamespaces) && count($configModelNamespaces) > 0) {
            $this->modelNamespaces = $configModelNamespaces;
        }
    }

    /**
     * Get the configured model namespaces.
     *
     * @return array<string>
     */
    public function getModelNamespaces(): array
    {
        return $this->modelNamespaces;
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

                $visitor = new PhpFilteringVisitor($this->modelNamespaces);
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
     * Note: find() is intentionally NOT in this list because:
     * - find(1) returns Model|null (not a Collection)
     * - find([1,2,3]) returns Collection (array of IDs)
     * We handle find() specially via isFindWithArrayArgument() to only flag
     * when called with an array literal.
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

    /**
     * Suffixes that indicate a class is NOT an Eloquent model.
     * Classes with these suffixes are services, clients, etc.
     *
     * @var array<string>
     */
    private const NON_MODEL_SUFFIXES = [
        'Service', 'Client', 'Repository', 'Handler', 'Factory',
        'Manager', 'Provider', 'Driver', 'Adapter', 'Gateway',
        'Connector', 'Api', 'Helper', 'Utility', 'Collection',
        'Controller', 'Middleware', 'Request', 'Resource', 'Job',
        'Event', 'Listener', 'Observer', 'Policy', 'Rule',
    ];

    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    /** @var array<string> */
    private array $modelNamespaces;

    /**
     * @param  array<string>  $modelNamespaces
     */
    public function __construct(array $modelNamespaces = ['App\\Models', 'App\\Model'])
    {
        $this->modelNamespaces = $modelNamespaces;
    }

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

        // Check if the chain contains find() with an array argument
        $hasFindWithArray = $this->hasFindWithArrayArgument($node);

        // Skip if root is not an Eloquent source (false positive prevention)
        $root = $this->getRootExpression($node);
        if (! $this->isEloquentSource($root, $chain, $hasFindWithArray)) {
            return;
        }

        // Track if root is a relationship (PropertyFetch that looks like relationship)
        // This is used to prevent false positives in hasPhpSideFiltering() for patterns
        // like User::filter() or $service->filter() where there's no fetch method
        $isRelationshipRoot = $root instanceof Node\Expr\PropertyFetch
            && $root->name instanceof Node\Identifier
            && $this->looksLikeRelationship($root->name->toString());

        // Check for problematic patterns
        if ($this->hasPhpSideFiltering($chain, $hasFindWithArray, $isRelationshipRoot)) {
            $pattern = $this->formatChain($chain);
            $severity = $this->determineSeverity($chain, $hasFindWithArray);
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
     * @param  bool  $hasFindWithArray  Whether the chain contains find() with array argument
     */
    private function isEloquentSource(Node\Expr $expr, array $chain = [], bool $hasFindWithArray = false): bool
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
            return $this->hasLikelyEloquentPattern($chain, $hasFindWithArray);
        }

        // Case 5: Method call as root - check if it originates from model-like static call
        if ($expr instanceof Node\Expr\MethodCall) {
            return $this->chainStartsWithModel($expr, $chain, $hasFindWithArray);
        }

        // Default: Cannot determine source type - don't flag
        return false;
    }

    /**
     * Check if a class name looks like an Eloquent model.
     *
     * Uses positive identification patterns:
     * - Configured model namespace patterns (default: App\Models\*, App\Model\*)
     * - Domain\*\Models\* namespace (DDD patterns)
     * - *Model suffix
     *
     * Conservative for short names (no namespace): accepts them as potential models
     * unless they have service/client-like suffixes. This handles the common Laravel
     * pattern where models are imported via `use App\Models\User;`.
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

        // POSITIVE CHECK 1: Configured model namespace patterns
        foreach ($this->modelNamespaces as $modelNamespace) {
            $prefix = rtrim($modelNamespace, '\\').'\\';
            if (str_starts_with($normalized, $prefix)) {
                return true;
            }
        }

        // POSITIVE CHECK 2: Domain-driven patterns (e.g., Domain\Users\Models\User)
        if (str_contains($normalized, '\\Models\\')) {
            return true;
        }

        // POSITIVE CHECK 3: Class name ends with "Model" suffix
        if (str_ends_with($shortName, 'Model')) {
            return true;
        }

        // POSITIVE CHECK 4: Short name only (no namespace) - accept as potential model
        // This handles the common Laravel pattern: `use App\Models\User;` then `User::get()`
        // Reject common non-model patterns (services, clients, etc.), accept others
        if (! str_contains($normalized, '\\')) {
            return ! $this->looksLikeServiceOrClient($shortName);
        }

        // Cannot determine - default to NOT a model
        return false;
    }

    /**
     * Check if a class name looks like a service, client, or other non-model class.
     *
     * @param  string  $name  Short class name (without namespace)
     */
    private function looksLikeServiceOrClient(string $name): bool
    {
        foreach (self::NON_MODEL_SUFFIXES as $suffix) {
            if (str_ends_with($name, $suffix)) {
                return true;
            }
        }

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
     * @param  bool  $hasFindWithArray  Whether the chain contains find() with array argument
     */
    private function hasLikelyEloquentPattern(array $chain, bool $hasFindWithArray = false): bool
    {
        $hasFetch = $hasFindWithArray; // find() with array counts as a fetch
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
     * @param  bool  $hasFindWithArray  Whether the chain contains find() with array argument
     */
    private function chainStartsWithModel(Node\Expr\MethodCall $expr, array $chain = [], bool $hasFindWithArray = false): bool
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
            return $this->hasLikelyEloquentPattern($chain, $hasFindWithArray);
        }

        return false;
    }

    /**
     * Check if property name looks like an Eloquent relationship.
     *
     * Uses POSITIVE IDENTIFICATION: only returns true for patterns that
     * strongly indicate a relationship (plural names, known relationship names).
     * This prevents false positives for custom JSON columns like profile_data.
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

        // POSITIVE IDENTIFICATION: Must look like a relationship
        return $this->hasRelationshipNaming($name);
    }

    /**
     * Check if a property name has relationship-like naming patterns.
     *
     * Laravel relationships typically follow naming conventions:
     * - Plural names for hasMany/belongsToMany: posts, comments, users
     * - CamelCase plural for compound names: orderItems, userRoles
     * - Known singular relationship names: parent, owner, author
     */
    private function hasRelationshipNaming(string $name): bool
    {
        // Convert camelCase/snake_case to words for analysis
        $words = $this->splitCamelCase($name);
        $lastWordRaw = end($words);

        // If splitting failed or returned empty, use the original name
        if ($lastWordRaw === false || $lastWordRaw === '') {
            $lastWord = strtolower($name);
        } else {
            $lastWord = strtolower($lastWordRaw);
        }

        // If the last word is a known non-relationship property, skip it
        // This handles cases like custom_attributes, profile_metadata
        if (in_array($lastWord, self::EXCLUDED_PROPERTIES, true)) {
            return false;
        }

        // Rule 1: Last word should be plural (Laravel convention for hasMany/belongsToMany)
        // posts, comments, items, users, roles, permissions
        if ($this->isPlural($lastWord)) {
            return true;
        }

        // Rule 2: Single word that's a known relationship name
        // e.g., 'parent', 'children', 'owner', 'author'
        if ($this->isKnownRelationshipName($lastWord)) {
            return true;
        }

        // Default: NOT a relationship (conservative approach)
        return false;
    }

    /**
     * Split a property name into words (handles camelCase and snake_case).
     *
     * Examples:
     * - orderItems -> ['order', 'Items'] -> ['order', 'items']
     * - user_roles -> ['user', 'roles']
     * - posts -> ['posts']
     *
     * @return array<string>
     */
    private function splitCamelCase(string $name): array
    {
        // Handle snake_case first
        if (str_contains($name, '_')) {
            return array_filter(explode('_', $name));
        }

        // Handle camelCase: orderItems -> ['order', 'Items']
        $parts = preg_split('/(?=[A-Z])/', $name, -1, PREG_SPLIT_NO_EMPTY);
        if ($parts === false) {
            return [$name];
        }

        return array_filter($parts);
    }

    /**
     * Check if a word is plural (common English plural patterns).
     *
     * Focuses on patterns commonly used in Laravel relationship naming.
     */
    private function isPlural(string $word): bool
    {
        // Skip very short words - often not relationships
        // (e.g., 'id', 'ids' - ids is technically plural but unlikely relationship)
        if (strlen($word) < 4) {
            return false;
        }

        // Irregular plurals that are common relationships
        $irregularPlurals = ['children', 'people', 'media', 'criteria', 'data'];
        if (in_array($word, $irregularPlurals, true)) {
            // 'data' is common but often not a relationship - exclude it
            return $word !== 'data';
        }

        // Words ending in common non-relationship suffixes despite looking plural
        // These often end in 's' but are not plural relationship names
        $falsePositiveSuffixes = ['status', 'news', 'series', 'species', 'analysis'];
        if (in_array($word, $falsePositiveSuffixes, true)) {
            return false;
        }

        // Regular plural patterns:
        // -ies: categories, entries, companies (but not 'series')
        if (preg_match('/[^aeiou]ies$/', $word) === 1) {
            return true;
        }

        // -es: boxes, matches, statuses (but need to be careful)
        // Only match common -es patterns: -shes, -ches, -xes, -zes, -ses
        if (preg_match('/(sh|ch|x|z|ss)es$/', $word) === 1) {
            return true;
        }

        // -s: posts, users, items, comments, orders
        // But exclude words that naturally end in 's' without being plural
        if (str_ends_with($word, 's') && ! str_ends_with($word, 'ss')) {
            // Additional check: word without 's' should be reasonable length
            $singular = rtrim($word, 's');
            if (strlen($singular) >= 3) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a word is a known singular relationship name.
     *
     * These are common names for belongsTo/hasOne relationships
     * that don't follow plural naming.
     */
    private function isKnownRelationshipName(string $word): bool
    {
        // Common singular relationship names (belongsTo/hasOne patterns)
        $knownNames = [
            // Hierarchical relationships
            'parent', 'owner', 'author', 'creator', 'updater',
            // Role-based relationships
            'manager', 'assignee', 'reviewer', 'approver', 'editor',
            // Common singular relations
            'user', 'admin', 'member', 'subscriber', 'customer',
            'profile', 'account', 'organization', 'company', 'team',
            // Document/content relationships
            'document', 'attachment', 'image', 'thumbnail', 'avatar',
            // Location relationships
            'address', 'location', 'country', 'region', 'city',
        ];

        return in_array($word, $knownNames, true);
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

        // Include property name for relationship patterns like $user->posts->filter()
        if ($current instanceof Node\Expr\PropertyFetch && $current->name instanceof Node\Identifier) {
            array_unshift($chain, $current->name->toString());
        }

        return $chain;
    }

    /**
     * Check if a method chain contains a find() call with an array argument.
     *
     * find() has dual return types:
     * - find(1) → Model|null (single ID)
     * - find([1,2,3]) → Collection (array of IDs)
     *
     * We only flag find() when it's called with an array literal, since that
     * returns a Collection. For variables, we cannot determine the type statically.
     */
    private function hasFindWithArrayArgument(Node\Expr\MethodCall $node): bool
    {
        $current = $node;

        while ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\StaticCall) {
            if ($this->isFindWithArrayArgument($current)) {
                return true;
            }

            if ($current instanceof Node\Expr\MethodCall) {
                $current = $current->var;
            } else {
                break;
            }
        }

        return false;
    }

    /**
     * Check if this specific node is a find() call with an array argument.
     */
    private function isFindWithArrayArgument(Node\Expr\StaticCall|Node\Expr\MethodCall $node): bool
    {
        if (! ($node->name instanceof Node\Identifier) || $node->name->toString() !== 'find') {
            return false;
        }

        if (empty($node->args) || ! isset($node->args[0])) {
            return false;
        }

        $firstArg = $node->args[0];
        if (! ($firstArg instanceof Node\Arg)) {
            return false;
        }

        // Array literal: find([1, 2, 3]) -> returns Collection
        return $firstArg->value instanceof Node\Expr\Array_;
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
     * @param  bool  $hasFindWithArray  Whether the chain contains find() with an array argument
     * @param  bool  $isRelationshipRoot  Whether the root is a PropertyFetch that looks like a relationship
     */
    private function hasPhpSideFiltering(array $chain, bool $hasFindWithArray = false, bool $isRelationshipRoot = false): bool
    {
        $fetchIndex = $this->findLastFetchMethod($chain);

        // Check for find() with array argument (acts like a fetch method)
        if ($hasFindWithArray && $fetchIndex === null) {
            $findIndex = $this->findFindMethodIndex($chain);
            if ($findIndex !== null) {
                $fetchIndex = $findIndex;
            }
        }

        // If chain contains find() WITHOUT array argument, skip entirely
        // find(1) or find($id) returns Model|null, not Collection
        // Calling filter() on this is broken code, not a PHP-side filtering issue
        if ($fetchIndex === null && $this->chainContainsFindWithoutArray($chain, $hasFindWithArray)) {
            return false;
        }

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
        // ONLY trigger when root is actually a PropertyFetch that looks like a relationship
        // This prevents false positives for User::filter() or $service->filter()
        // where there's no fetch method but the source isn't a relationship
        if ($isRelationshipRoot) {
            foreach ($chain as $method) {
                if (in_array($method, self::FILTER_METHODS, true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if chain contains find() without an array argument.
     *
     * @param  array<string>  $chain
     * @param  bool  $hasFindWithArray  Whether we already know find() has an array argument
     */
    private function chainContainsFindWithoutArray(array $chain, bool $hasFindWithArray): bool
    {
        // If find() has an array argument, it's not "find without array"
        if ($hasFindWithArray) {
            return false;
        }

        // Check if 'find' is in the chain
        return in_array('find', $chain, true);
    }

    /**
     * Find the index of the find() method in the chain.
     *
     * @param  array<string>  $chain
     */
    private function findFindMethodIndex(array $chain): ?int
    {
        for ($i = count($chain) - 1; $i >= 0; $i--) {
            if ($chain[$i] === 'find') {
                return $i;
            }
        }

        return null;
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
     * - get/all/find([...])/findMany: Critical (can fetch entire table)
     *
     * @param  array<string>  $chain
     * @param  bool  $hasFindWithArray  Whether the chain contains find() with array argument
     */
    private function determineSeverity(array $chain, bool $hasFindWithArray = false): Severity
    {
        // find() with array argument is critical (can fetch many records)
        if ($hasFindWithArray) {
            return Severity::Critical;
        }

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
     * Format method chain for display.
     *
     * Converts array chain to readable string:
     * - ['User', 'where', 'get', 'filter'] => 'User::where()->get()->filter()'
     * - ['posts', 'filter'] => 'posts->filter()' (relationship patterns)
     * - ['filter'] => 'filter()' (single method)
     *
     * @param  array<string>  $chain
     */
    private function formatChain(array $chain): string
    {
        if (empty($chain)) {
            return '';
        }

        // Check if first element is a class name (starts with uppercase)
        if (isset($chain[0]) && $chain[0] !== '' && ctype_upper($chain[0][0])) {
            $root = array_shift($chain);
            if (empty($chain)) {
                return $root;
            }

            return $root.'::'.implode('()->', $chain).'()';
        }

        // Check if first element is a property (from PropertyFetch - relationship access)
        // Properties are accessed without (), methods have ()
        if (count($chain) > 1 && ! in_array($chain[0], self::FETCH_METHODS, true) && ! in_array($chain[0], self::FILTER_METHODS, true)) {
            $property = array_shift($chain);

            // Format: property->method1()->method2()
            return $property.'->'.implode('()->', $chain).'()';
        }

        return implode('()->', $chain).'()';
    }

    /**
     * @param  array<string>  $chain
     */
    private function getRecommendation(array $chain): string
    {
        $pattern = $this->formatChain($chain);
        $fetchMethod = $this->getFetchMethod($chain);

        // Relationship pattern (no fetch method means direct property access)
        if ($fetchMethod === null) {
            return $this->getRelationshipRecommendation($chain, $pattern);
        }

        // Special handling for pluck() patterns
        if ($fetchMethod === 'pluck') {
            return $this->getPluckRecommendation($chain, $pattern);
        }

        return $this->getStandardRecommendation($chain, $pattern);
    }

    /**
     * Get recommendation for relationship patterns (no fetch method).
     *
     * @param  array<string>  $chain
     */
    private function getRelationshipRecommendation(array $chain, string $pattern): string
    {
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

        return sprintf(
            'Move filtering logic to the query builder. Current pattern "%s" filters an already-loaded collection in PHP memory instead of at the database level.',
            $pattern
        );
    }

    /**
     * Get recommendation for pluck() patterns.
     *
     * pluck() already optimizes SQL to select only specific columns,
     * so the recommendation differs from get()/all() patterns.
     *
     * @param  array<string>  $chain
     */
    private function getPluckRecommendation(array $chain, string $pattern): string
    {
        $pluckRecommendations = [
            'filter' => 'Add where() clauses before pluck() to filter at database level. Example: User::where("active", true)->pluck("id") instead of User::pluck("id")->filter(...).',
            'reject' => 'Add whereNot() or where() clauses before pluck() to exclude values at database level. Example: User::where("banned", false)->pluck("id") instead of User::pluck("id")->reject(...).',
            'whereIn' => 'Add whereIn() to the query before pluck(). Example: User::whereIn("role", ["admin"])->pluck("id") instead of User::pluck("id")->whereIn(...).',
            'whereNotIn' => 'Add whereNotIn() to the query before pluck(). Example: User::whereNotIn("status", ["deleted"])->pluck("id") instead of User::pluck("id")->whereNotIn(...).',
        ];

        foreach ($pluckRecommendations as $method => $recommendation) {
            if (in_array($method, $chain, true)) {
                return sprintf(
                    '%s Current pattern "%s" fetches column values then filters in PHP. While pluck() only loads one column, filtering should still happen in SQL for efficiency.',
                    $recommendation,
                    $pattern
                );
            }
        }

        return sprintf(
            'Move filtering to the query builder before pluck(). Current pattern "%s" filters column values in PHP instead of at the database level.',
            $pattern
        );
    }

    /**
     * Get standard recommendation for static model patterns (get/all/etc.).
     *
     * @param  array<string>  $chain
     */
    private function getStandardRecommendation(array $chain, string $pattern): string
    {
        // Standard recommendations for static model patterns
        $recommendations = [
            'filter' => 'Replace filter() with where() clauses before get()/all() to filter at database level. For complex filtering logic, consider database computed columns or raw where clauses.',
            'reject' => 'Replace reject() with where() or whereNot() clauses before get()/all() to filter at database level. The inverse logic can be expressed with whereNot() or negative where conditions.',
            'whereIn' => 'Move whereIn() into the query builder before get()/all(). Example: User::whereIn(...)->get() instead of User::get()->whereIn(...).',
            'whereNotIn' => 'Move whereNotIn() into the query builder before get()/all(). Example: User::whereNotIn(...)->get() instead of User::get()->whereNotIn(...).',
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
