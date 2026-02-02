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
     */
    private function isWhitelisted(string $path): bool
    {
        foreach ($this->whitelist as $pattern) {
            if (str_contains($path, $pattern)) {
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
     * Methods that fetch data from the database (trigger query execution).
     *
     * @var array<string>
     */
    private const FETCH_METHODS = [
        'get',
        'all',
        'paginate',
        'simplePaginate',
        'cursorPaginate',
        'cursor',
        'pluck',
        'findMany',
    ];

    /**
     * Methods that filter collections in PHP (after database fetch).
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
     * Classes that are NOT Eloquent models and should be excluded.
     * These are common Laravel/PHP classes that have similar method names.
     *
     * @var array<string>
     */
    private const EXCLUDED_CLASSES = [
        // Laravel Collections
        'Collection',
        'LazyCollection',
        'EloquentCollection',
        // Laravel Support
        'Arr',
        'Str',
        'Stringable',
        // Carbon/DateTime
        'Carbon',
        'CarbonImmutable',
        'DateTime',
        'DateTimeImmutable',
        // Laravel Facades & Services
        'Config',
        'Session',
        'Request',
        'Cache',
        'Cookie',
        'Http',
        'Response',
        'Log',
        'DB',
        'File',
        'Storage',
        'Queue',
        'Mail',
        'Notification',
        'Event',
        'Gate',
        'Auth',
        'Validator',
        'View',
        'URL',
        'Route',
        'Redirect',
        'Crypt',
        'Hash',
        'Password',
        'RateLimiter',
        'Bus',
        'Artisan',
        'App',
        // Common utility classes
        'Builder',
        'Factory',
        'Faker',
        'Client',
        'GuzzleHttp',
    ];

    /**
     * Properties that are NOT relationships (common scalar/object properties).
     *
     * @var array<string>
     */
    private const EXCLUDED_PROPERTIES = [
        'id',
        'name',
        'title',
        'status',
        'type',
        'data',
        'value',
        'key',
        'config',
        'options',
        'settings',
        'attributes',
        'service',
        'client',
        'http',
        'response',
        'request',
        'cache',
        'session',
        'connection',
        'driver',
        'handler',
        'manager',
        'factory',
        'builder',
        'query',
        'result',
        'output',
        'input',
        'error',
        'message',
        'content',
        'body',
        'headers',
        'params',
        'args',
        'context',
        'container',
        'app',
        'instance',
        'logger',
        'validator',
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

        // Get the root expression (source of the chain)
        $root = $this->getRootExpression($node);

        // Skip if root is not an Eloquent source (prevents false positives)
        if (! $this->isEloquentSource($root, $chain)) {
            return;
        }

        // Check for problematic patterns
        if ($this->hasPhpSideFiltering($chain)) {
            $pattern = implode('->', $chain);

            $this->issues[] = [
                'message' => sprintf(
                    'CRITICAL: Filtering data in PHP instead of database: %s',
                    $pattern
                ),
                'line' => $node->getLine(),
                'severity' => Severity::Critical,
                'recommendation' => $this->getRecommendation($chain),
                'code' => null,
            ];
        }
    }

    /**
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
                break;
            } else {
                break;
            }
        }

        return $chain;
    }

    /**
     * Get the root expression of a method chain.
     *
     * Traverses back through the chain to find the originating expression.
     * For example: User::where()->get()->filter() returns the StaticCall to User.
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
     * Determine if the root expression is likely an Eloquent source.
     *
     * Uses positive identification (conservative approach) to reduce false positives.
     * Only flags patterns where we're confident the source is an Eloquent query.
     *
     * @param  array<string>  $chain
     */
    private function isEloquentSource(Node\Expr $expr, array $chain): bool
    {
        // Case 1: Static call - check if model-like class (e.g., User::get())
        if ($expr instanceof Node\Expr\StaticCall && $expr->class instanceof Node\Name) {
            return $this->looksLikeModel($expr->class);
        }

        // Case 2: Function call - always non-Eloquent (collect(), request(), etc.)
        if ($expr instanceof Node\Expr\FuncCall) {
            return false;
        }

        // Case 3: Property fetch - check if relationship (e.g., $user->posts)
        if ($expr instanceof Node\Expr\PropertyFetch) {
            if ($expr->name instanceof Node\Identifier) {
                return $this->looksLikeRelationship($expr->name->toString());
            }

            return false;
        }

        // Case 4: Variable - require BOTH fetch AND filter in chain
        // This handles: $query->get()->filter() where $query is likely a query builder
        if ($expr instanceof Node\Expr\Variable) {
            return $this->hasLikelyEloquentPattern($chain);
        }

        // Case 5: Method call as root - traverse to find origin
        // This handles nested cases like $obj->query()->get()->filter()
        if ($expr instanceof Node\Expr\MethodCall) {
            return $this->chainStartsWithModel($expr, $chain);
        }

        return false;
    }

    /**
     * Check if a class name looks like an Eloquent model.
     *
     * Uses conservative heuristics to identify model classes:
     * - Class is in App\Models namespace
     * - Class contains \Models\ in path (DDD patterns)
     * - Class ends with Model suffix
     * - NOT in the excluded classes list
     */
    private function looksLikeModel(Node\Name $name): bool
    {
        $parts = $name->getParts();

        if ($parts === []) {
            return false;
        }

        $lastPart = $parts[array_key_last($parts)];

        // Check against excluded classes (facades, utilities, etc.)
        if (in_array($lastPart, self::EXCLUDED_CLASSES, true)) {
            return false;
        }

        // Fully qualified names: check for Models namespace
        if (count($parts) > 1) {
            $namespace = implode('\\', array_slice($parts, 0, -1));

            // App\Models\User, App\Model\User
            if (str_starts_with($namespace, 'App\\Models') || str_starts_with($namespace, 'App\\Model')) {
                return true;
            }

            // DDD patterns: Domain\Models\User, Modules\Users\Models\User
            if (str_contains($namespace, '\\Models')) {
                return true;
            }
        }

        // Single class name: assume it's a model if PascalCase and not excluded
        // This handles imported classes like: use App\Models\User; ... User::get()
        if (count($parts) === 1 && $lastPart !== '' && ctype_upper($lastPart[0])) {
            // Likely a model if it's a simple PascalCase name
            return true;
        }

        return false;
    }

    /**
     * Check if a property name looks like an Eloquent relationship.
     *
     * Uses heuristics to identify relationship properties:
     * - Plural names (posts, comments, users)
     * - Known relationship terms (parent, owner, children)
     * - NOT in excluded properties list
     */
    private function looksLikeRelationship(string $name): bool
    {
        // Check against excluded properties
        if (in_array($name, self::EXCLUDED_PROPERTIES, true)) {
            return false;
        }

        // Known relationship terms
        $relationshipTerms = [
            'parent',
            'owner',
            'children',
            'author',
            'creator',
            'members',
            'followers',
            'following',
            'friends',
            'roles',
            'permissions',
            'tags',
            'categories',
            'items',
            'entries',
            'records',
        ];

        if (in_array($name, $relationshipTerms, true)) {
            return true;
        }

        // Check for plural forms (simple heuristic: ends with 's' and length > 3)
        // This catches: posts, comments, users, orders, products, etc.
        if (strlen($name) > 3 && str_ends_with($name, 's') && ! str_ends_with($name, 'ss')) {
            // Avoid words that commonly end in 's' but aren't plurals
            $nonPluralEndings = ['status', 'class', 'address', 'access', 'process', 'success', 'progress'];
            if (! in_array($name, $nonPluralEndings, true)) {
                return true;
            }
        }

        // Check for 'ies' plural (categories, entries, etc.)
        if (strlen($name) > 4 && str_ends_with($name, 'ies')) {
            return true;
        }

        return false;
    }

    /**
     * Check if a method chain has both fetch and filter methods.
     *
     * For variable roots (e.g., $query->get()->filter()), we require
     * BOTH a fetch method AND a filter method in the chain.
     * This reduces false positives from non-Eloquent variables.
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
     * Check if a method chain starts with what looks like a model.
     *
     * Traverses nested method calls to find the ultimate origin.
     * Handles patterns like: $obj->query()->get()->filter()
     *
     * @param  array<string>  $chain
     */
    private function chainStartsWithModel(Node\Expr\MethodCall $expr, array $chain): bool
    {
        // Traverse to find the ultimate root
        $current = $expr;
        while ($current instanceof Node\Expr\MethodCall) {
            $current = $current->var;
        }

        // If we found a static call, check if it's a model
        if ($current instanceof Node\Expr\StaticCall && $current->class instanceof Node\Name) {
            return $this->looksLikeModel($current->class);
        }

        // If it's a property fetch, check if it looks like a relationship
        if ($current instanceof Node\Expr\PropertyFetch && $current->name instanceof Node\Identifier) {
            return $this->looksLikeRelationship($current->name->toString());
        }

        // For variables, require the chain pattern
        if ($current instanceof Node\Expr\Variable) {
            return $this->hasLikelyEloquentPattern($chain);
        }

        return false;
    }

    /**
     * @param  array<string>  $chain
     */
    private function hasPhpSideFiltering(array $chain): bool
    {
        // Only detect patterns NOT covered by Larastan:
        // - filter() - Custom filtering with closures
        // - reject() - Inverse of filter
        // - whereIn() - Array-based filtering
        // - whereNotIn() - Inverse of whereIn
        //
        // Patterns like where(), first(), last(), take(), skip() are
        // detected by CollectionCallAnalyzer (via Larastan)
        $criticalPatterns = [
            ['all', 'filter'],
            ['all', 'reject'],
            ['all', 'whereIn'],
            ['all', 'whereNotIn'],
            ['get', 'filter'],
            ['get', 'reject'],
            ['get', 'whereIn'],
            ['get', 'whereNotIn'],
        ];

        foreach ($criticalPatterns as $pattern) {
            if ($this->chainContainsSequence($chain, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a chain contains a specific sequence of methods.
     *
     * This properly checks for consecutive method calls, not just substring matching.
     * For example, ['get', 'filter'] will match in ['User', 'where', 'get', 'filter']
     * but NOT in ['getFilter'] or ['get', 'where', 'filter'] if we're looking for
     * consecutive calls.
     *
     * @param  array<string>  $chain
     * @param  array<string>  $sequence
     */
    private function chainContainsSequence(array $chain, array $sequence): bool
    {
        $chainLength = count($chain);
        $sequenceLength = count($sequence);

        if ($sequenceLength > $chainLength) {
            return false;
        }

        // Check if sequence appears consecutively in chain
        for ($i = 0; $i <= $chainLength - $sequenceLength; $i++) {
            $match = true;
            for ($j = 0; $j < $sequenceLength; $j++) {
                if ($chain[$i + $j] !== $sequence[$j]) {
                    $match = false;
                    break;
                }
            }
            if ($match) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<string>  $chain
     */
    private function getRecommendation(array $chain): string
    {
        $pattern = implode('->', $chain);

        // Recommendations for the 4 unique patterns we detect
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
