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
     * Laravel helper functions that return non-Eloquent data.
     * These should not be flagged as database queries.
     *
     * @var array<string>
     */
    private const EXCLUDED_HELPERS = [
        'config',
        'session',
        'request',
        'cache',
        'cookie',
        'collect',
        'env',
        'app',
        'auth',
        'validator',
        'response',
        'redirect',
        'view',
        'route',
        'url',
        'trans',
        '__',
        'old',
        'now',
        'today',
        'json_decode',
        'array_filter',
        'array_map',
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
        if (! $this->isEloquentSource($root)) {
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
     * This method filters out known non-Eloquent sources to prevent false positives.
     */
    private function isEloquentSource(Node\Expr $expr): bool
    {
        // Case 1: Function call - check if it's an excluded helper
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            $name = strtolower($expr->name->toString());
            if (in_array($name, array_map('strtolower', self::EXCLUDED_HELPERS), true)) {
                return false;
            }
        }

        // Case 2: Static call - check class name
        if ($expr instanceof Node\Expr\StaticCall && $expr->class instanceof Node\Name) {
            $className = $expr->class->getLast();
            if (in_array($className, self::EXCLUDED_CLASSES, true)) {
                return false;
            }
        }

        // Case 3: Property fetch on $this that looks like a helper
        // e.g., $this->request->all()->filter() where request is injected
        if ($expr instanceof Node\Expr\PropertyFetch) {
            if ($expr->name instanceof Node\Identifier) {
                $propertyName = strtolower($expr->name->toString());
                // Skip properties that match helper names (likely injected services)
                $serviceProperties = ['request', 'session', 'cache', 'config', 'validator'];
                if (in_array($propertyName, $serviceProperties, true)) {
                    return false;
                }
            }
        }

        // Case 4: Method call starting from a known non-Eloquent source
        // Handle cases like app()->make('config')->get()
        if ($expr instanceof Node\Expr\MethodCall) {
            // Check the immediate method name
            if ($expr->name instanceof Node\Identifier) {
                $methodName = $expr->name->toString();
                // json() typically returns array/collection from HTTP responses
                if (in_array($methodName, ['json', 'toArray', 'jsonSerialize'], true)) {
                    return false;
                }
            }
        }

        // Default: assume Eloquent (safer to flag than miss)
        return true;
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
