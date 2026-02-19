<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects cache lock usage on the default cache store.
 *
 * Checks for:
 * - Cache::lock() calls using the default cache store
 * - Missing lock_connection configuration (Laravel 8.20+)
 * - Risk of locks being cleared when cache is cleared
 */
class SharedCacheLockAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<string, array{file: string, line: int}>
     */
    private array $lockUsages = [];

    /**
     * Maps variable names to their assigned cache store names.
     *
     * @var array<string, string>
     */
    private array $variableStores = [];

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'shared-cache-lock',
            name: 'Shared Cache Lock Store Analyzer',
            description: 'Detects cache lock usage on the default cache store, which can cause locks to be cleared when cache is flushed',
            category: Category::Performance,
            severity: Severity::Low,
            tags: ['performance', 'cache', 'locks', 'redis', 'reliability'],
            timeToFix: 20
        );
    }

    public function shouldRun(): bool
    {
        // Only run if using Redis cache driver
        return $this->getCacheDriver() === 'redis';
    }

    public function getSkipReason(): string
    {
        $driver = $this->getCacheDriver();

        if ($driver === null) {
            return 'Default cache store not configured';
        }

        return "Not using Redis cache driver (current: $driver)";
    }

    protected function runAnalysis(): ResultInterface
    {
        // Check if lock_connection is configured separately (Laravel 8.20+)
        $defaultStore = $this->getDefaultStore();
        if ($defaultStore === null) {
            return $this->passed('Default cache store not configured');
        }

        $lockConnection = $this->config->get("cache.stores.$defaultStore.lock_connection");
        $cacheConnection = $this->config->get("cache.stores.$defaultStore.connection");

        // Validate types
        if ($lockConnection !== null && ! is_string($lockConnection)) {
            $lockConnection = null;
        }
        if ($cacheConnection !== null && ! is_string($cacheConnection)) {
            $cacheConnection = null;
        }

        if ($lockConnection !== null && $lockConnection !== $cacheConnection) {
            return $this->passed('Cache locks use a separate connection');
        }

        // Set paths to analyze (app directory only)
        $this->setPaths(['app']);

        // Search for Cache::lock() usage in the codebase
        $this->findCacheLockUsage();

        if (empty($this->lockUsages)) {
            return $this->passed('No cache lock usage detected');
        }

        // Create issues for each lock usage
        $issues = [];
        foreach (array_values($this->lockUsages) as $usage) {
            $issues[] = $this->createIssue(
                message: 'Cache lock usage detected on default cache store',
                location: new Location($this->getRelativePath($usage['file']), $usage['line']),
                severity: $this->metadata()->severity,
                recommendation: $this->getRecommendation(),
                code: FileParser::getCodeSnippet($usage['file'], $usage['line']),
                metadata: [
                    'file' => $usage['file'],
                    'line' => $usage['line'],
                    'default_store' => $defaultStore,
                    'cache_connection' => $cacheConnection,
                    'lock_connection' => $lockConnection,
                ]
            );
        }

        $message = count($issues) === 0
            ? 'No cache lock usage detected'
            : sprintf('Found %d cache lock usage(s) on default cache store', count($this->lockUsages));

        return $this->resultBySeverity($message, $issues);
    }

    private function findCacheLockUsage(): void
    {
        foreach ($this->getPhpFiles() as $file) {
            $filePath = $file instanceof \SplFileInfo ? $file->getPathname() : (string) $file;
            $content = FileParser::readFile($filePath);

            if ($content === null) {
                continue;
            }

            // Simple pattern matching for Cache::lock() calls
            if (str_contains($content, 'Cache::lock(') || str_contains($content, '->lock(')) {
                try {
                    $ast = $this->parser->parseFile($filePath);

                    // Track variable assignments to identify cache stores
                    $this->trackCacheVariableAssignments($ast);

                    // Find Cache::lock() static calls
                    $lockCalls = $this->parser->findStaticCalls($ast, 'Cache', 'lock');

                    foreach ($lockCalls as $call) {
                        $this->addLockUsage($filePath, $call->getLine());
                    }

                    // Also check for $cache->lock() method calls on cache-related variables
                    $methodCalls = $this->parser->findMethodCalls($ast, 'lock');
                    foreach ($methodCalls as $call) {
                        if ($call instanceof MethodCall && $this->isCacheLockMethodCall($call)) {
                            $this->addLockUsage($filePath, $call->getLine());
                        }
                    }
                } catch (\Throwable) {
                    // Skip files that can't be parsed
                    continue;
                }
            }
        }
    }

    private function isCacheLockMethodCall(MethodCall $call): bool
    {
        $caller = $call->var;

        // Check variable-based calls like $cache->lock()
        if ($caller instanceof Variable && is_string($caller->name)) {
            // Check if this variable was assigned a specific store with dedicated lock connection
            if (isset($this->variableStores[$caller->name])) {
                $storeName = $this->variableStores[$caller->name];
                if ($this->storeHasDedicatedLockConnection($storeName)) {
                    return false; // Skip - uses dedicated lock connection
                }
            }

            return in_array(strtolower($caller->name), ['cache', 'redis', 'store'], true);
        }

        // Check property-based calls like $this->cache->lock()
        if ($caller instanceof PropertyFetch && $caller->name instanceof Identifier) {
            return in_array(strtolower($caller->name->name), ['cache'], true);
        }

        // Check Cache::store('X')->lock() chains
        if ($caller instanceof StaticCall && $caller->class instanceof Name) {
            if ($caller->class->toString() === 'Cache') {
                if ($caller->name instanceof Identifier && $caller->name->name === 'store') {
                    // Extract store name and check if it has dedicated lock connection
                    $storeName = $this->extractStoreFromStaticCall($caller);
                    if ($storeName !== null && $this->storeHasDedicatedLockConnection($storeName)) {
                        return false; // Skip - uses dedicated lock connection
                    }

                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Add a lock usage entry, avoiding duplicates.
     */
    private function addLockUsage(string $file, int $line): void
    {
        $key = "{$file}:{$line}";
        if (isset($this->lockUsages[$key])) {
            return; // Already added
        }

        $this->lockUsages[$key] = [
            'file' => $file,
            'line' => $line,
        ];
    }

    /**
     * Get the default cache store name.
     */
    private function getDefaultStore(): ?string
    {
        $defaultStore = $this->config->get('cache.default');

        return is_string($defaultStore) ? $defaultStore : null;
    }

    /**
     * Get the cache driver for the default store.
     */
    private function getCacheDriver(): ?string
    {
        $defaultStore = $this->getDefaultStore();
        if ($defaultStore === null) {
            return null;
        }

        $driver = $this->config->get("cache.stores.$defaultStore.driver");

        return is_string($driver) ? $driver : null;
    }

    /**
     * Check if a specific cache store has a dedicated lock connection configured.
     */
    private function storeHasDedicatedLockConnection(string $storeName): bool
    {
        $lockConnection = $this->config->get("cache.stores.$storeName.lock_connection");
        $cacheConnection = $this->config->get("cache.stores.$storeName.connection");

        if ($lockConnection !== null && ! is_string($lockConnection)) {
            return false;
        }
        if ($cacheConnection !== null && ! is_string($cacheConnection)) {
            $cacheConnection = null;
        }

        return $lockConnection !== null && $lockConnection !== $cacheConnection;
    }

    /**
     * Track variable assignments that assign cache stores.
     *
     * @param  array<Node>  $ast
     */
    private function trackCacheVariableAssignments(array $ast): void
    {
        // Note: only tracks direct Cache::store('x') assignments.
        // It does NOT follow constructor injection, method returns,
        // helper functions, or conditional/dataflow assignments.

        $this->variableStores = [];

        $assignments = $this->parser->findNodes($ast, Assign::class);
        foreach ($assignments as $assign) {
            if (! $assign instanceof Assign) {
                continue;
            }

            if (! $assign->var instanceof Variable || ! is_string($assign->var->name)) {
                continue;
            }

            $storeName = $this->extractStoreFromExpression($assign->expr);
            if ($storeName !== null) {
                $this->variableStores[$assign->var->name] = $storeName;
            }
        }
    }

    /**
     * Extract store name from Cache::store('name') expression.
     */
    private function extractStoreFromExpression(Node $expr): ?string
    {
        if (! $expr instanceof StaticCall) {
            return null;
        }

        if (! $expr->class instanceof Name || $expr->class->toString() !== 'Cache') {
            return null;
        }

        if (! $expr->name instanceof Identifier || $expr->name->name !== 'store') {
            return null;
        }

        if (empty($expr->args) || ! isset($expr->args[0])) {
            return null;
        }

        $arg = $expr->args[0];
        if (! $arg instanceof Node\Arg) {
            return null;
        }

        if ($arg->value instanceof String_) {
            return $arg->value->value;
        }

        return null;
    }

    /**
     * Extract store name from a Cache::store() static call.
     */
    private function extractStoreFromStaticCall(StaticCall $call): ?string
    {
        if (empty($call->args) || ! isset($call->args[0])) {
            return null;
        }

        $arg = $call->args[0];
        if (! $arg instanceof Node\Arg) {
            return null;
        }

        if ($arg->value instanceof String_) {
            return $arg->value->value;
        }

        return null;
    }

    private function getRecommendation(): string
    {
        return <<<'REC'
Your application uses cache locks on your default cache store. This means that when your cache is cleared, your locks will also be cleared. Typically, this is not the intention when using locks for managing race conditions or concurrent processing.

Add this to your cache store config: "lock_connection" => "lock_redis",

Then define a separate "lock_redis" connection in config/database.php that uses a different Redis database number.
REC;
    }
}
