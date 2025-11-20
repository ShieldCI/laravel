<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
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
     * @var array<int, array{file: string, line: int}>
     */
    private array $lockUsages = [];

    public function __construct(
        private ParserInterface $parser,
        private ConfigRepository $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'shared-cache-lock',
            name: 'Shared Cache Lock Store',
            description: 'Detects cache lock usage on the default cache store, which can cause locks to be cleared when cache is flushed',
            category: Category::Performance,
            severity: Severity::Low,
            tags: ['performance', 'cache', 'locks', 'redis', 'reliability'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/shared-cache-lock',
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

        if ($lockConnection !== null && $lockConnection !== $cacheConnection) {
            return $this->passed('Cache locks use a separate connection');
        }

        // Set paths to analyze (app directory only)
        $this->setPaths([$this->basePath.'/app']);

        // Search for Cache::lock() usage in the codebase
        $this->findCacheLockUsage();

        if (empty($this->lockUsages)) {
            return $this->passed('No cache lock usage detected');
        }

        // Create issues for each lock usage
        $issues = [];
        foreach ($this->lockUsages as $usage) {
            $issues[] = $this->createIssue(
                message: 'Cache lock usage detected on default cache store',
                location: new Location($usage['file'], $usage['line']),
                severity: Severity::Low,
                recommendation: $this->getRecommendation(),
                metadata: [
                    'file' => $usage['file'],
                    'line' => $usage['line'],
                    'default_store' => $defaultStore,
                    'cache_connection' => $cacheConnection,
                    'lock_connection' => $lockConnection,
                ]
            );
        }

        return $this->warning(
            sprintf('Found %d cache lock usage(s) on default cache store', count($this->lockUsages)),
            $issues
        );
    }

    private function findCacheLockUsage(): void
    {
        foreach ($this->getPhpFiles() as $file) {
            $content = FileParser::readFile($file);

            if ($content === null) {
                continue;
            }

            // Simple pattern matching for Cache::lock() calls
            if (str_contains($content, 'Cache::lock(') || str_contains($content, '->lock(')) {
                try {
                    $ast = $this->parser->parseFile($file);

                    // Find Cache::lock() static calls
                    $lockCalls = $this->parser->findStaticCalls($ast, 'Cache', 'lock');

                    foreach ($lockCalls as $call) {
                        $this->lockUsages[] = [
                            'file' => $file,
                            'line' => $call->getLine(),
                        ];
                    }

                    // Also check for $cache->lock() method calls on cache-related variables
                    $methodCalls = $this->parser->findMethodCalls($ast, 'lock');
                    foreach ($methodCalls as $call) {
                        // Add method calls (note: may include some false positives for non-cache locks)
                        $this->lockUsages[] = [
                            'file' => $file,
                            'line' => $call->getLine(),
                        ];
                    }
                } catch (\Throwable) {
                    // Skip files that can't be parsed
                    continue;
                }
            }
        }
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

    private function getRecommendation(): string
    {
        return 'Your application uses cache locks on your default cache store. This means that when '
            .'your cache is cleared, your locks will also be cleared. Typically, this is not the '
            .'intention when using locks for managing race conditions or concurrent processing. '
            .'If you intend to persist locks despite cache clearing, it is recommended that '
            .'you use cache locks on a separate store. '
            ."\n\n"
            .'Laravel 8.20+ supports a separate lock_connection configuration. Add this to your cache store config: '
            ."\n"
            .'"lock_connection" => "lock_redis", '
            ."\n"
            .'Then define a separate "lock_redis" connection in config/database.php that uses a different Redis database number.';
    }
}
