<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Support\Facades\Cache;
use RuntimeException;
use ShieldCI\Analyzers\Reliability\CacheStatusAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CacheStatusAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CacheStatusAnalyzer;
    }

    protected function tearDown(): void
    {
        $root = Cache::getFacadeRoot();
        if (is_object($root) && method_exists($root, 'flush')) {
            Cache::flush();
        }

        Cache::clearResolvedInstance('cache');
        parent::tearDown();
    }

    public function test_passes_when_cache_operational(): void
    {
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => 'array',
    'stores' => [
        'array' => [
            'driver' => 'array',
            'serialize' => false,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/cache.php' => $cacheConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_cache_returns_incorrect_value(): void
    {
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => 'array',
    'stores' => [
        'array' => [
            'driver' => 'array',
            'serialize' => false,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/cache.php' => $cacheConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        Cache::shouldReceive('put')->andReturnTrue();
        Cache::shouldReceive('get')->andReturn('wrong');
        Cache::shouldReceive('forget')->andReturnTrue();

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('write/read test failed', $result);
    }

    public function test_fails_when_cache_put_throws_exception(): void
    {
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => 'array',
    'stores' => [
        'array' => [
            'driver' => 'array',
            'serialize' => false,
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/cache.php' => $cacheConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        config(['cache.default' => 'array']);
        config(['cache.stores.array.driver' => 'array']);

        Cache::shouldReceive('put')->andThrow(new RuntimeException('Cache offline'));
        Cache::shouldReceive('forget')->andReturnTrue();

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache connection/operation failed', $result);
    }
}
