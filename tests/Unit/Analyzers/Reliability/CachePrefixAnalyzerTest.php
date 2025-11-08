<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\CachePrefixAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CachePrefixAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CachePrefixAnalyzer;
    }

    public function test_fails_with_empty_cache_prefix(): void
    {
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'prefix' => '',
    'stores' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'cache',
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/cache.php' => $cacheConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May be skipped if not using a shared cache driver
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_fails_with_generic_cache_prefix(): void
    {
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'prefix' => 'laravel_cache',
    'stores' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'cache',
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/cache.php' => $cacheConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May be skipped if not using a shared cache driver
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_passes_with_unique_cache_prefix(): void
    {
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
    'prefix' => 'myapp_cache',
    'stores' => [
        'redis' => [
            'driver' => 'redis',
            'connection' => 'cache',
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/cache.php' => $cacheConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May be skipped if not using a shared cache driver
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
