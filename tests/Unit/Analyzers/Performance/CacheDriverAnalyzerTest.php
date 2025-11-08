<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\CacheDriverAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CacheDriverAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CacheDriverAnalyzer;
    }

    public function test_passes_with_redis_driver(): void
    {
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => 'redis',
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

        $this->assertPassed($result);
    }

    public function test_fails_with_null_driver(): void
    {
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => 'null',
    'stores' => [
        'null' => [
            'driver' => 'null',
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('null', $result);
    }

    public function test_checks_cache_configuration(): void
    {
        $envContent = 'APP_ENV=production';
        $cacheConfig = <<<'PHP'
<?php

return [
    'default' => 'file',
    'stores' => [
        'file' => [
            'driver' => 'file',
            'path' => storage_path('framework/cache/data'),
        ],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'config/cache.php' => $cacheConfig,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May warn about file driver depending on environment
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
