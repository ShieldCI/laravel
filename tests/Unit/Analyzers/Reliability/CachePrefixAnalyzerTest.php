<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\CachePrefixAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\Tests\AnalyzerTestCase;

class CachePrefixAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CachePrefixAnalyzer;
    }

    public function test_skips_when_cache_driver_not_shared(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'default' => 'file',
            'prefix' => null,
            'stores' => [
                'file' => [
                    'driver' => 'file',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertEquals(Status::Skipped, $result->getStatus());
    }

    public function test_fails_with_empty_cache_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache prefix is empty', $result);
    }

    public function test_fails_with_generic_cache_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'Laravel_Cache',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('too generic', $result);
    }

    public function test_passes_with_unique_cache_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => 'myapp_cache',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_store_specific_prefix(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'prefix' => 'tenant_cache',
                ],
            ],
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_missing_config_file(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->setupCacheConfig($tempDir, [
            'prefix' => '',
        ], writeFile: false);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private function setupCacheConfig(string $basePath, array $overrides = [], bool $writeFile = true): void
    {
        $default = [
            'default' => 'redis',
            'prefix' => '',
            'stores' => [
                'redis' => [
                    'driver' => 'redis',
                    'connection' => 'cache',
                ],
            ],
        ];

        $config = array_replace_recursive($default, $overrides);

        config()->set('cache', $config);
        config()->set('cache.default', $config['default']);
        config()->set('cache.prefix', $config['prefix']);
        config()->set('cache.stores', $config['stores']);
        config()->set('app.name', 'ShieldCI Demo');

        if (! $writeFile) {
            return;
        }

        $configDir = $basePath.'/config';
        if (! is_dir($configDir)) {
            mkdir($configDir, 0755, true);
        }

        $content = "<?php\n\nreturn ".var_export($config, true).";\n";
        file_put_contents($configDir.'/cache.php', $content);
    }
}
