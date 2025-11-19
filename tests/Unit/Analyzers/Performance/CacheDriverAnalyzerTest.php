<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Mockery;
use ShieldCI\Analyzers\Performance\CacheDriverAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CacheDriverAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $configValues
     */
    protected function createAnalyzer(array $configValues = []): AnalyzerInterface
    {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        // Set up default config values
        $defaults = [
            'app' => [
                'env' => 'production', // Default to production so tests actually run
            ],
            'cache' => [
                'default' => 'redis',
                'stores' => [
                    'redis' => [
                        'driver' => 'redis',
                    ],
                ],
            ],
        ];

        $configMap = array_replace_recursive($defaults, $configValues);

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) use ($configMap) {
                // Handle dotted key access (e.g., 'cache.stores.redis.driver')
                $keys = explode('.', $key);
                $value = $configMap;

                foreach ($keys as $segment) {
                    if (is_array($value) && array_key_exists($segment, $value)) {
                        $value = $value[$segment];
                    } else {
                        return $default;
                    }
                }

                return $value ?? $default;
            });

        return new CacheDriverAnalyzer($config);
    }

    public function test_passes_with_redis_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'redis',
                'stores' => [
                    'redis' => [
                        'driver' => 'redis',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_null_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'null',
                'stores' => [
                    'null' => [
                        'driver' => 'null',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('null', $result);
    }

    public function test_fails_with_file_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'file',
                'stores' => [
                    'file' => [
                        'driver' => 'file',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('File cache driver', $result);
    }

    public function test_passes_with_file_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'cache' => [
                'default' => 'file',
                'stores' => [
                    'file' => [
                        'driver' => 'file',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_array_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'array',
                'stores' => [
                    'array' => [
                        'driver' => 'array',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('array', $result);
    }

    public function test_passes_with_memcached_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'cache' => [
                'default' => 'memcached',
                'stores' => [
                    'memcached' => [
                        'driver' => 'memcached',
                    ],
                ],
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
