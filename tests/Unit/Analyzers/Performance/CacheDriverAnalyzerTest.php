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
    protected function createAnalyzer(
        string $environment = 'production',
        ?string $defaultStore = 'redis',
        ?string $driver = 'redis'
    ): AnalyzerInterface {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        // Mock config repository
        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->with('cache.default')
            ->andReturn($defaultStore);

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->with('app.env', 'production')
            ->andReturn($environment);

        if ($defaultStore !== null && $driver !== null) {
            /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
            $config->shouldReceive('get')
                ->with("cache.stores.{$defaultStore}.driver")
                ->andReturn($driver);
        }

        $analyzer = new CacheDriverAnalyzer($config);

        // Set a dummy basePath for location reporting
        $analyzer->setBasePath('/app');

        return $analyzer;
    }

    public function test_passes_with_redis_driver(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            defaultStore: 'redis',
            driver: 'redis'
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_null_driver(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            defaultStore: 'null',
            driver: 'null'
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('null', $result);
    }

    public function test_fails_with_file_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            defaultStore: 'file',
            driver: 'file'
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('File cache driver', $result);
    }

    public function test_passes_with_file_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'local',
            defaultStore: 'file',
            driver: 'file'
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_array_driver(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            defaultStore: 'array',
            driver: 'array'
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('array', $result);
    }

    public function test_passes_with_memcached_driver(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            defaultStore: 'memcached',
            driver: 'memcached'
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
