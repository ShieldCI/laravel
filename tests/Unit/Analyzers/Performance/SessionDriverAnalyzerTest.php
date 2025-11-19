<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Mockery;
use ShieldCI\Analyzers\Performance\SessionDriverAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class SessionDriverAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $configValues
     */
    protected function createAnalyzer(
        array $configValues = [],
        bool $usesSession = true
    ): AnalyzerInterface {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        // Set up default config values
        $defaults = [
            'app' => [
                'env' => 'production', // Default to production so tests actually run
            ],
            'session' => [
                'driver' => 'redis',
            ],
        ];

        $configMap = array_replace_recursive($defaults, $configValues);

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) use ($configMap) {
                // Handle dotted key access (e.g., 'session.driver', 'app.env')
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

        /** @var Router&\Mockery\MockInterface $router */
        $router = Mockery::mock(Router::class);

        /** @var Kernel&\Mockery\MockInterface $kernel */
        $kernel = Mockery::mock(Kernel::class);

        // Mock router - directly mock getRoutes() to avoid RouteCollection complexities
        $mockRoutes = [];
        if ($usesSession) {
            $route = Mockery::mock(Route::class);
            /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
            $route->shouldReceive('middleware')
                ->andReturn(['web']);
            $mockRoutes[] = $route;
        }

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $router->shouldReceive('getRoutes')
            ->andReturn($mockRoutes);

        // Mock kernel - no global middleware
        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $kernel->shouldReceive('getGlobalMiddleware')
            ->andReturn([]);

        return new SessionDriverAnalyzer($config, $router, $kernel);
    }

    public function test_passes_with_redis_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => [
                'driver' => 'redis',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_database_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => [
                'driver' => 'database',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_null_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => [
                'driver' => 'null',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('null', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('null', $issues[0]->metadata['driver'] ?? '');
    }

    public function test_warns_about_file_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => [
                'driver' => 'file',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('file', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('file', $issues[0]->metadata['driver'] ?? '');
        $this->assertEquals('production', $issues[0]->metadata['environment'] ?? '');
    }

    public function test_passes_with_file_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'session' => [
                'driver' => 'file',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_array_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => [
                'driver' => 'array',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('array', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('array', $issues[0]->metadata['driver'] ?? '');
    }

    public function test_passes_with_array_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'session' => [
                'driver' => 'array',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_about_cookie_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => [
                'driver' => 'cookie',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('cookie', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('cookie', $issues[0]->metadata['driver'] ?? '');
    }

    public function test_passes_with_cookie_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'session' => [
                'driver' => 'cookie',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_when_app_is_stateless(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'session' => [
                    'driver' => 'null',
                ],
            ],
            usesSession: false
        );

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_warns_about_file_driver_in_staging(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'staging',
            ],
            'session' => [
                'driver' => 'file',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('file', $result);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
