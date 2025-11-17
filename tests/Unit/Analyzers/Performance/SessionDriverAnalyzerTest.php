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
    protected function createAnalyzer(
        string $environment = 'production',
        string $driver = 'redis',
        bool $usesSession = true
    ): AnalyzerInterface {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        /** @var Router&\Mockery\MockInterface $router */
        $router = Mockery::mock(Router::class);

        /** @var Kernel&\Mockery\MockInterface $kernel */
        $kernel = Mockery::mock(Kernel::class);

        // Mock config repository
        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->with('session.driver', 'file')
            ->andReturn($driver);

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->with('app.env', 'production')
            ->andReturn($environment);

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
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            driver: 'redis',
            usesSession: true
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_database_driver(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            driver: 'database',
            usesSession: true
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_null_driver(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            driver: 'null',
            usesSession: true
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('null', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('null', $issues[0]->metadata['driver'] ?? '');
    }

    public function test_warns_about_file_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            driver: 'file',
            usesSession: true
        );

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
        $analyzer = $this->createAnalyzer(
            environment: 'local',
            driver: 'file',
            usesSession: true
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_array_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            driver: 'array',
            usesSession: true
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('array', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('array', $issues[0]->metadata['driver'] ?? '');
    }

    public function test_passes_with_array_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'local',
            driver: 'array',
            usesSession: true
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_about_cookie_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            driver: 'cookie',
            usesSession: true
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('cookie', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('cookie', $issues[0]->metadata['driver'] ?? '');
    }

    public function test_passes_with_cookie_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'local',
            driver: 'cookie',
            usesSession: true
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_when_app_is_stateless(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            driver: 'null',
            usesSession: false
        );

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_warns_about_file_driver_in_staging(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'staging',
            driver: 'file',
            usesSession: true
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('file', $result);
    }
}
