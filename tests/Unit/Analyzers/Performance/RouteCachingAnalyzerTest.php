<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesRoutes;
use Mockery;
use ShieldCI\Analyzers\Performance\RouteCachingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class RouteCachingAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(
        string $environment = 'production',
        bool $routesAreCached = false
    ): AnalyzerInterface {
        /** @var Application&CachesRoutes&\Mockery\MockInterface $app */
        $app = Mockery::mock(Application::class.', '.CachesRoutes::class);

        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        // Mock config repository
        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->with('app.env', 'production')
            ->andReturn($environment);

        // Mock app route caching status
        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $app->shouldReceive('routesAreCached')
            ->andReturn($routesAreCached);

        return new RouteCachingAnalyzer($app, $config);
    }

    public function test_warns_when_routes_cached_in_local(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'local',
            routesAreCached: true
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('cached in local', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('routesAreCached()', $issues[0]->metadata['detection_method'] ?? '');
    }

    public function test_fails_when_routes_not_cached_in_production(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            routesAreCached: false
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not cached', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('production', $issues[0]->metadata['environment'] ?? '');
        $this->assertFalse($issues[0]->metadata['cached'] ?? true);
    }

    public function test_passes_with_routes_cached_in_production(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'production',
            routesAreCached: true
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_routes_not_cached_in_local(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'local',
            routesAreCached: false
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_routes_not_cached_in_staging(): void
    {
        $analyzer = $this->createAnalyzer(
            environment: 'staging',
            routesAreCached: false
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not cached in staging', $result);
    }
}
