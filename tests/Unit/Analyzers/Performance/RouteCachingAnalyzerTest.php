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
    /**
     * @param  array<string, mixed>  $configValues
     */
    protected function createAnalyzer(
        array $configValues = [],
        bool $routesAreCached = false
    ): AnalyzerInterface {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        // Set up default config values
        $defaults = [
            'app' => [
                'env' => 'production', // Default to production so tests actually run
            ],
        ];

        $configMap = array_replace_recursive($defaults, $configValues);

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) use ($configMap) {
                // Handle dotted key access (e.g., 'app.env')
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

        // Mock Application with CachesRoutes interface
        /** @var Application&CachesRoutes&\Mockery\MockInterface $app */
        $app = Mockery::mock(Application::class.', '.CachesRoutes::class);

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $app->shouldReceive('routesAreCached')
            ->andReturn($routesAreCached);

        return new RouteCachingAnalyzer($app, $config);
    }

    public function test_warns_when_routes_cached_in_local(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'app' => [
                    'env' => 'local',
                ],
            ],
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
            [
                'app' => [
                    'env' => 'production',
                ],
            ],
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
            [
                'app' => [
                    'env' => 'production',
                ],
            ],
            routesAreCached: true
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_routes_not_cached_in_local(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'app' => [
                    'env' => 'local',
                ],
            ],
            routesAreCached: false
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_routes_not_cached_in_staging(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'app' => [
                    'env' => 'staging',
                ],
            ],
            routesAreCached: false
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not cached in staging', $result);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
