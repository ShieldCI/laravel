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
        bool $routesAreCached = false,
        bool $implementsCachesRoutes = true
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
        if ($implementsCachesRoutes) {
            /** @var Application&CachesRoutes&\Mockery\MockInterface $app */
            $app = Mockery::mock(Application::class.', '.CachesRoutes::class);

            /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
            $app->shouldReceive('routesAreCached')
                ->andReturn($routesAreCached);
        } else {
            /** @var Application&\Mockery\MockInterface $app */
            $app = Mockery::mock(Application::class);
        }

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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('cached in local', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('routesAreCached()', $issues[0]->metadata['detection_method'] ?? '');
    }

    public function test_warns_when_routes_cached_in_testing_environment(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'app' => [
                    'env' => 'testing',
                ],
            ],
            routesAreCached: true
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('testing', $issues[0]->metadata['environment'] ?? '');
    }

    public function test_warns_when_routes_cached_in_development_environment(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'app' => [
                    'env' => 'development',
                ],
            ],
            routesAreCached: true
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('development', $issues[0]->metadata['environment'] ?? '');
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

    public function test_passes_with_routes_not_cached_in_testing_environment(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'app' => [
                    'env' => 'testing',
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

    public function test_passes_when_routes_cached_in_staging(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'app' => [
                    'env' => 'staging',
                ],
            ],
            routesAreCached: true
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_when_application_does_not_implement_caches_routes(): void
    {
        /** @var RouteCachingAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer(implementsCachesRoutes: false);

        $this->assertFalse($analyzer->shouldRun());
        $this->assertSame('Application does not implement CachesRoutes interface', $analyzer->getSkipReason());
    }

    // ============================================================
    // Category 1: Result Type and Severity Validation (3 tests)
    // ============================================================

    public function test_returns_failed_result_when_high_severity_issue_in_production(): void
    {
        $analyzer = $this->createAnalyzer(
            ['app' => ['env' => 'production']],
            routesAreCached: false
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('route caching issue(s)', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }

    public function test_returns_warning_result_when_low_severity_issue_in_local(): void
    {
        $analyzer = $this->createAnalyzer(
            ['app' => ['env' => 'local']],
            routesAreCached: true
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('route caching issue(s)', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $issues[0]->severity);
    }

    public function test_passed_result_includes_environment_in_message(): void
    {
        $analyzer = $this->createAnalyzer(
            ['app' => ['env' => 'production']],
            routesAreCached: true
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('production environment', $result->getMessage());
        $this->assertStringContainsString('properly configured', $result->getMessage());
    }

    // ============================================================
    // Category 2: Metadata Validation (4 tests)
    // ============================================================

    public function test_production_uncached_routes_metadata_is_complete(): void
    {
        $analyzer = $this->createAnalyzer(
            ['app' => ['env' => 'production']],
            routesAreCached: false
        );

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('environment', $metadata);
        $this->assertArrayHasKey('cached', $metadata);
        $this->assertArrayHasKey('detection_method', $metadata);
        $this->assertArrayHasKey('detected_via', $metadata);

        $this->assertEquals('production', $metadata['environment']);
        $this->assertFalse($metadata['cached']);
        $this->assertEquals('routesAreCached()', $metadata['detection_method']);
        $this->assertEquals('bootstrap/cache/routes-v7.php', $metadata['detected_via']);
    }

    public function test_local_cached_routes_metadata_is_complete(): void
    {
        $analyzer = $this->createAnalyzer(
            ['app' => ['env' => 'local']],
            routesAreCached: true
        );

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('environment', $metadata);
        $this->assertArrayHasKey('cached', $metadata);
        $this->assertArrayHasKey('detection_method', $metadata);
        $this->assertArrayHasKey('detected_via', $metadata);

        $this->assertEquals('local', $metadata['environment']);
        $this->assertTrue($metadata['cached']);
        $this->assertEquals('routesAreCached()', $metadata['detection_method']);
        $this->assertEquals('bootstrap/cache/routes-v7.php', $metadata['detected_via']);
    }

    public function test_staging_uncached_routes_has_correct_severity(): void
    {
        $analyzer = $this->createAnalyzer(
            ['app' => ['env' => 'staging']],
            routesAreCached: false
        );

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }

    public function test_development_cached_routes_has_correct_severity(): void
    {
        $analyzer = $this->createAnalyzer(
            ['app' => ['env' => 'development']],
            routesAreCached: true
        );

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $issues[0]->severity);
    }

    // ============================================================
    // Category 3: Recommendation Content Validation (3 tests)
    // ============================================================

    public function test_production_uncached_recommendation_mentions_artisan_command(): void
    {
        $analyzer = $this->createAnalyzer(
            ['app' => ['env' => 'production']],
            routesAreCached: false
        );

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('php artisan route:cache', $recommendation);
        $this->assertStringContainsString('deployment script', $recommendation);
        $this->assertStringContainsString('performance improvements', $recommendation);
    }

    public function test_local_cached_recommendation_mentions_clear_command(): void
    {
        $analyzer = $this->createAnalyzer(
            ['app' => ['env' => 'local']],
            routesAreCached: true
        );

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('php artisan route:clear', $recommendation);
        $this->assertStringContainsString('not recommended for development', $recommendation);
    }

    public function test_staging_uncached_recommendation_matches_production(): void
    {
        $stagingAnalyzer = $this->createAnalyzer(
            ['app' => ['env' => 'staging']],
            routesAreCached: false
        );

        $productionAnalyzer = $this->createAnalyzer(
            ['app' => ['env' => 'production']],
            routesAreCached: false
        );

        $stagingResult = $stagingAnalyzer->analyze();
        $productionResult = $productionAnalyzer->analyze();

        $stagingIssues = $stagingResult->getIssues();
        $productionIssues = $productionResult->getIssues();

        // Both should have same recommendation (except environment name)
        $this->assertStringContainsString('php artisan route:cache', $stagingIssues[0]->recommendation);
        $this->assertStringContainsString('php artisan route:cache', $productionIssues[0]->recommendation);
    }

    // ============================================================
    // Category 4: Edge Cases and Variations (4 tests)
    // ============================================================

    public function test_handles_custom_environment_not_in_predefined_list(): void
    {
        $analyzer = $this->createAnalyzer(
            ['app' => ['env' => 'custom-env']],
            routesAreCached: false
        );

        $result = $analyzer->analyze();

        // Custom environment (not local/dev/testing/prod/staging) should pass
        // because it doesn't match any condition
        $this->assertPassed($result);
    }

    public function test_handles_empty_environment_string(): void
    {
        $analyzer = $this->createAnalyzer(
            ['app' => ['env' => '']],
            routesAreCached: true
        );

        $result = $analyzer->analyze();

        // Empty environment should pass (doesn't match any condition)
        $this->assertPassed($result);
    }

    public function test_metadata_detection_method_is_consistent(): void
    {
        $localAnalyzer = $this->createAnalyzer(
            ['app' => ['env' => 'local']],
            routesAreCached: true
        );

        $prodAnalyzer = $this->createAnalyzer(
            ['app' => ['env' => 'production']],
            routesAreCached: false
        );

        $localResult = $localAnalyzer->analyze();
        $prodResult = $prodAnalyzer->analyze();

        $localIssues = $localResult->getIssues();
        $prodIssues = $prodResult->getIssues();

        // Both should use same detection method
        $this->assertEquals('routesAreCached()', $localIssues[0]->metadata['detection_method'] ?? '');
        $this->assertEquals('routesAreCached()', $prodIssues[0]->metadata['detection_method'] ?? '');
    }

    public function test_analyzer_metadata_values(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('route-caching', $metadata->id);
        $this->assertEquals('Route Caching Analyzer', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $metadata->severity);
        $this->assertContains('cache', $metadata->tags);
        $this->assertContains('routes', $metadata->tags);
        $this->assertEquals(5, $metadata->timeToFix);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
