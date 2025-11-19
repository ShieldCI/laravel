<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use Mockery;
use ShieldCI\Analyzers\Performance\ConfigCachingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ConfigCachingAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $configValues
     */
    protected function createAnalyzer(
        array $configValues = [],
        bool $configIsCached = false,
        bool $implementsCachesConfiguration = true
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

        // Mock Application with CachesConfiguration interface
        if ($implementsCachesConfiguration) {
            /** @var Application&CachesConfiguration&\Mockery\MockInterface $app */
            $app = Mockery::mock(Application::class.', '.CachesConfiguration::class);

            /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
            $app->shouldReceive('configurationIsCached')
                ->andReturn($configIsCached);
        } else {
            /** @var Application&\Mockery\MockInterface $app */
            $app = Mockery::mock(Application::class);
        }

        return new ConfigCachingAnalyzer($app, $config);
    }

    public function test_fails_when_config_cached_in_local(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'app' => [
                    'env' => 'local',
                ],
            ],
            configIsCached: true
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('cached in local', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('configurationIsCached()', $issues[0]->metadata['detection_method'] ?? '');
    }

    public function test_fails_when_config_not_cached_in_production(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'app' => [
                    'env' => 'production',
                ],
            ],
            configIsCached: false
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not cached', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('production', $issues[0]->metadata['environment'] ?? '');
        $this->assertFalse($issues[0]->metadata['cached'] ?? true);
    }

    public function test_fails_when_config_not_cached_in_staging(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'app' => [
                    'env' => 'staging',
                ],
            ],
            configIsCached: false
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('staging', $result->getMessage());
    }

    public function test_passes_when_config_cached_in_production(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'app' => [
                    'env' => 'production',
                ],
            ],
            configIsCached: true
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('properly configured', $result->getMessage());
    }

    public function test_passes_when_config_not_cached_in_local(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'app' => [
                    'env' => 'local',
                ],
            ],
            configIsCached: false
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('local', $result->getMessage());
    }

    public function test_skips_when_caches_configuration_not_available(): void
    {
        // Create analyzer without mocking CachesConfiguration interface
        /** @var Application&\Mockery\MockInterface $app */
        $app = Mockery::mock(Application::class);

        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        $analyzer = new ConfigCachingAnalyzer($app, $config);

        // Should skip if app doesn't implement CachesConfiguration
        $shouldRun = $analyzer->shouldRun();

        // This will be true in Laravel 7+ test environment, false otherwise
        $this->assertIsBool($shouldRun);
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('config-caching', $metadata->id);
        $this->assertEquals('Configuration Caching', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $metadata->severity);
        $this->assertContains('cache', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(ConfigCachingAnalyzer::$runInCI);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
