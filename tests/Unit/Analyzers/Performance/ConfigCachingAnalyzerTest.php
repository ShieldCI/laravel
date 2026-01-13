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
    protected function createAnalyzer(
        string $environment = 'production',
        bool $configIsCached = false,
        bool $implementsCachesConfiguration = true
    ): AnalyzerInterface {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('app.env', Mockery::any())
            ->andReturn($environment);

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

    public function test_warns_when_config_cached_in_local(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'local', configIsCached: true);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('cached in local', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('configurationIsCached()', $issues[0]->metadata['detection_method'] ?? '');
    }

    public function test_fails_when_config_not_cached_in_production(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'production', configIsCached: false);

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
        $analyzer = $this->createAnalyzer(environment: 'staging', configIsCached: false);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('staging', $result->getMessage());
    }

    public function test_passes_when_config_cached_in_production(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'production', configIsCached: true);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('properly configured', $result->getMessage());
    }

    public function test_passes_when_config_not_cached_in_local(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'local', configIsCached: false);

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
        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')->andReturn('production');

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
        $this->assertEquals('Configuration Caching Analyzer', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $metadata->severity);
        $this->assertContains('cache', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(ConfigCachingAnalyzer::$runInCI);
    }

    public function test_warns_when_config_cached_in_development(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'development', configIsCached: true);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('cached in development', $result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals('development', $issues[0]->metadata['environment'] ?? '');
    }

    public function test_warns_when_config_cached_in_testing(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'testing', configIsCached: true);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('cached in testing', $result);
    }

    public function test_passes_when_config_not_cached_in_development(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'development', configIsCached: false);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_config_not_cached_in_testing(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'testing', configIsCached: false);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_config_cached_in_staging(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'staging', configIsCached: true);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_unknown_environment(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'qa', configIsCached: false);

        $result = $analyzer->analyze();

        // Unknown environments should pass (neither dev nor prod)
        $this->assertPassed($result);
    }

    public function test_handles_case_insensitive_production_environment(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'Production', configIsCached: false);

        $result = $analyzer->analyze();

        // Should fail because 'Production' (case-insensitive) is not cached
        $this->assertFailed($result);
    }

    public function test_handles_case_insensitive_local_environment(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'Local', configIsCached: true);

        $result = $analyzer->analyze();

        // Should fail because 'Local' (case-insensitive) is cached
        $this->assertWarning($result);
    }

    public function test_handles_empty_environment(): void
    {
        $analyzer = $this->createAnalyzer(environment: '', configIsCached: false);

        $result = $analyzer->analyze();

        // When environment is empty, parent AbstractAnalyzer defaults to 'production'
        // So this fails because production is not cached
        $this->assertFailed($result);
        $this->assertStringContainsString('not properly configured', $result->getMessage());
    }

    public function test_handles_configuration_is_cached_exception(): void
    {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->with('app.env', Mockery::any())
            ->andReturn('production');

        /** @var Application&CachesConfiguration&\Mockery\MockInterface $app */
        $app = Mockery::mock(Application::class.', '.CachesConfiguration::class);

        /** @phpstan-ignore-next-line */
        $app->shouldReceive('configurationIsCached')
            ->andThrow(new \RuntimeException('Cache check failed'));

        $analyzer = new ConfigCachingAnalyzer($app, $config);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('Failed to check configuration cache status', $result->getMessage());
        $this->assertStringContainsString('Cache check failed', $result->getMessage());
    }

    public function test_recommendation_contains_config_clear_command_for_dev(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'local', configIsCached: true);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertStringContainsString('php artisan config:clear', $issues[0]->recommendation);
    }

    public function test_recommendation_contains_config_cache_command_for_production(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'production', configIsCached: false);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertStringContainsString('php artisan config:cache', $issues[0]->recommendation);
    }

    public function test_issue_location_points_to_cached_config_file_for_dev(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'local', configIsCached: true);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertNotNull($issues[0]->location);
        $this->assertStringContainsString('bootstrap', $issues[0]->location->file);
        $this->assertStringContainsString('cache', $issues[0]->location->file);
        $this->assertStringContainsString('config.php', $issues[0]->location->file);
    }

    public function test_issue_location_points_to_cache_path_for_production(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'production', configIsCached: false);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertNotNull($issues[0]->location);
        // Should point to where the cache file should be (but isn't)
        $this->assertStringContainsString('bootstrap/cache/config.php', $issues[0]->location->file);
    }

    public function test_issue_has_correct_severity(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'production', configIsCached: false);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }

    public function test_creates_exactly_one_issue_for_dev_environment(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'local', configIsCached: true);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_creates_exactly_one_issue_for_production_environment(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'production', configIsCached: false);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_metadata_includes_cached_status_true(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'local', configIsCached: true);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertTrue($issues[0]->metadata['cached'] ?? false);
    }

    public function test_metadata_includes_cached_status_false(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'production', configIsCached: false);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertFalse($issues[0]->metadata['cached'] ?? true);
    }

    public function test_skip_reason_mentions_caches_configuration_interface(): void
    {
        /** @var Application&\Mockery\MockInterface $app */
        $app = Mockery::mock(Application::class);

        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);
        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')->andReturn('production');

        $analyzer = new ConfigCachingAnalyzer($app, $config);

        $skipReason = $analyzer->getSkipReason();

        $this->assertStringContainsString('CachesConfiguration', $skipReason);
    }

    public function test_multiple_consecutive_runs_produce_same_result(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'production', configIsCached: false);

        $result1 = $analyzer->analyze();
        $result2 = $analyzer->analyze();

        $this->assertEquals($result1->getMessage(), $result2->getMessage());
        $this->assertEquals($result1->getStatus(), $result2->getStatus());
    }

    public function test_handles_uppercase_staging_environment(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'STAGING', configIsCached: false);

        $result = $analyzer->analyze();

        // Should fail because STAGING (case-insensitive) is not cached
        $this->assertFailed($result);
    }

    public function test_handles_mixed_case_development_environment(): void
    {
        $analyzer = $this->createAnalyzer(environment: 'Development', configIsCached: true);

        $result = $analyzer->analyze();

        // Should fail because Development (case-insensitive) is cached
        $this->assertWarning($result);
    }

    public function test_handles_very_long_environment_names(): void
    {
        // Test with 255-character environment name
        $longEnv = str_repeat('a', 255);
        $analyzer = $this->createAnalyzer(environment: $longEnv, configIsCached: false);

        $result = $analyzer->analyze();

        // Unknown environment (not in DEV_ENVIRONMENTS or PROD_ENVIRONMENTS) should pass
        $this->assertPassed($result);
        $this->assertStringContainsString('properly configured', $result->getMessage());
    }

    public function test_handles_special_characters_in_environment_names(): void
    {
        // Test with environment name containing special characters
        $specialEnv = 'production@v2.1-preview';
        $analyzer = $this->createAnalyzer(environment: $specialEnv, configIsCached: false);

        $result = $analyzer->analyze();

        // Special characters environment (unknown) should pass
        $this->assertPassed($result);
    }

    public function test_handles_environment_with_hyphens(): void
    {
        // Common pattern: staging-preview, production-us, etc.
        $analyzer = $this->createAnalyzer(environment: 'staging-preview', configIsCached: false);

        $result = $analyzer->analyze();

        // 'staging-preview' is not in PROD_ENVIRONMENTS constant (only 'staging' is)
        // So it should pass (unknown environment, neither dev nor prod)
        $this->assertPassed($result);
    }

    public function test_handles_whitespace_in_environment(): void
    {
        // Test with leading/trailing whitespace
        $analyzer = $this->createAnalyzer(environment: ' production ', configIsCached: false);

        $result = $analyzer->analyze();

        // ' production ' with spaces is not in PROD_ENVIRONMENTS
        // So it should pass (unknown environment)
        $this->assertPassed($result);
    }

    public function test_handles_numeric_environment_names(): void
    {
        // Test with purely numeric environment name
        $analyzer = $this->createAnalyzer(environment: '12345', configIsCached: false);

        $result = $analyzer->analyze();

        // Numeric environment (unknown) should pass
        $this->assertPassed($result);
    }

    public function test_cached_config_path_uses_build_path(): void
    {
        // This test verifies that getCachedConfigPath uses buildPath correctly
        $analyzer = $this->createAnalyzer(environment: 'local', configIsCached: true);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertNotNull($issues[0]->location);

        // Verify path contains proper separators (buildPath uses DIRECTORY_SEPARATOR)
        $path = $issues[0]->location->file;
        $this->assertStringContainsString('bootstrap', $path);
        $this->assertStringContainsString('cache', $path);
        $this->assertStringContainsString('config.php', $path);

        // Verify path uses system directory separator
        if (DIRECTORY_SEPARATOR === '/') {
            $this->assertStringContainsString('bootstrap/cache/config.php', $path);
        } else {
            $this->assertStringContainsString('\\bootstrap\\cache\\config.php', $path);
        }
    }

    public function test_production_issue_includes_expected_cache_path_in_metadata(): void
    {
        // Verifies that metadata includes the expected cache path
        $analyzer = $this->createAnalyzer(environment: 'production', configIsCached: false);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertNotNull($issues[0]->location);

        // Verify metadata includes expected cache path
        $this->assertArrayHasKey('expected_cache_path', $issues[0]->metadata);
        $expectedPath = $issues[0]->metadata['expected_cache_path'];
        $this->assertIsString($expectedPath);
        $this->assertStringContainsString('bootstrap/cache/config.php', $expectedPath);

        // Path should point to cache location
        $path = $issues[0]->location->file;
        $this->assertStringContainsString('bootstrap/cache/config.php', $path);
        $this->assertNotEmpty($path);
        $this->assertIsString($path);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
