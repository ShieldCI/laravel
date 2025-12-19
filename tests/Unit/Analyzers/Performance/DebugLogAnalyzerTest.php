<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Mockery;
use ShieldCI\Analyzers\Performance\DebugLogAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class DebugLogAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $configValues
     */
    protected function createAnalyzer(array $configValues = []): AnalyzerInterface
    {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        // Set up config mock with default values
        $defaults = [
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'info',
        ];

        $configMap = array_merge($defaults, $configValues);

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) use ($configMap) {
                return $configMap[$key] ?? $default;
            });

        return new DebugLogAnalyzer($config);
    }

    public function test_passes_when_log_level_is_not_debug_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'info',
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('properly configured', $result->getMessage());
    }

    public function test_passes_when_debug_level_in_local_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'local',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('Not relevant in \'local\' environment', $result->getMessage());
    }

    public function test_passes_when_debug_level_in_development_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'development',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('Not relevant in \'development\' environment', $result->getMessage());
    }

    public function test_passes_when_debug_level_in_testing_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'testing',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('Not relevant in \'testing\' environment', $result->getMessage());
    }

    public function test_fails_when_debug_level_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('debug level', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('production', $issues[0]->metadata['environment'] ?? '');
        $this->assertEquals('single', $issues[0]->metadata['channel'] ?? '');
        $this->assertEquals('debug', $issues[0]->metadata['level'] ?? '');
    }

    public function test_detects_uppercase_debug_level(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'DEBUG',
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('DEBUG', $issues[0]->metadata['level'] ?? '');
    }

    public function test_fails_when_debug_level_in_staging(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'staging',
            'logging.default' => 'daily',
            'logging.channels.daily.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('staging', $result->getMessage());
    }

    public function test_checks_stack_driver_channels(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'stack',
            'logging.channels.stack.channels' => ['single', 'slack'],
            'logging.channels.stack.level' => 'info',
            'logging.channels.single.level' => 'debug',
            'logging.channels.slack.level' => 'error',
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('single', $result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals('single', $issues[0]->metadata['channel'] ?? '');
    }

    public function test_detects_multiple_debug_channels_in_stack(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'stack',
            'logging.channels.stack.channels' => ['single', 'daily', 'slack'],
            'logging.channels.single.level' => 'debug',
            'logging.channels.daily.level' => 'debug',
            'logging.channels.slack.level' => 'error',
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(2, $issues);

        $channels = array_map(fn ($issue) => $issue->metadata['channel'] ?? '', $issues);
        $this->assertContains('single', $channels);
        $this->assertContains('daily', $channels);
    }

    public function test_passes_when_stack_has_no_debug_channels(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'stack',
            'logging.channels.stack.channels' => ['single', 'slack'],
            'logging.channels.single.level' => 'info',
            'logging.channels.slack.level' => 'error',
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_missing_log_level_configuration(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            // No level configured - should pass (defaults to Laravel's default)
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('debug-log-level', $metadata->id);
        $this->assertEquals('Debug Log Level Analyzer', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $metadata->severity);
        $this->assertContains('logging', $metadata->tags);
        $this->assertContains('performance', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(DebugLogAnalyzer::$runInCI);
    }

    // Critical Untested Cases

    public function test_handles_non_string_default_channel_null(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => null,
        ]);

        $result = $analyzer->analyze();

        // No channels to check, should pass
        $this->assertPassed($result);
    }

    public function test_handles_non_string_default_channel_array(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => ['stack', 'single'],
        ]);

        $result = $analyzer->analyze();

        // Non-string default channel is filtered out, should pass
        $this->assertPassed($result);
    }

    public function test_handles_non_string_default_channel_integer(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 123,
        ]);

        $result = $analyzer->analyze();

        // Non-string default channel is filtered out, should pass
        $this->assertPassed($result);
    }

    public function test_handles_empty_string_default_channel(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => '',
        ]);

        $result = $analyzer->analyze();

        // Empty string is falsy, no channels to check, should pass
        $this->assertPassed($result);
    }

    public function test_handles_non_string_level_value_null(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => null,
        ]);

        $result = $analyzer->analyze();

        // Null level is not 'debug', should pass
        $this->assertPassed($result);
    }

    public function test_handles_non_string_level_value_array(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => ['debug', 'info'],
        ]);

        $result = $analyzer->analyze();

        // Array level is not 'debug' string, should pass
        $this->assertPassed($result);
    }

    public function test_handles_non_string_level_value_boolean(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => true,
        ]);

        $result = $analyzer->analyze();

        // Boolean level is not 'debug', should pass
        $this->assertPassed($result);
    }

    public function test_handles_non_string_level_value_integer(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => 7,
        ]);

        $result = $analyzer->analyze();

        // Numeric level (syslog style) is not 'debug' string, should pass
        $this->assertPassed($result);
    }

    public function test_handles_non_array_stack_channels_null(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'stack',
            'logging.channels.stack.channels' => null,
        ]);

        $result = $analyzer->analyze();

        // Null stack channels, only 'stack' itself checked, should pass
        $this->assertPassed($result);
    }

    public function test_handles_non_array_stack_channels_string(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'stack',
            'logging.channels.stack.channels' => 'single',
        ]);

        $result = $analyzer->analyze();

        // String instead of array causes foreach to fail gracefully, should pass
        $this->assertPassed($result);
    }

    public function test_handles_mixed_type_values_in_stack_channels_array(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'stack',
            'logging.channels.stack.channels' => [null, 'single', 123, true, 'daily'],
            'logging.channels.single.level' => 'info',
            'logging.channels.daily.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        // Non-string values filtered out, 'daily' has debug level
        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals('daily', $issues[0]->metadata['channel'] ?? '');
    }

    public function test_handles_empty_stack_channels_array(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'stack',
            'logging.channels.stack.channels' => [],
        ]);

        $result = $analyzer->analyze();

        // Empty array, no channels to check, should pass
        $this->assertPassed($result);
    }

    public function test_checks_stack_channel_itself_with_debug_level(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'stack',
            'logging.channels.stack.channels' => ['single'],
            'logging.channels.stack.level' => 'debug',
            'logging.channels.single.level' => 'info',
        ]);

        $result = $analyzer->analyze();

        // Stack channel itself has debug level
        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals('stack', $issues[0]->metadata['channel'] ?? '');
    }

    public function test_handles_missing_logging_default_config(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            // logging.default not set at all
        ]);

        $result = $analyzer->analyze();

        // No default channel configured, should pass
        $this->assertPassed($result);
    }

    // Edge Cases (Medium Priority)

    public function test_handles_mixed_case_debug_variations(): void
    {
        $testCases = [
            ['Debug', 'Debug'],
            ['DeBuG', 'DeBuG'],
            ['dEbUg', 'dEbUg'],
            ['DEBUG', 'DEBUG'],
        ];

        foreach ($testCases as [$level, $expectedMetadata]) {
            $analyzer = $this->createAnalyzer([
                'app.env' => 'production',
                'logging.default' => 'single',
                'logging.channels.single.level' => $level,
            ]);

            $result = $analyzer->analyze();

            $this->assertFailed($result);

            $issues = $result->getIssues();
            $this->assertNotEmpty($issues);
            $this->assertEquals($expectedMetadata, $issues[0]->metadata['level'] ?? '');
        }
    }

    public function test_handles_non_existent_channel_in_stack(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'stack',
            'logging.channels.stack.channels' => ['single', 'nonexistent'],
            'logging.channels.single.level' => 'info',
            // nonexistent channel not defined
        ]);

        $result = $analyzer->analyze();

        // Non-existent channel returns null for level, should pass
        $this->assertPassed($result);
    }

    public function test_handles_circular_stack_reference(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'stack',
            'logging.channels.stack.channels' => ['stack'],
            'logging.channels.stack.level' => 'info',
        ]);

        $result = $analyzer->analyze();

        // Circular reference: stack includes itself
        // Current implementation checks 'stack' twice but doesn't infinitely recurse
        $this->assertPassed($result);
    }

    public function test_handles_very_long_environment_names(): void
    {
        $longEnv = str_repeat('a', 255);
        $analyzer = $this->createAnalyzer([
            'app.env' => $longEnv,
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        // Long environment name is not in relevantEnvironments list, so it's skipped
        $this->assertSkipped($result);
        $this->assertStringContainsString('only relevant in:', $result->getMessage());
    }

    public function test_handles_special_characters_in_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production@v2',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        // Environment with special characters, not in relevantEnvironments list
        $this->assertSkipped($result);
        $this->assertStringContainsString('only relevant in:', $result->getMessage());
    }

    public function test_handles_whitespace_in_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => ' production ',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        // Environment with whitespace won't match relevantEnvironments check
        $this->assertSkipped($result);
        $this->assertStringContainsString('only relevant in:', $result->getMessage());
    }

    public function test_handles_unknown_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'qa',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        // 'qa' environment not in relevantEnvironments list, analyzer is skipped
        $this->assertSkipped($result);
        $this->assertStringContainsString('only relevant in:', $result->getMessage());
    }

    public function test_handles_empty_environment_string(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => '',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        // Empty string not in allowed list, checks proceed
        // AbstractAnalyzer defaults to 'production' for empty env
        $this->assertFailed($result);
    }

    public function test_preserves_original_case_in_metadata(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'stack',
            'logging.channels.stack.channels' => ['single', 'daily'],
            'logging.channels.single.level' => 'DEBUG',
            'logging.channels.daily.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertCount(2, $issues);

        // Check that original case is preserved in metadata
        $levels = array_map(fn ($issue) => $issue->metadata['level'] ?? '', $issues);
        $this->assertContains('DEBUG', $levels);
        $this->assertContains('debug', $levels);
    }

    // Low Priority Cases

    public function test_recommendation_contains_actionable_advice(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('info', $recommendation);
        $this->assertStringContainsString('production', $recommendation);
        $this->assertStringContainsString('LOG_LEVEL', $recommendation);
        $this->assertStringContainsString('performance', $recommendation);
    }

    public function test_location_points_to_config_file(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $location = $issues[0]->location;
        $this->assertStringContainsString('config', $location->file);
        $this->assertStringContainsString('logging.php', $location->file);
        $this->assertGreaterThanOrEqual(1, $location->line);
    }

    public function test_issue_has_correct_severity(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }

    public function test_detection_method_in_metadata(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('config_repository', $issues[0]->metadata['detection_method'] ?? '');
    }

    public function test_handles_warning_level_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'warning',
        ]);

        $result = $analyzer->analyze();

        // 'warning' is not 'debug', should pass
        $this->assertPassed($result);
    }

    public function test_handles_error_level_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'error',
        ]);

        $result = $analyzer->analyze();

        // 'error' is not 'debug', should pass
        $this->assertPassed($result);
    }

    public function test_handles_critical_level_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'production',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'critical',
        ]);

        $result = $analyzer->analyze();

        // 'critical' is not 'debug', should pass
        $this->assertPassed($result);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
