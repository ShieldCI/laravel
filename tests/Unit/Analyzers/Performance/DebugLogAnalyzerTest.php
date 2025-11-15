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

        $this->assertPassed($result);
        $this->assertStringContainsString('acceptable in local', $result->getMessage());
    }

    public function test_passes_when_debug_level_in_development_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'development',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('acceptable in development', $result->getMessage());
    }

    public function test_passes_when_debug_level_in_testing_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app.env' => 'testing',
            'logging.default' => 'single',
            'logging.channels.single.level' => 'debug',
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('acceptable in testing', $result->getMessage());
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
        $this->assertEquals('Debug Log Level', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $metadata->severity);
        $this->assertContains('logging', $metadata->tags);
        $this->assertContains('performance', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(DebugLogAnalyzer::$runInCI);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
