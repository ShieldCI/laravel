<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Container\Container;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzerManager;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Results\AnalysisResult;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Tests\TestCase;

class AnalyzerManagerTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    #[Test]
    public function it_can_get_all_analyzers(): void
    {
        $manager = $this->createManager([
            TestAnalyzer::class,
            AnotherTestAnalyzer::class,
        ]);

        $analyzers = $manager->getAnalyzers();

        $this->assertCount(2, $analyzers);
    }

    #[Test]
    public function it_filters_out_disabled_analyzers(): void
    {
        $manager = $this->createManager([
            TestAnalyzer::class,
            DisabledTestAnalyzer::class,
        ]);

        $analyzers = $manager->getAnalyzers();

        $this->assertCount(1, $analyzers);
    }

    #[Test]
    public function it_can_filter_by_category(): void
    {
        $manager = $this->createManager([
            TestAnalyzer::class,
            AnotherTestAnalyzer::class,
        ]);

        $security = $manager->getByCategory('security');
        $performance = $manager->getByCategory('performance');

        $this->assertCount(1, $security);
        $this->assertCount(1, $performance);
    }

    #[Test]
    public function it_can_run_all_analyzers(): void
    {
        $manager = $this->createManager([
            TestAnalyzer::class,
            AnotherTestAnalyzer::class,
        ]);

        $results = $manager->runAll();

        $this->assertCount(2, $results);
        $this->assertInstanceOf(AnalysisResult::class, $results->first());
    }

    #[Test]
    public function it_can_run_specific_analyzer(): void
    {
        $manager = $this->createManager([
            TestAnalyzer::class,
            AnotherTestAnalyzer::class,
        ]);

        $result = $manager->run('test-analyzer');

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertEquals('test-analyzer', $result->getAnalyzerId());
    }

    #[Test]
    public function it_returns_null_for_non_existent_analyzer(): void
    {
        $manager = $this->createManager([TestAnalyzer::class]);

        $result = $manager->run('non-existent');

        $this->assertNull($result);
    }

    #[Test]
    public function it_can_count_analyzers(): void
    {
        $manager = $this->createManager([
            TestAnalyzer::class,
            AnotherTestAnalyzer::class,
        ]);

        $this->assertEquals(2, $manager->count());
    }

    #[Test]
    public function it_can_count_enabled_analyzers(): void
    {
        $manager = $this->createManager([
            TestAnalyzer::class,
            DisabledTestAnalyzer::class,
        ]);

        $this->assertEquals(1, $manager->enabledCount());
    }

    #[Test]
    public function it_filters_by_disabled_analyzers_config(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, AnotherTestAnalyzer::class],
            ['disabled_analyzers' => ['test-analyzer']],
        );

        $analyzers = $manager->getAnalyzers();

        $this->assertCount(1, $analyzers);
        $this->assertEquals('another-test-analyzer', $analyzers->first()->getId());
    }

    #[Test]
    public function it_filters_by_ci_mode_whitelist(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, AnotherTestAnalyzer::class],
            [
                'ci_mode' => true,
                'ci_mode_analyzers' => ['test-analyzer'],
            ],
        );

        $analyzers = $manager->getAnalyzers();

        $this->assertCount(1, $analyzers);
        $this->assertEquals('test-analyzer', $analyzers->first()->getId());
    }

    #[Test]
    public function it_filters_by_ci_mode_run_in_ci_property(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, CiIncompatibleTestAnalyzer::class],
            ['ci_mode' => true],
        );

        $analyzers = $manager->getAnalyzers();

        $this->assertCount(1, $analyzers);
        $this->assertEquals('test-analyzer', $analyzers->first()->getId());
    }

    #[Test]
    public function it_filters_by_ci_mode_blacklist(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, AnotherTestAnalyzer::class],
            [
                'ci_mode' => true,
                'ci_mode_exclude_analyzers' => ['another-test-analyzer'],
            ],
        );

        $analyzers = $manager->getAnalyzers();

        $this->assertCount(1, $analyzers);
        $this->assertEquals('test-analyzer', $analyzers->first()->getId());
    }

    #[Test]
    public function it_filters_by_enabled_categories(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, AnotherTestAnalyzer::class],
            ['analyzers' => ['security' => ['enabled' => true], 'performance' => ['enabled' => false]]],
        );

        $analyzers = $manager->getAnalyzers();

        $this->assertCount(1, $analyzers);
        $this->assertEquals('test-analyzer', $analyzers->first()->getId());
    }

    #[Test]
    public function it_returns_no_analyzers_when_no_categories_enabled(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, AnotherTestAnalyzer::class],
            ['analyzers' => ['security' => ['enabled' => false], 'performance' => ['enabled' => false]]],
        );

        $analyzers = $manager->getAnalyzers();

        $this->assertCount(0, $analyzers);
    }

    #[Test]
    public function it_gets_skipped_analyzers(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, DisabledTestAnalyzer::class],
            [],
        );

        $skipped = $manager->getSkippedAnalyzers();

        $this->assertCount(1, $skipped);
        $this->assertEquals('disabled-test-analyzer', $skipped->first()->getAnalyzerId());
    }

    #[Test]
    public function it_gets_skip_reason_for_disabled_analyzer(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, AnotherTestAnalyzer::class],
            ['disabled_analyzers' => ['another-test-analyzer']],
        );

        $skipped = $manager->getSkippedAnalyzers();

        $this->assertCount(1, $skipped);
        $this->assertStringContainsString('Disabled', $skipped->first()->getMessage());
    }

    #[Test]
    public function it_gets_skip_reason_for_ci_whitelist(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, AnotherTestAnalyzer::class],
            [
                'ci_mode' => true,
                'ci_mode_analyzers' => ['test-analyzer'],
            ],
        );

        $skipped = $manager->getSkippedAnalyzers();

        $this->assertCount(1, $skipped);
        $this->assertStringContainsString('CI mode whitelist', $skipped->first()->getMessage());
    }

    #[Test]
    public function it_gets_skip_reason_for_ci_run_in_ci(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, CiIncompatibleTestAnalyzer::class],
            ['ci_mode' => true],
        );

        $skipped = $manager->getSkippedAnalyzers();

        $this->assertCount(1, $skipped);
        $this->assertStringContainsString('CI', $skipped->first()->getMessage());
    }

    #[Test]
    public function it_gets_skip_reason_for_ci_blacklist(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, AnotherTestAnalyzer::class],
            [
                'ci_mode' => true,
                'ci_mode_exclude_analyzers' => ['another-test-analyzer'],
            ],
        );

        $skipped = $manager->getSkippedAnalyzers();

        $this->assertCount(1, $skipped);
        $this->assertStringContainsString('Excluded from CI', $skipped->first()->getMessage());
    }

    #[Test]
    public function it_gets_skip_reason_for_category_not_enabled(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, AnotherTestAnalyzer::class],
            ['analyzers' => ['security' => ['enabled' => true], 'performance' => ['enabled' => false]]],
        );

        $skipped = $manager->getSkippedAnalyzers();

        $this->assertCount(1, $skipped);
        $this->assertStringContainsString('Category not enabled', $skipped->first()->getMessage());
    }

    #[Test]
    public function it_gets_skip_reason_for_should_run_false(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, DisabledTestAnalyzer::class],
            [],
        );

        $skipped = $manager->getSkippedAnalyzers();

        $this->assertCount(1, $skipped);
        $this->assertStringContainsString('Disabled for testing', $skipped->first()->getMessage());
    }

    #[Test]
    public function it_includes_skipped_analyzers_in_run_all(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, DisabledTestAnalyzer::class],
            [],
        );

        $results = $manager->runAll();

        // 1 running + 1 skipped
        $this->assertCount(2, $results);
    }

    #[Test]
    public function it_gets_analyzer_config(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class],
            ['analyzers' => ['security' => ['enabled' => true, 'test-analyzer' => ['threshold' => 5]]]],
        );

        $config = $manager->getAnalyzerConfig('security', 'test-analyzer', ['threshold' => 10]);

        $this->assertEquals(5, $config['threshold']);
    }

    #[Test]
    public function it_returns_defaults_for_missing_analyzer_config(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class],
            ['analyzers' => ['security' => ['enabled' => true]]],
        );

        $config = $manager->getAnalyzerConfig('security', 'test-analyzer', ['threshold' => 10]);

        $this->assertEquals(10, $config['threshold']);
    }

    #[Test]
    public function it_returns_defaults_for_missing_category_config(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class],
            [],
        );

        $config = $manager->getAnalyzerConfig('nonexistent', 'test-analyzer', ['limit' => 100]);

        $this->assertEquals(100, $config['limit']);
    }

    #[Test]
    public function it_returns_defaults_when_category_config_is_not_array(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class],
            ['analyzers' => ['security' => 'not-an-array']],
        );

        $config = $manager->getAnalyzerConfig('security', 'test-analyzer', ['threshold' => 10]);

        $this->assertEquals(10, $config['threshold']);
    }

    #[Test]
    public function it_returns_defaults_when_analyzer_config_is_not_array(): void
    {
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class],
            ['analyzers' => ['security' => ['test-analyzer' => 'string-not-array']]],
        );

        $config = $manager->getAnalyzerConfig('security', 'test-analyzer', ['threshold' => 10]);

        $this->assertEquals(10, $config['threshold']);
    }

    #[Test]
    public function it_filters_out_analyzers_that_throw_on_construction(): void
    {
        $container = Mockery::mock(Container::class);
        $container->shouldReceive('make')
            ->andReturnUsing(function (string $class) {
                if ($class === 'ThrowingAnalyzer') {
                    throw new \RuntimeException('Cannot instantiate');
                }

                return new $class;
            });

        $config = Mockery::mock(Config::class);
        $config->shouldReceive('get')
            ->andReturnUsing(function (string $key, $default = null) {
                $values = [
                    'disabled_analyzers' => [],
                    'analyzers' => [],
                    'ci_mode' => false,
                    'ci_mode_analyzers' => [],
                    'ci_mode_exclude_analyzers' => [],
                    'paths.analyze' => [],
                    'excluded_paths' => [],
                ];
                $shortKey = str_replace('shieldci.', '', $key);

                return $values[$shortKey] ?? $default;
            });

        /** @phpstan-ignore-next-line */
        $manager = new AnalyzerManager($config, [TestAnalyzer::class, 'ThrowingAnalyzer'], $container);

        $analyzers = $manager->getAnalyzers();

        $this->assertCount(1, $analyzers);
        $this->assertEquals('test-analyzer', $analyzers->first()->getId());
    }

    #[Test]
    public function it_sets_base_path_and_paths_on_file_analyzers(): void
    {
        $manager = $this->createManagerWithConfig(
            [FileTestAnalyzer::class],
            ['paths.analyze' => ['app', 'src'], 'excluded_paths' => ['vendor']],
        );

        $analyzers = $manager->getAnalyzers();

        $this->assertCount(1, $analyzers);
        $analyzer = $analyzers->first();
        $this->assertInstanceOf(FileTestAnalyzer::class, $analyzer);
        $this->assertNotNull($analyzer->basePath);
        $this->assertNotEmpty($analyzer->paths);
        $this->assertNotEmpty($analyzer->excludePatterns);
    }

    #[Test]
    public function it_sets_file_analyzer_properties_on_skipped_analyzers(): void
    {
        // FileTestAnalyzer has setBasePath/setPaths/setExcludePatterns methods
        // Disabling it via config means it goes through the skipped path
        $manager = $this->createManagerWithConfig(
            [TestAnalyzer::class, FileTestAnalyzer::class],
            [
                'disabled_analyzers' => ['file-test-analyzer'],
                'paths.analyze' => ['app', 'routes'],
                'excluded_paths' => ['vendor', 'node_modules'],
            ],
        );

        $skipped = $manager->getSkippedAnalyzers();

        $this->assertCount(1, $skipped);
        $this->assertEquals('file-test-analyzer', $skipped->first()->getAnalyzerId());
    }

    #[Test]
    public function it_handles_throwing_analyzer_in_skipped_analyzers(): void
    {
        $container = Mockery::mock(Container::class);
        $container->shouldReceive('make')
            ->andReturnUsing(function (string $class) {
                if ($class === 'ThrowingAnalyzer') {
                    throw new \RuntimeException('Cannot instantiate');
                }

                return new $class;
            });

        $config = Mockery::mock(Config::class);
        $config->shouldReceive('get')
            ->andReturnUsing(function (string $key, $default = null) {
                $values = [
                    'disabled_analyzers' => [],
                    'analyzers' => [],
                    'ci_mode' => false,
                    'ci_mode_analyzers' => [],
                    'ci_mode_exclude_analyzers' => [],
                    'paths.analyze' => [],
                    'excluded_paths' => [],
                ];
                $shortKey = str_replace('shieldci.', '', $key);

                return $values[$shortKey] ?? $default;
            });

        /** @phpstan-ignore-next-line */
        $manager = new AnalyzerManager($config, [TestAnalyzer::class, 'ThrowingAnalyzer'], $container);

        // getSkippedAnalyzers should handle the throwing analyzer gracefully
        $skipped = $manager->getSkippedAnalyzers();

        // The throwing analyzer should be filtered out (null), not included in skipped results
        // Only valid analyzers that are actually skipped should appear
        $this->assertCount(0, $skipped);
    }

    protected function createManager(array $analyzerClasses): AnalyzerManager
    {
        $config = Mockery::mock(Config::class);
        $config->shouldReceive('get')->andReturn(true);

        $container = Mockery::mock(Container::class);
        $container->shouldReceive('make')
            ->andReturnUsing(function (string $class) {
                return new $class;
            });

        return new AnalyzerManager($config, $analyzerClasses, $container);
    }

    /**
     * @param  array<class-string<AnalyzerInterface>>  $analyzerClasses
     * @param  array<string, mixed>  $configOverrides
     */
    protected function createManagerWithConfig(array $analyzerClasses, array $configOverrides = []): AnalyzerManager
    {
        $configDefaults = [
            'disabled_analyzers' => [],
            'analyzers' => [],
            'ci_mode' => false,
            'ci_mode_analyzers' => [],
            'ci_mode_exclude_analyzers' => [],
            'paths.analyze' => [],
            'excluded_paths' => [],
        ];

        $configValues = array_merge($configDefaults, $configOverrides);

        $config = Mockery::mock(Config::class);
        $config->shouldReceive('get')
            ->andReturnUsing(function (string $key, $default = null) use ($configValues) {
                $shortKey = str_replace('shieldci.', '', $key);

                return $configValues[$shortKey] ?? $default;
            });

        $container = Mockery::mock(Container::class);
        $container->shouldReceive('make')
            ->andReturnUsing(function (string $class) {
                return new $class;
            });

        return new AnalyzerManager($config, $analyzerClasses, $container);
    }
}

// Test stub analyzers
class TestAnalyzer implements AnalyzerInterface
{
    public function analyze(): ResultInterface
    {
        return AnalysisResult::passed('test-analyzer', 'Test passed');
    }

    public function getMetadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'test-analyzer',
            name: 'Test Analyzer',
            description: 'Test description',
            category: Category::Security,
            severity: Severity::High,
        );
    }

    public function shouldRun(): bool
    {
        return true;
    }

    public function getSkipReason(): string
    {
        return 'Not applicable';
    }

    public function getId(): string
    {
        return 'test-analyzer';
    }
}

class AnotherTestAnalyzer implements AnalyzerInterface
{
    public function analyze(): ResultInterface
    {
        return AnalysisResult::passed('another-test-analyzer', 'Test passed');
    }

    public function getMetadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'another-test-analyzer',
            name: 'Another Test Analyzer',
            description: 'Test description',
            category: Category::Performance,
            severity: Severity::Medium,
        );
    }

    public function shouldRun(): bool
    {
        return true;
    }

    public function getSkipReason(): string
    {
        return 'Not applicable';
    }

    public function getId(): string
    {
        return 'another-test-analyzer';
    }
}

class DisabledTestAnalyzer implements AnalyzerInterface
{
    public function analyze(): ResultInterface
    {
        return AnalysisResult::skipped('disabled-test-analyzer', 'Skipped');
    }

    public function getMetadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'disabled-test-analyzer',
            name: 'Disabled Test Analyzer',
            description: 'Test description',
            category: Category::Security,
            severity: Severity::Low,
        );
    }

    public function shouldRun(): bool
    {
        return false;
    }

    public function getSkipReason(): string
    {
        return 'Disabled for testing';
    }

    public function getId(): string
    {
        return 'disabled-test-analyzer';
    }
}

class CiIncompatibleTestAnalyzer implements AnalyzerInterface
{
    public static bool $runInCI = false;

    public function analyze(): ResultInterface
    {
        return AnalysisResult::passed('ci-incompatible-analyzer', 'Test passed');
    }

    public function getMetadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'ci-incompatible-analyzer',
            name: 'CI Incompatible Analyzer',
            description: 'Analyzer that does not run in CI',
            category: Category::Security,
            severity: Severity::Medium,
        );
    }

    public function shouldRun(): bool
    {
        return true;
    }

    public function getSkipReason(): string
    {
        return 'Not applicable in CI';
    }

    public function getId(): string
    {
        return 'ci-incompatible-analyzer';
    }
}

class FileTestAnalyzer implements AnalyzerInterface
{
    public ?string $basePath = null;

    /** @var array<string> */
    public array $paths = [];

    /** @var array<string> */
    public array $excludePatterns = [];

    public function setBasePath(string $basePath): void
    {
        $this->basePath = $basePath;
    }

    /**
     * @param  array<string>  $paths
     */
    public function setPaths(array $paths): void
    {
        $this->paths = $paths;
    }

    /**
     * @param  array<string>  $patterns
     */
    public function setExcludePatterns(array $patterns): void
    {
        $this->excludePatterns = $patterns;
    }

    public function analyze(): ResultInterface
    {
        return AnalysisResult::passed('file-test-analyzer', 'Test passed');
    }

    public function getMetadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'file-test-analyzer',
            name: 'File Test Analyzer',
            description: 'Test analyzer with file methods',
            category: Category::Security,
            severity: Severity::High,
        );
    }

    public function shouldRun(): bool
    {
        return true;
    }

    public function getSkipReason(): string
    {
        return '';
    }

    public function getId(): string
    {
        return 'file-test-analyzer';
    }
}
