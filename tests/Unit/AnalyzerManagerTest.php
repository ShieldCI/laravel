<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Container\Container;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzerManager;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
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
    public function it_can_filter_by_multiple_categories(): void
    {
        $manager = $this->createManager([
            TestAnalyzer::class,
            AnotherTestAnalyzer::class,
        ]);

        $both = $manager->getByCategories(['security', 'performance']);
        $securityOnly = $manager->getByCategories(['security']);
        $none = $manager->getByCategories(['reliability']);

        $this->assertCount(2, $both);
        $this->assertCount(1, $securityOnly);
        $this->assertCount(0, $none);
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

    #[Test]
    public function it_instantiates_each_analyzer_class_exactly_once_across_get_analyzers_and_get_skipped(): void
    {
        $container = Mockery::mock(Container::class);
        // With 2 classes, container->make() must be called exactly 2 times total,
        // even though both getAnalyzers() and getSkippedAnalyzers() are invoked.
        $container->shouldReceive('make')
            ->times(2)
            ->andReturnUsing(fn (string $class) => new $class);

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

                return $values[str_replace('shieldci.', '', $key)] ?? $default;
            });

        $manager = new AnalyzerManager($config, [TestAnalyzer::class, DisabledTestAnalyzer::class], $container);

        $manager->getAnalyzers();
        $manager->getSkippedAnalyzers();
        // Third call — must still hit cache, no new make() calls.
        $manager->getAnalyzers();

        // Mockery's times(2) expectation in tearDown() is the primary assertion.
        // This explicit one prevents the "risky test" warning from PHPUnit.
        $this->addToAssertionCount(1);
    }

    #[Test]
    public function it_reads_config_keys_exactly_once_regardless_of_call_count(): void
    {
        $container = Mockery::mock(Container::class);
        $container->shouldReceive('make')->andReturnUsing(fn (string $class) => new $class);

        $config = Mockery::mock(Config::class);
        // 8 config keys read once each in initConfigCache().
        // initConfigCache() reads exactly 7 config keys, once, on the first invocation.
        $config->shouldReceive('get')
            ->times(7)
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

                return $values[str_replace('shieldci.', '', $key)] ?? $default;
            });

        $manager = new AnalyzerManager($config, [TestAnalyzer::class], $container);

        // Multiple calls — config must only be read on the first.
        $manager->getAnalyzers();
        $manager->getAnalyzers();
        $manager->getSkippedAnalyzers();
        $manager->getSkippedAnalyzers();

        $this->addToAssertionCount(1);
    }

    #[Test]
    public function it_returns_same_collection_instance_on_repeated_calls_to_get_analyzers(): void
    {
        $manager = $this->createManagerWithConfig([TestAnalyzer::class], []);

        $first = $manager->getAnalyzers();
        $second = $manager->getAnalyzers();

        $this->assertSame($first, $second);
    }

    #[Test]
    public function it_returns_same_collection_instance_on_repeated_calls_to_get_skipped_analyzers(): void
    {
        $manager = $this->createManagerWithConfig([TestAnalyzer::class, DisabledTestAnalyzer::class], []);

        $first = $manager->getSkippedAnalyzers();
        $second = $manager->getSkippedAnalyzers();

        $this->assertSame($first, $second);
    }

    #[Test]
    public function it_re_instantiates_analyzers_after_invalidate_cache(): void
    {
        $callCount = 0;

        $container = Mockery::mock(Container::class);
        $container->shouldReceive('make')
            ->andReturnUsing(function (string $class) use (&$callCount) {
                $callCount++;

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

                return $values[str_replace('shieldci.', '', $key)] ?? $default;
            });

        $manager = new AnalyzerManager($config, [TestAnalyzer::class], $container);

        $manager->getAnalyzers();
        $this->assertEquals(1, $callCount, 'First getAnalyzers() should call make() once');

        $manager->getAnalyzers();
        $this->assertEquals(1, $callCount, 'Second getAnalyzers() should hit cache — no new make() calls');

        $manager->invalidateCache();

        $manager->getAnalyzers();
        $this->assertEquals(2, $callCount, 'After invalidateCache(), make() should be called again');
    }

    #[Test]
    public function it_calls_clear_cache_on_parser_when_method_exists(): void
    {
        $parser = new ParserWithClearCache;

        $config = Mockery::mock(Config::class);
        $config->shouldReceive('get')->andReturn([]);

        $container = Mockery::mock(Container::class);
        $container->shouldReceive('make')
            ->with(ParserInterface::class)
            ->once()
            ->andReturn($parser);

        $manager = new AnalyzerManager($config, [], $container);
        $manager->clearParserCache();

        $this->assertTrue($parser->clearCacheCalled);
    }

    #[Test]
    public function it_does_not_throw_when_parser_has_no_clear_cache_method(): void
    {
        $parser = new ParserWithoutClearCache;

        $config = Mockery::mock(Config::class);
        $config->shouldReceive('get')->andReturn([]);

        $container = Mockery::mock(Container::class);
        $container->shouldReceive('make')
            ->with(ParserInterface::class)
            ->once()
            ->andReturn($parser);

        $manager = new AnalyzerManager($config, [], $container);
        $manager->clearParserCache();

        $this->addToAssertionCount(1);
    }

    #[Test]
    public function it_calls_clear_ast_parser_cache_on_analyzer_after_run_all(): void
    {
        $analyzerInstance = null;

        $container = Mockery::mock(Container::class);
        $container->shouldReceive('make')
            ->andReturnUsing(function (string $class) use (&$analyzerInstance) {
                if ($class === ParserInterface::class) {
                    throw new \RuntimeException('Not bound');
                }
                $instance = new $class;
                if ($instance instanceof AnalyzerWithAstParserCache) {
                    $analyzerInstance = $instance;
                }

                return $instance;
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

                return $values[str_replace('shieldci.', '', $key)] ?? $default;
            });

        $manager = new AnalyzerManager($config, [AnalyzerWithAstParserCache::class], $container);
        $manager->runAll();

        $this->assertNotNull($analyzerInstance);
        $this->assertTrue($analyzerInstance->clearAstParserCacheCalled);
    }

    #[Test]
    public function it_calls_clear_ast_parser_cache_on_analyzer_after_run(): void
    {
        $analyzerInstance = null;

        $container = Mockery::mock(Container::class);
        $container->shouldReceive('make')
            ->andReturnUsing(function (string $class) use (&$analyzerInstance) {
                if ($class === ParserInterface::class) {
                    throw new \RuntimeException('Not bound');
                }
                $instance = new $class;
                if ($instance instanceof AnalyzerWithAstParserCache) {
                    $analyzerInstance = $instance;
                }

                return $instance;
            });

        $config = Mockery::mock(Config::class);
        $config->shouldReceive('get')
            ->andReturnUsing(function (string $key, $default = null) {
                $values = [
                    'disabled_analyzers' => [],
                    'analyzers' => [],
                    'ci_mode' => false,
                    'ci_mode_exclude_analyzers' => [],
                    'ci_mode_analyzers' => [],
                    'paths.analyze' => [],
                    'excluded_paths' => [],
                ];

                return $values[str_replace('shieldci.', '', $key)] ?? $default;
            });

        $manager = new AnalyzerManager($config, [AnalyzerWithAstParserCache::class], $container);
        $manager->run('ast-cache-analyzer');

        $this->assertNotNull($analyzerInstance);
        $this->assertTrue($analyzerInstance->clearAstParserCacheCalled);
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

class ParserWithClearCache implements ParserInterface
{
    public bool $clearCacheCalled = false;

    public function parseFile(string $filePath): array
    {
        return [];
    }

    public function parseCode(string $code): array
    {
        return [];
    }

    public function findNodes(array $ast, string $nodeType): array
    {
        return [];
    }

    public function findMethodCalls(array $ast, string $methodName): array
    {
        return [];
    }

    public function findStaticCalls(array $ast, string $className, string $methodName): array
    {
        return [];
    }

    public function resolveNames(array $ast, array $options = []): array
    {
        return [];
    }

    public function collectStringLines(array $ast): array
    {
        return [];
    }

    public function clearCache(): void
    {
        $this->clearCacheCalled = true;
    }
}

class ParserWithoutClearCache implements ParserInterface
{
    public function parseFile(string $filePath): array
    {
        return [];
    }

    public function parseCode(string $code): array
    {
        return [];
    }

    public function findNodes(array $ast, string $nodeType): array
    {
        return [];
    }

    public function findMethodCalls(array $ast, string $methodName): array
    {
        return [];
    }

    public function findStaticCalls(array $ast, string $className, string $methodName): array
    {
        return [];
    }

    public function resolveNames(array $ast, array $options = []): array
    {
        return [];
    }

    public function collectStringLines(array $ast): array
    {
        return [];
    }
}

class AnalyzerWithAstParserCache implements AnalyzerInterface
{
    public bool $clearAstParserCacheCalled = false;

    public function clearAstParserCache(): void
    {
        $this->clearAstParserCacheCalled = true;
    }

    public function analyze(): ResultInterface
    {
        return AnalysisResult::passed('ast-cache-analyzer', 'Test passed');
    }

    public function getMetadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'ast-cache-analyzer',
            name: 'AST Cache Analyzer',
            description: 'Test analyzer with clearAstParserCache()',
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
        return 'ast-cache-analyzer';
    }
}
