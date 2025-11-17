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
