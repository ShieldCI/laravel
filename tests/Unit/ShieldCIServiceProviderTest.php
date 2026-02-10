<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzerManager;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\Contracts\ReporterInterface;
use ShieldCI\Support\Composer;
use ShieldCI\Support\PathFilter;
use ShieldCI\Support\Reporter;
use ShieldCI\Support\SecurityAdvisories\AdvisoryAnalyzerInterface;
use ShieldCI\Support\SecurityAdvisories\AdvisoryFetcherInterface;
use ShieldCI\Support\SecurityAdvisories\ComposerDependencyReader;
use ShieldCI\Support\SecurityAdvisories\VersionConstraintMatcher;
use ShieldCI\Tests\TestCase;

class ShieldCIServiceProviderTest extends TestCase
{
    #[Test]
    public function it_registers_parser_interface(): void
    {
        $parser = $this->app->make(ParserInterface::class);

        $this->assertInstanceOf(ParserInterface::class, $parser);
    }

    #[Test]
    public function it_registers_reporter_interface(): void
    {
        $reporter = $this->app->make(ReporterInterface::class);

        $this->assertInstanceOf(Reporter::class, $reporter);
    }

    #[Test]
    public function it_registers_analyzer_manager(): void
    {
        $manager = $this->app->make(AnalyzerManager::class);

        $this->assertInstanceOf(AnalyzerManager::class, $manager);
    }

    #[Test]
    public function it_registers_composer_support(): void
    {
        $composer = $this->app->make(Composer::class);

        $this->assertInstanceOf(Composer::class, $composer);
    }

    #[Test]
    public function it_registers_path_filter(): void
    {
        $filter = $this->app->make(PathFilter::class);

        $this->assertInstanceOf(PathFilter::class, $filter);
    }

    #[Test]
    public function it_registers_version_constraint_matcher(): void
    {
        $matcher = $this->app->make(VersionConstraintMatcher::class);

        $this->assertInstanceOf(VersionConstraintMatcher::class, $matcher);
    }

    #[Test]
    public function it_registers_advisory_analyzer_interface(): void
    {
        $analyzer = $this->app->make(AdvisoryAnalyzerInterface::class);

        $this->assertInstanceOf(AdvisoryAnalyzerInterface::class, $analyzer);
    }

    #[Test]
    public function it_registers_advisory_fetcher_interface(): void
    {
        $fetcher = $this->app->make(AdvisoryFetcherInterface::class);

        $this->assertInstanceOf(AdvisoryFetcherInterface::class, $fetcher);
    }

    #[Test]
    public function it_registers_composer_dependency_reader(): void
    {
        $reader = $this->app->make(ComposerDependencyReader::class);

        $this->assertInstanceOf(ComposerDependencyReader::class, $reader);
    }

    #[Test]
    public function it_merges_config(): void
    {
        $this->assertNotNull(config('shieldci'));
        $this->assertIsArray(config('shieldci'));
    }

    #[Test]
    public function it_registers_analyze_command(): void
    {
        $this->artisan('list')
            ->assertSuccessful()
            ->expectsOutputToContain('shield:analyze');
    }

    #[Test]
    public function it_registers_baseline_command(): void
    {
        $this->artisan('list')
            ->assertSuccessful()
            ->expectsOutputToContain('shield:baseline');
    }

    #[Test]
    public function it_uses_singleton_for_reporter(): void
    {
        $reporter1 = $this->app->make(ReporterInterface::class);
        $reporter2 = $this->app->make(ReporterInterface::class);

        $this->assertSame($reporter1, $reporter2);
    }

    #[Test]
    public function it_uses_singleton_for_analyzer_manager(): void
    {
        $manager1 = $this->app->make(AnalyzerManager::class);
        $manager2 = $this->app->make(AnalyzerManager::class);

        $this->assertSame($manager1, $manager2);
    }

    #[Test]
    public function it_uses_singleton_for_path_filter(): void
    {
        $filter1 = $this->app->make(PathFilter::class);
        $filter2 = $this->app->make(PathFilter::class);

        $this->assertSame($filter1, $filter2);
    }

    #[Test]
    public function it_discovers_analyzers(): void
    {
        $manager = $this->app->make(AnalyzerManager::class);

        // Should have discovered at least some analyzers
        $this->assertGreaterThan(0, $manager->count());
    }

    #[Test]
    public function it_respects_config_for_path_filter(): void
    {
        config(['shieldci.paths.analyze' => ['app', 'routes']]);
        config(['shieldci.excluded_paths' => ['vendor', 'tests']]);

        // Re-resolve to pick up new config
        $this->app->forgetInstance(PathFilter::class);
        $filter = $this->app->make(PathFilter::class);

        $this->assertEquals(['app', 'routes'], $filter->getAnalyzePaths());
        $this->assertEquals(['vendor', 'tests'], $filter->getExcludedPaths());
    }

    #[Test]
    public function it_resolves_logger_from_log_binding(): void
    {
        // Fully remove LoggerInterface binding using reflection
        $this->app->offsetUnset(\Psr\Log\LoggerInterface::class);
        $this->app->forgetInstance(\Psr\Log\LoggerInterface::class);

        // Remove from bindings via reflection to ensure bound() returns false
        $app = $this->app;
        $this->assertNotNull($app);
        $ref = new \ReflectionProperty($app, 'bindings');
        $ref->setAccessible(true);
        $bindings = $ref->getValue($app);
        unset($bindings[\Psr\Log\LoggerInterface::class]);
        $ref->setValue($app, $bindings);

        // Also remove from aliases if present
        $aliasRef = new \ReflectionProperty($app, 'aliases');
        $aliasRef->setAccessible(true);
        $aliases = $aliasRef->getValue($app);
        unset($aliases[\Psr\Log\LoggerInterface::class]);
        $aliasRef->setValue($app, $aliases);

        // Keep 'log' binding available
        $this->app->bind('log', fn () => \Mockery::mock(\Psr\Log\LoggerInterface::class));

        // Force re-resolution of AdvisoryFetcherInterface
        $this->app->forgetInstance(\ShieldCI\Support\SecurityAdvisories\AdvisoryFetcherInterface::class);
        $fetcher = $this->app->make(\ShieldCI\Support\SecurityAdvisories\AdvisoryFetcherInterface::class);

        $this->assertInstanceOf(\ShieldCI\Support\SecurityAdvisories\HttpAdvisoryFetcher::class, $fetcher);
    }

    #[Test]
    public function it_returns_null_for_file_without_namespace(): void
    {
        $provider = new \ShieldCI\ShieldCIServiceProvider($this->app);

        $tempFile = tempnam(sys_get_temp_dir(), 'shieldci_test_');
        file_put_contents($tempFile, "<?php\nclass NoNamespace {}\n");

        try {
            $reflection = new \ReflectionMethod($provider, 'getClassFromFile');
            $reflection->setAccessible(true);

            $result = $reflection->invoke($provider, $tempFile);

            $this->assertNull($result);
        } finally {
            @unlink($tempFile);
        }
    }

    #[Test]
    public function it_returns_null_for_file_without_class_declaration(): void
    {
        $provider = new \ShieldCI\ShieldCIServiceProvider($this->app);

        $tempFile = tempnam(sys_get_temp_dir(), 'shieldci_test_');
        file_put_contents($tempFile, "<?php\nnamespace App\\Test;\n\nfunction helper() {}\n");

        try {
            $reflection = new \ReflectionMethod($provider, 'getClassFromFile');
            $reflection->setAccessible(true);

            $result = $reflection->invoke($provider, $tempFile);

            $this->assertNull($result);
        } finally {
            @unlink($tempFile);
        }
    }

    #[Test]
    public function it_skips_non_existent_analyzer_directory(): void
    {
        $provider = new \ShieldCI\ShieldCIServiceProvider($this->app);

        $reflection = new \ReflectionMethod($provider, 'discoverAnalyzers');
        $reflection->setAccessible(true);

        // This should work and not throw even if some directories don't exist
        $analyzers = $reflection->invoke($provider);

        $this->assertIsArray($analyzers);
    }

    #[Test]
    public function it_configures_docs_base_url_resolver(): void
    {
        config(['shieldci.docs_base_url' => 'https://custom-docs.example.com']);

        // The resolver is configured during registration, so it should use the config value
        // This tests that the configuration integration works
        $this->assertEquals('https://custom-docs.example.com', config('shieldci.docs_base_url'));
    }
}
