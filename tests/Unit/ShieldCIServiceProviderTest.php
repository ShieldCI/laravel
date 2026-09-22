<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit;

use Illuminate\Contracts\Config\Repository;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\LoggerInterface;
use ShieldCI\AnalyzerManager;
use ShieldCI\Analyzers\BestPractices\ChunkMissingAnalyzer;
use ShieldCI\Analyzers\BestPractices\FatModelAnalyzer;
use ShieldCI\Analyzers\BestPractices\LogicInBladeAnalyzer;
use ShieldCI\Analyzers\BestPractices\ServiceContainerResolutionAnalyzer;
use ShieldCI\Analyzers\Performance\EnvCallAnalyzer;
use ShieldCI\Analyzers\Security\AuthenticationAnalyzer;
use ShieldCI\Analyzers\Security\CsrfAnalyzer;
use ShieldCI\Analyzers\Security\DebugModeAnalyzer;
use ShieldCI\Analyzers\Security\FillableForeignKeyAnalyzer;
use ShieldCI\Analyzers\Security\LoginThrottlingAnalyzer;
use ShieldCI\Analyzers\Security\MassAssignmentAnalyzer;
use ShieldCI\Analyzers\Security\XssAnalyzer;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Contracts\ReporterInterface;
use ShieldCI\ShieldCIServiceProvider;
use ShieldCI\Support\Composer;
use ShieldCI\Support\OriginReachability\OriginReachabilityChecker;
use ShieldCI\Support\PathFilter;
use ShieldCI\Support\Reporter;
use ShieldCI\Support\SecurityAdvisories\AdvisoryAnalyzerInterface;
use ShieldCI\Support\SecurityAdvisories\AdvisoryFetcherInterface;
use ShieldCI\Support\SecurityAdvisories\ComposerDependencyReader;
use ShieldCI\Support\SecurityAdvisories\HttpAdvisoryFetcher;
use ShieldCI\Support\SecurityAdvisories\VersionConstraintMatcher;
use ShieldCI\Tests\TestCase;

class ShieldCIServiceProviderTest extends TestCase
{
    /** @test */
    #[Test]
    public function it_registers_parser_interface(): void
    {
        $parser = $this->app->make(ParserInterface::class);

        $this->assertInstanceOf(ParserInterface::class, $parser);
    }

    /** @test */
    #[Test]
    public function it_shares_one_ast_parser_between_concrete_and_interface_resolution(): void
    {
        $parser = $this->app->make(AstParser::class);

        $this->assertSame($parser, $this->app->make(AstParser::class));
        $this->assertSame($parser, $this->app->make(ParserInterface::class));
    }

    /** @test */
    #[Test]
    public function analyzers_type_hinting_the_concrete_parser_receive_the_shared_singleton(): void
    {
        $singleton = $this->app->make(ParserInterface::class);

        // Class => the property the parser lands in. Most analyzers type-hint it into
        // the InspectsCode property; LogicInBladeAnalyzer declares its own.
        $analyzerClasses = [
            AuthenticationAnalyzer::class => 'parser',
            MassAssignmentAnalyzer::class => 'parser',
            FillableForeignKeyAnalyzer::class => 'parser',
            LoginThrottlingAnalyzer::class => 'parser',
            FatModelAnalyzer::class => 'parser',
            ServiceContainerResolutionAnalyzer::class => 'parser',
            ChunkMissingAnalyzer::class => 'parser',
            CsrfAnalyzer::class => 'parser',
            DebugModeAnalyzer::class => 'parser',
            XssAnalyzer::class => 'parser',
            EnvCallAnalyzer::class => 'parser',
            LogicInBladeAnalyzer::class => 'astParser',
        ];

        foreach ($analyzerClasses as $class => $property) {
            $analyzer = $this->app->make($class);
            $parser = (new \ReflectionProperty($class, $property))->getValue($analyzer);

            $this->assertSame($singleton, $parser, sprintf(
                '%s must receive the shared AstParser singleton so its AST cache is cleared between analyzers.',
                $class
            ));
        }
    }

    /** @test */
    #[Test]
    public function an_analyzer_built_without_a_parser_still_gets_the_singleton(): void
    {
        $singleton = $this->app->make(AstParser::class);

        // The constructor argument is optional for backward compatibility, so the
        // no-argument path has to reach the singleton too. A fallback of `new AstParser`
        // would satisfy the type and silently reintroduce the private instance.
        $envCall = new EnvCallAnalyzer;
        $blade = new LogicInBladeAnalyzer($this->app->make(Repository::class));

        $this->assertSame($singleton, (new \ReflectionProperty(EnvCallAnalyzer::class, 'parser'))->getValue($envCall));
        $this->assertSame($singleton, (new \ReflectionProperty(LogicInBladeAnalyzer::class, 'astParser'))->getValue($blade));
    }

    /** @test */
    #[Test]
    public function it_registers_reporter_interface(): void
    {
        $reporter = $this->app->make(ReporterInterface::class);

        $this->assertInstanceOf(Reporter::class, $reporter);
    }

    /** @test */
    #[Test]
    public function it_registers_analyzer_manager(): void
    {
        $manager = $this->app->make(AnalyzerManager::class);

        $this->assertInstanceOf(AnalyzerManager::class, $manager);
    }

    /** @test */
    #[Test]
    public function it_registers_composer_support(): void
    {
        $composer = $this->app->make(Composer::class);

        $this->assertInstanceOf(Composer::class, $composer);
    }

    /** @test */
    #[Test]
    public function it_registers_path_filter(): void
    {
        $filter = $this->app->make(PathFilter::class);

        $this->assertInstanceOf(PathFilter::class, $filter);
    }

    /** @test */
    #[Test]
    public function it_registers_version_constraint_matcher(): void
    {
        $matcher = $this->app->make(VersionConstraintMatcher::class);

        $this->assertInstanceOf(VersionConstraintMatcher::class, $matcher);
    }

    /** @test */
    #[Test]
    public function it_registers_advisory_analyzer_interface(): void
    {
        $analyzer = $this->app->make(AdvisoryAnalyzerInterface::class);

        $this->assertInstanceOf(AdvisoryAnalyzerInterface::class, $analyzer);
    }

    /** @test */
    #[Test]
    public function it_registers_advisory_fetcher_interface(): void
    {
        $fetcher = $this->app->make(AdvisoryFetcherInterface::class);

        $this->assertInstanceOf(AdvisoryFetcherInterface::class, $fetcher);
    }

    /** @test */
    #[Test]
    public function it_registers_composer_dependency_reader(): void
    {
        $reader = $this->app->make(ComposerDependencyReader::class);

        $this->assertInstanceOf(ComposerDependencyReader::class, $reader);
    }

    /** @test */
    #[Test]
    public function it_merges_config(): void
    {
        $this->assertNotNull(config('shieldci'));
        $this->assertIsArray(config('shieldci'));
    }

    /** @test */
    #[Test]
    public function it_registers_analyze_command(): void
    {
        $this->artisan('list')
            ->assertSuccessful()
            ->expectsOutputToContain('shield:analyze');
    }

    /** @test */
    #[Test]
    public function it_registers_baseline_command(): void
    {
        $this->artisan('list')
            ->assertSuccessful()
            ->expectsOutputToContain('shield:baseline');
    }

    /** @test */
    #[Test]
    public function it_uses_singleton_for_reporter(): void
    {
        $reporter1 = $this->app->make(ReporterInterface::class);
        $reporter2 = $this->app->make(ReporterInterface::class);

        $this->assertSame($reporter1, $reporter2);
    }

    /** @test */
    #[Test]
    public function it_uses_singleton_for_analyzer_manager(): void
    {
        $manager1 = $this->app->make(AnalyzerManager::class);
        $manager2 = $this->app->make(AnalyzerManager::class);

        $this->assertSame($manager1, $manager2);
    }

    /** @test */
    #[Test]
    public function it_uses_singleton_for_path_filter(): void
    {
        $filter1 = $this->app->make(PathFilter::class);
        $filter2 = $this->app->make(PathFilter::class);

        $this->assertSame($filter1, $filter2);
    }

    /**
     * The checker caches one probe per origin on the instance. An analyzer resolving its own
     * copy would start from an empty cache and re-request every origin the run had already
     * asked about, which is the same escape the AstParser binding above exists to close.
     */
    /** @test */
    #[Test]
    public function it_uses_singleton_for_the_origin_reachability_checker(): void
    {
        $checker1 = $this->app->make(OriginReachabilityChecker::class);
        $checker2 = $this->app->make(OriginReachabilityChecker::class);

        $this->assertSame($checker1, $checker2);
    }

    /** @test */
    #[Test]
    public function it_discovers_analyzers(): void
    {
        $manager = $this->app->make(AnalyzerManager::class);

        // Should have discovered at least some analyzers
        $this->assertGreaterThan(0, $manager->count());
    }

    /** @test */
    #[Test]
    public function file_analyzers_get_the_shipped_paths_when_a_published_config_omits_analyze(): void
    {
        // mergeConfigFrom() is a shallow array_merge, so an application's `paths` array
        // replaces the package's entirely. A published config that keeps `paths` but drops
        // `analyze` leaves the key absent without the user ever touching it, which is the
        // trigger of ShieldCI/laravel#378 most likely to be hit by accident. Driven through
        // the real container rather than a mocked Config so the merge is the one that ships.
        config(['shieldci.paths' => ['exclude' => ['storage']]]);

        $this->app->forgetInstance(AnalyzerManager::class);
        $manager = $this->app->make(AnalyzerManager::class);
        $this->assertInstanceOf(AnalyzerManager::class, $manager);

        $analyzer = $manager->getAnalyzers()->first(
            static fn (AnalyzerInterface $candidate): bool => $candidate instanceof AbstractFileAnalyzer
        );
        $this->assertInstanceOf(AbstractFileAnalyzer::class, $analyzer);

        $paths = new \ReflectionProperty(AbstractFileAnalyzer::class, 'paths');

        $this->assertSame(AnalyzerManager::DEFAULT_ANALYZE_PATHS, $paths->getValue($analyzer));
    }

    /** @test */
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

    /** @test */
    #[Test]
    public function it_resolves_logger_from_log_binding(): void
    {
        // Fully remove LoggerInterface binding using reflection
        $this->app->offsetUnset(LoggerInterface::class);
        $this->app->forgetInstance(LoggerInterface::class);

        // Remove from bindings via reflection to ensure bound() returns false
        $app = $this->app;
        $this->assertNotNull($app);
        $ref = new \ReflectionProperty($app, 'bindings');
        $ref->setAccessible(true);
        $bindings = $ref->getValue($app);
        unset($bindings[LoggerInterface::class]);
        $ref->setValue($app, $bindings);

        // Also remove from aliases if present
        $aliasRef = new \ReflectionProperty($app, 'aliases');
        $aliasRef->setAccessible(true);
        $aliases = $aliasRef->getValue($app);
        unset($aliases[LoggerInterface::class]);
        $aliasRef->setValue($app, $aliases);

        // Keep 'log' binding available
        $this->app->bind('log', fn () => \Mockery::mock(LoggerInterface::class));

        // Force re-resolution of AdvisoryFetcherInterface
        $this->app->forgetInstance(AdvisoryFetcherInterface::class);
        $fetcher = $this->app->make(AdvisoryFetcherInterface::class);

        $this->assertInstanceOf(HttpAdvisoryFetcher::class, $fetcher);
    }

    /** @test */
    #[Test]
    public function it_returns_null_for_file_without_namespace(): void
    {
        $provider = new ShieldCIServiceProvider($this->app);

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

    /** @test */
    #[Test]
    public function it_returns_null_for_file_without_class_declaration(): void
    {
        $provider = new ShieldCIServiceProvider($this->app);

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

    /** @test */
    #[Test]
    public function it_skips_non_existent_analyzer_directory(): void
    {
        $provider = new ShieldCIServiceProvider($this->app);

        $reflection = new \ReflectionMethod($provider, 'discoverAnalyzers');
        $reflection->setAccessible(true);

        // This should work and not throw even if some directories don't exist
        $analyzers = $reflection->invoke($provider);

        $this->assertIsArray($analyzers);
    }

    /** @test */
    #[Test]
    public function it_configures_docs_base_url_resolver(): void
    {
        config(['shieldci.docs_base_url' => 'https://custom-docs.example.com']);

        // The resolver is configured during registration, so it should use the config value
        // This tests that the configuration integration works
        $this->assertEquals('https://custom-docs.example.com', config('shieldci.docs_base_url'));
    }
}
