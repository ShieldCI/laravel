<?php

declare(strict_types=1);

namespace ShieldCI;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Illuminate\Support\ServiceProvider;
use Psr\Log\LoggerInterface;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Commands\AnalyzeCommand;
use ShieldCI\Commands\BaselineCommand;
use ShieldCI\Contracts\ReporterInterface;
use ShieldCI\Support\Reporter;
use ShieldCI\Support\SecurityAdvisories\AdvisoryAnalyzer;
use ShieldCI\Support\SecurityAdvisories\AdvisoryAnalyzerInterface;
use ShieldCI\Support\SecurityAdvisories\AdvisoryFetcherInterface;
use ShieldCI\Support\SecurityAdvisories\ComposerDependencyReader;
use ShieldCI\Support\SecurityAdvisories\HttpAdvisoryFetcher;
use ShieldCI\Support\SecurityAdvisories\VersionConstraintMatcher;

class ShieldCIServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/shieldci.php',
            'shieldci'
        );

        // Configure documentation base URL resolver for AnalyzerMetadata
        // This allows auto-generation of docs URLs from category + analyzer ID
        AnalyzerMetadata::setDocsBaseUrlResolver(
            function (): string {
                /** @var \Illuminate\Contracts\Config\Repository $config */
                $config = $this->app->make('config');
                /** @var string $baseUrl */
                $baseUrl = $config->get('shieldci.docs_base_url', 'https://docs.shieldci.com');

                return $baseUrl;
            }
        );

        // Register bindings
        $this->app->singleton(ParserInterface::class, AstParser::class);
        $this->app->singleton(ReporterInterface::class, Reporter::class);
        $this->app->singleton(\ShieldCI\Contracts\ClientInterface::class, \ShieldCI\Http\Client\ShieldCIClient::class);

        // Register Composer with correct working path
        $this->app->singleton(\ShieldCI\Support\Composer::class, function ($app) {
            return new \ShieldCI\Support\Composer(
                $app['files'],
                $app->basePath()
            );
        });

        $this->app->bind(ClientInterface::class, Client::class);
        $this->app->singleton(VersionConstraintMatcher::class);
        $this->app->singleton(AdvisoryAnalyzerInterface::class, function ($app) {
            return new AdvisoryAnalyzer($app->make(VersionConstraintMatcher::class));
        });
        $this->app->singleton(AdvisoryFetcherInterface::class, function ($app) {
            $logger = null;
            if ($app->bound(LoggerInterface::class)) {
                $logger = $app->make(LoggerInterface::class);
            } elseif ($app->bound('log')) {
                $logger = $app->make('log');
            }

            $source = $app['config']->get('shieldci.security_advisories.source', HttpAdvisoryFetcher::DEFAULT_SOURCE);

            return new HttpAdvisoryFetcher(
                $app->make(ClientInterface::class),
                $logger,
                $source
            );
        });
        $this->app->singleton(ComposerDependencyReader::class);

        // Register path filter
        $this->app->singleton(\ShieldCI\Support\PathFilter::class, function ($app) {
            return new \ShieldCI\Support\PathFilter(
                $app['config']->get('shieldci.paths.analyze', []),
                $app['config']->get('shieldci.excluded_paths', [])
            );
        });

        // Register analyzer manager
        $this->app->singleton(AnalyzerManager::class, function ($app) {
            return new AnalyzerManager(
                $app->make('config'),
                $this->discoverAnalyzers(),
                $app
            );
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            // Publish config
            $this->publishes([
                __DIR__.'/../config/shieldci.php' => config_path('shieldci.php'),
            ], 'shieldci-config');

            // Register commands
            $this->commands([
                AnalyzeCommand::class,
                BaselineCommand::class,
            ]);
        }
    }

    /**
     * Discover all analyzer classes.
     */
    protected function discoverAnalyzers(): array
    {
        $analyzers = [];

        // Scan analyzer directories
        $directories = [
            __DIR__.'/Analyzers/Security',
            __DIR__.'/Analyzers/Performance',
            __DIR__.'/Analyzers/Reliability',
            __DIR__.'/Analyzers/CodeQuality',
            __DIR__.'/Analyzers/BestPractices',
        ];

        foreach ($directories as $directory) {
            if (! is_dir($directory)) {
                continue;
            }

            $files = glob($directory.'/*Analyzer.php');

            foreach ($files as $file) {
                $className = $this->getClassFromFile($file);

                if ($className && class_exists($className)) {
                    $analyzers[] = $className;
                }
            }
        }

        return $analyzers;
    }

    /**
     * Get class name from file path.
     */
    protected function getClassFromFile(string $file): ?string
    {
        $content = FileParser::readFile($file);

        if ($content === null || ! preg_match('/namespace\s+(.+?);/', $content, $namespaceMatch)) {
            return null;
        }

        // Match class declaration, ensuring it's not in a comment
        // Look for "class" at start of line (with optional whitespace) or after visibility modifier
        if (! preg_match('/^\s*(?:final\s+|abstract\s+)?class\s+(\w+)/m', $content, $classMatch)) {
            return null;
        }

        return $namespaceMatch[1].'\\'.$classMatch[1];
    }
}
