<?php

declare(strict_types=1);

namespace ShieldCI;

use Illuminate\Support\ServiceProvider;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Commands\AnalyzeCommand;
use ShieldCI\Commands\BaselineCommand;
use ShieldCI\Contracts\ReporterInterface;
use ShieldCI\Support\Reporter;

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

        // Register bindings
        $this->app->singleton(ParserInterface::class, AstParser::class);
        $this->app->singleton(ReporterInterface::class, Reporter::class);

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
        $content = file_get_contents($file);

        if (! preg_match('/namespace\s+(.+?);/', $content, $namespaceMatch)) {
            return null;
        }

        if (! preg_match('/class\s+(\w+)/', $content, $classMatch)) {
            return null;
        }

        return $namespaceMatch[1].'\\'.$classMatch[1];
    }
}
