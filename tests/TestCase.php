<?php

declare(strict_types=1);

namespace ShieldCI\Tests;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Support\Collection;
use Orchestra\Testbench\TestCase as Orchestra;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\ShieldCIServiceProvider;
use ShieldCI\Tests\Concerns\CreatesTemporaryPaths;

abstract class TestCase extends Orchestra
{
    use CreatesTemporaryPaths;

    protected function setUp(): void
    {
        parent::setUp();
    }

    /**
     * Collection is invariant in its value type, so collect([AnalysisResult, ...]) infers
     * Collection<int, AnalysisResult> and is rejected where Collection<int, ResultInterface>
     * is declared. Widening once here beats annotating every call site.
     *
     * @return Collection<int, ResultInterface>
     */
    protected function resultsOf(ResultInterface ...$results): Collection
    {
        return (new Collection($results))->values();
    }

    protected function getPackageProviders($app): array
    {
        return [
            ShieldCIServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        // Setup test configuration
        /** @var Config $config */
        $config = $app->make('config');
        $config->set('shieldci.enabled', true);
        $config->set('shieldci.token', 'test-token');
        $config->set('shieldci.project_id', 'test-project-id');
        $config->set('shieldci.api_url', 'https://api.test.shieldci.com');
    }

    /**
     * Create a uniquely named temporary directory, removed when the test finishes.
     */
    protected function makeTempDirectory(string $prefix = 'shieldci_test_'): string
    {
        $dir = $this->uniqueTempPath($prefix);

        // No is_dir() fallback: the path carries this process id and eight random bytes,
        // so it cannot already exist, and treating "it is there already" as success would
        // hand two tests the same fixture directory. The @ is load-bearing rather than
        // lazy: Testbench bootstraps HandleExceptions, which rethrows any reported
        // warning as an ErrorException, so without it mkdir() never returns and the
        // failure surfaces as an unrelated-looking exception instead of this message.
        if (! @mkdir($dir, 0755, true)) {
            throw new \RuntimeException(
                "Unable to create temporary test directory {$dir}: {$this->lastErrorMessage()}"
            );
        }

        $this->beforeApplicationDestroyed(function () use ($dir): void {
            $this->removeDirectory($dir);
        });

        return $dir;
    }

    /**
     * Get test fixture path.
     */
    protected function getFixturePath(string $path = ''): string
    {
        return __DIR__.'/Fixtures/'.ltrim($path, '/');
    }

    /**
     * Get test stub file path.
     */
    protected function getStubPath(string $path = ''): string
    {
        return __DIR__.'/Stubs/'.ltrim($path, '/');
    }
}
