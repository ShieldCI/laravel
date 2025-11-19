<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Filesystem\Filesystem;
use Illuminate\View\Factory as ViewFactory;
use Illuminate\View\FileViewFinder;
use Mockery;
use ShieldCI\Analyzers\Performance\ViewCachingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ViewCachingAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $configValues
     * @param  array<string>  $viewPaths
     * @param  array<string, array<string>>  $viewHints
     */
    protected function createAnalyzer(
        array $configValues = [],
        array $viewPaths = [],
        array $viewHints = [],
        int $compiledFileCount = 10
    ): AnalyzerInterface {
        /** @var Filesystem&\Mockery\MockInterface $files */
        $files = Mockery::mock(Filesystem::class);

        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        // Set up default config values
        $defaults = [
            'app' => [
                'env' => 'production', // Default to production so tests actually run
            ],
            'view' => [
                'compiled' => '/path/to/compiled/views',
            ],
            'shieldci' => [
                'environment_mapping' => [],
            ],
        ];

        $configMap = array_replace_recursive($defaults, $configValues);

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) use ($configMap) {
                // Handle dotted key access (e.g., 'view.compiled', 'app.env')
                $keys = explode('.', $key);
                $value = $configMap;

                foreach ($keys as $segment) {
                    if (is_array($value) && array_key_exists($segment, $value)) {
                        $value = $value[$segment];
                    } else {
                        return $default;
                    }
                }

                return $value ?? $default;
            });

        // Mock filesystem glob for compiled views
        $compiledPath = $configMap['view']['compiled'] ?? '/path/to/compiled/views';
        $compiledFiles = array_fill(0, $compiledFileCount, $compiledPath.'/file.php');
        /** @phpstan-ignore-next-line */
        $files->shouldReceive('glob')
            ->with($compiledPath.'/*')
            ->andReturn($compiledFiles);

        // Mock view finder for counting blade files
        if (! empty($viewPaths) || ! empty($viewHints)) {
            $this->mockViewFinder($viewPaths, $viewHints);
        }

        return new ViewCachingAnalyzer($files, $config);
    }

    /**
     * Mock Laravel's view finder.
     *
     * @param  array<string>  $paths
     * @param  array<string, array<string>>  $hints
     */
    private function mockViewFinder(array $paths, array $hints): void
    {
        $finder = Mockery::mock(FileViewFinder::class);

        $finder->shouldReceive('getPaths')
            ->andReturn($paths);

        $finder->shouldReceive('getHints')
            ->andReturn($hints);

        $viewFactory = Mockery::mock(ViewFactory::class);
        $viewFactory->shouldReceive('getFinder')
            ->andReturn($finder);

        // Mock app('view') to return our mock view factory
        $this->app->instance('view', $viewFactory);
    }

    public function test_passes_when_all_views_cached_in_production(): void
    {
        // Create a temp directory with blade files
        $tempDir = $this->createTempDirectory([
            'resources/views/welcome.blade.php' => '<html></html>',
            'resources/views/home.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 2
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_views_not_fully_cached_in_production(): void
    {
        // Create a temp directory with blade files
        $tempDir = $this->createTempDirectory([
            'resources/views/welcome.blade.php' => '<html></html>',
            'resources/views/home.blade.php' => '<html></html>',
            'resources/views/about.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 1  // Only 1 out of 3 views compiled
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('1 out of 3', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(3, $issues[0]->metadata['total_views'] ?? 0);
        $this->assertEquals(1, $issues[0]->metadata['compiled_views'] ?? 0);
        $this->assertEquals(2, $issues[0]->metadata['missing_views'] ?? 0);
    }

    public function test_skips_in_local_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_passes_when_no_views_exist(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 0
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_partial_caching(): void
    {
        // Create a temp directory with blade files
        $tempDir = $this->createTempDirectory([
            'resources/views/page1.blade.php' => '<html></html>',
            'resources/views/page2.blade.php' => '<html></html>',
            'resources/views/page3.blade.php' => '<html></html>',
            'resources/views/page4.blade.php' => '<html></html>',
            'resources/views/page5.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 3  // 60% cached
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('3 out of 5', $result);
        $this->assertHasIssueContaining('60.0%', $result);
    }

    public function test_handles_multiple_view_paths(): void
    {
        // Create temp directories for multiple view paths
        $tempDir1 = $this->createTempDirectory([
            'views/main.blade.php' => '<html></html>',
        ]);

        $tempDir2 = $this->createTempDirectory([
            'views/admin.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir1.'/views', $tempDir2.'/views'],
            viewHints: [],
            compiledFileCount: 2
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_package_view_hints(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/app.blade.php' => '<html></html>',
            'vendor/package/views/package.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: ['package' => [$tempDir.'/vendor/package/views']],
            compiledFileCount: 2
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_in_staging_environment(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [
                'app' => [
                    'env' => 'staging',
                ],
            ],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 0
        );

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('0 out of 1', $result);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
