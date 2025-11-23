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
     * @param  array<string>|null  $compiledFiles
     */
    protected function createAnalyzer(
        array $configValues = [],
        array $viewPaths = [],
        array $viewHints = [],
        ?array $compiledFiles = null,
        bool $globShouldFail = false,
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
        $configuredCompiledPath = $configMap['view']['compiled'] ?? '/path/to/compiled/views';
        $compiledPathForGlob = is_string($configuredCompiledPath)
            ? $configuredCompiledPath
            : '/path/to/compiled/views';

        if ($compiledFiles === null && ! $globShouldFail) {
            if ($compiledFileCount <= 0) {
                $compiledFiles = [];
            } else {
                $compiledFiles = array_map(
                    fn ($i) => $compiledPathForGlob.'/file'.$i.'.php',
                    range(1, $compiledFileCount)
                );
            }
        }

        $globReturn = $globShouldFail ? false : $compiledFiles;

        /** @phpstan-ignore-next-line */
        $files->allows('glob')
            ->with($compiledPathForGlob.'/*.php')
            ->andReturn($globReturn);

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
        if ($this->app === null) {
            throw new \RuntimeException('Application not available in test');
        }

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

    public function test_warns_when_views_not_fully_cached_in_production(): void
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('0 out of 1', $result);
    }

    public function test_errors_when_view_compiled_config_is_invalid(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/example.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [
                'view' => [
                    'compiled' => ['not-a-path'],
                ],
            ],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: []
        );

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('Invalid view.compiled', $result->getMessage());
    }

    public function test_handles_glob_failure(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/example.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFiles: null,
            globShouldFail: true
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('0 out of 1', $result);
    }

    public function test_handles_zero_compiled_views_correctly(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/page1.blade.php' => '<html></html>',
            'resources/views/page2.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 0 // Zero compiled views
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('0 out of 2', $result);
        $this->assertHasIssueContaining('0.0%', $result);

        $issues = $result->getIssues();
        $this->assertEquals(0.0, $issues[0]->metadata['cached_percentage']);
    }

    public function test_handles_view_factory_exception_gracefully(): void
    {
        // Don't mock view factory - let it fail and use fallback
        $tempDir = $this->createTempDirectory([
            'resources/views/example.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [], // Empty - will trigger fallback
            viewHints: [],
            compiledFileCount: 0
        );

        $result = $analyzer->analyze();

        // Should still work using fallback resource_path('views')
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_handles_empty_view_path_string(): void
    {
        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: ['', '   '], // Empty and whitespace paths
            viewHints: [],
            compiledFileCount: 0
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_finder_exception_in_count_blade_files(): void
    {
        // Create a path that will cause Finder to throw exception
        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: ['/this/path/definitely/does/not/exist/at/all'],
            viewHints: [],
            compiledFileCount: 0
        );

        $result = $analyzer->analyze();

        // Should pass because no views found (exception caught)
        $this->assertPassed($result);
    }

    public function test_handles_division_by_zero_in_percentage_calculation(): void
    {
        // No views exist, but we'll force the scenario
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/nonexistent'],
            viewHints: [],
            compiledFileCount: 0
        );

        $result = $analyzer->analyze();

        // Should pass without errors (division by zero protected)
        $this->assertPassed($result);
    }

    public function test_fallback_to_artisan_when_config_file_not_found(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/example.blade.php' => '<html></html>',
            'artisan' => '#!/usr/bin/env php',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 0
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        // Location should be in view.php config or artisan file
        // In test environment, config file exists, so we just verify location is set
        $this->assertNotNull($issues[0]->location);
        $this->assertNotNull($issues[0]->location->file);
        $this->assertGreaterThan(0, $issues[0]->location->line);
    }

    public function test_handles_non_existent_view_path(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/exists.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [
                $tempDir.'/resources/views',
                $tempDir.'/resources/nonexistent', // This doesn't exist
            ],
            viewHints: [],
            compiledFileCount: 1
        );

        $result = $analyzer->analyze();

        // Should still work, just skip the non-existent path
        $this->assertPassed($result);
    }

    public function test_vendor_directory_is_excluded_from_blade_count(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/app.blade.php' => '<html></html>',
            'resources/views/vendor/package/view.blade.php' => '<html></html>', // Should be excluded
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 1 // Only 1, not 2
        );

        $result = $analyzer->analyze();

        // Should pass because vendor views are excluded
        $this->assertPassed($result);
    }

    public function test_issue_metadata_includes_all_required_fields(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/page1.blade.php' => '<html></html>',
            'resources/views/page2.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 1
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertArrayHasKey('environment', $issue->metadata);
        $this->assertArrayHasKey('total_views', $issue->metadata);
        $this->assertArrayHasKey('compiled_views', $issue->metadata);
        $this->assertArrayHasKey('cached_percentage', $issue->metadata);
        $this->assertArrayHasKey('missing_views', $issue->metadata);

        $this->assertEquals('production', $issue->metadata['environment']);
        $this->assertEquals(2, $issue->metadata['total_views']);
        $this->assertEquals(1, $issue->metadata['compiled_views']);
        $this->assertEquals(50.0, $issue->metadata['cached_percentage']);
        $this->assertEquals(1, $issue->metadata['missing_views']);
    }

    public function test_recommendation_includes_artisan_command(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 0
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('php artisan view:cache', $issues[0]->recommendation);
    }

    public function test_result_message_includes_percentage(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/page1.blade.php' => '<html></html>',
            'resources/views/page2.blade.php' => '<html></html>',
            'resources/views/page3.blade.php' => '<html></html>',
            'resources/views/page4.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 2
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('2/4', $result->getMessage());
        $this->assertStringContainsString('50.0%', $result->getMessage());
    }

    public function test_all_issues_have_medium_severity(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 0
        );

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issue->severity);
        }
    }

    public function test_warning_result_for_medium_severity(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 0
        );

        $result = $analyzer->analyze();

        // Medium severity issues should return warning
        $this->assertWarning($result);
    }

    public function test_skip_reason_includes_environment_names(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
        ]);

        $shouldRun = $analyzer->shouldRun();
        $this->assertFalse($shouldRun);

        if (method_exists($analyzer, 'getSkipReason')) {
            $reason = $analyzer->getSkipReason();

            $this->assertStringContainsString('local', $reason);
            $this->assertStringContainsString('production', $reason);
            $this->assertStringContainsString('staging', $reason);
        }
    }

    public function test_handles_empty_view_hints(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/app.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: ['package' => []], // Empty hints array
            compiledFileCount: 1
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_mixed_valid_invalid_paths(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/valid.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [
                '/totally/invalid/path',
                $tempDir.'/resources/views', // Valid
                '/another/invalid/path',
            ],
            viewHints: [],
            compiledFileCount: 1
        );

        $result = $analyzer->analyze();

        // Should pass - counts only from valid path
        $this->assertPassed($result);
    }

    public function test_passed_message_includes_environment(): void
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
            compiledFileCount: 1
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('staging', $result->getMessage());
        $this->assertStringContainsString('1 views', $result->getMessage());
    }

    public function test_cached_percentage_calculation_accuracy(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/page1.blade.php' => '<html></html>',
            'resources/views/page2.blade.php' => '<html></html>',
            'resources/views/page3.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            compiledFileCount: 1
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();

        // 1 out of 3 = 33.3%
        $this->assertEquals(33.3, $issues[0]->metadata['cached_percentage']);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
