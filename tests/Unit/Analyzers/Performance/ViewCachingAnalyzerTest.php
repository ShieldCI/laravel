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
    private string $compiledPath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->compiledPath = sys_get_temp_dir().'/shieldci_compiled_'.uniqid();
        @mkdir($this->compiledPath, 0755, true);
    }

    protected function tearDown(): void
    {
        // Clean up compiled path
        if (is_dir($this->compiledPath)) {
            $files = glob($this->compiledPath.'/*.php');
            if (is_array($files)) {
                foreach ($files as $file) {
                    @unlink($file);
                }
            }
            @rmdir($this->compiledPath);
        }

        Mockery::close();
        parent::tearDown();
    }

    /**
     * @param  array<string, mixed>  $configValues
     * @param  array<string>  $viewPaths
     * @param  array<string, array<string>>  $viewHints
     * @param  array<string>|false|null  $globReturn
     */
    protected function createAnalyzer(
        array $configValues = [],
        array $viewPaths = [],
        array $viewHints = [],
        array|false|null $globReturn = null,
    ): AnalyzerInterface {
        /** @var Filesystem&\Mockery\MockInterface $files */
        $files = Mockery::mock(Filesystem::class);

        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        // Set up default config values
        $defaults = [
            'app' => [
                'env' => 'production',
            ],
            'view' => [
                'compiled' => $this->compiledPath,
            ],
            'shieldci' => [
                'environment_mapping' => [],
            ],
        ];

        $configMap = array_replace_recursive($defaults, $configValues);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) use ($configMap) {
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
        $configuredCompiledPath = $configMap['view']['compiled'] ?? $this->compiledPath;
        $compiledPathForGlob = is_string($configuredCompiledPath)
            ? $configuredCompiledPath
            : $this->compiledPath;

        // If globReturn not specified, use actual files from the directory
        if ($globReturn === null) {
            $actualFiles = glob($compiledPathForGlob.'/*.php');
            $globReturn = is_array($actualFiles) ? $actualFiles : [];
        }

        /** @phpstan-ignore-next-line */
        $files->allows('glob')
            ->with($compiledPathForGlob.'/*.php')
            ->andReturn($globReturn);

        // Mock view finder
        if (! empty($viewPaths) || ! empty($viewHints)) {
            $this->mockViewFinder($viewPaths, $viewHints);
        }

        return new ViewCachingAnalyzer($files, $config);
    }

    /**
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

        if ($this->app === null) {
            throw new \RuntimeException('Application not available in test');
        }

        $this->app->instance('view', $viewFactory);
    }

    /**
     * Create compiled view files with a specific timestamp.
     *
     * @return array<string>
     */
    private function createCompiledViews(int $count, int $timestamp): array
    {
        $files = [];
        for ($i = 1; $i <= $count; $i++) {
            $file = $this->compiledPath.'/compiled'.$i.'.php';
            file_put_contents($file, '<?php // compiled view');
            touch($file, $timestamp);
            $files[] = $file;
        }

        return $files;
    }

    public function test_passes_when_cache_is_fresh(): void
    {
        $bladeTime = time() - 3600; // Blade files modified 1 hour ago
        $compiledTime = time() - 1800; // Compiled files created 30 minutes ago (more recent)

        $tempDir = $this->createTempDirectory([
            'resources/views/welcome.blade.php' => '<html></html>',
            'resources/views/home.blade.php' => '<html></html>',
        ]);

        // Set blade files to older timestamp
        touch($tempDir.'/resources/views/welcome.blade.php', $bladeTime);
        touch($tempDir.'/resources/views/home.blade.php', $bladeTime);

        // Create compiled files with newer timestamp
        $compiledFiles = $this->createCompiledViews(2, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('fresh', $result->getMessage());
    }

    public function test_warns_when_cache_is_stale(): void
    {
        $compiledTime = time() - 3600; // Compiled files created 1 hour ago
        $bladeTime = time() - 1800; // Blade files modified 30 minutes ago (more recent)

        $tempDir = $this->createTempDirectory([
            'resources/views/welcome.blade.php' => '<html></html>',
        ]);

        // Set blade file to newer timestamp
        touch($tempDir.'/resources/views/welcome.blade.php', $bladeTime);

        // Create compiled files with older timestamp
        $compiledFiles = $this->createCompiledViews(2, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('stale', $result->getMessage());
    }

    public function test_warns_when_no_compiled_views_exist(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/welcome.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: [] // No compiled files
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('No compiled views found', $result);
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

    public function test_passes_when_no_blade_files_exist(): void
    {
        $tempDir = $this->createTempDirectory([]);

        // No compiled files needed - if there are no blade files, we don't need cache
        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: [] // No compiled files
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('No Blade templates found', $result->getMessage());
    }

    public function test_handles_multiple_view_paths(): void
    {
        $bladeTime = time() - 3600;
        $compiledTime = time() - 1800;

        $tempDir1 = $this->createTempDirectory([
            'views/main.blade.php' => '<html></html>',
        ]);
        touch($tempDir1.'/views/main.blade.php', $bladeTime);

        $tempDir2 = $this->createTempDirectory([
            'views/admin.blade.php' => '<html></html>',
        ]);
        touch($tempDir2.'/views/admin.blade.php', $bladeTime);

        $compiledFiles = $this->createCompiledViews(2, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir1.'/views', $tempDir2.'/views'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_package_views_by_default(): void
    {
        $appBladeTime = time() - 3600; // App views older
        $packageBladeTime = time() - 1800; // Package views newer (would trigger stale if included)
        $compiledTime = time() - 2400; // Between app and package times

        $tempDir = $this->createTempDirectory([
            'resources/views/app.blade.php' => '<html></html>',
            'vendor/package/views/package.blade.php' => '<html></html>',
        ]);

        touch($tempDir.'/resources/views/app.blade.php', $appBladeTime);
        touch($tempDir.'/vendor/package/views/package.blade.php', $packageBladeTime);

        $compiledFiles = $this->createCompiledViews(2, $compiledTime);

        // Default: package views excluded
        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: ['package' => [$tempDir.'/vendor/package/views']],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        // Should PASS because only app views are checked (older than compiled)
        $this->assertPassed($result);
    }

    public function test_includes_package_views_when_configured(): void
    {
        $appBladeTime = time() - 3600; // App views older
        $packageBladeTime = time() - 1800; // Package views newer
        $compiledTime = time() - 2400; // Between app and package times

        $tempDir = $this->createTempDirectory([
            'resources/views/app.blade.php' => '<html></html>',
            'vendor/package/views/package.blade.php' => '<html></html>',
        ]);

        touch($tempDir.'/resources/views/app.blade.php', $appBladeTime);
        touch($tempDir.'/vendor/package/views/package.blade.php', $packageBladeTime);

        $compiledFiles = $this->createCompiledViews(2, $compiledTime);

        // Explicitly include package views
        $analyzer = $this->createAnalyzer(
            configValues: [
                'shieldci' => [
                    'analyzers' => [
                        'performance' => [
                            'view-caching' => [
                                'include_package_views' => true,
                            ],
                        ],
                    ],
                ],
            ],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: ['package' => [$tempDir.'/vendor/package/views']],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        // Should be STALE because package views are included and newer than compiled
        $this->assertWarning($result);
        $this->assertStringContainsString('stale', $result->getMessage());
    }

    public function test_runs_in_staging_environment(): void
    {
        $bladeTime = time() - 3600;
        $compiledTime = time() - 1800;

        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);
        touch($tempDir.'/resources/views/page.blade.php', $bladeTime);

        $compiledFiles = $this->createCompiledViews(1, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [
                'app' => [
                    'env' => 'staging',
                ],
            ],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('staging', $result->getMessage());
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

    public function test_warn_when_compiled_directory_does_not_exist(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/example.blade.php' => '<html></html>',
        ]);

        // Remove the compiled path so it doesn't exist
        @rmdir($this->compiledPath);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: []
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('View cache has not been generated', $result->getMessage());
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
            globReturn: false
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('No compiled views found', $result);
    }

    public function test_handles_view_factory_exception_gracefully(): void
    {
        $compiledFiles = $this->createCompiledViews(1, time());

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_handles_empty_view_path_string(): void
    {
        $compiledFiles = $this->createCompiledViews(1, time());

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: ['', '   '],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        // No blade files found = passed
        $this->assertPassed($result);
    }

    public function test_handles_finder_exception_in_blade_files(): void
    {
        $compiledFiles = $this->createCompiledViews(1, time());

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: ['/this/path/definitely/does/not/exist/at/all'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_issue_metadata_includes_timestamps(): void
    {
        $compiledTime = time() - 3600;
        $bladeTime = time() - 1800;

        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);
        touch($tempDir.'/resources/views/page.blade.php', $bladeTime);

        $compiledFiles = $this->createCompiledViews(1, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertArrayHasKey('environment', $issue->metadata);
        $this->assertArrayHasKey('newest_blade_mtime', $issue->metadata);
        $this->assertArrayHasKey('newest_compiled_mtime', $issue->metadata);
        $this->assertArrayHasKey('stale_by_seconds', $issue->metadata);
        $this->assertArrayHasKey('cache_age_seconds', $issue->metadata);

        $this->assertEquals('production', $issue->metadata['environment']);
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
            globReturn: []
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('php artisan view:cache', $issues[0]->recommendation);
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
            globReturn: []
        );

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        foreach ($issues as $issue) {
            $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issue->severity);
        }
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
        $bladeTime = time() - 3600;
        $compiledTime = time() - 1800;

        $tempDir = $this->createTempDirectory([
            'resources/views/app.blade.php' => '<html></html>',
        ]);
        touch($tempDir.'/resources/views/app.blade.php', $bladeTime);

        $compiledFiles = $this->createCompiledViews(1, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: ['package' => []],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_mixed_valid_invalid_paths(): void
    {
        $bladeTime = time() - 3600;
        $compiledTime = time() - 1800;

        $tempDir = $this->createTempDirectory([
            'resources/views/valid.blade.php' => '<html></html>',
        ]);
        touch($tempDir.'/resources/views/valid.blade.php', $bladeTime);

        $compiledFiles = $this->createCompiledViews(1, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [
                '/totally/invalid/path',
                $tempDir.'/resources/views',
                '/another/invalid/path',
            ],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passed_message_includes_environment(): void
    {
        $bladeTime = time() - 3600;
        $compiledTime = time() - 1800;

        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);
        touch($tempDir.'/resources/views/page.blade.php', $bladeTime);

        $compiledFiles = $this->createCompiledViews(1, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [
                'app' => [
                    'env' => 'staging',
                ],
            ],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('staging', $result->getMessage());
    }

    public function test_published_vendor_views_are_included_in_scan(): void
    {
        $bladeTime = time() - 3600;
        $publishedViewTime = time() - 1800; // Published view modified more recently
        $compiledTime = time() - 2400; // Compiled before published view was modified

        $tempDir = $this->createTempDirectory([
            'resources/views/app.blade.php' => '<html></html>',
            'resources/views/vendor/package/view.blade.php' => '<html></html>',
        ]);

        touch($tempDir.'/resources/views/app.blade.php', $bladeTime);
        touch($tempDir.'/resources/views/vendor/package/view.blade.php', $publishedViewTime);

        $compiledFiles = $this->createCompiledViews(1, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        // Should be STALE because the published vendor view was modified after compilation
        $this->assertWarning($result);
        $this->assertStringContainsString('stale', $result->getMessage());
    }

    public function test_human_duration_formatting_seconds(): void
    {
        $compiledTime = time() - 100; // 100 seconds ago
        $bladeTime = time() - 50; // 50 seconds ago (50 seconds stale)

        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);
        touch($tempDir.'/resources/views/page.blade.php', $bladeTime);

        $compiledFiles = $this->createCompiledViews(1, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('seconds', $issues[0]->message);
    }

    public function test_human_duration_formatting_minutes(): void
    {
        $compiledTime = time() - 3600; // 1 hour ago
        $bladeTime = time() - 1800; // 30 minutes ago (30 minutes stale)

        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);
        touch($tempDir.'/resources/views/page.blade.php', $bladeTime);

        $compiledFiles = $this->createCompiledViews(1, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('minutes', $issues[0]->message);
    }

    public function test_human_duration_formatting_hours(): void
    {
        $compiledTime = time() - 86400; // 1 day ago
        $bladeTime = time() - 7200; // 2 hours ago (22 hours stale)

        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);
        touch($tempDir.'/resources/views/page.blade.php', $bladeTime);

        $compiledFiles = $this->createCompiledViews(1, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('hours', $issues[0]->message);
    }

    public function test_human_duration_formatting_days(): void
    {
        $compiledTime = time() - (86400 * 3); // 3 days ago
        $bladeTime = time() - 86400; // 1 day ago (2 days stale)

        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);
        touch($tempDir.'/resources/views/page.blade.php', $bladeTime);

        $compiledFiles = $this->createCompiledViews(1, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('days', $issues[0]->message);
    }

    public function test_stale_cache_metadata_includes_compiled_path_for_no_cache(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: []
        );

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertArrayHasKey('compiled_path', $issues[0]->metadata);
    }

    public function test_handles_non_existent_view_path(): void
    {
        $bladeTime = time() - 3600;
        $compiledTime = time() - 1800;

        $tempDir = $this->createTempDirectory([
            'resources/views/exists.blade.php' => '<html></html>',
        ]);
        touch($tempDir.'/resources/views/exists.blade.php', $bladeTime);

        $compiledFiles = $this->createCompiledViews(1, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [
                $tempDir.'/resources/views',
                $tempDir.'/resources/nonexistent',
            ],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_uses_newest_blade_timestamp_across_all_paths(): void
    {
        $oldBladeTime = time() - 7200; // 2 hours ago
        $newBladeTime = time() - 1800; // 30 minutes ago
        $compiledTime = time() - 3600; // 1 hour ago (stale because newBladeTime > compiledTime)

        $tempDir1 = $this->createTempDirectory([
            'views/old.blade.php' => '<html></html>',
        ]);
        touch($tempDir1.'/views/old.blade.php', $oldBladeTime);

        $tempDir2 = $this->createTempDirectory([
            'views/new.blade.php' => '<html></html>',
        ]);
        touch($tempDir2.'/views/new.blade.php', $newBladeTime);

        $compiledFiles = $this->createCompiledViews(2, $compiledTime);

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir1.'/views', $tempDir2.'/views'],
            viewHints: [],
            globReturn: $compiledFiles
        );

        $result = $analyzer->analyze();

        // Should be stale because the newest blade (30 min ago) is newer than compiled (1 hour ago)
        $this->assertWarning($result);
        $this->assertStringContainsString('stale', $result->getMessage());
    }

    public function test_uses_newest_compiled_timestamp(): void
    {
        $bladeTime = time() - 3600; // 1 hour ago

        $tempDir = $this->createTempDirectory([
            'resources/views/page.blade.php' => '<html></html>',
        ]);
        touch($tempDir.'/resources/views/page.blade.php', $bladeTime);

        // Create compiled files with different timestamps
        // One older than blade (stale orphan), one newer than blade (from view:cache)
        $compiledFile1 = $this->compiledPath.'/compiled1.php';
        $compiledFile2 = $this->compiledPath.'/compiled2.php';

        file_put_contents($compiledFile1, '<?php // compiled view');
        file_put_contents($compiledFile2, '<?php // compiled view');

        touch($compiledFile1, time() - 7200); // 2 hours ago (stale orphan)
        touch($compiledFile2, time() - 1800); // 30 minutes ago (newest - from view:cache)

        $analyzer = $this->createAnalyzer(
            configValues: [],
            viewPaths: [$tempDir.'/resources/views'],
            viewHints: [],
            globReturn: [$compiledFile1, $compiledFile2]
        );

        $result = $analyzer->analyze();

        // Should be FRESH because blade (1 hour ago) is OLDER than newest compiled (30 min ago)
        // The newest compiled timestamp represents when view:cache was last run
        $this->assertPassed($result);
    }
}
