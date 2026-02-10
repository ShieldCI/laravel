<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Support\PathFilter;
use ShieldCI\Tests\TestCase;

class PathFilterTest extends TestCase
{
    #[Test]
    public function it_allows_paths_in_analyze_paths(): void
    {
        $filter = new PathFilter(['app', 'routes'], []);

        $this->assertTrue($filter->shouldAnalyze(base_path('app/Http/Controllers/HomeController.php')));
        $this->assertTrue($filter->shouldAnalyze(base_path('routes/web.php')));
    }

    #[Test]
    public function it_rejects_paths_not_in_analyze_paths(): void
    {
        $filter = new PathFilter(['app'], []);

        $this->assertFalse($filter->shouldAnalyze(base_path('config/app.php')));
        $this->assertFalse($filter->shouldAnalyze(base_path('database/migrations/test.php')));
    }

    #[Test]
    public function it_excludes_paths_matching_exclusion_patterns(): void
    {
        $filter = new PathFilter(['app'], ['vendor', 'node_modules']);

        $this->assertFalse($filter->shouldAnalyze(base_path('vendor/laravel/framework/src/Test.php')));
        $this->assertFalse($filter->shouldAnalyze(base_path('node_modules/package/index.js')));
    }

    #[Test]
    public function it_allows_all_paths_when_analyze_paths_is_empty(): void
    {
        $filter = new PathFilter([], []);

        $this->assertTrue($filter->shouldAnalyze(base_path('app/Test.php')));
        $this->assertTrue($filter->shouldAnalyze(base_path('config/app.php')));
        $this->assertTrue($filter->shouldAnalyze(base_path('routes/web.php')));
    }

    #[Test]
    public function it_prioritizes_exclusions_over_inclusions(): void
    {
        // The exclusion pattern must match the full path, not just start with it
        $filter = new PathFilter(['app'], ['app/Exceptions.*']);

        $this->assertTrue($filter->shouldAnalyze(base_path('app/Http/Controller.php')));
        $this->assertFalse($filter->shouldAnalyze(base_path('app/Exceptions/Handler.php')));
    }

    #[Test]
    public function it_handles_glob_wildcard_patterns(): void
    {
        $filter = new PathFilter(['app'], ['*.log', 'storage/*']);

        $this->assertTrue($filter->shouldAnalyze(base_path('app/Test.php')));
        $this->assertFalse($filter->shouldAnalyze(base_path('app/debug.log')));
    }

    #[Test]
    public function it_normalizes_windows_path_separators(): void
    {
        $filter = new PathFilter(['app'], []);

        // Even with backslashes, paths should be normalized and matched
        $this->assertTrue($filter->shouldAnalyze(base_path('app\\Http\\Controllers\\HomeController.php')));
    }

    #[Test]
    public function it_handles_exact_path_matches(): void
    {
        $filter = new PathFilter(['app'], []);

        $this->assertTrue($filter->shouldAnalyze(base_path('app')));
    }

    #[Test]
    public function it_handles_relative_paths(): void
    {
        $filter = new PathFilter(['app', 'routes'], []);

        $this->assertTrue($filter->shouldAnalyze('app/Models/User.php'));
        $this->assertTrue($filter->shouldAnalyze('routes/api.php'));
        $this->assertFalse($filter->shouldAnalyze('vendor/test.php'));
    }

    #[Test]
    public function it_returns_analyze_paths(): void
    {
        $paths = ['app', 'routes', 'resources'];
        $filter = new PathFilter($paths, []);

        $this->assertEquals($paths, $filter->getAnalyzePaths());
    }

    #[Test]
    public function it_returns_excluded_paths(): void
    {
        $excluded = ['vendor', 'node_modules', 'storage'];
        $filter = new PathFilter([], $excluded);

        $this->assertEquals($excluded, $filter->getExcludedPaths());
    }

    #[Test]
    public function it_handles_complex_glob_patterns(): void
    {
        $filter = new PathFilter(['app'], ['tests/*', '*.test.php', 'app/Temp/*']);

        $this->assertTrue($filter->shouldAnalyze(base_path('app/Models/User.php')));
        $this->assertFalse($filter->shouldAnalyze(base_path('tests/Unit/ExampleTest.php')));
        $this->assertFalse($filter->shouldAnalyze(base_path('app/Example.test.php')));
    }

    #[Test]
    public function it_is_case_insensitive_for_pattern_matching(): void
    {
        // Case-insensitive matching: Vendor matches vendor, TESTS matches tests
        // But the pattern must match as a prefix in analyze paths
        $filter = new PathFilter([], ['Vendor*', 'TESTS*']);

        $this->assertFalse($filter->shouldAnalyze('vendor/test.php'));
        $this->assertFalse($filter->shouldAnalyze('tests/Unit/Test.php'));
    }

    #[Test]
    public function it_handles_nested_directory_paths(): void
    {
        $filter = new PathFilter(['app/Http/Controllers'], []);

        $this->assertTrue($filter->shouldAnalyze('app/Http/Controllers/Admin/DashboardController.php'));
        $this->assertFalse($filter->shouldAnalyze('app/Http/Middleware/Auth.php'));
        $this->assertFalse($filter->shouldAnalyze('app/Models/User.php'));
    }

    #[Test]
    public function it_handles_paths_with_trailing_slashes(): void
    {
        $filter = new PathFilter(['app/', 'routes/'], []);

        $this->assertTrue($filter->shouldAnalyze('app/Test.php'));
        $this->assertTrue($filter->shouldAnalyze('routes/web.php'));
    }
}
