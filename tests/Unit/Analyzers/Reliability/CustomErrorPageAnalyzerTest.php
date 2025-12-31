<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\View;
use ShieldCI\Analyzers\Reliability\CustomErrorPageAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CustomErrorPageAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        $router = app(Router::class);
        $kernel = app(Kernel::class);
        $files = new Filesystem;

        return new CustomErrorPageAnalyzer($router, $kernel, $files);
    }

    public function test_fails_when_required_templates_missing(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/welcome.blade.php' => '<html></html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Custom error pages not configured', $result);
    }

    public function test_passes_with_custom_error_pages(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/401.blade.php' => '<html>401</html>',
            'resources/views/errors/403.blade.php' => '<html>403</html>',
            'resources/views/errors/404.blade.php' => '<html>404</html>',
            'resources/views/errors/419.blade.php' => '<html>419</html>',
            'resources/views/errors/429.blade.php' => '<html>429</html>',
            'resources/views/errors/500.blade.php' => '<html>500</html>',
            'resources/views/errors/503.blade.php' => '<html>503</html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_error_namespace_is_used(): void
    {
        $tempDir = $this->createTempDirectory([
            'custom/errors/401.blade.php' => '<html>401</html>',
            'custom/errors/403.blade.php' => '<html>403</html>',
            'custom/errors/404.blade.php' => '<html>404</html>',
            'custom/errors/419.blade.php' => '<html>419</html>',
            'custom/errors/429.blade.php' => '<html>429</html>',
            'custom/errors/500.blade.php' => '<html>500</html>',
            'custom/errors/503.blade.php' => '<html>503</html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);
        View::addNamespace('errors', $tempDir.'/custom/errors');

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skip_reason_for_stateless_apps(): void
    {
        $analyzer = $this->createAnalyzer();

        // Test environment is stateless (no session middleware)
        $this->assertFalse($analyzer->shouldRun());

        if (method_exists($analyzer, 'getSkipReason')) {
            $this->assertStringContainsString('stateless', $analyzer->getSkipReason());
        }
    }

    // =========================================================================
    // Partial Template Coverage Tests
    // =========================================================================

    public function test_fails_when_only_404_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/404.blade.php' => '<html>404</html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('401.blade.php', $result);
        $this->assertHasIssueContaining('403.blade.php', $result);
        $this->assertHasIssueContaining('419.blade.php', $result);
        $this->assertHasIssueContaining('429.blade.php', $result);
        $this->assertHasIssueContaining('500.blade.php', $result);
        $this->assertHasIssueContaining('503.blade.php', $result);
    }

    public function test_fails_when_only_500_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/500.blade.php' => '<html>500</html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('401.blade.php', $result);
        $this->assertHasIssueContaining('403.blade.php', $result);
        $this->assertHasIssueContaining('404.blade.php', $result);
        $this->assertHasIssueContaining('419.blade.php', $result);
        $this->assertHasIssueContaining('429.blade.php', $result);
        $this->assertHasIssueContaining('503.blade.php', $result);
    }

    public function test_fails_when_only_503_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/503.blade.php' => '<html>503</html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('401.blade.php', $result);
        $this->assertHasIssueContaining('403.blade.php', $result);
        $this->assertHasIssueContaining('404.blade.php', $result);
        $this->assertHasIssueContaining('419.blade.php', $result);
        $this->assertHasIssueContaining('429.blade.php', $result);
        $this->assertHasIssueContaining('500.blade.php', $result);
    }

    public function test_fails_when_only_some_templates_exist(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/404.blade.php' => '<html>404</html>',
            'resources/views/errors/500.blade.php' => '<html>500</html>',
            'resources/views/errors/503.blade.php' => '<html>503</html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('401.blade.php', $result);
        $this->assertHasIssueContaining('403.blade.php', $result);
        $this->assertHasIssueContaining('419.blade.php', $result);
        $this->assertHasIssueContaining('429.blade.php', $result);
    }

    // =========================================================================
    // Edge Case Validation Tests
    // =========================================================================

    public function test_handles_empty_view_paths(): void
    {
        $tempDir = $this->createTempDirectory([]);

        config(['view.paths' => []]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Custom error pages not configured', $result);
    }

    public function test_handles_non_array_view_paths(): void
    {
        $tempDir = $this->createTempDirectory([]);

        config(['view.paths' => null]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_handles_invalid_view_path(): void
    {
        config(['view.paths' => ['/non/existent/path']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Custom error pages not configured', $result);
    }

    public function test_checks_multiple_view_paths(): void
    {
        $tempDir1 = $this->createTempDirectory([
            'views1/errors/401.blade.php' => '<html>401</html>',
            'views1/errors/403.blade.php' => '<html>403</html>',
            'views1/errors/404.blade.php' => '<html>404</html>',
            'views1/errors/419.blade.php' => '<html>419</html>',
        ]);

        $tempDir2 = $this->createTempDirectory([
            'views2/errors/429.blade.php' => '<html>429</html>',
            'views2/errors/500.blade.php' => '<html>500</html>',
            'views2/errors/503.blade.php' => '<html>503</html>',
        ]);

        config(['view.paths' => [$tempDir1.'/views1', $tempDir2.'/views2']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        // Should pass because all templates exist across different paths
        $this->assertPassed($result);
    }

    // =========================================================================
    // Metadata Validation Tests
    // =========================================================================

    public function test_includes_missing_templates_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/404.blade.php' => '<html>404</html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertArrayHasKey('missing_templates', $issues[0]->metadata);
        $missingTemplates = $issues[0]->metadata['missing_templates'];
        $this->assertIsArray($missingTemplates);
        $this->assertContains('401.blade.php', $missingTemplates);
        $this->assertContains('403.blade.php', $missingTemplates);
        $this->assertContains('419.blade.php', $missingTemplates);
        $this->assertContains('429.blade.php', $missingTemplates);
        $this->assertContains('500.blade.php', $missingTemplates);
        $this->assertContains('503.blade.php', $missingTemplates);
        $this->assertNotContains('404.blade.php', $missingTemplates);
    }

    public function test_includes_view_paths_checked_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertArrayHasKey('view_paths_checked', $issues[0]->metadata);
        $this->assertIsArray($issues[0]->metadata['view_paths_checked']);
    }

    // =========================================================================
    // Namespace Hint Edge Cases
    // =========================================================================

    public function test_handles_multiple_namespace_hints(): void
    {
        $tempDir1 = $this->createTempDirectory([
            'custom1/401.blade.php' => '<html>401</html>',
            'custom1/403.blade.php' => '<html>403</html>',
            'custom1/404.blade.php' => '<html>404</html>',
            'custom1/419.blade.php' => '<html>419</html>',
        ]);

        $tempDir2 = $this->createTempDirectory([
            'custom2/429.blade.php' => '<html>429</html>',
            'custom2/500.blade.php' => '<html>500</html>',
            'custom2/503.blade.php' => '<html>503</html>',
        ]);

        config(['view.paths' => []]);
        View::addNamespace('errors', [$tempDir1.'/custom1', $tempDir2.'/custom2']);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        // Should pass because all templates exist across different namespace hints
        $this->assertPassed($result);
    }

    public function test_handles_namespace_hints_with_non_existent_paths(): void
    {
        config(['view.paths' => []]);
        View::addNamespace('errors', ['/non/existent/path']);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    // =========================================================================
    // Location Validation Tests
    // =========================================================================

    public function test_location_points_to_resources_views_directory(): void
    {
        $tempDir = $this->createTempDirectory([]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('resources', $issues[0]->location->file);
        $this->assertStringContainsString('views', $issues[0]->location->file);
    }
}
