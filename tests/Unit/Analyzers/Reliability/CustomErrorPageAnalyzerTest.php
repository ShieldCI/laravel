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

    public function test_warns_when_required_templates_missing(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/welcome.blade.php' => '<html></html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Custom error pages not configured', $result);
        $this->assertWarning($result);
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

    public function test_skips_when_api_only_app_has_web_group_defined_but_unused(): void
    {
        // Register the 'web' group (containing StartSession) in the router,
        // but only register API routes that don't use it.
        // shouldRun() must return false — the group is defined but not assigned.
        $router = app(Router::class);
        $router->middlewareGroup('web', [\Illuminate\Session\Middleware\StartSession::class]);
        $router->get('/api/test', fn () => 'ok')->middleware('api');

        $analyzer = $this->createAnalyzer();
        // Do NOT use statelessOverride — exercise the real two-pass detection
        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_runs_when_app_has_own_web_route(): void
    {
        // If the app defines its own closure route using a session-containing group,
        // shouldRun() must return true — the app does serve HTML pages.
        $router = app(Router::class);
        $router->middlewareGroup('web', [\Illuminate\Session\Middleware\StartSession::class]);
        $router->get('/home', fn () => 'welcome')->middleware('web');

        $analyzer = $this->createAnalyzer();
        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_skips_when_only_vendor_routes_use_session_group(): void
    {
        // Simulate an API-only app that has a vendor package (e.g. Laravel Vapor)
        // injecting a web-group route. The 'web' group IS used, but only by vendor
        // infrastructure code — the app itself has no web routes.
        $router = app(Router::class);
        $router->middlewareGroup('web', [\Illuminate\Session\Middleware\StartSession::class]);

        // Use a real vendor class so isVendorRoute() correctly identifies it
        $router->post('/vendor/signed-url', [\Illuminate\Foundation\Auth\User::class, 'all'])
            ->middleware('web');

        // App's own routes use api only
        $router->post('/api/resource', fn () => response()->json([]))->middleware('api');

        $analyzer = $this->createAnalyzer();
        $this->assertFalse($analyzer->shouldRun());
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertHasIssueContaining('Custom error pages not configured', $result);
        $this->assertWarning($result);
    }

    public function test_handles_non_array_view_paths(): void
    {
        $tempDir = $this->createTempDirectory([]);

        config(['view.paths' => null]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertWarning($result);
    }

    public function test_handles_invalid_view_path(): void
    {
        config(['view.paths' => ['/non/existent/path']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Custom error pages not configured', $result);
        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
    }

    // =========================================================================
    // Config Override & Dynamic Recommendation Tests
    // =========================================================================

    public function test_respects_custom_required_templates_config(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/403.blade.php' => '<html>403</html>',
            'resources/views/errors/404.blade.php' => '<html>404</html>',
            'resources/views/errors/500.blade.php' => '<html>500</html>',
            'resources/views/errors/503.blade.php' => '<html>503</html>',
        ]);

        config([
            'view.paths' => [$tempDir.'/resources/views'],
            'shieldci.analyzers.reliability.custom-error-pages.required_templates' => [
                '403.blade.php',
                '404.blade.php',
                '500.blade.php',
                '503.blade.php',
            ],
        ]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $this->assertPassed($analyzer->analyze());
    }

    public function test_recommendation_lists_only_missing_templates(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/errors/404.blade.php' => '<html>404</html>',
        ]);

        config(['view.paths' => [$tempDir.'/resources/views']]);

        /** @var CustomErrorPageAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setStatelessOverride(false);
        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issue = $result->getIssues()[0];
        $recommendation = $issue->recommendation;

        $this->assertStringContainsString('401.blade.php', $recommendation);
        $this->assertStringContainsString('403.blade.php', $recommendation);
        $this->assertStringContainsString('419.blade.php', $recommendation);
        $this->assertStringContainsString('429.blade.php', $recommendation);
        $this->assertStringContainsString('500.blade.php', $recommendation);
        $this->assertStringContainsString('503.blade.php', $recommendation);
        $this->assertStringNotContainsString('404.blade.php', $recommendation);
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

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertNotNull($issues[0]->location);
        $this->assertStringContainsString('resources', $issues[0]->location->file);
        $this->assertStringContainsString('views', $issues[0]->location->file);
    }
}
