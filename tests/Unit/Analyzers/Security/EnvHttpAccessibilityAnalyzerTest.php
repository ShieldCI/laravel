<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\URL;
use Psr\Http\Message\ResponseInterface;
use ShieldCI\Analyzers\Security\EnvHttpAccessibilityAnalyzer;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\Support\OriginReachability\DeclaredOrigin;
use ShieldCI\Support\OriginReachability\OriginReachabilityChecker;
use ShieldCI\Tests\AnalyzerTestCase;

class EnvHttpAccessibilityAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<ResponseInterface|\Exception>  $responses
     */
    protected function createAnalyzer(array $responses = []): EnvHttpAccessibilityAnalyzer
    {
        // HTTP checks only run in production/staging — default to production for these tests.
        // Individual tests can override app.env after calling this helper if needed.
        if (config('app.env') === 'testing') {
            config(['app.env' => 'production']);
        }

        // Force URL root to respect app.url config in tests
        // This is needed because Orchestra Testbench doesn't automatically
        // configure the URL generator from app.url
        $appUrl = config('app.url');
        if ($appUrl && is_string($appUrl)) {
            URL::forceRootUrl($appUrl);
        }

        /** @var Router $router */
        $router = $this->app?->make('router');

        // The analyzer no longer owns a client: it asks the shared origin checker, and the
        // checker is where a mock handler goes. Tests that queue no responses still get a
        // checker, so nothing reaches the network by accident.
        $mock = new MockHandler($responses);
        $client = new Client(['handler' => HandlerStack::create($mock)]);

        return new EnvHttpAccessibilityAnalyzer($router, new OriginReachabilityChecker($client));
    }

    public function test_skips_when_no_url_configured(): void
    {
        config(['app.url' => null]);
        config(['shieldci.guest_url' => null]);

        $analyzer = $this->createAnalyzer();

        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_skips_when_url_is_localhost(): void
    {
        config(['app.url' => 'http://localhost']);

        $analyzer = $this->createAnalyzer();

        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_skips_when_url_is_127_0_0_1(): void
    {
        config(['app.url' => 'http://127.0.0.1:8000']);

        $analyzer = $this->createAnalyzer();

        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_runs_when_valid_url_configured(): void
    {
        config(['app.url' => 'https://example.com']);

        $analyzer = $this->createAnalyzer();

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_passes_when_env_returns_404(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $responses = [
            new Response(404, [], 'Not Found'),
            new Response(404, [], 'Not Found'),
            new Response(404, [], 'Not Found'),
            new Response(404, [], 'Not Found'),
            new Response(404, [], 'Not Found'),
            new Response(404, [], 'Not Found'),
            new Response(404, [], 'Not Found'),
            new Response(404, [], 'Not Found'),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('not accessible via HTTP', $result->getMessage());
    }

    public function test_passes_when_env_returns_403(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $responses = [
            new Response(403, [], 'Forbidden'),
            new Response(403, [], 'Forbidden'),
            new Response(403, [], 'Forbidden'),
            new Response(403, [], 'Forbidden'),
            new Response(403, [], 'Forbidden'),
            new Response(403, [], 'Forbidden'),
            new Response(403, [], 'Forbidden'),
            new Response(403, [], 'Forbidden'),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_env_is_accessible_with_app_key(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:abcdefghijklmnopqrstuvwxyz1234567890
APP_DEBUG=false
ENV;

        $responses = [
            new Response(200, [], $envContent), // .env
            new Response(404), // ../env
            new Response(404), // ../../.env
            new Response(404), // ../../../.env
            new Response(404), // storage/.env
            new Response(404), // public/.env
            new Response(404), // app/.env
            new Response(404), // config/.env
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('publicly accessible', $result->getMessage());
        $this->assertNotEmpty($result->getIssues());

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('example.com/.env', $issue->message);
    }

    public function test_fails_when_env_is_accessible_with_database_credentials(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $envContent = <<<'ENV'
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_DATABASE=laravel
DB_USERNAME=root
DB_PASSWORD=secret
ENV;

        $responses = [
            new Response(200, [], $envContent),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertNotEmpty($result->getIssues());
    }

    public function test_critical_severity_for_public_directory(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $envContent = <<<'ENV'
APP_NAME=Laravel
APP_KEY=base64:test123
DB_HOST=localhost
ENV;

        $responses = [
            new Response(404), // .env
            new Response(404), // ../env
            new Response(404), // ../../.env
            new Response(404), // ../../../.env
            new Response(404), // storage/.env
            new Response(200, [], $envContent), // public/.env - CRITICAL!
            new Response(404), // app/.env
            new Response(404), // config/.env
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('public/.env', $issue->message);
        $this->assertEquals(Severity::Critical, $issue->severity);
        $this->assertStringContainsString('public directory', $issue->recommendation);
    }

    public function test_detects_parent_directory_traversal(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $envContent = <<<'ENV'
APP_NAME=Test
APP_ENV=production
APP_KEY=base64:secret
ENV;

        $responses = [
            new Response(404), // .env
            new Response(200, [], $envContent), // ../.env - parent directory
            new Response(404), // ../../.env
            new Response(404), // ../../../.env
            new Response(404), // storage/.env
            new Response(404), // public/.env
            new Response(404), // app/.env
            new Response(404), // config/.env
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('../.env', $issue->message);
    }

    public function test_handles_network_timeout_gracefully(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $responses = [
            new ConnectException(
                'Connection timed out',
                new Request('GET', 'https://example.com/.env')
            ),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        // A probe that never completed is not proof the file is absent. A .env wide open to
        // the internet must not read as green because the scanner could not reach the host.
        $this->assertNotSame(Status::Passed, $result->getStatus());
        $this->assertStringNotContainsString('properly configured', $result->getMessage());
        $this->assertStringContainsString('produced no response', $result->getMessage());
    }

    public function test_passes_when_response_doesnt_contain_env_indicators(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $htmlContent = <<<'HTML'
<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body><h1>Hello World</h1></body>
</html>
HTML;

        $responses = [
            new Response(200, [], $htmlContent),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_uses_guest_url_from_config(): void
    {
        config(['shieldci.guest_url' => 'https://staging.example.com']);
        config(['app.url' => 'http://localhost']);

        $analyzer = $this->createAnalyzer();

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_uses_custom_guest_path_from_config(): void
    {
        config(['app.url' => 'https://staging.example.com']);
        config(['shieldci.guest_url' => '/custom-page']);

        $analyzer = $this->createAnalyzer();

        // findLoginRoute() returns https://staging.example.com/custom-page
        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('env-http-accessibility', $metadata->id);
        $this->assertEquals('Environment File HTTP Accessibility Analyzer', $metadata->name);
        $this->assertEquals(Category::Security, $metadata->category);
        $this->assertEquals(Severity::Critical, $metadata->severity);
    }

    public function test_detects_multiple_accessible_locations(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $envContent = <<<'ENV'
APP_NAME=Test
APP_KEY=base64:test
DB_HOST=localhost
ENV;

        $responses = [
            new Response(200, [], $envContent), // .env - accessible!
            new Response(200, [], $envContent), // ../.env - accessible!
            new Response(404), // ../../.env
            new Response(404), // ../../../.env
            new Response(404), // storage/.env
            new Response(200, [], $envContent), // public/.env - accessible!
            new Response(404), // app/.env
            new Response(404), // config/.env
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(3, $result->getIssues());
        $this->assertStringContainsString('3 locations', $result->getMessage());
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(EnvHttpAccessibilityAnalyzer::$runInCI);
    }

    // ==================== extractBaseUrl() Tests ====================

    public function test_extract_base_url_with_standard_url(): void
    {
        config(['app.url' => 'https://example.com/login']);
        config(['shieldci.guest_url' => '/']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        // Use reflection to test private method
        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('extractBaseUrl');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, 'https://example.com/login');
        $this->assertEquals('https://example.com', $result);
    }

    public function test_extract_base_url_with_port(): void
    {
        config(['app.url' => 'https://example.com:8443/admin']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('extractBaseUrl');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, 'https://example.com:8443/admin');
        $this->assertEquals('https://example.com:8443', $result);
    }

    public function test_extract_base_url_with_http(): void
    {
        config(['app.url' => 'http://example.com']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('extractBaseUrl');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, 'http://example.com/path');
        $this->assertEquals('http://example.com', $result);
    }

    public function test_extract_base_url_with_malformed_url(): void
    {
        config(['app.url' => 'https://example.com']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('extractBaseUrl');
        $method->setAccessible(true);

        // Test with a truly malformed URL that parse_url will reject
        $result = $method->invoke($analyzer, 'http:///example');
        // parse_url returns false for severely malformed URLs, resulting in empty string
        $this->assertEquals('', $result);
    }

    public function test_extract_base_url_with_subdomain(): void
    {
        config(['app.url' => 'https://app.example.com']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('extractBaseUrl');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, 'https://app.example.com/dashboard');
        $this->assertEquals('https://app.example.com', $result);
    }

    // ==================== determineSeverity() Tests ====================

    public function test_determine_severity_critical_for_public_path(): void
    {
        config(['app.url' => 'https://example.com']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('determineSeverity');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, 'public/.env');
        $this->assertEquals(Severity::Critical, $result);
    }

    public function test_determine_severity_critical_for_root_env(): void
    {
        config(['app.url' => 'https://example.com']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('determineSeverity');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, '.env');
        $this->assertEquals(Severity::Critical, $result);
    }

    public function test_determine_severity_critical_for_parent_env(): void
    {
        config(['app.url' => 'https://example.com']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('determineSeverity');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, '../.env');
        $this->assertEquals(Severity::Critical, $result);
    }

    public function test_determine_severity_high_for_storage_path(): void
    {
        config(['app.url' => 'https://example.com']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('determineSeverity');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, 'storage/.env');
        $this->assertEquals(Severity::High, $result);
    }

    public function test_determine_severity_high_for_app_path(): void
    {
        config(['app.url' => 'https://example.com']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('determineSeverity');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, 'app/.env');
        $this->assertEquals(Severity::High, $result);
    }

    public function test_determine_severity_medium_for_deep_traversal(): void
    {
        config(['app.url' => 'https://example.com']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('determineSeverity');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, '../../.env');
        $this->assertEquals(Severity::Medium, $result);
    }

    // ==================== getRecommendation() Tests ====================

    public function test_get_recommendation_for_public_directory(): void
    {
        config(['app.url' => 'https://example.com']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('getRecommendation');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, 'public/.env');
        $this->assertIsString($result);
        $this->assertStringContainsString('public directory', $result);
        $this->assertStringContainsString('NEVER be in a publicly accessible directory', $result);
    }

    public function test_get_recommendation_for_root_env(): void
    {
        config(['app.url' => 'https://example.com']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('getRecommendation');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, '.env');
        $this->assertIsString($result);
        $this->assertStringContainsString('web server', $result);
        $this->assertStringContainsString('htaccess', $result);
    }

    public function test_get_recommendation_for_path_traversal(): void
    {
        config(['app.url' => 'https://example.com']);

        $responses = [new Response(404)];
        $analyzer = $this->createAnalyzer($responses);

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('getRecommendation');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, '../../.env');
        $this->assertIsString($result);
        $this->assertStringContainsString('directory traversal', $result);
        $this->assertStringContainsString('path traversal', $result);
    }

    // ==================== Edge Cases ====================

    public function test_detects_env_with_only_one_indicator_and_key_value_pattern(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $envContent = <<<'ENV'
APP_NAME=MyApp
SOME_KEY=some_value
ANOTHER_KEY=another_value
ENV;

        $responses = [
            new Response(200, [], $envContent),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        // Should detect due to KEY=VALUE pattern even with only 1 indicator
        $this->assertFailed($result);
    }

    public function test_passes_when_env_contains_zero_indicators(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $content = 'Random content without env indicators';

        $responses = [
            new Response(200, [], $content),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_includes_metadata_in_issues(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $envContent = <<<'ENV'
APP_NAME=Test
APP_KEY=base64:test
DB_HOST=localhost
ENV;

        $responses = [
            new Response(200, ['Server' => 'nginx/1.18'], $envContent),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issue = $result->getIssues()[0];

        $this->assertArrayHasKey('url', $issue->metadata);
        $this->assertArrayHasKey('path', $issue->metadata);
        $this->assertArrayHasKey('accessible', $issue->metadata);
        $this->assertArrayHasKey('indicators_found', $issue->metadata);
        $this->assertArrayHasKey('status_code', $issue->metadata);
        $this->assertArrayHasKey('response_size', $issue->metadata);
        $this->assertArrayHasKey('server_type', $issue->metadata);
        $this->assertEquals(200, $issue->metadata['status_code']);
        $this->assertEquals('nginx/1.18', $issue->metadata['server_type']);
    }

    public function test_avoids_duplicate_url_tests(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        // The eight .env candidates are eight distinct URLs, so nothing is deduplicated
        // within one run and eight responses are consumed. The previous version of this
        // test queued one response and passed only because the seven "mock queue is empty"
        // exceptions were swallowed by the same catch that hid every real network failure:
        // it asserted the defect, under a name that suggested otherwise.
        $responses = array_fill(0, 8, new Response(404));

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /** Asking the same path twice costs one request, because the shared checker caches it. */
    public function test_repeating_a_path_costs_one_request(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $origin = new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL]);
        $mock = new MockHandler([new Response(404)]);
        $checker = new OriginReachabilityChecker(new Client(['handler' => HandlerStack::create($mock)]));

        $checker->probe([$origin], null, [], '/.env');
        $checker->probe([$origin], null, [], '/.env');

        // A second request would empty the queue and throw, which the checker would report
        // as a transport failure rather than a 404.
        $probe = $checker->probe([$origin], null, [], '/.env')->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertSame(404, $probe->statusCode);
    }

    public function test_handles_empty_response_body(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $responses = [
            new Response(200, [], ''),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_response_without_server_header(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $envContent = <<<'ENV'
APP_NAME=Test
APP_KEY=base64:test
DB_HOST=localhost
ENV;

        $responses = [
            new Response(200, [], $envContent), // No Server header
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issue = $result->getIssues()[0];
        $this->assertNull($issue->metadata['server_type']);
    }

    public function test_detects_env_with_different_status_codes(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $responses = [
            new Response(301), // Redirect - not 200
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
            new Response(404),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        // Should pass since non-200 responses are considered blocked
        $this->assertPassed($result);
    }

    public function test_handles_exception_from_http_client(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $responses = [
            new \Exception('Network error'),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        // Same rule for a non-Guzzle throwable: an error is an absence of evidence, not
        // evidence of absence.
        $this->assertNotSame(Status::Passed, $result->getStatus());
        $this->assertStringNotContainsString('properly configured', $result->getMessage());
    }

    // ==================== Configuration Edge Cases ====================

    public function test_skips_with_empty_guest_url(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '']);

        $analyzer = $this->createAnalyzer();

        // Empty guest URL still uses app.url, so analyzer should run
        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_uses_app_url_when_guest_url_is_relative(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/dashboard']);

        $analyzer = $this->createAnalyzer();

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_get_skip_reason_when_no_url(): void
    {
        config(['app.url' => null]);
        config(['shieldci.guest_url' => null]);

        $analyzer = $this->createAnalyzer();

        $this->assertFalse($analyzer->shouldRun());
        $reason = $analyzer->getSkipReason();
        // With production env set, the env gate passes; findLoginRoute() falls back to url('/') which is localhost
        $this->assertStringContainsString('localhost', $reason);
    }

    public function test_get_skip_reason_for_localhost(): void
    {
        config(['app.url' => 'http://localhost']);

        $analyzer = $this->createAnalyzer();

        $reason = $analyzer->getSkipReason();
        $this->assertStringContainsString('localhost', $reason);
        $this->assertStringContainsString('local development', $reason);
    }

    public function test_skips_when_environment_is_local(): void
    {
        config(['app.url' => 'https://example.com']);
        $analyzer = $this->createAnalyzer();
        config(['app.env' => 'local']); // Override after helper sets 'production'

        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_skips_when_environment_is_testing(): void
    {
        config(['app.url' => 'https://example.com']);
        $analyzer = $this->createAnalyzer();
        config(['app.env' => 'testing']); // Override after helper sets 'production'

        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_get_skip_reason_for_non_production_environment(): void
    {
        config(['app.url' => 'https://example.com']);
        $analyzer = $this->createAnalyzer();
        config(['app.env' => 'local']); // Override after helper sets 'production'

        $reason = $analyzer->getSkipReason();
        $this->assertStringContainsString('production/staging', $reason);
        $this->assertStringContainsString('local', $reason);
    }

    /**
     * The case most easily missed: some paths answered and some did not. Seven clean 404s
     * alongside one refused connection is not the same as eight clean 404s, and the run may
     * not claim the web server is properly configured while a location went unchecked.
     */
    public function test_partial_answers_do_not_certify_the_locations_that_went_unchecked(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $request = new Request('GET', 'https://example.com/.env');
        $responses = array_fill(0, 7, new Response(404));
        $responses[] = new ConnectException('cURL error 7: Connection refused', $request);

        $result = $this->createAnalyzer($responses)->analyze();

        $this->assertNotSame(Status::Passed, $result->getStatus());
        $this->assertStringNotContainsString('properly configured', $result->getMessage());
        $this->assertStringContainsString('1 of 8', $result->getMessage());
    }

    /**
     * An exposed .env still fails even when other locations could not be checked, and the
     * summary says both things. Finding the file is the more urgent fact; the unchecked
     * locations must not be silently dropped from the report.
     */
    public function test_an_exposed_env_is_still_reported_when_other_locations_are_unchecked(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $envBody = "APP_NAME=Test\nAPP_KEY=base64:test\nDB_HOST=localhost";
        $request = new Request('GET', 'https://example.com/.env');

        $responses = [new Response(200, ['Server' => 'nginx/1.18'], $envBody)];
        $responses = array_merge($responses, array_fill(0, 7, new ConnectException('cURL error 28: timed out', $request)));

        $result = $this->createAnalyzer($responses)->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('publicly accessible at 1 location', $result->getMessage());
        $this->assertStringContainsString('7 further locations could not be checked', $result->getMessage());
    }

    /**
     * Certificate verification stays on.
     *
     * This analyzer used to set verify => false to tolerate self-signed certificates in
     * staging, but it runs in production too, and "the web server is properly configured"
     * asserted over a connection whose peer was never authenticated is a claim about a host
     * that was never identified. An untrusted certificate is now a transport failure
     * carrying no evidence, which is more than the pass it used to produce.
     */
    public function test_an_untrusted_certificate_is_not_a_clean_result(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);

        $request = new Request('GET', 'https://example.com/.env');
        $responses = array_fill(0, 8, new ConnectException(
            'cURL error 60: SSL certificate problem: self signed certificate',
            $request
        ));

        $result = $this->createAnalyzer($responses)->analyze();

        $this->assertNotSame(Status::Passed, $result->getStatus());
        $this->assertStringNotContainsString('properly configured', $result->getMessage());
    }
}
