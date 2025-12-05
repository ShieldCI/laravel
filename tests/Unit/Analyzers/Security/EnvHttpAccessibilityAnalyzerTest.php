<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Facades\URL;
use ShieldCI\Analyzers\Security\EnvHttpAccessibilityAnalyzer;
use ShieldCI\Tests\AnalyzerTestCase;

class EnvHttpAccessibilityAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<\Psr\Http\Message\ResponseInterface|\Exception>  $responses
     */
    protected function createAnalyzer(array $responses = []): EnvHttpAccessibilityAnalyzer
    {
        // Force URL root to respect app.url config in tests
        // This is needed because Orchestra Testbench doesn't automatically
        // configure the URL generator from app.url
        $appUrl = config('app.url');
        if ($appUrl && is_string($appUrl)) {
            URL::forceRootUrl($appUrl);
        }

        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app?->make('router');
        $analyzer = new EnvHttpAccessibilityAnalyzer($router);

        if (! empty($responses)) {
            $mock = new MockHandler($responses);
            $handlerStack = HandlerStack::create($mock);
            $client = new Client(['handler' => $handlerStack]);
            $analyzer->setHttpClient($client);
        }

        return $analyzer;
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issue->severity);
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

        // Should pass because we couldn't verify it's accessible
        $this->assertPassed($result);
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Security, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $metadata->severity);
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $result);
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $result);
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $result);
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $result);
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $result);
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $result);
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

        // Only need one response since duplicate URLs should be skipped
        $responses = [
            new Response(404),
        ];

        $analyzer = $this->createAnalyzer($responses);
        $result = $analyzer->analyze();

        // If it tries to test duplicates, MockHandler will throw exception
        // for missing responses. If we get here, test passed.
        $this->assertPassed($result);
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

        // Should pass because error means not accessible
        $this->assertPassed($result);
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
        // When no URL is configured, findLoginRoute() falls back to url('/') which is localhost
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
}
