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
        $this->assertEquals('Environment File HTTP Accessibility Check', $metadata->name);
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
        $this->assertStringContainsString('3 location(s)', $result->getMessage());
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(EnvHttpAccessibilityAnalyzer::$runInCI);
    }
}
