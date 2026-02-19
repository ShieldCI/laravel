<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Http\Client;

use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Contracts\ClientInterface;
use ShieldCI\Http\Client\ShieldCIClient;
use ShieldCI\Tests\TestCase;

class ShieldCIClientTest extends TestCase
{
    #[Test]
    public function it_implements_client_interface(): void
    {
        $client = new ShieldCIClient;

        $this->assertInstanceOf(ClientInterface::class, $client);
    }

    #[Test]
    public function it_reads_config_values_on_construction(): void
    {
        config([
            'shieldci.api_url' => 'https://custom-api.example.com/',
            'shieldci.token' => 'custom-token-123',
        ]);

        $client = new ShieldCIClient;

        // Verify by making a fake request and checking the URL/token
        Http::fake([
            'custom-api.example.com/*' => Http::response(['success' => true]),
        ]);

        $result = $client->verifyToken();

        Http::assertSent(function ($request) {
            return str_contains($request->url(), 'custom-api.example.com/api/v1/auth/verify')
                && $request->hasHeader('Authorization', 'Bearer custom-token-123');
        });

        $this->assertEquals(['success' => true], $result);
    }

    #[Test]
    public function it_trims_trailing_slash_from_base_url(): void
    {
        config(['shieldci.api_url' => 'https://api.example.com///']);

        $client = new ShieldCIClient;

        Http::fake(['api.example.com/*' => Http::response([])]);

        $client->verifyToken();

        Http::assertSent(function ($request) {
            return $request->url() === 'https://api.example.com/api/v1/auth/verify';
        });
    }

    #[Test]
    public function it_defaults_base_url_when_config_is_non_string(): void
    {
        config(['shieldci.api_url' => 12345]);

        $client = new ShieldCIClient;

        Http::fake(['api.shieldci.com/*' => Http::response([])]);

        $client->verifyToken();

        Http::assertSent(function ($request) {
            return str_contains($request->url(), 'api.shieldci.com');
        });
    }

    #[Test]
    public function it_defaults_token_when_config_is_non_string(): void
    {
        config(['shieldci.token' => 12345]);

        $client = new ShieldCIClient;

        Http::fake(['*' => Http::response(['ok' => true])]);

        $result = $client->verifyToken();

        // Should still work (empty token used as fallback)
        $this->assertEquals(['ok' => true], $result);
        Http::assertSentCount(1);
    }

    #[Test]
    public function send_report_posts_payload_to_reports_endpoint(): void
    {
        Http::fake([
            'api.test.shieldci.com/api/v1/reports' => Http::response([
                'success' => true,
                'id' => 'report-123',
            ]),
        ]);

        $client = new ShieldCIClient;
        $payload = ['project_id' => 'proj-1', 'score' => 85];

        $result = $client->sendReport($payload);

        $this->assertEquals(['success' => true, 'id' => 'report-123'], $result);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://api.test.shieldci.com/api/v1/reports'
                && $request->method() === 'POST'
                && $request['project_id'] === 'proj-1'
                && $request['score'] === 85;
        });
    }

    #[Test]
    public function send_report_returns_empty_array_on_null_json(): void
    {
        Http::fake([
            'api.test.shieldci.com/*' => Http::response('', 204),
        ]);

        $client = new ShieldCIClient;
        $result = $client->sendReport(['test' => true]);

        $this->assertEquals([], $result);
    }

    #[Test]
    public function verify_token_calls_auth_verify_endpoint(): void
    {
        Http::fake([
            'api.test.shieldci.com/api/v1/auth/verify' => Http::response([
                'valid' => true,
                'user' => 'test@example.com',
            ]),
        ]);

        $client = new ShieldCIClient;
        $result = $client->verifyToken();

        $this->assertEquals(['valid' => true, 'user' => 'test@example.com'], $result);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://api.test.shieldci.com/api/v1/auth/verify'
                && $request->method() === 'GET';
        });
    }

    #[Test]
    public function get_project_calls_projects_endpoint_with_id(): void
    {
        Http::fake([
            'api.test.shieldci.com/api/v1/projects/proj-456' => Http::response([
                'id' => 'proj-456',
                'name' => 'My Project',
            ]),
        ]);

        $client = new ShieldCIClient;
        $result = $client->getProject('proj-456');

        $this->assertEquals(['id' => 'proj-456', 'name' => 'My Project'], $result);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://api.test.shieldci.com/api/v1/projects/proj-456'
                && $request->method() === 'GET';
        });
    }

    #[Test]
    public function get_project_returns_empty_array_on_null_json(): void
    {
        Http::fake([
            'api.test.shieldci.com/*' => Http::response('', 204),
        ]);

        $client = new ShieldCIClient;
        $result = $client->getProject('proj-789');

        $this->assertEquals([], $result);
    }

    #[Test]
    public function send_report_includes_bearer_token(): void
    {
        Http::fake(['*' => Http::response([])]);

        $client = new ShieldCIClient;
        $client->sendReport(['data' => 'test']);

        Http::assertSent(function ($request) {
            return $request->hasHeader('Authorization', 'Bearer test-token');
        });
    }
}
