<?php

declare(strict_types=1);

namespace ShieldCI\Http\Client;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use ShieldCI\Contracts\ClientInterface;

/**
 * HTTP client for communicating with the ShieldCI platform API.
 */
class ShieldCIClient implements ClientInterface
{
    private string $baseUrl;

    private string $token;

    public function __construct()
    {
        $configUrl = config('shieldci.api_url', 'https://api.shieldci.com');
        $this->baseUrl = is_string($configUrl) ? rtrim($configUrl, '/') : 'https://api.shieldci.com';

        $configToken = config('shieldci.token', '');
        $this->token = is_string($configToken) ? $configToken : '';
    }

    /**
     * Send an analysis report to the ShieldCI platform.
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     *
     * @throws ConnectionException
     */
    public function sendReport(array $payload): array
    {
        $response = Http::withToken($this->token)
            ->timeout(30)
            ->post("{$this->baseUrl}/api/v1/reports", $payload);

        /** @var array<string, mixed> $data */
        $data = $response->json() ?? [];

        return $data;
    }

    /**
     * Verify the API token is valid.
     *
     * @return array<string, mixed>
     *
     * @throws ConnectionException
     */
    public function verifyToken(): array
    {
        $response = Http::withToken($this->token)
            ->timeout(10)
            ->get("{$this->baseUrl}/api/v1/auth/verify");

        /** @var array<string, mixed> $data */
        $data = $response->json() ?? [];

        return $data;
    }

    /**
     * Get project information from the platform.
     *
     * @return array<string, mixed>
     *
     * @throws ConnectionException
     */
    public function getProject(string $projectId): array
    {
        $response = Http::withToken($this->token)
            ->timeout(10)
            ->get("{$this->baseUrl}/api/v1/projects/{$projectId}");

        /** @var array<string, mixed> $data */
        $data = $response->json() ?? [];

        return $data;
    }
}
