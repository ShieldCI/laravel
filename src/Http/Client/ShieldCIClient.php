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
        $configUrl = config('shieldci.api_url', 'https://shieldci.com');
        $this->baseUrl = is_string($configUrl) ? rtrim($configUrl, '/') : 'https://shieldci.com';

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
     * @throws \JsonException
     */
    public function sendReport(array $payload): array
    {
        return $this->postJson('/api/reports', $payload, 30);
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
            ->get("{$this->baseUrl}/api/token/verify");

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
    public function getProject(): array
    {
        $response = Http::withToken($this->token)
            ->timeout(10)
            ->get("{$this->baseUrl}/api/project");

        /** @var array<string, mixed> $data */
        $data = $response->json() ?? [];

        return $data;
    }

    /**
     * Notify the ShieldCI platform that analysis failed before completion.
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     *
     * @throws ConnectionException
     * @throws \JsonException
     */
    public function sendFailureNotification(array $payload): array
    {
        return $this->postJson('/api/reports/failure', $payload, 15);
    }

    /**
     * POST a JSON payload, encoding it here rather than through Guzzle's json option.
     *
     * Guzzle's encoder throws on the first invalid UTF-8 byte, and these payloads quote text
     * that is not always UTF-8: source fragments in a report, or an exception message the
     * sanitizer cut mid-character. Invalid bytes become U+FFFD; valid payloads encode exactly
     * as Guzzle encoded them.
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     *
     * @throws ConnectionException
     * @throws \JsonException
     */
    private function postJson(string $path, array $payload, int $timeout): array
    {
        $body = json_encode($payload, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);

        $response = Http::withToken($this->token)
            ->timeout($timeout)
            ->withBody($body, 'application/json')
            ->post($this->baseUrl.$path);

        /** @var array<string, mixed> $data */
        $data = $response->json() ?? [];

        return $data;
    }
}
