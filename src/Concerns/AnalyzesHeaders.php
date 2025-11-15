<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

/**
 * Provides methods for analyzing HTTP headers.
 *
 * Provides methods to retrieve and analyze HTTP response headers
 * from a given URL, useful for security header verification.
 */
trait AnalyzesHeaders
{
    /**
     * The Guzzle client instance.
     */
    protected Client $client;

    /**
     * Set the Guzzle client.
     */
    public function setClient(Client $client): void
    {
        $this->client = $client;
    }

    /**
     * Get the Guzzle client instance.
     */
    protected function getClient(): Client
    {
        if (! isset($this->client)) {
            $this->client = new Client([
                'timeout' => 10,
                'connect_timeout' => 5,
                'http_errors' => false,
                'verify' => false, // Allow self-signed certs in staging
            ]);
        }

        return $this->client;
    }

    /**
     * Determine if the header(s) exist on the URL.
     *
     * @param  string|array<int, string>  $headers
     * @param  array<string, mixed>  $options
     */
    protected function headerExistsOnUrl(?string $url, string|array $headers, array $options = []): bool
    {
        if ($url === null) {
            // If we can't find the route, we cannot perform this check.
            return false;
        }

        try {
            $response = $this->getClient()->get($url, array_merge([
                'http_errors' => false,
                'verify' => false,
            ], $options));

            $headerList = is_array($headers) ? $headers : [$headers];

            return collect($headerList)->contains(function ($header) use ($response) {
                return $response->hasHeader($header);
            });
        } catch (GuzzleException) {
            return false;
        }
    }

    /**
     * Get the headers on the URL.
     *
     * @param  array<string, mixed>  $options
     * @return array<int, string>
     */
    protected function getHeadersOnUrl(?string $url, string $header, array $options = []): array
    {
        if ($url === null) {
            // If we can't find the route, we cannot perform this check.
            return [];
        }

        try {
            $response = $this->getClient()->get($url, array_merge([
                'http_errors' => false,
                'verify' => false,
            ], $options));

            return $response->getHeader($header);
        } catch (GuzzleException) {
            return [];
        }
    }

    /**
     * Legacy method for backward compatibility.
     * Set HTTP client (for testing).
     *
     * @deprecated Use setClient() instead
     */
    public function setHttpClient(Client $client): void
    {
        $this->setClient($client);
    }
}
