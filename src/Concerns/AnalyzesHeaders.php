<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

/**
 * Trait for analyzing HTTP headers.
 *
 * Provides methods to retrieve and analyze HTTP response headers
 * from a given URL, useful for security header verification.
 */
trait AnalyzesHeaders
{
    protected Client $httpClient;

    /**
     * Get HTTP headers from a URL.
     *
     * @param  string  $url  The URL to request
     * @param  string|null  $headerName  Specific header to retrieve (null for all headers)
     * @return array<string>|array<string, array<string>>|null Array of header values, all headers, or null on error
     */
    protected function getHeadersOnUrl(string $url, ?string $headerName = null): ?array
    {
        try {
            $response = $this->httpClient->get($url, [
                'timeout' => 5,
                'connect_timeout' => 3,
                'http_errors' => false,
                'verify' => false, // Allow self-signed certs in staging
            ]);

            if ($headerName === null) {
                // Return all headers
                $headers = [];
                foreach ($response->getHeaders() as $name => $values) {
                    $headers[$name] = $values;
                }

                return $headers;
            }

            // Return specific header
            if ($response->hasHeader($headerName)) {
                return $response->getHeader($headerName);
            }

            return null;
        } catch (GuzzleException $e) {
            // Network error - return null (graceful failure)
            return null;
        }
    }

    /**
     * Set HTTP client (for testing).
     */
    public function setHttpClient(Client $client): void
    {
        $this->httpClient = $client;
    }
}
