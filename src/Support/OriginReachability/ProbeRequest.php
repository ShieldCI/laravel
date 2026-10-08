<?php

declare(strict_types=1);

namespace ShieldCI\Support\OriginReachability;

use InvalidArgumentException;

/**
 * How a probe asks its question: the request headers it sends and whether the response body
 * is decoded on the way back.
 *
 * Only headers that shape what the origin sends back may be named. The probe is
 * unauthenticated by design, and a header that identifies the caller (Authorization, Cookie,
 * Proxy-Authorization) or redirects the request (Host) would make its answer evidence about
 * something other than what a visitor sees. A header outside the allowlist is refused rather
 * than dropped, because dropping it would leave the caller believing it had been sent.
 *
 * Decoding can be turned off for a caller that inspects Content-Encoding. The probe streams
 * its response, and Guzzle's stream handler inflates a gzip or deflate body and removes the
 * Content-Encoding header as it does so, which makes a compressed origin read as an
 * uncompressed one.
 */
final class ProbeRequest
{
    /**
     * Request headers a caller may name, keyed by lower-cased name onto the spelling sent.
     *
     * @var array<string, string>
     */
    public const ALLOWED_HEADERS = [
        'accept' => 'Accept',
        'accept-encoding' => 'Accept-Encoding',
    ];

    /** @var array<string, string> */
    private const DEFAULT_HEADERS = ['Accept' => '*/*'];

    /** @var array<string, string> */
    private readonly array $headers;

    /**
     * @param  array<string, string>  $headers  request headers, named case-insensitively
     * @param  bool  $decodeContent  whether a compressed response body is inflated and its Content-Encoding removed
     *
     * @throws InvalidArgumentException when a header is outside the allowlist or named twice
     */
    public function __construct(array $headers = [], public readonly bool $decodeContent = true)
    {
        $named = [];

        foreach ($headers as $name => $value) {
            $canonical = self::ALLOWED_HEADERS[strtolower($name)] ?? null;

            if ($canonical === null) {
                throw new InvalidArgumentException(sprintf(
                    'The origin probe is unauthenticated and may only send %s; "%s" is not allowed.',
                    implode(', ', self::ALLOWED_HEADERS),
                    $name,
                ));
            }

            if (isset($named[$canonical])) {
                throw new InvalidArgumentException(sprintf('The header "%s" is named more than once.', $canonical));
            }

            $named[$canonical] = $value;
        }

        // Laid out in allowlist order rather than the order the caller named them in, so the
        // same headers always come out as the same array and therefore the same cache key.
        $sent = [];

        foreach (self::ALLOWED_HEADERS as $canonical) {
            $value = $named[$canonical] ?? self::DEFAULT_HEADERS[$canonical] ?? null;

            if ($value !== null) {
                $sent[$canonical] = $value;
            }
        }

        $this->headers = $sent;
    }

    /**
     * The headers sent: the defaults, with any the caller named in their place.
     *
     * @return array<string, string>
     */
    public function headers(): array
    {
        return $this->headers;
    }

    /**
     * What makes two requests to one URL the same question.
     *
     * Built from the headers actually sent, which are canonically named and ordered, so the
     * case and order a caller named them in cannot split one question into two, and naming
     * the default Accept outright asks the same question as naming nothing.
     */
    public function cacheKey(): string
    {
        return json_encode([$this->headers, $this->decodeContent], JSON_THROW_ON_ERROR);
    }
}
