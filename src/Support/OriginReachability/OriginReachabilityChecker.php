<?php

declare(strict_types=1);

namespace ShieldCI\Support\OriginReachability;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Illuminate\Contracts\Config\Repository;
use Psr\Http\Message\ResponseInterface;
use Throwable;

/**
 * Makes exactly one unauthenticated GET per distinct declared origin and classifies the
 * outcome into named states.
 *
 * Redirects are deliberately not followed and HTTP errors deliberately not thrown, so the
 * response the origin itself returned is the one captured. TLS verification is left on:
 * turning it off would silently convert a broken certificate into a clean 200, which is
 * exactly the kind of false evidence this helper exists to prevent.
 *
 * Guzzle 8 types its request options as an array shape, so options forwarded to the client
 * have to name the keys they may carry. Guzzle 7 declares the same parameter as a plain
 * array and accepts this unchanged.
 *
 * @phpstan-type GuzzleRequestOptions array{allow_redirects?: bool, connect_timeout?: int|float, headers?: array<string, string>, http_errors?: bool, timeout?: int|float, verify?: bool|string}
 */
final class OriginReachabilityChecker
{
    public const DEFAULT_TIMEOUT = 10.0;

    public const DEFAULT_CONNECT_TIMEOUT = 5.0;

    /** Bytes of the response body kept as evidence. */
    public const BODY_PREFIX_BYTES = 2048;

    /**
     * cURL error numbers mapped onto the outcomes they mean.
     *
     * Taken from libcurl's CURLE_* constants: 6 could-not-resolve-host, 7 could-not-connect,
     * 28 operation-timed-out, and the SSL family for handshake and certificate problems.
     *
     * @var array<int, string>
     */
    private const CURL_ERRNO_OUTCOMES = [
        6 => 'dns',
        7 => 'refused',
        28 => 'timeout',
        35 => 'tls',
        51 => 'tls',
        53 => 'tls',
        54 => 'tls',
        58 => 'tls',
        59 => 'tls',
        60 => 'tls',
        66 => 'tls',
        77 => 'tls',
        83 => 'tls',
        91 => 'tls',
    ];

    private ClientInterface $client;

    /**
     * Probes already made, keyed by origin, so an origin costs one request for the life of
     * this instance however many rules ask about it.
     *
     * @var array<string, OriginProbeResult>
     */
    private array $probed = [];

    private DeclaredOriginResolver $resolver;

    public function __construct(
        ?ClientInterface $client = null,
        ?DeclaredOriginResolver $resolver = null,
        private readonly float $timeout = self::DEFAULT_TIMEOUT,
        private readonly float $connectTimeout = self::DEFAULT_CONNECT_TIMEOUT,
    ) {
        $this->client = $client ?? new Client;
        $this->resolver = $resolver ?? new DeclaredOriginResolver;
    }

    /**
     * Resolve the origins an application declares from its configuration, then probe them.
     *
     * This is the entry point rules use: one call, one request per distinct origin, and a
     * report that cannot say Passed unless something actually answered.
     */
    public function checkApplication(string $basePath, Repository $config): OriginReachabilityReport
    {
        return $this->check(
            $basePath,
            $this->stringConfig($config, 'app.url'),
            $this->stringConfig($config, 'app.asset_url'),
            $this->stringConfig($config, 'app.env'),
        );
    }

    /**
     * Resolve the declared origins under a base path and probe them.
     */
    public function check(string $basePath, ?string $appUrl, ?string $assetUrl, ?string $environment = null): OriginReachabilityReport
    {
        return $this->probe($this->resolver->resolve($basePath, $appUrl, $assetUrl), $environment);
    }

    private function stringConfig(Repository $config, string $key): ?string
    {
        $value = $config->get($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Probe each distinct declared origin once.
     *
     * Declarations naming the same origin are merged before anything is sent, so two
     * config values pointing at one host cost one request and produce one probe carrying
     * both declarations as its sources.
     *
     * @param  array<int, DeclaredOrigin>  $origins
     * @param  string|null  $environment  the application environment (APP_ENV), when known
     */
    public function probe(array $origins, ?string $environment = null): OriginReachabilityReport
    {
        $probes = [];

        foreach ($this->distinct($origins) as $origin) {
            $probes[] = $this->probeOrigin($origin);
        }

        return new OriginReachabilityReport($probes, $environment);
    }

    /**
     * Collapse declarations onto distinct origins, keeping first-seen order and the union
     * of the declarations each origin came from.
     *
     * @param  array<int, DeclaredOrigin>  $origins
     * @return array<int, DeclaredOrigin>
     */
    private function distinct(array $origins): array
    {
        $distinct = [];

        foreach ($origins as $origin) {
            $key = $origin->origin;

            $distinct[$key] = isset($distinct[$key])
                ? $distinct[$key]->mergeSources($origin)
                : $origin;
        }

        return array_values($distinct);
    }

    private function probeOrigin(DeclaredOrigin $origin): OriginProbeResult
    {
        $cached = $this->probed[$origin->origin] ?? null;

        if ($cached !== null) {
            return $cached->declaredOrigin->sources === $origin->sources
                ? $cached
                : $cached->withDeclaredOrigin($origin);
        }

        return $this->probed[$origin->origin] = $this->sendProbe($origin);
    }

    private function sendProbe(DeclaredOrigin $origin): OriginProbeResult
    {
        $url = $origin->origin.'/';

        /** @var GuzzleRequestOptions $options */
        $options = [
            'allow_redirects' => false,
            'http_errors' => false,
            'timeout' => $this->timeout,
            'connect_timeout' => $this->connectTimeout,
            'verify' => true,
            'headers' => ['Accept' => '*/*'],
        ];

        try {
            $response = $this->client->request('GET', $url, $options);
        } catch (Throwable $exception) {
            return new OriginProbeResult(
                declaredOrigin: $origin,
                probedUrl: $url,
                outcome: $this->classifyFailure($exception),
                failureMessage: $exception->getMessage(),
                loopback: $this->isLoopback($origin->host()),
            );
        }

        return $this->classifyResponse($origin, $url, $response);
    }

    private function classifyResponse(DeclaredOrigin $origin, string $url, ResponseInterface $response): OriginProbeResult
    {
        $status = $response->getStatusCode();
        $location = $response->getHeaderLine('Location');
        $location = $location === '' ? null : $location;

        $outcome = match (true) {
            $status >= 300 && $status < 400 && $this->pointsOffHost($origin, $location) => OriginOutcome::RedirectedOffHost,
            $status >= 200 && $status < 300 => OriginOutcome::Connected2xx,
            default => OriginOutcome::ConnectedNon2xx,
        };

        return new OriginProbeResult(
            declaredOrigin: $origin,
            probedUrl: $url,
            outcome: $outcome,
            statusCode: $status,
            headers: $response->getHeaders(),
            bodyPrefix: $this->bodyPrefix($response),
            redirectLocation: $location,
            loopback: $this->isLoopback($origin->host()),
        );
    }

    /**
     * Whether a host names the machine the analysis is running on.
     *
     * An origin that answers from here is not evidence about a deployed origin, so the
     * distinction has to survive into the report rather than being flattened into "it
     * answered".
     */
    private function isLoopback(string $host): bool
    {
        $host = strtolower(trim($host, '[]'));

        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            return true;
        }

        if ($host === '::1' || $host === '0.0.0.0' || $host === '::') {
            return true;
        }

        return (bool) preg_match('/^127(?:\.\d{1,3}){3}$/', $host);
    }

    /**
     * Whether a redirect target names a host other than the one that was probed.
     *
     * A relative Location, or one naming the same host, keeps the exchange on the origin:
     * only a different host means the origin handed the request somewhere else.
     */
    private function pointsOffHost(DeclaredOrigin $origin, ?string $location): bool
    {
        if ($location === null) {
            return false;
        }

        $host = parse_url($location, PHP_URL_HOST);

        if (! is_string($host) || $host === '') {
            return false;
        }

        return strtolower($host) !== strtolower($origin->host());
    }

    /**
     * Name the transport failure.
     *
     * The cURL error number is authoritative and is read out of the message, which both
     * supported Guzzle majors format as "cURL error <errno>: <error>". It is read from the
     * text rather than from an exception accessor because Guzzle 8 dropped the handler
     * context that carried it, and this package supports 7 and 8.
     *
     * Handlers that are not cURL (the stream handler, for instance) produce no errno, so
     * the message is matched for the phrases those handlers use. Anything still
     * unrecognised stays TransportFailure rather than being guessed into a neighbouring
     * state: an unnamed failure is still an absence of evidence, and a wrong name would
     * make the report lie.
     */
    private function classifyFailure(Throwable $exception): OriginOutcome
    {
        $message = $exception->getMessage();
        $errno = $this->curlErrno($message);

        if ($errno !== null && isset(self::CURL_ERRNO_OUTCOMES[$errno])) {
            return $this->outcomeForKind(self::CURL_ERRNO_OUTCOMES[$errno]);
        }

        $message = strtolower($message);

        return match (true) {
            $this->messageMentions($message, ['could not resolve host', "couldn't resolve host", 'name or service not known', 'nodename nor servname', 'getaddrinfo', 'no such host']) => OriginOutcome::DnsFailure,
            $this->messageMentions($message, ['connection refused']) => OriginOutcome::ConnectionRefused,
            $this->messageMentions($message, ['timed out', 'timeout']) => OriginOutcome::Timeout,
            $this->messageMentions($message, ['ssl', 'tls', 'certificate']) => OriginOutcome::TlsFailure,
            default => OriginOutcome::TransportFailure,
        };
    }

    private function outcomeForKind(string $kind): OriginOutcome
    {
        return match ($kind) {
            'dns' => OriginOutcome::DnsFailure,
            'refused' => OriginOutcome::ConnectionRefused,
            'timeout' => OriginOutcome::Timeout,
            default => OriginOutcome::TlsFailure,
        };
    }

    /**
     * @param  array<int, string>  $needles
     */
    private function messageMentions(string $message, array $needles): bool
    {
        foreach ($needles as $needle) {
            if (str_contains($message, $needle)) {
                return true;
            }
        }

        return false;
    }

    private function curlErrno(string $message): ?int
    {
        return preg_match('/\bcURL error (\d+)\b/i', $message, $matches) === 1
            ? (int) $matches[1]
            : null;
    }

    private function bodyPrefix(ResponseInterface $response): ?string
    {
        try {
            $body = $response->getBody();

            if ($body->isSeekable()) {
                $body->rewind();
            }

            return $body->read(self::BODY_PREFIX_BYTES);
        } catch (Throwable) {
            // A body that cannot be read is not evidence; the status and headers still are.
            return null;
        }
    }
}
