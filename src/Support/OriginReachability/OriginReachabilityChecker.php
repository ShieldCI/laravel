<?php

declare(strict_types=1);

namespace ShieldCI\Support\OriginReachability;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\Psr7\UriResolver;
use Illuminate\Contracts\Config\Repository;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use ShieldCI\Concerns\SanitizesErrorMessages;
use Throwable;

/**
 * Makes exactly one unauthenticated GET per distinct declared origin and path, and
 * classifies the outcome into named states.
 *
 * The path is the caller's to name. Asking whether an origin is reachable at all is the
 * root, which is the default, but every rule this helper was built to serve asks about a
 * particular path: an .env candidate, a compiled asset, the login route. Each distinct
 * (origin, path) is one question and costs one request for the life of this instance.
 *
 * Redirects are deliberately not followed and HTTP errors deliberately not thrown, so the
 * response the origin itself returned is the one captured. A caller asking about the page a
 * browser would land on opts into following redirects that stay on the origin's host with
 * probeFollowingSameHost(), which still makes every hop as one of these probes. TLS
 * verification is left on:
 * turning it off would silently convert a broken certificate into a clean 200, which is
 * exactly the kind of false evidence this helper exists to prevent.
 *
 * How the question is asked is the caller's to name too, within limits ProbeRequest sets:
 * which encodings to accept, and whether the body is decoded on the way back. A caller that
 * inspects Content-Encoding needs both, because a streamed gzip response is otherwise
 * inflated by Guzzle and its Content-Encoding removed before the helper sees it. Nothing
 * that identifies the caller can be sent, so the probe stays unauthenticated.
 *
 * The response is streamed rather than buffered. Only BODY_PREFIX_BYTES of the body is ever
 * kept, and an origin serving a large document at its root should not be downloaded in full
 * for the sake of the first two kilobytes.
 *
 * Guzzle 8 types its request options as an array shape, so options forwarded to the client
 * have to name the keys they may carry. Guzzle 7 declares the same parameter as a plain
 * array and accepts this unchanged.
 *
 * @phpstan-type GuzzleRequestOptions array{allow_redirects?: bool, connect_timeout?: int|float, decode_content?: bool, headers?: array<string, string>, http_errors?: bool, stream?: bool, timeout?: int|float, verify?: bool|string}
 */
final class OriginReachabilityChecker
{
    use SanitizesErrorMessages;

    public const DEFAULT_TIMEOUT = 10.0;

    public const DEFAULT_CONNECT_TIMEOUT = 5.0;

    /** Bytes of the response body kept as evidence. */
    public const BODY_PREFIX_BYTES = 2048;

    /** Redirects probeFollowingSameHost() follows by default, matching Guzzle's own limit. */
    public const MAX_SAME_HOST_REDIRECTS = 5;

    /** @var array<int, int> */
    private const FOLLOWED_REDIRECT_STATUSES = [301, 302, 303, 307, 308];

    /**
     * cURL error numbers mapped onto the outcomes they mean.
     *
     * Taken from libcurl's CURLE_* constants: 6 could-not-resolve-host, 28 operation-timed-out,
     * and the SSL family for handshake and certificate problems the far end is responsible for.
     *
     * Two families are deliberately absent.
     *
     * 7 is CURLE_COULDNT_CONNECT, which libcurl also raises for "network is unreachable" and
     * "no route to host". Naming all three "connection refused" would be a specific and wrong
     * diagnosis, because refused means something answered the SYN with a RST. It falls through
     * to the message instead, which does distinguish the refusal.
     *
     * 53, 54, 58, 66 and 77 are local TLS faults: a missing SSL engine, a bad client
     * certificate, an unreadable CA bundle. In a container with no ca-certificates package
     * every origin raises 77, and calling that a TLS failure blames the deployed origin for
     * this machine's setup. They stay a transport failure, which is true and still an absence
     * of evidence.
     *
     * @var array<int, string>
     */
    private const CURL_ERRNO_OUTCOMES = [
        6 => 'dns',
        28 => 'timeout',
        35 => 'tls',
        51 => 'tls',
        53 => 'local',
        54 => 'local',
        58 => 'local',
        59 => 'tls',
        60 => 'tls',
        66 => 'local',
        77 => 'local',
        83 => 'tls',
        91 => 'tls',
    ];

    private ClientInterface $client;

    /**
     * Probes already made, keyed by the URL that was probed and how it was asked, so one
     * question costs one request for the life of this instance however many rules ask it.
     *
     * The key is origin plus path rather than origin alone. Keyed on the origin, a caller
     * asking about /.env would be handed the response captured for the home page and would
     * read a 200 as the file being exposed — the cache silently answering a question it
     * was never asked. The probed URL is unique per (origin, path) by construction, since
     * an origin never ends in a slash and a normalised path always begins with one.
     *
     * The request variant is part of the key for the same reason. Keyed on the URL alone, a
     * caller that turned decoding off would be handed a response captured with it on, and
     * would read a compressed asset as uncompressed.
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
     *
     * @param  string  $path  the path to request on each origin; the root by default
     * @param  ProbeRequest|null  $request  the headers to send and whether to decode; a plain GET by default
     */
    public function checkApplication(string $basePath, Repository $config, string $path = '/', ?ProbeRequest $request = null): OriginReachabilityReport
    {
        return $this->check(
            $basePath,
            $this->stringConfig($config, 'app.url'),
            $this->stringConfig($config, 'app.asset_url'),
            $this->stringConfig($config, 'app.env'),
            $path,
            $request,
        );
    }

    /**
     * Resolve the declared origins under a base path and probe them.
     *
     * @param  string  $path  the path to request on each origin; the root by default
     * @param  ProbeRequest|null  $request  the headers to send and whether to decode; a plain GET by default
     */
    public function check(string $basePath, ?string $appUrl, ?string $assetUrl, ?string $environment = null, string $path = '/', ?ProbeRequest $request = null): OriginReachabilityReport
    {
        $resolved = $this->resolver->resolve($basePath, $appUrl, $assetUrl);

        return $this->probe($resolved['origins'], $environment, $resolved['unusable'], $path, $request);
    }

    private function stringConfig(Repository $config, string $key): ?string
    {
        $value = $config->get($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Probe each distinct declared origin once, at one path.
     *
     * Declarations naming the same origin are merged before anything is sent, so two
     * config values pointing at one host cost one request and produce one probe carrying
     * both declarations as its sources.
     *
     * One call asks one question of every origin, and the report it returns is the answer
     * to that question: whether each origin answered at that path, never whether what it
     * answered was good. A rule with several paths to ask about calls this once per path
     * and reads each report on its own terms, which is what keeps the never-Passed-from-
     * silence guarantee true of each path rather than of the origin in general.
     *
     * @param  array<int, DeclaredOrigin>  $origins
     * @param  string|null  $environment  the application environment (APP_ENV), when known
     * @param  array<int, string>  $unusable  declarations that named no usable origin
     * @param  string  $path  the path to request on each origin; the root by default
     * @param  ProbeRequest|null  $request  the headers to send and whether to decode; a plain GET by default
     */
    public function probe(array $origins, ?string $environment = null, array $unusable = [], string $path = '/', ?ProbeRequest $request = null): OriginReachabilityReport
    {
        $path = $this->normalizePath($path);
        $request ??= new ProbeRequest;

        $probes = [];

        foreach ($this->distinct($origins) as $origin) {
            $probes[] = $this->probeOrigin($origin, $origin->origin.$path, $request);
        }

        return new OriginReachabilityReport($probes, $environment, $unusable);
    }

    /**
     * Probe one path on one origin, following redirects for as long as they stay on its host.
     *
     * This is for a rule asking about the page a browser would end up rendering, such as the
     * policy headers on a login page, where `/` answering 302 to `/login` or http answering
     * 301 to https is the application handing over to itself. It is opt-in because the
     * opposite question is just as common: a rule asking whether /.env is exposed must read
     * a 302 to the login page as "not served", never as the login page's 200.
     *
     * Each hop is an ordinary probe, cached by URL and sent with TLS verification on, so a
     * chain several rules walk costs one request per hop for the life of this instance. The
     * chain ends at the first response that is not a same-host redirect. An off-host redirect
     * therefore ends it as RedirectedOffHost, which keeps an identity-aware proxy's own login
     * page from being read as the application's, including a proxy that first bounces the
     * request through a path of its own on the same host.
     *
     * A scheme change on the same host is followed, so http that upgrades to https is graded
     * over https. A revisited URL or the redirect limit ends the chain on the redirect that
     * was left unfollowed, and the chain says which.
     *
     * @param  string  $path  the path to request first; the root by default
     * @param  ProbeRequest|null  $request  the headers to send and whether to decode, on every hop
     * @param  int  $maxRedirects  how many redirects to follow; Guzzle's own default
     */
    public function probeFollowingSameHost(DeclaredOrigin $origin, string $path = '/', ?ProbeRequest $request = null, int $maxRedirects = self::MAX_SAME_HOST_REDIRECTS): RedirectChain
    {
        $request ??= new ProbeRequest;

        $probe = $this->probeOrigin($origin, $origin->origin.$this->normalizePath($path), $request);
        $probes = [$probe];
        $visited = [$probe->probedUrl => true];

        while (($next = $this->sameHostRedirectTarget($probe)) !== null) {
            if (isset($visited[$next['url']])) {
                return new RedirectChain($probes, RedirectChain::STOPPED_AT_LOOP);
            }

            if (count($probes) > $maxRedirects) {
                return new RedirectChain($probes, RedirectChain::STOPPED_AT_LIMIT);
            }

            // The hop keeps the declaration it came from: an http origin upgraded to https
            // is still the origin app.url named, reached under the scheme it insists on.
            $hopOrigin = $next['origin'] === $origin->origin
                ? $origin
                : new DeclaredOrigin($next['origin'], $origin->sources);

            $probe = $this->probeOrigin($hopOrigin, $next['url'], $request);
            $probes[] = $probe;
            $visited[$next['url']] = true;
        }

        return new RedirectChain($probes);
    }

    /**
     * The URL a same-host redirect points at, resolved against the URL that was probed.
     *
     * Only the statuses that send a client on to the Location are followed. A 300 offers a
     * choice and a 304 is not a redirect at all, so either ends the chain as the non-2xx it
     * is. The Location is resolved by RFC 3986 rules, so "../login" means what a browser
     * takes it to mean, and the result goes back through the same origin and path
     * normalisation as any other probe so a hop and a direct question share a cache entry.
     *
     * @return array{origin: string, url: string}|null
     */
    private function sameHostRedirectTarget(OriginProbeResult $probe): ?array
    {
        // RedirectedOffHost is excluded by the outcome itself, which is the off-host test.
        if ($probe->outcome !== OriginOutcome::ConnectedNon2xx
            || ! in_array($probe->statusCode, self::FOLLOWED_REDIRECT_STATUSES, true)
            || $probe->redirectLocation === null
        ) {
            return null;
        }

        try {
            $target = (string) UriResolver::resolve(new Uri($probe->probedUrl), new Uri($probe->redirectLocation));
        } catch (InvalidArgumentException) {
            // A Location that is not a URI names nowhere to go; the 3xx stays the answer.
            return null;
        }

        $origin = DeclaredOriginResolver::normalizeOrigin($target, 'https');

        if ($origin === null) {
            return null;
        }

        return ['origin' => $origin, 'url' => $origin.$this->normalizePath($target)];
    }

    /**
     * Reduce whatever a caller named into a path that is requested on the declared origin.
     *
     * Only the path and query are read, so the request cannot leave the origin. Callers
     * hand over asset URLs straight out of a build manifest, and those are frequently
     * fully qualified against a CDN host; the resolver has already collapsed that host
     * into a DeclaredOrigin of its own, and aiming a probe at a host that arrived in a
     * path argument would report on something nobody declared.
     *
     * A leading slash is added when it is missing so 'build/app.js' and '/build/app.js'
     * are one question rather than two, and a fragment is dropped because it is never sent
     * and would otherwise split the cache on a difference the server never sees.
     */
    private function normalizePath(string $path): string
    {
        $path = trim($path);

        if ($path === '' || $path === '/') {
            return '/';
        }

        $parts = parse_url($path);

        // parse_url only refuses input it cannot make sense of at all. Reading that as a
        // literal path still sends the caller's own string to the declared origin, which
        // is closer to what was asked for than silently substituting the root.
        if (! is_array($parts)) {
            $parts = ['path' => $path];
        }

        $requestPath = isset($parts['path']) && is_string($parts['path']) ? $parts['path'] : '';
        $query = isset($parts['query']) && is_string($parts['query']) && $parts['query'] !== ''
            ? '?'.$parts['query']
            : '';

        if ($requestPath === '') {
            $requestPath = '/';
        } elseif (! str_starts_with($requestPath, '/')) {
            $requestPath = '/'.$requestPath;
        }

        return $requestPath.$query;
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

    private function probeOrigin(DeclaredOrigin $origin, string $url, ProbeRequest $request): OriginProbeResult
    {
        $key = $url."\n".$request->cacheKey();
        $cached = $this->probed[$key] ?? null;

        if ($cached !== null) {
            // Union, not replacement: an origin named by app.url and later by app.asset_url
            // is misconfigured in both places, and a report that credits only the second
            // sends the user to fix one of the two keys that need it.
            $merged = $cached->declaredOrigin->mergeSources($origin);

            return $merged->sources === $cached->declaredOrigin->sources
                ? $cached
                : $cached->withDeclaredOrigin($merged);
        }

        return $this->probed[$key] = $this->sendProbe($origin, $url, $request);
    }

    private function sendProbe(DeclaredOrigin $origin, string $url, ProbeRequest $request): OriginProbeResult
    {
        /** @var GuzzleRequestOptions $options */
        $options = [
            'allow_redirects' => false,
            'http_errors' => false,
            'timeout' => $this->timeout,
            'connect_timeout' => $this->connectTimeout,
            'verify' => true,
            'stream' => true,
            'headers' => $request->headers(),
            'decode_content' => $request->decodeContent,
        ];

        try {
            $response = $this->client->request('GET', $url, $options);
        } catch (Throwable $exception) {
            return new OriginProbeResult(
                declaredOrigin: $origin,
                probedUrl: $url,
                // Classified from the raw message and stored sanitised. SanitizesErrorMessages
                // draws that line itself: redaction rewrites the substrings classification
                // depends on, so the matching reads the original and only the copy that
                // reaches a result message, an issue or the uploaded report is bounded.
                outcome: $this->classifyFailure($exception),
                failureMessage: $this->sanitizedErrorMessage($exception->getMessage()),
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

        $message = strtolower($this->withoutProbedUrl($message));

        return match (true) {
            $this->messageMentions($message, ['could not resolve host', "couldn't resolve host", 'name or service not known', 'nodename nor servname', 'getaddrinfo', 'no such host']) => OriginOutcome::DnsFailure,
            $this->messageMentions($message, ['connection refused']) => OriginOutcome::ConnectionRefused,
            $this->messageMentions($message, ['timed out', 'timeout']) => OriginOutcome::Timeout,
            $this->messageMentions($message, ['ssl', 'tls', 'certificate']) => OriginOutcome::TlsFailure,
            default => OriginOutcome::TransportFailure,
        };
    }

    /**
     * Drop the " for <url>" Guzzle appends to a transport error.
     *
     * The URL always carries the host that was probed, so leaving it in means the needles
     * below are matched against the origin's own name: https://ssl.cdn.example.com would be
     * called a TLS failure on the strength of its hostname. Only what the handler said about
     * the failure should decide what the failure is called.
     */
    private function withoutProbedUrl(string $message): string
    {
        $stripped = preg_replace('/\s+for\s+https?:\/\/\S*\s*$/i', '', $message);

        return $stripped ?? $message;
    }

    private function outcomeForKind(string $kind): OriginOutcome
    {
        return match ($kind) {
            'dns' => OriginOutcome::DnsFailure,
            'timeout' => OriginOutcome::Timeout,
            'local' => OriginOutcome::TransportFailure,
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
