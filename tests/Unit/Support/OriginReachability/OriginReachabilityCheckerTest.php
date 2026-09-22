<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support\OriginReachability;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use Illuminate\Contracts\Config\Repository;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\Support\OriginReachability\DeclaredOrigin;
use ShieldCI\Support\OriginReachability\OriginOutcome;
use ShieldCI\Support\OriginReachability\OriginReachabilityChecker;
use ShieldCI\Tests\AnalyzerTestCase;

/**
 * Extends AnalyzerTestCase only for createTempDirectory(); there is no analyzer here, the
 * same way SeededTableScannerTest borrows the fixture helper.
 */
class OriginReachabilityCheckerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        throw new \LogicException('No analyzer under test.');
    }

    /**
     * Build a client whose handler replays the queued responses (or throws the queued
     * exceptions) in order, and record every request it is asked to send so tests can
     * assert on how many probes actually left the helper.
     *
     * Requests are recorded by a middleware of our own rather than Guzzle's history
     * middleware, which takes its container as a widened array|ArrayAccess reference; this
     * keeps $recorded a plain list of requests the assertions can count.
     *
     * @param  array<int, ResponseInterface|\Throwable>  $queue
     * @param  array<int, RequestInterface>  $recorded
     *
     * @param-out array<int, RequestInterface> $recorded
     */
    private function clientReplaying(array $queue, array &$recorded = []): Client
    {
        $stack = HandlerStack::create(new MockHandler($queue));

        $stack->push(static function (callable $handler) use (&$recorded): callable {
            return static function (RequestInterface $request, array $options) use ($handler, &$recorded) {
                $recorded[] = $request;

                return $handler($request, $options);
            };
        });

        return new Client(['handler' => $stack]);
    }

    /**
     * Build a client that records the request options the checker asks for.
     *
     * The recorded RequestInterface carries none of verify, timeout, connect_timeout or
     * allow_redirects, so asserting on it cannot pin any of them. The options array is where
     * those live and is the only place a regression in them would show.
     *
     * Guzzle declares the middleware's $options as a bare array, so that is what comes back
     * out; the assertions read the keys they name.
     *
     * @param  array<int, ResponseInterface|\Throwable>  $queue
     * @param  array<int, array<mixed, mixed>>  $recorded
     *
     * @param-out array<int, array<mixed, mixed>> $recorded
     */
    private function clientRecordingOptions(array $queue, array &$recorded = []): Client
    {
        $stack = HandlerStack::create(new MockHandler($queue));

        $stack->push(static function (callable $handler) use (&$recorded): callable {
            return static function (RequestInterface $request, array $options) use ($handler, &$recorded) {
                $recorded[] = $options;

                return $handler($request, $options);
            };
        });

        return new Client(['handler' => $stack]);
    }

    /**
     * A transport-level failure as Guzzle's cURL handler reports one.
     *
     * The cURL error number lives in the message text on purpose: Guzzle 8 dropped the
     * handler context that used to carry it, and this package supports Guzzle 7 and 8, so
     * the text is the only place both majors put it.
     */
    private function connectException(string $message): ConnectException
    {
        return new ConnectException($message, new Request('GET', 'https://example.com/'));
    }

    /** @test */
    #[Test]
    public function it_classifies_a_2xx_response_as_connected(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([new Response(200, ['X-Frame-Options' => 'DENY'], 'hello world')])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);

        $probe = $report->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::Connected2xx, $probe->outcome);
        $this->assertSame(200, $probe->statusCode);
        $this->assertSame('DENY', $probe->header('x-frame-options'));
        $this->assertSame('hello world', $probe->bodyPrefix);
        $this->assertTrue($probe->hasEvidence());
    }

    /** @test */
    #[Test]
    public function it_classifies_a_non_2xx_response_as_connected_but_not_ok(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([new Response(503, ['Retry-After' => '120'], 'maintenance')])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::ConnectedNon2xx, $probe->outcome);
        $this->assertSame(503, $probe->statusCode);
        $this->assertSame('120', $probe->header('Retry-After'));
        $this->assertTrue($probe->hasEvidence());
    }

    /** @test */
    #[Test]
    public function it_classifies_a_redirect_to_another_host_as_redirected_off_host(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([new Response(302, ['Location' => 'https://cdn.elsewhere.test/home'])])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::RedirectedOffHost, $probe->outcome);
        $this->assertSame('https://cdn.elsewhere.test/home', $probe->redirectLocation);
        $this->assertSame(302, $probe->statusCode);
    }

    /** @test */
    #[Test]
    public function it_treats_a_redirect_that_stays_on_the_same_host_as_connected_non_2xx(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([new Response(301, ['Location' => 'https://example.com/login'])])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::ConnectedNon2xx, $probe->outcome);
        $this->assertSame('https://example.com/login', $probe->redirectLocation);
    }

    /**
     * A 3xx carries no Location when it is not a redirect at all: a 304 Not Modified is
     * the common one. There is nowhere for it to have sent the request, so the origin
     * answered and that answer is the evidence.
     */
    /** @test */
    #[Test]
    public function it_treats_a_3xx_without_a_location_as_connected_non_2xx(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([new Response(304, ['ETag' => '"abc123"'])])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::ConnectedNon2xx, $probe->outcome);
        $this->assertNull($probe->redirectLocation);
        $this->assertSame('"abc123"', $probe->header('etag'));
        $this->assertTrue($probe->hasEvidence());
    }

    /**
     * A relative Location names no host, so the redirect stays on the origin that was
     * probed and must not be reported as having handed the request elsewhere.
     */
    /** @test */
    #[Test]
    public function it_treats_a_relative_redirect_as_staying_on_the_origin(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([new Response(302, ['Location' => '/login'])])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::ConnectedNon2xx, $probe->outcome);
        $this->assertSame('/login', $probe->redirectLocation);
    }

    /**
     * The status and the headers are evidence in their own right. A body that cannot be
     * read costs the body prefix and nothing else. It must not throw the probe away, or
     * an unreadable body would look the same as an origin that never answered.
     */
    /** @test */
    #[Test]
    public function it_keeps_the_status_and_headers_when_the_body_cannot_be_read(): void
    {
        $body = Utils::streamFor('never readable');
        $response = new Response(200, ['X-Frame-Options' => 'DENY'], $body);
        $body->detach();

        $checker = new OriginReachabilityChecker($this->clientReplaying([$response]));

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::Connected2xx, $probe->outcome);
        $this->assertSame(200, $probe->statusCode);
        $this->assertSame('DENY', $probe->header('X-Frame-Options'));
        $this->assertNull($probe->bodyPrefix);
        $this->assertTrue($probe->hasEvidence());
    }

    /** @test */
    #[Test]
    public function it_classifies_a_certificate_failure_as_a_tls_failure(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([$this->connectException('cURL error 60: SSL certificate problem: self signed certificate')])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::TlsFailure, $probe->outcome);
        $this->assertFalse($probe->hasEvidence());
        $this->assertNull($probe->statusCode);
        $this->assertStringContainsString('SSL certificate problem', (string) $probe->failureMessage);
    }

    /** @test */
    #[Test]
    public function it_classifies_an_unresolvable_host_as_a_dns_failure(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([$this->connectException('cURL error 6: Could not resolve host: example.invalid')])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.invalid', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.invalid');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::DnsFailure, $probe->outcome);
        $this->assertFalse($probe->hasEvidence());
    }

    /** @test */
    #[Test]
    public function it_classifies_a_refused_connection_as_connection_refused(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([$this->connectException('cURL error 7: Failed to connect to example.com port 443: Connection refused')])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::ConnectionRefused, $probe->outcome);
        $this->assertFalse($probe->hasEvidence());
    }

    /** @test */
    #[Test]
    public function it_classifies_an_expired_request_as_a_timeout(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([$this->connectException('cURL error 28: Operation timed out after 10000 milliseconds')])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::Timeout, $probe->outcome);
        $this->assertFalse($probe->hasEvidence());
    }

    /** @test */
    #[Test]
    public function it_classifies_transport_errors_it_cannot_name_without_pretending_to_know_which_one(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([$this->connectException('cURL error 55: Failed sending data to the peer')])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::TransportFailure, $probe->outcome);
        $this->assertFalse($probe->hasEvidence());
    }

    /**
     * The cURL error number decides, not the wording: libcurl's text varies by version and
     * platform, so a message carrying none of the familiar phrases must still land in the
     * right state.
     */
    /** @test */
    #[Test]
    public function it_names_a_failure_from_the_curl_error_number_alone(): void
    {
        $checker = new OriginReachabilityChecker($this->clientReplaying([
            $this->connectException('cURL error 35: handshake failure alert'),
            $this->connectException('cURL error 6: the name went nowhere'),
        ]));

        $report = $checker->probe([
            new DeclaredOrigin('https://handshake.test', [DeclaredOrigin::SOURCE_APP_URL]),
            new DeclaredOrigin('https://nowhere.test', [DeclaredOrigin::SOURCE_ASSET_URL]),
        ]);

        $handshake = $report->probeFor('https://handshake.test');
        $nowhere = $report->probeFor('https://nowhere.test');

        $this->assertNotNull($handshake);
        $this->assertNotNull($nowhere);
        $this->assertSame(OriginOutcome::TlsFailure, $handshake->outcome);
        $this->assertSame(OriginOutcome::DnsFailure, $nowhere->outcome);
    }

    /**
     * CURLE_COULDNT_CONNECT (7) is raised for a refusal, for "network is unreachable" and for
     * "no route to host" alike, so the number alone cannot name the failure. It defers to the
     * message, which distinguishes them, rather than calling all three a refusal: refused
     * means something answered the SYN with a RST, and saying so when nothing did is the
     * report inventing a diagnosis.
     */
    /** @test */
    #[Test]
    public function it_does_not_call_every_failure_to_connect_a_refusal(): void
    {
        $checker = new OriginReachabilityChecker($this->clientReplaying([
            $this->connectException('cURL error 7: Failed to connect to refused.test port 443: Connection refused'),
            $this->connectException('cURL error 7: Failed to connect to unreachable.test port 443: Network is unreachable'),
        ]));

        $report = $checker->probe([
            new DeclaredOrigin('https://refused.test', [DeclaredOrigin::SOURCE_APP_URL]),
            new DeclaredOrigin('https://unreachable.test', [DeclaredOrigin::SOURCE_ASSET_URL]),
        ]);

        $refused = $report->probeFor('https://refused.test');
        $unreachable = $report->probeFor('https://unreachable.test');

        $this->assertNotNull($refused);
        $this->assertNotNull($unreachable);
        $this->assertSame(OriginOutcome::ConnectionRefused, $refused->outcome);
        $this->assertSame(OriginOutcome::TransportFailure, $unreachable->outcome);
    }

    /**
     * A missing CA bundle, an unusable SSL engine or a bad client certificate are faults of
     * the machine running the analysis. Calling them a TLS failure blames the deployed origin
     * for this container's setup, and in a slim CI image every origin would be reported as
     * having a broken certificate.
     */
    /** @test */
    #[Test]
    public function it_does_not_blame_the_origin_for_a_local_tls_fault(): void
    {
        $checker = new OriginReachabilityChecker($this->clientReplaying([
            $this->connectException('cURL error 77: error setting certificate verify locations'),
            $this->connectException('cURL error 60: SSL certificate problem: self signed certificate'),
        ]));

        $report = $checker->probe([
            new DeclaredOrigin('https://local-fault.test', [DeclaredOrigin::SOURCE_APP_URL]),
            new DeclaredOrigin('https://bad-cert.test', [DeclaredOrigin::SOURCE_ASSET_URL]),
        ]);

        $localFault = $report->probeFor('https://local-fault.test');
        $badCert = $report->probeFor('https://bad-cert.test');

        $this->assertNotNull($localFault);
        $this->assertNotNull($badCert);
        $this->assertSame(OriginOutcome::TransportFailure, $localFault->outcome);
        $this->assertSame(OriginOutcome::TlsFailure, $badCert->outcome);
    }

    /**
     * Guzzle appends " for <url>" to a transport error, and that URL carries the host that was
     * probed. Matching the needles against it would let an origin name itself: ssl.cdn.test
     * would be called a TLS failure on the strength of its own hostname.
     */
    /** @test */
    #[Test]
    public function it_does_not_let_the_probed_host_name_the_failure(): void
    {
        $checker = new OriginReachabilityChecker($this->clientReplaying([
            $this->connectException('Recv failure: Connection reset by peer for https://ssl.cdn.test/'),
        ]));

        $report = $checker->probe([new DeclaredOrigin('https://ssl.cdn.test', [DeclaredOrigin::SOURCE_APP_URL])]);

        $probe = $report->probeFor('https://ssl.cdn.test');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::TransportFailure, $probe->outcome);
    }

    /** @test */
    #[Test]
    public function it_classifies_transport_errors_from_handlers_that_report_no_errno(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([$this->connectException('php_network_getaddresses: getaddrinfo failed: Name or service not known')])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.invalid', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.invalid');

        $this->assertNotNull($probe);
        $this->assertSame(OriginOutcome::DnsFailure, $probe->outcome);
    }

    /**
     * The reason this helper exists. A probe that never reached anything must not be
     * reportable as success: an analyzer that turns silence into a pass is the defect
     * being removed, so the only honest verdict from zero responses is a warning that
     * says no evidence was obtained.
     */
    /** @test */
    #[Test]
    public function it_never_reports_passed_when_no_response_was_obtained(): void
    {
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([$this->connectException('cURL error 6: Could not resolve host: example.com')])
        );

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);

        $this->assertSame(Status::Warning, $report->status());
        $this->assertFalse($report->hasEvidence());
        $this->assertCount(1, $report->withoutEvidence());
        $this->assertSame([], $report->withEvidence());
        $this->assertStringContainsString('no evidence', strtolower(implode(' ', $report->findings())));
        $this->assertStringContainsString('https://example.com', implode(' ', $report->findings()));
    }

    /** @test */
    #[Test]
    public function it_never_reports_passed_when_nothing_was_declared(): void
    {
        $checker = new OriginReachabilityChecker($this->clientReplaying([]));

        $report = $checker->probe([]);

        $this->assertSame(Status::Warning, $report->status());
        $this->assertFalse($report->hasEvidence());
        $this->assertStringContainsString('no evidence', strtolower(implode(' ', $report->findings())));
    }

    /** @test */
    #[Test]
    public function it_never_reports_passed_when_only_some_origins_answered(): void
    {
        $checker = new OriginReachabilityChecker($this->clientReplaying([
            new Response(200, [], 'ok'),
            $this->connectException('cURL error 7: Connection refused'),
        ]));

        $report = $checker->probe([
            new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL]),
            new DeclaredOrigin('https://assets.example.net', [DeclaredOrigin::SOURCE_ASSET_URL]),
        ]);

        $this->assertSame(Status::Warning, $report->status());
        $this->assertTrue($report->hasEvidence());
        $this->assertCount(1, $report->withEvidence());
        $this->assertCount(1, $report->withoutEvidence());
        $this->assertStringContainsString('https://assets.example.net', implode(' ', $report->findings()));
    }

    /** @test */
    #[Test]
    public function it_reports_passed_when_every_declared_origin_answered(): void
    {
        $checker = new OriginReachabilityChecker($this->clientReplaying([
            new Response(200, [], 'ok'),
            new Response(503, [], 'down'),
        ]));

        $report = $checker->probe([
            new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL]),
            new DeclaredOrigin('https://assets.example.net', [DeclaredOrigin::SOURCE_ASSET_URL]),
        ]);

        // A 503 is still evidence: the origin answered, and what it answered is for the
        // calling rule to judge. The report only says whether a response was captured.
        $this->assertSame(Status::Passed, $report->status());
        $this->assertSame([], $report->findings());
        $this->assertTrue($report->hasEvidence());
    }

    /** @test */
    #[Test]
    public function it_treats_a_production_app_url_on_localhost_as_a_finding_of_its_own(): void
    {
        $checker = new OriginReachabilityChecker($this->clientReplaying([new Response(200, [], 'ok')]));

        $report = $checker->probe(
            [new DeclaredOrigin('http://localhost', [DeclaredOrigin::SOURCE_APP_URL])],
            'production'
        );

        $probe = $report->probeFor('http://localhost');

        $this->assertNotNull($probe);
        $this->assertTrue($probe->loopback);
        $this->assertSame(Status::Warning, $report->status());
        $this->assertCount(1, $report->loopbackInProduction());
        $this->assertStringContainsString('app.url', implode(' ', $report->findings()));
        $this->assertStringContainsString('localhost', implode(' ', $report->findings()));
    }

    /** @test */
    #[Test]
    public function it_accepts_a_loopback_origin_outside_production(): void
    {
        $checker = new OriginReachabilityChecker($this->clientReplaying([new Response(200, [], 'ok')]));

        $report = $checker->probe(
            [new DeclaredOrigin('http://127.0.0.1:8000', [DeclaredOrigin::SOURCE_APP_URL])],
            'local'
        );

        $probe = $report->probeFor('http://127.0.0.1:8000');

        $this->assertNotNull($probe);
        $this->assertTrue($probe->loopback);
        $this->assertSame([], $report->loopbackInProduction());
        $this->assertSame(Status::Passed, $report->status());
    }

    /**
     * localhost is only one of the spellings that name this machine. An IPv6 loopback or a
     * wildcard bind address is the same finding in production, and missing one of them
     * would let exactly the case this guards against slip through.
     */
    /** @test */
    #[Test]
    public function it_recognises_every_loopback_spelling_as_this_machine(): void
    {
        $checker = new OriginReachabilityChecker($this->clientReplaying([
            new Response(200, [], 'ok'),
            new Response(200, [], 'ok'),
            new Response(200, [], 'ok'),
        ]));

        $report = $checker->probe([
            new DeclaredOrigin('http://[::1]:8000', [DeclaredOrigin::SOURCE_APP_URL]),
            new DeclaredOrigin('http://0.0.0.0:8080', [DeclaredOrigin::SOURCE_ASSET_URL]),
            new DeclaredOrigin('https://app.example.com', [DeclaredOrigin::SOURCE_VITE_MANIFEST]),
        ], 'production');

        $ipv6 = $report->probeFor('http://[::1]:8000');
        $wildcard = $report->probeFor('http://0.0.0.0:8080');
        $public = $report->probeFor('https://app.example.com');

        $this->assertNotNull($ipv6);
        $this->assertNotNull($wildcard);
        $this->assertNotNull($public);
        $this->assertTrue($ipv6->loopback);
        $this->assertTrue($wildcard->loopback);
        $this->assertFalse($public->loopback);
        $this->assertCount(2, $report->loopbackInProduction());
        $this->assertSame(Status::Warning, $report->status());
    }

    /**
     * De-duplication: several declarations naming the same host must cost one request,
     * not one per declaration.
     */
    /** @test */
    #[Test]
    public function it_makes_one_request_for_two_declarations_sharing_a_host(): void
    {
        $recorded = [];
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([new Response(200, [], 'ok')], $recorded)
        );

        $report = $checker->probe([
            new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL]),
            new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_ASSET_URL]),
        ]);

        $this->assertCount(1, $recorded);
        $this->assertCount(1, $report->probes());

        $probe = $report->probeFor('https://example.com');
        $this->assertNotNull($probe);
        $this->assertSame(
            [DeclaredOrigin::SOURCE_APP_URL, DeclaredOrigin::SOURCE_ASSET_URL],
            $probe->declaredOrigin->sources
        );
    }

    /** @test */
    #[Test]
    public function it_probes_an_origin_once_even_when_asked_a_second_time(): void
    {
        $recorded = [];
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([new Response(200, [], 'ok')], $recorded)
        );

        $origins = [new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])];

        $first = $checker->probe($origins);
        $second = $checker->probe($origins);

        $this->assertCount(1, $recorded);
        $this->assertEquals($first->probes(), $second->probes());
    }

    /** @test */
    #[Test]
    public function it_attributes_a_reused_probe_to_every_declaration_that_named_the_origin(): void
    {
        $recorded = [];
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([new Response(200, [], 'ok')], $recorded)
        );

        $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);
        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_ASSET_URL])]);

        $probe = $report->probeFor('https://example.com');

        $this->assertCount(1, $recorded);
        $this->assertNotNull($probe);
        $this->assertSame(
            [DeclaredOrigin::SOURCE_APP_URL, DeclaredOrigin::SOURCE_ASSET_URL],
            $probe->declaredOrigin->sources
        );
        $this->assertSame(200, $probe->statusCode);
    }

    /**
     * Constructed with no client and no resolver it builds its own, and still sends
     * nothing when there is nothing declared, so this makes no network call.
     */
    /** @test */
    #[Test]
    public function it_builds_its_own_client_and_resolver_when_none_are_injected(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $report = (new OriginReachabilityChecker)->check($basePath, null, null);

        $this->assertSame([], $report->probes());
        $this->assertSame(Status::Warning, $report->status());
    }

    /** @test */
    #[Test]
    public function it_sends_one_unauthenticated_get_that_does_not_follow_redirects(): void
    {
        $recorded = [];
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([new Response(302, ['Location' => 'https://elsewhere.test/'])], $recorded)
        );

        $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);

        $this->assertCount(1, $recorded);

        $request = $recorded[0];

        $this->assertSame('GET', $request->getMethod());
        $this->assertSame('https://example.com/', (string) $request->getUri());
        $this->assertFalse($request->hasHeader('Authorization'));
        $this->assertFalse($request->hasHeader('Cookie'));
    }

    /** @test */
    #[Test]
    public function it_checks_every_origin_the_application_declares_in_its_configuration(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => ['file' => 'https://cdn.example.net/build/app-abc123.js'],
        ]);

        $basePath = $this->createTempDirectory([
            'composer.json' => '{}',
            'public/build/manifest.json' => $manifest,
        ]);

        $config = $this->configWith([
            'app.url' => 'https://example.com',
            'app.asset_url' => 'https://example.com/assets',
            'app.env' => 'production',
        ]);

        $recorded = [];
        $checker = new OriginReachabilityChecker(
            $this->clientReplaying([new Response(200, [], 'app'), new Response(200, [], 'cdn')], $recorded)
        );

        $report = $checker->checkApplication($basePath, $config);

        // app.url and app.asset_url share a host, so they cost one request between them.
        $this->assertCount(2, $recorded);
        $this->assertSame(Status::Passed, $report->status());
        $this->assertSame('production', $report->environment());

        $app = $report->probeFor('https://example.com');
        $this->assertNotNull($app);
        $this->assertSame(
            [DeclaredOrigin::SOURCE_APP_URL, DeclaredOrigin::SOURCE_ASSET_URL],
            $app->declaredOrigin->sources
        );

        $cdn = $report->probeFor('https://cdn.example.net');
        $this->assertNotNull($cdn);
        $this->assertSame([DeclaredOrigin::SOURCE_VITE_MANIFEST], $cdn->declaredOrigin->sources);
    }

    /** @test */
    #[Test]
    public function it_warns_without_sending_anything_when_configuration_declares_no_origin(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $config = $this->configWith(['app.url' => null, 'app.asset_url' => null, 'app.env' => 'production']);

        $recorded = [];
        $checker = new OriginReachabilityChecker($this->clientReplaying([], $recorded));

        $report = $checker->checkApplication($basePath, $config);

        $this->assertSame([], $recorded);
        $this->assertSame(Status::Warning, $report->status());
        $this->assertFalse($report->hasEvidence());
    }

    /** @test */
    #[Test]
    public function it_flags_a_production_app_url_that_points_at_this_machine(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $config = $this->configWith([
            'app.url' => 'http://localhost',
            'app.asset_url' => null,
            'app.env' => 'production',
        ]);

        $checker = new OriginReachabilityChecker($this->clientReplaying([new Response(200, [], 'ok')]));

        $report = $checker->checkApplication($basePath, $config);

        $this->assertSame(Status::Warning, $report->status());
        $this->assertCount(1, $report->loopbackInProduction());
    }

    /**
     * @param  array<string, string|null>  $values
     */
    private function configWith(array $values): Repository
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        foreach ($values as $key => $value) {
            $config->set($key, $value);
        }

        return $config;
    }

    /**
     * TLS verification staying on is the point of this helper: turning it off converts a
     * broken certificate into a clean 200, which is the false evidence it exists to remove.
     * Two places in this package already set verify => false with an inviting comment, so
     * the option is pinned here rather than left to be copied away silently.
     */
    /** @test */
    #[Test]
    public function it_verifies_tls_and_does_not_buffer_the_whole_body(): void
    {
        $recorded = [];
        $checker = new OriginReachabilityChecker(
            $this->clientRecordingOptions([new Response(200, [], 'ok')], $recorded)
        );

        $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);

        $this->assertCount(1, $recorded);

        $options = $recorded[0];

        $this->assertTrue($options['verify'], 'TLS verification must stay on.');
        $this->assertTrue($options['stream'], 'The body must be streamed, not buffered to keep a 2 KB prefix.');
        $this->assertFalse($options['allow_redirects']);
        $this->assertFalse($options['http_errors']);
        $this->assertSame(OriginReachabilityChecker::DEFAULT_TIMEOUT, $options['timeout']);
        $this->assertSame(OriginReachabilityChecker::DEFAULT_CONNECT_TIMEOUT, $options['connect_timeout']);
    }

    /**
     * A loopback origin in production that could not be reached is still a misconfiguration
     * worth reporting, but the sentence must not claim a response. "Whatever answered is this
     * machine" about a refused connection is the report asserting evidence it never got.
     */
    /** @test */
    #[Test]
    public function it_does_not_claim_anything_answered_when_a_production_loopback_was_refused(): void
    {
        $checker = new OriginReachabilityChecker($this->clientReplaying([
            $this->connectException('cURL error 7: Failed to connect to localhost port 80: Connection refused'),
        ]));

        $report = $checker->probe(
            [new DeclaredOrigin('http://localhost', [DeclaredOrigin::SOURCE_APP_URL])],
            'production'
        );

        $findings = implode("\n", $report->findings());

        $this->assertSame(Status::Warning, $report->status());
        $this->assertStringNotContainsString('Whatever answered', $findings);
        $this->assertStringContainsString('could not be reached', $findings);
        $this->assertStringContainsString('is a loopback address', $findings);
    }

    /**
     * The same origin reached in production still gets the sentence that does describe a
     * response, so narrowing the claim above did not silence the case it was written for.
     */
    /** @test */
    #[Test]
    public function it_still_says_this_machine_answered_when_a_production_loopback_responds(): void
    {
        $checker = new OriginReachabilityChecker($this->clientReplaying([new Response(200, [], 'ok')]));

        $report = $checker->probe(
            [new DeclaredOrigin('http://127.0.0.1', [DeclaredOrigin::SOURCE_APP_URL])],
            'production'
        );

        $this->assertStringContainsString('Whatever answered is this machine', implode("\n", $report->findings()));
    }

    /**
     * A declaration that names no usable origin is a different fault from no declaration at
     * all, and reporting the second when the first happened sends the user looking for a
     * missing APP_URL instead of the broken one in front of them.
     */
    /** @test */
    #[Test]
    public function it_reports_a_broken_declaration_rather_than_calling_it_an_absent_one(): void
    {
        $recorded = [];
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);
        $checker = new OriginReachabilityChecker($this->clientReplaying([], $recorded));

        $report = $checker->check($basePath, 'http://example.com:port', null);

        $findings = implode("\n", $report->findings());

        $this->assertCount(0, $recorded, 'nothing is probed, because nothing resolved');
        $this->assertSame(Status::Warning, $report->status());
        $this->assertStringContainsString('app.url is set to a value that is not a usable http or https origin', $findings);
        $this->assertStringNotContainsString('declares no origin it is served from', $findings);
    }

    /**
     * The failure message reaches result text, issue text and the uploaded report, so it is
     * bounded and redacted on the way in. Classification still reads the original: redaction
     * rewrites the substrings the matching depends on, so the phrase that names this failure
     * sits past the truncation point on purpose.
     */
    /** @test */
    #[Test]
    public function it_bounds_and_redacts_the_failure_message_without_blinding_the_classifier(): void
    {
        $message = 'cURL error 7: '.str_repeat('context ', 80).'Connection refused for https://admin:hunter2@example.com/';

        $this->assertGreaterThan(500, strlen($message));

        $checker = new OriginReachabilityChecker($this->clientReplaying([$this->connectException($message)]));

        $report = $checker->probe([new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL])]);
        $probe = $report->probeFor('https://example.com');

        $this->assertNotNull($probe);
        $this->assertNotNull($probe->failureMessage);
        $this->assertSame(OriginOutcome::ConnectionRefused, $probe->outcome, 'classification must read the unredacted message');
        $this->assertLessThanOrEqual(503, strlen($probe->failureMessage));
        $this->assertStringNotContainsString('hunter2', $probe->failureMessage);
    }
}
