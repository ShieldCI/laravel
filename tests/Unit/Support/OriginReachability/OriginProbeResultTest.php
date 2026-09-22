<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support\OriginReachability;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\Support\OriginReachability\DeclaredOrigin;
use ShieldCI\Support\OriginReachability\OriginOutcome;
use ShieldCI\Support\OriginReachability\OriginProbeResult;
use ShieldCI\Support\OriginReachability\OriginReachabilityReport;

/**
 * The shared artifact itself: what a captured response exposes to the rules that assert
 * over it, and how a report describes what it found.
 */
class OriginProbeResultTest extends TestCase
{
    /**
     * @param  array<string, array<int, string>>  $headers
     */
    private function connected(string $origin, int $status, array $headers = [], string $body = ''): OriginProbeResult
    {
        return new OriginProbeResult(
            declaredOrigin: new DeclaredOrigin($origin, [DeclaredOrigin::SOURCE_APP_URL]),
            probedUrl: $origin.'/',
            outcome: $status >= 200 && $status < 300 ? OriginOutcome::Connected2xx : OriginOutcome::ConnectedNon2xx,
            statusCode: $status,
            headers: $headers,
            bodyPrefix: $body,
        );
    }

    /** @test */
    #[Test]
    public function it_matches_header_names_case_insensitively(): void
    {
        $probe = $this->connected('https://example.com', 200, [
            'Strict-Transport-Security' => ['max-age=31536000'],
            'Set-Cookie' => ['a=1', 'b=2'],
        ]);

        $this->assertSame('max-age=31536000', $probe->header('strict-transport-security'));
        $this->assertSame(['a=1', 'b=2'], $probe->headerValues('SET-COOKIE'));
        $this->assertTrue($probe->hasHeader('Strict-Transport-Security'));
        $this->assertFalse($probe->hasHeader('Content-Security-Policy'));
        $this->assertNull($probe->header('Content-Security-Policy'));
        $this->assertSame([], $probe->headerValues('Content-Security-Policy'));
    }

    /** @test */
    #[Test]
    public function it_describes_what_a_captured_response_was(): void
    {
        $this->assertSame(
            'https://example.com/: connected (2xx) HTTP 200',
            $this->connected('https://example.com', 200)->describe()
        );

        $this->assertSame(
            'https://example.com/: connected (non-2xx) HTTP 503',
            $this->connected('https://example.com', 503)->describe()
        );
    }

    /** @test */
    #[Test]
    public function it_describes_a_redirect_off_host_with_where_it_went(): void
    {
        $probe = new OriginProbeResult(
            declaredOrigin: new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL]),
            probedUrl: 'https://example.com/',
            outcome: OriginOutcome::RedirectedOffHost,
            statusCode: 302,
            redirectLocation: 'https://elsewhere.test/',
        );

        $this->assertSame(
            'https://example.com/: redirected off host HTTP 302 to https://elsewhere.test/',
            $probe->describe()
        );
    }

    /** @test */
    #[Test]
    public function it_describes_a_failure_with_the_reason_it_failed(): void
    {
        $probe = new OriginProbeResult(
            declaredOrigin: new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL]),
            probedUrl: 'https://example.com/',
            outcome: OriginOutcome::DnsFailure,
            failureMessage: 'cURL error 6: Could not resolve host',
        );

        $this->assertSame(
            'https://example.com/: DNS failure: cURL error 6: Could not resolve host',
            $probe->describe()
        );
    }

    /** @test */
    #[Test]
    public function it_describes_a_failure_that_carried_no_message(): void
    {
        $probe = new OriginProbeResult(
            declaredOrigin: new DeclaredOrigin('https://example.com'),
            probedUrl: 'https://example.com/',
            outcome: OriginOutcome::TransportFailure,
        );

        $this->assertSame('https://example.com/: transport failure', $probe->describe());
    }

    /** @test */
    #[Test]
    public function only_connected_outcomes_count_as_evidence(): void
    {
        $evidence = [OriginOutcome::Connected2xx, OriginOutcome::ConnectedNon2xx, OriginOutcome::RedirectedOffHost];

        foreach (OriginOutcome::cases() as $outcome) {
            $this->assertSame(
                in_array($outcome, $evidence, true),
                $outcome->hasEvidence(),
                "{$outcome->value} reported the wrong evidence state"
            );
            $this->assertNotSame('', $outcome->label());
        }
    }

    /** @test */
    #[Test]
    public function a_declaration_reports_its_host_and_its_sources(): void
    {
        $origin = new DeclaredOrigin('https://example.com:8443', [DeclaredOrigin::SOURCE_APP_URL]);

        $this->assertSame('example.com', $origin->host());
        $this->assertSame('app.url', $origin->describeSources());
        $this->assertSame('an unnamed declaration', (new DeclaredOrigin('https://example.com'))->describeSources());
        $this->assertSame('', (new DeclaredOrigin('not-a-url'))->host());
    }

    /**
     * A failure that carried no message still has to produce a finding that names the
     * outcome. Reporting an empty reason would leave the reader unable to tell an
     * unreachable origin from a reached one.
     */
    /** @test */
    #[Test]
    public function a_report_states_the_outcome_when_a_failure_carried_no_message(): void
    {
        $report = new OriginReachabilityReport([
            new OriginProbeResult(
                declaredOrigin: new DeclaredOrigin('https://example.com', [DeclaredOrigin::SOURCE_APP_URL]),
                probedUrl: 'https://example.com/',
                outcome: OriginOutcome::TransportFailure,
            ),
        ]);

        $findings = $report->findings();

        $this->assertCount(1, $findings);
        $this->assertSame(
            'https://example.com (declared by app.url) could not be reached: transport failure. No evidence was obtained about this origin.',
            $findings[0]
        );
        $this->assertSame(Status::Warning, $report->status());
    }

    /** @test */
    #[Test]
    public function a_report_summarises_how_many_origins_answered(): void
    {
        $empty = new OriginReachabilityReport([]);
        $this->assertSame('No declared origin to probe; no evidence obtained.', $empty->message());
        $this->assertNull($empty->environment());

        $one = new OriginReachabilityReport([$this->connected('https://example.com', 200)]);
        $this->assertSame('Probed 1 declared origin; 1 answered.', $one->message());

        $two = new OriginReachabilityReport([
            $this->connected('https://example.com', 200),
            new OriginProbeResult(
                declaredOrigin: new DeclaredOrigin('https://cdn.example.net'),
                probedUrl: 'https://cdn.example.net/',
                outcome: OriginOutcome::Timeout,
            ),
        ]);
        $this->assertSame('Probed 2 declared origins; 1 answered.', $two->message());
        $this->assertNull($two->probeFor('https://nowhere.test'));
    }

    /**
     * The summary has to account for a declaration that never became a probe, or the count
     * it reports silently omits the part of the configuration that is broken.
     */
    /** @test */
    #[Test]
    public function a_report_counts_declarations_that_could_not_be_probed(): void
    {
        $noneResolved = new OriginReachabilityReport([], null, [DeclaredOrigin::SOURCE_APP_URL]);

        $this->assertSame('No declared origin could be probed; no evidence obtained.', $noneResolved->message());
        $this->assertSame([DeclaredOrigin::SOURCE_APP_URL], $noneResolved->unusableDeclarations());

        $oneOfEach = new OriginReachabilityReport(
            [$this->connected('https://example.com', 200)],
            null,
            [DeclaredOrigin::SOURCE_ASSET_URL]
        );

        $this->assertSame(
            'Probed 1 declared origin; 1 answered. 1 further declaration is unusable.',
            $oneOfEach->message()
        );

        $several = new OriginReachabilityReport(
            [$this->connected('https://example.com', 200)],
            null,
            [DeclaredOrigin::SOURCE_APP_URL, DeclaredOrigin::SOURCE_ASSET_URL]
        );

        $this->assertSame(
            'Probed 1 declared origin; 1 answered. 2 further declarations are unusable.',
            $several->message()
        );
    }

    /**
     * An origin that answered alongside a declaration that could not be parsed is still not
     * a pass: the broken declaration is its own finding, and the status follows the findings.
     */
    /** @test */
    #[Test]
    public function a_reachable_origin_does_not_excuse_a_broken_declaration(): void
    {
        $report = new OriginReachabilityReport(
            [$this->connected('https://example.com', 200)],
            null,
            [DeclaredOrigin::SOURCE_ASSET_URL]
        );

        $findings = $report->findings();

        $this->assertCount(1, $findings);
        $this->assertSame(
            'app.asset_url is set to a value that is not a usable http or https origin, so it could not be probed and no evidence was obtained about it.',
            $findings[0]
        );
        $this->assertSame(Status::Warning, $report->status());
    }
}
