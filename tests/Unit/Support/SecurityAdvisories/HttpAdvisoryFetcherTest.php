<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support\SecurityAdvisories;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\LoggerInterface;
use ShieldCI\Support\SecurityAdvisories\HttpAdvisoryFetcher;
use ShieldCI\Tests\TestCase;

class HttpAdvisoryFetcherTest extends TestCase
{
    /**
     * Build a client whose handler replays the given queued responses in order.
     * The fetcher first POSTs to querybatch, then issues one GET /v1/vulns/{id}
     * per unique vuln id, so tests queue a batch response followed by hydrations.
     *
     * @param  array<int, Response|ConnectException>  $responses
     */
    private function clientReturning(array $responses): Client
    {
        return new Client(['handler' => HandlerStack::create(new MockHandler($responses))]);
    }

    private function encode(mixed $payload): string
    {
        return (string) json_encode($payload);
    }

    /** @test */
    #[Test]
    public function it_returns_empty_array_for_empty_dependencies(): void
    {
        $fetcher = new HttpAdvisoryFetcher(new Client);

        $result = $fetcher->fetch([]);

        $this->assertSame([], $result);
    }

    /** @test */
    #[Test]
    public function it_fetches_and_hydrates_advisories_for_dependencies(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode([
                'results' => [
                    ['vulns' => [['id' => 'GHSA-1234', 'modified' => '2024-01-01T00:00:00Z']]],
                ],
            ])),
            new Response(200, [], $this->encode([
                'id' => 'GHSA-1234',
                'summary' => 'SQL Injection vulnerability',
                'aliases' => ['CVE-2023-1234'],
                'references' => [['type' => 'WEB', 'url' => 'https://github.com/advisory/GHSA-1234']],
                'affected' => [[
                    'package' => ['ecosystem' => 'Packagist', 'name' => 'laravel/framework'],
                    'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '9.1.0']]]],
                ]],
            ])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'laravel/framework' => ['version' => '9.0.0', 'time' => null],
        ]);

        $this->assertArrayHasKey('laravel/framework', $result);
        $this->assertCount(1, $result['laravel/framework']);
        $this->assertEquals('SQL Injection vulnerability', $result['laravel/framework'][0]['title']);
        $this->assertEquals('CVE-2023-1234', $result['laravel/framework'][0]['cve']);
        $this->assertEquals('https://github.com/advisory/GHSA-1234', $result['laravel/framework'][0]['link']);
        $this->assertEquals(['<9.1.0'], $result['laravel/framework'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_reports_the_advisory_range_not_the_installed_version(): void
    {
        // Regression for #308: affected_versions must be the real OSV range, not an
        // echo of the installed version.
        $client = $this->clientReturning([
            new Response(200, [], $this->encode([
                'results' => [
                    ['vulns' => [['id' => 'GHSA-h95v-h523-3mw8', 'modified' => '2024-01-01T00:00:00Z']]],
                ],
            ])),
            new Response(200, [], $this->encode([
                'id' => 'GHSA-h95v-h523-3mw8',
                'summary' => 'Change in port should be considered a change in origin',
                'aliases' => ['CVE-2024-99999'],
                'references' => [['type' => 'ADVISORY', 'url' => 'https://github.com/guzzle/guzzle/security/advisories/GHSA-h95v-h523-3mw8']],
                'affected' => [[
                    'package' => ['ecosystem' => 'Packagist', 'name' => 'guzzlehttp/guzzle'],
                    'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '7.15.1']]]],
                ]],
            ])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'guzzlehttp/guzzle' => ['version' => '7.15.0', 'time' => null],
        ]);

        $advisory = $result['guzzlehttp/guzzle'][0];
        $this->assertNotSame(['7.15.0'], $advisory['affected_versions']);
        $this->assertContains('<7.15.1', $advisory['affected_versions']);
        $this->assertEquals('CVE-2024-99999', $advisory['cve']);
    }

    /** @test */
    #[Test]
    public function it_builds_compound_range_from_bounded_events(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode([
                'results' => [['vulns' => [['id' => 'GHSA-bound']]]],
            ])),
            new Response(200, [], $this->encode([
                'id' => 'GHSA-bound',
                'summary' => 'Bounded range',
                'affected' => [[
                    'package' => ['ecosystem' => 'Packagist', 'name' => 'vendor/pkg'],
                    'ranges' => [['type' => 'SEMVER', 'events' => [['introduced' => '2.0.0'], ['fixed' => '2.5.0']]]],
                ]],
            ])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'vendor/pkg' => ['version' => '2.3.0', 'time' => null],
        ]);

        $this->assertEquals(['>=2.0.0,<2.5.0'], $result['vendor/pkg'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_prefers_the_compact_range_over_explicit_versions(): void
    {
        // OSV records often carry BOTH a huge versions[] enumeration and a compact
        // range; only the range should surface as metadata.
        $client = $this->clientReturning([
            new Response(200, [], $this->encode([
                'results' => [['vulns' => [['id' => 'GHSA-both']]]],
            ])),
            new Response(200, [], $this->encode([
                'id' => 'GHSA-both',
                'summary' => 'Both forms present',
                'affected' => [[
                    'package' => ['ecosystem' => 'Packagist', 'name' => 'vendor/pkg'],
                    'versions' => ['3.1.0', '3.1.1', '3.1.2', '3.1.3', '3.1.4', '3.1.5'],
                    'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '3.1.6']]]],
                ]],
            ])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'vendor/pkg' => ['version' => '3.1.5', 'time' => null],
        ]);

        $this->assertEquals(['<3.1.6'], $result['vendor/pkg'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_falls_back_to_explicit_versions_without_a_range(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode([
                'results' => [['vulns' => [['id' => 'GHSA-versions-only']]]],
            ])),
            new Response(200, [], $this->encode([
                'id' => 'GHSA-versions-only',
                'summary' => 'Explicit versions only',
                'affected' => [[
                    'package' => ['ecosystem' => 'Packagist', 'name' => 'vendor/pkg'],
                    'versions' => ['1.0.0', '1.0.1'],
                ]],
            ])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'vendor/pkg' => ['version' => '1.0.0', 'time' => null],
        ]);

        $this->assertEquals(['1.0.0', '1.0.1'], $result['vendor/pkg'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_ignores_affected_entries_for_other_ecosystems(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode([
                'results' => [['vulns' => [['id' => 'GHSA-multi']]]],
            ])),
            new Response(200, [], $this->encode([
                'id' => 'GHSA-multi',
                'summary' => 'Multi-ecosystem advisory',
                'affected' => [
                    [
                        'package' => ['ecosystem' => 'npm', 'name' => 'guzzle-js'],
                        'ranges' => [['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '99.0.0']]]],
                    ],
                    [
                        'package' => ['ecosystem' => 'Packagist', 'name' => 'guzzlehttp/guzzle'],
                        'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '7.15.1']]]],
                    ],
                ],
            ])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'guzzlehttp/guzzle' => ['version' => '7.15.0', 'time' => null],
        ]);

        // Only the Packagist range is kept; the npm "<99.0.0" is discarded.
        $this->assertEquals(['<7.15.1'], $result['guzzlehttp/guzzle'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_fails_open_when_hydration_fails(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode([
                'results' => [['vulns' => [['id' => 'GHSA-FAIL', 'modified' => '2024-01-01T00:00:00Z']]]],
            ])),
            new Response(500, [], 'Server Error'),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'vendor/pkg' => ['version' => '1.0.0', 'time' => null],
        ]);

        // The advisory is still reported (OSV confirmed the hit); details are minimal.
        $this->assertArrayHasKey('vendor/pkg', $result);
        $this->assertEquals('GHSA-FAIL', $result['vendor/pkg'][0]['title']);
        $this->assertNull($result['vendor/pkg'][0]['cve']);
        $this->assertNull($result['vendor/pkg'][0]['link']);
        $this->assertSame([], $result['vendor/pkg'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_deduplicates_shared_vuln_ids_across_packages(): void
    {
        // Two packages reference the same advisory id; it must be hydrated once and
        // served to both (only one GET response is queued).
        $client = $this->clientReturning([
            new Response(200, [], $this->encode([
                'results' => [
                    ['vulns' => [['id' => 'GHSA-shared']]],
                    ['vulns' => [['id' => 'GHSA-shared']]],
                ],
            ])),
            new Response(200, [], $this->encode([
                'id' => 'GHSA-shared',
                'summary' => 'Shared advisory',
            ])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'vendor/one' => ['version' => '1.0.0', 'time' => null],
            'vendor/two' => ['version' => '1.0.0', 'time' => null],
        ]);

        $this->assertEquals('Shared advisory', $result['vendor/one'][0]['title']);
        $this->assertEquals('Shared advisory', $result['vendor/two'][0]['title']);
    }

    /** @test */
    #[Test]
    public function it_returns_empty_array_on_non_200_response(): void
    {
        $fetcher = new HttpAdvisoryFetcher($this->clientReturning([new Response(500, [], 'Server Error')]));

        $result = $fetcher->fetch(['laravel/framework' => ['version' => '9.0.0', 'time' => null]]);

        $this->assertSame([], $result);
    }

    /** @test */
    #[Test]
    public function it_returns_empty_array_on_invalid_json_response(): void
    {
        $fetcher = new HttpAdvisoryFetcher($this->clientReturning([new Response(200, [], 'not json')]));

        $result = $fetcher->fetch(['laravel/framework' => ['version' => '9.0.0', 'time' => null]]);

        $this->assertSame([], $result);
    }

    /** @test */
    #[Test]
    public function it_returns_empty_array_on_connection_exception(): void
    {
        $fetcher = new HttpAdvisoryFetcher($this->clientReturning([
            new ConnectException('Connection refused', new Request('POST', 'https://api.osv.dev/v1/querybatch')),
        ]));

        $result = $fetcher->fetch(['laravel/framework' => ['version' => '9.0.0', 'time' => null]]);

        $this->assertSame([], $result);
    }

    /** @test */
    #[Test]
    public function it_logs_failure_when_logger_is_provided(): void
    {
        $client = $this->clientReturning([
            new ConnectException('Connection refused', new Request('POST', 'https://api.osv.dev/v1/querybatch')),
        ]);

        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('warning')
            ->once()
            ->with(\Mockery::pattern('/Failed to fetch security advisories/'));

        $fetcher = new HttpAdvisoryFetcher($client, $logger);

        $fetcher->fetch(['laravel/framework' => ['version' => '9.0.0', 'time' => null]]);
    }

    /** @test */
    #[Test]
    public function it_skips_dependencies_with_invalid_data(): void
    {
        $fetcher = new HttpAdvisoryFetcher($this->clientReturning([new Response(200, [], $this->encode(['results' => []]))]));

        // Empty package name and missing version both produce no query.
        $result = $fetcher->fetch([
            '' => ['version' => '1.0.0', 'time' => null],
            'valid/package' => ['time' => null],
        ]);

        $this->assertSame([], $result);
    }

    /** @test */
    #[Test]
    public function it_handles_response_without_results_key(): void
    {
        $fetcher = new HttpAdvisoryFetcher($this->clientReturning([new Response(200, [], $this->encode(['data' => []]))]));

        $result = $fetcher->fetch(['laravel/framework' => ['version' => '9.0.0', 'time' => null]]);

        $this->assertSame([], $result);
    }

    /** @test */
    #[Test]
    public function it_handles_vulns_without_aliases_or_references(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode(['results' => [['vulns' => [['id' => 'OSV-2023-1']]]]])),
            new Response(200, [], $this->encode(['id' => 'OSV-2023-1', 'summary' => 'Some vulnerability'])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch(['test/package' => ['version' => '1.0.0', 'time' => null]]);

        $this->assertArrayHasKey('test/package', $result);
        $this->assertEquals('Some vulnerability', $result['test/package'][0]['title']);
        $this->assertNull($result['test/package'][0]['cve']);
        $this->assertNull($result['test/package'][0]['link']);
        $this->assertSame([], $result['test/package'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_returns_empty_array_on_non_200_status_like_204(): void
    {
        $fetcher = new HttpAdvisoryFetcher($this->clientReturning([new Response(204, [], '')]));

        $result = $fetcher->fetch(['laravel/framework' => ['version' => '9.0.0', 'time' => null]]);

        $this->assertSame([], $result);
    }

    /** @test */
    #[Test]
    public function it_skips_results_without_matching_query_index(): void
    {
        // One package queried, but the batch returns two result entries. The second
        // has no matching query, so it is neither hydrated nor mapped.
        $client = $this->clientReturning([
            new Response(200, [], $this->encode([
                'results' => [
                    ['vulns' => [['id' => 'V1']]],
                    ['vulns' => [['id' => 'V2']]],
                ],
            ])),
            new Response(200, [], $this->encode(['id' => 'V1', 'summary' => 'Vuln for package one'])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch(['package/one' => ['version' => '1.0.0', 'time' => null]]);

        $this->assertArrayHasKey('package/one', $result);
        $this->assertCount(1, $result['package/one']);
        $this->assertEquals('Vuln for package one', $result['package/one'][0]['title']);
    }

    /** @test */
    #[Test]
    public function it_skips_non_array_vuln_entries(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode([
                'results' => [['vulns' => ['string-not-array', ['id' => 'V1']]]],
            ])),
            new Response(200, [], $this->encode(['id' => 'V1', 'summary' => 'Real vulnerability'])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch(['test/package' => ['version' => '1.0.0', 'time' => null]]);

        $this->assertArrayHasKey('test/package', $result);
        $this->assertCount(1, $result['test/package']);
        $this->assertEquals('Real vulnerability', $result['test/package'][0]['title']);
    }

    /** @test */
    #[Test]
    public function it_parses_last_affected_and_open_ended_ranges(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode(['results' => [['vulns' => [['id' => 'GHSA-mix']]]]])),
            new Response(200, [], $this->encode([
                'id' => 'GHSA-mix',
                'summary' => 'Mixed events',
                'affected' => [[
                    'package' => ['ecosystem' => 'Packagist', 'name' => 'vendor/pkg'],
                    'ranges' => [['type' => 'SEMVER', 'events' => [
                        ['introduced' => '1.0.0'],
                        ['last_affected' => '1.5.0'],
                        ['introduced' => '2.0.0'],
                    ]]],
                ]],
            ])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch(['vendor/pkg' => ['version' => '1.2.0', 'time' => null]]);

        $this->assertEquals(['>=1.0.0,<=1.5.0', '>=2.0.0'], $result['vendor/pkg'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_represents_an_unfixed_from_zero_range_as_wildcard(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode(['results' => [['vulns' => [['id' => 'GHSA-open']]]]])),
            new Response(200, [], $this->encode([
                'id' => 'GHSA-open',
                'summary' => 'No fix yet',
                'affected' => [[
                    'package' => ['ecosystem' => 'Packagist', 'name' => 'vendor/pkg'],
                    'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0']]]],
                ]],
            ])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch(['vendor/pkg' => ['version' => '5.0.0', 'time' => null]]);

        $this->assertEquals(['*'], $result['vendor/pkg'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_skips_git_ranges_and_malformed_range_data(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode(['results' => [['vulns' => [['id' => 'GHSA-junk']]]]])),
            new Response(200, [], $this->encode([
                'id' => 'GHSA-junk',
                'summary' => 'Ranges with junk',
                'affected' => [[
                    'package' => ['ecosystem' => 'Packagist', 'name' => 'vendor/pkg'],
                    'ranges' => [
                        'not-a-range-array',
                        ['type' => 'GIT', 'events' => [['introduced' => '0'], ['fixed' => 'abc123']]],
                        ['type' => 'SEMVER'], // no events
                        ['type' => 'SEMVER', 'events' => [
                            'not-an-event',
                            ['introduced' => '0'],
                            ['fixed' => ''],   // empty upper bound is dropped
                            ['fixed' => '1.0.0'],
                        ]],
                    ],
                ]],
            ])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch(['vendor/pkg' => ['version' => '0.9.0', 'time' => null]]);

        $this->assertEquals(['<1.0.0'], $result['vendor/pkg'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_includes_affected_entries_without_a_package_block(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode(['results' => [['vulns' => [['id' => 'GHSA-nopkg']]]]])),
            new Response(200, [], $this->encode([
                'id' => 'GHSA-nopkg',
                'summary' => 'No package block',
                'affected' => [[
                    'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '2.0.0']]]],
                ]],
            ])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch(['vendor/pkg' => ['version' => '1.0.0', 'time' => null]]);

        $this->assertEquals(['<2.0.0'], $result['vendor/pkg'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_excludes_affected_entries_with_a_mismatched_package_name(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode(['results' => [['vulns' => [['id' => 'GHSA-name']]]]])),
            new Response(200, [], $this->encode([
                'id' => 'GHSA-name',
                'summary' => 'Same ecosystem, different package',
                'affected' => [
                    [
                        'package' => ['ecosystem' => 'Packagist', 'name' => 'other/pkg'],
                        'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '99.0.0']]]],
                    ],
                    [
                        'package' => ['ecosystem' => 'Packagist', 'name' => 'vendor/pkg'],
                        'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '2.0.0']]]],
                    ],
                ],
            ])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch(['vendor/pkg' => ['version' => '1.0.0', 'time' => null]]);

        $this->assertEquals(['<2.0.0'], $result['vendor/pkg'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_fails_open_on_non_200_vuln_response(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode(['results' => [['vulns' => [['id' => 'GHSA-204']]]]])),
            new Response(204, [], ''),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch(['vendor/pkg' => ['version' => '1.0.0', 'time' => null]]);

        $this->assertEquals('GHSA-204', $result['vendor/pkg'][0]['title']);
        $this->assertSame([], $result['vendor/pkg'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_fails_open_on_invalid_vuln_json(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode(['results' => [['vulns' => [['id' => 'GHSA-bad']]]]])),
            new Response(200, [], 'not json'),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch(['vendor/pkg' => ['version' => '1.0.0', 'time' => null]]);

        $this->assertEquals('GHSA-bad', $result['vendor/pkg'][0]['title']);
        $this->assertSame([], $result['vendor/pkg'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_derives_the_vuln_url_from_a_non_querybatch_source(): void
    {
        // A source URL without "querybatch" falls back to the default vulns endpoint.
        $client = $this->clientReturning([
            new Response(200, [], $this->encode(['results' => [['vulns' => [['id' => 'GHSA-src']]]]])),
            new Response(200, [], $this->encode(['id' => 'GHSA-src', 'summary' => 'Derived source'])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client, null, 'https://osv.example/scan');

        $result = $fetcher->fetch(['vendor/pkg' => ['version' => '1.0.0', 'time' => null]]);

        $this->assertEquals('Derived source', $result['vendor/pkg'][0]['title']);
    }

    /** @test */
    #[Test]
    public function it_honours_an_explicit_vuln_url(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode(['results' => [['vulns' => [['id' => 'GHSA-explicit']]]]])),
            new Response(200, [], $this->encode(['id' => 'GHSA-explicit', 'summary' => 'Explicit URL'])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client, null, HttpAdvisoryFetcher::DEFAULT_SOURCE, 10, 'https://osv.example/vulns');

        $result = $fetcher->fetch(['vendor/pkg' => ['version' => '1.0.0', 'time' => null]]);

        $this->assertEquals('Explicit URL', $result['vendor/pkg'][0]['title']);
    }

    /** @test */
    #[Test]
    public function it_handles_multiple_packages(): void
    {
        $client = $this->clientReturning([
            new Response(200, [], $this->encode([
                'results' => [
                    ['vulns' => [['id' => 'V1']]],
                    [], // No vulns for the second package.
                ],
            ])),
            new Response(200, [], $this->encode(['id' => 'V1', 'summary' => 'Vuln 1'])),
        ]);

        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'package/one' => ['version' => '1.0.0', 'time' => null],
            'package/two' => ['version' => '2.0.0', 'time' => null],
        ]);

        $this->assertArrayHasKey('package/one', $result);
        $this->assertArrayNotHasKey('package/two', $result);
    }
}
