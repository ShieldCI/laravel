<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support\SecurityAdvisories;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\LoggerInterface;
use ShieldCI\Support\SecurityAdvisories\HttpAdvisoryFetcher;
use ShieldCI\Tests\TestCase;

class HttpAdvisoryFetcherTest extends TestCase
{
    #[Test]
    public function it_returns_empty_array_for_empty_dependencies(): void
    {
        $client = new Client;
        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([]);

        $this->assertSame([], $result);
    }

    #[Test]
    public function it_fetches_advisories_for_dependencies(): void
    {
        $responseBody = json_encode([
            'results' => [
                [
                    'vulns' => [
                        [
                            'id' => 'GHSA-1234',
                            'summary' => 'SQL Injection vulnerability',
                            'aliases' => ['CVE-2023-1234'],
                            'references' => [
                                ['url' => 'https://github.com/advisory/GHSA-1234'],
                            ],
                        ],
                    ],
                ],
            ],
        ]);

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], $responseBody),
        ]);

        $client = new Client(['handler' => HandlerStack::create($mock)]);
        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'laravel/framework' => ['version' => '9.0.0', 'time' => null],
        ]);

        $this->assertArrayHasKey('laravel/framework', $result);
        $this->assertCount(1, $result['laravel/framework']);
        $this->assertEquals('SQL Injection vulnerability', $result['laravel/framework'][0]['title']);
        $this->assertEquals('CVE-2023-1234', $result['laravel/framework'][0]['cve']);
        $this->assertEquals('https://github.com/advisory/GHSA-1234', $result['laravel/framework'][0]['link']);
    }

    #[Test]
    public function it_returns_empty_array_on_non_200_response(): void
    {
        $mock = new MockHandler([
            new Response(500, [], 'Server Error'),
        ]);

        $client = new Client(['handler' => HandlerStack::create($mock)]);
        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'laravel/framework' => ['version' => '9.0.0', 'time' => null],
        ]);

        $this->assertSame([], $result);
    }

    #[Test]
    public function it_returns_empty_array_on_invalid_json_response(): void
    {
        $mock = new MockHandler([
            new Response(200, [], 'not json'),
        ]);

        $client = new Client(['handler' => HandlerStack::create($mock)]);
        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'laravel/framework' => ['version' => '9.0.0', 'time' => null],
        ]);

        $this->assertSame([], $result);
    }

    #[Test]
    public function it_returns_empty_array_on_connection_exception(): void
    {
        $mock = new MockHandler([
            new \GuzzleHttp\Exception\ConnectException(
                'Connection refused',
                new \GuzzleHttp\Psr7\Request('POST', 'https://api.osv.dev/v1/querybatch')
            ),
        ]);

        $client = new Client(['handler' => HandlerStack::create($mock)]);
        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'laravel/framework' => ['version' => '9.0.0', 'time' => null],
        ]);

        $this->assertSame([], $result);
    }

    #[Test]
    public function it_logs_failure_when_logger_is_provided(): void
    {
        $mock = new MockHandler([
            new \GuzzleHttp\Exception\ConnectException(
                'Connection refused',
                new \GuzzleHttp\Psr7\Request('POST', 'https://api.osv.dev/v1/querybatch')
            ),
        ]);

        $client = new Client(['handler' => HandlerStack::create($mock)]);
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('warning')
            ->once()
            ->with(\Mockery::pattern('/Failed to fetch security advisories/'));

        $fetcher = new HttpAdvisoryFetcher($client, $logger);

        $fetcher->fetch([
            'laravel/framework' => ['version' => '9.0.0', 'time' => null],
        ]);
    }

    #[Test]
    public function it_skips_dependencies_with_invalid_data(): void
    {
        $responseBody = json_encode(['results' => []]);
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], $responseBody),
        ]);

        $client = new Client(['handler' => HandlerStack::create($mock)]);
        $fetcher = new HttpAdvisoryFetcher($client);

        // Empty package name, missing version
        $result = $fetcher->fetch([
            '' => ['version' => '1.0.0', 'time' => null],
            'valid/package' => ['time' => null], // missing version
        ]);

        $this->assertSame([], $result);
    }

    #[Test]
    public function it_handles_response_without_results_key(): void
    {
        $mock = new MockHandler([
            new Response(200, [], json_encode(['data' => []])),
        ]);

        $client = new Client(['handler' => HandlerStack::create($mock)]);
        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'laravel/framework' => ['version' => '9.0.0', 'time' => null],
        ]);

        $this->assertSame([], $result);
    }

    #[Test]
    public function it_handles_vulns_without_aliases_or_references(): void
    {
        $responseBody = json_encode([
            'results' => [
                [
                    'vulns' => [
                        [
                            'id' => 'OSV-2023-1',
                            'summary' => 'Some vulnerability',
                        ],
                    ],
                ],
            ],
        ]);

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], $responseBody),
        ]);

        $client = new Client(['handler' => HandlerStack::create($mock)]);
        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'test/package' => ['version' => '1.0.0', 'time' => null],
        ]);

        $this->assertArrayHasKey('test/package', $result);
        $this->assertNull($result['test/package'][0]['cve']);
        $this->assertNull($result['test/package'][0]['link']);
    }

    #[Test]
    public function it_returns_empty_array_on_non_200_status_like_204(): void
    {
        $mock = new MockHandler([
            new Response(204, [], ''),
        ]);

        $client = new Client(['handler' => HandlerStack::create($mock)]);
        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'laravel/framework' => ['version' => '9.0.0', 'time' => null],
        ]);

        $this->assertSame([], $result);
    }

    #[Test]
    public function it_skips_results_without_matching_query_index(): void
    {
        // Send 1 package but mock response has 2 result entries
        $responseBody = json_encode([
            'results' => [
                ['vulns' => [['id' => 'V1', 'summary' => 'Vuln for package one']]],
                ['vulns' => [['id' => 'V2', 'summary' => 'No matching query']]],
            ],
        ]);

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], $responseBody),
        ]);

        $client = new Client(['handler' => HandlerStack::create($mock)]);
        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'package/one' => ['version' => '1.0.0', 'time' => null],
        ]);

        // Only the first result should be mapped (index 0)
        $this->assertArrayHasKey('package/one', $result);
        $this->assertCount(1, $result['package/one']);
    }

    #[Test]
    public function it_skips_non_array_vuln_entries(): void
    {
        $responseBody = json_encode([
            'results' => [
                [
                    'vulns' => [
                        'string-not-array',
                        ['id' => 'V1', 'summary' => 'Real vulnerability'],
                    ],
                ],
            ],
        ]);

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], $responseBody),
        ]);

        $client = new Client(['handler' => HandlerStack::create($mock)]);
        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'test/package' => ['version' => '1.0.0', 'time' => null],
        ]);

        $this->assertArrayHasKey('test/package', $result);
        $this->assertCount(1, $result['test/package']);
        $this->assertEquals('Real vulnerability', $result['test/package'][0]['title']);
    }

    #[Test]
    public function it_handles_multiple_packages(): void
    {
        $responseBody = json_encode([
            'results' => [
                ['vulns' => [['id' => 'V1', 'summary' => 'Vuln 1']]],
                [], // No vulns for second package
            ],
        ]);

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], $responseBody),
        ]);

        $client = new Client(['handler' => HandlerStack::create($mock)]);
        $fetcher = new HttpAdvisoryFetcher($client);

        $result = $fetcher->fetch([
            'package/one' => ['version' => '1.0.0', 'time' => null],
            'package/two' => ['version' => '2.0.0', 'time' => null],
        ]);

        $this->assertArrayHasKey('package/one', $result);
        $this->assertArrayNotHasKey('package/two', $result);
    }
}
