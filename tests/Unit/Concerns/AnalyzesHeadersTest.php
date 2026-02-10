<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Concerns\AnalyzesHeaders;
use ShieldCI\Tests\TestCase;

class AnalyzesHeadersTest extends TestCase
{
    #[Test]
    public function it_can_set_and_get_client(): void
    {
        $class = new class
        {
            use AnalyzesHeaders;

            public function publicGetClient(): Client
            {
                return $this->getClient();
            }
        };

        $mockClient = new Client;
        $class->setClient($mockClient);

        $this->assertSame($mockClient, $class->publicGetClient());
    }

    #[Test]
    public function it_creates_default_client_if_not_set(): void
    {
        $class = new class
        {
            use AnalyzesHeaders;

            public function publicGetClient(): Client
            {
                return $this->getClient();
            }
        };

        $client = $class->publicGetClient();

        $this->assertInstanceOf(Client::class, $client);
    }

    #[Test]
    public function it_detects_header_exists_on_url(): void
    {
        $mock = new MockHandler([
            new Response(200, ['X-Custom-Header' => 'value']),
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $class = new class
        {
            use AnalyzesHeaders;

            public function publicHeaderExistsOnUrl(?string $url, string|array $headers, array $options = []): bool
            {
                return $this->headerExistsOnUrl($url, $headers, $options);
            }
        };

        $class->setClient($client);

        $this->assertTrue($class->publicHeaderExistsOnUrl('https://example.com', 'X-Custom-Header'));
    }

    #[Test]
    public function it_detects_header_does_not_exist_on_url(): void
    {
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'text/html']),
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $class = new class
        {
            use AnalyzesHeaders;

            public function publicHeaderExistsOnUrl(?string $url, string|array $headers, array $options = []): bool
            {
                return $this->headerExistsOnUrl($url, $headers, $options);
            }
        };

        $class->setClient($client);

        $this->assertFalse($class->publicHeaderExistsOnUrl('https://example.com', 'X-Custom-Header'));
    }

    #[Test]
    public function it_checks_multiple_headers(): void
    {
        $mock = new MockHandler([
            new Response(200, ['Strict-Transport-Security' => 'max-age=31536000']),
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $class = new class
        {
            use AnalyzesHeaders;

            public function publicHeaderExistsOnUrl(?string $url, string|array $headers, array $options = []): bool
            {
                return $this->headerExistsOnUrl($url, $headers, $options);
            }
        };

        $class->setClient($client);

        // Returns true if ANY of the headers exist
        $this->assertTrue($class->publicHeaderExistsOnUrl(
            'https://example.com',
            ['X-Not-Present', 'Strict-Transport-Security']
        ));
    }

    #[Test]
    public function it_returns_false_for_null_url(): void
    {
        $class = new class
        {
            use AnalyzesHeaders;

            public function publicHeaderExistsOnUrl(?string $url, string|array $headers, array $options = []): bool
            {
                return $this->headerExistsOnUrl($url, $headers, $options);
            }
        };

        $this->assertFalse($class->publicHeaderExistsOnUrl(null, 'X-Header'));
    }

    #[Test]
    public function it_gets_headers_on_url(): void
    {
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json']),
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $class = new class
        {
            use AnalyzesHeaders;

            /**
             * @return array<int, string>
             */
            public function publicGetHeadersOnUrl(?string $url, string $header, array $options = []): array
            {
                return $this->getHeadersOnUrl($url, $header, $options);
            }
        };

        $class->setClient($client);

        $headers = $class->publicGetHeadersOnUrl('https://example.com', 'Content-Type');

        $this->assertIsArray($headers);
        $this->assertContains('application/json', $headers);
    }

    #[Test]
    public function it_returns_empty_array_for_missing_header(): void
    {
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'text/html']),
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $class = new class
        {
            use AnalyzesHeaders;

            /**
             * @return array<int, string>
             */
            public function publicGetHeadersOnUrl(?string $url, string $header, array $options = []): array
            {
                return $this->getHeadersOnUrl($url, $header, $options);
            }
        };

        $class->setClient($client);

        $headers = $class->publicGetHeadersOnUrl('https://example.com', 'X-Not-Present');

        $this->assertIsArray($headers);
        $this->assertEmpty($headers);
    }

    #[Test]
    public function it_returns_empty_array_for_null_url_in_get_headers(): void
    {
        $class = new class
        {
            use AnalyzesHeaders;

            /**
             * @return array<int, string>
             */
            public function publicGetHeadersOnUrl(?string $url, string $header, array $options = []): array
            {
                return $this->getHeadersOnUrl($url, $header, $options);
            }
        };

        $headers = $class->publicGetHeadersOnUrl(null, 'X-Header');

        $this->assertIsArray($headers);
        $this->assertEmpty($headers);
    }

    #[Test]
    public function it_returns_false_on_connection_exception(): void
    {
        $mock = new MockHandler([
            new \GuzzleHttp\Exception\ConnectException(
                'Connection refused',
                new \GuzzleHttp\Psr7\Request('GET', 'https://example.com')
            ),
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $class = new class
        {
            use AnalyzesHeaders;

            public function publicHeaderExistsOnUrl(?string $url, string|array $headers, array $options = []): bool
            {
                return $this->headerExistsOnUrl($url, $headers, $options);
            }
        };

        $class->setClient($client);

        $this->assertFalse($class->publicHeaderExistsOnUrl('https://example.com', 'X-Header'));
    }

    #[Test]
    public function it_supports_legacy_set_http_client_method(): void
    {
        $class = new class
        {
            use AnalyzesHeaders;

            public function publicGetClient(): Client
            {
                return $this->getClient();
            }
        };

        $mockClient = new Client;
        $class->setHttpClient($mockClient);

        $this->assertSame($mockClient, $class->publicGetClient());
    }
}
