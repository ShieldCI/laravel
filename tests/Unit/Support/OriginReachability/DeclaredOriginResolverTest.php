<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support\OriginReachability;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Support\OriginReachability\DeclaredOrigin;
use ShieldCI\Support\OriginReachability\DeclaredOriginResolver;
use ShieldCI\Tests\AnalyzerTestCase;

/**
 * Extends AnalyzerTestCase only for createTempDirectory(); there is no analyzer here, the
 * same way SeededTableScannerTest borrows the fixture helper.
 */
class DeclaredOriginResolverTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        throw new \LogicException('No analyzer under test.');
    }

    private function resolver(): DeclaredOriginResolver
    {
        return new DeclaredOriginResolver;
    }

    /**
     * @param  array<int, DeclaredOrigin>  $origins
     * @return array<int, string>
     */
    private function originStrings(array $origins): array
    {
        return array_map(static fn (DeclaredOrigin $origin): string => $origin->origin, $origins);
    }

    /**
     * The origins half of a resolve(), which is what most of these tests assert over.
     *
     * @return array<int, DeclaredOrigin>
     */
    private function originsFor(string $basePath, ?string $appUrl, ?string $assetUrl): array
    {
        return $this->resolver()->resolve($basePath, $appUrl, $assetUrl)['origins'];
    }

    /** @test */
    #[Test]
    public function it_resolves_the_app_url_down_to_its_origin(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $origins = $this->originsFor($basePath, 'https://example.com/app/', null);

        $this->assertCount(1, $origins);
        $this->assertSame('https://example.com', $origins[0]->origin);
        $this->assertSame([DeclaredOrigin::SOURCE_APP_URL], $origins[0]->sources);
    }

    /** @test */
    #[Test]
    public function it_elides_the_default_port_so_two_spellings_of_one_origin_collapse(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $origins = $this->originsFor($basePath, 'https://example.com', 'https://example.com:443/assets');

        $this->assertCount(1, $origins);
        $this->assertSame('https://example.com', $origins[0]->origin);
        $this->assertSame(
            [DeclaredOrigin::SOURCE_APP_URL, DeclaredOrigin::SOURCE_ASSET_URL],
            $origins[0]->sources
        );
    }

    /** @test */
    #[Test]
    public function it_keeps_a_non_default_port(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $origins = $this->originsFor($basePath, 'http://localhost:8000', null);

        $this->assertSame(['http://localhost:8000'], $this->originStrings($origins));
    }

    /** @test */
    #[Test]
    public function it_resolves_an_asset_url_on_another_host_as_its_own_origin(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $origins = $this->originsFor($basePath, 'https://example.com', 'https://cdn.example.net');

        $this->assertSame(['https://example.com', 'https://cdn.example.net'], $this->originStrings($origins));
        $this->assertSame([DeclaredOrigin::SOURCE_ASSET_URL], $origins[1]->sources);
    }

    /** @test */
    #[Test]
    public function it_reads_an_absolute_asset_origin_out_of_a_vite_manifest(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'https://cdn.example.net/build/assets/app-abc123.js',
                'isEntry' => true,
                'css' => ['https://cdn.example.net/build/assets/app-def456.css'],
            ],
        ]);

        $basePath = $this->createTempDirectory([
            'composer.json' => '{}',
            'public/build/manifest.json' => $manifest,
        ]);

        $origins = $this->originsFor($basePath, 'https://example.com', null);

        $this->assertSame(['https://example.com', 'https://cdn.example.net'], $this->originStrings($origins));
        $this->assertSame([DeclaredOrigin::SOURCE_VITE_MANIFEST], $origins[1]->sources);
    }

    /** @test */
    #[Test]
    public function it_reads_an_absolute_asset_origin_out_of_a_mix_manifest(): void
    {
        $manifest = json_encode([
            '/js/app.js' => 'https://cdn.example.net/js/app.js?id=abc123',
        ]);

        $basePath = $this->createTempDirectory([
            'composer.json' => '{}',
            'public/mix-manifest.json' => $manifest,
        ]);

        $origins = $this->originsFor($basePath, 'https://example.com', null);

        $this->assertSame(['https://example.com', 'https://cdn.example.net'], $this->originStrings($origins));
        $this->assertSame([DeclaredOrigin::SOURCE_MIX_MANIFEST], $origins[1]->sources);
    }

    /** @test */
    #[Test]
    public function it_contributes_no_origin_for_manifest_entries_that_are_relative(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => ['file' => 'assets/app-abc123.js', 'css' => ['assets/app-def456.css']],
        ]);

        $basePath = $this->createTempDirectory([
            'composer.json' => '{}',
            'public/build/manifest.json' => $manifest,
        ]);

        $origins = $this->originsFor($basePath, 'https://example.com', null);

        $this->assertSame(['https://example.com'], $this->originStrings($origins));
    }

    /**
     * public/manifest.json is one of the places a Vite build lands, and also where a PWA
     * web app manifest lives. The latter names third-party icon and start URLs that the
     * application is not served from, so it must not become a probed origin.
     */
    /** @test */
    #[Test]
    public function it_does_not_mistake_a_pwa_web_app_manifest_for_a_vite_manifest(): void
    {
        $manifest = json_encode([
            'name' => 'Example',
            'start_url' => 'https://pwa.example.net/',
            'icons' => [['src' => 'https://icons.example.net/192.png', 'sizes' => '192x192']],
        ]);

        $basePath = $this->createTempDirectory([
            'composer.json' => '{}',
            'public/manifest.json' => $manifest,
        ]);

        $origins = $this->originsFor($basePath, 'https://example.com', null);

        $this->assertSame(['https://example.com'], $this->originStrings($origins));
    }

    /** @test */
    #[Test]
    public function it_ignores_a_manifest_that_is_not_readable_json(): void
    {
        $basePath = $this->createTempDirectory([
            'composer.json' => '{}',
            'public/build/manifest.json' => '{ this is not json',
        ]);

        $origins = $this->originsFor($basePath, 'https://example.com', null);

        $this->assertSame(['https://example.com'], $this->originStrings($origins));
    }

    /** @test */
    #[Test]
    public function it_ignores_declarations_that_are_not_http_urls(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $this->assertSame([], $this->originStrings($this->originsFor($basePath, '', null)));
        $this->assertSame([], $this->originStrings($this->originsFor($basePath, 'not a url', null)));
        $this->assertSame([], $this->originStrings($this->originsFor($basePath, '/relative/path', null)));
        $this->assertSame([], $this->originStrings($this->originsFor($basePath, 'ftp://example.com', null)));
    }

    /**
     * A URL malformed enough that parse_url() refuses it outright, where a non-numeric port is
     * the everyday way to get there, usually an unsubstituted placeholder in an env file.
     * It declares no origin that can be probed, and it is reported as such rather than
     * discarded: a broken APP_URL and an absent one are different faults.
     */
    /** @test */
    #[Test]
    public function it_reports_a_declaration_that_cannot_be_parsed_at_all(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $this->assertFalse(parse_url('http://example.com:port'), 'fixture must be unparseable for this test to mean anything');

        $resolved = $this->resolver()->resolve($basePath, 'http://example.com:port', 'https://');

        $this->assertSame([], $this->originStrings($resolved['origins']));
        $this->assertSame([DeclaredOrigin::SOURCE_APP_URL, DeclaredOrigin::SOURCE_ASSET_URL], $resolved['unusable']);
    }

    /**
     * Nothing declared is itself the absence of evidence, not a pass: the resolver says so
     * by returning no origins, and the report turns that into a warning.
     */
    /** @test */
    #[Test]
    public function it_returns_no_origins_when_the_application_declares_none(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $resolved = $this->resolver()->resolve($basePath, null, null);

        $this->assertSame([], $resolved['origins']);
        $this->assertSame([], $resolved['unusable']);
    }

    /**
     * An empty string is an absent declaration, not a broken one. Treating it as unusable
     * would report a fault at every application that simply leaves ASSET_URL unset.
     */
    /** @test */
    #[Test]
    public function it_does_not_call_an_empty_declaration_unusable(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $this->assertSame([], $this->resolver()->resolve($basePath, '', '   ')['unusable']);
    }

    /**
     * A relative manifest entry is how a manifest normally looks, not a misconfiguration,
     * so it must not be reported alongside a genuinely broken APP_URL.
     */
    /** @test */
    #[Test]
    public function it_does_not_call_a_relative_manifest_entry_unusable(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => ['file' => 'assets/app-abc123.js'],
        ]);

        $basePath = $this->createTempDirectory([
            'composer.json' => '{}',
            'public/build/manifest.json' => $manifest,
        ]);

        $resolved = $this->resolver()->resolve($basePath, 'https://example.com', null);

        $this->assertSame(['https://example.com'], $this->originStrings($resolved['origins']));
        $this->assertSame([], $resolved['unusable']);
    }

    /**
     * A protocol-relative asset base names a host, so it names an origin. Dropping it would
     * leave a CDN the application is genuinely served from unprobed while the report still
     * read Passed, which is the silence-reads-as-success outcome this helper exists to stop.
     */
    /** @test */
    #[Test]
    public function it_inherits_the_app_url_scheme_for_a_protocol_relative_asset_base(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => ['file' => '//cdn.example.net/build/app-abc123.js'],
        ]);

        $basePath = $this->createTempDirectory([
            'composer.json' => '{}',
            'public/build/manifest.json' => $manifest,
        ]);

        $origins = $this->originsFor($basePath, 'http://example.com', null);

        $this->assertSame(['http://example.com', 'http://cdn.example.net'], $this->originStrings($origins));
    }

    /** @test */
    #[Test]
    public function it_falls_back_to_https_for_a_protocol_relative_declaration_when_no_scheme_is_known(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $origins = $this->originsFor($basePath, null, '//cdn.example.net/assets');

        $this->assertSame(['https://cdn.example.net'], $this->originStrings($origins));
    }
}
