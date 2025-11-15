<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Filesystem\Filesystem;
use ShieldCI\Analyzers\Performance\CacheHeaderAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CacheHeaderAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<\Psr\Http\Message\ResponseInterface|\Exception>  $responses
     */
    protected function createAnalyzer(array $responses = []): AnalyzerInterface
    {
        $files = new Filesystem;
        $analyzer = new CacheHeaderAnalyzer($files);

        if (! empty($responses)) {
            $mock = new MockHandler($responses);
            $handlerStack = HandlerStack::create($mock);
            $client = new Client(['handler' => $handlerStack]);
            $analyzer->setClient($client);
        }

        return $analyzer;
    }

    public function test_skips_when_no_manifest_exists(): void
    {
        $analyzer = $this->createAnalyzer();

        $this->assertFalse($analyzer->shouldRun());

        if (method_exists($analyzer, 'getSkipReason')) {
            $this->assertStringContainsString('No asset build system', $analyzer->getSkipReason());
        }
    }

    public function test_passes_when_mix_assets_have_cache_headers(): void
    {
        // Create temp directory with Mix manifest
        $manifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
            '/js/app.js' => '/js/app.js?id=def456',
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $manifest,
        ]);

        // Mock HTTP responses with Cache-Control headers
        $responses = [
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),  // mix()
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),  // mix()
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_mix_assets_missing_cache_headers(): void
    {
        // Create temp directory with Mix manifest
        $manifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
            '/js/app.js' => '/js/app.js?id=def456',
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $manifest,
        ]);

        // Mock HTTP responses WITHOUT Cache-Control headers
        $responses = [
            new Response(200),  // No Cache-Control
            new Response(200),  // No Cache-Control (fallback to asset())
            new Response(200),  // No Cache-Control
            new Response(200),  // No Cache-Control (fallback to asset())
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('missing Cache-Control headers', $result);

        // Verify uncached assets are listed
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertArrayHasKey('uncached_assets', $issues[0]->metadata);
    }

    public function test_passes_when_vite_assets_have_cache_headers(): void
    {
        // Create Vite manifest
        $manifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.abc123.js',
                'css' => [
                    'assets/app.def456.css',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => $manifest,
        ]);

        // Mock HTTP responses with Cache-Control headers
        $responses = [
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),  // JS file
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),  // CSS file
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_vite_assets_missing_cache_headers(): void
    {
        // Create Vite manifest
        $manifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.abc123.js',
                'css' => [
                    'assets/app.def456.css',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => $manifest,
        ]);

        // Mock HTTP responses WITHOUT Cache-Control headers
        $responses = [
            new Response(200),  // No Cache-Control on JS
            new Response(200),  // No Cache-Control on CSS
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('missing Cache-Control headers', $result);

        // Verify both files are listed as uncached
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        /** @var array<int, string> $uncachedAssets */
        $uncachedAssets = $issues[0]->metadata['uncached_assets'] ?? [];
        $this->assertCount(2, $uncachedAssets);
    }

    public function test_supports_both_mix_and_vite(): void
    {
        // Create both manifests
        $mixManifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
        ]);

        $viteManifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.def456.js',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $mixManifest,
            'public/build/manifest.json' => $viteManifest,
        ]);

        // Mock responses for both
        $responses = [
            new Response(200, ['Cache-Control' => 'public']),  // Mix asset
            new Response(200, ['Cache-Control' => 'public']),  // Vite asset
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('asset-cache-headers', $metadata->id);
        $this->assertEquals('Asset Cache Headers', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $metadata->severity);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(CacheHeaderAnalyzer::$runInCI);
    }
}
