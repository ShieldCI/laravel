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
    protected function createAnalyzer(array $responses = [], bool $setAppUrl = true): AnalyzerInterface
    {
        $files = new Filesystem;
        $analyzer = new CacheHeaderAnalyzer($files);

        // Allow analyzer to run in test environment
        $analyzer->setRelevantEnvironments(null);

        if ($setAppUrl) {
            $analyzer->setAppUrl('https://example.test');
        } else {
            // Explicitly set to null to prevent fallback to config('app.url')
            $analyzer->setAppUrl(null);
        }

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
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),
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
            new Response(200),
            new Response(200),
            new Response(200),
            new Response(200),
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache-Control headers', $result);

        // Verify uncached assets are listed
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertArrayHasKey('uncached_assets', $issues[0]->metadata);
        $firstAsset = $issues[0]->metadata['uncached_assets'][0];
        $this->assertEquals('/css/app.css', $firstAsset['path']);
        $this->assertEquals('mix', $firstAsset['source']);
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
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),
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
        $this->assertHasIssueContaining('Cache-Control headers', $result);

        // Verify both files are listed as uncached
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        /** @var array<int, string> $uncachedAssets */
        $uncachedAssets = $issues[0]->metadata['uncached_assets'] ?? [];
        $this->assertCount(2, $uncachedAssets);
    }

    public function test_vite_imports_reference_manifest_entries(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.abc123.js',
                'imports' => ['resources/js/chunk.js'],
            ],
            'resources/js/chunk.js' => [
                'file' => 'assets/chunk.def456.js',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => $manifest,
        ]);

        $responses = [
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_vite_import_without_cache_headers_is_reported(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.abc123.js',
                'imports' => ['resources/js/chunk.js'],
            ],
            'resources/js/chunk.js' => [
                'file' => 'assets/chunk.def456.js',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => $manifest,
        ]);

        $responses = [
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),
            new Response(200),
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $firstIssue = $issues[0];
        $this->assertArrayHasKey('uncached_assets', $firstIssue->metadata);
        $this->assertSame('build/assets/chunk.def456.js', $firstIssue->metadata['uncached_assets'][0]['path']);
    }

    public function test_vite_dynamic_imports_and_assets_are_checked(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.abc123.js',
                'dynamicImports' => ['resources/js/lazy.js'],
                'assets' => ['assets/fonts.ghi789.woff2'],
            ],
            'resources/js/lazy.js' => [
                'file' => 'assets/lazy.def456.js',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => $manifest,
        ]);

        $responses = [
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),
            new Response(200),
            new Response(200),
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $uncachedAssets = $issues[0]->metadata['uncached_assets'] ?? [];
        $paths = is_array($uncachedAssets) ? array_column($uncachedAssets, 'path') : [];
        $this->assertContains('build/assets/lazy.def456.js', $paths);
        $this->assertContains('build/assets/fonts.ghi789.woff2', $paths);
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
            new Response(200, ['Cache-Control' => 'public, max-age=3600']),
            new Response(200, ['Cache-Control' => 'public, max-age=3600']),
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

    public function test_warns_when_app_url_missing(): void
    {
        $manifest = json_encode([
            '/js/app.js' => '/js/app.js?id=123',
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $manifest,
        ]);

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer([], false);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('APP_URL is not properly configured', $result->getMessage());
    }

    public function test_detects_non_cacheable_directives(): void
    {
        $manifest = json_encode([
            '/js/app.js' => '/js/app.js?id=123',
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $manifest,
        ]);

        // Response includes Cache-Control but with no-store
        $responses = [
            new Response(200, ['Cache-Control' => 'no-store, max-age=0']),
            new Response(200, ['Cache-Control' => 'no-cache']),
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache-Control headers', $result);
    }
}
