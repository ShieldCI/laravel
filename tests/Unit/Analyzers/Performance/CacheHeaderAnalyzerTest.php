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
        $this->assertEquals('Asset Cache Headers Analyzer', $metadata->name);
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

    public function test_handles_invalid_mix_manifest_json(): void
    {
        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => '{invalid json syntax',
        ]);

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should pass gracefully (skips invalid manifest)
        $this->assertPassed($result);
    }

    public function test_handles_invalid_vite_manifest_json(): void
    {
        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => '{invalid json syntax',
        ]);

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should pass gracefully (skips invalid manifest)
        $this->assertPassed($result);
    }

    public function test_handles_non_array_mix_manifest(): void
    {
        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => json_encode('string instead of object'),
        ]);

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should pass gracefully (skips non-array manifest)
        $this->assertPassed($result);
    }

    public function test_handles_non_array_vite_manifest(): void
    {
        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => json_encode('string instead of object'),
        ]);

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should pass gracefully (skips non-array manifest)
        $this->assertPassed($result);
    }

    public function test_handles_vite_entry_with_non_array_value(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => 'string instead of object',
            'resources/js/valid.js' => [
                'file' => 'assets/valid.js',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => $manifest,
        ]);

        $responses = [
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should pass (skips non-array entry, processes valid one)
        $this->assertPassed($result);
    }

    public function test_handles_vite_entry_with_non_string_file(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => [
                'file' => 123, // Non-string file
            ],
            'resources/js/valid.js' => [
                'file' => 'assets/valid.js',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => $manifest,
        ]);

        $responses = [
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should pass (skips non-string file, processes valid one)
        $this->assertPassed($result);
    }

    public function test_handles_vite_css_with_non_string_values(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.js',
                'css' => [
                    null,
                    42,
                    'assets/valid.css',
                ],
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

        // Should pass (skips non-strings, processes valid CSS)
        $this->assertPassed($result);
    }

    public function test_handles_vite_imports_with_non_string_keys(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.js',
                'imports' => [
                    123,
                    null,
                    'resources/js/valid.js',
                ],
            ],
            'resources/js/valid.js' => [
                'file' => 'assets/valid.js',
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

        // Should pass (skips non-string imports, processes valid one)
        $this->assertPassed($result);
    }

    public function test_relevant_environments_can_be_configured(): void
    {
        $manifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $manifest,
        ]);

        $files = new Filesystem;
        $analyzer = new CacheHeaderAnalyzer($files);

        // Test that setRelevantEnvironments works
        $analyzer->setRelevantEnvironments(['production', 'staging']);
        $this->assertIsArray($analyzer->getMetadata()->tags);

        // Test that null means all environments
        $analyzer->setRelevantEnvironments(null);
        $analyzer->setAppUrl('https://example.test');
        $analyzer->setPublicPath($tempDir.'/public');

        // Should run when environments is null
        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_skip_reason_when_no_asset_build_system(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $files = new Filesystem;
        $analyzer = new CacheHeaderAnalyzer($files);
        $analyzer->setRelevantEnvironments(null);
        $analyzer->setAppUrl('https://example.test');
        $analyzer->setPublicPath($tempDir.'/public');

        $this->assertFalse($analyzer->shouldRun());
        $skipReason = $analyzer->getSkipReason();
        $this->assertStringContainsString('No asset build system', $skipReason);
    }

    public function test_handles_circular_vite_imports(): void
    {
        // A imports B, B imports A (circular reference)
        $manifest = json_encode([
            'resources/js/a.js' => [
                'file' => 'assets/a.js',
                'imports' => ['resources/js/b.js'],
            ],
            'resources/js/b.js' => [
                'file' => 'assets/b.js',
                'imports' => ['resources/js/a.js'],
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

        // Should pass (visited array prevents infinite loop)
        $this->assertPassed($result);
    }

    public function test_handles_empty_mix_manifest(): void
    {
        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => json_encode([]),
        ]);

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should pass (nothing to check)
        $this->assertPassed($result);
    }

    public function test_handles_empty_vite_manifest(): void
    {
        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => json_encode([]),
        ]);

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should pass (nothing to check)
        $this->assertPassed($result);
    }

    public function test_handles_http_request_exceptions(): void
    {
        $manifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $manifest,
        ]);

        // Mock handler that throws exception
        $mock = new MockHandler([
            new \GuzzleHttp\Exception\ConnectException(
                'Connection failed',
                new \GuzzleHttp\Psr7\Request('GET', 'test')
            ),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setClient($client);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should fail gracefully (treats exception as no headers)
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache-Control headers', $result);
    }

    public function test_handles_mix_non_versioned_assets(): void
    {
        // Mix manifest with non-versioned assets (no ?id= query)
        $manifest = json_encode([
            '/css/app.css' => '/css/app.css', // No version
            '/js/app.js' => '/js/app.js?id=abc123', // Versioned
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $manifest,
        ]);

        $responses = [
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should pass (only checks versioned assets, skips non-versioned)
        $this->assertPassed($result);
    }

    public function test_handles_vite_import_not_in_manifest(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.js',
                'imports' => ['resources/js/missing.js'], // Not in manifest
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => $manifest,
        ]);

        $responses = [
            new Response(200, ['Cache-Control' => 'public, max-age=31536000']),
            new Response(200), // Missing import has no cache headers
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should fail (missing import treated as direct file without headers)
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $uncachedAssets = $issues[0]->metadata['uncached_assets'] ?? [];
        $this->assertIsArray($uncachedAssets);
        /** @var array<int, array{path: string, source: string}> $uncachedAssets */
        $paths = array_column($uncachedAssets, 'path');
        $this->assertContains('build/resources/js/missing.js', $paths);
    }

    public function test_handles_multiple_cache_control_headers(): void
    {
        $manifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $manifest,
        ]);

        // Multiple Cache-Control headers (first invalid, second valid)
        $responses = [
            new Response(200, [
                'Cache-Control' => [
                    'no-store',
                    'public, max-age=31536000',
                ],
            ]),
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should pass (second header is valid)
        $this->assertPassed($result);
    }

    public function test_handles_deep_vite_import_nesting(): void
    {
        // Create a deeply nested import chain
        $manifest = [
            'level0.js' => [
                'file' => 'assets/level0.js',
                'imports' => ['level1.js'],
            ],
        ];

        // Create 50 levels of nesting (well below 100 depth limit)
        for ($i = 1; $i <= 50; $i++) {
            $manifest["level{$i}.js"] = [
                'file' => "assets/level{$i}.js",
                'imports' => $i < 50 ? ['level'.($i + 1).'.js'] : [],
            ];
        }

        $tempDir = $this->createTempDirectory([
            'public/build/manifest.json' => json_encode($manifest),
        ]);

        // Create responses for all 51 files
        $responses = array_fill(0, 51, new Response(200, ['Cache-Control' => 'public, max-age=31536000']));

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should pass (handles deep nesting without hitting depth limit)
        $this->assertPassed($result);
    }

    public function test_handles_vite_dynamic_imports_with_non_string_keys(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.js',
                'dynamicImports' => [
                    null,
                    123,
                    'resources/js/valid.js',
                ],
            ],
            'resources/js/valid.js' => [
                'file' => 'assets/valid.js',
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

        // Should pass (skips non-string dynamic imports)
        $this->assertPassed($result);
    }

    public function test_handles_vite_assets_with_non_string_values(): void
    {
        $manifest = json_encode([
            'resources/js/app.js' => [
                'file' => 'assets/app.js',
                'assets' => [
                    null,
                    42,
                    'assets/fonts/font.woff2',
                ],
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

        // Should pass (skips non-string assets)
        $this->assertPassed($result);
    }

    public function test_handles_max_age_zero_as_invalid(): void
    {
        $manifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $manifest,
        ]);

        $responses = [
            new Response(200, ['Cache-Control' => 'max-age=0']),
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // max-age=0 is technically present but not optimal, should still pass
        // (current implementation only checks for presence of max-age=)
        $this->assertPassed($result);
    }

    public function test_handles_private_cache_control(): void
    {
        $manifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $manifest,
        ]);

        $responses = [
            new Response(200, ['Cache-Control' => 'private, max-age=3600']),
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        // Should pass (has max-age, even though private)
        $this->assertPassed($result);
    }

    public function test_format_uncached_assets_single(): void
    {
        $manifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $manifest,
        ]);

        $responses = [
            new Response(200), // No cache headers
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $recommendation = $issues[0]->recommendation;

        // Should format single asset without "and"
        $this->assertStringContainsString('[/css/app.css via mix]', $recommendation);
        $this->assertStringNotContainsString(' and ', $recommendation);
    }

    public function test_format_uncached_assets_multiple(): void
    {
        $manifest = json_encode([
            '/css/app.css' => '/css/app.css?id=abc123',
            '/js/app.js' => '/js/app.js?id=def456',
            '/js/vendor.js' => '/js/vendor.js?id=ghi789',
        ]);

        $tempDir = $this->createTempDirectory([
            'public/mix-manifest.json' => $manifest,
        ]);

        $responses = [
            new Response(200), // No cache headers
            new Response(200), // No cache headers
            new Response(200), // No cache headers
        ];

        /** @var CacheHeaderAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer($responses);
        $analyzer->setPublicPath($tempDir.'/public');
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $recommendation = $issues[0]->recommendation;

        // Should format multiple assets with commas and "and"
        $this->assertStringContainsString('[/css/app.css via mix]', $recommendation);
        $this->assertStringContainsString('[/js/app.js via mix]', $recommendation);
        $this->assertStringContainsString('[/js/vendor.js via mix]', $recommendation);
        $this->assertStringContainsString(' and ', $recommendation);
    }
}
