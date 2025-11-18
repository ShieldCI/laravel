<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\AnalyzesHeaders;

/**
 * Analyzes cache headers for compiled assets using HTTP verification.
 *
 * Makes actual HTTP requests to verify
 * that Cache-Control headers are properly set on compiled assets.
 *
 * This approach is superior because:
 * - Actually verifies headers are set (not just config files exist)
 * - Identifies specific assets missing headers
 * - Works with both Laravel Mix and Vite
 * - Tests real HTTP responses, not assumptions
 *
 * Environment Relevance:
 * - Production/Staging: Critical for browser caching performance
 * - Local/Development: Not relevant (dev server doesn't need cache headers)
 * - Testing: Not relevant (tests don't serve assets via HTTP)
 */
class CacheHeaderAnalyzer extends AbstractAnalyzer
{
    use AnalyzesHeaders;

    /**
     * HTTP cache header checks require a live web server, not applicable in CI.
     */
    public static bool $runInCI = false;

    /**
     * This analyzer is only relevant in production and staging environments.
     *
     * Cache headers improve browser caching performance by telling browsers
     * how long to cache compiled assets.
     *
     * @var array<string>
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    /**
     * The list of uncached assets.
     *
     * @var \Illuminate\Support\Collection<int, string>
     */
    protected $uncachedAssets;

    /**
     * The public path (for testing).
     */
    private ?string $publicPath = null;

    public function __construct(
        private Filesystem $files
    ) {}

    /**
     * Set the public path (for testing).
     */
    public function setPublicPath(string $path): void
    {
        $this->publicPath = $path;
    }

    /**
     * Set relevant environments (for testing).
     *
     * @param  array<string>|null  $environments
     */
    public function setRelevantEnvironments(?array $environments): void
    {
        $this->relevantEnvironments = $environments;
    }

    /**
     * Get the public path.
     */
    private function getPublicPath(string $path = ''): string
    {
        if ($this->publicPath !== null) {
            return $this->publicPath.($path ? '/'.$path : $path);
        }

        return function_exists('public_path') ? public_path($path) : '';
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'asset-cache-headers',
            name: 'Asset Cache Headers',
            description: 'Ensures compiled assets have appropriate cache headers for optimal browser caching',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['cache', 'assets', 'performance', 'headers', 'browser-cache'],
            docsUrl: 'https://laravel.com/docs/mix#versioning-and-cache-busting'
        );
    }

    public function shouldRun(): bool
    {
        // Check environment relevance first
        if (! $this->isRelevantForCurrentEnvironment()) {
            return false;
        }

        // Only run if an asset build system is present
        return $this->hasMixManifest() || $this->hasViteManifest();
    }

    public function getSkipReason(): string
    {
        if (! $this->isRelevantForCurrentEnvironment()) {
            $currentEnv = $this->getEnvironment();
            $relevantEnvs = implode(', ', $this->relevantEnvironments ?? []);

            return "Not relevant in '{$currentEnv}' environment (only relevant in: {$relevantEnvs})";
        }

        return 'No asset build system detected (Laravel Mix or Vite)';
    }

    protected function runAnalysis(): ResultInterface
    {
        $this->uncachedAssets = collect();

        // Validate APP_URL configuration before making HTTP requests
        if (! $this->isAppUrlConfigured()) {
            return $this->warning(
                'APP_URL is not properly configured. Cannot verify cache headers via HTTP requests. '.
                'Please set APP_URL in your .env file to enable cache header verification.'
            );
        }

        // Check Laravel Mix assets
        if ($this->hasMixManifest()) {
            $this->checkMixAssets();
        }

        // Check Vite assets
        if ($this->hasViteManifest()) {
            $this->checkViteAssets();
        }

        if ($this->uncachedAssets->isEmpty()) {
            return $this->passed('All compiled assets have appropriate cache headers');
        }

        return $this->failed(
            sprintf('Found %d asset(s) without proper cache headers', $this->uncachedAssets->count()),
            [$this->createIssue(
                message: 'Compiled assets are missing Cache-Control headers',
                location: new Location('public', 1),
                severity: Severity::High,
                recommendation: sprintf(
                    'Your application does not set appropriate cache headers on compiled assets. '.
                    'To improve performance, configure Cache-Control headers via your web server. '.
                    'Uncached assets: %s. '.
                    'For Apache, add rules to .htaccess. For Nginx, add cache headers in server config. '.
                    'Versioned assets should use "Cache-Control: public, max-age=31536000, immutable".',
                    $this->formatUncachedAssets()
                ),
                metadata: [
                    'uncached_assets' => $this->uncachedAssets->toArray(),
                    'count' => $this->uncachedAssets->count(),
                ]
            )]
        );
    }

    /**
     * Check Laravel Mix assets for cache headers.
     */
    private function checkMixAssets(): void
    {
        try {
            $manifestPath = $this->getPublicPath('mix-manifest.json');
            $manifest = json_decode($this->files->get($manifestPath), true);

            if (! is_array($manifest)) {
                return;
            }

            foreach ($manifest as $key => $value) {
                // Only check versioned (cache-busted) files
                if (is_string($value) && Str::contains($value, '?id=')) {
                    // Try both mix() and asset() URLs
                    $mixUrl = $this->getMixUrl($key);
                    $assetUrl = $this->getAssetUrl($key);

                    if (! $this->headerExistsOnUrl($mixUrl, 'Cache-Control')
                        && ! $this->headerExistsOnUrl($assetUrl, 'Cache-Control')) {
                        $this->uncachedAssets->push($key);
                    }
                }
            }
        } catch (\Throwable) {
            // Gracefully handle missing or invalid manifest
        }
    }

    /**
     * Check Vite assets for cache headers.
     */
    private function checkViteAssets(): void
    {
        try {
            $manifestPath = $this->getPublicPath('build/manifest.json');
            $manifest = json_decode($this->files->get($manifestPath), true);

            if (! is_array($manifest)) {
                return;
            }

            foreach ($manifest as $key => $entry) {
                if (! is_array($entry)) {
                    continue;
                }

                // Check the main file
                if (isset($entry['file']) && is_string($entry['file'])) {
                    $url = $this->getViteAssetUrl($entry['file']);
                    if (! $this->headerExistsOnUrl($url, 'Cache-Control')) {
                        $this->uncachedAssets->push('build/'.$entry['file']);
                    }
                }

                // Check CSS files
                if (isset($entry['css']) && is_array($entry['css'])) {
                    foreach ($entry['css'] as $cssFile) {
                        if (is_string($cssFile)) {
                            $url = $this->getViteAssetUrl($cssFile);
                            if (! $this->headerExistsOnUrl($url, 'Cache-Control')) {
                                $this->uncachedAssets->push('build/'.$cssFile);
                            }
                        }
                    }
                }

                // Check preloaded imports (Vite feature for code splitting)
                if (isset($entry['imports']) && is_array($entry['imports'])) {
                    foreach ($entry['imports'] as $importFile) {
                        if (is_string($importFile)) {
                            $url = $this->getViteAssetUrl($importFile);
                            if (! $this->headerExistsOnUrl($url, 'Cache-Control')) {
                                $this->uncachedAssets->push('build/'.$importFile);
                            }
                        }
                    }
                }
            }
        } catch (\Throwable) {
            // Gracefully handle missing or invalid manifest
        }
    }

    /**
     * Get the URL for a Mix asset.
     */
    private function getMixUrl(string $path): ?string
    {
        try {
            if (! function_exists('mix')) {
                return null;
            }

            $result = mix($path);

            return is_string($result) ? $result : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Get the URL for an asset.
     */
    private function getAssetUrl(string $path): ?string
    {
        try {
            if (! function_exists('asset')) {
                return null;
            }

            $result = asset($path);

            return is_string($result) ? $result : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Get the URL for a Vite asset.
     */
    private function getViteAssetUrl(string $file): ?string
    {
        try {
            if (! function_exists('asset')) {
                return null;
            }

            $result = asset('build/'.$file);

            return is_string($result) ? $result : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Check if Laravel Mix manifest exists.
     */
    private function hasMixManifest(): bool
    {
        $path = $this->getPublicPath('mix-manifest.json');

        return $path !== '' && file_exists($path);
    }

    /**
     * Check if Vite manifest exists.
     */
    private function hasViteManifest(): bool
    {
        $path = $this->getPublicPath('build/manifest.json');

        return $path !== '' && file_exists($path);
    }

    /**
     * Format uncached assets for display.
     */
    private function formatUncachedAssets(): string
    {
        return $this->uncachedAssets->map(function ($file) {
            return "[{$file}]";
        })->join(', ', ' and ');
    }

    /**
     * Check if APP_URL is properly configured for HTTP requests.
     */
    private function isAppUrlConfigured(): bool
    {
        // Check if config helper is available
        if (! function_exists('config')) {
            return false;
        }

        $appUrl = config('app.url');
        if (! is_string($appUrl) || $appUrl === '') {
            return false;
        }

        // Validate that it's a valid URL format
        return filter_var($appUrl, FILTER_VALIDATE_URL) !== false;
    }
}
