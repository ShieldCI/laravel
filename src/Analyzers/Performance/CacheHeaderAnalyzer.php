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
     * The list of uncached assets and their sources.
     *
     * @var \Illuminate\Support\Collection<int, array{path: string, source: string, type?: string}>
     */
    protected $uncachedAssets;

    /**
     * The public path (for testing).
     */
    private ?string $publicPath = null;

    /**
     * Optional override for the application URL (used in testing).
     */
    private ?string $appUrlOverride = null;

    /**
     * Track whether the app URL was explicitly set (even if set to null).
     */
    private bool $appUrlExplicitlySet = false;

    /**
     * Cache of URL header check results to avoid duplicate HTTP requests.
     *
     * @var array<string, bool>
     */
    private array $headerCheckCache = [];

    /**
     * Maximum number of uncached assets to detect before stopping.
     * Prevents excessive HTTP requests for large builds.
     */
    private int $maxUncachedAssets = 10;

    public function __construct(
        private Filesystem $files
    ) {}

    /**
     * Set the maximum number of uncached assets to detect (for testing).
     */
    public function setMaxUncachedAssets(int $max): void
    {
        $this->maxUncachedAssets = $max;
    }

    /**
     * Set the public path (for testing).
     */
    public function setPublicPath(string $path): void
    {
        $this->publicPath = $path;
    }

    /**
     * Override the application URL (used in testing).
     */
    public function setAppUrl(?string $url): void
    {
        $this->appUrlOverride = $url ? rtrim($url, '/') : null;
        $this->appUrlExplicitlySet = true;
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
            return $this->publicPath.($path ? DIRECTORY_SEPARATOR.$path : $path);
        }

        return function_exists('public_path') ? public_path($path) : '';
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'asset-cache-headers',
            name: 'Asset Cache Headers Analyzer',
            description: 'Ensures compiled assets have appropriate cache headers for optimal browser caching',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['cache', 'assets', 'performance', 'headers', 'browser-cache'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/asset-cache-headers',
            timeToFix: 30
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
        $this->headerCheckCache = []; // Reset cache for each analysis run

        // Validate APP_URL configuration before making HTTP requests
        if (! $this->isAppUrlConfigured()) {
            return $this->warning(
                'APP_URL is not properly configured. Cannot verify cache headers via HTTP requests. '.
                'Please set APP_URL in your .env file to enable cache header verification.'
            );
        }

        // Check Laravel Mix assets (with early bailout)
        if ($this->hasMixManifest() && ! $this->hasReachedMaxUncached()) {
            $this->checkMixAssets();
        }

        // Check Vite assets (with early bailout)
        if ($this->hasViteManifest() && ! $this->hasReachedMaxUncached()) {
            $this->checkViteAssets();
        }

        if ($this->uncachedAssets->isEmpty()) {
            return $this->passed('All compiled assets have appropriate cache headers');
        }

        /** @var array{path: string, source: string} $firstAsset */
        $firstAsset = $this->uncachedAssets->first();
        $firstSource = $firstAsset['source'];
        $issueLocation = $firstSource === 'vite' ? 'public/build/manifest.json' : 'public/mix-manifest.json';

        // Check if we hit the threshold (early bailout)
        $hitThreshold = $this->uncachedAssets->count() >= $this->maxUncachedAssets;
        $thresholdNote = $hitThreshold
            ? ' Note: Analysis stopped after finding '.$this->maxUncachedAssets.' uncached assets to prevent excessive HTTP requests. Additional assets may also be missing headers.'
            : '';

        $issues = [$this->createIssueWithSnippet(
            message: 'Compiled assets are missing Cache-Control headers or use non-cacheable directives',
            filePath: $this->buildPath($issueLocation),
            lineNumber: null,
            severity: Severity::High,
            recommendation: sprintf(
                'Your application does not set appropriate cache headers on compiled assets. '.
                'To improve performance, configure Cache-Control headers via your web server. '.
                'Uncached assets: %s. '.
                'For Apache, add rules to .htaccess. For Nginx, add cache headers in server config. '.
                'Versioned assets should use "Cache-Control: public, max-age=31536000, immutable".%s',
                $this->formatUncachedAssets(),
                $thresholdNote
            ),
            code: 'cache-headers',
            metadata: [
                'uncached_assets' => $this->uncachedAssets->toArray(),
                'count' => $this->uncachedAssets->count(),
                'hit_threshold' => $hitThreshold,
            ]
        )];

        return $this->resultBySeverity(
            sprintf('Found %d asset(s) without proper cache headers', $this->uncachedAssets->count()),
            $issues
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

            if (json_last_error() !== JSON_ERROR_NONE || ! is_array($manifest)) {
                return;
            }

            foreach ($manifest as $key => $value) {
                // Early bailout if we've found enough uncached assets
                if ($this->hasReachedMaxUncached()) {
                    break;
                }

                // Only check versioned (cache-busted) files
                if (is_string($value) && Str::contains($value, '?id=')) {
                    $compiledUrl = $this->getMixUrl($value);

                    // Check the compiled URL (the actual asset served to users)
                    if (! $this->assetHasCacheHeaders($compiledUrl)) {
                        $this->uncachedAssets->push([
                            'path' => $key,
                            'source' => 'mix',
                        ]);
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

            if (json_last_error() !== JSON_ERROR_NONE || ! is_array($manifest)) {
                return;
            }

            $visited = [];

            foreach ($manifest as $key => $entry) {
                if (! is_array($entry)) {
                    continue;
                }

                $this->checkViteManifestEntry($entry, $manifest, $visited, is_string($key) ? $key : null, 0);
            }
        } catch (\Throwable) {
            // Gracefully handle missing or invalid manifest
        }
    }

    /**
     * Inspect a Vite manifest entry (and any nested imports) for cache headers.
     *
     * @param  array<string, mixed>  $entry
     * @param  array<string, mixed>  $manifest
     * @param  array<string, bool>  $visited
     */
    private function checkViteManifestEntry(array $entry, array $manifest, array &$visited, ?string $entryKey = null, int $depth = 0): void
    {
        // Prevent infinite recursion in pathological cases
        if ($depth > 100) {
            return;
        }

        // Early bailout if we've found enough uncached assets
        if ($this->hasReachedMaxUncached()) {
            return;
        }

        if ($entryKey !== null) {
            if (isset($visited[$entryKey])) {
                return;
            }

            $visited[$entryKey] = true;
        }

        // Check the main file
        if (isset($entry['file']) && is_string($entry['file'])) {
            $url = $this->getViteAssetUrl($entry['file']);
            if (! $this->assetHasCacheHeaders($url)) {
                $this->uncachedAssets->push([
                    'path' => 'build/'.$entry['file'],
                    'source' => 'vite',
                ]);
            }
        }

        // No need to check hasReachedMaxUncached() again - we already return early above
        $this->checkViteAssetList($entry['css'] ?? null, 'css');

        // Check preloaded imports (Vite feature for code splitting)
        if (isset($entry['imports']) && is_array($entry['imports'])) {
            $this->checkViteImports($entry['imports'], $manifest, $visited, $depth);
        }

        if (isset($entry['dynamicImports']) && is_array($entry['dynamicImports'])) {
            $this->checkViteImports($entry['dynamicImports'], $manifest, $visited, $depth);
        }

        if (isset($entry['assets']) && is_array($entry['assets'])) {
            $this->checkViteAssetList($entry['assets'], 'asset');
        }
    }

    /**
     * @param  mixed  $items
     */
    private function checkViteAssetList($items, string $type): void
    {
        $files = is_array($items) ? $items : [$items];

        foreach ($files as $file) {
            // Early bailout if we've found enough uncached assets
            if ($this->hasReachedMaxUncached()) {
                break;
            }

            if (! is_string($file)) {
                continue;
            }

            $url = $this->getViteAssetUrl($file);
            if (! $this->assetHasCacheHeaders($url)) {
                $this->uncachedAssets->push([
                    'path' => 'build/'.$file,
                    'source' => 'vite',
                    'type' => $type,
                ]);
            }
        }
    }

    /**
     * @param  array<int, string>  $imports
     * @param  array<string, mixed>  $manifest
     * @param  array<string, bool>  $visited
     */
    private function checkViteImports(array $imports, array $manifest, array &$visited, int $depth = 0): void
    {
        foreach ($imports as $importKey) {
            // Early bailout if we've found enough uncached assets
            if ($this->hasReachedMaxUncached()) {
                break;
            }

            if (! is_string($importKey)) {
                continue;
            }

            if (isset($manifest[$importKey]) && is_array($manifest[$importKey])) {
                $this->checkViteManifestEntry($manifest[$importKey], $manifest, $visited, $importKey, $depth + 1);

                continue;
            }

            $url = $this->getViteAssetUrl($importKey);
            if (! $this->assetHasCacheHeaders($url)) {
                $this->uncachedAssets->push([
                    'path' => 'build/'.$importKey,
                    'source' => 'vite',
                    'type' => 'import',
                ]);
            }
        }
    }

    /**
     * Get the URL for a Mix asset.
     */
    private function getMixUrl(string $path): ?string
    {
        try {
            return $this->buildAbsoluteUrl($path);
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
            return $this->buildAbsoluteUrl('build/'.$file);
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
        $items = $this->uncachedAssets->map(function (array $asset) {
            return sprintf('[%s via %s]', $asset['path'], $asset['source']);
        })->all();

        if (count($items) === 0) {
            return '';
        }

        if (count($items) === 1) {
            return $items[0];
        }

        $last = array_pop($items);

        return implode(', ', $items).' and '.$last;
    }

    /**
     * Check if APP_URL is properly configured for HTTP requests.
     */
    private function isAppUrlConfigured(): bool
    {
        return $this->getAppUrl() !== null;
    }

    private function getAppUrl(): ?string
    {
        // If explicitly set (even to null), return the override value
        if ($this->appUrlExplicitlySet) {
            return $this->appUrlOverride;
        }

        // Otherwise, fall back to config
        if (! function_exists('config')) {
            return null;
        }

        $appUrl = config('app.url');
        if (! is_string($appUrl) || $appUrl === '') {
            return null;
        }

        $normalized = rtrim($appUrl, '/');

        return filter_var($normalized, FILTER_VALIDATE_URL) !== false ? $normalized : null;
    }

    private function buildAbsoluteUrl(string $path): ?string
    {
        $base = $this->getAppUrl();

        if ($base === null) {
            return null;
        }

        $trimmed = ltrim($path, '/');

        return $trimmed === ''
            ? $base
            : $base.'/'.$trimmed;
    }

    /**
     * Check if we've reached the maximum number of uncached assets.
     */
    private function hasReachedMaxUncached(): bool
    {
        return $this->uncachedAssets->count() >= $this->maxUncachedAssets;
    }

    private function assetHasCacheHeaders(?string $url): bool
    {
        if ($url === null) {
            return false;
        }

        // Check cache first to avoid duplicate HTTP requests
        if (isset($this->headerCheckCache[$url])) {
            return $this->headerCheckCache[$url];
        }

        $headers = $this->getHeadersOnUrl($url, 'Cache-Control');

        if (empty($headers)) {
            // Cache the result (no headers = not cached)
            $this->headerCheckCache[$url] = false;

            return false;
        }

        foreach ($headers as $header) {
            if ($this->isCacheHeaderOptimized($header)) {
                // Cache the result (valid headers found)
                $this->headerCheckCache[$url] = true;

                return true;
            }
        }

        // Cache the result (headers present but not optimized)
        $this->headerCheckCache[$url] = false;

        return false;
    }

    /**
     * Check if a Cache-Control header value is optimized for long-term caching.
     *
     * For versioned assets (with cache busting), we expect:
     * - Long max-age (>= 1 year recommended)
     * - OR s-maxage for CDN/proxy caching
     * - public directive (allows shared caches)
     * - immutable is a bonus (prevents revalidation)
     *
     * Minimum threshold: 1 day (86400 seconds) to avoid flagging valid short caches
     * Recommended: 1 year (31536000 seconds) for versioned assets
     */
    private function isCacheHeaderOptimized(string $headerValue): bool
    {
        $value = strtolower($headerValue);

        // Reject explicit non-caching directives
        if (str_contains($value, 'no-store') || str_contains($value, 'no-cache')) {
            return false;
        }

        // Reject private caching for public assets
        if (str_contains($value, 'private')) {
            return false;
        }

        // Extract max-age value (for browser cache)
        $maxAge = $this->extractCacheAge($value, 'max-age');

        // Extract s-maxage value (for CDN/shared cache)
        $sMaxAge = $this->extractCacheAge($value, 's-maxage');

        // Use the longest cache duration found
        $cacheDuration = max($maxAge ?? 0, $sMaxAge ?? 0);

        // Minimum threshold: 1 day (86400 seconds)
        // Versioned assets should use much longer (1 year = 31536000)
        // But we use 1 day to avoid false positives for legitimate short caches
        return $cacheDuration >= 86400;
    }

    /**
     * Extract cache age value from Cache-Control header.
     *
     * Examples:
     * - "max-age=31536000" → 31536000
     * - "public, max-age=3600, immutable" → 3600
     * - "s-maxage=86400" → 86400
     *
     * @param  string  $headerValue  Lowercase Cache-Control value
     * @param  string  $directive  Directive name (max-age or s-maxage)
     * @return int|null Age in seconds, or null if not found
     */
    private function extractCacheAge(string $headerValue, string $directive): ?int
    {
        // Match: max-age=31536000 or max-age = 31536000 (with optional whitespace)
        $pattern = '/'.$directive.'\s*=\s*(\d+)/';

        if (preg_match($pattern, $headerValue, $matches)) {
            return (int) $matches[1];
        }

        return null;
    }
}
