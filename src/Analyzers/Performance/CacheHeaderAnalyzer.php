<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Concerns\DetectsDeploymentPlatform;
use ShieldCI\Support\OriginReachability\DeclaredOrigin;
use ShieldCI\Support\OriginReachability\DeclaredOriginResolver;
use ShieldCI\Support\OriginReachability\OriginOutcome;
use ShieldCI\Support\OriginReachability\OriginProbeResult;
use ShieldCI\Support\OriginReachability\OriginReachabilityChecker;

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
    use DetectsDeploymentPlatform;

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
     * @var Collection<int, array{path: string, source: string, type?: string}>
     */
    protected $uncachedAssets;

    /**
     * Assets no 2xx response was received for, and why.
     *
     * They are neither cached nor uncached: nothing was observed about them, and grading
     * an empty header list from a refused connection, a 404 or a redirect to a login page
     * is how this analyzer used to report a High failure from zero responses.
     *
     * @var Collection<int, array{path: string, source: string, type?: string, reason: string}>
     */
    protected $unobservedAssets;

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
     * Maximum number of uncached, or of unobserved, assets to detect before stopping.
     * Prevents excessive HTTP requests for large builds and for an origin that does not answer.
     */
    private int $maxUncachedAssets = 10;

    /**
     * The checker is a container singleton, so each asset URL is probed once for the whole
     * run however many analyzers ask about it. It never follows a redirect, which keeps an
     * identity-aware proxy's login page from being graded as the asset.
     *
     * Certificate verification is the checker's and is left on, as it is for
     * env-http-accessibility: a header read over a connection whose peer was never
     * authenticated is a claim about a host nobody identified. A staging origin with a
     * self-signed certificate now produces a warning that names the TLS failure.
     */
    public function __construct(
        private Filesystem $files,
        private OriginReachabilityChecker $checker,
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
            timeToFix: 30
        );
    }

    public function shouldRun(): bool
    {
        // Check environment relevance first
        if (! $this->isRelevantForCurrentEnvironment()) {
            return false;
        }

        // On Laravel Cloud, asset cache headers are managed by the platform and
        // cannot be altered. No actionable fix exists, so suppress this check.
        if ($this->isLaravelCloud()) {
            return false;
        }

        // On Vapor/serverless, compiled assets are served from a CDN (ASSET_URL /
        // CloudFront) whose cache headers the platform manages, so whatever the probe
        // found there would have no fix the application could apply.
        if ($this->isVaporOrServerless()) {
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

        if ($this->isLaravelCloud()) {
            return 'Laravel Cloud manages asset cache headers. No configuration is possible.';
        }

        if ($this->isVaporOrServerless()) {
            return 'Laravel Vapor serves compiled assets from a CDN with platform-managed cache headers. No configuration is possible.';
        }

        return 'No asset build system detected (Laravel Mix or Vite)';
    }

    protected function runAnalysis(): ResultInterface
    {
        $this->uncachedAssets = collect();
        $this->unobservedAssets = collect();

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
            // Nothing uncached and something unobserved is not a clean bill of health.
            return $this->unobservedAssets->isEmpty()
                ? $this->passed('All compiled assets have appropriate cache headers')
                : $this->warning($this->describeUnobserved());
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

        $message = 'Compiled assets are missing Cache-Control headers or use non-cacheable directives';
        $summary = sprintf('Found %d asset(s) without proper cache headers', $this->uncachedAssets->count());

        if ($this->unobservedAssets->isNotEmpty()) {
            $summary .= sprintf(' (%d further asset(s) could not be checked)', $this->unobservedAssets->count());
        }

        $issues = [$this->createIssueWithSnippet(
            message: $message,
            filePath: $this->buildPath($issueLocation),
            lineNumber: null,
            severity: Severity::High,
            recommendation: $this->buildRecommendation($thresholdNote),
            metadata: [
                'uncached_assets' => $this->uncachedAssets->toArray(),
                'count' => $this->uncachedAssets->count(),
                'hit_threshold' => $hitThreshold,
                'code' => 'cache-headers',
            ]
        )];

        return $this->resultBySeverity($summary, $issues);
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
                    $this->recordAsset($compiledUrl, [
                        'path' => (string) $key,
                        'source' => 'mix',
                    ]);
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

            /** @var array<string, mixed> $manifest */
            $visited = [];

            foreach ($manifest as $key => $entry) {
                if (! is_array($entry)) {
                    continue;
                }

                /** @var array<string, mixed> $entry */
                $this->checkViteManifestEntry($entry, $manifest, $visited, $key, 0);
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
            $this->recordAsset($this->getViteAssetUrl($entry['file']), [
                'path' => 'build/'.$entry['file'],
                'source' => 'vite',
            ]);
        }

        // No need to check hasReachedMaxUncached() again - we already return early above
        $this->checkViteAssetList($entry['css'] ?? null, 'css');

        // Check preloaded imports (Vite feature for code splitting)
        if (isset($entry['imports']) && is_array($entry['imports'])) {
            /** @var array<int, string> $imports */
            $imports = array_values(array_filter($entry['imports'], 'is_string'));
            $this->checkViteImports($imports, $manifest, $visited, $depth);
        }

        if (isset($entry['dynamicImports']) && is_array($entry['dynamicImports'])) {
            /** @var array<int, string> $dynamicImports */
            $dynamicImports = array_values(array_filter($entry['dynamicImports'], 'is_string'));
            $this->checkViteImports($dynamicImports, $manifest, $visited, $depth);
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

            $this->recordAsset($this->getViteAssetUrl($file), [
                'path' => 'build/'.$file,
                'source' => 'vite',
                'type' => $type,
            ]);
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
                /** @var array<string, mixed> $importEntry */
                $importEntry = $manifest[$importKey];
                $this->checkViteManifestEntry($importEntry, $manifest, $visited, $importKey, $depth + 1);

                continue;
            }

            $this->recordAsset($this->getViteAssetUrl($importKey), [
                'path' => 'build/'.$importKey,
                'source' => 'vite',
                'type' => 'import',
            ]);
        }
    }

    /**
     * Get the URL for a Mix asset, as mix() builds it.
     *
     * mix() prefixes app.mix_url to the manifest value and nothing else, so a CDN set there
     * is where the browser fetches from. A result with no host is root-relative and is
     * fetched from the page's own origin, app.url.
     */
    private function getMixUrl(string $path): ?string
    {
        $url = $this->getConfigString('app.mix_url').$path;

        return parse_url($url, PHP_URL_HOST) !== null
            ? $url
            : $this->buildAbsoluteUrl($this->getAppUrl(), $url);
    }

    /**
     * Get the URL for a Vite asset, as the Vite helper builds it.
     *
     * The helper resolves asset('build/'.$file), which is rooted at app.asset_url when that
     * is set. Probing app.url instead asks a host that never serves the asset, and every
     * asset of an application on a CDN would answer 404.
     */
    private function getViteAssetUrl(string $file): ?string
    {
        return $this->buildAbsoluteUrl($this->getConfigString('app.asset_url') ?? $this->getAppUrl(), 'build/'.$file);
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

    private function buildRecommendation(string $thresholdNote): string
    {
        $assets = $this->formatUncachedAssets();

        return sprintf(
            'Compiled assets are missing long-lived cache headers. Uncached assets: %s. '.
            'For Apache, add rules to .htaccess. For Nginx, add cache headers in server config. '.
            'Versioned assets should use "Cache-Control: public, max-age=31536000, immutable".%s',
            $assets,
            $thresholdNote
        );
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

    private function buildAbsoluteUrl(?string $base, string $path): ?string
    {
        if ($base === null) {
            return null;
        }

        $base = rtrim($base, '/');
        $trimmed = ltrim($path, '/');

        return $trimmed === ''
            ? $base
            : $base.'/'.$trimmed;
    }

    private function getConfigString(string $key): ?string
    {
        if (! function_exists('config')) {
            return null;
        }

        $value = config($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Check if we've reached the maximum number of uncached, or of unobserved, assets.
     *
     * Unobserved assets are capped too: an origin that times out would otherwise be asked
     * about every asset in the manifest, each costing the full timeout.
     */
    private function hasReachedMaxUncached(): bool
    {
        return $this->uncachedAssets->count() >= $this->maxUncachedAssets
            || $this->unobservedAssets->count() >= $this->maxUncachedAssets;
    }

    /**
     * Probe one asset and file it as cached, uncached or unobserved.
     *
     * Only a 2xx is graded. A transport failure, a non-2xx and a redirect off the host all
     * carry no Cache-Control about the asset, and reading their empty header list as
     * "not cached" is the conflation this analyzer was filed for. hasEvidence() is not the
     * test: it is true for an off-host redirect, which is exactly what an identity-aware
     * proxy such as Cloudflare Access answers every asset with.
     *
     * @param  array{path: string, source: string, type?: string}  $asset
     */
    private function recordAsset(?string $url, array $asset): void
    {
        $probe = $this->probeAsset($url);

        if ($probe === null || $probe->outcome !== OriginOutcome::Connected2xx) {
            $this->unobservedAssets->push($asset + [
                'reason' => $probe?->describe() ?? sprintf('no http(s) URL could be built for %s', $asset['path']),
            ]);

            return;
        }

        foreach ($probe->headerValues('Cache-Control') as $header) {
            if ($this->isCacheHeaderOptimized($header)) {
                return;
            }
        }

        $this->uncachedAssets->push($asset);
    }

    /**
     * Ask the checker about one asset URL, on the origin that URL names.
     *
     * The checker caches each probe by URL, so an asset referenced from several manifest
     * entries costs one request. A protocol-relative CDN URL is fetched over the scheme
     * the page is served with.
     */
    private function probeAsset(?string $url): ?OriginProbeResult
    {
        if ($url === null) {
            return null;
        }

        $scheme = parse_url((string) $this->getAppUrl(), PHP_URL_SCHEME);
        $origin = DeclaredOriginResolver::normalizeOrigin($url, is_string($scheme) ? strtolower($scheme) : 'https');

        if ($origin === null) {
            return null;
        }

        $declared = new DeclaredOrigin($origin);

        return $this->checker->probe([$declared], null, [], $url)->probeFor($origin);
    }

    /**
     * Warning text for a run that found nothing uncached but could not observe everything.
     */
    private function describeUnobserved(): string
    {
        $count = $this->unobservedAssets->count();

        /** @var array{reason: string} $first */
        $first = $this->unobservedAssets->first();

        $message = sprintf(
            'Could not verify cache headers on %d compiled asset(s): no 2xx response was received, so nothing was learned about %s (first: %s).',
            $count,
            $count === 1 ? 'it' : 'them',
            $first['reason']
        );

        return $count >= $this->maxUncachedAssets
            ? $message.' Probing stopped after '.$this->maxUncachedAssets.' unanswered assets.'
            : $message;
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
