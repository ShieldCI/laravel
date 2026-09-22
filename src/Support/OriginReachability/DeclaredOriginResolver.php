<?php

declare(strict_types=1);

namespace ShieldCI\Support\OriginReachability;

use ShieldCI\AnalyzersCore\Support\FileParser;

/**
 * Works out every origin the application declares it is served from.
 *
 * Three declarations are read: app.url, app.asset_url, and any absolute base baked into a
 * Vite or Mix manifest (a CDN build writes fully-qualified asset URLs, and that CDN is an
 * origin the application is served from as surely as app.url is). Declarations that name
 * the same origin are merged, so each origin is declared once and probed once.
 */
final class DeclaredOriginResolver
{
    /**
     * Where a built asset manifest lands, and which declaration it counts as.
     *
     * public/build/manifest.json is the Laravel default; .vite/manifest.json is where
     * Vite 5 puts it; public/manifest.json is the flattened layout a custom build_path
     * produces.
     *
     * @var array<string, string>
     */
    private const MANIFESTS = [
        'public/build/manifest.json' => DeclaredOrigin::SOURCE_VITE_MANIFEST,
        'public/build/.vite/manifest.json' => DeclaredOrigin::SOURCE_VITE_MANIFEST,
        'public/manifest.json' => DeclaredOrigin::SOURCE_VITE_MANIFEST,
        'public/mix-manifest.json' => DeclaredOrigin::SOURCE_MIX_MANIFEST,
    ];

    /**
     * Resolve the declared origins, and the declarations that name none.
     *
     * The two lists are separate because "nothing was declared" and "something was declared
     * and cannot be used" are different facts about the application, and a report that
     * collapses them tells the user the opposite of what is wrong. Only the name of the
     * declaration is carried out, never the value: the value can hold credentials, and the
     * user needs the config key, not its contents.
     *
     * @param  string  $basePath  application root, where public/ is looked for
     * @param  string|null  $appUrl  the configured app.url
     * @param  string|null  $assetUrl  the configured app.asset_url
     * @return array{origins: array<int, DeclaredOrigin>, unusable: array<int, string>}
     */
    public function resolve(string $basePath, ?string $appUrl, ?string $assetUrl): array
    {
        /** @var array<string, array<int, string>> $collected */
        $collected = [];

        /** @var array<int, string> $unusable */
        $unusable = [];

        // A relative manifest entry declares no origin and is not a misconfiguration, so
        // only the two config values are watched for declarations that cannot be used.
        $this->collect($collected, $unusable, $appUrl, DeclaredOrigin::SOURCE_APP_URL, 'https', true);

        $scheme = $this->schemeOf($appUrl) ?? 'https';

        $this->collect($collected, $unusable, $assetUrl, DeclaredOrigin::SOURCE_ASSET_URL, $scheme, true);

        foreach (self::MANIFESTS as $relativePath => $source) {
            foreach ($this->manifestUrls($basePath.'/'.$relativePath, $source) as $url) {
                $this->collect($collected, $unusable, $url, $source, $scheme, false);
            }
        }

        $origins = [];

        foreach ($collected as $origin => $sources) {
            $origins[] = new DeclaredOrigin($origin, $sources);
        }

        return ['origins' => $origins, 'unusable' => $unusable];
    }

    /**
     * Record one declaration under its normalised origin, keeping first-seen order.
     *
     * @param  array<string, array<int, string>>  $collected
     * @param  array<int, string>  $unusable
     * @param  string  $defaultScheme  scheme a protocol-relative declaration inherits
     * @param  bool  $reportUnusable  whether a value that names no origin is a misconfiguration
     */
    private function collect(array &$collected, array &$unusable, ?string $url, string $source, string $defaultScheme, bool $reportUnusable): void
    {
        $origin = $this->normalizeOrigin($url, $defaultScheme);

        if ($origin === null) {
            if ($reportUnusable && $url !== null && trim($url) !== '' && ! in_array($source, $unusable, true)) {
                $unusable[] = $source;
            }

            return;
        }

        if (! isset($collected[$origin])) {
            $collected[$origin] = [];
        }

        if (! in_array($source, $collected[$origin], true)) {
            $collected[$origin][] = $source;
        }
    }

    /**
     * The scheme of a declared URL, when it names one.
     *
     * A protocol-relative asset base inherits the scheme the application itself is served
     * over, which is the one thing the deployment has already told us.
     */
    private function schemeOf(?string $url): ?string
    {
        if ($url === null) {
            return null;
        }

        $scheme = parse_url(trim($url), PHP_URL_SCHEME);

        if (! is_string($scheme)) {
            return null;
        }

        $scheme = strtolower($scheme);

        return $scheme === 'http' || $scheme === 'https' ? $scheme : null;
    }

    /**
     * Reduce a declared URL to scheme://host[:port], or null when it declares no origin.
     *
     * The default port for the scheme is dropped so https://example.com and
     * https://example.com:443 are recognised as one origin and cost one request.
     *
     * A protocol-relative declaration (//cdn.example.net/build/app.js, the scheme-agnostic
     * CDN spelling a build can write into a manifest) names a host and so names an origin.
     * Dropping it would leave an origin the application is genuinely served from unprobed
     * while the report still read Passed, so it inherits $defaultScheme instead.
     */
    private function normalizeOrigin(?string $url, string $defaultScheme): ?string
    {
        if ($url === null) {
            return null;
        }

        $url = trim($url);

        if ($url === '') {
            return null;
        }

        $parts = parse_url($url);

        if (! is_array($parts)) {
            return null;
        }

        $host = isset($parts['host']) && is_string($parts['host']) ? strtolower($parts['host']) : null;

        $scheme = isset($parts['scheme']) && is_string($parts['scheme'])
            ? strtolower($parts['scheme'])
            : ($host === null ? null : $defaultScheme);

        if (($scheme !== 'http' && $scheme !== 'https') || $host === null || $host === '') {
            return null;
        }

        $port = isset($parts['port']) && is_int($parts['port']) ? $parts['port'] : null;
        $isDefaultPort = ($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443);

        return $port === null || $isDefaultPort
            ? "{$scheme}://{$host}"
            : "{$scheme}://{$host}:{$port}";
    }

    /**
     * Absolute asset URLs declared inside one manifest file.
     *
     * @return array<int, string>
     */
    private function manifestUrls(string $path, string $source): array
    {
        $contents = FileParser::readFile($path);

        if ($contents === null) {
            return [];
        }

        $decoded = json_decode($contents, true);

        if (! is_array($decoded)) {
            return [];
        }

        return $source === DeclaredOrigin::SOURCE_MIX_MANIFEST
            ? $this->mixManifestUrls($decoded)
            : $this->viteManifestUrls($decoded);
    }

    /**
     * A Mix manifest maps a public path to the built path, so only its values matter.
     *
     * @param  array<array-key, mixed>  $manifest
     * @return array<int, string>
     */
    private function mixManifestUrls(array $manifest): array
    {
        $urls = [];

        foreach ($manifest as $value) {
            if (is_string($value)) {
                $urls[] = $value;
            }
        }

        return $urls;
    }

    /**
     * A Vite manifest maps each source file to an entry object carrying `file`, and often
     * `css` and `assets` arrays.
     *
     * Only entries of that shape are read. public/manifest.json is also where a PWA web
     * app manifest lives, and its start_url and icon URLs are not origins the application
     * is served from; requiring the Vite entry shape keeps one file's contents from being
     * read as the other's.
     *
     * @param  array<array-key, mixed>  $manifest
     * @return array<int, string>
     */
    private function viteManifestUrls(array $manifest): array
    {
        $urls = [];

        foreach ($manifest as $entry) {
            if (! is_array($entry) || ! isset($entry['file']) || ! is_string($entry['file'])) {
                continue;
            }

            $urls[] = $entry['file'];

            foreach (['css', 'assets'] as $key) {
                if (! isset($entry[$key]) || ! is_array($entry[$key])) {
                    continue;
                }

                foreach ($entry[$key] as $asset) {
                    if (is_string($asset)) {
                        $urls[] = $asset;
                    }
                }
            }
        }

        return $urls;
    }
}
