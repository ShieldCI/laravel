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
     * @param  string  $basePath  application root, where public/ is looked for
     * @param  string|null  $appUrl  the configured app.url
     * @param  string|null  $assetUrl  the configured app.asset_url
     * @return array<int, DeclaredOrigin>
     */
    public function resolve(string $basePath, ?string $appUrl, ?string $assetUrl): array
    {
        /** @var array<string, array<int, string>> $collected */
        $collected = [];

        $this->collect($collected, $appUrl, DeclaredOrigin::SOURCE_APP_URL);
        $this->collect($collected, $assetUrl, DeclaredOrigin::SOURCE_ASSET_URL);

        foreach (self::MANIFESTS as $relativePath => $source) {
            foreach ($this->manifestUrls($basePath.'/'.$relativePath, $source) as $url) {
                $this->collect($collected, $url, $source);
            }
        }

        $origins = [];

        foreach ($collected as $origin => $sources) {
            $origins[] = new DeclaredOrigin($origin, $sources);
        }

        return $origins;
    }

    /**
     * Record one declaration under its normalised origin, keeping first-seen order.
     *
     * @param  array<string, array<int, string>>  $collected
     */
    private function collect(array &$collected, ?string $url, string $source): void
    {
        $origin = $this->normalizeOrigin($url);

        if ($origin === null) {
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
     * Reduce a declared URL to scheme://host[:port], or null when it declares no origin.
     *
     * The default port for the scheme is dropped so https://example.com and
     * https://example.com:443 are recognised as one origin and cost one request.
     */
    private function normalizeOrigin(?string $url): ?string
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

        $scheme = isset($parts['scheme']) && is_string($parts['scheme']) ? strtolower($parts['scheme']) : null;
        $host = isset($parts['host']) && is_string($parts['host']) ? strtolower($parts['host']) : null;

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
