<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Analyzes cache headers for compiled assets.
 *
 * Checks for:
 * - Cache-Control headers on versioned assets (mix-manifest.json)
 * - Cache-Control headers on versioned assets (vite manifest)
 * - Proper cache configuration for static assets
 * - Browser caching recommendations
 */
class CacheHeaderAnalyzer extends AbstractFileAnalyzer
{
    /**
     * HTTP cache header checks require a live web server, not applicable in CI.
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'asset-cache-headers',
            name: 'Asset Cache Headers',
            description: 'Ensures compiled assets have appropriate cache headers for optimal browser caching',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['cache', 'assets', 'performance', 'headers', 'browser-cache'],
            docsUrl: 'https://laravel.com/docs/mix#versioning-and-cache-busting'
        );
    }

    public function shouldRun(): bool
    {
        // Skip if user configured to skip in local environment
        return ! $this->isLocalAndShouldSkip();
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check for Laravel Mix manifest
        $mixManifestPath = $this->basePath.'/public/mix-manifest.json';
        $viteManifestPath = $this->basePath.'/public/build/manifest.json';

        $hasMix = file_exists($mixManifestPath);
        $hasVite = file_exists($viteManifestPath);

        if (! $hasMix && ! $hasVite) {
            return $this->skipped('No asset build system detected (Laravel Mix or Vite)');
        }

        // Check for .htaccess or nginx config recommendations
        $hasHtaccess = file_exists($this->basePath.'/public/.htaccess');
        $hasNginxConfig = file_exists($this->basePath.'/nginx.conf') ||
                          file_exists($this->basePath.'/.nginx.conf');

        if ($hasMix) {
            $this->checkMixAssets($mixManifestPath, $hasHtaccess, $hasNginxConfig, $issues);
        }

        if ($hasVite) {
            $this->checkViteAssets($viteManifestPath, $hasHtaccess, $hasNginxConfig, $issues);
        }

        if (empty($issues)) {
            return $this->passed('Asset caching configuration appears to be properly configured');
        }

        return $this->warning(
            sprintf('Found %d asset caching recommendations', count($issues)),
            $issues
        );
    }

    private function checkMixAssets(string $manifestPath, bool $hasHtaccess, bool $hasNginxConfig, array &$issues): void
    {
        $manifest = json_decode(file_get_contents($manifestPath), true);

        if (empty($manifest)) {
            return;
        }

        // Check if assets are versioned (contain hash)
        $versionedAssets = [];
        $unversionedAssets = [];

        foreach ($manifest as $key => $value) {
            if (is_string($value) && (str_contains($value, '?id=') || preg_match('/\.[a-f0-9]{8,}\.(js|css)$/', $value))) {
                $versionedAssets[] = $key;
            } else {
                $unversionedAssets[] = $key;
            }
        }

        if (! empty($versionedAssets) && ! $hasHtaccess && ! $hasNginxConfig) {
            $issues[] = $this->createIssue(
                message: 'Versioned assets detected but no web server cache configuration found',
                location: new Location($this->basePath.'/public', 1),
                severity: Severity::Medium,
                recommendation: 'Configure your web server to set Cache-Control headers for versioned assets. For Apache, add rules to .htaccess. For Nginx, add cache headers in your server configuration. This enables browser caching and improves load times significantly.',
                metadata: [
                    'versioned_assets_count' => count($versionedAssets),
                    'build_system' => 'Laravel Mix',
                    'has_htaccess' => $hasHtaccess,
                    'has_nginx_config' => $hasNginxConfig,
                ]
            );
        }

        if ($hasHtaccess) {
            $this->checkHtaccessCacheRules($issues);
        }
    }

    private function checkViteAssets(string $manifestPath, bool $hasHtaccess, bool $hasNginxConfig, array &$issues): void
    {
        $manifest = json_decode(file_get_contents($manifestPath), true);

        if (! is_array($manifest) || empty($manifest)) {
            return;
        }

        // Vite assets are typically in /public/build/ and are hashed
        $assetCount = count($manifest);

        if ($assetCount > 0 && ! $hasHtaccess && ! $hasNginxConfig) {
            $issues[] = $this->createIssue(
                message: 'Vite compiled assets detected but no web server cache configuration found',
                location: new Location($this->basePath.'/public/build', 1),
                severity: Severity::Medium,
                recommendation: 'Configure your web server to set long-term Cache-Control headers for Vite assets in /public/build/. These assets are fingerprinted and can be cached for a year. Add "Cache-Control: public, max-age=31536000, immutable" for optimal performance.',
                metadata: [
                    'assets_count' => $assetCount,
                    'build_system' => 'Vite',
                    'has_htaccess' => $hasHtaccess,
                    'has_nginx_config' => $hasNginxConfig,
                ]
            );
        }

        if ($hasHtaccess) {
            $this->checkHtaccessCacheRules($issues);
        }
    }

    private function checkHtaccessCacheRules(array &$issues): void
    {
        $htaccessPath = $this->basePath.'/public/.htaccess';
        $content = file_get_contents($htaccessPath);

        if ($content === false) {
            return;
        }

        // Check if cache headers are configured
        $hasCacheControl = str_contains($content, 'Cache-Control') ||
                          str_contains($content, 'mod_expires') ||
                          str_contains($content, 'ExpiresActive');

        if (! $hasCacheControl) {
            $issues[] = $this->createIssue(
                message: '.htaccess exists but does not configure cache headers',
                location: new Location($htaccessPath, 1),
                severity: Severity::Low,
                recommendation: 'Add cache control rules to .htaccess for static assets. Example: Use mod_expires to set far-future expiration dates for CSS, JS, and image files. This reduces server requests and improves page load times.',
                metadata: [
                    'has_mod_expires' => false,
                    'has_cache_control' => false,
                ]
            );
        }
    }
}
