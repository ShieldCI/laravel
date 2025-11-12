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
 * Detects unminified assets in production.
 *
 * Checks for:
 * - Unminified JavaScript files
 * - Unminified CSS files
 * - Assets that should be minified but aren't
 */
class MinificationAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Asset minification checks require compiled assets, not applicable in CI.
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'asset-minification',
            name: 'Asset Minification',
            description: 'Ensures JavaScript and CSS assets are minified in production',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['assets', 'minification', 'performance', 'javascript', 'css'],
            docsUrl: 'https://laravel.com/docs/vite#production-builds'
        );
    }

    public function shouldRun(): bool
    {
        $environment = $this->getEnvironment();

        // Only run in non-local environments
        return $environment !== 'local' && file_exists($this->basePath.'/public');
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $publicPath = $this->basePath.'/public';

        if (! is_dir($publicPath)) {
            return $this->skipped('Public directory not found');
        }

        // Check for build directories
        $hasMix = file_exists($publicPath.'/mix-manifest.json');
        $hasVite = file_exists($publicPath.'/build/manifest.json');

        if (! $hasMix && ! $hasVite) {
            // Check for standalone JS/CSS files
            $this->checkStandaloneAssets($publicPath, $issues);
        } else {
            // Check build system assets
            if ($hasMix) {
                $this->checkMixAssets($publicPath, $issues);
            }

            if ($hasVite) {
                $this->checkViteAssets($publicPath.'/build', $issues);
            }
        }

        if (empty($issues)) {
            return $this->passed('All assets appear to be properly minified');
        }

        return $this->warning(
            sprintf('Found %d asset minification recommendations', count($issues)),
            $issues
        );
    }

    private function checkStandaloneAssets(string $publicPath, array &$issues): void
    {
        // Find JS and CSS files in public directory (excluding vendor)
        $jsFiles = glob($publicPath.'/js/*.js') ?: [];
        $cssFiles = glob($publicPath.'/css/*.css') ?: [];

        $unminifiedFiles = [];

        foreach (array_merge($jsFiles, $cssFiles) as $file) {
            // Skip already minified files
            if (str_contains($file, '.min.')) {
                continue;
            }

            // Check if file looks minified (has very long lines or very few lines)
            if ($this->isUnminified($file)) {
                $unminifiedFiles[] = str_replace($this->basePath.'/', '', $file);
            }
        }

        if (! empty($unminifiedFiles)) {
            $issues[] = $this->createIssue(
                message: sprintf('Found %d unminified assets in production', count($unminifiedFiles)),
                location: new Location($publicPath, 1),
                severity: Severity::Medium,
                recommendation: 'Minify your JavaScript and CSS assets using a build tool like Laravel Mix, Vite, or Webpack. Minification reduces file sizes by 50-70% and improves page load times significantly. Consider using Laravel Vite for modern asset bundling.',
                metadata: [
                    'unminified_files' => array_slice($unminifiedFiles, 0, 10),
                    'total_count' => count($unminifiedFiles),
                ]
            );
        }
    }

    private function checkMixAssets(string $publicPath, array &$issues): void
    {
        $manifestPath = $publicPath.'/mix-manifest.json';
        $manifest = json_decode(file_get_contents($manifestPath), true);

        if (! is_array($manifest)) {
            return;
        }

        $unminifiedAssets = [];

        foreach ($manifest as $key => $path) {
            if (! is_string($path)) {
                continue;
            }

            $fullPath = $publicPath.$path;

            // Remove query string for file check
            $fullPath = preg_replace('/\?.*$/', '', $fullPath);

            if (is_string($fullPath) && file_exists($fullPath) && $this->isUnminified($fullPath)) {
                $unminifiedAssets[] = $path;
            }
        }

        if (! empty($unminifiedAssets)) {
            $issues[] = $this->createIssue(
                message: 'Laravel Mix assets are not minified',
                location: new Location($manifestPath, 1),
                severity: Severity::Medium,
                recommendation: 'Run "npm run production" instead of "npm run dev" when building assets for production. The production build minifies JS and CSS. Update your deployment script to use the production build command.',
                metadata: [
                    'unminified_assets' => array_slice($unminifiedAssets, 0, 10),
                    'total_count' => count($unminifiedAssets),
                ]
            );
        }
    }

    private function checkViteAssets(string $buildPath, array &$issues): void
    {
        if (! is_dir($buildPath)) {
            return;
        }

        // Vite assets should be minified by default in production builds
        // Check if there are suspiciously large files
        $largeAssets = [];
        $jsFiles = glob($buildPath.'/assets/*.js') ?: [];
        $cssFiles = glob($buildPath.'/assets/*.css') ?: [];

        foreach (array_merge($jsFiles, $cssFiles) as $file) {
            if ($this->isUnminified($file)) {
                $largeAssets[] = str_replace($this->basePath.'/', '', $file);
            }
        }

        if (! empty($largeAssets)) {
            $issues[] = $this->createIssue(
                message: 'Vite assets may not be properly minified',
                location: new Location($buildPath, 1),
                severity: Severity::Low,
                recommendation: 'Ensure you\'re running "npm run build" (not "npm run dev") for production. Vite automatically minifies assets in production mode. Verify your vite.config.js has the correct build settings.',
                metadata: [
                    'suspicious_files' => array_slice($largeAssets, 0, 5),
                    'total_count' => count($largeAssets),
                ]
            );
        }
    }

    private function isUnminified(string $filePath): bool
    {
        if (! file_exists($filePath)) {
            return false;
        }

        $content = file_get_contents($filePath);

        if ($content === false) {
            return false;
        }

        $lines = explode("\n", $content);
        $lineCount = count($lines);

        // Minified files typically have very few lines (usually 1-5 for small files, maybe 10-20 for large ones)
        // Files with more than 20 lines are likely not minified (accounting for source maps and copyright notices)
        if ($lineCount > 20) {
            return true;
        }

        // Also check average line length - minified files have very long lines
        $totalLength = strlen($content);
        $avgLineLength = $lineCount > 0 ? $totalLength / $lineCount : 0;

        // If average line length is less than 500 chars, likely not minified
        return $avgLineLength < 500;
    }

    private function getEnvironment(): string
    {
        $envFile = $this->basePath.'/.env';

        if (! file_exists($envFile)) {
            return 'production';
        }

        $content = file_get_contents($envFile);

        if ($content === false) {
            return 'production';
        }

        if (preg_match('/^APP_ENV\s*=\s*(\w+)/m', $content, $matches)) {
            return $matches[1];
        }

        return 'production';
    }
}
