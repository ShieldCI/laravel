<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects unminified assets in production.
 *
 * Checks for:
 * - Unminified JavaScript files
 * - Unminified CSS files
 * - Assets that should be minified but aren't
 *
 * Environment Relevance:
 * - Production/Staging: Critical for performance (minification reduces file sizes by 50-70%)
 * - Local/Development: Not relevant (developers work with unminified assets for debugging)
 * - Testing: Not relevant (tests don't serve assets to browsers)
 */
class MinificationAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Asset minification checks require compiled assets, not applicable in CI.
     */
    public static bool $runInCI = false;

    /**
     * This analyzer is only relevant in production and staging environments.
     *
     * Minification is a critical production optimization that reduces asset file sizes
     * by 50-70% and significantly improves page load times.
     *
     * @var array<string>|null
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    /**
     * Set relevant environments (for testing).
     *
     * @param  array<string>|null  $environments
     */
    public function setRelevantEnvironments(?array $environments): void
    {
        $this->relevantEnvironments = $environments;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'asset-minification',
            name: 'Asset Minification',
            description: 'Ensures JavaScript and CSS assets are minified in production',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['assets', 'minification', 'performance', 'javascript', 'css'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/asset-minification'
        );
    }

    public function shouldRun(): bool
    {
        // Check environment relevance first
        if (! $this->isRelevantForCurrentEnvironment()) {
            return false;
        }

        // Only run if build directory exists
        $buildPath = $this->getBuildPath();

        return is_dir($buildPath);
    }

    public function getSkipReason(): string
    {
        if (! $this->isRelevantForCurrentEnvironment()) {
            $currentEnv = $this->getEnvironment();
            $relevantEnvs = implode(', ', $this->relevantEnvironments ?? []);

            return "Not relevant in '{$currentEnv}' environment (only relevant in: {$relevantEnvs})";
        }

        return 'Build directory not found (configure via shieldci.build_path or SHIELDCI_BUILD_PATH)';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $publicPath = $this->getBuildPath();

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
        $jsFiles = glob($publicPath.'/js/*.js');
        $cssFiles = glob($publicPath.'/css/*.css');

        // Handle glob() returning false on error
        if ($jsFiles === false) {
            $jsFiles = [];
        }
        if ($cssFiles === false) {
            $cssFiles = [];
        }

        $unminifiedFiles = [];

        foreach (array_merge($jsFiles, $cssFiles) as $file) {
            // Skip already minified files
            if (str_contains($file, '.min.')) {
                continue;
            }

            // Check if file looks minified (has very long lines or very few lines)
            if ($this->isUnminified($file)) {
                $unminifiedFiles[] = $this->getRelativePath($file);
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
        $manifestContent = FileParser::readFile($manifestPath);

        if ($manifestContent === null) {
            return;
        }

        $manifest = json_decode($manifestContent, true);

        // Check for JSON decode errors
        if (json_last_error() !== JSON_ERROR_NONE || ! is_array($manifest)) {
            return;
        }

        // Check if manifest is empty
        if (empty($manifest)) {
            return;
        }

        $unminifiedAssets = [];

        foreach ($manifest as $key => $path) {
            if (! is_string($path)) {
                continue;
            }

            $fullPath = $publicPath.$path;

            // Remove query string for file check
            $cleanedPath = preg_replace('/\?.*$/', '', $fullPath);

            // Validate preg_replace() result
            if (! is_string($cleanedPath)) {
                $cleanedPath = $fullPath;
            }

            if (file_exists($cleanedPath) && $this->isUnminified($cleanedPath)) {
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
        $jsFiles = glob($buildPath.'/assets/*.js');
        $cssFiles = glob($buildPath.'/assets/*.css');

        // Handle glob() returning false on error
        if ($jsFiles === false) {
            $jsFiles = [];
        }
        if ($cssFiles === false) {
            $cssFiles = [];
        }

        foreach (array_merge($jsFiles, $cssFiles) as $file) {
            if ($this->isUnminified($file)) {
                $largeAssets[] = $this->getRelativePath($file);
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

        $content = FileParser::readFile($filePath);

        if ($content === null) {
            return false;
        }

        // Check for source map reference - minified files often include this
        if ($this->hasSourceMapReference($content)) {
            return false; // Has source map = likely minified
        }

        $lines = FileParser::getLines($filePath);
        $lineCount = count($lines);

        // Minified files typically have very few lines (usually 1-5 for small files, maybe 10-15 for large ones)
        // Files with more than 15 lines are likely not minified (accounting for source maps and copyright notices)
        if ($lineCount > 15) {
            return true;
        }

        // Check file size - very small files (< 1KB) might need pattern analysis
        $fileSize = strlen($content);
        if ($fileSize < 1024) {
            // For very small files, check if they have typical minification patterns
            // (e.g., single line, no whitespace, or very compact)
            return $this->hasUnminifiedPatterns($content);
        }

        // Also check average line length - minified files have very long lines
        $avgLineLength = $lineCount > 0 ? $fileSize / $lineCount : 0;

        // Minified files typically have average line length > 500 chars
        // But also check for other indicators
        if ($avgLineLength < 500) {
            // Check for patterns that indicate unminified code
            return $this->hasUnminifiedPatterns($content);
        }

        // Check for excessive whitespace (unminified files have more whitespace)
        $whitespaceRatio = substr_count($content, ' ') / max($fileSize, 1);
        if ($whitespaceRatio > 0.15) {
            return true; // More than 15% whitespace suggests unminified
        }

        // Check for newlines in the middle of statements (unminified code)
        $match = preg_match('/\n\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(/m', $content);
        if (is_int($match) && $match === 1) {
            return true; // Function calls on new lines suggest unminified
        }

        return false;
    }

    /**
     * Check for patterns that indicate unminified code.
     */
    private function hasUnminifiedPatterns(string $content): bool
    {
        // Check for multiple consecutive newlines (unminified code often has blank lines)
        $match = preg_match('/\n\s*\n\s*\n/', $content);
        if (is_int($match) && $match === 1) {
            return true;
        }

        // Check for comments (unminified code often has comments)
        $match = preg_match('/\/\/[^\n]*|\/\*[\s\S]*?\*\//', $content);
        if (is_int($match) && $match === 1) {
            // But exclude source map comments which are in minified files
            if (! str_contains($content, 'sourceMappingURL=')) {
                return true;
            }
        }

        // Check for CSS-style formatting (indented properties)
        // Pattern: newline + spaces + property: value (common in formatted CSS)
        $match = preg_match('/\n\s{2,}[\w\-]+\s*:\s*[\w\-#]+/', $content);
        if (is_int($match) && $match === 1) {
            return true; // Indented CSS properties suggest unminified
        }

        // Check for readable variable names (unminified code has descriptive names)
        // Minified code often has single-letter variables
        $match = preg_match('/\b[a-z]{3,}[a-zA-Z0-9_]*\s*=/i', $content);
        if (is_int($match) && $match === 1) {
            // But this is not definitive, so combine with other checks
            $lines = explode("\n", $content);
            $lineCount = count($lines);
            if ($lineCount > 5) {
                return true; // Multiple lines with readable names suggest unminified
            }
        }

        return false;
    }

    /**
     * Check if the file has a source map reference.
     * Minified files often include //# sourceMappingURL= or /*# sourceMappingURL= comments.
     */
    private function hasSourceMapReference(string $content): bool
    {
        if (str_contains($content, 'sourceMappingURL=')) {
            return true;
        }

        if (str_contains($content, '//# sourceURL=')) {
            return true;
        }

        $match = preg_match('/\/[*\/]#\s*sourceMappingURL=/i', $content);
        if (! is_int($match)) {
            $match = 0;
        }

        return $match === 1;
    }

    /**
     * Get the build path from configuration or default to public directory.
     */
    private function getBuildPath(): string
    {
        try {
            $configPath = config('shieldci.build_path');

            // If config returns a valid path that is within the base path, use it
            if ($configPath && is_string($configPath) && str_starts_with($configPath, $this->basePath)) {
                return $configPath;
            }
        } catch (\Throwable $e) {
            // Config not available (e.g., in tests), fall through to default
        }

        // Default to public directory under base path
        return $this->basePath.'/public';
    }
}
