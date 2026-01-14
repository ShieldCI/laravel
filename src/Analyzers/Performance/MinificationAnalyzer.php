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
     * Minimum average line length (in characters) for a file to be considered minified.
     * Minified files typically have very long lines (> 500 chars on average).
     */
    private const MIN_AVG_LINE_LENGTH_FOR_MINIFIED = 500;

    /**
     * Maximum whitespace ratio (0.15 = 15%) for a file to be considered minified.
     * Unminified files have more whitespace due to formatting.
     */
    private const MAX_WHITESPACE_RATIO_FOR_MINIFIED = 0.15;

    /**
     * Minimum file size (in bytes) to skip pattern analysis.
     * Very small files (< 1KB) need pattern analysis instead of size-based checks.
     */
    private const MIN_FILE_SIZE_FOR_SIZE_CHECKS = 1024;

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
            name: 'Asset Minification Analyzer',
            description: 'Ensures JavaScript and CSS assets are minified in production',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['assets', 'minification', 'performance', 'javascript', 'css'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/asset-minification',
            timeToFix: 15
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
        $mixManifestPath = $this->joinPaths($publicPath, 'mix-manifest.json');
        $viteManifestPath = $this->joinPaths($publicPath, 'build', 'manifest.json');
        $hasMix = file_exists($mixManifestPath);
        $hasVite = file_exists($viteManifestPath);

        if (! $hasMix && ! $hasVite) {
            // Check for standalone JS/CSS files
            $this->checkStandaloneAssets($publicPath, $issues);
        } else {
            // Check build system assets
            if ($hasMix) {
                $this->checkMixAssets($publicPath, $issues);
            }

            if ($hasVite) {
                $viteBuildPath = $this->joinPaths($publicPath, 'build');
                $this->checkViteAssets($viteBuildPath, $issues);
            }
        }

        if (count($issues) === 0) {
            return $this->passed('All assets appear to be properly minified');
        }

        return $this->resultBySeverity(
            sprintf('Found %d asset minification recommendation(s)', count($issues)),
            $issues
        );
    }

    private function checkStandaloneAssets(string $publicPath, array &$issues): void
    {
        $unminifiedFiles = [];

        foreach (['js', 'css'] as $subDirectory) {
            $directoryPath = $this->joinPaths($publicPath, $subDirectory);
            if (! is_dir($directoryPath)) {
                continue;
            }

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($directoryPath, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY
            );

            /** @var \SplFileInfo $fileInfo */
            foreach ($iterator as $fileInfo) {
                if (! $fileInfo->isFile()) {
                    continue;
                }

                $filePath = $fileInfo->getPathname();

                if (str_contains($filePath, '.min.')) {
                    continue;
                }

                if ($this->isUnminified($filePath)) {
                    $unminifiedFiles[] = $this->getRelativePath($filePath);
                }
            }
        }

        if (! empty($unminifiedFiles)) {
            $issues[] = $this->createIssue(
                message: sprintf('Found %d unminified assets in production', count($unminifiedFiles)),
                location: new Location($this->getRelativePath($publicPath)),
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
        $manifestPath = $this->joinPaths($publicPath, 'mix-manifest.json');
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

            // Normalize path: remove leading slash and query string
            $normalizedPath = ltrim($path, DIRECTORY_SEPARATOR.'/');
            $normalizedPath = preg_replace('/\?.*$/', '', $normalizedPath);

            // Validate preg_replace() result
            if (! is_string($normalizedPath)) {
                $normalizedPath = ltrim($path, DIRECTORY_SEPARATOR.'/');
            }

            $fullPath = $this->joinPaths($publicPath, $normalizedPath);

            if (file_exists($fullPath) && $this->isUnminified($fullPath)) {
                $unminifiedAssets[] = $path;
            }
        }

        if (! empty($unminifiedAssets)) {
            $issues[] = $this->createIssue(
                message: 'Laravel Mix assets are not minified',
                location: new Location($this->getRelativePath($manifestPath)),
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
        // Note: glob() works with forward slashes on all platforms
        $jsPattern = str_replace('\\', '/', $buildPath).'/assets/*.js';
        $cssPattern = str_replace('\\', '/', $buildPath).'/assets/*.css';
        $jsFiles = glob($jsPattern);
        $cssFiles = glob($cssPattern);

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
                location: new Location($this->getRelativePath($buildPath)),
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

        $lines = FileParser::getLines($filePath);
        $lineCount = count($lines);
        $fileSize = strlen($content);

        // Small files need pattern-based analysis
        if ($fileSize < self::MIN_FILE_SIZE_FOR_SIZE_CHECKS) {
            return $this->hasUnminifiedPatterns($content);
        }

        $avgLineLength = $lineCount > 0 ? $fileSize / $lineCount : 0;

        // Primary check: Average line length (most reliable indicator)
        // Minified files have very long lines (>500 chars) regardless of line count
        // A file with 100 lines but 2000+ chars/line is likely minified (with banners/chunks)
        // A file with 20 lines but 100 chars/line is likely unminified
        if ($avgLineLength < self::MIN_AVG_LINE_LENGTH_FOR_MINIFIED) {
            // Low average line length + unminified patterns = definitely unminified
            return $this->hasUnminifiedPatterns($content);
        }

        // If average line length is high (>500 chars), likely minified
        // Even with many lines (license banners, webpack chunks, etc.)
        // But double-check with whitespace and statement formatting patterns

        // Check for excessive whitespace (unminified files have more whitespace)
        $whitespaceRatio = substr_count($content, ' ') / max($fileSize, 1);
        if ($whitespaceRatio > self::MAX_WHITESPACE_RATIO_FOR_MINIFIED) {
            return true;
        }

        // Check for newlines in the middle of statements (unminified code)
        $match = preg_match('/\n\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(/m', $content);
        if (is_int($match) && $match === 1) {
            return true;
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
     * Get the build path from configuration or default to public directory.
     */
    private function getBuildPath(): string
    {
        // Use $this->basePath if set (from setBasePath), otherwise use getBasePath()
        $basePath = ! empty($this->basePath) ? $this->basePath : $this->getBasePath();

        try {
            $configPath = config('shieldci.build_path');

            if ($configPath && is_string($configPath)) {
                $resolved = str_starts_with($configPath, DIRECTORY_SEPARATOR)
                    ? $configPath
                    : $this->joinPaths($basePath, $configPath);

                $normalizedConfigPath = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $resolved);
                $normalizedBasePath = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $basePath);

                if (str_starts_with($normalizedConfigPath, rtrim($normalizedBasePath, DIRECTORY_SEPARATOR))) {
                    return $resolved;
                }
            }
        } catch (\Throwable $e) {
            // Config not available (e.g., in tests), fall through to default
        }

        // Default to public directory under base path
        return $this->joinPaths($basePath, 'public');
    }

    /**
     * Join path segments using DIRECTORY_SEPARATOR.
     */
    private function joinPaths(string ...$paths): string
    {
        $filtered = array_filter($paths, fn ($path) => $path !== '' && $path !== null);

        if (empty($filtered)) {
            return '';
        }

        // Normalize all path segments
        $normalized = array_map(
            fn ($path) => str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path),
            $filtered
        );

        // Remove trailing separators from all but the last segment
        $normalized = array_map(
            fn ($index, $path) => $index < count($normalized) - 1
                ? rtrim($path, DIRECTORY_SEPARATOR)
                : $path,
            array_keys($normalized),
            $normalized
        );

        return implode(DIRECTORY_SEPARATOR, $normalized);
    }
}
