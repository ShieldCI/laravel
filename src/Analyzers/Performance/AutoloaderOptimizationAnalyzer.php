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
 * Analyzes Composer autoloader optimization for performance.
 *
 * This analyzer checks for production-specific optimizations and is only
 * relevant in production and staging environments where performance matters.
 *
 * Checks for:
 * - Autoloader optimization (composer dump-autoload -o) in production
 * - Authoritative class map (composer dump-autoload --classmap-authoritative)
 *
 * Environment Relevance:
 * - Production/Staging: Critical for performance
 * - Local: Not relevant (unoptimized autoloader is fine for development)
 */
class AutoloaderOptimizationAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Autoloader optimization checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

    /**
     * This analyzer is only relevant in production and staging environments.
     *
     * Custom environment names are automatically handled via environment mapping.
     *
     * Not relevant in:
     * - local: Developers don't need optimized autoloader
     * - development: Same as local
     * - testing: Test suite doesn't need optimization
     *
     * @var array<string>
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'autoloader-optimization',
            name: 'Composer Autoloader Optimization Analyzer',
            description: 'Ensures Composer autoloader is optimized for production performance',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['composer', 'autoloader', 'performance', 'optimization'],
            docsUrl: 'https://docs.shieldci.com/analyzers/performance/autoloader-optimization',
            timeToFix: 5
        );
    }

    public function shouldRun(): bool
    {
        // Check if relevant for current environment first
        if (! $this->isRelevantForCurrentEnvironment()) {
            return false;
        }

        // Only run if vendor directory exists
        $autoloadPath = $this->buildPath('vendor', 'autoload.php');

        return file_exists($autoloadPath);
    }

    public function getSkipReason(): string
    {
        // Check environment relevance first
        if (! $this->isRelevantForCurrentEnvironment()) {
            $currentEnv = $this->getEnvironment();
            $relevantEnvs = implode(', ', $this->relevantEnvironments ?? []);

            return "Not relevant in '{$currentEnv}' environment (only relevant in: {$relevantEnvs})";
        }

        // Otherwise, provide specific reason about missing vendor directory
        return 'Composer vendor directory not found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $environment = $this->getEnvironment();

        $composerConfig = $this->getComposerConfig();
        $configFlags = $this->extractComposerOptimizationFlags($composerConfig);

        $scriptsConfig = $composerConfig['scripts'] ?? [];
        if (! is_array($scriptsConfig)) {
            $scriptsConfig = [];
        }

        $scriptsRunOptimization = $this->composerScriptsRunOptimization($scriptsConfig);

        // Check if autoloader is optimized
        $isOptimized = $this->isAutoloaderOptimized();
        $isAuthoritative = $this->isClassMapAuthoritative();

        if (! $isOptimized && ! $isAuthoritative) {
            $message = $configFlags['optimize']
                ? 'Composer config enables "optimize-autoloader" but the generated autoload files are not optimized'
                : "Composer autoloader is not optimized in {$environment} environment";

            $composerJsonPath = $this->buildPath('composer.json');
            $configLine = $this->findConfigSectionLine($composerJsonPath);

            $issues[] = $this->createIssue(
                message: $message,
                location: new Location($composerJsonPath, $configLine),
                severity: Severity::High,
                recommendation: 'Run "composer dump-autoload -o" or "composer install --optimize-autoloader" in production. This converts PSR-4/PSR-0 rules into classmap rules for improved performance. Add this to your deployment script for best results.',
                metadata: [
                    'optimized' => false,
                    'authoritative' => false,
                    'environment' => $environment,
                    'configured_optimize' => $configFlags['optimize'],
                    'configured_authoritative' => $configFlags['authoritative'],
                    'configured_via_scripts' => $scriptsRunOptimization,
                ]
            );
        }

        // Recommend authoritative classmap for even better performance
        if ($isOptimized && ! $isAuthoritative) {
            $message = $configFlags['authoritative']
                ? 'Composer config enables classmap authoritative mode but the generated autoload files are not authoritative'
                : 'Composer autoloader could use authoritative classmap for better performance';

            $composerJsonPath = $this->buildPath('composer.json');
            $configLine = $this->findConfigSectionLine($composerJsonPath);

            $issues[] = $this->createIssue(
                message: $message,
                location: new Location($composerJsonPath, $configLine),
                severity: Severity::Low,
                recommendation: 'For even better performance, use "composer dump-autoload --classmap-authoritative" or add "classmap-authoritative": true to composer.json config. This prevents the autoloader from falling back to filesystem checks, providing faster class loading.',
                metadata: [
                    'optimized' => true,
                    'authoritative' => false,
                    'environment' => $environment,
                    'configured_optimize' => $configFlags['optimize'],
                    'configured_authoritative' => $configFlags['authoritative'],
                    'configured_via_scripts' => $scriptsRunOptimization,
                ]
            );
        }

        if (count($issues) === 0) {
            return $this->passed("Composer autoloader is properly optimized for {$environment} environment");
        }

        return $this->resultBySeverity(
            sprintf('Found %d autoloader optimization issue(s)', count($issues)),
            $issues
        );
    }

    private function isAutoloaderOptimized(): bool
    {
        $classMapPath = $this->buildPath('vendor', 'composer', 'autoload_classmap.php');

        if (! file_exists($classMapPath)) {
            return false;
        }

        /** @var mixed $classMap */
        $classMap = @include $classMapPath;

        if (! is_array($classMap)) {
            return false;
        }

        return $this->hasProjectClassesInClassmap($classMap);
    }

    /**
     * Determine if the generated classmap contains project classes (non-vendor paths).
     *
     * @param  array<string, string>  $classMap
     */
    private function hasProjectClassesInClassmap(array $classMap): bool
    {
        if (empty($classMap)) {
            return false;
        }

        $basePath = $this->getBasePath();
        $normalizedBasePath = rtrim($this->normalizePathString($basePath), '/');
        $vendorPrefix = $normalizedBasePath.'/vendor/';

        foreach ($classMap as $path) {
            if (! is_string($path) || $path === '') {
                continue;
            }

            $normalizedPath = $this->normalizePathString($path);

            if ($normalizedPath === '') {
                continue;
            }

            if (str_starts_with($normalizedPath, $vendorPrefix)) {
                continue;
            }

            if (str_starts_with($normalizedPath, $normalizedBasePath.'/')) {
                return true;
            }

            if (! str_contains($normalizedPath, '/vendor/')) {
                return true;
            }
        }

        return false;
    }

    private function normalizePathString(string $path): string
    {
        $path = str_replace('\\', '/', $path);

        $prefix = '';
        if (preg_match('/^[A-Za-z]:/', $path) === 1) {
            $prefix = substr($path, 0, 2);
            $path = substr($path, 2);
        } elseif (str_starts_with($path, '/')) {
            $prefix = '/';
            $path = substr($path, 1);
        }

        $segments = explode('/', $path);
        $normalized = [];

        foreach ($segments as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }

            if ($segment === '..') {
                if (! empty($normalized)) {
                    array_pop($normalized);
                }

                continue;
            }

            $normalized[] = $segment;
        }

        $combined = implode('/', $normalized);

        return $prefix.$combined;
    }

    private function isClassMapAuthoritative(): bool
    {
        $autoloadRealPath = $this->buildPath('vendor', 'composer', 'autoload_real.php');

        if (! file_exists($autoloadRealPath)) {
            return false;
        }

        $content = FileParser::readFile($autoloadRealPath);

        if (is_null($content)) {
            return false;
        }

        // Check if setClassMapAuthoritative is called
        return str_contains($content, 'setClassMapAuthoritative(true)');
    }

    /**
     * @return array<string, mixed>
     */
    private function getComposerConfig(): array
    {
        $composerPath = $this->buildPath('composer.json');

        if (! file_exists($composerPath)) {
            return [];
        }

        $content = FileParser::readFile($composerPath);
        if ($content === null) {
            return [];
        }

        $decoded = json_decode($content, true);

        // Check for JSON parsing errors
        if (json_last_error() !== JSON_ERROR_NONE) {
            return [];
        }

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * @param  array<string, mixed>  $composerConfig
     * @return array{optimize: bool, authoritative: bool}
     */
    private function extractComposerOptimizationFlags(array $composerConfig): array
    {
        $config = [];

        if (isset($composerConfig['config']) && is_array($composerConfig['config'])) {
            $config = $composerConfig['config'];
        }

        return [
            'optimize' => isset($config['optimize-autoloader']) ? (bool) $config['optimize-autoloader'] : false,
            'authoritative' => isset($config['classmap-authoritative']) ? (bool) $config['classmap-authoritative'] : false,
        ];
    }

    /**
     * @param  array<string, mixed>  $scripts
     */
    private function composerScriptsRunOptimization(array $scripts): bool
    {
        foreach ($scripts as $commands) {
            foreach ($this->normalizeScriptCommands($commands) as $command) {
                $command = strtolower($command);

                // Check for dump-autoload with optimization flags
                if (str_contains($command, 'dump-autoload')) {
                    // Check for -o or --optimize flags
                    if (str_contains($command, '-o') ||
                        str_contains($command, '--optimize') ||
                        str_contains($command, '--optimize-autoloader') ||
                        str_contains($command, '--classmap-authoritative')) {
                        return true;
                    }
                }

                // Check for install/update with optimization flags
                if (str_contains($command, 'composer install') || str_contains($command, 'composer update')) {
                    if (str_contains($command, '--optimize-autoloader') ||
                        str_contains($command, '--classmap-authoritative')) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * @return array<int, string>
     */
    private function normalizeScriptCommands(mixed $commands): array
    {
        if (is_string($commands)) {
            return [$commands];
        }

        if (is_array($commands)) {
            $normalized = [];
            foreach ($commands as $command) {
                if (is_string($command)) {
                    $normalized[] = $command;
                }
            }

            return $normalized;
        }

        return [];
    }

    /**
     * Find the line number of the "config" section in composer.json.
     * Falls back to line 1 if not found.
     */
    private function findConfigSectionLine(string $composerJsonPath): int
    {
        if (! file_exists($composerJsonPath)) {
            return 1;
        }

        $lines = FileParser::getLines($composerJsonPath);

        if (empty($lines)) {
            return 1;
        }

        foreach ($lines as $lineNumber => $line) {
            // Strip comments (though JSON doesn't support comments, but be safe)
            $lineWithoutComments = FileParser::stripComments($line);

            // Look for "config": pattern (with optional whitespace)
            if (preg_match('/^\s*"config"\s*:/', $lineWithoutComments) === 1) {
                return $lineNumber + 1;
            }
        }

        return 1;
    }
}
