<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

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
 * Every dump writes autoload_static.php and a classmap, so neither file's presence or
 * size shows -o ran. What -o adds is the root package's PSR-4/PSR-0 classes: the dump
 * is optimized when the generated classmap holds a class under one of those prefixes.
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
        $isOptimized = $this->isAutoloaderOptimized($composerConfig);
        $isAuthoritative = $this->isClassMapAuthoritative();

        if (! $isOptimized && ! $isAuthoritative) {
            $message = $configFlags['optimize']
                ? 'Composer config enables "optimize-autoloader" but the generated autoload files are not optimized'
                : "Composer autoloader is not optimized in {$environment} environment";

            $issues[] = $this->createIssue(
                message: $message,
                location: null,
                severity: Severity::High,
                recommendation: 'Run "composer dump-autoload -o" or "composer install --optimize-autoloader" in production. This converts PSR-4/PSR-0 rules into classmap rules for improved performance. Add this to your deployment script for best results.',
                metadata: [
                    'optimized' => false,
                    'authoritative' => false,
                    'environment' => $environment,
                    'configured_optimize' => $configFlags['optimize'],
                    'configured_authoritative' => $configFlags['authoritative'],
                    'configured_via_scripts' => $scriptsRunOptimization,
                    'detected_via' => 'composer.json',
                ]
            );
        }

        // Recommend authoritative classmap for even better performance
        if ($isOptimized && ! $isAuthoritative) {
            $message = $configFlags['authoritative']
                ? 'Composer config enables classmap authoritative mode but the generated autoload files are not authoritative'
                : 'Composer autoloader could use authoritative classmap for better performance';

            $issues[] = $this->createIssue(
                message: $message,
                location: null,
                severity: Severity::Low,
                recommendation: 'For even better performance, use "composer dump-autoload --classmap-authoritative" or add "classmap-authoritative": true to composer.json config. This prevents the autoloader from falling back to filesystem checks, providing faster class loading. Only enable this if your application does not rely on runtime class discovery.',
                metadata: [
                    'optimized' => true,
                    'authoritative' => false,
                    'environment' => $environment,
                    'configured_optimize' => $configFlags['optimize'],
                    'configured_authoritative' => $configFlags['authoritative'],
                    'configured_via_scripts' => $scriptsRunOptimization,
                    'detected_via' => 'composer.json',
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

    /**
     * @param  array<string, mixed>  $composerConfig
     */
    private function isAutoloaderOptimized(array $composerConfig): bool
    {
        $classMap = $this->includeGeneratedArray('autoload_classmap.php');

        if ($classMap === null) {
            return false;
        }

        // Prefer the root package's own prefixes; without them, the generated PSR-4 rules
        // that point into the project serve, minus any the root declared, since those are
        // only absent because exclude-from-classmap covers them.
        ['usable' => $prefixes, 'declared' => $declared] = $this->rootAutoloadPrefixes($composerConfig);

        if ($prefixes === []) {
            $generated = $this->projectPrefixes($this->includeGeneratedArray('autoload_psr4.php') ?? []);
            $prefixes = array_values(array_diff($generated, $declared));
        }

        // Nothing for -o to have added, so the dump mode cannot be told apart: no finding.
        if ($prefixes === []) {
            return true;
        }

        foreach (array_keys($classMap) as $class) {
            if (! is_string($class)) {
                continue;
            }

            foreach ($prefixes as $prefix) {
                if (str_starts_with($class, $prefix)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The PSR-4 and PSR-0 prefixes of the root package's `autoload` section (not
     * `autoload-dev`). `declared` holds them all; `usable` drops those whose directories
     * exclude-from-classmap covers entirely, as -o never adds their classes.
     *
     * @param  array<string, mixed>  $composerConfig
     * @return array{usable: list<string>, declared: list<string>}
     */
    private function rootAutoloadPrefixes(array $composerConfig): array
    {
        $autoload = $composerConfig['autoload'] ?? null;

        if (! is_array($autoload)) {
            return ['usable' => [], 'declared' => []];
        }

        $excluded = [];
        if (isset($autoload['exclude-from-classmap']) && is_array($autoload['exclude-from-classmap'])) {
            foreach ($autoload['exclude-from-classmap'] as $pattern) {
                if (! is_string($pattern)) {
                    continue;
                }

                // "dir/**" and "dir/*" (Composer compiles it to dir/[^/]+?($|/)) exclude all of
                // dir, as a plain path does; any other glob is not resolved, so it never covers.
                $pattern = rtrim(str_replace('\\', '/', $pattern), '/');
                if (str_ends_with($pattern, '/**')) {
                    $pattern = substr($pattern, 0, -3);
                } elseif (str_ends_with($pattern, '/*')) {
                    $pattern = substr($pattern, 0, -2);
                }

                if (! str_contains($pattern, '*')) {
                    $excluded[] = $this->normalizeDirectory($pattern);
                }
            }
        }

        $usable = [];
        $declared = [];

        foreach (['psr-4', 'psr-0'] as $standard) {
            if (! isset($autoload[$standard]) || ! is_array($autoload[$standard])) {
                continue;
            }

            foreach ($autoload[$standard] as $prefix => $directories) {
                $prefix = $this->normalizePrefix($prefix);

                if ($prefix === null) {
                    continue;
                }

                $declared[] = $prefix;

                if (! $this->allDirectoriesExcluded($directories, $excluded)) {
                    $usable[] = $prefix;
                }
            }
        }

        return ['usable' => $usable, 'declared' => $declared];
    }

    /**
     * @param  list<string>  $excluded  normalized exclude-from-classmap paths
     */
    private function allDirectoriesExcluded(mixed $directories, array $excluded): bool
    {
        $directories = is_string($directories) ? [$directories] : (is_array($directories) ? $directories : []);
        $covered = false;

        foreach ($directories as $directory) {
            if (! is_string($directory)) {
                continue;
            }

            $directory = $this->normalizeDirectory($directory);
            $isExcluded = false;

            foreach ($excluded as $exclusion) {
                if ($exclusion !== '' && ($directory === $exclusion || str_starts_with($directory, $exclusion.'/'))) {
                    $isExcluded = true;
                    break;
                }
            }

            if (! $isExcluded) {
                return false;
            }

            $covered = true;
        }

        return $covered;
    }

    private function normalizeDirectory(string $path): string
    {
        $path = str_replace('\\', '/', $path);

        // Composer trims surrounding slashes from exclude-from-classmap patterns.
        while (str_starts_with($path, './') || str_starts_with($path, '/')) {
            $path = substr($path, str_starts_with($path, './') ? 2 : 1);
        }

        return rtrim($path, '/');
    }

    /**
     * Composer drops a leading backslash from a prefix, so the classmap keys never carry
     * one. The PSR-0 "" fallback prefix matches every class, so it is not a prefix here.
     */
    private function normalizePrefix(int|string $prefix): ?string
    {
        if (! is_string($prefix)) {
            return null;
        }

        $prefix = ltrim($prefix, '\\');

        return $prefix === '' ? null : $prefix;
    }

    /**
     * The prefixes of autoload_psr4.php whose directories all lie inside the project and
     * outside vendor/: the root package's own rules. A dependency's prefix can match a
     * plain dump's classmap when the package also declares a `classmap` (nette/utils does).
     *
     * @param  array<mixed>  $psr4
     * @return list<string>
     */
    private function projectPrefixes(array $psr4): array
    {
        $base = $this->resolvePath($this->getBasePath()).'/';
        $vendor = $this->resolvePath($this->buildPath('vendor')).'/';
        $prefixes = [];

        foreach ($psr4 as $prefix => $directories) {
            $prefix = $this->normalizePrefix($prefix);

            if ($prefix === null || ! is_array($directories) || $directories === []) {
                continue;
            }

            foreach ($directories as $directory) {
                if (! is_string($directory)) {
                    continue 2;
                }

                $directory = $this->resolvePath($directory).'/';

                if (! str_starts_with($directory, $base) || str_starts_with($directory, $vendor)) {
                    continue 2;
                }
            }

            $prefixes[] = $prefix;
        }

        return $prefixes;
    }

    /**
     * Resolve symlinks (macOS temp dirs live under /private/var) when the path exists;
     * Composer builds the generated paths from the resolved vendor directory either way.
     */
    private function resolvePath(string $path): string
    {
        $resolved = realpath($path);

        return rtrim(str_replace('\\', '/', $resolved === false ? $path : $resolved), '/');
    }

    /**
     * Load one of the array files Composer generates in vendor/composer/.
     *
     * @return array<mixed>|null null when the file is missing or does not return an array
     */
    private function includeGeneratedArray(string $file): ?array
    {
        $path = $this->buildPath('vendor', 'composer', $file);

        if (! file_exists($path)) {
            return null;
        }

        // A truncated or hand-edited file is a parse error, which @ does not silence.
        try {
            /** @var mixed $contents */
            $contents = @include $path;
        } catch (\ParseError) {
            return null;
        }

        return is_array($contents) ? $contents : null;
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

        // Check if setClassMapAuthoritative is called with true
        // Use regex to handle formatting variations and whitespace
        return preg_match('/setClassMapAuthoritative\s*\(\s*true\s*\)/', $content) === 1;
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
                $commandLower = strtolower($command);

                // Skip obvious false positives (echo, comments, string literals)
                if (preg_match('/^\s*(echo|#|\/\/|\/\*)/', $commandLower) ||
                    str_contains($commandLower, 'echo ')) {
                    continue;
                }

                // Check for composer dump-autoload with optimization flags
                // Require both "composer" and "dump-autoload" in the same command
                if (str_contains($commandLower, 'composer') && str_contains($commandLower, 'dump-autoload')) {
                    // Check for -o or --optimize flags
                    if (preg_match('/\s-o[a-z]*\b/', $commandLower) ||
                        str_contains($commandLower, '--optimize') ||
                        str_contains($commandLower, '--classmap-authoritative')) {
                        return true;
                    }
                }

                // Check for composer install/update with optimization flags
                if (str_contains($commandLower, 'composer install') || str_contains($commandLower, 'composer update')) {
                    if (str_contains($commandLower, '--optimize-autoloader') ||
                        str_contains($commandLower, '--classmap-authoritative')) {
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
}
