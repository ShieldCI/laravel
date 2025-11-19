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
            name: 'Composer Autoloader Optimization',
            description: 'Ensures Composer autoloader is optimized for production performance',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['composer', 'autoloader', 'performance', 'optimization'],
            docsUrl: 'https://getcomposer.org/doc/articles/autoloader-optimization.md'
        );
    }

    public function shouldRun(): bool
    {
        // Check if relevant for current environment first
        if (! $this->isRelevantForCurrentEnvironment()) {
            return false;
        }

        // Only run if vendor directory exists
        $autoloadPath = $this->basePath.'/vendor/autoload.php';

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

            $issues[] = $this->createIssue(
                message: $message,
                location: new Location($this->basePath.'/composer.json', 1),
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

            $issues[] = $this->createIssue(
                message: $message,
                location: new Location($this->basePath.'/composer.json', 1),
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

        if (empty($issues)) {
            return $this->passed("Composer autoloader is properly optimized for {$environment} environment");
        }

        return $this->failed(
            sprintf('Found %d autoloader optimization issues', count($issues)),
            $issues
        );
    }

    private function isAutoloaderOptimized(): bool
    {
        $classMapPath = $this->basePath.'/vendor/composer/autoload_classmap.php';

        if (! file_exists($classMapPath)) {
            return false;
        }

        /** @var mixed $classMap */
        $classMap = @include $classMapPath;

        if (! is_array($classMap)) {
            return false;
        }

        // Optimization with -o populates the generated classmap with project classes
        // Unoptimized autoloaders keep this file empty, so count entries instead
        return count($classMap) > 0;
    }

    private function isClassMapAuthoritative(): bool
    {
        $autoloadRealPath = $this->basePath.'/vendor/composer/autoload_real.php';

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
        $composerPath = $this->basePath.'/composer.json';

        if (! file_exists($composerPath)) {
            return [];
        }

        $content = FileParser::readFile($composerPath);
        if ($content === null) {
            return [];
        }

        $decoded = json_decode($content, true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * @param  array<string, mixed>  $composerConfig
     * @return array{optimize: bool, authoritative: bool, apcu: bool}
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
            'apcu' => isset($config['apcu-autoloader']) ? (bool) $config['apcu-autoloader'] : false,
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

                if (str_contains($command, 'dump-autoload') && str_contains($command, '-o')) {
                    return true;
                }

                if (str_contains($command, '--optimize-autoloader') || str_contains($command, '--classmap-authoritative')) {
                    return true;
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
