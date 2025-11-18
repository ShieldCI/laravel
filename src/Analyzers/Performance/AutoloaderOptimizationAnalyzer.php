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

        // Check if autoloader is optimized
        $isOptimized = $this->isAutoloaderOptimized();
        $isAuthoritative = $this->isClassMapAuthoritative();

        if (! $isOptimized && ! $isAuthoritative) {
            $issues[] = $this->createIssue(
                message: "Composer autoloader is not optimized in {$environment} environment",
                location: new Location($this->basePath.'/composer.json', 1),
                severity: Severity::High,
                recommendation: 'Run "composer dump-autoload -o" or "composer install --optimize-autoloader" in production. This converts PSR-4/PSR-0 rules into classmap rules for improved performance. Add this to your deployment script for best results.',
                metadata: [
                    'optimized' => false,
                    'authoritative' => false,
                    'environment' => $environment,
                ]
            );
        }

        // Recommend authoritative classmap for even better performance
        if ($isOptimized && ! $isAuthoritative) {
            $issues[] = $this->createIssue(
                message: 'Composer autoloader could use authoritative classmap for better performance',
                location: new Location($this->basePath.'/composer.json', 1),
                severity: Severity::Low,
                recommendation: 'For even better performance, use "composer dump-autoload --classmap-authoritative" or add "classmap-authoritative": true to composer.json config. This prevents the autoloader from falling back to filesystem checks, providing faster class loading.',
                metadata: [
                    'optimized' => true,
                    'authoritative' => false,
                    'environment' => $environment,
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
        $staticLoaderPath = $this->basePath.'/vendor/composer/autoload_static.php';

        if (! file_exists($staticLoaderPath)) {
            return false;
        }

        $content = $this->readFile($staticLoaderPath);

        if (is_null($content)) {
            return false;
        }

        // Check if classmap is populated (indication of optimization)
        // The classmap should contain core Laravel classes if optimized
        return str_contains($content, 'public static $classMap') &&
               str_contains($content, 'Illuminate\\');
    }

    private function isClassMapAuthoritative(): bool
    {
        $autoloadRealPath = $this->basePath.'/vendor/composer/autoload_real.php';

        if (! file_exists($autoloadRealPath)) {
            return false;
        }

        $content = $this->readFile($autoloadRealPath);

        if (is_null($content)) {
            return false;
        }

        // Check if setClassMapAuthoritative is called
        return str_contains($content, 'setClassMapAuthoritative(true)');
    }
}
