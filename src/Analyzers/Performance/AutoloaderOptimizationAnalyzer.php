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
 * Checks for:
 * - Autoloader optimization (composer dump-autoload -o) in production
 * - Authoritative class map (composer dump-autoload --classmap-authoritative)
 * - APCu optimization for better performance
 */
class AutoloaderOptimizationAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Autoloader optimization checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

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
        $environment = $this->getEnvironment();

        // Skip in local environment
        return $environment !== 'local' && file_exists($this->basePath.'/vendor/autoload.php');
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $autoloadPath = $this->basePath.'/vendor/autoload.php';

        if (! file_exists($autoloadPath)) {
            return $this->skipped('Composer vendor directory not found');
        }

        // Check if autoloader is optimized
        $isOptimized = $this->isAutoloaderOptimized();
        $isAuthoritative = $this->isClassMapAuthoritative();

        if (! $isOptimized && ! $isAuthoritative) {
            $issues[] = $this->createIssue(
                message: 'Composer autoloader is not optimized in production',
                location: new Location($this->basePath.'/composer.json', 1),
                severity: Severity::High,
                recommendation: 'Run "composer dump-autoload -o" or "composer install --optimize-autoloader" in production. This converts PSR-4/PSR-0 rules into classmap rules for improved performance. Add this to your deployment script for best results.',
                metadata: [
                    'optimized' => false,
                    'authoritative' => false,
                    'environment' => $this->getEnvironment(),
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
                    'environment' => $this->getEnvironment(),
                ]
            );
        }

        if (empty($issues)) {
            return $this->passed('Composer autoloader is properly optimized for production');
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

        $content = file_get_contents($staticLoaderPath);

        if ($content === false) {
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

        $content = file_get_contents($autoloadRealPath);

        if ($content === false) {
            return false;
        }

        // Check if setClassMapAuthoritative is called
        return str_contains($content, 'setClassMapAuthoritative(true)');
    }

    private function getEnvironment(): string
    {
        $envFile = $this->basePath.'/.env';

        if (! file_exists($envFile)) {
            return 'production';
        }

        $content = file_get_contents($envFile);

        if (preg_match('/^APP_ENV\s*=\s*(\w+)/m', $content, $matches)) {
            return $matches[1];
        }

        return 'production';
    }
}
