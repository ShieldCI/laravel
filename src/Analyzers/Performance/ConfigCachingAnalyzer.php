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
 * Analyzes configuration caching setup.
 *
 * Checks for:
 * - Config cached in local/dev environment (not recommended)
 * - Config not cached in production (performance issue)
 * - Proper use of php artisan config:cache
 */
class ConfigCachingAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'config-caching',
            name: 'Configuration Caching',
            description: 'Ensures configuration caching is properly configured for each environment',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['cache', 'configuration', 'performance', 'optimization'],
            docsUrl: 'https://laravel.com/docs/configuration#configuration-caching'
        );
    }

    public function shouldRun(): bool
    {
        return file_exists($this->basePath.'/bootstrap/cache');
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $environment = $this->getEnvironment();
        $configIsCached = $this->configurationIsCached();

        if ($environment === 'local' && $configIsCached) {
            $issues[] = $this->createIssue(
                message: 'Configuration is cached in local environment',
                location: new Location($this->basePath.'/bootstrap/cache/config.php', 1),
                severity: Severity::Low,
                recommendation: 'Configuration caching is not recommended for development. Run "php artisan config:clear" to clear the cache. Config changes won\'t be reflected until you clear the cache.',
                metadata: ['environment' => 'local', 'cached' => true]
            );
        } elseif ($environment !== 'local' && ! $configIsCached) {
            $issues[] = $this->createIssue(
                message: "Configuration is not cached in {$environment} environment",
                location: new Location($this->basePath.'/config', 1),
                severity: Severity::Medium,
                recommendation: 'Configuration caching provides significant performance improvements. Add "php artisan config:cache" to your deployment script. This can improve bootstrap time by up to 50%.',
                metadata: ['environment' => $environment, 'cached' => false]
            );
        }

        if (empty($issues)) {
            return $this->passed("Configuration caching is properly configured for {$environment} environment");
        }

        return $this->warning(
            sprintf('Found %d configuration caching issues', count($issues)),
            $issues
        );
    }

    private function configurationIsCached(): bool
    {
        return file_exists($this->basePath.'/bootstrap/cache/config.php');
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
