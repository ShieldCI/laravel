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
 * Analyzes session driver configuration for performance and scalability.
 *
 * Checks for:
 * - File session driver in multi-server environments
 * - Cookie session driver limitations
 * - Array session driver in production
 * - Recommends Redis/Database for production
 */
class SessionDriverAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'session-driver',
            name: 'Session Driver Configuration',
            description: 'Ensures a proper session driver is configured for scalability and performance',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['session', 'performance', 'configuration', 'redis', 'scalability'],
            docsUrl: 'https://laravel.com/docs/session#driver-prerequisites'
        );
    }

    public function shouldRun(): bool
    {
        return file_exists($this->getConfigPath('session.php'));
    }

    public function getSkipReason(): string
    {
        return 'Session configuration file (config/session.php) not found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $sessionConfig = $this->getSessionConfig();
        $driver = $sessionConfig['driver'] ?? 'file';
        $environment = $this->getEnvironment();

        // Check for problematic drivers
        if ($driver === 'array' && $environment !== 'local') {
            $issues[] = $this->createIssue(
                message: "Session driver is set to 'array' in {$environment} environment",
                location: new Location($this->getConfigPath('session.php'), $this->findLineInConfig('session', 'driver')),
                severity: Severity::Critical,
                recommendation: 'Array driver stores sessions in memory and they are lost after the request. This is only suitable for testing. Use redis, database, or file for production.',
                metadata: ['driver' => 'array', 'environment' => $environment]
            );
        } elseif ($driver === 'file' && $environment !== 'local') {
            $issues[] = $this->createIssue(
                message: "Session driver is set to 'file' in {$environment} environment",
                location: new Location($this->getConfigPath('session.php'), $this->findLineInConfig('session', 'driver')),
                severity: Severity::Medium,
                recommendation: 'File session driver only works properly on single-server setups. For load-balanced or multi-server environments, use redis or database driver to share sessions across servers. File sessions can cause users to be logged out when requests hit different servers.',
                metadata: ['driver' => 'file', 'environment' => $environment]
            );
        } elseif ($driver === 'cookie') {
            $issues[] = $this->createIssue(
                message: "Session driver is set to 'cookie'",
                location: new Location($this->getConfigPath('session.php'), $this->findLineInConfig('session', 'driver')),
                severity: Severity::Low,
                recommendation: 'Cookie driver stores all session data in encrypted cookies. This has a 4KB size limit and every request sends all session data. For better performance and security, consider using redis or database driver.',
                metadata: ['driver' => 'cookie', 'environment' => $environment]
            );
        }

        if (empty($issues)) {
            return $this->passed("Session driver '{$driver}' is properly configured for {$environment} environment");
        }

        return $this->failed(
            sprintf('Found %d session driver configuration issues', count($issues)),
            $issues
        );
    }

    private function getSessionConfig(): array
    {
        $configFile = $this->getConfigPath('session.php');

        if (! file_exists($configFile)) {
            return [];
        }

        return include $configFile;
    }

    private function getConfigPath(string $file): string
    {
        return $this->basePath.'/config/'.$file;
    }

    private function findLineInConfig(string $file, string $key): int
    {
        $configFile = $this->getConfigPath($file.'.php');

        if (! file_exists($configFile)) {
            return 1;
        }

        $lines = file($configFile);

        foreach ($lines as $lineNumber => $line) {
            if (str_contains($line, "'{$key}'") || str_contains($line, "\"{$key}\"")) {
                return $lineNumber + 1;
            }
        }

        return 1;
    }
}
