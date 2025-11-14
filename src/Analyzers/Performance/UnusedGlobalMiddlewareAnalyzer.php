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
 * Detects unused global HTTP middleware in the application.
 *
 * Checks for:
 * - TrustProxies middleware without configured proxies
 * - TrustHosts middleware without TrustProxies (useless)
 * - CORS middleware without configured paths
 */
class UnusedGlobalMiddlewareAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<int, array{name: string, reason: string, recommendation: string}>
     */
    private array $unusedMiddleware = [];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'unused-global-middleware',
            name: 'Unused Global Middleware',
            description: 'Detects global HTTP middleware that is registered but not being used, causing unnecessary overhead on every request',
            category: Category::Performance,
            severity: Severity::Low,
            tags: ['performance', 'middleware', 'optimization', 'http'],
            docsUrl: 'https://laravel.com/docs/middleware#global-middleware'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $kernelPath = $this->basePath.'/app/Http/Kernel.php';

        if (! file_exists($kernelPath)) {
            return $this->warning('HTTP Kernel file not found', [
                $this->createIssue(
                    message: 'Could not locate app/Http/Kernel.php',
                    location: new Location($this->basePath.'/app/Http', 0),
                    severity: Severity::Low,
                    recommendation: 'Ensure your Laravel application has the standard app/Http/Kernel.php file.',
                    metadata: ['kernel_path' => $kernelPath]
                ),
            ]);
        }

        $this->checkTrustProxiesMiddleware();
        $this->checkTrustHostsMiddleware();
        $this->checkCorsMiddleware();

        if (empty($this->unusedMiddleware)) {
            return $this->passed('No unused global middleware detected');
        }

        $issues = [];
        foreach ($this->unusedMiddleware as $middleware) {
            $issues[] = $this->createIssue(
                message: "Unused global middleware detected: {$middleware['name']}",
                location: new Location($this->basePath.'/app/Http/Kernel.php', 0),
                severity: Severity::Low,
                recommendation: $middleware['recommendation'],
                metadata: [
                    'middleware' => $middleware['name'],
                    'reason' => $middleware['reason'],
                ]
            );
        }

        return $this->failed(
            sprintf('Found %d unused global middleware', count($this->unusedMiddleware)),
            $issues
        );
    }

    private function checkTrustProxiesMiddleware(): void
    {
        $kernelContent = $this->getKernelContent();
        if ($kernelContent === null) {
            return;
        }

        // Check if TrustProxies middleware is registered
        $hasTrustProxies = str_contains($kernelContent, 'TrustProxies::class')
            || str_contains($kernelContent, '\\Illuminate\\Http\\Middleware\\TrustProxies')
            || str_contains($kernelContent, '\\Fideloper\\Proxy\\TrustProxies');

        if (! $hasTrustProxies) {
            return;
        }

        // Check if proxies are configured
        $trustProxiesPath = $this->basePath.'/app/Http/Middleware/TrustProxies.php';
        if (! file_exists($trustProxiesPath)) {
            return;
        }

        $trustProxiesContent = file_get_contents($trustProxiesPath);
        if ($trustProxiesContent === false) {
            return;
        }

        // Check if $proxies property is set to something other than null or empty
        $hasConfiguredProxies = preg_match('/protected\s+\$proxies\s*=\s*["\'\[]/', $trustProxiesContent) === 1
            || preg_match('/protected\s+\$proxies\s*=\s*\*/', $trustProxiesContent) === 1;

        // Check trustedproxy config (for older Laravel versions)
        $trustedProxyConfigPath = $this->basePath.'/config/trustedproxy.php';
        $hasTrustedProxyConfig = false;
        if (file_exists($trustedProxyConfigPath)) {
            $configContent = file_get_contents($trustedProxyConfigPath);
            if ($configContent !== false) {
                $hasTrustedProxyConfig = preg_match('/"proxies"\s*=>\s*["\'\[]/', $configContent) === 1
                    || preg_match('/"proxies"\s*=>\s*\*/', $configContent) === 1;
            }
        }

        if (! $hasConfiguredProxies && ! $hasTrustedProxyConfig) {
            $this->unusedMiddleware[] = [
                'name' => 'TrustProxies',
                'reason' => 'No proxies are configured',
                'recommendation' => 'Remove TrustProxies middleware from app/Http/Kernel.php $middleware array, as no proxies are configured. This middleware runs on every request unnecessarily. Only add it back if you deploy behind a proxy (like CloudFlare, AWS ALB, nginx).',
            ];
        }
    }

    private function checkTrustHostsMiddleware(): void
    {
        $kernelContent = $this->getKernelContent();
        if ($kernelContent === null) {
            return;
        }

        // Check if TrustHosts middleware is registered
        $hasTrustHosts = str_contains($kernelContent, 'TrustHosts::class')
            || str_contains($kernelContent, '\\Illuminate\\Http\\Middleware\\TrustHosts');

        if (! $hasTrustHosts) {
            return;
        }

        // Check if TrustProxies is also registered
        $hasTrustProxies = str_contains($kernelContent, 'TrustProxies::class')
            || str_contains($kernelContent, '\\Illuminate\\Http\\Middleware\\TrustProxies')
            || str_contains($kernelContent, '\\Fideloper\\Proxy\\TrustProxies');

        if (! $hasTrustProxies) {
            $this->unusedMiddleware[] = [
                'name' => 'TrustHosts',
                'reason' => 'TrustHosts is useless without TrustProxies',
                'recommendation' => 'Remove TrustHosts middleware from app/Http/Kernel.php $middleware array. TrustHosts only works when used together with TrustProxies middleware, as it validates the Host header from trusted proxies.',
            ];
        }
    }

    private function checkCorsMiddleware(): void
    {
        $kernelContent = $this->getKernelContent();
        if ($kernelContent === null) {
            return;
        }

        // Check if CORS middleware is registered
        $hasCors = str_contains($kernelContent, 'HandleCors::class')
            || str_contains($kernelContent, '\\Illuminate\\Http\\Middleware\\HandleCors')
            || str_contains($kernelContent, '\\Fruitcake\\Cors\\HandleCors');

        if (! $hasCors) {
            return;
        }

        // Check if CORS paths are configured
        $corsConfigPath = $this->basePath.'/config/cors.php';
        if (! file_exists($corsConfigPath)) {
            // No config file means CORS is not configured
            $this->unusedMiddleware[] = [
                'name' => 'HandleCors',
                'reason' => 'No CORS configuration file exists',
                'recommendation' => 'Remove HandleCors middleware from app/Http/Kernel.php $middleware array, as no CORS paths are configured. This middleware runs on every request unnecessarily. Only add it back if you need to handle Cross-Origin Resource Sharing.',
            ];

            return;
        }

        $configContent = file_get_contents($corsConfigPath);
        if ($configContent === false) {
            return;
        }

        // Check if paths array is empty
        $hasConfiguredPaths = preg_match('/"paths"\s*=>\s*\[\s*["\']/', $configContent) === 1;

        if (! $hasConfiguredPaths) {
            $this->unusedMiddleware[] = [
                'name' => 'HandleCors',
                'reason' => 'No CORS paths are configured',
                'recommendation' => 'Remove HandleCors middleware from app/Http/Kernel.php $middleware array, as the "paths" configuration is empty. This middleware runs on every request unnecessarily. Only add it back when you configure specific paths that require CORS handling.',
            ];
        }
    }

    private function getKernelContent(): ?string
    {
        $kernelPath = $this->basePath.'/app/Http/Kernel.php';
        if (! file_exists($kernelPath)) {
            return null;
        }

        $content = file_get_contents($kernelPath);

        return $content === false ? null : $content;
    }
}
