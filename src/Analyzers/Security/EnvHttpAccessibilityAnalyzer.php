<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Routing\Router;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\FindsLoginRoute;

/**
 * Checks if .env file is publicly accessible via HTTP.
 *
 * Makes HTTP requests to verify .env cannot be accessed via web server.
 * This is a runtime check that complements the static EnvFileSecurityAnalyzer.
 *
 * Checks for:
 * - .env accessible at root level
 * - .env accessible from parent directories
 * - .env accessible in public directory
 * - .env accessible in storage directory
 */
class EnvHttpAccessibilityAnalyzer extends AbstractAnalyzer
{
    use FindsLoginRoute;

    /**
     * HTTP checks require a live web server, not applicable in CI.
     */
    public static bool $runInCI = false;

    private Client $httpClient;

    /**
     * Sensitive keys that indicate .env file content.
     */
    private array $envIndicators = [
        'APP_NAME=',
        'APP_ENV=',
        'APP_KEY=',
        'DB_CONNECTION=',
        'DB_HOST=',
        'DB_DATABASE=',
        'DB_USERNAME=',
        'DB_PASSWORD=',
    ];

    public function __construct(Router $router)
    {
        $this->router = $router;
        $this->httpClient = new Client([
            'timeout' => 5,
            'connect_timeout' => 3,
            'http_errors' => false, // Don't throw on 4xx/5xx
            'verify' => false, // Allow self-signed certs in staging
        ]);
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'env-http-accessibility',
            name: 'Environment File HTTP Accessibility Check',
            description: 'Verifies .env file is not accessible via HTTP requests to the web server',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['env', 'http', 'security', 'runtime', 'web-server', 'deployment'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/env-http-accessibility',
            timeToFix: 20
        );
    }

    public function shouldRun(): bool
    {
        // Only run if we can find a guest route to test from
        $url = $this->findLoginRoute();

        if ($url === null) {
            return false;
        }

        // Skip localhost URLs (local development)
        if (str_contains($url, 'localhost') || str_contains($url, '127.0.0.1')) {
            return false;
        }

        return true;
    }

    public function getSkipReason(): string
    {
        $url = $this->findLoginRoute();

        if ($url === null) {
            return 'No guest URL found for HTTP accessibility check';
        }

        // Otherwise, provide specific reason about localhost URLs
        return 'Skipped for localhost URLs (local development environment)';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $guestUrl = $this->findLoginRoute();

        if ($guestUrl === null) {
            return $this->warning('No guest URL found - skipping HTTP accessibility check');
        }

        // Extract base URL from the guest URL
        $appUrl = $this->extractBaseUrl($guestUrl);

        // Test multiple possible .env locations
        $envPaths = [
            '.env',                // Root level
            '../.env',             // One directory up
            '../../.env',          // Two directories up
            '../../../.env',       // Three directories up (rare but possible)
            'storage/.env',        // In storage (misconfiguration)
            'public/.env',         // In public (critical misconfiguration)
            'app/.env',            // In app directory
            'config/.env',         // In config directory
        ];

        $testedUrls = [];

        foreach ($envPaths as $path) {
            $testUrl = rtrim($appUrl, '/').'/'.ltrim($path, '/');

            // Avoid duplicate tests
            if (in_array($testUrl, $testedUrls, true)) {
                continue;
            }

            $testedUrls[] = $testUrl;

            $result = $this->checkEnvAccessibility($testUrl);

            if ($result['accessible']) {
                $issues[] = $this->createIssue(
                    message: sprintf('.env file is publicly accessible via HTTP at: %s', $testUrl),
                    location: new Location('.env', 1),
                    severity: $this->determineSeverity($path),
                    recommendation: $this->getRecommendation($path),
                    metadata: [
                        'url' => $testUrl,
                        'path' => $path,
                        'accessible' => true,
                        'indicators_found' => $result['indicators_found'],
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('.env file is not accessible via HTTP - web server properly configured');
        }

        $criticalCount = collect($issues)->filter(fn (Issue $issue) => $issue->severity === Severity::Critical)->count();

        if ($criticalCount > 0) {
            return $this->failed(
                sprintf('CRITICAL SECURITY ISSUE: .env file is publicly accessible at %d location(s)!', count($issues)),
                $issues
            );
        }

        return $this->warning(
            sprintf('Found %d potential .env accessibility issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Check if .env is accessible at the given URL.
     *
     * @return array{accessible: bool, indicators_found: array<string>}
     */
    private function checkEnvAccessibility(string $url): array
    {
        try {
            $response = $this->httpClient->get($url);
            $statusCode = $response->getStatusCode();
            $body = (string) $response->getBody();

            // If we don't get a 200, it's likely blocked (good!)
            if ($statusCode !== 200) {
                return ['accessible' => false, 'indicators_found' => []];
            }

            // Check if the content looks like an .env file
            $indicatorsFound = [];

            foreach ($this->envIndicators as $indicator) {
                if (str_contains($body, $indicator)) {
                    $indicatorsFound[] = $indicator;
                }
            }

            // If we found 2 or more indicators, it's very likely an .env file
            if (count($indicatorsFound) >= 2) {
                return ['accessible' => true, 'indicators_found' => $indicatorsFound];
            }

            // Check for .env-like patterns (key=value format)
            $envPattern = '/^[A-Z_][A-Z0-9_]*\s*=\s*.+$/m';
            if (preg_match($envPattern, $body)) {
                // Found key=value patterns, but no specific indicators
                // Could be a false positive, so mark as accessible but with caution
                return ['accessible' => true, 'indicators_found' => ['KEY=VALUE pattern detected']];
            }

            return ['accessible' => false, 'indicators_found' => []];

        } catch (RequestException $e) {
            // Network errors, timeouts, DNS failures, etc.
            // We'll assume the file is not accessible (could be blocked, which is good)
            return ['accessible' => false, 'indicators_found' => []];
        } catch (\Throwable $e) {
            // Any other error - assume not accessible
            return ['accessible' => false, 'indicators_found' => []];
        }
    }

    /**
     * Determine severity based on the path where .env was found.
     */
    private function determineSeverity(string $path): Severity
    {
        // Critical: .env in public directories or easily guessable root paths
        if (str_contains($path, 'public/') || $path === '.env' || $path === '../.env') {
            return Severity::Critical;
        }

        // High: .env in other accessible directories
        if (str_contains($path, 'storage/') || str_contains($path, 'app/') || str_contains($path, 'config/')) {
            return Severity::High;
        }

        // Medium: .env in less common locations (path traversal attempts)
        return Severity::Medium;
    }

    /**
     * Get recommendation based on where .env was found.
     */
    private function getRecommendation(string $path): string
    {
        $baseRecommendation = 'IMMEDIATE ACTION REQUIRED: ';

        if (str_contains($path, 'public/')) {
            return $baseRecommendation.
                   'Remove .env from the public directory immediately. '.
                   'The .env file must NEVER be in a publicly accessible directory. '.
                   'Configure your web server to serve only from public/ and keep .env one level above.';
        }

        if ($path === '.env' || $path === '../.env') {
            return $baseRecommendation.
                   'Configure your web server to block access to .env files. '.
                   'Add deny rules in .htaccess (Apache): "RewriteRule ^\.env$ - [F,L]" or '.
                   'nginx config: "location ~ /\.env { deny all; }" '.
                   'Also ensure your document root is set to public/ directory.';
        }

        return $baseRecommendation.
               'Configure your web server to block directory traversal and access to .env files. '.
               'Review your web server configuration and ensure path traversal attacks are blocked.';
    }

    /**
     * Extract base URL from a full URL.
     *
     * Example: https://example.com/login -> https://example.com
     */
    private function extractBaseUrl(string $url): string
    {
        $parsed = parse_url($url);

        $scheme = $parsed['scheme'] ?? 'https';
        $host = $parsed['host'] ?? '';
        $port = isset($parsed['port']) ? ':'.$parsed['port'] : '';

        return "{$scheme}://{$host}{$port}";
    }

    /**
     * Allow injection of HTTP client for testing.
     */
    public function setHttpClient(Client $client): void
    {
        $this->httpClient = $client;
    }
}
