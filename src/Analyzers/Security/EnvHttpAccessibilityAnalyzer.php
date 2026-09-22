<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use Illuminate\Routing\Router;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\FindsLoginRoute;
use ShieldCI\Support\OriginReachability\DeclaredOrigin;
use ShieldCI\Support\OriginReachability\OriginProbeResult;
use ShieldCI\Support\OriginReachability\OriginReachabilityChecker;

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

    private OriginReachabilityChecker $checker;

    /**
     * HTTP checks require a live web server, not applicable in CI.
     */
    public static bool $runInCI = false;

    /**
     * Minimum number of indicators required to confirm .env file.
     */
    private const MIN_INDICATORS_FOR_DETECTION = 2;

    /**
     * Sensitive keys that indicate .env file content.
     *
     * @var list<string>
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

    /**
     * The checker is a container singleton, so the origin is probed once per path for the
     * whole run however many analyzers ask about it.
     *
     * Certificate verification is the checker's and is left on. This analyzer used to
     * disable it to tolerate self-signed certificates in staging, but it runs in production
     * too, and a conclusion of "the web server is properly configured" drawn over a
     * connection whose peer was never authenticated is a claim about a host we cannot
     * identify. An untrusted certificate is now a named outcome carrying no evidence, which
     * is more than the pass it used to produce.
     */
    public function __construct(Router $router, OriginReachabilityChecker $checker)
    {
        $this->router = $router;
        $this->checker = $checker;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'env-http-accessibility',
            name: 'Environment File HTTP Accessibility Analyzer',
            description: 'Verifies .env file is not accessible via HTTP requests to the web server',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['env', 'http', 'security', 'runtime', 'web-server', 'deployment'],
            timeToFix: 20
        );
    }

    public function shouldRun(): bool
    {
        // HTTP accessibility checks only apply in deployed environments
        if (! $this->isHttpCheckEnvironment()) {
            return false;
        }

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
        if (! $this->isHttpCheckEnvironment()) {
            return sprintf('HTTP accessibility checks only run in production/staging (current: %s)', $this->getEnvironment());
        }

        $url = $this->findLoginRoute();

        if ($url === null) {
            return 'No guest URL found for HTTP accessibility check';
        }

        return 'Skipped for localhost URLs (local development environment)';
    }

    private function isHttpCheckEnvironment(): bool
    {
        $current = $this->getEnvironment();

        return strcasecmp($current, 'production') === 0
            || strcasecmp($current, 'staging') === 0;
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

        if ($appUrl === '') {
            return $this->warning('Could not determine the application origin - skipping HTTP accessibility check');
        }

        $origin = new DeclaredOrigin($appUrl, [DeclaredOrigin::SOURCE_APP_URL]);

        // Paths that produced no response at all. They are neither safe nor exposed: they
        // are unknown, and the difference decides whether this run may claim anything.
        $unobserved = [];

        foreach ($envPaths as $path) {
            $result = $this->checkEnvAccessibility($origin, $path);

            if (! $result['observed']) {
                $unobserved[] = $path;

                continue;
            }

            if ($result['accessible']) {
                $issues[] = $this->createIssue(
                    message: sprintf('.env file is publicly accessible via HTTP at: %s', $result['url']),
                    location: new Location('.env'),
                    severity: $this->determineSeverity($path),
                    recommendation: $this->getRecommendation($path),
                    metadata: [
                        'url' => $result['url'],
                        'path' => $path,
                        'accessible' => true,
                        'indicators_found' => $result['indicators_found'],
                        'status_code' => $result['status_code'] ?? null,
                        'response_size' => $result['response_size'] ?? null,
                        'server_type' => $result['server_type'] ?? null,
                    ]
                );
            }
        }

        // Nothing found and something unchecked is not a clean bill of health. Returning
        // passed here is the defect this analyzer was filed for: every probe failing read
        // as the web server being properly configured.
        if ($issues === [] && $unobserved !== []) {
            return $this->warning(sprintf(
                'Could not verify .env accessibility: %d of %d location%s on %s produced no response, so nothing was learned about %s.',
                count($unobserved),
                count($envPaths),
                count($envPaths) === 1 ? '' : 's',
                $appUrl,
                count($unobserved) === 1 ? 'it' : 'them'
            ));
        }

        $summary = $issues === []
            ? '.env file is not accessible via HTTP - web server properly configured'
            : sprintf('.env file is publicly accessible at %d location%s', count($issues), count($issues) === 1 ? '' : 's');

        if ($issues !== [] && $unobserved !== []) {
            $summary .= sprintf(' (%d further location%s could not be checked)', count($unobserved), count($unobserved) === 1 ? '' : 's');
        }

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check whether .env is reachable at one path on the declared origin.
     *
     * Three states, not two. "The server answered and the file is not there" and "nothing
     * answered" are different facts about the deployment, and reporting the first when the
     * second happened is how this analyzer used to certify a web server it never reached.
     * The caller reads `observed` before it reads `accessible`.
     *
     * @return array{observed: bool, accessible: bool, indicators_found: array<string>, url: string, status_code?: int, response_size?: int, server_type?: string|null, reason?: string}
     */
    private function checkEnvAccessibility(DeclaredOrigin $origin, string $path): array
    {
        $probe = $this->checker->probe([$origin], null, [], $path)->probeFor($origin->origin);

        if ($probe === null || ! $probe->hasEvidence()) {
            return [
                'observed' => false,
                'accessible' => false,
                'indicators_found' => [],
                'url' => $probe->probedUrl ?? $origin->origin,
                'reason' => $probe?->describe() ?? 'the origin was not probed',
            ];
        }

        $url = $probe->probedUrl;
        $statusCode = $probe->statusCode ?? 0;

        // If we don't get a 200, it's likely blocked (good!)
        if ($statusCode !== 200) {
            return [
                'observed' => true,
                'accessible' => false,
                'indicators_found' => [],
                'url' => $url,
                'status_code' => $statusCode,
            ];
        }

        $body = $probe->bodyPrefix ?? '';
        $serverType = $probe->header('Server');

        // Check if the content looks like an .env file
        $indicatorsFound = [];

        foreach ($this->envIndicators as $indicator) {
            if (str_contains($body, $indicator)) {
                $indicatorsFound[] = $indicator;
            }
        }

        $found = static fn (array $indicators): array => [
            'observed' => true,
            'accessible' => true,
            'indicators_found' => $indicators,
        ];

        // If we found enough indicators, it's very likely an .env file
        if (count($indicatorsFound) >= self::MIN_INDICATORS_FOR_DETECTION) {
            return $found($indicatorsFound) + [
                'url' => $url,
                'status_code' => $statusCode,
                'response_size' => $this->responseSize($probe, $body),
                'server_type' => $serverType ?: null,
            ];
        }

        // Check for .env-like patterns (key=value format)
        $envPattern = '/^[A-Z_][A-Z0-9_]*\s*=\s*.+$/m';
        if (preg_match($envPattern, $body)) {
            // Found key=value patterns, but no specific indicators
            // Could be a false positive, so mark as accessible but with caution
            return $found(['KEY=VALUE pattern detected']) + [
                'url' => $url,
                'status_code' => $statusCode,
                'response_size' => $this->responseSize($probe, $body),
                'server_type' => $serverType ?: null,
            ];
        }

        return [
            'observed' => true,
            'accessible' => false,
            'indicators_found' => [],
            'url' => $url,
            'status_code' => $statusCode,
        ];
    }

    /**
     * Size of the exposed file.
     *
     * The probe keeps only a prefix of the body, so the captured length understates a large
     * file. Content-Length is what the server said the whole thing weighs and is preferred
     * when it is present and sane.
     */
    private function responseSize(OriginProbeResult $probe, string $body): int
    {
        $declared = $probe->header('Content-Length');

        return $declared !== null && ctype_digit($declared) ? (int) $declared : strlen($body);
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

        // parse_url() can return false for malformed URLs
        if ($parsed === false || ! is_array($parsed)) {
            return '';
        }

        $scheme = $parsed['scheme'] ?? 'https';
        $host = $parsed['host'] ?? '';
        $port = isset($parsed['port']) ? ':'.$parsed['port'] : '';

        return "{$scheme}://{$host}{$port}";
    }
}
