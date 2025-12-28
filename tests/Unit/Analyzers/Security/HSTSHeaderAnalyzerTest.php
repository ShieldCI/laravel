<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\HSTSHeaderAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class HSTSHeaderAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new HSTSHeaderAnalyzer;
    }

    // ============================================
    // Basic Functionality Tests
    // ============================================

    public function test_skips_for_non_https_applications(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => false,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    // ============================================
    // HTTPS Detection Tests
    // ============================================

    public function test_detects_https_from_session_secure_true(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because HTTPS is detected but no HSTS
        $this->assertFailed($result);
        $this->assertHasIssueContaining('HSTS', $result);
    }

    public function test_detects_https_from_env_app_url(): void
    {
        $env = <<<'ENV'
APP_URL=https://example.com
ENV;

        $tempDir = $this->createTempDirectory(['.env' => $env]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('HSTS', $result);
    }

    public function test_detects_https_from_env_force_https(): void
    {
        $env = <<<'ENV'
FORCE_HTTPS=true
ENV;

        $tempDir = $this->createTempDirectory(['.env' => $env]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('HSTS', $result);
    }

    public function test_detects_https_from_config_app_force_https(): void
    {
        $appConfig = <<<'PHP'
<?php

return [
    'force_https' => true,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/app.php' => $appConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('HSTS', $result);
    }

    public function test_detects_https_from_kernel_force_https_middleware(): void
    {
        $kernel = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middleware = [
        \App\Http\Middleware\ForceHttps::class,
    ];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Kernel.php' => $kernel]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('HSTS', $result);
    }

    public function test_detects_https_from_kernel_https_protocol_middleware(): void
    {
        $kernel = <<<'PHP'
<?php

namespace App\Http;

class Kernel
{
    protected $middleware = [
        \App\Http\Middleware\HttpsProtocol::class,
    ];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Kernel.php' => $kernel]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('HSTS', $result);
    }

    public function test_detects_https_from_app_service_provider_force_scheme(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\Facades\URL;

class AppServiceProvider
{
    public function boot(): void
    {
        URL::forceScheme('https');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $provider,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('HSTS', $result);
    }

    public function test_does_not_detect_commented_force_scheme(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

class AppServiceProvider
{
    public function boot(): void
    {
        // URL::forceScheme('https');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $provider,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_does_not_detect_non_url_force_scheme(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

class AppServiceProvider
{
    public function boot(): void
    {
        $this->forceScheme('https');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $provider,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_detects_https_from_force_https_helper_laravel_11(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\Facades\URL;

class AppServiceProvider
{
    public function boot(): void
    {
        URL::forceHttps();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $provider,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('HSTS', $result);
    }

    // ============================================
    // HSTS Middleware Detection Tests
    // ============================================

    public function test_detects_hsts_from_strict_transport_security_header(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_hsts_from_hsts_keyword(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        // HSTS configuration
        $response = $next($request);
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass because HSTS keyword is found (even though not properly configured)
        // The validation tests below check for proper configuration
        $this->assertPassed($result);
    }

    public function test_fails_when_https_app_missing_hsts(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('HSTS', $result);
    }

    // ============================================
    // max-age Validation Tests
    // ============================================

    public function test_fails_for_max_age_below_minimum(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=86400');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('max-age', $result);
    }

    public function test_passes_for_max_age_at_minimum(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=15768000; includeSubDomains');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_for_max_age_above_minimum(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ============================================
    // includeSubDomains Directive Tests
    // ============================================

    public function test_warns_about_missing_include_subdomains(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('includeSubDomains', $result);
    }

    public function test_passes_with_include_subdomains(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ============================================
    // preload Directive Tests
    // ============================================

    public function test_does_not_warn_about_missing_preload_by_default(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_about_missing_preload_when_configured(): void
    {
        config(['shieldci.hsts_header.require_preload' => true]);

        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('preload', $result);
    }

    public function test_passes_with_preload_when_configured(): void
    {
        config(['shieldci.hsts_header.require_preload' => true]);

        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ============================================
    // Security Package Detection Tests
    // ============================================

    public function test_passes_with_bepsvpt_secure_headers_package(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $composerJson = <<<'JSON'
{
    "require": {
        "bepsvpt/secure-headers": "^7.0"
    }
}
JSON;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_spatie_laravel_csp_package(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $composerJson = <<<'JSON'
{
    "require": {
        "spatie/laravel-csp": "^2.0"
    }
}
JSON;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_beyondcode_laravel_secure_headers_package(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $composerJson = <<<'JSON'
{
    "require": {
        "beyondcode/laravel-secure-headers": "^1.0"
    }
}
JSON;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'composer.json' => $composerJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_security_package_but_has_issues(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $composerJson = <<<'JSON'
{
    "require": {
        "bepsvpt/secure-headers": "^7.0"
    }
}
JSON;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=86400');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'composer.json' => $composerJson,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail even with security package if issues exist
        $this->assertFailed($result);
        $this->assertHasIssueContaining('max-age', $result);
    }

    // ============================================
    // Session Configuration Tests
    // ============================================

    public function test_fails_for_https_app_with_insecure_cookies(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => false,
];
PHP;

        $env = <<<'ENV'
APP_URL=https://example.com
ENV;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            '.env' => $env,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('secure cookies disabled', $result);
    }

    public function test_passes_for_https_app_with_secure_cookies(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_session_check_when_disabled_in_config(): void
    {
        config(['shieldci.hsts_header.check_session_secure' => false]);

        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => false,
];
PHP;

        $env = <<<'ENV'
APP_URL=https://example.com
ENV;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            '.env' => $env,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass because session check is disabled
        $this->assertPassed($result);
    }

    // ============================================
    // Configuration Tests
    // ============================================

    public function test_respects_custom_min_max_age(): void
    {
        config(['shieldci.hsts_header.min_max_age' => 31536000]); // 1 year

        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=15768000; includeSubDomains');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('max-age', $result);
    }

    public function test_respects_disabled_include_subdomains_requirement(): void
    {
        config(['shieldci.hsts_header.require_include_subdomains' => false]);

        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_respects_ignored_middleware(): void
    {
        config(['shieldci.hsts_header.ignored_middleware' => ['TestMiddleware']]);

        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class TestMiddleware
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=86400');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/TestMiddleware.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because no HSTS found (ignored middleware is skipped)
        $this->assertFailed($result);
        $this->assertHasIssueContaining('missing HSTS', $result);
    }

    // ============================================
    // Multiple Issues Tests
    // ============================================

    public function test_reports_multiple_issues(): void
    {
        config(['shieldci.hsts_header.require_preload' => true]);

        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => false,
];
PHP;

        $env = <<<'ENV'
APP_URL=https://example.com
ENV;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=86400');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            '.env' => $env,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        // Should have multiple issues:
        // 1. Low max-age (High severity)
        // 2. Missing includeSubDomains (Medium severity)
        // 3. Missing preload (Low severity)
        // 4. Insecure cookies (High severity)
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(4, count($issues));
    }

    // ============================================
    // Edge Cases Tests
    // ============================================

    public function test_handles_missing_composer_json(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should not crash, just fail because no HSTS
        $this->assertFailed($result);
    }

    public function test_handles_empty_middleware_directory(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/.gitkeep' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('missing HSTS', $result);
    }

    public function test_handles_non_middleware_php_files(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class HomeController
{
    public function index()
    {
        return view('home');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Controllers/HomeController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because no middleware found
        $this->assertFailed($result);
        $this->assertHasIssueContaining('missing HSTS', $result);
    }

    // ============================================
    // Result Format Tests
    // ============================================

    public function test_result_has_correct_metadata(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=86400');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $issue = $issues[0];
        $metadata = $issue->metadata;

        $this->assertArrayHasKey('issue_type', $metadata);
        $this->assertSame('weak_max_age', $metadata['issue_type']);
        $this->assertArrayHasKey('max_age', $metadata);
        $this->assertArrayHasKey('min_recommended', $metadata);
        $this->assertArrayHasKey('days_vulnerable', $metadata);
    }

    public function test_result_severity_mapping(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Missing includeSubDomains is Medium severity
        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $issue = $issues[0];
        $this->assertSame(Severity::Medium, $issue->severity);
    }

    public function test_result_includes_recommendations(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'secure' => true,
];
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->headers->set('Strict-Transport-Security', 'max-age=86400');
        return $response;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Middleware/SecurityHeaders.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $issue = $issues[0];
        $this->assertNotEmpty($issue->recommendation);
        $this->assertStringContainsString('max-age', $issue->recommendation);
    }
}
