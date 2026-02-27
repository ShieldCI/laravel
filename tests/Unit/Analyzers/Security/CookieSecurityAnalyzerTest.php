<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\CookieSecurityAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CookieSecurityAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CookieSecurityAnalyzer;
    }

    // ==================== BASIC PASS CASES ====================

    public function test_passes_with_secure_cookie_configuration(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => 'lax',
];
PHP;

        $kernelFile = <<<'PHP'
<?php

namespace App\Http;

class Kernel
{
    protected $middleware = [
        \App\Http\Middleware\EncryptCookies::class,
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Kernel.php' => $kernelFile,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_strict_same_site(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => 'strict',
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== HTTP_ONLY TESTS ====================

    public function test_fails_when_http_only_disabled(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => false,
    'secure' => true,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('HttpOnly', $result);
    }

    public function test_fails_when_http_only_is_integer_zero(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => 0,
    'secure' => true,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('HttpOnly', $result);
    }

    // ==================== SECURE FLAG TESTS ====================

    public function test_warns_about_secure_flag_disabled(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => false,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('secure', $result);
    }

    public function test_warns_when_secure_is_integer_zero(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => 0,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('secure', $result);
    }

    // ==================== SAME_SITE TESTS ====================

    public function test_warns_when_same_site_is_null(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => null,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Medium severity should result in warning
        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('SameSite', $result);
    }

    public function test_warns_when_same_site_is_string_null(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => 'null',
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('SameSite', $result);
    }

    public function test_warns_when_same_site_is_none(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => 'none',
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('SameSite', $result);
    }

    public function test_warns_when_same_site_is_none_uppercase(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => 'None',
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('SameSite', $result);
    }

    public function test_passes_when_same_site_is_lax(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => 'lax',
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_same_site_is_strict(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => 'strict',
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== ENV() CALL TESTS ====================

    public function test_passes_when_same_site_uses_env_with_lax_default(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => env('SESSION_SAME_SITE', 'lax'),
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_same_site_uses_env_with_strict_default(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => env('SESSION_SAME_SITE', 'strict'),
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_same_site_uses_env_with_null_default(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => env('SESSION_SAME_SITE', null),
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('SameSite', $result);
    }

    public function test_fails_when_same_site_uses_env_with_none_default(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => env('SESSION_SAME_SITE', 'none'),
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('SameSite', $result);
    }

    public function test_passes_when_same_site_uses_env_without_default(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => true,
    'same_site' => env('SESSION_SAME_SITE'),
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Indeterminate — should not flag (conservative)
        $this->assertPassed($result);
    }

    public function test_passes_when_http_only_uses_env_with_true_default(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => env('SESSION_HTTP_ONLY', true),
    'secure' => true,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_http_only_uses_env_with_false_default(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => env('SESSION_HTTP_ONLY', false),
    'secure' => true,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('HttpOnly', $result);
    }

    public function test_passes_when_secure_uses_env_with_true_default(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => env('SESSION_SECURE_COOKIE', true),
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_secure_uses_env_with_false_default(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => true,
    'secure' => env('SESSION_SECURE_COOKIE', false),
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('secure', $result);
    }

    // ==================== ENCRYPT_COOKIES MIDDLEWARE TESTS ====================

    public function test_fails_when_encrypt_cookies_middleware_missing(): void
    {
        $kernelFile = <<<'PHP'
<?php

namespace App\Http;

class Kernel
{
    protected $middleware = [
        \App\Http\Middleware\TrustProxies::class,
    ];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Kernel.php' => $kernelFile]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('EncryptCookies middleware is not registered', $result);
    }

    public function test_fails_when_encrypt_cookies_middleware_commented_out(): void
    {
        $kernelFile = <<<'PHP'
<?php

namespace App\Http;

class Kernel
{
    protected $middleware = [
        // \App\Http\Middleware\EncryptCookies::class,
        \App\Http\Middleware\TrustProxies::class,
    ];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Kernel.php' => $kernelFile]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('EncryptCookies middleware is commented out', $result);
    }

    public function test_passes_when_encrypt_cookies_middleware_present(): void
    {
        $kernelFile = <<<'PHP'
<?php

namespace App\Http;

class Kernel
{
    protected $middleware = [
        \App\Http\Middleware\EncryptCookies::class,
        \App\Http\Middleware\TrustProxies::class,
    ];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Kernel.php' => $kernelFile]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_encrypt_cookies_using_string_reference(): void
    {
        $kernelFile = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Middleware\EncryptCookies;

class Kernel
{
    protected $middleware = [
        EncryptCookies::class,
    ];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Kernel.php' => $kernelFile]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== LARAVEL 11+ BOOTSTRAP/APP.PHP TESTS ====================

    public function test_passes_with_laravel_11_encrypt_cookies_capitalized(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->EncryptCookies();
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory(['bootstrap/app.php' => $bootstrapApp]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_laravel_11_encrypt_cookies_lowercase(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->encryptCookies();
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory(['bootstrap/app.php' => $bootstrapApp]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_when_laravel_11_encrypt_cookies_missing(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        // No encrypt cookies
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory(['bootstrap/app.php' => $bootstrapApp]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('EncryptCookies middleware may not be properly configured', $result);
    }

    // ==================== EDGE CASES ====================

    public function test_passes_when_no_session_config_exists(): void
    {
        $kernelFile = <<<'PHP'
<?php

namespace App\Http;

class Kernel
{
    protected $middleware = [
        \App\Http\Middleware\EncryptCookies::class,
    ];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Kernel.php' => $kernelFile]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - no session config means no session config issues
        $this->assertPassed($result);
    }

    public function test_fails_when_kernel_only_has_encrypt_cookies_in_comment(): void
    {
        $kernelFile = <<<'PHP'
<?php
// EncryptCookies is mentioned here in a comment only
// Not actually registered
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Kernel.php' => $kernelFile]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail - commented reference doesn't count as registered
        $this->assertFailed($result);
        $this->assertHasIssueContaining('EncryptCookies middleware is commented out', $result);
    }

    public function test_handles_multiple_issues_in_session_config(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'http_only' => false,
    'secure' => false,
    'same_site' => null,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    public function test_handles_session_config_with_comments(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    // 'http_only' => false,  // Commented out
    'http_only' => true,
    'secure' => true,
];
PHP;

        $kernelFile = <<<'PHP'
<?php

class Kernel
{
    protected $middleware = [
        \App\Http\Middleware\EncryptCookies::class,
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/session.php' => $sessionConfig,
            'app/Http/Kernel.php' => $kernelFile,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_empty_kernel_file(): void
    {
        $kernelFile = '';

        $tempDir = $this->createTempDirectory(['app/Http/Kernel.php' => $kernelFile]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('EncryptCookies middleware is not registered', $result);
    }

    // ==================== SHOULD RUN TESTS ====================

    public function test_should_run_when_session_config_exists(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return ['http_only' => true];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_when_kernel_exists(): void
    {
        $kernelFile = <<<'PHP'
<?php

class Kernel {}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Kernel.php' => $kernelFile]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_when_bootstrap_app_exists(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

return app();
PHP;

        $tempDir = $this->createTempDirectory(['bootstrap/app.php' => $bootstrapApp]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_not_run_when_no_files_exist(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_get_skip_reason(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertSame(
            'No session configuration or middleware files found to analyze',
            $analyzer->getSkipReason()
        );
    }

    public function test_skips_when_no_files_exist(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertSame('No session configuration or middleware files found to analyze', $result->getMessage());
    }

    // ==================== METADATA TESTS ====================

    public function test_includes_metadata_for_http_only_issue(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return ['http_only' => false];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $issue = $issues[0];
        $this->assertArrayHasKey('file', $issue->metadata);
        $this->assertArrayHasKey('config_key', $issue->metadata);
        $this->assertSame('session.php', $issue->metadata['file']);
        $this->assertSame('http_only', $issue->metadata['config_key']);
    }

    public function test_includes_metadata_for_encrypt_cookies_missing(): void
    {
        $kernelFile = <<<'PHP'
<?php

class Kernel { protected $middleware = []; }
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Kernel.php' => $kernelFile]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $issue = $issues[0];
        $this->assertArrayHasKey('file', $issue->metadata);
        $this->assertArrayHasKey('middleware', $issue->metadata);
        $this->assertArrayHasKey('status', $issue->metadata);
        $this->assertSame('EncryptCookies', $issue->metadata['middleware']);
        $this->assertSame('missing', $issue->metadata['status']);
    }

    // ==================== CODE SNIPPET TESTS ====================

    public function test_code_snippets_are_attached_to_issues(): void
    {
        $sessionConfig = <<<'PHP'
<?php

return [
    'driver' => 'file',
    'http_only' => false,
    'secure' => false,
    'same_site' => null,
];
PHP;

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        // Enable code snippets in config
        config(['shieldci.report.show_code_snippets' => true]);
        config(['shieldci.report.snippet_context_lines' => 5]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));

        // Check that at least one issue has a code snippet
        $hasSnippet = false;
        foreach ($issues as $issue) {
            if ($issue->codeSnippet !== null) {
                $hasSnippet = true;
                $this->assertGreaterThan(0, count($issue->codeSnippet->getLines()));
                $this->assertGreaterThan(0, $issue->codeSnippet->getTargetLine());
                break;
            }
        }

        $this->assertTrue($hasSnippet, 'At least one issue should have a code snippet attached');
    }
}
