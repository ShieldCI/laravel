<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\HSTSHeaderAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class HSTSHeaderAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new HSTSHeaderAnalyzer;
    }

    public function test_passes_for_non_https_applications(): void
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

    public function test_passes_with_hsts_middleware(): void
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

    public function test_warns_about_low_max_age(): void
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('includeSubDomains', $result);
    }
}
