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

        $tempDir = $this->createTempDirectory(['config/session.php' => $sessionConfig]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

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
}
