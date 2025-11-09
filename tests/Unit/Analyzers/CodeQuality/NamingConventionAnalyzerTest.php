<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\NamingConventionAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class NamingConventionAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new NamingConventionAnalyzer($this->parser);
    }

    public function test_detects_naming_violations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class user_service
{
    private $User_Name;

    public function Get_User($user_id)
    {
        return User::find($user_id);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/user_service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('convention', $result);
    }

    public function test_passes_with_psr_naming(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    private const MAX_RETRIES = 3;

    private $userName;

    public function getUser($userId)
    {
        return User::find($userId);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
