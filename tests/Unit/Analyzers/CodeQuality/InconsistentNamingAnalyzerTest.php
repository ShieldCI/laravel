<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\InconsistentNamingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class InconsistentNamingAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new InconsistentNamingAnalyzer($this->parser);
    }

    public function test_detects_inconsistent_naming(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUser($id) { }
    public function fetch_profile($id) { }
    public function retrieveData($id) { }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('inconsistent', $result);
    }

    public function test_passes_with_consistent_naming(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUser($id) { }
    public function getProfile($id) { }
    public function getData($id) { }
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
