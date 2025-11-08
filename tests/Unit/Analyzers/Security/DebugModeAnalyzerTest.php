<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\DebugModeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class DebugModeAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new DebugModeAnalyzer;
    }

    public function test_passes_with_debug_disabled(): void
    {
        $envContent = <<<'ENV'
APP_DEBUG=false
APP_ENV=production
ENV;

        $tempDir = $this->createTempDirectory(['.env' => $envContent]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_debug_enabled_in_production(): void
    {
        $envContent = <<<'ENV'
APP_DEBUG=true
APP_ENV=production
ENV;

        $tempDir = $this->createTempDirectory(['.env.production' => $envContent]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APP_DEBUG', $result);
    }

    public function test_detects_debug_functions_in_code(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class DebugController
{
    public function index()
    {
        dd($data);
        return view('home');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/DebugController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('dd()', $result);
    }

    public function test_passes_when_no_debug_issues(): void
    {
        $envContent = <<<'ENV'
APP_DEBUG=false
APP_ENV=production
ENV;

        $tempDir = $this->createTempDirectory(['.env' => $envContent]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
