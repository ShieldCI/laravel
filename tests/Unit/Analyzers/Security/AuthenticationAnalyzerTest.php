<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\AuthenticationAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class AuthenticationAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new AuthenticationAnalyzer($this->parser);
    }

    public function test_passes_with_auth_middleware(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class DashboardController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
    }

    public function index()
    {
        return view('dashboard');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/DashboardController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_sensitive_methods_without_auth(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController extends Controller
{
    public function destroy($id)
    {
        User::destroy($id);
        return redirect()->back();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('destroy', $result);
    }

    public function test_passes_when_no_controllers_found(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
