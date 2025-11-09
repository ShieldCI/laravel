<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\QueryBuilderInControllerAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class QueryBuilderInControllerAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new QueryBuilderInControllerAnalyzer($this->parser);
    }

    public function test_detects_query_builder_in_controller(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = DB::table('users')
            ->where('active', true)
            ->orderBy('created_at', 'desc')
            ->paginate(20);

        return view('users.index', compact('users'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database query', $result);
    }

    public function test_passes_with_repository_pattern(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function __construct(
        private UserRepository $users
    ) {}

    public function index()
    {
        $users = $this->users->getActive();

        return view('users.index', compact('users'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
