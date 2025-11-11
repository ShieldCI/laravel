<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\RawEloquentAvoidanceAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class RawEloquentAvoidanceAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new RawEloquentAvoidanceAnalyzer($this->parser);
    }

    public function test_passes_without_raw_sql(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        return User::where('status', 'active')->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_simple_db_raw(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

class ReportService
{
    public function getStats()
    {
        // DB::raw with COUNT(*) is considered simple
        return DB::table('users')->select(DB::raw('COUNT(*)'))->first();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReportService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('raw', $result);
    }

    public function test_detects_simple_select_query(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

class UserService
{
    public function getUsers()
    {
        // Simple SELECT * FROM users
        return DB::select('SELECT * FROM users');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('SELECT', $result);
    }

    public function test_provides_eloquent_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

class ProductService
{
    public function getProducts()
    {
        // Simple query that could use Eloquent
        return DB::select('SELECT * FROM products');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('Eloquent', $issues[0]->recommendation);
    }

    public function test_ignores_files_with_parse_errors(): void
    {
        $code = '<?php this is invalid PHP code {{{';

        $tempDir = $this->createTempDirectory(['Invalid.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
