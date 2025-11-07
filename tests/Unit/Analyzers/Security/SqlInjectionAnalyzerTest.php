<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\SqlInjectionAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class SqlInjectionAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new SqlInjectionAnalyzer($this->parser);
    }

    public function test_passes_with_safe_query_builder(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class UserController
{
    public function index()
    {
        $users = DB::table('users')
            ->where('status', 'active')
            ->get();

        return $users;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_db_raw_with_concatenation(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class UserController
{
    public function search($query)
    {
        $results = DB::select(DB::raw("SELECT * FROM users WHERE name = '" . $query . "'"));
        return $results;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('DB::raw()', $result);
    }

    public function test_detects_where_raw_with_user_input(): void
    {
        $code = <<<'PHP'
<?php

class UserRepository
{
    public function findByName($name)
    {
        return DB::table('users')
            ->whereRaw("name = '" . $name . "'")
            ->first();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['UserRepository.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('whereRaw()', $result);
    }

    public function test_detects_order_by_raw_with_concatenation(): void
    {
        $code = <<<'PHP'
<?php

class UserController
{
    public function list($sortBy)
    {
        return DB::table('users')
            ->orderByRaw($sortBy . ' DESC')
            ->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('orderByRaw()', $result);
    }

    public function test_detects_select_raw_with_request_input(): void
    {
        $code = <<<'PHP'
<?php

class ReportController
{
    public function generate()
    {
        $field = request('field');
        return DB::table('reports')
            ->selectRaw('SUM(' . $field . ') as total')
            ->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['ReportController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('selectRaw()', $result);
    }

    public function test_detects_having_raw_with_user_input(): void
    {
        $code = <<<'PHP'
<?php

class AnalyticsController
{
    public function stats($minCount)
    {
        return DB::table('stats')
            ->groupBy('category')
            ->havingRaw('count(*) > ' . $minCount)
            ->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['AnalyticsController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('havingRaw()', $result);
    }

    public function test_detects_db_select_with_superglobal(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class SearchController
{
    public function search()
    {
        return DB::select("SELECT * FROM products WHERE name = '" . $_GET['q'] . "'");
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['SearchController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('DB::select()', $result);
    }

    public function test_passes_with_parameter_binding(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class UserController
{
    public function search($query)
    {
        $results = DB::select("SELECT * FROM users WHERE name = ?", [$query]);
        return $results;
    }

    public function filter($status)
    {
        return DB::table('users')
            ->whereRaw('status = ?', [$status])
            ->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_multiple_sql_injection_vulnerabilities(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class ProductController
{
    public function search()
    {
        $name = $_POST['name'];
        $category = request('category');

        $query1 = DB::select("SELECT * FROM products WHERE name = '" . $name . "'");
        $query2 = DB::table('products')->whereRaw("category = '" . $category . "'")->get();

        return compact('query1', 'query2');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['ProductController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(2, $result);
    }
}
