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

    public function test_passes_with_request_in_bindings_array(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class UserController
{
    public function search()
    {
        // SAFE: request() is in bindings array, not concatenated
        $results = DB::select('SELECT * FROM users WHERE id = ?', [request('id')]);
        return $results;
    }

    public function filter()
    {
        // SAFE: $_GET is in bindings array
        return DB::table('users')
            ->whereRaw('status = ?', [$_GET['status']])
            ->get();
    }

    public function findByEmail()
    {
        // SAFE: Request::input in bindings
        return DB::table('users')
            ->whereRaw('email = ?', [Request::input('email')])
            ->first();
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

    public function test_detects_request_in_sql_string_without_bindings(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class DangerousController
{
    public function search()
    {
        // DANGEROUS: request() value directly in SQL (no bindings)
        $id = request('id');
        return DB::select("SELECT * FROM users WHERE id = $id");
    }

    public function filter()
    {
        // DANGEROUS: $_GET directly in SQL
        return DB::table('users')
            ->whereRaw("status = '{$_GET['status']}'")
            ->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['DangerousController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(2, $result);
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

    public function test_detects_variable_interpolation_in_db_raw(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class UserController
{
    public function search($userId)
    {
        // Variable interpolation without curly braces
        $results = DB::raw("SELECT * FROM users WHERE id = $userId");
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

    public function test_detects_variable_interpolation_with_curly_braces(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class UserController
{
    public function find($userName)
    {
        // Variable interpolation with curly braces
        return DB::table('users')->whereRaw("name = '{$userName}'")->first();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('whereRaw()', $result);
    }

    public function test_detects_db_unprepared(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class MigrationController
{
    public function dropTable($tableName)
    {
        DB::unprepared("DROP TABLE IF EXISTS temp_" . $tableName);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['MigrationController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('DB::unprepared()', $result);
    }

    public function test_detects_native_mysqli_query(): void
    {
        $code = <<<'PHP'
<?php

class DatabaseHelper
{
    public function executeQuery($conn, $userId)
    {
        $query = "SELECT * FROM users WHERE id = " . $userId;
        return mysqli_query($conn, $query);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['DatabaseHelper.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('mysqli_query()', $result);
    }

    public function test_detects_native_pg_query(): void
    {
        $code = <<<'PHP'
<?php

class PostgresHelper
{
    public function search($conn, $name)
    {
        return pg_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['PostgresHelper.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('pg_query()', $result);
    }

    public function test_detects_pdo_instantiation(): void
    {
        $code = <<<'PHP'
<?php

class DatabaseConnection
{
    public function connect()
    {
        $dsn = "mysql:host=localhost;dbname=mydb";
        return new PDO($dsn, 'user', 'password');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['DatabaseConnection.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('new PDO()', $result);
    }

    public function test_detects_mysqli_instantiation(): void
    {
        $code = <<<'PHP'
<?php

class MysqliConnection
{
    public function connect()
    {
        return new mysqli('localhost', 'user', 'password', 'database');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['MysqliConnection.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('new mysqli()', $result);
    }

    public function test_detects_request_object_input(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;
use Illuminate\Http\Request;

class SearchController
{
    public function search(Request $request)
    {
        $term = $request->input('q');
        return DB::select("SELECT * FROM products WHERE name LIKE '%" . $term . "%'");
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

    public function test_passes_with_empty_directory(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_handles_parse_errors_gracefully(): void
    {
        $code = <<<'PHP'
<?php
// Invalid PHP syntax
class Broken {
    function test(
}
PHP;

        $tempDir = $this->createTempDirectory(['Broken.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because unparseable files are skipped
        $this->assertPassed($result);
    }

    public function test_detects_all_dangerous_raw_methods(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class QueryBuilder
{
    public function dangerousQueries($value)
    {
        // DB::raw is both a static call AND finds 'raw' as a method
        DB::raw("query " . $value);
        DB::table('users')->whereRaw("col = " . $value)->get();
        DB::table('users')->havingRaw("count > " . $value)->get();
        DB::table('users')->orderByRaw($value . " DESC")->get();
        DB::table('users')->selectRaw("col, " . $value)->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['QueryBuilder.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // DB::raw gets detected twice (as static call and in method list), so 6 issues
        $this->assertIssueCount(6, $result);
    }

    public function test_detects_multiple_native_functions(): void
    {
        $code = <<<'PHP'
<?php

class NativeDatabaseCode
{
    public function queries($conn)
    {
        mysqli_connect('localhost', 'user', 'pass');
        mysqli_query($conn, "SELECT * FROM users");
        pg_connect("host=localhost");
        pg_query($conn, "SELECT * FROM posts");
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['NativeDatabaseCode.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(4, $result);
    }
}
