<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use Illuminate\Contracts\Config\Repository as Config;
use Mockery;
use ShieldCI\Analyzers\Security\SqlInjectionAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class SqlInjectionAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        /** @var Config&\Mockery\MockInterface $config */
        $config = Mockery::mock(Config::class);

        /** @phpstan-ignore-next-line */
        $config->shouldReceive('get')->andReturn(null);

        return new SqlInjectionAnalyzer($this->parser, $config);
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
    public function findByName()
    {
        return DB::table('users')
            ->whereRaw("name = '" . $_GET['name'] . "'")
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
    public function list()
    {
        return DB::table('users')
            ->orderByRaw(request('sort') . ' DESC')
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
        return DB::table('reports')
            ->selectRaw('SUM(' . request('field') . ') as total')
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
    public function stats()
    {
        return DB::table('stats')
            ->groupBy('category')
            ->havingRaw('count(*) > ' . $_POST['count'])
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

        $query1 = DB::select("SELECT * FROM products WHERE name = '" . $name . "'");
        $query2 = DB::table('products')->whereRaw("category = '" . request('category') . "'")->get();

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
    public function find()
    {
        // Variable interpolation with curly braces using superglobal
        return DB::table('users')->whereRaw("name = '{$_GET['name']}'")->first();
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
        // Direct concatenation in the function call
        return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $userId);
    }

    public function unsafeInterpolation($conn, $name)
    {
        // Variable interpolation in the function call
        return mysqli_query($conn, "SELECT * FROM users WHERE name = '$name'");
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['DatabaseHelper.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(2, $result);
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

    public function test_passes_with_safe_native_prepared_statements(): void
    {
        $code = <<<'PHP'
<?php

class DatabaseHelper
{
    public function safeMysqliQuery($conn, $userId)
    {
        // SAFE: Using mysqli prepared statements
        $stmt = mysqli_prepare($conn, 'SELECT * FROM users WHERE id = ?');
        mysqli_stmt_bind_param($stmt, 'i', $userId);
        mysqli_stmt_execute($stmt);
        return mysqli_stmt_get_result($stmt);
    }

    public function safePdoQuery($pdo, $email)
    {
        // SAFE: Using PDO prepared statements
        $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?');
        $stmt->execute([$email]);
        return $stmt->fetchAll();
    }

    public function connect()
    {
        // SAFE: Just connecting (not a query)
        $pdo = new PDO('mysql:host=localhost;dbname=test', 'user', 'pass');
        $mysqli = new mysqli('localhost', 'user', 'pass', 'db');
        mysqli_connect('localhost', 'user', 'pass');
        return $pdo;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['DatabaseHelper.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_interpolation_in_non_sql_arguments(): void
    {
        $code = <<<'PHP'
<?php

class DatabaseHelper
{
    public function dynamicConnection($host, $dbName)
    {
        // SAFE: Interpolation in connection string (1st arg), not SQL query
        $conn = mysqli_connect("$host", 'user', 'pass', "$dbName");

        // SAFE: Static SQL query without variables
        $result = mysqli_query($conn, "SELECT * FROM users WHERE active = 1");

        return $result;
    }

    public function safeQueryWithDynamicConnection($server)
    {
        // SAFE: Variable in connection (1st arg), static SQL (2nd arg)
        $pgConn = pg_connect("host=$server dbname=test");
        $result = pg_query($pgConn, "SELECT * FROM posts");

        return $result;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['DatabaseHelper.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because interpolation is only in connection args, not SQL args
        $this->assertPassed($result);
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
    public function dangerousQueries()
    {
        // DB::raw with concatenation (strict mode - any concat flagged)
        DB::raw("query " . $_GET['val']);
        // *Raw methods with direct user input (lenient mode - only user input flagged)
        DB::table('users')->whereRaw("col = " . $_POST['val'])->get();
        DB::table('users')->havingRaw("count > " . request('sort'))->get();
        DB::table('users')->orderByRaw(Request::input('col') . " DESC")->get();
        DB::table('users')->selectRaw("col, " . $_GET['val'])->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['QueryBuilder.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // 5 dangerous methods: raw, whereRaw, havingRaw, orderByRaw, selectRaw
        $this->assertIssueCount(5, $result);
    }

    public function test_safe_order_by_raw_with_table_name_concatenation(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class LeaderboardController
{
    public function index()
    {
        $goalTable = (new Goal)->getTable();

        return DB::table('deals')
            ->join($goalTable, 'deals.goal_id', '=', $goalTable.'.id')
            ->orderByRaw('(sent_deals_count/'.$goalTable.'.goal) ASC')
            ->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['LeaderboardController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass: $goalTable is a model table name, not user input
        $this->assertPassed($result);
    }

    public function test_safe_where_raw_with_variable_concatenation(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class ReportController
{
    public function show()
    {
        $column = 'email';
        $table = (new User)->getTable();

        return DB::table($table)
            ->whereRaw($column . ' IS NOT NULL')
            ->selectRaw('COUNT(' . $column . ') as total')
            ->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['ReportController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass: $column and $table are not user input
        $this->assertPassed($result);
    }

    public function test_detects_raw_methods_with_superglobal_in_concatenation(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class UnsafeController
{
    public function index()
    {
        DB::table('users')->whereRaw("name = '" . $_GET['name'] . "'")->get();
        DB::table('users')->havingRaw('count(*) > ' . $_POST['count'])->get();
        DB::table('users')->orderByRaw(request('sort') . ' DESC')->get();
        DB::table('users')->selectRaw('SUM(' . Request::input('col') . ')')->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['UnsafeController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // All 4 *Raw methods with direct user input should be flagged
        $this->assertFailed($result);
        $this->assertIssueCount(4, $result);
    }

    public function test_strict_concatenation_for_db_static_methods(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class QueryController
{
    public function queries($table, $column)
    {
        // DB static methods should flag ALL concatenation, even without user input
        DB::select("SELECT * FROM " . $table . " WHERE id = 1");
        DB::insert("INSERT INTO " . $table . " (name) VALUES ('test')");
        DB::update("UPDATE " . $table . " SET name = 'test'");
        DB::delete("DELETE FROM " . $table . " WHERE id = 1");
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['QueryController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // All 4 DB:: static methods flag any concatenation (strict mode)
        $this->assertFailed($result);
        $this->assertIssueCount(4, $result);
    }

    public function test_safe_db_select_with_dynamic_placeholders_and_bindings(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class MemberController
{
    public function getDirectMembers()
    {
        $airportIDsArray = [1, 2, 3];
        $airportPlaceholders = implode(',', array_fill(0, count($airportIDsArray), '?'));

        // SAFE: concatenation is structural (dynamic placeholders), bindings handle the data
        $members = DB::select(
            'SELECT email FROM members WHERE airport_id IN (' . $airportPlaceholders . ') AND subscribed = ?',
            [...$airportIDsArray, 1]
        );

        return $members;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['MemberController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass: bindings are present, concatenation is structural (placeholders)
        $this->assertPassed($result);
    }

    public function test_detects_db_select_with_user_input_in_concat_despite_bindings(): void
    {
        $code = <<<'PHP'
<?php
use Illuminate\Support\Facades\DB;

class UnsafeController
{
    public function search()
    {
        // DANGEROUS: user input concatenated into SQL even though bindings exist
        $results = DB::select(
            "SELECT * FROM " . $_GET['table'] . " WHERE id = ?",
            [1]
        );

        return $results;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['UnsafeController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should fail: even with bindings, direct user input in SQL concat is dangerous
        $this->assertFailed($result);
        $this->assertHasIssueContaining('DB::select()', $result);
    }

    public function test_detects_multiple_native_functions_with_injection(): void
    {
        $code = <<<'PHP'
<?php

class NativeDatabaseCode
{
    public function queries($conn, $userId, $name)
    {
        // SAFE: These are not flagged (no concatenation/interpolation)
        mysqli_connect('localhost', 'user', 'pass');
        mysqli_query($conn, "SELECT * FROM users WHERE id = 1");
        pg_connect("host=localhost");

        // DANGEROUS: These have concatenation/interpolation
        mysqli_query($conn, "SELECT * FROM users WHERE id = " . $userId);
        mysqli_real_query($conn, "SELECT * FROM posts WHERE title = '$name'");
        pg_query($conn, "SELECT * FROM posts WHERE id = " . $userId);
        pg_send_query($conn, "DELETE FROM users WHERE name = '$name'");
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['NativeDatabaseCode.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should detect 4 dangerous queries with concatenation/interpolation
        $this->assertIssueCount(4, $result);
    }
}
