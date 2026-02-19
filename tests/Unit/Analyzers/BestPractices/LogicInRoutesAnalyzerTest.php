<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\LogicInRoutesAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class LogicInRoutesAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'logic-in-routes' => [
                            'max_closure_lines' => 5,
                        ],
                    ],
                ],
            ],
        ]);

        return new LogicInRoutesAnalyzer($this->parser, $config);
    }

    public function test_passes_with_controller_references(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;

Route::get('/users', [UserController::class, 'index']);
Route::post('/users', [UserController::class, 'store']);
Route::get('/users/{id}', [UserController::class, 'show']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_simple_closures(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/about', function () {
    return view('about');
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_database_queries_with_db_facade(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;

Route::get('/users', function () {
    return DB::table('users')->where('active', true)->get();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database queries', $result);
    }

    public function test_detects_eloquent_model_queries(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\Product;

Route::get('/products', function () {
    return Product::where('price', '>', 100)->orderBy('name')->get();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('database queries', $result);
    }

    public function test_allows_simple_find_by_default(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/user/{id}', function ($id) {
    return User::find($id);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Simple reads are allowed by default (equivalent to route model binding)
        $this->assertPassed($result);
    }

    public function test_flags_create_as_high_severity(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\Order;

Route::post('/orders', function () {
    return Order::create([
        'user_id' => auth()->id(),
        'total' => request('total'),
    ]);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operations', $result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
    }

    public function test_detects_query_builder_methods(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\Post;

Route::get('/posts', function () {
    $query = Post::query();
    $query->select('id', 'title')
          ->where('published', true)
          ->orderBy('created_at', 'desc')
          ->limit(10);
    return $query->get();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database queries', $result);
    }

    public function test_detects_nested_if_statements(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/check', function () {
    if (auth()->check()) {
        if (auth()->user()->isAdmin()) {
            return 'Admin';
        }
    }
    return 'Guest';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_foreach_loops_with_calculations(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/items', function () {
    $items = [1, 2, 3];
    $total = 0;
    foreach ($items as $item) {
        $total += $item;
    }
    return $total;
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_for_loops_with_calculations(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/count', function () {
    $sum = 0;
    for ($i = 0; $i < 10; $i++) {
        $sum = $sum + $i;
    }
    return $sum;
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_while_loops_with_calculations(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/process', function () {
    $i = 0;
    $product = 1;
    while ($i < 10) {
        $product = $product * 2;
        $i++;
    }
    return $product;
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_passes_with_simple_if_statement(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/check', function () {
    if (auth()->check()) { return 'Authenticated'; }
    return 'Guest';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_closure_exceeding_line_threshold(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/long', function () {
    $a = 1;
    $b = 2;
    $c = 3;
    $d = 4;
    $e = 5;
    $f = 6;
    return $a + $b + $c + $d + $e + $f;
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('lines', $result);
    }

    public function test_closure_exactly_at_threshold_passes(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/exact', function () {
    $a = 1;
    $b = 2;
    return $a + $b;
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_consolidates_multiple_problems_into_single_issue(): void
    {
        // Use a 3-method chain to trigger complex database queries (where->orderBy->get)
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/complex', function () {
    $users = User::where('active', true)->orderBy('name')->get();
    $total = 0;
    foreach ($users as $user) {
        $total += $user->balance;
    }
    $a = 1;
    $b = 2;
    $c = 3;
    return $users;
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        // Should be ONE consolidated issue
        $this->assertCount(1, $issues);

        // Should mention multiple problems
        $this->assertStringContainsString('database queries', $issues[0]->message);
        $this->assertStringContainsString('complex business logic', $issues[0]->message);
        $this->assertStringContainsString('lines', $issues[0]->message);
    }

    public function test_allows_simple_all_by_default(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/users', function () {
    return User::all();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Simple reads are allowed by default
        $this->assertPassed($result);
    }

    public function test_severity_high_for_complex_business_logic(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/process', function () {
    $total = 0;
    foreach ([1, 2, 3] as $item) {
        $total += $item;
    }
    return $total;
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
    }

    public function test_severity_medium_for_long_closures(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/long', function () {
    $a = 1;
    $b = 2;
    $c = 3;
    $d = 4;
    $e = 5;
    $f = 6;
    return $a + $b + $c + $d + $e + $f;
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertEquals('medium', $issues[0]->severity->value);
    }

    public function test_issue_code_for_raw_database_queries(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;

Route::get('/data', function () {
    return DB::select('SELECT * FROM users');
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('route-has-raw-queries', $issues[0]->code);
    }

    public function test_issue_code_for_business_logic(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/check', function () {
    if (true) {
        if (false) {
            return 'nested';
        }
    }
    return 'done';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('route-has-business-logic', $issues[0]->code);
    }

    public function test_issue_code_for_long_closure(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/long', function () {
    $a = 1;
    $b = 2;
    $c = 3;
    $d = 4;
    $e = 5;
    $f = 6;
    return $a + $b + $c + $d + $e + $f;
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertEquals('route-closure-too-long', $issues[0]->code);
    }

    public function test_false_positive_config_get_not_flagged_as_query(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/settings', function () {
    $setting = config()->get('app.name');
    return response()->json(['setting' => $setting]);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should pass - config()->get() is not a database query
        $this->assertPassed($result);
    }

    public function test_false_positive_simple_math_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/calculate', function () {
    $total = 100 + 50;
    return response()->json(['total' => $total]);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_files_with_parse_errors(): void
    {
        $code = '<?php this is invalid PHP code {{{';

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_empty_route_file(): void
    {
        $code = <<<'PHP'
<?php

// Empty routes file
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_multiple_routes_in_same_file(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/good', function () {
    return view('good');
});

Route::post('/bad', function () {
    return User::create(['name' => 'Test']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_custom_threshold_configuration(): void
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'logic-in-routes' => [
                            'max_closure_lines' => 3,
                        ],
                    ],
                ],
            ],
        ]);

        $analyzer = new LogicInRoutesAnalyzer($this->parser, $config);

        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/test', function () {
    $a = 1;
    $b = 2;
    return $a + $b;
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should fail with custom threshold of 3
        $this->assertWarning($result);
    }

    public function test_provides_controller_recommendation_for_db_writes(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\Order;

Route::post('/orders', function () {
    return Order::create([
        'user_id' => auth()->id(),
        'total' => request('total'),
    ]);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('controller', strtolower($issues[0]->recommendation));
    }

    public function test_code_snippet_is_included(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::post('/users', function () {
    return User::create(['name' => 'Test']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotNull($issues[0]->codeSnippet);
        $this->assertNotEmpty($issues[0]->codeSnippet->getLines());
    }

    public function test_metadata_includes_problem_details(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::post('/test', function () {
    return User::create(['name' => 'Test']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        $this->assertArrayHasKey('problems', $issues[0]->metadata);
        $this->assertArrayHasKey('has_db_queries', $issues[0]->metadata);
        $this->assertTrue($issues[0]->metadata['has_db_queries']);
        $this->assertArrayHasKey('has_write_queries', $issues[0]->metadata);
        $this->assertTrue($issues[0]->metadata['has_write_queries']);
    }

    public function test_does_not_flag_collection_where_as_query(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/filter', function () {
    return collect(['a', 'b'])->where('key', 'value')->first();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should PASS - Collection methods, not DB queries
        $this->assertPassed($result);
    }

    public function test_does_not_flag_carbon_create_as_query(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Carbon\Carbon;

Route::get('/date', function () {
    $date = Carbon::create(2024, 1, 1);
    return response()->json(['date' => $date->toDateString()]);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should PASS - Date creation, not DB query
        $this->assertPassed($result);
    }

    public function test_does_not_flag_simple_validation_loop(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/tags', function () {
    foreach (request('tags', []) as $tag) { if (strlen($tag) > 50) abort(422); }
    return 'ok';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should PASS - Simple validation loop without calculations
        $this->assertPassed($result);
    }

    public function test_flags_loop_with_calculations(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/total', function () {
    $items = request('items', []);
    $total = 0;
    foreach ($items as $item) {
        $total += $item['price'] * $item['quantity'];
    }
    return response()->json(['total' => $total]);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should FAIL - Loop contains business logic (arithmetic)
        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_does_not_flag_validator_make_as_query(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;

Route::post('/submit', function () {
    return Validator::make(request()->all(), ['email' => 'required']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should PASS - Validator is not a DB query
        $this->assertPassed($result);
    }

    public function test_detects_route_with_fully_qualified_name(): void
    {
        $code = <<<'PHP'
<?php

use App\Models\User;

\Illuminate\Support\Facades\Route::post('/users', function () {
    return User::create(['name' => 'Test']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should detect database write even with FQN Route facade
        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operations', $result);
    }

    public function test_detects_route_with_alias(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route as R;
use App\Models\Product;

R::post('/products', function () {
    return Product::create(['name' => 'Test']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should detect database write even with aliased Route facade
        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operations', $result);
    }

    public function test_detects_route_without_use_statement(): void
    {
        $code = <<<'PHP'
<?php

use App\Models\Order;

Route::post('/orders', function () {
    return Order::create(['name' => 'Test']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should still work with unresolved short name (global alias)
        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operations', $result);
    }

    public function test_detects_dispatch_function_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/orders', function () {
    dispatch(new ProcessOrderJob());
    return response()->json(['status' => 'queued']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_event_function_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/users', function () {
    event(new UserCreated($user));
    return response()->json(['created' => true]);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_mail_facade_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Mail;

Route::post('/contact', function () {
    Mail::send('emails.contact', request()->all(), function ($m) {
        $m->to('admin@example.com');
    });
    return 'sent';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_notification_facade_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Notification;

Route::post('/notify', function () {
    Notification::send($users, new WelcomeNotification());
    return 'notified';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_queue_facade_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Queue;

Route::post('/process', function () {
    Queue::push(new ProcessDataJob());
    return 'queued';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_app_make_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\App;

Route::get('/service', function () {
    $service = App::make('SomeService');
    return $service->getData();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_resolve_function_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/resolve', function () {
    $service = resolve('PaymentGateway');
    return $service->getStatus();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_non_query_model_method(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::post('/welcome', function () {
    User::sendWelcomeEmail($email);
    return 'sent';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_heavy_method_chain(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/process', function ($request) {
    $result = $request->validate()->process()->transform()->save();
    return $result;
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_does_not_flag_short_method_chain(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/test', function () {
    return response()->json(['ok' => true]);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should pass - only 2 method calls in chain
        $this->assertPassed($result);
    }

    public function test_simple_find_passes_by_default(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/users', function () {
    return User::find(1);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Simple reads pass by default (equivalent to route model binding)
        $this->assertPassed($result);
    }

    public function test_detects_broadcast_function_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/message', function () {
    broadcast(new MessageSent($message));
    return 'broadcasted';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_rescue_function_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/risky', function () {
    return rescue(fn() => riskyOperation(), 'default');
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_bus_facade_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Bus;

Route::post('/batch', function () {
    Bus::chain([new FirstJob(), new SecondJob()])->dispatch();
    return 'dispatched';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_event_facade_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Event;

Route::post('/trigger', function () {
    Event::dispatch(new OrderPlaced($order));
    return 'triggered';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_app_function_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/app', function () {
    $service = app('MyService');
    return $service->execute();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_retry_function_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/api-call', function () {
    return retry(3, fn() => externalApiCall(), 100);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_dispatch_sync_function_call(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/sync', function () {
    dispatch_sync(new ProcessNowJob());
    return 'done';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_mail_facade_with_fqn(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/email', function () {
    \Illuminate\Support\Facades\Mail::raw('Hello', fn($m) => $m->to('test@example.com'));
    return 'sent';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_method_chain_exactly_three_is_flagged(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/chain', function ($obj) {
    return $obj->first()->second()->third();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // 3 method calls should be flagged
        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_flags_update_as_high_severity(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::put('/user/{id}', function ($id) {
    User::where('id', $id)->update(['active' => true]);
    return 'updated';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operations', $result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
    }

    public function test_flags_delete_as_high_severity(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::delete('/user/{id}', function ($id) {
    User::destroy($id);
    return 'deleted';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operations', $result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
    }

    public function test_strict_mode_flags_all_queries(): void
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'logic-in-routes' => [
                            'max_closure_lines' => 5,
                            'allow_simple_reads' => false,
                        ],
                    ],
                ],
            ],
        ]);

        $analyzer = new LogicInRoutesAnalyzer($this->parser, $config);

        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/user/{id}', function ($id) {
    return User::find($id);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // In strict mode, even simple reads are flagged
        $this->assertWarning($result);
        $this->assertHasIssueContaining('database queries (strict mode)', $result);
        $issues = $result->getIssues();
        $this->assertEquals('low', $issues[0]->severity->value);
    }

    public function test_complex_read_chain_flagged_as_medium(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/users', function () {
    return User::where('active', true)->orderBy('name')->paginate(10);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Complex reads (3+ method chain) should be flagged as medium
        $this->assertWarning($result);
        $this->assertHasIssueContaining('complex database queries', $result);
        $issues = $result->getIssues();
        $this->assertEquals('medium', $issues[0]->severity->value);
    }

    public function test_db_facade_always_flagged_as_high(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;

Route::get('/users', function () {
    return DB::table('users')->get();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Raw DB queries are always flagged as high
        $this->assertFailed($result);
        $this->assertHasIssueContaining('raw database queries', $result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
    }

    public function test_issue_code_for_db_writes(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::post('/users', function () {
    return User::create(['name' => 'Test']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('route-has-db-writes', $issues[0]->code);
    }

    public function test_issue_code_for_complex_queries(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/users', function () {
    return User::where('active', true)->orderBy('name')->get();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertEquals('route-has-complex-queries', $issues[0]->code);
    }

    public function test_allows_simple_first_by_default(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/user', function () {
    return User::first();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Simple reads are allowed by default
        $this->assertPassed($result);
    }

    public function test_allows_simple_find_or_fail_by_default(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/user/{id}', function ($id) {
    return User::findOrFail($id);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Simple reads are allowed by default (this is what route model binding does)
        $this->assertPassed($result);
    }

    public function test_where_get_chain_is_simple_read(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\Product;

Route::get('/products', function () {
    return Product::where('active', true)->get();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // 2-method chain ending with terminal read (where + get) is a simple read
        $this->assertPassed($result);
    }

    public function test_allows_where_first_as_simple_read(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/user/{slug}', function ($slug) {
    return User::where('slug', $slug)->first();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // 2-method chain ending with terminal read (where + first) is simple
        // This is equivalent to route model binding behavior
        $this->assertPassed($result);
    }

    public function test_two_method_chain_without_terminal_is_complex(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/users', function () {
    $query = User::where('active', true)->orderBy('name');
    return $query->get();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // 2-method chain without terminal read (where + orderBy) is complex
        // The separate ->get() creates a 3-chain which is also complex
        $this->assertWarning($result);
        $this->assertHasIssueContaining('complex database queries', $result);
    }

    public function test_allows_view_fluent_chain(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/home', function () {
    return view('home')->with('title', 'Welcome')->with('subtitle', 'Hello');
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // view() fluent chains should pass - standard Laravel pattern
        $this->assertPassed($result);
    }

    public function test_allows_response_json_with_headers(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/api/data', function () {
    return response()->json(['ok' => true])->header('X-Custom', 'value');
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // response() fluent chains should pass - standard Laravel pattern
        $this->assertPassed($result);
    }

    public function test_allows_redirect_fluent_chain(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/go', function () {
    return redirect()->route('dashboard')->with('status', 'success');
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // redirect() fluent chains should pass - standard Laravel pattern
        $this->assertPassed($result);
    }

    public function test_allows_back_fluent_chain(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/form', function () {
    return back()->withInput()->withErrors(['email' => 'Invalid']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // back() fluent chains should pass - standard Laravel pattern
        $this->assertPassed($result);
    }

    public function test_allows_collect_fluent_chain(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/items', function () {
    return collect([1, 2, 3])->map(fn($x) => $x * 2)->filter(fn($x) => $x > 2)->values();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // collect() fluent chains should pass - standard Laravel pattern
        $this->assertPassed($result);
    }

    public function test_still_flags_non_safe_method_chains(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/process', function ($service) {
    return $service->validate()->process()->save();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Non-safe method chains should still be flagged
        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_does_not_flag_http_facade_get(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Http;

Route::get('/api-proxy', function () {
    $response = Http::get('https://api.example.com/data');
    return response()->json($response->json());
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Http::get() is NOT a database query - should pass
        $this->assertPassed($result);
    }

    public function test_does_not_flag_service_class_static_methods(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Services\PaymentGateway;

Route::post('/charge', function () {
    return PaymentGateway::charge(1000);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // PaymentGateway is in App\Services, not App\Models - should pass
        $this->assertPassed($result);
    }

    public function test_flags_model_in_domain_models_namespace(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Domain\Blog\Models\Author;

Route::post('/authors', function () {
    return Author::create(['name' => 'Test']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Domain\Blog\Models\Author contains \Models\ - should be flagged
        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operations', $result);
    }

    public function test_route_group_closure_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AirportController;

Route::group(['as' => 'airports.', 'prefix' => 'airports'], function () {
    Route::get('/', [AirportController::class, 'index'])->name('index');
    Route::get('/create', [AirportController::class, 'create'])->name('create');
    Route::post('/', [AirportController::class, 'store'])->name('store');
    Route::get('/{airport}', [AirportController::class, 'show'])->name('show');
    Route::get('/{airport}/edit', [AirportController::class, 'edit'])->name('edit');
    Route::put('/{airport}', [AirportController::class, 'update'])->name('update');
    Route::delete('/{airport}', [AirportController::class, 'destroy'])->name('destroy');
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Route::group() closures contain route definitions, not business logic
        $this->assertPassed($result);
    }

    public function test_route_middleware_group_closure_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\ProfileController;

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
    Route::get('/profile', [ProfileController::class, 'show']);
    Route::put('/profile', [ProfileController::class, 'update']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Route grouping closures should not be flagged
        $this->assertPassed($result);
    }

    public function test_route_prefix_group_closure_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\UserController;
use App\Http\Controllers\Api\PostController;

Route::prefix('api/v1')->group(function () {
    Route::get('/users', [UserController::class, 'index']);
    Route::get('/posts', [PostController::class, 'index']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Route grouping closures should not be flagged
        $this->assertPassed($result);
    }

    public function test_route_group_with_bad_handler_inside_still_flagged(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::group(['prefix' => 'admin'], function () {
    Route::post('/users', function () {
        return User::create(['name' => 'Test']);
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // The inner Route::post handler closure should still be flagged
        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operations', $result);
    }

    public function test_does_not_flag_unresolved_pascalcase_class(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/test', function () {
    return SomeUnknownClass::getData();
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Without a use statement, we can't determine namespace - assume not a model
        $this->assertPassed($result);
    }
}
