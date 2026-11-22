<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use PhpParser\Node;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\BestPractices\LogicInRoutesAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
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
        $this->assertEquals('route-has-raw-queries', $issues[0]->metadata['code']);
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
        $this->assertEquals('route-has-business-logic', $issues[0]->metadata['code']);
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
        $this->assertEquals('route-closure-too-long', $issues[0]->metadata['code']);
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
        $this->assertEquals('route-has-db-writes', $issues[0]->metadata['code']);
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
        $this->assertEquals('route-has-complex-queries', $issues[0]->metadata['code']);
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

    public function test_colliding_imports_do_not_drop_the_route_file(): void
    {
        // Two imports landing on one alias. NameResolver's default handler throws on the
        // second, and the file loop's catch used to drop the route file without a finding.
        $code = <<<'PHP'
<?php

use App\Billing\Ledger;
use App\Legacy\Ledger;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;

Route::post('/invoices/{id}/approve', function ($id) {
    DB::table('invoices')->where('id', $id)->update(['approved' => true]);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_does_not_replace_names_in_the_shared_parse_cache(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;

Route::post('/invoices/{id}/approve', function ($id) {
    DB::table('invoices')->where('id', $id)->update(['approved' => true]);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        // Parse first and keep the nodes, so what is inspected afterwards is the very tree the
        // analyzer was handed.
        $path = $tempDir.'/routes/web.php';
        $ast = $this->parser->parseFile($path);

        /** @var array<int, Node\Expr\StaticCall> $calls */
        $calls = $this->parser->findNodes($ast, Node\Expr\StaticCall::class);
        $this->assertCount(2, $calls);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        // A finding says the walk reached this tree rather than skipping it.
        $this->assertFailed($analyzer->analyze());
        $this->assertSame(1, $this->cachedTreesFor($path));

        foreach ($calls as $call) {
            $class = $call->class;
            if (! $class instanceof Node\Name) {
                self::fail('Expected the static call to name a class.');
            }

            // Still the name as written, with the resolution left beside it.
            $this->assertSame(Node\Name::class, $class::class);
            $resolved = $class->getAttribute('resolvedName');
            $this->assertInstanceOf(Node\Name\FullyQualified::class, $resolved);
            $this->assertStringStartsWith('Illuminate\Support\Facades\\', $resolved->toString());
        }
    }

    /**
     * A model read is graded by the read rules, not as "complex business logic": a builder
     * method outside the plain where/find set, or a custom scope chained into a read terminal,
     * is still a read, and a simple read passes under the default config.
     *
     * @dataProvider modelReadChainProvider
     */
    #[DataProvider('modelReadChainProvider')]
    public function test_model_read_chain_is_not_graded_as_business_logic(string $expression): void
    {
        $result = $this->analyzeRouteReturning($expression);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function modelReadChainProvider(): array
    {
        return [
            'paginate' => ['Article::paginate(20)'],
            'simplePaginate' => ['Article::simplePaginate()'],
            'cursorPaginate' => ['Article::cursorPaginate(10)'],
            'latest then get' => ['Article::latest()->get()'],
            'oldest then first' => ['Article::oldest()->first()'],
            'withCount then get' => ["Article::withCount('remarks')->get()"],
            'custom scope then get' => ['Article::visible()->get()'],
            'custom scope then paginate' => ['Article::visible()->paginate(20)'],
            'where then paginate' => ["Article::where('state', 'live')->paginate(20)"],
        ];
    }

    public function test_where_in_read_chain_is_graded_as_a_complex_read(): void
    {
        $result = $this->analyzeRouteReturning("Article::whereIn('id', [7, 8])->get()");

        $this->assertWarning($result);
        $this->assertHasIssueContaining('complex database queries', $result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame('medium', $issue->severity->value);
        $this->assertStringNotContainsString('complex business logic', $issue->message);
    }

    /**
     * A write anywhere in a model chain, or a model method that is neither a query method nor
     * followed by a read terminal, keeps its High grade.
     *
     * @dataProvider modelWriteOrDomainCallProvider
     */
    #[DataProvider('modelWriteOrDomainCallProvider')]
    public function test_model_write_or_domain_call_stays_high(string $expression, string $expectedMessage): void
    {
        $result = $this->analyzeRouteReturning($expression);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame('high', $issue->severity->value);
        $this->assertSame($expectedMessage, $issue->message);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function modelWriteOrDomainCallProvider(): array
    {
        return [
            'static create' => [
                'Article::create(request()->all())',
                'Route closure contains database write operations, complex business logic',
            ],
            'where then update' => [
                "Article::where('state', 'draft')->update(['state' => 'live'])",
                'Route closure contains database write operations',
            ],
            'custom scope then delete' => [
                'Article::visible()->delete()',
                'Route closure contains database write operations, complex business logic',
            ],
            'custom scope read then higher-order delete' => [
                'Article::visible()->get()->each->delete()',
                'Route closure contains complex business logic',
            ],
            'custom scope read then nullsafe delete' => [
                'Article::visible()->first()?->delete()',
                'Route closure contains complex business logic',
            ],
            'domain method without a read terminal' => [
                'Invoice::issueCredit($id)',
                'Route closure contains complex business logic',
            ],
        ];
    }

    public function test_strict_mode_reports_direct_paginate_as_a_simple_read(): void
    {
        $result = $this->analyzeRouteReturning('Article::paginate(20)', allowSimpleReads: false);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame('low', $issue->severity->value);
        $this->assertSame('Route closure contains database queries (strict mode)', $issue->message);
    }

    public function test_strict_mode_reports_direct_all_as_a_simple_read(): void
    {
        $result = $this->analyzeRouteReturning('Article::all()', allowSimpleReads: false);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame('low', $issue->severity->value);
        $this->assertSame('Route closure contains database queries (strict mode)', $issue->message);
    }

    /**
     * A read on its own is exempt from "complex business logic", but not when the closure also
     * writes: the read's result, or anything else, may be what gets written.
     *
     * @dataProvider readThenWriteElsewhereProvider
     */
    #[DataProvider('readThenWriteElsewhereProvider')]
    public function test_read_chain_in_a_closure_that_writes_stays_high(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $this->assertSame('high', $result->getIssues()[0]->severity->value);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function readThenWriteElsewhereProvider(): array
    {
        return [
            'scope read, write on the variable' => [
                "Route::get('/a', function () { \$a = Article::visible()->first(); \$a->delete(); return 1; });",
            ],
            'latest read, write on the variable' => [
                "Route::get('/a', function () { \$a = Article::latest()->first(); \$a->delete(); return 1; });",
            ],
            'scope read, write on an indexed element' => [
                "Route::get('/a', function () { Article::visible()->get()[0]->delete(); return 1; });",
            ],
            'scope read, write inside an each callback' => [
                "Route::get('/a', function () { Article::visible()->get()->each(function (\$a) { \$a->delete(); }); return 1; });",
            ],
            'long relation read, write on the result' => [
                "Route::get('/a', function () { \$a = auth()->user()->articles()->latest()->first(); \$a->delete(); return 1; });",
            ],
        ];
    }

    /**
     * @dataProvider restoreChainProvider
     */
    #[DataProvider('restoreChainProvider')]
    public function test_restore_is_graded_as_a_write(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $issue = $result->getIssues()[0];
        $this->assertSame('high', $issue->severity->value);
        $this->assertStringContainsString('database write operations', $issue->message);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function restoreChainProvider(): array
    {
        return [
            'onlyTrashed then restore' => ["Route::get('/a', fn () => Article::onlyTrashed()->restore());"],
            'withTrashed find then restore' => ["Route::get('/a', fn () => Article::withTrashed()->find(1)->restore());"],
        ];
    }

    /**
     * @dataProvider strictModeDirectReadProvider
     */
    #[DataProvider('strictModeDirectReadProvider')]
    public function test_strict_mode_reports_direct_static_read(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes, allowSimpleReads: false);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame('low', $issue->severity->value);
        $this->assertSame('Route closure contains database queries (strict mode)', $issue->message);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function strictModeDirectReadProvider(): array
    {
        return [
            'firstWhere' => ["Route::get('/a', fn () => Article::firstWhere('slug', 'x'));"],
            'sum' => ["Route::get('/a', fn () => Article::sum('views'));"],
            'findMany' => ["Route::get('/a', fn () => Article::findMany([1, 2]));"],
            'value' => ["Route::get('/a', fn () => Article::value('title'));"],
        ];
    }

    /**
     * A chain of three or more calls that ends in a read terminal is a read, graded by the
     * database-query rules rather than as "complex business logic".
     *
     * @dataProvider longReadChainProvider
     */
    #[DataProvider('longReadChainProvider')]
    public function test_long_read_chain_is_not_graded_as_business_logic(string $routes, string $expectedStatus): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertSame($expectedStatus, $result->getStatus()->value);
        foreach ($result->getIssues() as $issue) {
            $this->assertNotSame('high', $issue->severity->value, $issue->message);
            $this->assertStringNotContainsString('complex business logic', $issue->message);
        }
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function longReadChainProvider(): array
    {
        return [
            'query where latest paginate' => [
                "Route::get('/a', fn () => Article::query()->where('live', true)->latest()->paginate(15));",
                'warning',
            ],
            'with where latest paginate' => [
                "Route::get('/a', fn () => Article::with('author')->where('live', true)->latest()->paginate(15));",
                'warning',
            ],
            'request user relation read' => [
                "Route::get('/a', fn (Request \$r) => \$r->user()->articles()->latest()->get());",
                'passed',
            ],
            'auth user relation paginate' => [
                "Route::get('/a', fn () => auth()->user()->articles()->paginate());",
                'passed',
            ],
        ];
    }

    /**
     * @dataProvider longNonReadChainProvider
     */
    #[DataProvider('longNonReadChainProvider')]
    public function test_long_non_read_chain_stays_business_logic(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $issue = $result->getIssues()[0];
        $this->assertSame('high', $issue->severity->value);
        $this->assertStringContainsString('complex business logic', $issue->message);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function longNonReadChainProvider(): array
    {
        return [
            'service chain without a read terminal' => [
                "Route::get('/a', fn (\$service) => \$service->load()->transform()->render());",
            ],
            'facade chain ending in get' => [
                "Route::get('/a', fn () => Http::withToken('t')->retry(3)->timeout(5)->get('https://example.test'));",
            ],
        ];
    }

    public function test_where_null_and_where_not_null_reads_are_graded_alike(): void
    {
        $this->assertPassed($this->analyzeRouteFile("Route::get('/a', fn () => Article::whereNull('archived_at')->get());"));
        $this->assertPassed($this->analyzeRouteFile("Route::get('/a', fn () => Article::whereNotNull('archived_at')->get());"));
    }

    /**
     * Only a model static call or the signed-in user, reached through user(), roots a read
     * chain. Any other receiver, such as an HTTP client or a service, keeps check 3.
     *
     * @dataProvider nonRelationReceiverChainProvider
     */
    #[DataProvider('nonRelationReceiverChainProvider')]
    public function test_long_chain_on_a_non_relation_receiver_stays_business_logic(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $issue = $result->getIssues()[0];
        $this->assertSame('high', $issue->severity->value);
        $this->assertStringContainsString('complex business logic', $issue->message);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonRelationReceiverChainProvider(): array
    {
        return [
            'http client through a variable' => [
                "Route::get('/a', function () { \$api = Http::withToken('t'); return \$api->retry(3)->timeout(5)->get('https://example.test'); });",
            ],
            'injected http factory' => [
                "Route::get('/a', fn (Factory \$http) => \$http->withToken('t')->retry(3)->get('https://example.test'));",
            ],
            'new pending request' => [
                "Route::get('/a', fn () => (new \\Illuminate\\Http\\Client\\PendingRequest)->withToken('t')->retry(3)->get('https://example.test'));",
            ],
            'injected service ending in sum' => [
                "Route::get('/a', fn (\\App\\Services\\Ledger \$l) => \$l->forClient(1)->applyCredits()->settle()->sum('total'));",
            ],
            'new service ending in get' => [
                "Route::get('/a', fn () => (new \\App\\Services\\Digest)->forMonth(1)->withTotals()->get());",
            ],
        ];
    }

    public function test_relation_read_through_a_property_hop_is_not_business_logic(): void
    {
        $this->assertPassed($this->analyzeRouteFile("Route::get('/a', fn () => auth()->user()->team->articles()->latest()->get());"));
    }

    /**
     * A read followed by a per-row callback is not a read: the callback can do anything.
     *
     * @dataProvider readThenCallbackProvider
     */
    #[DataProvider('readThenCallbackProvider')]
    public function test_read_followed_by_a_callback_stays_high(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $issue = $result->getIssues()[0];
        $this->assertSame('high', $issue->severity->value);
        $this->assertStringContainsString('complex business logic', $issue->message);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function readThenCallbackProvider(): array
    {
        return [
            'oldest then each' => [
                "Route::post('/a', fn () => Member::oldest()->each(fn (\$m) => \$m->bill(100, 'card')));",
            ],
            'scope get then each' => [
                "Route::post('/a', fn () => Article::visible()->get()->each(fn (\$a) => \$a->author->notify(new \\App\\Notifications\\Digest)));",
            ],
            'latest then each' => [
                "Route::post('/a', fn () => Article::latest()->each(fn (\$a) => \$a->author->notify(new \\App\\Notifications\\Digest)));",
            ],
            'latest get then each' => [
                "Route::post('/a', fn () => Article::latest()->get()->each(fn (\$a) => \$a->author->notify(new \\App\\Notifications\\Digest)));",
            ],
            'latest get in a foreach' => [
                "Route::post('/a', function () { foreach (Article::latest()->get() as \$a) { \$a->author->notify(new \\App\\Notifications\\Digest); } return 1; });",
            ],
            'oldest then chunk' => [
                "Route::post('/a', fn () => Article::oldest()->chunk(100, fn (\$as) => \$as->each->notify(new \\App\\Notifications\\Digest)));",
            ],
        ];
    }

    /**
     * The read exemption covers only a closure whose whole body is one read chain. Any other
     * statement beside the read, even a write-named call that does not touch the database,
     * leaves the closure graded as before.
     *
     * @dataProvider nonModelWriteNamedCallProvider
     */
    #[DataProvider('nonModelWriteNamedCallProvider')]
    public function test_statement_beside_a_read_keeps_the_business_logic_grade(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $issue = $result->getIssues()[0];
        $this->assertSame('high', $issue->severity->value);
        $this->assertStringContainsString('complex business logic', $issue->message);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonModelWriteNamedCallProvider(): array
    {
        return [
            'session helper increment' => [
                "Route::get('/a', function () { session()->increment('views'); return Article::latest()->get(); });",
            ],
            'storage facade delete' => [
                "Route::get('/a', function () { Storage::delete('x'); return Article::paginate(15); });",
            ],
            'cache facade increment' => [
                "Route::get('/a', function () { Cache::increment('x'); return Article::paginate(15); });",
            ],
        ];
    }

    public function test_write_on_the_signed_in_user_cancels_the_read_exemption(): void
    {
        $result = $this->analyzeRouteFile("Route::get('/a', function () { auth()->user()->delete(); return Article::latest()->get(); });");

        $this->assertFailed($result);
        $this->assertSame('high', $result->getIssues()[0]->severity->value);
    }

    /**
     * Writes, per-row callbacks and higher-order proxies beside or after a read keep the
     * business-logic grade: the read exemption needs the whole body to be one read chain.
     *
     * @dataProvider notASingleReadChainProvider
     */
    #[DataProvider('notASingleReadChainProvider')]
    public function test_body_that_is_not_a_single_read_chain_stays_high(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $issue = $result->getIssues()[0];
        $this->assertSame('high', $issue->severity->value);
        $this->assertStringContainsString('complex business logic', $issue->message);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function notASingleReadChainProvider(): array
    {
        return [
            'write on a model short-named like a utility class' => [
                "Route::delete('/a/{id}', function (\$id) { File::findOrFail(\$id)->delete(); return Article::latest()->paginate(); });",
            ],
            'force delete through a collect helper' => [
                "Route::post('/a', function () { collect(Article::onlyTrashed()->get())->each->forceDelete(); return 'ok'; });",
            ],
            'per-row callback on a read held in a variable' => [
                "Route::post('/a', function () { \$articles = Article::visible()->get(); \$articles->each(fn (\$a) => \$a->author->notify(new \\App\\Notifications\\Digest(\$a))); return 'ok'; });",
            ],
            'per-row callback before a count' => [
                "Route::post('/a', fn () => Article::visible()->get()->each(fn (\$a) => \$a->author->notify(new \\App\\Notifications\\Digest(\$a)))->count());",
            ],
            'higher-order each proxy before a count' => [
                "Route::post('/a', fn () => Article::latest()->get()->each->publish()->count());",
            ],
            'read terminal taking a callback' => [
                "Route::get('/a', fn () => Article::findOr(1, fn () => abort(404)));",
            ],
            'array callable passed to each' => [
                "Route::get('/a', fn () => Article::where('due', true)->get()->each([\\App\\Jobs\\SendReminder::class, 'dispatch'])->count());",
            ],
            'function name passed to each' => [
                "Route::get('/a', fn () => Article::where('due', true)->get()->each('send_reminder')->count());",
            ],
            'invokable passed to each' => [
                "Route::get('/a', fn () => Article::where('due', true)->get()->each(new \\App\\Actions\\ArchiveArticle)->count());",
            ],
            'invokable passed to tap' => [
                "Route::get('/a', fn () => Article::where('due', true)->get()->tap(new \\App\\Actions\\ArchiveArticles)->count());",
            ],
            'array callable passed to pipe' => [
                "Route::get('/a', fn () => Article::where('due', true)->get()->pipe([\\App\\Actions\\ArchiveArticles::class, 'run'])->count());",
            ],
            'builder in a variable, read in the return' => [
                "Route::get('/a', function () { \$q = Article::latest(); return \$q->get(); });",
            ],
        ];
    }

    /**
     * A paginator or serialisation call after a read terminal is still the read.
     *
     * @dataProvider readResultTailProvider
     */
    #[DataProvider('readResultTailProvider')]
    public function test_read_followed_by_a_result_tail_is_not_business_logic(string $routes, string $expectedStatus): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertSame($expectedStatus, $result->getStatus()->value);
        foreach ($result->getIssues() as $issue) {
            $this->assertNotSame('high', $issue->severity->value, $issue->message);
            $this->assertStringNotContainsString('complex business logic', $issue->message);
        }
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function readResultTailProvider(): array
    {
        return [
            'paginate with query string' => [
                "Route::get('/a', fn () => Article::latest()->paginate(15)->withQueryString());",
                'passed',
            ],
            'paginate with appends' => [
                "Route::get('/a', fn () => Article::latest()->paginate(15)->appends(request()->query()));",
                'passed',
            ],
            'take get to array' => [
                "Route::get('/a', fn () => Article::latest()->take(5)->get()->toArray());",
                'warning',
            ],
        ];
    }

    /**
     * A comment after the return statement is parsed as an extra no-op statement; the body
     * is still the single read chain.
     *
     * @dataProvider commentedReadChainProvider
     */
    #[DataProvider('commentedReadChainProvider')]
    public function test_read_chain_with_a_trailing_comment_is_not_business_logic(string $routes): void
    {
        $this->assertPassed($this->analyzeRouteFile($routes));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function commentedReadChainProvider(): array
    {
        return [
            'line comment after the return' => [
                "Route::get('/a', function () {\n    return Article::paginate(15); // newest first\n});",
            ],
            'block comment on its own line' => [
                "Route::get('/a', function () {\n    return Article::paginate(15);\n    /* keep simple */\n});",
            ],
        ];
    }

    private function analyzeRouteFile(string $routes, bool $allowSimpleReads = true): ResultInterface
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'logic-in-routes' => [
                            'max_closure_lines' => 50,
                            'allow_simple_reads' => $allowSimpleReads,
                        ],
                    ],
                ],
            ],
        ]);

        $code = "<?php\n\nuse App\\Models\\Article;\nuse App\\Models\\File;\nuse App\\Models\\Member;\nuse Illuminate\\Http\\Client\\Factory;\nuse Illuminate\\Http\\Request;\nuse Illuminate\\Support\\Facades\\Cache;\nuse Illuminate\\Support\\Facades\\Http;\nuse Illuminate\\Support\\Facades\\Route;\nuse Illuminate\\Support\\Facades\\Storage;\n\n{$routes}\n";

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = new LogicInRoutesAnalyzer($this->parser, $config);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        return $analyzer->analyze();
    }

    private function analyzeRouteReturning(string $expression, bool $allowSimpleReads = true): ResultInterface
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'logic-in-routes' => [
                            'max_closure_lines' => 5,
                            'allow_simple_reads' => $allowSimpleReads,
                        ],
                    ],
                ],
            ],
        ]);

        $code = <<<PHP
<?php

use App\\Models\\Article;
use App\\Models\\Invoice;
use Illuminate\\Support\\Facades\\Route;

Route::get('/articles/{id}', function (\$id) {
    return {$expression};
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = new LogicInRoutesAnalyzer($this->parser, $config);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        return $analyzer->analyze();
    }

    /**
     * @dataProvider registrarChainRouteProvider
     */
    #[DataProvider('registrarChainRouteProvider')]
    public function test_flags_handler_closure_on_a_registrar_chain(string $route): void
    {
        // A route registered through a RouteRegistrar chain (Route::middleware()->get())
        // carries its handler on the chain's last call rather than on the static call, and
        // is graded as the same route registered with Route::get() would be.
        $code = <<<PHP
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Route as Router;
use App\Models\Widget;

{$route}
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('database write operations', $result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
        $this->assertSame(7, $issues[0]->location?->line);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function registrarChainRouteProvider(): array
    {
        $body = "function () {\n    return Widget::create(request()->all());\n}";

        return [
            'middleware then get' => ["Route::middleware('auth')->get('/widgets', {$body});"],
            'prefix then post' => ["Route::prefix('admin')->post('/widgets', {$body});"],
            'name then get' => ["Route::name('widgets.store')->get('/widgets', {$body});"],
            'middleware, prefix and name then put' => ["Route::middleware(['auth'])->prefix('admin')->name('admin.')->put('/widgets', {$body});"],
            'domain then get' => ["Route::domain('shop.example.test')->get('/widgets', {$body});"],
            'withoutMiddleware then get' => ["Route::withoutMiddleware('throttle')->get('/widgets', {$body});"],
            'middleware then any' => ["Route::middleware('auth')->any('/widgets', {$body});"],
            'middleware then match' => ["Route::middleware('auth')->match(['get', 'post'], '/widgets', {$body});"],
            'middleware then patch' => ["Route::middleware('auth')->patch('/widgets', {$body});"],
            'middleware then delete' => ["Route::middleware('auth')->delete('/widgets', {$body});"],
            'middleware then options' => ["Route::middleware('auth')->options('/widgets', {$body});"],
            'middleware then arrow function' => ["Route::middleware('auth')->post('/widgets', fn () =>\n    Widget::create(request()->all()));"],
            'aliased facade' => ["Router::middleware('auth')->post('/widgets', {$body});"],
            'fully qualified facade' => ["\\Illuminate\\Support\\Facades\\Route::prefix('admin')->post('/widgets', {$body});"],
        ];
    }

    public function test_registrar_chain_reports_the_same_issue_as_a_plain_route(): void
    {
        $plain = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\Widget;

Route::post('/widgets', function () {
    return Widget::create(request()->all());
});
PHP;

        $chained = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\Widget;

Route::middleware('auth')->post('/widgets', function () {
    return Widget::create(request()->all());
});
PHP;

        $plainDir = $this->createTempDirectory(['routes/web.php' => $plain]);
        $chainedDir = $this->createTempDirectory(['routes/web.php' => $chained]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($plainDir);
        $analyzer->setPaths(['routes']);
        $plainIssues = $analyzer->analyze()->getIssues();

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($chainedDir);
        $analyzer->setPaths(['routes']);
        $chainedIssues = $analyzer->analyze()->getIssues();

        $this->assertCount(1, $plainIssues);
        $this->assertCount(1, $chainedIssues);
        $this->assertSame($plainIssues[0]->message, $chainedIssues[0]->message);
        $this->assertSame($plainIssues[0]->severity, $chainedIssues[0]->severity);
        $this->assertSame($plainIssues[0]->recommendation, $chainedIssues[0]->recommendation);
        $this->assertSame($plainIssues[0]->metadata, $chainedIssues[0]->metadata);
    }

    public function test_registrar_chain_with_trivial_closure_passes(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::middleware('auth')->get('/widgets', function () {
    return view('widgets.index');
});

Route::prefix('admin')->name('admin.')->get('/widgets', fn () => view('admin.widgets'));
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_registrar_chain_without_a_closure_handler_passes(): void
    {
        // Controller routes, resources and controller-group string actions carry no closure.
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\WidgetController;

Route::middleware('auth')->post('/widgets', [WidgetController::class, 'store']);
Route::middleware('auth')->resource('gadgets', WidgetController::class);
Route::controller(WidgetController::class)->post('/widgets/archive', 'archive');
Route::controller(WidgetController::class)->group(function () {
    Route::post('/widgets/restore', 'restore');
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_router_variable_chain_is_not_analysed(): void
    {
        // Only chains rooted at the Route facade are routes; a $router variable is out of scope.
        $code = <<<'PHP'
<?php

use App\Models\Widget;

$router->middleware('auth')->post('/widgets', function () {
    return Widget::create(request()->all());
});

$router->post('/gadgets', function () {
    return Widget::create(request()->all());
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_registrar_group_closure_is_not_a_handler_but_its_routes_are_analysed_once(): void
    {
        // The group closure holds route registrations, so it is never graded itself even
        // though it is long and contains a write; each nested handler is graded exactly once.
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\Widget;

Route::middleware('auth')->prefix('admin')->group(function () {
    Route::prefix('widgets')->post('/', function () {
        return Widget::create(request()->all());
    });

    Route::get('/widgets', function () {
        return view('admin.widgets');
    });

    Route::name('gadgets.')->get('/gadgets', fn () => view('admin.gadgets'));
});

Route::post('/widgets', function () {
    return Widget::create(request()->all());
})->middleware('auth')->name('widgets.store');
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(2, $result);
        $lines = array_map(fn ($issue) => $issue->location?->line, $result->getIssues());
        sort($lines);
        $this->assertSame([7, 18], $lines);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function bareAppHelperProvider(): array
    {
        return [
            'getLocale' => ['fn () => app()->getLocale()'],
            'environment' => ['fn () => app()->environment()'],
            'environment with argument' => ["fn () => app()->environment('local') ? 'dev' : 'live'"],
            'isLocal' => ['fn () => app()->isLocal()'],
            'isProduction' => ['fn () => app()->isProduction()'],
            'version' => ['fn () => app()->version()'],
            'runningInConsole' => ['fn () => app()->runningInConsole()'],
            'currentLocale' => ['fn () => app()->currentLocale()'],
            'fully qualified' => ['fn () => \\app()->getLocale()'],
            'closure body' => ["function () {\n    return ['locale' => app()->getLocale()];\n}"],
        ];
    }

    /**
     * @dataProvider bareAppHelperProvider
     */
    #[DataProvider('bareAppHelperProvider')]
    public function test_passes_bare_app_helper_for_application_info(string $handler): void
    {
        $code = "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::get('/sample', {$handler});\n";

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function appContainerResolutionProvider(): array
    {
        return [
            'app with class argument' => ['fn () => app(SampleBillingService::class)->charge(1)'],
            'app with string argument' => ["fn () => app('sample.mailer')->send('sample')"],
            'app make' => ['fn () => app()->make(SampleWidget::class)->run()'],
            'app makeWith' => ["fn () => app()->makeWith(SampleWidget::class, ['size' => 1])->run()"],
            'app call' => ["fn () => app()->call([SampleHandler::class, 'handle'])"],
            'app get' => ["fn () => app()->get('sample.service')->run()"],
            'app array access' => ["fn () => app()['sample.service']->run()"],
            'resolve' => ['fn () => resolve(SampleWidget::class)->run()'],
            'app magic property' => ["fn () => app()->sample_mailer->send('sample')"],
            'app assigned to a variable' => ["function () {\n    \$container = app();\n    return \$container->make(SampleWidget::class)->run();\n}"],
            'app nullsafe make' => ['fn () => app()?->make(SampleWidget::class)->run()'],
            'app dynamic method name' => ["fn () => app()->{'make'}(SampleWidget::class)"],
            'app make in another case' => ['fn () => app()->MAKE(SampleWidget::class)->run()'],
            'app build' => ['fn () => app()->build(SampleWidget::class)->run()'],
            'app factory' => ['fn () => app()->factory(SampleWidget::class)'],
            'app offsetGet' => ["fn () => app()->offsetGet('sample.service')->run()"],
            'app passed as an argument' => ["fn () => view('sample', ['container' => app()])"],
        ];
    }

    /**
     * @dataProvider appContainerResolutionProvider
     */
    #[DataProvider('appContainerResolutionProvider')]
    public function test_flags_app_helper_container_resolution_as_high(string $handler): void
    {
        $code = "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::get('/sample', {$handler});\n";

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals('high', $issues[0]->severity->value);
    }
}
