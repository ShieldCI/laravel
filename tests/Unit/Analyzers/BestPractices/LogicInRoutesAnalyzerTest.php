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
                    'best_practices' => [
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database queries', $result);
    }

    public function test_detects_eloquent_find_method(): void
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database queries', $result);
    }

    public function test_detects_eloquent_create_method(): void
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
        $this->assertHasIssueContaining('database queries', $result);
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

    public function test_detects_foreach_loops(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/items', function () {
    $items = [1, 2, 3];
    foreach ($items as $item) {
        echo $item;
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
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_for_loops(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/count', function () {
    for ($i = 0; $i < 10; $i++) {
        echo $i;
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
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_detects_while_loops(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/process', function () {
    $i = 0;
    while ($i < 10) {
        echo $i;
        $i++;
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
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    public function test_passes_with_simple_if_statement(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/check', function () {
    if (auth()->check()) {
        return 'Authenticated';
    }
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

        $this->assertFailed($result);
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
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Models\User;

Route::get('/complex', function () {
    $users = User::where('active', true)->get();
    foreach ($users as $user) {
        if ($user->age > 18) {
            echo $user->name;
        }
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

    public function test_severity_critical_for_database_queries(): void
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

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('critical', $issues[0]->severity->value);
    }

    public function test_severity_high_for_complex_business_logic(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/process', function () {
    foreach ([1, 2, 3] as $item) {
        echo $item;
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

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('medium', $issues[0]->severity->value);
    }

    public function test_issue_code_for_database_queries(): void
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
        $this->assertEquals('route-has-db-queries', $issues[0]->code);
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

        $this->assertFailed($result);
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

Route::get('/bad', function () {
    return User::where('active', true)->get();
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
                    'best_practices' => [
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
        $this->assertFailed($result);
    }

    public function test_provides_controller_recommendation_for_db_queries(): void
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

Route::get('/users', function () {
    return User::all();
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

Route::get('/test', function () {
    return User::where('active', true)->get();
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
    }
}
