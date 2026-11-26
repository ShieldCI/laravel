<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use PhpParser\Node;
use PhpParser\ParserFactory;
use PhpParser\PhpVersion;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\AnalyzerManager;
use ShieldCI\Analyzers\BestPractices\LogicInRoutesAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Tests\AnalyzerTestCase;

class LogicInRoutesAnalyzerTest extends AnalyzerTestCase
{
    private const UNPARSEABLE_ROUTES = <<<'PHP'
<?php

use App\Models\Article;
use Illuminate\Support\Facades\Route;

Route::post('/articles', function () {
    return Article::create(request()->all())
});

PHP;

    private const WRITING_ROUTES = <<<'PHP'
<?php

use App\Models\Article;
use Illuminate\Support\Facades\Route;

Route::post('/articles', fn () => Article::create(request()->all()));

PHP;

    private const ARTICLE_MODEL = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Article extends Model
{
}

PHP;

    private const WRITING_PROJECT = [
        'app/Models/Article.php' => self::ARTICLE_MODEL,
        'routes/web.php' => self::WRITING_ROUTES,
    ];

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
    return DB::table('users')->whereRaw('active = 1')->get();
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

    /**
     * A route file that does not parse is reported, so the routes it registers are not read
     * as clean: one Low issue at the parse error's line, a warning rather than a pass.
     */
    public function test_reports_an_unparseable_route_file(): void
    {
        $tempDir = $this->createTempDirectory(['routes/web.php' => self::UNPARSEABLE_ROUTES]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertUnparseableRouteIssue($result->getIssues()[0], 'routes/web.php', 8);
    }

    /**
     * The message is the parser's own, without the line it names or any path, so it stays
     * stable for a baseline.
     */
    public function test_reports_the_parser_message_for_an_unparseable_route_file(): void
    {
        $tempDir = $this->createTempDirectory(['routes/web.php' => '<?php this is invalid PHP code {{{']);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame('Route file could not be parsed: Syntax error, unexpected T_STRING', $issue->message);
        $this->assertUnparseableRouteIssue($issue, 'routes/web.php', 1);
    }

    public function test_reports_an_unparseable_route_file_beside_a_route_file_with_a_write(): void
    {
        $tempDir = $this->createTempDirectory([
            'routes/api.php' => self::WRITING_ROUTES,
            'routes/web.php' => self::UNPARSEABLE_ROUTES,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(2, $result);
        $codes = array_map(static fn ($issue) => $issue->metadata['code'] ?? null, $result->getIssues());
        sort($codes);
        $this->assertSame(['route-file-parse-error', 'route-has-db-writes'], $codes);
    }

    /**
     * The shared parser keeps the first sighting of a failure for the whole run, so a route
     * file another analyzer already failed to parse is still reported once, and a failure the
     * log holds for a file outside the analysed set is not reported here.
     */
    public function test_reports_an_unparseable_route_file_already_in_the_shared_failure_log_once(): void
    {
        $tempDir = $this->createTempDirectory([
            'routes/web.php' => self::UNPARSEABLE_ROUTES,
            'scripts/broken.php' => "<?php\n\nfunction (\n",
        ]);

        $this->parser->parseFile($tempDir.'/routes/web.php');
        $this->parser->parseFile($tempDir.'/scripts/broken.php');
        $this->assertCount(2, $this->parser->failures());

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertUnparseableRouteIssue($result->getIssues()[0], 'routes/web.php', 8);
    }

    /**
     * Only route files get the parse-error issue: a broken class under another configured path
     * is left to the report's parse-failure log, as for every other analyzer.
     */
    public function test_does_not_report_an_unparseable_file_outside_routes(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Broken.php' => "<?php\n\nclass Broken {\n",
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::get('/', fn () => view('welcome'));\n",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * A route file that parses to no statements is empty, not broken.
     *
     * @dataProvider emptyRouteFileProvider
     */
    #[DataProvider('emptyRouteFileProvider')]
    public function test_passes_an_empty_route_file(string $code): void
    {
        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function emptyRouteFileProvider(): array
    {
        return [
            'open tag only' => ['<?php'],
            'open tag and newline' => ["<?php\n"],
            'comments only' => ["<?php\n\n// No routes yet.\n/* Nothing here either. */\n"],
            'zero bytes' => [''],
        ];
    }

    /**
     * With a parser that keeps no failure log the analyzer still tells a broken route file
     * from an empty one.
     *
     * @dataProvider nonRecordingParserRouteFileProvider
     */
    #[DataProvider('nonRecordingParserRouteFileProvider')]
    public function test_tells_a_broken_route_file_from_an_empty_one_with_a_non_recording_parser(string $code, bool $broken): void
    {
        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = new LogicInRoutesAnalyzer($this->nonRecordingParser(), new Repository([]));
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        if (! $broken) {
            $this->assertPassed($result);

            return;
        }

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertUnparseableRouteIssue($result->getIssues()[0], 'routes/web.php', 8);
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function nonRecordingParserRouteFileProvider(): array
    {
        return [
            'unparseable' => [self::UNPARSEABLE_ROUTES, true],
            'open tag only' => ['<?php', false],
            'comments only' => ["<?php\n\n// No routes yet.\n", false],
        ];
    }

    public function test_detects_a_write_with_a_non_recording_parser(): void
    {
        $tempDir = $this->createTempDirectory(['routes/web.php' => self::WRITING_ROUTES]);

        $analyzer = new LogicInRoutesAnalyzer($this->nonRecordingParser(), new Repository([]));
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('route-has-db-writes', $result->getIssues()[0]->metadata['code'] ?? null);
    }

    /**
     * The route files are read whatever the configured paths are, so narrowing them to app/
     * does not turn a route with a write into a pass.
     */
    public function test_analyzes_route_files_when_the_configured_paths_do_not_include_routes(): void
    {
        $tempDir = $this->createTempDirectory(self::WRITING_PROJECT);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('route-has-db-writes', $result->getIssues()[0]->metadata['code'] ?? null);
        $this->assertSame('routes/web.php', $result->getIssues()[0]->location?->file);
    }

    public function test_still_analyzes_files_under_the_configured_paths(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Article.php' => self::ARTICLE_MODEL,
            'legacy/routes.php' => self::WRITING_ROUTES,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['legacy']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('legacy/routes.php', $result->getIssues()[0]->location?->file);
    }

    public function test_analyzes_route_files_through_the_manager_when_paths_analyze_omits_routes(): void
    {
        $app = $this->app;
        $this->assertNotNull($app);

        $tempDir = $this->createTempDirectory(self::WRITING_PROJECT);

        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $app->make('config');
        $config->set('shieldci.paths.analyze', ['app']);
        $config->set('shieldci.excluded_paths', []);

        $result = $this->withBasePath($tempDir, function () use ($app, $config): ResultInterface {
            $manager = new AnalyzerManager($config, [LogicInRoutesAnalyzer::class], $app);
            $analyzer = $manager->getAnalyzers()->first();
            $this->assertInstanceOf(LogicInRoutesAnalyzer::class, $analyzer);

            return $analyzer->analyze();
        });

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('route-has-db-writes', $result->getIssues()[0]->metadata['code'] ?? null);
    }

    /**
     * A route file reached through a configured path as well as through routes/ is analysed
     * once, so its findings are not doubled.
     *
     * @dataProvider overlappingPathsProvider
     *
     * @param  list<string>  $paths
     */
    #[DataProvider('overlappingPathsProvider')]
    public function test_analyzes_a_route_file_reached_twice_once(array $paths): void
    {
        $tempDir = $this->createTempDirectory(self::WRITING_PROJECT);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths($paths);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    /**
     * @return array<string, array{list<string>}>
     */
    public static function overlappingPathsProvider(): array
    {
        return [
            'routes' => [['routes']],
            'routes twice' => [['routes', 'routes']],
            'routes and the file' => [['routes', 'routes/web.php']],
            'the file alone' => [['routes/web.php']],
            'base path' => [['.']],
            'base path and routes' => [['', 'routes']],
            'trailing separator' => [['routes/']],
        ];
    }

    public function test_reports_an_unparseable_route_file_reached_twice_once(): void
    {
        $tempDir = $this->createTempDirectory(['routes/web.php' => self::UNPARSEABLE_ROUTES]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.', 'routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
    }

    /**
     * excluded_paths still applies to the route files the analyzer adds itself.
     *
     * @dataProvider excludedRoutesProvider
     */
    #[DataProvider('excludedRoutesProvider')]
    public function test_honours_excluded_paths_for_the_route_files(string $pattern): void
    {
        $tempDir = $this->createTempDirectory([
            ...self::WRITING_PROJECT,
            'routes/broken.php' => self::UNPARSEABLE_ROUTES,
        ]);

        $analyzer = new LogicInRoutesAnalyzer($this->parser, new Repository([]));
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);
        $analyzer->setExcludePatterns([$pattern]);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function excludedRoutesProvider(): array
    {
        return [
            'relative glob' => ['routes/*'],
            'absolute glob' => ['*/routes/*'],
        ];
    }

    /**
     * On a case-insensitive filesystem routes/ spelled in another case is the same directory,
     * so its files are analysed once whichever spelling reaches them first.
     *
     * @dataProvider differentlyCasedRoutesProvider
     *
     * @param  list<string>  $paths
     */
    #[DataProvider('differentlyCasedRoutesProvider')]
    public function test_analyzes_a_route_file_reached_through_a_differently_cased_path_once(array $paths): void
    {
        $tempDir = $this->createTempDirectory(self::WRITING_PROJECT);

        if (! is_file($tempDir.'/Routes/web.php')) {
            $this->markTestSkipped('The filesystem is case-sensitive, so Routes/ is not routes/');
        }

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths($paths);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    /**
     * @return array<string, array{list<string>}>
     */
    public static function differentlyCasedRoutesProvider(): array
    {
        return [
            'Routes' => [['Routes']],
            'app, ROUTES/web.php and routes' => [['app', 'ROUTES/web.php', 'routes']],
        ];
    }

    /**
     * A file reached through a symbolic link is the file itself.
     */
    public function test_analyzes_a_route_file_reached_through_a_link_once(): void
    {
        $tempDir = $this->createTempDirectory(self::WRITING_PROJECT);

        if (! @symlink($tempDir.'/routes', $tempDir.'/linked-routes')) {
            $this->markTestSkipped('Symbolic links cannot be created here');
        }

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['linked-routes']);

        $this->assertIssueCount(1, $analyzer->analyze());
    }

    public function test_summarises_only_unparseable_route_files_without_counting_them_as_routes(): void
    {
        $tempDir = $this->createTempDirectory(['routes/web.php' => self::UNPARSEABLE_ROUTES]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringNotContainsString('business logic', $result->getMessage());
        $this->assertSame('Found 1 route file(s) that could not be analysed', $result->getMessage());
    }

    public function test_summarises_routes_and_unparseable_route_files_separately(): void
    {
        $tempDir = $this->createTempDirectory([
            'routes/api.php' => self::WRITING_ROUTES,
            'routes/web.php' => self::UNPARSEABLE_ROUTES,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertSame(
            'Found 1 route(s) with business logic that should be moved to controllers, and 1 route file(s) that could not be analysed',
            $result->getMessage()
        );
    }

    public function test_summarises_routes_with_business_logic_as_before(): void
    {
        $tempDir = $this->createTempDirectory(['routes/web.php' => self::WRITING_ROUTES]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $this->assertSame(
            'Found 1 route(s) with business logic that should be moved to controllers',
            $analyzer->analyze()->getMessage()
        );
    }

    public function test_reports_an_unreadable_route_file_as_unreadable(): void
    {
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            $this->markTestSkipped('root reads a file whatever its mode');
        }

        $tempDir = $this->createTempDirectory(['routes/web.php' => self::WRITING_ROUTES]);
        chmod($tempDir.'/routes/web.php', 0000);

        try {
            $analyzer = $this->createAnalyzer();
            $analyzer->setBasePath($tempDir);
            $analyzer->setPaths(['routes']);

            $result = $analyzer->analyze();
        } finally {
            chmod($tempDir.'/routes/web.php', 0644);
        }

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame(Severity::Low, $issue->severity);
        $this->assertSame('route-file-unreadable', $issue->metadata['code'] ?? null);
        $this->assertSame('Route file could not be read: File is not readable.', $issue->message);
        $this->assertStringNotContainsString('syntax', $issue->recommendation);
        $this->assertStringContainsString('permissions', $issue->recommendation);
    }

    /**
     * Valid PHP the installed parser has not caught up with is not a syntax error.
     */
    public function test_reports_syntax_the_parser_does_not_support_without_calling_it_a_syntax_error(): void
    {
        $tempDir = $this->createTempDirectory([
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::get('/', fn () => view('welcome'));\n",
        ]);

        $parser = new AstParser((new ParserFactory)->createForVersion(PhpVersion::fromString('7.0')));
        $analyzer = new LogicInRoutesAnalyzer($parser, new Repository([]));
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame('route-file-parse-error', $issue->metadata['code'] ?? null);
        $this->assertStringStartsWith('Route file could not be parsed: ', $issue->message);
        $this->assertStringNotContainsString('syntax error', strtolower($issue->recommendation));
        $this->assertStringContainsString('nikic/php-parser', $issue->recommendation);
    }

    /**
     * The configured paths are analysed exactly as before: a hard link to a route file under
     * app/ keeps its own finding, and routes/web.php keeps its finding too.
     */
    public function test_default_config_keeps_routes_web_php_finding_when_a_hard_link_exists_under_app(): void
    {
        $dir = $this->createTempDirectory(self::WRITING_PROJECT);
        $this->assertTrue(link($dir.'/routes/web.php', $dir.'/app/legacy-routes.php'));

        $analyzer = new LogicInRoutesAnalyzer(new AstParser, new Repository([]));
        $analyzer->setBasePath($dir);
        $analyzer->setPaths(AnalyzerManager::DEFAULT_ANALYZE_PATHS);

        $files = array_map(static fn ($issue) => $issue->location?->file, $analyzer->analyze()->getIssues());
        sort($files);

        $this->assertSame(['app/legacy-routes.php', 'routes/web.php'], $files);
    }

    /**
     * Under a '.' entry a symbolic link to a route file keeps its own finding beside the route
     * file's, whichever order the directory walk meets them in.
     */
    public function test_base_path_entry_keeps_both_spellings_of_a_linked_route_file(): void
    {
        $dir = $this->createTempDirectory(self::WRITING_PROJECT);
        @mkdir($dir.'/other');
        if (! @symlink($dir.'/routes/web.php', $dir.'/other/web.php')) {
            $this->markTestSkipped('Symbolic links cannot be created here');
        }

        $analyzer = new LogicInRoutesAnalyzer(new AstParser, new Repository([]));
        $analyzer->setBasePath($dir);
        $analyzer->setPaths(['.']);

        $files = array_map(static fn ($issue) => $issue->location?->file, $analyzer->analyze()->getIssues());
        sort($files);

        $this->assertCount(2, $files);
        $this->assertStringEndsWith('other/web.php', (string) $files[0]);
        $this->assertStringEndsWith('routes/web.php', (string) $files[1]);
    }

    /**
     * A broken route file reached under two names is one file that did not parse.
     */
    public function test_reports_an_unparseable_route_file_reached_under_two_names_once(): void
    {
        $dir = $this->createTempDirectory(['routes/web.php' => self::UNPARSEABLE_ROUTES]);
        @mkdir($dir.'/app');
        $this->assertTrue(link($dir.'/routes/web.php', $dir.'/app/legacy-routes.php'));

        $analyzer = new LogicInRoutesAnalyzer(new AstParser, new Repository([]));
        $analyzer->setBasePath($dir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
    }

    /**
     * Code the running PHP tokenises but does not compile is classified like syntax newer than
     * the parser, so the recommendation covers both rather than only blaming the parser.
     */
    public function test_recommendation_for_code_that_does_not_compile_covers_both_causes(): void
    {
        $tempDir = $this->createTempDirectory([
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware(['auth', , 'verified'])->group(function () {\n    Route::get('/home', fn () => view('home'));\n});\n",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame('route-file-parse-error', $issue->metadata['code'] ?? null);
        $this->assertStringStartsWith('Route file could not be parsed: ', $issue->message);
        $this->assertStringContainsString('php -l', $issue->recommendation);
        $this->assertStringContainsString('does not compile', $issue->recommendation);
        $this->assertStringContainsString('nikic/php-parser', $issue->recommendation);
    }

    /**
     * An entry that already covers routes/ (through a link here) is walked as before, so an
     * exclude written against that entry still applies to the route files.
     */
    public function test_link_entry_exclude_is_honoured(): void
    {
        $dir = $this->createTempDirectory([
            ...self::WRITING_PROJECT,
            'routes/api.php' => self::WRITING_ROUTES,
            'routes/admin/nested.php' => self::WRITING_ROUTES,
        ]);
        if (! @symlink($dir.'/routes', $dir.'/routeslink')) {
            $this->markTestSkipped('Symbolic links cannot be created here');
        }

        $analyzer = new LogicInRoutesAnalyzer($this->parser, new Repository([]));
        $analyzer->setBasePath($dir);
        $analyzer->setPaths(['routeslink']);
        $analyzer->setExcludePatterns(['routeslink/*']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_absolute_link_entry_exclude_is_honoured(): void
    {
        $dir = $this->createTempDirectory(self::WRITING_PROJECT);
        if (! @symlink($dir.'/routes', $dir.'/routeslink')) {
            $this->markTestSkipped('Symbolic links cannot be created here');
        }

        $analyzer = new LogicInRoutesAnalyzer($this->parser, new Repository([]));
        $analyzer->setBasePath($dir);
        $analyzer->setPaths([$dir.'/routeslink']);
        $analyzer->setExcludePatterns(['routeslink/*']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_case_variant_entry_exclude_is_honoured(): void
    {
        $dir = $this->createTempDirectory([
            ...self::WRITING_PROJECT,
            'routes/api.php' => self::WRITING_ROUTES,
        ]);

        if (! is_file($dir.'/Routes/web.php')) {
            $this->markTestSkipped('The filesystem is case-sensitive, so Routes/ is not routes/');
        }

        $analyzer = new LogicInRoutesAnalyzer($this->parser, new Repository([]));
        $analyzer->setBasePath($dir);
        $analyzer->setPaths(['Routes']);
        $analyzer->setExcludePatterns(['Routes/*']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * An entry naming one route file, or a directory below routes/, does not cover routes/,
     * so the other route files are still added.
     *
     * @dataProvider entryInsideRoutesProvider
     *
     * @param  list<string>  $paths
     */
    #[DataProvider('entryInsideRoutesProvider')]
    public function test_an_entry_inside_routes_still_adds_the_other_route_files(array $paths, string $exclude): void
    {
        $dir = $this->createTempDirectory([
            ...self::WRITING_PROJECT,
            'routes/api.php' => self::WRITING_ROUTES,
            'routes/admin/nested.php' => self::WRITING_ROUTES,
            'routes2/web.php' => self::WRITING_ROUTES,
        ]);

        $analyzer = new LogicInRoutesAnalyzer($this->parser, new Repository([]));
        $analyzer->setBasePath($dir);
        $analyzer->setPaths($paths);
        $analyzer->setExcludePatterns([$exclude]);

        $files = array_map(static fn ($issue) => $issue->location?->file, $analyzer->analyze()->getIssues());
        sort($files);

        $this->assertSame(['routes/admin/nested.php', 'routes/api.php', 'routes/web.php'], $files);
    }

    /**
     * @return array<string, array{list<string>, string}>
     */
    public static function entryInsideRoutesProvider(): array
    {
        return [
            'one route file' => [['routes/web.php'], 'routes2/*'],
            'a directory below routes/' => [['routes/admin'], 'routes2/*'],
            'a sibling sharing the prefix' => [['routes2'], 'routes2/*'],
        ];
    }

    public function test_analyzes_each_analyze_call_the_same_way(): void
    {
        $tempDir = $this->createTempDirectory(self::WRITING_PROJECT);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertIssueCount(1, $analyzer->analyze());
        $this->assertIssueCount(1, $analyzer->analyze());
    }

    private function assertUnparseableRouteIssue(Issue $issue, string $file, int $line): void
    {
        $this->assertSame(Severity::Low, $issue->severity);
        $this->assertSame('route-file-parse-error', $issue->metadata['code'] ?? null);
        $this->assertStringStartsWith('Route file could not be parsed: Syntax error', $issue->message);
        $this->assertStringNotContainsString(DIRECTORY_SEPARATOR.'routes'.DIRECTORY_SEPARATOR, $issue->message);
        $this->assertNotNull($issue->location);
        $this->assertSame($file, $issue->location->file);
        $this->assertSame($line, $issue->location->line);
    }

    /**
     * A ParserInterface that is not a RecordingParserInterface: it parses as AstParser does
     * but keeps no failure log.
     */
    private function nonRecordingParser(): ParserInterface
    {
        return new class implements ParserInterface
        {
            private AstParser $parser;

            public function __construct()
            {
                $this->parser = new AstParser;
            }

            public function parseFile(string $filePath): array
            {
                return $this->parser->parseFile($filePath);
            }

            public function parseCode(string $code): array
            {
                return $this->parser->parseCode($code);
            }

            public function findNodes(array $ast, string $nodeType): array
            {
                return $this->parser->findNodes($ast, $nodeType);
            }

            public function findMethodCalls(array $ast, string $methodName): array
            {
                return $this->parser->findMethodCalls($ast, $methodName);
            }

            public function findStaticCalls(array $ast, string $className, string $methodName): array
            {
                return $this->parser->findStaticCalls($ast, $className, $methodName);
            }

            public function resolveNames(array $ast, array $options = []): array
            {
                return $this->parser->resolveNames($ast, $options);
            }

            public function collectStringLines(array $ast): array
            {
                return $this->parser->collectStringLines($ast);
            }
        };
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

    public function test_raw_db_facade_query_flagged_as_high(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;

Route::get('/users', function () {
    return DB::selectOne('SELECT * FROM users LIMIT 1');
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
                'Route closure contains database write operations, complex business logic',
            ],
            'custom scope read then nullsafe delete' => [
                'Article::visible()->first()?->delete()',
                'Route closure contains database write operations, complex business logic',
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
     * The read exemption covers only a closure whose statements are all reads or session()
     * helper calls. Any other statement beside the read, even a write-named call that does not
     * touch the database, leaves the closure graded as before.
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
     * business-logic grade: the read exemption needs every statement of the body to be a read.
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

    /**
     * @dataProvider sideEffectingRouteBodyProvider
     */
    #[DataProvider('sideEffectingRouteBodyProvider')]
    public function test_flags_job_dispatch_artisan_and_notify_as_business_logic(string $imports, string $route): void
    {
        $code = "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n{$imports}\n{$route}\n";

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('complex business logic', $result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
        $this->assertEquals('route-has-business-logic', $issues[0]->metadata['code']);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function sideEffectingRouteBodyProvider(): array
    {
        return [
            'static dispatch, fully qualified job' => [
                '',
                "Route::post('/digests', function () {\n    \\Acme\\Jobs\\CompileDigest::dispatch();\n    return 'ok';\n});",
            ],
            'static dispatch, imported job with arguments' => [
                'use Acme\\Jobs\\CompileDigest;',
                "Route::post('/digests/{id}', fn (\$id) => CompileDigest::dispatch(\$id));",
            ],
            'dispatchSync' => [
                'use Acme\\Jobs\\CompileDigest;',
                "Route::post('/digests', fn () => CompileDigest::dispatchSync());",
            ],
            'dispatchNow' => [
                'use Acme\\Jobs\\CompileDigest;',
                "Route::post('/digests', fn () => CompileDigest::dispatchNow());",
            ],
            'dispatchIf' => [
                'use Acme\\Jobs\\CompileDigest;',
                "Route::post('/digests', fn () => CompileDigest::dispatchIf(true));",
            ],
            'dispatchUnless' => [
                'use Acme\\Jobs\\CompileDigest;',
                "Route::post('/digests', fn () => CompileDigest::dispatchUnless(false));",
            ],
            'dispatchAfterResponse' => [
                'use Acme\\Jobs\\CompileDigest;',
                "Route::post('/digests', fn () => CompileDigest::dispatchAfterResponse());",
            ],
            'withChain then dispatch' => [
                'use Acme\\Jobs\\CompileDigest;
use Acme\\Jobs\\ArchiveDigest;',
                "Route::post('/digests', fn () => CompileDigest::withChain([new ArchiveDigest])->dispatch());",
            ],
            'dispatchable event' => [
                'use Acme\\Events\\DigestRequested;',
                "Route::post('/digests', fn () => DigestRequested::dispatch());",
            ],
            'Artisan::call via import' => [
                'use Illuminate\\Support\\Facades\\Artisan;',
                "Route::get('/flush', function () {\n    Artisan::call('cache:clear');\n    return 'flushed';\n});",
            ],
            'Artisan::queue via global alias' => [
                '',
                "Route::get('/flush', fn () => Artisan::queue('acme:rebuild'));",
            ],
            'Artisan::call fully qualified' => [
                '',
                "Route::get('/flush', fn () => \\Illuminate\\Support\\Facades\\Artisan::call('cache:clear'));",
            ],
            'Artisan facade under an alias' => [
                'use Illuminate\\Support\\Facades\\Artisan as Console;',
                "Route::get('/flush', fn () => Console::call('cache:clear'));",
            ],
            'notify on the request user' => [
                'use Illuminate\\Http\\Request;',
                "Route::post('/welcome', fn (Request \$r) => \$r->user()->notify(new \\Acme\\Notifications\\Greeting));",
            ],
            'notifyNow on a variable' => [
                '',
                "Route::post('/welcome/{member}', function (\$member) {\n    \$member->notifyNow(new \\Acme\\Notifications\\Greeting);\n    return 'sent';\n});",
            ],
            'nullsafe notify' => [
                '',
                "Route::post('/welcome', fn () => auth()->user()?->notify(new \\Acme\\Notifications\\Greeting));",
            ],
            'static dispatch in another letter case' => [
                'use Acme\\Jobs\\CompileDigest;',
                "Route::post('/digests', fn () => CompileDigest::Dispatch());",
            ],
            'notify in another letter case' => [
                '',
                "Route::post('/welcome/{member}', fn (\$member) => \$member->Notify(new \\Acme\\Notifications\\Greeting));",
            ],
        ];
    }

    /**
     * @dataProvider sideEffectFreeRouteBodyProvider
     */
    #[DataProvider('sideEffectFreeRouteBodyProvider')]
    public function test_does_not_flag_look_alikes_of_dispatch_artisan_and_notify(string $imports, string $route): void
    {
        $code = "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n{$imports}\n{$route}\n";

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function sideEffectFreeRouteBodyProvider(): array
    {
        return [
            'view' => ['', "Route::get('/', fn () => view('landing'));"],
            'redirect' => ['', "Route::get('/old', fn () => redirect('/new'));"],
            'Str::of' => [
                'use Illuminate\\Support\\Str;',
                "Route::get('/slug/{t}', fn (\$t) => Str::of(\$t)->slug());",
            ],
            'Carbon::now' => [
                'use Carbon\\Carbon;',
                "Route::get('/time', fn () => Carbon::now()->toIso8601String());",
            ],
            'Route::dispatch forwards a request, not a job' => [
                '',
                "Route::get('/proxy', fn () => Route::dispatch(request()));",
            ],
            'a dispatch-prefixed static method that is not Dispatchable' => [
                'use Acme\\Support\\Router;',
                "Route::get('/table', fn () => Router::dispatchesTo('home'));",
            ],
            'a static dispatchesEvents property read' => [
                'use Acme\\Models\\Invoice;',
                "Route::get('/events', fn () => array_keys(Invoice::\$dispatchesEvents));",
            ],
            'a notify-prefixed method' => [
                '',
                "Route::get('/prefs/{member}', fn (\$member) => \$member->notifyVia());",
            ],
            'a notify property read' => [
                '',
                "Route::get('/prefs/{member}', fn (\$member) => \$member->notify);",
            ],
            'a free notify() function' => [
                '',
                "Route::get('/ping', fn () => notify('ping'));",
            ],
            'a model named Artisan, simple find' => [
                'use App\\Models\\Artisan;',
                "Route::get('/makers/{id}', fn (\$id) => Artisan::find(\$id));",
            ],
            'a model named Artisan, two-call read' => [
                'use App\\Models\\Artisan;',
                "Route::get('/makers', fn () => Artisan::where('active', 1)->get());",
            ],
            'a non-facade class named Artisan' => [
                'use Acme\\Support\\Artisan;',
                "Route::get('/makers', fn () => Artisan::label());",
            ],
        ];
    }

    /**
     * @dataProvider writeExpressionProvider
     */
    #[DataProvider('writeExpressionProvider')]
    public function test_a_write_in_an_arrow_route_is_a_database_write(string $expression): void
    {
        $code = <<<PHP
<?php

use App\Models\Ticket;
use Illuminate\Support\Facades\Route;

Route::post('/tickets/{id}', fn (\$id) => {$expression});
PHP;

        $result = $this->analyzeRouteCode($code);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('database write operations', $result);
        $issue = $result->getIssues()[0];
        $this->assertSame(Severity::High, $issue->severity);
        $this->assertSame('route-has-db-writes', $issue->metadata['code'] ?? null);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function writeExpressionProvider(): array
    {
        return [
            // Already detected: the plain and chained spellings of a write.
            'find()->delete()' => ['Ticket::find($id)->delete()'],
            'where()->update()' => ["Ticket::where('id', \$id)->update(['open' => false])"],
            'static destroy()' => ['Ticket::destroy($id)'],

            // A nullsafe call on the found model.
            'find()?->delete()' => ['Ticket::find($id)?->delete()'],
            'where()->first()?->delete()' => ["Ticket::where('id', \$id)->first()?->delete()"],
            'find()?->update()' => ["Ticket::find(\$id)?->update(['open' => false])"],
            'find()?->labels()->sync()' => ['Ticket::find($id)?->labels()->sync([1])'],

            // Pivot writes on a belongs-to-many relation.
            'sync()' => ['Ticket::findOrFail($id)->labels()->sync([1])'],
            'syncWithoutDetaching()' => ['Ticket::findOrFail($id)->labels()->syncWithoutDetaching([1])'],
            'syncWithPivotValues()' => ["Ticket::findOrFail(\$id)->labels()->syncWithPivotValues([1], ['pinned' => true])"],
            'attach()' => ['Ticket::findOrFail($id)->labels()->attach(1)'],
            'detach()' => ['Ticket::findOrFail($id)->labels()->detach(1)'],
            'toggle()' => ['Ticket::findOrFail($id)->labels()->toggle([1])'],
            'updateExistingPivot()' => ["Ticket::findOrFail(\$id)->labels()->updateExistingPivot(1, ['pinned' => true])"],

            // Has-many and builder writes.
            'createMany()' => ["Ticket::findOrFail(\$id)->replies()->createMany([['body' => 'a']])"],
            'saveMany()' => ['Ticket::findOrFail($id)->replies()->saveMany([])'],
            'relation forceCreate()' => ["Ticket::findOrFail(\$id)->replies()->forceCreate(['body' => 'a'])"],
            'static forceCreate()' => ["Ticket::forceCreate(['subject' => 'a'])"],

            // The quiet variants, which skip model events but still write.
            'static createQuietly()' => ["Ticket::createQuietly(['subject' => 'a'])"],
            'static forceCreateQuietly()' => ["Ticket::forceCreateQuietly(['subject' => 'a'])"],
            'createManyQuietly()' => ["Ticket::findOrFail(\$id)->replies()->createManyQuietly([['body' => 'a']])"],
            'saveManyQuietly()' => ['Ticket::findOrFail($id)->replies()->saveManyQuietly([])'],
            'saveQuietly()' => ['Ticket::findOrFail($id)->saveQuietly()'],
            'updateQuietly()' => ["Ticket::findOrFail(\$id)->updateQuietly(['open' => false])"],
            'deleteQuietly()' => ['Ticket::findOrFail($id)->deleteQuietly()'],
            'forceDeleteQuietly()' => ['Ticket::findOrFail($id)->forceDeleteQuietly()'],
            'restoreQuietly()' => ['Ticket::findOrFail($id)->restoreQuietly()'],
            'incrementQuietly()' => ["Ticket::findOrFail(\$id)->incrementQuietly('views')"],
            'decrementQuietly()' => ["Ticket::findOrFail(\$id)->decrementQuietly('views')"],
            'touchQuietly()' => ['Ticket::findOrFail($id)->touchQuietly()'],
            'pushQuietly()' => ['Ticket::findOrFail($id)->pushQuietly()'],

            // The *OrFail, *OrFirst and multi-column writes.
            'updateOrFail()' => ["Ticket::findOrFail(\$id)->updateOrFail(['open' => false])"],
            'saveOrFail()' => ['Ticket::findOrFail($id)->saveOrFail()'],
            'deleteOrFail()' => ['Ticket::findOrFail($id)->deleteOrFail()'],
            'static createOrFirst()' => ["Ticket::createOrFirst(['subject' => 'a'])"],
            'relation createOrFirst()' => ["Ticket::findOrFail(\$id)->replies()->createOrFirst(['body' => 'a'])"],
            'static forceDestroy()' => ['Ticket::forceDestroy($id)'],
            'incrementEach()' => ["Ticket::where('id', \$id)->incrementEach(['views' => 1])"],
            'decrementEach()' => ["Ticket::findOrFail(\$id)->decrementEach(['views' => 1])"],
            'insertUsing()' => ["Ticket::query()->insertUsing(['subject'], Ticket::query()->select('subject'))"],
            'insertOrIgnoreUsing()' => ["Ticket::query()->insertOrIgnoreUsing(['subject'], Ticket::query()->select('subject'))"],
            'insertOrIgnore()' => ["Ticket::query()->insertOrIgnore(['subject' => 'a'])"],
            'insertGetId()' => ["Ticket::query()->insertGetId(['subject' => 'a'])"],
            'upsert()' => ["Ticket::upsert([['subject' => 'a']], ['subject'])"],
        ];
    }

    /**
     * @dataProvider nonModelSameNamedCallProvider
     */
    #[DataProvider('nonModelSameNamedCallProvider')]
    public function test_a_same_named_call_off_a_non_model_is_not_a_write(string $expression): void
    {
        $code = <<<PHP
<?php

use App\Services\FeatureFlags;
use App\Support\Mirror;
use Illuminate\Support\Facades\Route;

Route::post('/flags', fn () => {$expression});
PHP;

        $this->assertPassed($this->analyzeRouteCode($code));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonModelSameNamedCallProvider(): array
    {
        return [
            'service toggle()' => ["FeatureFlags::current()->toggle('beta')"],
            'service sync()' => ['Mirror::remote()->sync()'],
            'service attach()' => ["Mirror::remote()->attach('origin')"],
            'nullsafe service delete()' => ["FeatureFlags::current()?->delete('beta')"],
        ];
    }

    /**
     * @dataProvider modelNamedLikeAUtilityProvider
     */
    #[DataProvider('modelNamedLikeAUtilityProvider')]
    public function test_a_write_on_a_model_named_like_a_utility_class_is_flagged(string $import, string $statement): void
    {
        $code = <<<PHP
<?php

use {$import};
use Illuminate\Support\Facades\Route;

Route::delete('/assets/{id}', function (\$id) {
    {$statement}
    return 'ok';
});
PHP;

        $result = $this->analyzeRouteCode($code);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('database write operations', $result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function modelNamedLikeAUtilityProvider(): array
    {
        return [
            'App\Models\File' => ['App\Models\File', "File::where('id', \$id)->delete();"],
            'App\Models\Storage' => ['App\Models\Storage', 'Storage::destroy($id);'],
            'domain Models\Cache' => ['Domain\Media\Models\Cache', "Cache::whereKey(\$id)->update(['stale' => true]);"],
            'App\Models\Config find()?->delete()' => ['App\Models\Config', 'Config::find($id)?->delete();'],
            'App\Models\Config static create()' => ['App\Models\Config', "Config::create(['key' => \$id]);"],
        ];
    }

    /**
     * @dataProvider utilityFacadeCallProvider
     */
    #[DataProvider('utilityFacadeCallProvider')]
    public function test_a_utility_facade_call_is_not_a_write(string $imports, string $statement): void
    {
        $code = <<<PHP
<?php

{$imports}
use Illuminate\Support\Facades\Route;

Route::delete('/assets/{name}', function (\$name) {
    {$statement}
    return 'ok';
});
PHP;

        $this->assertPassed($this->analyzeRouteCode($code));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function utilityFacadeCallProvider(): array
    {
        return [
            'Storage facade delete()' => ['use Illuminate\Support\Facades\Storage;', 'Storage::delete($name);'],
            'Cache facade forget()' => ['use Illuminate\Support\Facades\Cache;', 'Cache::forget($name);'],
            'File facade delete()' => ['use Illuminate\Support\Facades\File;', 'File::delete($name);'],
            'unimported File delete()' => ['', 'File::delete($name);'],
        ];
    }

    /**
     * @dataProvider writeRootedAtTheUserOrAPropertyProvider
     */
    #[DataProvider('writeRootedAtTheUserOrAPropertyProvider')]
    public function test_a_write_rooted_at_the_signed_in_user_or_through_a_property_is_a_database_write(string $import, string $closure): void
    {
        $result = $this->analyzeRouteCode($this->routeFile($import, $closure));

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('database write operations', $result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function writeRootedAtTheUserOrAPropertyProvider(): array
    {
        return [
            'auth()->user()->update()' => ['App\Models\Ticket', "fn () => auth()->user()->update(['name' => 'a'])"],
            "auth('staff')->user()->delete()" => ['App\Models\Ticket', "fn () => auth('staff')->user()->delete()"],
            'request()->user()->relation()->create()' => ['App\Models\Ticket', "fn () => request()->user()->tickets()->create(['subject' => 'a'])"],
            '$request->user()->delete()' => ['Illuminate\Http\Request', 'fn (Request $request) => $request->user()->delete()'],
            'Auth::user()->update()' => ['Illuminate\Support\Facades\Auth', "fn () => Auth::user()->update(['name' => 'a'])"],
            'find()->property->update()' => ['App\Models\Ticket', "fn (\$id) => Ticket::find(\$id)->assignee->update(['name' => 'a'])"],
            'find()?->property?->delete()' => ['App\Models\Ticket', 'fn ($id) => Ticket::find($id)?->assignee?->delete()'],
            'get()->each->delete()' => ['App\Models\Ticket', "function (\$id) { Ticket::where('board_id', \$id)->get()->each->delete(); return 1; }"],
            'auth()->user()->push()' => ['App\Models\Ticket', 'fn () => auth()->user()->push()'],
        ];
    }

    /**
     * @dataProvider readKeepsItsVerdictProvider
     */
    #[DataProvider('readKeepsItsVerdictProvider')]
    public function test_a_read_or_a_non_model_call_keeps_passing(string $import, string $closure): void
    {
        $this->assertPassed($this->analyzeRouteCode($this->routeFile($import, $closure)));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function readKeepsItsVerdictProvider(): array
    {
        return [
            // Reads on a model whose short name matches a utility class.
            'App\Models\Config latest()->get()' => ['App\Models\Config', 'fn () => Config::latest()->get()'],
            'App\Models\Response paginate()' => ['App\Models\Response', 'fn () => Response::paginate(10)'],
            'App\Models\Config firstWhere()' => ['App\Models\Config', "fn (\$key) => Config::firstWhere('key', \$key)"],

            // Reads on a model whose short name matches a business facade.
            'App\Models\Event find()' => ['App\Models\Event', 'fn ($id) => Event::find($id)'],
            'App\Models\Notification find()' => ['App\Models\Notification', 'fn ($id) => Notification::find($id)'],

            // Reads through the signed-in user or a property, and a write off an arbitrary variable.
            'request()->user() relation read' => ['App\Models\Ticket', 'fn () => request()->user()->tickets()->latest()->get()'],
            'find()->property->relation()->get()' => ['App\Models\Ticket', 'fn ($id) => Ticket::find($id)->assignee->tickets()->get()'],
            'arbitrary variable update()' => ['App\Models\Ticket', "fn (\$ticket) => \$ticket->update(['open' => false])"],

            // Reads on a model that is one only by its namespace, not by its utility short name.
            'App\Models\Config where()->orderBy()->get()' => ['App\Models\Config', "fn () => Config::where('group', 'mail')->orderBy('key')->get()"],
            'App\Models\Config where()' => ['App\Models\Config', "fn () => Config::where('a', 1)"],
            'domain Models\Cache query()->latest()->paginate()' => ['Domain\Media\Models\Cache', 'fn () => Cache::query()->latest()->paginate()'],

            // Reads through a nullsafe link.
            'find()?->toJson()' => ['App\Models\Ticket', 'fn ($id) => Ticket::find($id)?->toJson()'],
            'where()->first()?->relation()->get()' => ['App\Models\Ticket', "fn (\$slug) => Ticket::where('slug', \$slug)->first()?->replies()->get()"],
            'variable ?->whereIn()' => ['App\Models\Ticket', "fn (\$query) => \$query?->whereIn('id', [1])"],

            // An in-memory push() on a loaded relation, which is a Collection.
            'find()->property->push()' => ['App\Models\Ticket', 'fn ($id) => Ticket::findOrFail($id)->labels->push(new Label)->toJson()'],
            'auth()->user()->property->push()' => ['App\Models\Ticket', 'fn ($role) => auth()->user()->roles->push($role)'],
        ];
    }

    /**
     * @dataProvider belongsToKeyChangeProvider
     */
    #[DataProvider('belongsToKeyChangeProvider')]
    public function test_associate_and_dissociate_are_not_database_writes(string $closure): void
    {
        // BelongsTo::associate() and dissociate() only set the key and the relation in memory;
        // nothing is saved until save() is called.
        $result = $this->analyzeRouteCode($this->routeFile('App\Models\Ticket', $closure));

        foreach ($result->getIssues() as $issue) {
            $this->assertStringNotContainsString('database write operations', $issue->message);
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function belongsToKeyChangeProvider(): array
    {
        return [
            'associate()->toArray()' => ['fn ($id) => Ticket::findOrFail($id)->assignee()->associate(request()->user())->toArray()'],
            'dissociate()' => ['fn () => Ticket::find(1)->assignee()->dissociate()'],
        ];
    }

    public function test_collection_push_after_a_terminal_read_on_the_signed_in_user_is_not_a_write(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

Route::get('/roles', function () {
    return Auth::user()->getRoleNames()->push('member');
});
PHP;

        $this->assertPassed($this->analyzeRouteCode($code));
    }

    public function test_collection_push_after_a_nullsafe_relation_read_is_not_a_write(): void
    {
        $code = <<<'PHP'
<?php

use App\Models\Ticket;
use Illuminate\Support\Facades\Route;

Route::get('/labels', function () {
    return Ticket::find(1)?->labels()->pluck('name')->push('featured');
});
PHP;

        $this->assertPassed($this->analyzeRouteCode($code));
    }

    public function test_collection_push_after_a_pluck_is_a_complex_query_not_a_write(): void
    {
        $result = $this->analyzeRouteCode($this->routeFile('App\Models\Ticket', "fn () => Ticket::where('a', 1)->pluck('name')->push('x')"));

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame('Route closure contains complex database queries', $issue->message);
        $this->assertSame(Severity::Medium, $issue->severity);
        $this->assertSame('route-has-complex-queries', $issue->metadata['code'] ?? null);
    }

    public function test_collection_push_on_the_signed_in_users_relation_keeps_the_business_logic_verdict(): void
    {
        $result = $this->analyzeRouteCode($this->routeFile('App\Models\Ticket', 'fn () => auth()->user()->tickets()->get()->push(1)'));

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame('Route closure contains complex business logic', $issue->message);
        $this->assertSame(Severity::High, $issue->severity);
        $this->assertSame('route-has-business-logic', $issue->metadata['code'] ?? null);
    }

    /**
     * @dataProvider firstClassCallableOfAWriteProvider
     */
    #[DataProvider('firstClassCallableOfAWriteProvider')]
    public function test_a_first_class_callable_of_a_write_method_is_not_a_write(string $import, string $closure, ?string $expectedMessage): void
    {
        // delete(...) builds a Closure; nothing is written until it is called.
        $result = $this->analyzeRouteCode($this->routeFile($import, $closure));

        if ($expectedMessage === null) {
            $this->assertPassed($result);

            return;
        }

        $this->assertIssueCount(1, $result);
        $this->assertSame($expectedMessage, $result->getIssues()[0]->message);
    }

    /**
     * @return array<string, array{string, string, string|null}>
     */
    public static function firstClassCallableOfAWriteProvider(): array
    {
        return [
            'Auth::user()->delete(...)' => ['Illuminate\Support\Facades\Auth', 'fn () => Auth::user()->delete(...)', null],
            'find()?->delete(...)' => ['App\Models\Ticket', 'fn () => Ticket::find(1)?->delete(...)', null],
            'find()->property->update(...)' => ['App\Models\Ticket', 'fn () => Ticket::find(1)->assignee->update(...)', null],
            // A two-call chain that does not end in a terminal read keeps its read grade.
            'find()->delete(...)' => ['App\Models\Ticket', 'fn () => Ticket::find(1)->delete(...)', 'Route closure contains complex database queries'],
        ];
    }

    /**
     * @dataProvider argumentlessPushProvider
     */
    #[DataProvider('argumentlessPushProvider')]
    public function test_an_argumentless_push_is_a_database_write(string $import, string $closure): void
    {
        $result = $this->analyzeRouteCode($this->routeFile($import, $closure));

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains database write operations', $result->getIssues()[0]->message);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function argumentlessPushProvider(): array
    {
        return [
            'Auth::user()->push()' => ['Illuminate\Support\Facades\Auth', 'fn () => Auth::user()->push()'],
            'find()->push()' => ['App\Models\Ticket', 'fn () => Ticket::find(1)->push()'],
            // Master passes this: its chain walk stopped at the property. Model::push() saves.
            'find()->property->push()' => ['App\Models\Ticket', 'fn () => Ticket::find(1)->assignee->push()'],
        ];
    }

    /**
     * @dataProvider strictModeReadOnAUtilityNamedModelProvider
     */
    #[DataProvider('strictModeReadOnAUtilityNamedModelProvider')]
    public function test_strict_mode_keeps_passing_a_read_on_a_utility_named_model(string $import, string $closure): void
    {
        $this->assertPassed($this->analyzeRouteCode($this->routeFile($import, $closure), allowSimpleReads: false));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function strictModeReadOnAUtilityNamedModelProvider(): array
    {
        return [
            'App\Models\File find()' => ['App\Models\File', 'fn ($id) => File::find($id)'],
            'App\Models\Config latest()->get()' => ['App\Models\Config', 'fn () => Config::latest()->get()'],
        ];
    }

    public function test_strict_mode_still_flags_a_read_on_an_ordinary_model(): void
    {
        $result = $this->analyzeRouteCode($this->routeFile('App\Models\Ticket', 'fn ($id) => Ticket::find($id)'), allowSimpleReads: false);

        $this->assertWarning($result);
        $this->assertHasIssueContaining('database queries (strict mode)', $result);
        $this->assertSame(Severity::Low, $result->getIssues()[0]->severity);
    }

    /**
     * @dataProvider businessFacadeProvider
     */
    #[DataProvider('businessFacadeProvider')]
    public function test_a_business_facade_call_stays_business_logic(string $imports): void
    {
        $code = <<<PHP
<?php

{$imports}
use Illuminate\Support\Facades\Route;

Route::post('/tickets/{id}', fn (\$id) => Event::dispatch('ticket.closed'));
PHP;

        $result = $this->analyzeRouteCode($code);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function businessFacadeProvider(): array
    {
        return [
            'imported Event facade' => ['use Illuminate\Support\Facades\Event;'],
            'unimported Event' => [''],
        ];
    }

    /**
     * attach() with a file-shaped first argument is Mailable::attach() or MailMessage::attach(),
     * not a pivot write, so the chain keeps the grade it has without the attach() call.
     *
     * @dataProvider fileShapedAttachProvider
     */
    #[DataProvider('fileShapedAttachProvider')]
    public function test_attach_with_a_file_shaped_argument_is_not_a_write(string $imports, string $closure): void
    {
        $result = $this->analyzeRouteCode($this->attachRouteFile($imports, $closure));

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame(Severity::Medium, $issue->severity);
        $this->assertSame('Route closure contains complex database queries', $issue->message);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function fileShapedAttachProvider(): array
    {
        $chain = 'fn ($id) => Receipt::findOrFail($id)->toMailable()->attach';

        return [
            'string literal' => ['', $chain."('/srv/files/receipt.pdf')"],
            'interpolated string' => ['', $chain.'("/srv/files/{$id}.pdf")'],
            'string concatenation' => ['', $chain."('/srv/files/'.\$id.'.pdf')"],
            'storage_path()' => ['', $chain."(storage_path('receipts/r.pdf'))"],
            'public_path()' => ['', $chain."(public_path('r.pdf'))"],
            'base_path()' => ['', $chain."(base_path('r.pdf'))"],
            'resource_path()' => ['', $chain."(resource_path('r.pdf'))"],
            'app_path()' => ['', $chain."(app_path('r.pdf'))"],
            'database_path()' => ['', $chain."(database_path('r.pdf'))"],
            'lang_path()' => ['', $chain."(lang_path('r.pdf'))"],
            'config_path()' => ['', $chain."(config_path('r.pdf'))"],
            'fully qualified \storage_path()' => ['', $chain."(\\storage_path('r.pdf'))"],
            'mixed-case Storage_Path()' => ['', $chain."(Storage_Path('r.pdf'))"],
            'fully qualified Attachment::fromPath()' => ['', $chain."(\\Illuminate\\Mail\\Mailables\\Attachment::fromPath('/r.pdf'))"],
            'imported Attachment::fromStorage()' => ['use Illuminate\Mail\Mailables\Attachment;', $chain."(Attachment::fromStorage('r.pdf'))"],
            'aliased Attachment' => ['use Illuminate\Mail\Mailables\Attachment as MailFile;', $chain."(MailFile::fromPath('/r.pdf'))"],
            'new Attachment' => ['use Illuminate\Mail\Mailables\Attachment;', $chain.'(new Attachment(fn ($p) => $p))'],
            'named file argument' => ['', $chain.'(file: $id)'],
            'named file argument after named options' => ['', $chain."(options: ['as' => 'r.pdf'], file: '/srv/r.pdf')"],
            'positional file with named options' => ['', $chain."('/srv/r.pdf', options: ['as' => 'r.pdf'])"],
            'file name with an extension' => ['', $chain."('r.pdf')"],
            'nowdoc path' => ['', $chain."(<<<'FILE'\n    /srv/r.pdf\n    FILE)"],
            '__DIR__ concatenation' => ['', $chain."(__DIR__.'/r.pdf')"],
            'path helper concatenation' => ['', $chain."(storage_path('a').'/b.pdf')"],
            'ternary of two paths' => ['', $chain."(\$id ? '/srv/a.pdf' : '/srv/b.pdf')"],
            'Attachment with a fluent tail' => ['use Illuminate\Mail\Mailables\Attachment;', $chain."(Attachment::fromPath('/r.pdf')->as('r.pdf')->withMime('application/pdf'))"],
            'new Attachment with a fluent tail' => ['use Illuminate\Mail\Mailables\Attachment;', $chain."((new Attachment(fn (\$p) => \$p))->as('r.pdf'))"],
            'base Illuminate\Mail\Attachment' => ['use Illuminate\Mail\Attachment;', $chain."(Attachment::fromPath('/r.pdf'))"],
            'Storage::path()' => ['use Illuminate\Support\Facades\Storage;', $chain."(Storage::path('r.pdf'))"],
            'Storage::disk()->path()' => ['use Illuminate\Support\Facades\Storage;', $chain."(Storage::disk('s3')->path('r.pdf'))"],
            'unimported Storage alias' => ['', $chain."(Storage::path('r.pdf'))"],
            'request()->file()' => ['', $chain."(request()->file('doc'))"],
            'typed request variable file()' => ['use Illuminate\Http\Request;', "fn (\$id, Request \$req) => Receipt::findOrFail(\$id)->toMailable()->attach(\$req->file('doc'))"],
            'absolute path without an extension' => ['', $chain."('/srv/files/receipt')"],
            'upper-case extension' => ['', $chain."('R.PDF')"],
            'interpolated name with an extension' => ['', $chain.'("{$id}.csv")'],
            'concatenation onto an absolute directory' => ['', $chain."('/srv/'.\$id)"],
        ];
    }

    /**
     * attach() that is not positively file-shaped keeps its pivot write verdict.
     *
     * @dataProvider nonFileShapedAttachProvider
     */
    #[DataProvider('nonFileShapedAttachProvider')]
    public function test_attach_without_a_file_shaped_argument_stays_a_write(string $imports, string $closure): void
    {
        $result = $this->analyzeRouteCode($this->attachRouteFile($imports, $closure));

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame(Severity::High, $issue->severity);
        $this->assertStringStartsWith('Route closure contains database write operations', $issue->message);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function nonFileShapedAttachProvider(): array
    {
        $pivot = 'fn ($id, $labelId) => Receipt::findOrFail($id)->labels()->attach';
        $mail = 'fn ($id, $path) => Receipt::findOrFail($id)->toMailable()->attach';

        return [
            'pivot int' => ['', $pivot.'(7)'],
            'pivot array' => ['', $pivot.'([7, 8])'],
            'pivot variable' => ['', $pivot.'($labelId)'],
            'pivot model variable' => ['', 'fn ($id, Label $label) => Receipt::findOrFail($id)->labels()->attach($label)'],
            'pivot model property' => ['', 'fn ($id, Label $label) => Receipt::findOrFail($id)->labels()->attach($label->id)'],
            'pivot named id argument' => ['', $pivot.'(id: 7)'],
            'mail path variable' => ['', $mail.'($path)'],
            'spread argument' => ['', $mail.'(...$path)'],
            'unrecognised helper' => ['', $mail."(report_path('r.pdf'))"],
            'helper imported from another namespace' => ['use function Acme\Files\storage_path;', $mail."(storage_path('r.pdf'))"],
            'qualified helper' => ['', $mail."(Acme\\storage_path('r.pdf'))"],
            'another Attachment class' => ['use App\Mail\Attachment;', $mail."(Attachment::fromPath('/r.pdf'))"],
            'unimported Attachment' => ['', $mail."(Attachment::fromPath('/r.pdf'))"],
            'pivot UUID key' => ['', $pivot."('3c1a9e52-6b0d-4f7e-8a21-5d4c3b2a1f09')"],
            'pivot ULID key' => ['', $pivot."('01HZX4K7M2N8P5Q3R6S9T0V1W2')"],
            'pivot slug key' => ['', $pivot."('release-notes')"],
            'pivot interpolated key' => ['', $pivot.'("{$labelId}")'],
            'pivot concatenated key' => ['', $pivot."('label-'.\$labelId)"],
            'pivot key with attributes' => ['', $pivot."('reviewer', ['expires_at' => now()])"],
            'signed-in user pivot key' => ['', "fn () => auth()->user()->labels()->attach('reviewer')"],
            'named id argument after named attributes' => ['', $pivot.'(attributes: [], id: 7)'],
            'ternary with a non-path branch' => ['', $pivot."(\$id ? '/srv/a.pdf' : \$labelId)"],
            'another Storage class' => ['use App\Support\Storage;', $mail."(Storage::path('r.pdf'))"],
            'file() on another receiver' => ['', $mail."(Receipt::file('doc'))"],
            'tag name vue.js' => ['', 'fn ($id) => Receipt::findOrFail($id)->tags()->attach(\'vue.js\')'],
            'tag name with pivot attributes' => ['', "fn (\$id) => Receipt::findOrFail(\$id)->tags()->attach('asp.net', ['pinned' => true])"],
            'domain key' => ['', "fn (\$id) => Receipt::findOrFail(\$id)->domains()->attach('example.com')"],
            'email key' => ['', "fn (\$id) => Receipt::findOrFail(\$id)->reviewers()->attach('ops@example.com')"],
            'version key' => ['', "fn (\$id) => Receipt::findOrFail(\$id)->releases()->attach('v1.2')"],
            'IP address key' => ['', "fn (\$id) => Receipt::findOrFail(\$id)->hosts()->attach('10.0.0.1')"],
            'interpolated email key' => ['', 'fn ($id, $u) => Receipt::findOrFail($id)->reviewers()->attach("{$u}@example.com")'],
            'nullsafe dotted key' => ['', "fn (\$id) => Receipt::find(\$id)?->tags()->attach('vue.js')"],
            'relative slash key' => ['', $pivot."('team/backend')"],
            'interpolated relative slash key' => ['', $pivot.'("teams/{$id}")'],
            'concatenated dotted suffix' => ['', $pivot."(\$labelId.'.v2')"],
            'bare __DIR__' => ['', $mail.'(__DIR__)'],
            'file() on a model variable' => ['', 'fn ($id, Label $label) => Receipt::findOrFail($id)->labels()->attach($label->file())'],
            'file() on an untyped variable' => ['', $mail."(\$path->file('doc'))"],
            'file() on a variable typed as another Request' => ['use App\Http\Request;', "fn (\$id, Request \$req) => Receipt::findOrFail(\$id)->labels()->attach(\$req->file('doc'))"],
        ];
    }

    /**
     * attachData() and attachFromStorage() are not write methods, whatever their arguments.
     *
     * @dataProvider mailAttachVariantProvider
     */
    #[DataProvider('mailAttachVariantProvider')]
    public function test_mail_attach_variants_are_not_writes(string $closure): void
    {
        $result = $this->analyzeRouteCode($this->attachRouteFile('', $closure));

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame(Severity::Medium, $issue->severity);
        $this->assertSame('Route closure contains complex database queries', $issue->message);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function mailAttachVariantProvider(): array
    {
        return [
            'attachData()' => ["fn (\$id, \$bytes) => Receipt::findOrFail(\$id)->toMailable()->attachData(\$bytes, 'r.pdf')"],
            'attachFromStorage()' => ['fn ($id, $path) => Receipt::findOrFail($id)->toMailable()->attachFromStorage($path)'],
        ];
    }

    private function attachRouteFile(string $imports, string $closure): string
    {
        return <<<PHP
<?php

use App\Models\Receipt;
{$imports}
use Illuminate\Support\Facades\Route;

Route::get('/receipts/{id}/mail', {$closure});
PHP;
    }

    /**
     * @dataProvider writeMethodCaseProvider
     */
    #[DataProvider('writeMethodCaseProvider')]
    public function test_a_write_method_is_matched_case_insensitively(string $import, string $closure, string $lowercaseClosure, string $expectedMessage, Severity $expectedSeverity): void
    {
        $issues = $this->writeCaseIssueSummary($this->analyzeRouteCode($this->routeFile($import, $closure)));

        $this->assertSame([[$expectedMessage, $expectedSeverity]], $issues);
        $this->assertSame($this->writeCaseIssueSummary($this->analyzeRouteCode($this->routeFile($import, $lowercaseClosure))), $issues);
    }

    /**
     * @return array<string, array{string, string, string, string, Severity}>
     */
    public static function writeMethodCaseProvider(): array
    {
        $write = 'Route closure contains database write operations';

        return [
            'static Create()' => ['App\Models\Ledger', 'fn () => Ledger::Create(request()->all())', 'fn () => Ledger::create(request()->all())', 'Route closure contains database write operations, complex business logic', Severity::High],
            'chained Delete()' => ['App\Models\Ledger', 'fn ($id) => Ledger::findOrFail($id)->Delete()', 'fn ($id) => Ledger::findOrFail($id)->delete()', $write, Severity::High],
            'chained UPDATE()' => ['App\Models\Ledger', "fn (\$id) => Ledger::findOrFail(\$id)->UPDATE(['a' => 1])", "fn (\$id) => Ledger::findOrFail(\$id)->update(['a' => 1])", $write, Severity::High],
            'relation SYNC()' => ['App\Models\Ledger', 'fn ($id) => Ledger::findOrFail($id)->labels()->SYNC([1])', 'fn ($id) => Ledger::findOrFail($id)->labels()->sync([1])', $write, Severity::High],
            'relation Attach()' => ['App\Models\Ledger', 'fn ($id) => Ledger::findOrFail($id)->labels()->Attach(1)', 'fn ($id) => Ledger::findOrFail($id)->labels()->attach(1)', $write, Severity::High],
            'mail Attach() with a file' => ['App\Models\Ledger', "fn (\$id) => Ledger::findOrFail(\$id)->toMailable()->Attach('/tmp/ledger.pdf')", "fn (\$id) => Ledger::findOrFail(\$id)->toMailable()->attach('/tmp/ledger.pdf')", 'Route closure contains complex database queries', Severity::Medium],
            'nullsafe ?->Delete()' => ['App\Models\Ledger', 'fn ($id) => Ledger::find($id)?->Delete()', 'fn ($id) => Ledger::find($id)?->delete()', $write, Severity::High],
            'argumentless PUSH()' => ['App\Models\Ledger', 'fn () => Ledger::find(1)->PUSH()', 'fn () => Ledger::find(1)->push()', $write, Severity::High],
            'signed-in user Update()' => ['App\Models\Ledger', "fn () => auth()->user()->Update(['name' => 'a'])", "fn () => auth()->user()->update(['name' => 'a'])", $write, Severity::High],
            'collection Push() after pluck()' => ['App\Models\Ledger', "fn () => Ledger::where('a', 1)->pluck('a')->Push('x')", "fn () => Ledger::where('a', 1)->pluck('a')->push('x')", 'Route closure contains complex database queries', Severity::Medium],
            'static FirstOrCreate() under a read tail' => ['App\\Models\\Ledger', "fn () => Ledger::FirstOrCreate(['a' => 1])->labels()->get()", "fn () => Ledger::firstOrCreate(['a' => 1])->labels()->get()", 'Route closure contains database write operations, complex business logic', Severity::High],
            'lowercase delete() control' => ['App\Models\Ledger', 'fn ($id) => Ledger::findOrFail($id)->delete()', 'fn ($id) => Ledger::findOrFail($id)->delete()', $write, Severity::High],
        ];
    }

    /**
     * @return list<array{string, Severity}>
     */
    private function writeCaseIssueSummary(ResultInterface $result): array
    {
        return array_map(static fn ($issue): array => [$issue->message, $issue->severity], array_values($result->getIssues()));
    }

    private function routeFile(string $import, string $closure): string
    {
        return <<<PHP
<?php

use {$import};
use Illuminate\Support\Facades\Route;

Route::post('/tickets/{id}', {$closure});
PHP;
    }

    private function analyzeRouteCode(string $code, bool $allowSimpleReads = true): ResultInterface
    {
        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = new LogicInRoutesAnalyzer($this->parser, new Repository([
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
        ]));
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        return $analyzer->analyze();
    }

    public function test_passes_view_model_suffix_class_that_extends_nothing(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use App\ViewModels\ReportPageViewModel;
use Illuminate\Support\Facades\Route;

Route::get('/reports', fn () => view('reports.index', ReportPageViewModel::make()));
PHP,
            'app/ViewModels/ReportPageViewModel.php' => <<<'PHP'
<?php

namespace App\ViewModels;

class ReportPageViewModel
{
    public static function make(): array
    {
        return [];
    }
}
PHP,
        ]);

        $this->assertPassed($result);
    }

    public function test_passes_view_model_extending_vendor_base_class(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use App\ViewModels\ReportPageViewModel;
use Illuminate\Support\Facades\Route;

Route::get('/reports', fn () => view('reports.index', ReportPageViewModel::make()));
PHP,
            'app/ViewModels/ReportPageViewModel.php' => <<<'PHP'
<?php

namespace App\ViewModels;

use Acme\Presenters\ViewModel;

class ReportPageViewModel extends ViewModel
{
}
PHP,
        ]);

        $this->assertPassed($result);
    }

    public function test_passes_unimported_fully_qualified_view_model(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/reports', fn () => view('reports.index', \App\ViewModels\ReportPageViewModel::make()));
PHP,
            'app/ViewModels/ReportPageViewModel.php' => <<<'PHP'
<?php

namespace App\ViewModels;

class ReportPageViewModel
{
}
PHP,
        ]);

        $this->assertPassed($result);
    }

    public function test_flags_write_on_model_suffix_class_whose_declaration_is_absent(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use App\Entities\InvoiceModel;
use Illuminate\Support\Facades\Route;

Route::post('/invoices', fn () => InvoiceModel::create(request()->all()));
PHP,
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains database write operations, complex business logic', $result->getIssues()[0]->message);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    public function test_flags_write_on_unreadable_module_model_with_unchanged_message(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use Modules\Billing\InvoiceModel;
use Illuminate\Support\Facades\Route;

Route::post('/invoices', fn () => InvoiceModel::create(request()->all()));
PHP,
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains database write operations, complex business logic', $result->getIssues()[0]->message);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @dataProvider writeLaterInChainProvider
     */
    #[DataProvider('writeLaterInChainProvider')]
    public function test_flags_write_later_in_chain_on_unreadable_module_model_with_unchanged_message(string $closure): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<PHP
<?php

use Modules\\Billing\\InvoiceModel;
use Illuminate\\Support\\Facades\\Route;

Route::post('/invoices', {$closure});
PHP,
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains database write operations, complex business logic', $result->getIssues()[0]->message);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function writeLaterInChainProvider(): array
    {
        return [
            'factory then create' => ['fn () => InvoiceModel::factory()->create()'],
            'read then delete' => ['fn () => InvoiceModel::latest()->first()->delete()'],
            'trashed read then restore' => ['fn () => InvoiceModel::withTrashed()->find(1)->restore()'],
            'make then save' => ['fn () => InvoiceModel::make()->save()'],
        ];
    }

    /**
     * @dataProvider rawQueryBesideUnknownModelProvider
     */
    #[DataProvider('rawQueryBesideUnknownModelProvider')]
    public function test_flags_raw_query_beside_non_query_call_on_undeclared_model_suffix_class_with_unchanged_message(string $closure): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<PHP
<?php

use App\\Entities\\InvoiceModel;
use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

Route::post('/invoices', {$closure});
PHP,
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains raw database queries, complex business logic', $result->getIssues()[0]->message);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function rawQueryBesideUnknownModelProvider(): array
    {
        return [
            'query builder insert' => ['function () { $invoice = InvoiceModel::fromRequest(request()); DB::table(\'ledger\')->insert([]); return $invoice; }'],
            'raw insert' => ['function () { DB::insert(\'insert into ledger values (1)\'); return InvoiceModel::make(); }'],
            'raw statement' => ['function () { DB::statement(\'truncate ledger\'); return InvoiceModel::make(); }'],
            'transaction' => ['fn () => DB::transaction(function () { $invoice = InvoiceModel::make(request()->all()); $invoice->save(); })'],
        ];
    }

    public function test_does_not_grade_read_chain_on_declared_non_eloquent_model_suffix_class_as_business_logic(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use App\Support\ArchiveModel;
use Illuminate\Support\Facades\Route;

Route::get('/archive', fn () => ArchiveModel::with('entries')->where('year', 1)->orderBy('month')->get());
PHP,
            'app/Support/ArchiveModel.php' => $this->nonEloquentArchiveModel(),
        ]);

        $this->assertPassed($result);
    }

    public function test_grades_builder_chain_on_declared_non_eloquent_model_suffix_class_as_complex_query(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use App\Support\ArchiveModel;
use Illuminate\Support\Facades\Route;

Route::get('/archive', fn () => ArchiveModel::where('year', 1)->whereIn('month', [1, 2])->orderBy('day')->get());
PHP,
            'app/Support/ArchiveModel.php' => $this->nonEloquentArchiveModel(),
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains complex database queries', $result->getIssues()[0]->message);
        $this->assertSame(Severity::Medium, $result->getIssues()[0]->severity);
    }

    private function nonEloquentArchiveModel(): string
    {
        return <<<'PHP'
<?php

namespace App\Support;

class ArchiveModel
{
    public static function __callStatic(string $method, array $arguments): static
    {
        return new static;
    }
}
PHP;
    }

    public function test_grades_read_chain_on_unreadable_module_model_as_complex_query(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use Modules\Billing\InvoiceModel;
use Illuminate\Support\Facades\Route;

Route::get('/invoices', function () {
    return InvoiceModel::with('lines')->where('paid', 1)->orderBy('due_at')->get();
});
PHP,
            'modules/Billing/InvoiceModel.php' => <<<'PHP'
<?php

namespace Modules\Billing;

class InvoiceModel extends \Illuminate\Database\Eloquent\Model
{
}
PHP,
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains complex database queries', $result->getIssues()[0]->message);
        $this->assertSame(Severity::Medium, $result->getIssues()[0]->severity);
    }

    public function test_grades_read_chain_on_undeclared_model_suffix_class_as_complex_query(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use App\Entities\InvoiceModel;
use Illuminate\Support\Facades\Route;

Route::get('/invoices', function () {
    return InvoiceModel::with('lines')->where('paid', 1)->orderBy('due_at')->get();
});
PHP,
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains complex database queries', $result->getIssues()[0]->message);
        $this->assertSame(Severity::Medium, $result->getIssues()[0]->severity);
    }

    public function test_grades_builder_chain_on_undeclared_model_suffix_class_as_complex_query(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use App\Entities\InvoiceModel;
use Illuminate\Support\Facades\Route;

Route::get('/invoices', function () {
    return InvoiceModel::where('paid', 1)->whereIn('status', [1, 2])->orderBy('due_at')->join('lines', 'lines.invoice_id', '=', 'invoices.id')->get();
});
PHP,
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains complex database queries', $result->getIssues()[0]->message);
        $this->assertSame(Severity::Medium, $result->getIssues()[0]->severity);
    }

    public function test_passes_non_query_static_call_on_model_suffix_class_whose_declaration_is_absent(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use App\Data\InvoiceModel;
use Illuminate\Support\Facades\Route;

Route::post('/invoices', fn () => InvoiceModel::fromRequest(request()));
PHP,
        ]);

        $this->assertPassed($result);
    }

    public function test_flags_write_on_model_suffix_class_declared_as_eloquent_outside_models_namespace(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use App\Entities\InvoiceModel;
use Illuminate\Support\Facades\Route;

Route::post('/invoices', fn () => InvoiceModel::create(request()->all()));
PHP,
            'app/Entities/InvoiceModel.php' => <<<'PHP'
<?php

namespace App\Entities;

class InvoiceModel extends \Illuminate\Database\Eloquent\Model
{
}
PHP,
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operations', $result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    public function test_flags_write_on_models_namespace_class_without_declaration(): void
    {
        $result = $this->analyzeProject([
            'routes/web.php' => <<<'PHP'
<?php

use App\Models\Invoice;
use Illuminate\Support\Facades\Route;

Route::post('/invoices', fn () => Invoice::create(request()->all()));
PHP,
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database write operations', $result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @param  array<string, string>  $files
     */
    private function analyzeProject(array $files): ResultInterface
    {
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($this->createTempDirectory($files));
        $analyzer->setPaths(['routes']);

        return $analyzer->analyze();
    }

    /**
     * A query callback whose body only constrains the builder it is handed keeps the chain a read.
     *
     * @dataProvider queryCallbackReadProvider
     */
    #[DataProvider('queryCallbackReadProvider')]
    public function test_a_read_with_a_query_callback_is_not_business_logic(string $routes): void
    {
        $this->assertPassed($this->analyzeRouteFile($routes));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function queryCallbackReadProvider(): array
    {
        return [
            'whereHas arrow callback' => [
                "Route::get('/a', fn () => Article::whereHas('labels', fn (\$q) => \$q->where('slug', 'php'))->paginate(15));",
            ],
            'when arrow callback with the value' => [
                "Route::get('/a', fn () => Article::when(request('term'), fn (\$q, \$term) => \$q->where('title', 'like', \"%{\$term}%\"))->paginate(15));",
            ],
            'whereHas statement callback' => [
                "Route::get('/a', fn () => Article::whereHas('labels', function (\$q) { \$q->where('slug', 'php'); })->paginate(15));",
            ],
            'nested query callbacks' => [
                "Route::get('/a', fn () => Article::when(request('tag'), fn (\$q) => \$q->whereHas('labels', fn (\$l) => \$l->where('slug', 'php')))->paginate(15));",
            ],
        ];
    }

    /**
     * A callback that does more than constrain its builder keeps the business-logic grade.
     *
     * @dataProvider nonReadQueryCallbackProvider
     */
    #[DataProvider('nonReadQueryCallbackProvider')]
    public function test_a_query_callback_that_is_not_a_read_stays_high(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonReadQueryCallbackProvider(): array
    {
        return [
            'callback sends a notification' => [
                "Route::get('/a', fn () => Article::when(request('x'), fn (\$q) => \$q->first()->notify(new \\App\\Notifications\\Digest))->paginate(15));",
            ],
            'callback is rooted elsewhere' => [
                "Route::get('/a', fn () => Article::when(request('x'), fn (\$q) => Member::query()->where('a', 1))->paginate(15));",
            ],
            'callback without a parameter' => [
                "Route::get('/a', fn () => Article::when(request('x'), fn () => abort(404))->paginate(15));",
            ],
            'callback with two statements' => [
                "Route::get('/a', fn () => Article::when(request('x'), function (\$q) { \$q->where('a', 1); \$q->where('b', 2); })->paginate(15));",
            ],
        ];
    }

    /**
     * @dataProvider writeInAQueryCallbackProvider
     */
    #[DataProvider('writeInAQueryCallbackProvider')]
    public function test_a_write_inside_a_query_callback_is_a_database_write(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('database write operations', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function writeInAQueryCallbackProvider(): array
    {
        return [
            'delete in a when callback' => [
                "Route::get('/a', fn () => Article::when(request('purge'), fn (\$q) => \$q->delete())->paginate(15));",
            ],
            'delete in a whereHas callback' => [
                "Route::get('/a', fn () => Article::whereHas('labels', fn (\$q) => \$q->delete())->get());",
            ],
            'update in a statement callback' => [
                "Route::get('/a', fn () => Article::when(request('x'), function (\$q) { \$q->update(['seen' => true]); })->paginate(15));",
            ],
            'delete per chunk on a model static call' => [
                "Route::post('/a', fn () => Article::chunk(100, fn (\$rows) => \$rows->each->delete()));",
            ],
            'delete per row after a read' => [
                "Route::post('/a', fn () => Article::latest()->get()->each(fn (\$a) => \$a->delete()));",
            ],
            'delete in an eager-load constraint' => [
                "Route::get('/a', fn () => Article::with(['labels' => fn (\$q) => \$q->delete()])->paginate(15));",
            ],
        ];
    }

    /**
     * A model static call named like a collection callback method, with no callback argument,
     * is a local scope.
     *
     * @dataProvider scopeNamedLikeACallbackMethodProvider
     */
    #[DataProvider('scopeNamedLikeACallbackMethodProvider')]
    public function test_a_scope_named_like_a_callback_method_is_a_read(string $routes): void
    {
        $this->assertPassed($this->analyzeRouteFile($routes));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function scopeNamedLikeACallbackMethodProvider(): array
    {
        return [
            'filter scope' => ["Route::get('/a', fn () => Article::filter(request()->all())->paginate(15));"],
            'when scope' => ["Route::get('/a', fn () => Article::when(request('q'))->paginate(15));"],
            'sortBy scope' => ["Route::get('/a', fn () => Article::sortBy('title')->paginate(15));"],
        ];
    }

    public function test_a_write_after_a_scope_named_like_a_callback_method_is_a_database_write(): void
    {
        $result = $this->analyzeRouteFile("Route::post('/a', fn () => Article::filter(request()->all())->update(['seen' => true]));");

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('database write operations', $result);
    }

    public function test_a_callback_method_name_on_an_instance_call_stays_high(): void
    {
        $result = $this->analyzeRouteFile("Route::get('/a', fn () => Article::latest()->filter(request()->all())->paginate(15));");

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    /**
     * @dataProvider boundModelRelationReadProvider
     */
    #[DataProvider('boundModelRelationReadProvider')]
    public function test_a_relation_read_on_a_route_bound_model_is_not_business_logic(string $routes): void
    {
        $this->assertPassed($this->analyzeRouteFile("use App\\Models\\Team;\n".$routes));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function boundModelRelationReadProvider(): array
    {
        return [
            'arrow function' => ["Route::get('/t/{team}', fn (Team \$team) => \$team->members()->latest()->get());"],
            'closure' => ["Route::get('/t/{team}', function (Team \$team) { return \$team->members()->latest()->paginate(15); });"],
            'property hop' => ["Route::get('/t/{team}', fn (Team \$team) => \$team->owner->articles()->latest()->get());"],
        ];
    }

    public function test_a_relation_chain_on_an_untyped_parameter_stays_high(): void
    {
        $result = $this->analyzeRouteFile("Route::get('/t/{team}', fn (\$team) => \$team->members()->latest()->get());");

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    /**
     * @dataProvider boundModelWriteProvider
     */
    #[DataProvider('boundModelWriteProvider')]
    public function test_a_write_on_a_route_bound_model_is_a_database_write(string $routes): void
    {
        $result = $this->analyzeRouteFile("use App\\Models\\Team;\n".$routes);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains database write operations', $result->getIssues()[0]->message);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function boundModelWriteProvider(): array
    {
        return [
            'relation delete' => ["Route::delete('/t/{team}', fn (Team \$team) => \$team->members()->delete());"],
            'model delete' => ["Route::delete('/t/{team}', fn (Team \$team) => \$team->delete());"],
            'relation create' => ["Route::post('/t/{team}', fn (Team \$team) => \$team->members()->create(request()->all()));"],
            'nullable type' => ["Route::delete('/t/{team}', fn (?Team \$team) => \$team->members()->delete());"],
            'captured by a nested closure' => ["Route::delete('/t/{team}', function (Team \$team) { return tap(\$team, function () use (\$team) { \$team->members()->delete(); }); });"],
        ];
    }

    /**
     * @dataProvider guardedUserRelationReadProvider
     */
    #[DataProvider('guardedUserRelationReadProvider')]
    public function test_a_relation_read_on_a_guarded_signed_in_user_is_not_business_logic(string $routes): void
    {
        $this->assertPassed($this->analyzeRouteFile("use Illuminate\\Support\\Facades\\Auth;\n".$routes));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function guardedUserRelationReadProvider(): array
    {
        return [
            'auth helper guard' => ["Route::get('/me', fn () => auth()->guard('api')->user()->invoices()->latest()->get());"],
            'Auth facade guard' => ["Route::get('/me', fn () => Auth::guard('api')->user()->invoices()->latest()->get());"],
        ];
    }

    /**
     * @dataProvider guardedUserWriteProvider
     */
    #[DataProvider('guardedUserWriteProvider')]
    public function test_a_write_on_a_guarded_signed_in_user_is_a_database_write(string $routes): void
    {
        $result = $this->analyzeRouteFile("use Illuminate\\Support\\Facades\\Auth;\n".$routes);

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('database write operations', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function guardedUserWriteProvider(): array
    {
        return [
            'relation create on the auth helper guard' => ["Route::post('/me', fn () => auth()->guard('api')->user()->invoices()->create(['total' => 1]));"],
            'update on the Auth facade guard' => ["Route::post('/me', fn () => Auth::guard('api')->user()->update(['name' => 'x']));"],
            'delete on the auth helper guard' => ["Route::post('/me', fn () => auth()->guard('api')->user()->delete());"],
        ];
    }

    /**
     * A read-only closure with several statements grades exactly as the same read written as
     * a single return.
     *
     * @dataProvider multiStatementReadProvider
     */
    #[DataProvider('multiStatementReadProvider')]
    public function test_a_multi_statement_read_grades_like_the_single_return_read(string $multiStatement, string $singleReturn, string $expectedStatus): void
    {
        $multi = $this->analyzeRouteFile($multiStatement);
        $single = $this->analyzeRouteFile($singleReturn);

        $this->assertSame($expectedStatus, $multi->getStatus()->value);
        $this->assertSame($this->issueSummary($single), $this->issueSummary($multi));
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function multiStatementReadProvider(): array
    {
        return [
            'builder in a variable' => [
                "Route::get('/a', function () { \$query = Article::latest(); return \$query->paginate(15); });",
                "Route::get('/a', function () { return Article::latest()->paginate(15); });",
                'passed',
            ],
            'query() in a variable' => [
                "Route::get('/a', function () { \$query = Article::query(); return \$query->paginate(15); });",
                "Route::get('/a', function () { return Article::query()->paginate(15); });",
                'passed',
            ],
            'constraint after the variable' => [
                "Route::get('/a', function () { \$query = Article::latest(); return \$query->where('live', true)->get(); });",
                "Route::get('/a', function () { return Article::latest()->where('live', true)->get(); });",
                'warning',
            ],
            'session helper beside the read' => [
                "Route::get('/a', function () { session()->increment('views'); return Article::latest()->take(5)->get(); });",
                "Route::get('/a', function () { return Article::latest()->take(5)->get(); });",
                'warning',
            ],
            'result in a variable' => [
                "Route::get('/a', function () { \$articles = Article::latest()->take(5)->get(); return \$articles; });",
                "Route::get('/a', function () { return Article::latest()->take(5)->get(); });",
                'warning',
            ],
            'two variables' => [
                "Route::get('/a', function () { \$query = Article::latest(); \$query = \$query->where('live', true); return \$query->paginate(15); });",
                "Route::get('/a', function () { return Article::latest()->where('live', true)->paginate(15); });",
                'warning',
            ],
            'literal in a variable' => [
                "Route::get('/a', function () { \$perPage = 15; return Article::latest()->paginate(\$perPage); });",
                "Route::get('/a', function () { return Article::latest()->paginate(15); });",
                'passed',
            ],
            'request input in a variable' => [
                "Route::get('/a', function () { \$term = request('q'); return Article::latest()->where('title', \$term)->paginate(); });",
                "Route::get('/a', function () { return Article::latest()->where('title', request('q'))->paginate(); });",
                'warning',
            ],
            'request method and config in variables' => [
                "Route::get('/a', function (Request \$request) { \$sort = \$request->string('sort'); \$size = config('shelf.size', [10, 20]); return Article::orderBy(\$sort)->paginate(\$size); });",
                "Route::get('/a', function (Request \$request) { return Article::orderBy(\$request->string('sort'))->paginate(config('shelf.size', [10, 20])); });",
                'passed',
            ],
        ];
    }

    /**
     * @dataProvider multiStatementNonReadProvider
     */
    #[DataProvider('multiStatementNonReadProvider')]
    public function test_a_multi_statement_closure_with_a_non_read_statement_stays_high(string $routes, string $expected): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining($expected, $result);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function multiStatementNonReadProvider(): array
    {
        return [
            'write assigned then returned' => [
                "Route::post('/a', function () { \$a = Article::create(request()->all()); return \$a; });",
                'database write operations',
            ],
            'loop beside the read' => [
                "Route::get('/a', function () { \$q = Article::latest(); foreach (request('tags', []) as \$t) { \$q->whereHas('labels', fn (\$l) => \$l->where('slug', \$t)); } return \$q->paginate(15); });",
                'complex business logic',
            ],
            'if beside the read' => [
                "Route::get('/a', function () { \$q = Article::latest(); if (request('x')) { \$q->archive(); } return \$q->paginate(15); });",
                'complex business logic',
            ],
            'call on the variable beside the read' => [
                "Route::get('/a', function () { \$q = Article::latest(); \$q->archive(); return \$q->paginate(15); });",
                'complex business logic',
            ],
            'computed value beside the read' => [
                "Route::get('/a', function () { \$n = strtoupper(request('q')); return Article::latest()->where('a', \$n)->get(); });",
                'complex business logic',
            ],
        ];
    }

    public function test_a_cache_helper_read_chain_is_not_business_logic(): void
    {
        $this->assertPassed($this->analyzeRouteFile("Route::get('/s', fn () => cache()->store('redis')->tags(['site'])->get('config'));"));
    }

    /**
     * @dataProvider helperAndFacadeChainProvider
     */
    #[DataProvider('helperAndFacadeChainProvider')]
    public function test_a_cache_or_session_helper_chain_grades_like_its_facade(string $helper, string $facade): void
    {
        $routes = "use Illuminate\\Support\\Facades\\Session;\n";

        $this->assertSame(
            $this->issueSummary($this->analyzeRouteFile($routes."Route::post('/s', fn () => {$facade});")),
            $this->issueSummary($this->analyzeRouteFile($routes."Route::post('/s', fn () => {$helper});"))
        );
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function helperAndFacadeChainProvider(): array
    {
        return [
            'cache put' => ["cache()->store('redis')->tags(['site'])->put('config', 1)", "Cache::store('redis')->tags(['site'])->put('config', 1)"],
            'cache increment' => ["cache()->store('redis')->tags(['site'])->increment('hits')", "Cache::store('redis')->tags(['site'])->increment('hits')"],
            'session put' => ["session()->driver('array')->getHandler()->put('k', 1)", "Session::driver('array')->getHandler()->put('k', 1)"],
        ];
    }

    /**
     * @dataProvider collectionWhereInProvider
     */
    #[DataProvider('collectionWhereInProvider')]
    public function test_a_collection_where_in_is_not_a_database_query(string $routes): void
    {
        $this->assertPassed($this->analyzeRouteFile("use Illuminate\\Support\\Collection;\n".$routes));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function collectionWhereInProvider(): array
    {
        return [
            'collect whereIn' => ["Route::get('/k', fn () => collect(config('shelf.kinds'))->whereIn('kind', ['a', 'b']));"],
            'Collection::make whereNotIn' => ["Route::get('/k', fn () => Collection::make(config('shelf.kinds'))->whereNotIn('kind', ['a']));"],
            'new Collection whereBetween' => ["Route::get('/k', fn () => (new Collection(config('shelf.kinds')))->whereBetween('size', [1, 5]));"],
        ];
    }

    /**
     * @dataProvider nonCollectionWhereInProvider
     */
    #[DataProvider('nonCollectionWhereInProvider')]
    public function test_a_where_in_off_a_collection_keeps_its_grade(string $routes, string $expectedMessage, Severity $expectedSeverity): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertIssueCount(1, $result);
        $this->assertSame($expectedMessage, $result->getIssues()[0]->message);
        $this->assertSame($expectedSeverity, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string, string, Severity}>
     */
    public static function nonCollectionWhereInProvider(): array
    {
        return [
            'variable whereIn' => [
                "Route::get('/k', fn (\$query) => \$query->whereIn('id', [1])->get());",
                'Route closure contains complex database queries',
                Severity::Medium,
            ],
            'DB table whereIn' => [
                "Route::get('/k', fn () => DB::table('kinds')->whereIn('id', [1])->get());",
                'Route closure contains complex database queries',
                Severity::Medium,
            ],
        ];
    }

    public function test_a_write_in_a_collection_callback_stays_high(): void
    {
        $result = $this->analyzeRouteFile("Route::post('/k', fn () => collect(request('rows'))->each(fn (\$row) => Article::create(\$row)));");

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('database write operations', $result);
    }

    /**
     * @return list<array{string, string}>
     */
    private function issueSummary(ResultInterface $result): array
    {
        return array_values(array_map(
            static fn ($issue): array => [$issue->message, $issue->severity->value],
            $result->getIssues()
        ));
    }

    /**
     * An assigned chain that neither ends in a read terminal nor only builds a query that a
     * later statement continues is not a read.
     *
     * @dataProvider assignedNonReadChainProvider
     */
    #[DataProvider('assignedNonReadChainProvider')]
    public function test_an_assigned_chain_that_is_not_a_read_stays_high(string $routes): void
    {
        $result = $this->analyzeRouteFile("use App\\Models\\Post;\n".$routes);

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function assignedNonReadChainProvider(): array
    {
        return [
            'method on a relation property of the user' => [
                "Route::post('/n', function () { \$marked = auth()->user()->unreadNotifications->markAsRead(); return auth()->user()->notifications()->latest()->get(); });",
            ],
            'domain method on a user relation' => [
                "Route::post('/n', function (Request \$request) { \$s = \$request->user()->plan('default')->cancelNow(); return \$request->user()->plans()->get(); });",
            ],
            'domain method after a read on a bound model' => [
                "Route::post('/n', function (Post \$o) { \$r = \$o->comments()->first()->approve(); return \$o->comments()->latest()->get(); });",
            ],
            'domain method after a model read' => [
                "Route::post('/n', function () { \$r = Article::where('a', 1)->first()->publishNow(); return Article::latest()->get(); });",
            ],
            'builder never continued' => [
                "Route::post('/n', function () { \$q = Article::latest()->where('a', 1); return Article::latest()->get(); });",
            ],
        ];
    }

    /**
     * A builder method that takes a callback, called statically with a callable that is not a
     * closure, cannot be a local scope: the callable is opaque.
     *
     * @dataProvider opaqueBuilderCallbackProvider
     */
    #[DataProvider('opaqueBuilderCallbackProvider')]
    public function test_an_opaque_callable_passed_to_a_builder_callback_method_stays_high(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function opaqueBuilderCallbackProvider(): array
    {
        return [
            'closure held in a variable' => [
                "\$purge = function (\$query) { \$query->delete(); };\nRoute::get('/a', function () use (\$purge) { return Article::when(request()->boolean('purge'), \$purge)->get(); });",
            ],
            'invokable passed to when' => ["Route::get('/a', fn () => Article::when(request('a'), new \\App\\Filters\\Archived)->paginate());"],
            'array callable passed to unless' => ["Route::get('/a', fn () => Article::unless(request('a'), [\\App\\Filters::class, 'purge'])->paginate());"],
            'invokable passed to tap' => ["Route::get('/a', fn () => Article::tap(new \\App\\Purge)->get());"],
            'function name passed to each' => ["Route::get('/a', fn () => Article::each('x')->get());"],
        ];
    }

    /**
     * @dataProvider strictModeNewRootReadProvider
     */
    #[DataProvider('strictModeNewRootReadProvider')]
    public function test_strict_mode_flags_a_read_on_a_bound_model_or_guarded_user(string $routes): void
    {
        $result = $this->analyzeRouteFile("use App\\Models\\Team;\n".$routes, allowSimpleReads: false);

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains database queries (strict mode)', $result->getIssues()[0]->message);
        $this->assertSame(Severity::Low, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function strictModeNewRootReadProvider(): array
    {
        return [
            'bound model relation' => ["Route::get('/t/{team}', fn (Team \$team) => \$team->members()->latest()->get());"],
            'guarded user relation' => ["Route::get('/me', fn () => auth()->guard('api')->user()->invoices()->latest()->get());"],
        ];
    }

    /**
     * @dataProvider scopeInAQueryCallbackProvider
     */
    #[DataProvider('scopeInAQueryCallbackProvider')]
    public function test_a_scope_inside_a_query_callback_is_a_read(string $routes): void
    {
        $this->assertPassed($this->analyzeRouteFile($routes));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function scopeInAQueryCallbackProvider(): array
    {
        return [
            'local scope' => ["Route::get('/a', fn () => Article::whereHas('author', fn (\$q) => \$q->active())->paginate(15));"],
            'orderByRaw' => ["Route::get('/a', fn () => Article::whereHas('author', fn (\$q) => \$q->orderByRaw('x'))->paginate(15));"],
        ];
    }

    public function test_an_eager_load_constraint_is_not_business_logic(): void
    {
        $result = $this->analyzeRouteFile("Route::get('/a', fn () => Article::latest()->with(['labels' => fn (\$q) => \$q->latest()])->paginate());");

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains complex database queries', $result->getIssues()[0]->message);
    }

    public function test_a_relation_read_on_the_request_facade_user_is_not_business_logic(): void
    {
        $this->assertPassed($this->analyzeRouteCode($this->routeFile('Illuminate\Support\Facades\Request', 'fn () => Request::user()->orders()->latest()->get()')));
    }

    public function test_a_write_on_the_request_facade_user_is_a_database_write(): void
    {
        $result = $this->analyzeRouteCode($this->routeFile('Illuminate\Support\Facades\Request', "fn () => Request::user()->update(['name' => 'x'])"));

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains database write operations', $result->getIssues()[0]->message);
    }

    public function test_a_relation_read_on_a_bound_model_named_like_a_utility_class_is_not_business_logic(): void
    {
        $this->assertPassed($this->analyzeRouteFile("Route::get('/f/{file}', fn (File \$file) => \$file->versions()->latest()->get());"));
    }

    /**
     * A session() statement beside a read is allowed only with plain arguments: a side effect
     * passed to it is not laundered.
     *
     * @dataProvider sessionStatementWithASideEffectProvider
     */
    #[DataProvider('sessionStatementWithASideEffectProvider')]
    public function test_a_session_statement_with_a_side_effect_argument_stays_high(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function sessionStatementWithASideEffectProvider(): array
    {
        return [
            'storage call in put' => ["Route::get('/a', function () { session()->put('x', Storage::delete('a')); return Article::paginate(15); });"],
            'http call in flash' => ["Route::get('/a', function () { session()->flash('r', Http::post('https://api.example.test/charge', request()->all())->json()); return Article::latest()->get(); });"],
            'service call in the array form' => ["Route::get('/a', function () { session(['r' => (new \\App\\Services\\Billing)->chargeAll()]); return Article::latest()->get(); });"],
        ];
    }

    /**
     * A closure passed after the read terminal runs per row of the result, so it is never a
     * query callback.
     *
     * @dataProvider callbackAfterTheReadProvider
     */
    #[DataProvider('callbackAfterTheReadProvider')]
    public function test_a_callback_passed_after_the_read_terminal_stays_high(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('complex business logic', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function callbackAfterTheReadProvider(): array
    {
        return [
            'first with a callback on a bound model' => ["Route::post('/m/{member}', fn (Member \$member) => \$member->invoices()->get()->first(fn (\$i) => \$i->sendReminder()));"],
            'sum with a callback on the user' => ["Route::post('/m', fn () => auth()->user()->orders()->get()->sum(fn (\$o) => \$o->refund()));"],
            'sole with a callback on a model read' => ["Route::post('/m', fn () => Article::latest()->get()->sole(fn (\$o) => \$o->cancel()));"],
        ];
    }

    /**
     * @dataProvider mixedCaseWriteInACallbackProvider
     */
    #[DataProvider('mixedCaseWriteInACallbackProvider')]
    public function test_a_mixed_case_write_in_a_query_callback_stays_high(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function mixedCaseWriteInACallbackProvider(): array
    {
        return [
            'Delete' => ["Route::get('/a', fn () => Article::when(request('purge'), fn (\$q) => \$q->Delete())->paginate(15));"],
            'DELETE' => ["Route::get('/a', fn () => Article::when(request('purge'), fn (\$q) => \$q->DELETE())->paginate(15));"],
        ];
    }

    /**
     * A whereIn() is a collection filter only while every call from the collection root keeps
     * a collection.
     *
     * @dataProvider whereInAfterLeavingTheCollectionProvider
     */
    #[DataProvider('whereInAfterLeavingTheCollectionProvider')]
    public function test_a_where_in_after_leaving_the_collection_is_a_complex_query(string $routes): void
    {
        $this->assertHasIssueContaining('complex database queries', $this->analyzeRouteFile($routes));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function whereInAfterLeavingTheCollectionProvider(): array
    {
        return [
            'relation of the first item' => ["Route::get('/k', fn () => collect([Article::find(1)])->first()->comments()->whereIn('status', ['a'])->get());"],
            'toQuery' => ["Route::get('/k', fn () => \\Illuminate\\Database\\Eloquent\\Collection::make(request('ids'))->toQuery()->whereIn('id', [1])->get());"],
        ];
    }

    public function test_a_relation_read_on_the_signed_in_user_in_a_variable_is_not_business_logic(): void
    {
        $this->assertPassed($this->analyzeRouteFile("Route::get('/me', function () { \$user = auth()->user(); return \$user->orders()->latest()->get(); });"));
    }

    public function test_a_write_on_the_signed_in_user_in_a_variable_is_a_database_write(): void
    {
        $result = $this->analyzeRouteFile("Route::post('/me', function () { \$user = auth()->user(); \$user->orders()->delete(); return 'ok'; });");

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('database write operations', $result);
    }

    /**
     * @dataProvider readPassedToAViewProvider
     */
    #[DataProvider('readPassedToAViewProvider')]
    public function test_a_read_passed_to_a_view_is_not_business_logic(string $routes): void
    {
        $this->assertPassed($this->analyzeRouteFile($routes));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function readPassedToAViewProvider(): array
    {
        return [
            'read in the view data' => ["Route::get('/', fn () => view('welcome', ['articles' => Article::latest()->paginate(15)]));"],
            'read in a variable through compact' => ["Route::get('/', function () { \$a = Article::latest()->paginate(15); return view('a', compact('a')); });"],
        ];
    }

    public function test_a_write_passed_to_a_view_is_a_database_write(): void
    {
        $result = $this->analyzeRouteFile("Route::post('/', fn () => view('a', ['article' => Article::create(request()->all())]));");

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('database write operations', $result);
    }

    /**
     * @dataProvider collectionRootProvider
     */
    #[DataProvider('collectionRootProvider')]
    public function test_a_where_in_on_a_collection_from_a_read_or_a_variable_is_not_a_database_query(string $routes): void
    {
        $this->assertPassed($this->analyzeRouteFile("use Illuminate\\Support\\LazyCollection;\n".$routes));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function collectionRootProvider(): array
    {
        return [
            'model all' => ["Route::get('/k', fn () => Article::all()->whereIn('type', ['a', 'b']));"],
            'model read get' => ["Route::get('/k', fn () => Article::where('live', true)->get()->whereIn('type', ['a', 'b']));"],
            'collection in a variable' => ["Route::get('/k', function () { \$c = collect(config('shelf.kinds')); return \$c->whereIn('t', ['a']); });"],
            'lazy collection' => ["Route::get('/k', fn () => LazyCollection::make(config('shelf.kinds'))->whereIn('t', ['a']));"],
        ];
    }

    public function test_a_write_on_a_union_typed_bound_model_is_a_database_write(): void
    {
        $result = $this->analyzeRouteFile("Route::delete('/m/{m}', fn (Member|Article \$m) => \$m->delete());");

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame('Route closure contains database write operations', $result->getIssues()[0]->message);
    }

    public function test_a_relation_read_on_a_union_typed_bound_model_is_not_business_logic(): void
    {
        $this->assertPassed($this->analyzeRouteFile("Route::get('/m/{m}', fn (Member|Article \$m) => \$m->comments()->latest()->get());"));
    }

    /**
     * @dataProvider requestInputInAVariableProvider
     */
    #[DataProvider('requestInputInAVariableProvider')]
    public function test_request_input_in_a_variable_grades_like_the_inlined_read(string $multiStatement, string $singleReturn): void
    {
        $multi = $this->analyzeRouteFile($multiStatement);

        $this->assertSame($this->issueSummary($this->analyzeRouteFile($singleReturn)), $this->issueSummary($multi));
        $this->assertSame('warning', $multi->getStatus()->value);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function requestInputInAVariableProvider(): array
    {
        return [
            'form request parameter' => [
                "use App\\Http\\Requests\\StoreArticleRequest;\nRoute::get('/a', function (StoreArticleRequest \$request) { \$t = \$request->input('t'); return Article::latest()->where('t', \$t)->get(); });",
                "use App\\Http\\Requests\\StoreArticleRequest;\nRoute::get('/a', function (StoreArticleRequest \$request) { return Article::latest()->where('t', \$request->input('t'))->get(); });",
            ],
            'Request facade' => [
                "use Illuminate\\Support\\Facades\\Request as Input;\nRoute::get('/a', function () { \$t = Input::input('t'); return Article::latest()->where('t', \$t)->get(); });",
                "use Illuminate\\Support\\Facades\\Request as Input;\nRoute::get('/a', function () { return Article::latest()->where('t', Input::input('t'))->get(); });",
            ],
        ];
    }

    public function test_a_callback_parameter_named_like_a_collection_variable_is_not_a_collection(): void
    {
        $result = $this->analyzeRouteFile("Route::get('/a', function () {\n    \$query = Article::latest()->get();\n\n    return Article::whereHas('labels', fn (\$query) => \$query->whereIn('slug', ['php']))->first();\n});");
        $withoutTheVariable = $this->analyzeRouteFile("Route::get('/a', function () {\n    return Article::whereHas('labels', fn (\$query) => \$query->whereIn('slug', ['php']))->first();\n});");

        $this->assertNotSame('passed', $result->getStatus()->value);
        $this->assertHasIssueContaining('complex database queries', $result);
        $this->assertSame($this->issueSummary($withoutTheVariable), $this->issueSummary($result));
    }

    public function test_an_arrow_function_capturing_a_collection_variable_keeps_it_a_collection(): void
    {
        $this->assertPassed($this->analyzeRouteFile("Route::get('/a', function () { \$items = collect(config('shelf.kinds')); return collect([1])->map(fn (\$x) => \$items->whereIn('slug', [\$x])); });"));
    }

    public function test_a_write_per_row_of_a_model_collection_in_a_variable_is_a_database_write(): void
    {
        $result = $this->analyzeRouteFile("Route::post('/a', function () { \$articles = Article::where('status', 'draft')->get(); return \$articles->whereIn('type', ['news'])->each(fn (\$article) => \$article->update(['archived' => true])); });");

        $this->assertFailed($result);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('database write operations', $result);
    }

    /**
     * A collection whereIn() followed by a per-row callback or a higher-order proxy keeps its
     * complex-query grade: the callback is not analysed as a collection filter.
     *
     * @dataProvider perRowCallbackAfterACollectionWhereInProvider
     */
    #[DataProvider('perRowCallbackAfterACollectionWhereInProvider')]
    public function test_a_per_row_callback_after_a_collection_where_in_keeps_the_complex_query_grade(string $routes): void
    {
        $result = $this->analyzeRouteFile($routes);

        $this->assertNotSame('passed', $result->getStatus()->value);
        $this->assertHasIssueContaining('complex database queries', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function perRowCallbackAfterACollectionWhereInProvider(): array
    {
        return [
            'higher-order each proxy on a model collection' => ["Route::post('/a', fn () => Article::all()->whereIn('type', ['news'])->each->archive());"],
            'map callback on a collect() collection' => ["Route::post('/a', fn () => collect(request('ids'))->whereIn('type', ['news'])->map(fn (\$id) => \\App\\Services\\Billing::refund(\$id)));"],
        ];
    }

    /**
     * A collection method named like a callback method but called without a callable, such as
     * sortBy('name') or filter(), keeps the chain a collection.
     *
     * @dataProvider collectionMethodWithoutACallableProvider
     */
    #[DataProvider('collectionMethodWithoutACallableProvider')]
    public function test_a_collection_method_without_a_callable_keeps_the_collection(string $routes): void
    {
        $this->assertPassed($this->analyzeRouteFile($routes));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function collectionMethodWithoutACallableProvider(): array
    {
        return [
            'sortBy key then values' => ["Route::get('/k', fn () => Article::all()->sortBy('x')->values());"],
            'whereIn then sortBy key' => ["Route::get('/k', fn () => Article::all()->whereIn('type', [1])->sortBy('name'));"],
            'collect whereIn sortBy values' => ["Route::get('/k', fn () => collect(config('shelf.items'))->whereIn('type', ['book'])->sortBy('name')->values());"],
            'whereIn then argument-less filter' => ["Route::get('/k', fn () => Article::all()->whereIn('t', [1])->filter());"],
        ];
    }

    /**
     * A closure that is exactly a read on DB::table(), DB::query()->from() or
     * DB::connection()->table(), every call a listed builder read with written arguments, is
     * graded like the same chain on a model.
     *
     * @dataProvider queryBuilderReadProvider
     *
     * @param  list<array{string, Severity}>  $grade
     * @param  list<array{string, Severity}>  $strictGrade
     */
    #[DataProvider('queryBuilderReadProvider')]
    public function test_a_closure_that_is_only_a_query_builder_read_is_graded_like_the_model_read(string $routes, array $grade, array $strictGrade): void
    {
        $this->assertSame($grade, $this->dbRouteGrade($routes, allowSimpleReads: true));
        $this->assertSame($strictGrade, $this->dbRouteGrade($routes, allowSimpleReads: false));
    }

    /**
     * @return array<string, array{string, list<array{string, Severity}>, list<array{string, Severity}>}>
     */
    public static function queryBuilderReadProvider(): array
    {
        $strict = [['Route closure contains database queries (strict mode)', Severity::Low]];
        $complex = [['Route closure contains complex database queries', Severity::Medium]];

        return [
            'table()->latest()->get()' => ["Route::get('/articles', fn () => DB::table('articles')->latest()->get());", [], $strict],
            'closure returning the read' => ["Route::get('/articles', function () { return DB::table('articles')->latest()->get(); });", [], $strict],
            'query()->from()->latest()->get()' => ["Route::get('/articles', fn () => DB::query()->from('articles')->latest()->get());", [], $strict],
            'connection()->table()->latest()->get()' => ["Route::get('/articles', fn () => DB::connection('replica')->table('articles')->latest()->get());", [], $strict],
            'paginate()' => ["Route::get('/articles', fn () => DB::table('articles')->paginate(15));", [], $strict],
            'find() of a scalar route parameter' => ["Route::get('/articles/{id}', fn (int \$id) => DB::table('articles')->find(\$id));", [], $strict],
            'where() of request()->query() then first()' => ["Route::get('/articles', fn () => DB::table('articles')->where('slug', request()->query('slug'))->first());", [], $strict],
            'where() of request()->input() then first()' => ["Route::get('/articles', fn () => DB::table('articles')->where('views', '>', request()->input('min'))->first());", [], $strict],
            'a macro of another name on the facade' => ["DB::macro('ledgerTotals', fn () => 1);\nRoute::get('/articles', fn () => DB::table('articles')->latest()->get());", [], $strict],
            'fully qualified now()' => ["Route::get('/articles', fn () => DB::table('articles')->whereDate('published_at', \\now())->get());", [], $strict],
            'where() of request()->input() with a default' => ["Route::get('/articles', fn () => DB::table('articles')->where('status', request()->input('status', 'live'))->first());", [], $strict],
            'where() with an operator then get()' => ["Route::get('/articles', fn () => DB::table('articles')->where('views', '>=', 10)->get());", [], $strict],
            'whereDate() of now()' => ["Route::get('/articles', fn () => DB::table('articles')->whereDate('published_at', now())->get());", [], $strict],
            'whereIn() is complex' => ["Route::get('/articles', fn () => DB::table('articles')->whereIn('id', [1, 2])->get());", $complex, $complex],
            'three calls are complex' => ["Route::get('/articles', fn () => DB::table('articles')->where('status', 'live')->latest()->get());", $complex, $complex],
            'method names in another case' => ["Route::get('/articles', fn () => DB::table('articles')->LATEST()->get());", [], $strict],
            'facade imported under an alias' => ["use Illuminate\\Support\\Facades\\DB as Database;\nRoute::get('/articles', fn () => Database::table('articles')->latest()->get());", [], $strict],
            'facade written in another case' => ["Route::get('/articles', fn () => Db::TABLE('articles')->latest()->get());", [], $strict],
            'fully qualified facade' => ["Route::get('/articles', fn () => \\Illuminate\\Support\\Facades\\DB::table('articles')->latest()->get());", [], $strict],
        ];
    }

    /**
     * @dataProvider queryBuilderReadAndModelReadProvider
     */
    #[DataProvider('queryBuilderReadAndModelReadProvider')]
    public function test_a_query_builder_read_is_graded_like_the_same_read_on_a_model(string $chain): void
    {
        foreach ([true, false] as $allowSimpleReads) {
            $model = $this->dbRouteGrade("use App\\Models\\Article;\nRoute::get('/articles/{id}', fn (int \$id) => Article::{$chain});", $allowSimpleReads);
            $builder = $this->dbRouteGrade("Route::get('/articles/{id}', fn (int \$id) => DB::table('articles')->{$chain});", $allowSimpleReads);

            $this->assertSame($model, $builder);
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function queryBuilderReadAndModelReadProvider(): array
    {
        return [
            'get()' => ['get()'],
            'latest()->get()' => ['latest()->get()'],
            'where()->first()' => ["where('id', \$id)->first()"],
            'find()' => ['find($id)'],
            'paginate()' => ['paginate(15)'],
            'whereIn()->get()' => ["whereIn('id', [1, 2])->get()"],
            'whereNull()->whereNotNull()->orderBy()->get()' => ["whereNull('deleted_at')->whereNotNull('published_at')->orderBy('title')->get()"],
            'orderBy() alone' => ["orderBy('title')"],
            'where() alone' => ["where('id', \$id)"],
            'select()->limit()->pluck()' => ["select(['id', 'title'])->limit(5)->pluck('title')"],
            'count()' => ['count()'],
        ];
    }

    /**
     * Anything outside the closure shape, the listed reads or their written arguments keeps
     * master's grade exactly, including every input the reviews of #776 found a broader design
     * mishandling.
     *
     * @dataProvider queryBuilderClosureKeepsMastersGradeProvider
     */
    #[DataProvider('queryBuilderClosureKeepsMastersGradeProvider')]
    public function test_a_closure_outside_the_query_builder_read_shape_keeps_masters_grade(string $routes, string $message): void
    {
        foreach ([true, false] as $allowSimpleReads) {
            $this->assertSame([[$message, Severity::High]], $this->dbRouteGrade($routes, $allowSimpleReads));
        }
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function queryBuilderClosureKeepsMastersGradeProvider(): array
    {
        return [
            'control: a second statement before the return' => ['Route::get(\'/a\', function () { $status = request(\'status\'); return DB::table(\'articles\')->where(\'status\', $status)->get(); });', 'Route closure contains raw database queries'],
            'control: a wrapped return' => ['Route::get(\'/a\', fn () => response()->json(DB::table(\'articles\')->get()));', 'Route closure contains raw database queries'],
            'control: a callback argument' => ['Route::get(\'/a\', fn () => DB::table(\'articles\')->where(fn ($query) => $query->where(\'a\', 1))->get());', 'Route closure contains raw database queries'],
            'control: a table name from input' => ['Route::get(\'/a\', fn () => DB::table(request(\'t\'))->get());', 'Route closure contains raw database queries'],
            'control: a table name from a route parameter' => ['Route::get(\'/a/{t}\', fn ($t) => DB::table($t)->get());', 'Route closure contains raw database queries'],
            'control: a ?-> link' => ['Route::get(\'/a\', fn () => DB::table(\'articles\')->where(\'a\', 1)?->get());', 'Route closure contains raw database queries'],
            'control: groupBy()' => ['Route::get(\'/a\', fn () => DB::table(\'articles\')->groupBy(\'author_id\')->get());', 'Route closure contains raw database queries'],
            'control: join()' => ['Route::get(\'/a\', fn () => DB::table(\'articles\')->join(\'authors\', \'authors.id\', \'=\', \'articles.author_id\')->get());', 'Route closure contains raw database queries'],
            'control: when()' => ['Route::get(\'/a\', fn () => DB::table(\'articles\')->when(request(\'q\'), fn ($query) => $query->where(\'a\', 1))->get());', 'Route closure contains raw database queries'],
            'control: an operator from input' => ['Route::get(\'/a\', fn () => DB::table(\'articles\')->where(\'views\', request(\'op\'), 1)->get());', 'Route closure contains raw database queries'],
            'control: a boolean other than and or or' => ['Route::get(\'/a\', fn () => DB::table(\'articles\')->where(\'views\', \'=\', 1, \'xor\')->get());', 'Route closure contains raw database queries'],
            'control: a boolean from input' => ['Route::get(\'/a\', fn () => DB::table(\'articles\')->whereNull(\'deleted_at\', request(\'b\'))->get());', 'Route closure contains raw database queries'],
            'control: a typed object route parameter as a value' => ['Route::get(\'/a\', fn (\\App\\Services\\Clock $clock) => DB::table(\'articles\')->where(\'published_at\', $clock)->get());', 'Route closure contains raw database queries'],
            'control: an array first argument to where()' => ['Route::get(\'/a\', fn () => DB::table(\'articles\')->where([\'status\' => \'live\'])->get());', 'Route closure contains raw database queries'],
            'control: a named argument' => ['Route::get(\'/a\', fn () => DB::table(\'articles\')->where(column: \'status\', operator: \'live\')->get());', 'Route closure contains raw database queries'],
            'control: a request default that is not a literal' => ['Route::get(\'/a\', fn () => DB::table(\'articles\')->where(\'status\', request(\'status\', now()))->get());', 'Route closure contains raw database queries'],
            'control: a closure capturing a variable' => ['$status = \'live\';
Route::get(\'/a\', function () use ($status) { return DB::table(\'articles\')->where(\'status\', $status)->get(); });', 'Route closure contains raw database queries'],
            'control: a write' => ['Route::post(\'/a/{id}\', fn ($id) => DB::table(\'articles\')->where(\'id\', $id)->delete());', 'Route closure contains raw database queries'],
            'control: a bare root' => ['Route::get(\'/a\', fn () => DB::table(\'articles\'));', 'Route closure contains raw database queries'],
            'control: a column from input' => ['Route::get(\'/a\', fn () => DB::table(\'articles\')->orderBy(request(\'sort\'))->get());', 'Route closure contains raw database queries'],
            'round 1: write on a builder variable' => ['Route::post(\'/l/{id}\', function ($id) { $query = DB::table(\'ledgers\')->where(\'id\', $id); $query->update([\'closed\' => true]); return $query->first(); });', 'Route closure contains raw database queries'],
            'round 1: write continuing a builder variable' => ['Route::post(\'/l/{id}\', function ($id) { $query = DB::table(\'ledgers\')->where(\'id\', $id); return $query->where(\'open\', 1)->delete(); });', 'Route closure contains raw database queries'],
            'round 1: write on clone()' => ['Route::post(\'/l\', function () { $query = DB::table(\'ledgers\')->where(\'open\', 1); return $query->clone()->delete(); });', 'Route closure contains raw database queries'],
            'round 1: write on a clone expression' => ['Route::post(\'/l\', function () { $query = DB::table(\'ledgers\')->where(\'open\', 1); return (clone $query)->delete(); });', 'Route closure contains raw database queries'],
            'round 1: write on a captured builder' => ['Route::post(\'/l\', function () { $query = DB::table(\'ledgers\')->where(\'open\', 1); collect([1])->each(function () use ($query) { $query->delete(); }); return 1; });', 'Route closure contains raw database queries'],
            'round 1: write through tap()' => ['Route::post(\'/l/{id}\', fn ($id) => tap(DB::table(\'ledgers\')->where(\'id\', $id))->delete());', 'Route closure contains raw database queries'],
            'round 1: builder handed to a function' => ['function purgeLedgers($query) { return $query->delete(); }
Route::post(\'/l\', fn () => purgeLedgers(DB::table(\'ledgers\')->where(\'open\', 1)));', 'Route closure contains raw database queries'],
            'round 1: write on a latest() builder variable' => ['Route::post(\'/l\', function () { $query = DB::table(\'ledgers\')->latest(); return $query->update([\'closed\' => true]); });', 'Route closure contains raw database queries'],
            'round 1: insert on a query() builder variable' => ['Route::post(\'/l\', function () { $query = DB::query()->from(\'ledgers\'); return $query->insert([\'name\' => \'Draft\']); });', 'Route closure contains raw database queries'],
            'round 1: write on a reassigned builder variable' => ['Route::post(\'/l\', function () { $query = DB::table(\'ledgers\'); $query = $query->where(\'open\', 1); return $query->delete(); });', 'Route closure contains raw database queries'],
            'round 1: write in a when() callback' => ['Route::post(\'/l/{id}\', fn ($id) => DB::table(\'ledgers\')->when($id, fn ($query) => $query->where(\'id\', $id)->delete()));', 'Route closure contains raw database queries'],
            'round 1: macro in a where() callback' => ['\\Illuminate\\Database\\Query\\Builder::macro(\'openOnly\', function () { return $this->whereRaw(\'closed_at is null\'); });
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(fn ($query) => $query->openOnly())->get());', 'Route closure contains raw database queries'],
            'round 1: macro on a typed callback parameter' => ['\\Illuminate\\Database\\Query\\Builder::macro(\'openOnly\', function () { return $this->whereRaw(\'closed_at is null\'); });
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(fn (\\Illuminate\\Database\\Query\\Builder $query) => $query->openOnly())->get());', 'Route closure contains raw database queries'],
            'round 1: macro on a builder variable' => ['\\Illuminate\\Database\\Query\\Builder::macro(\'openOnly\', function () { return $this->whereRaw(\'closed_at is null\'); });
Route::get(\'/l\', function () { $query = DB::table(\'ledgers\')->where(\'a\', 1); $query->openOnly(); return $query->get(); });', 'Route closure contains raw database queries'],
            'round 1: callback parameter handed to a function' => ['function applyLedgerFilter($query) { return $query->whereRaw(request(\'filter\')); }
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(fn ($query) => applyLedgerFilter($query))->get());', 'Route closure contains raw database queries'],
            'round 1: callback parameter handed to a static method' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(fn ($query) => \\App\\Filters\\LedgerFilter::apply($query))->get());', 'Route closure contains raw database queries'],
            'round 1: callback parameter handed to an object' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(fn ($query) => (new \\App\\Filters\\LedgerFilter)->apply($query))->get());', 'Route closure contains raw database queries'],
            'round 1: function call argument' => ['function ledgerTotal() { return DB::raw(\'count(*) as total\'); }
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->select(ledgerTotal())->first());', 'Route closure contains raw database queries'],
            'round 1: global constant argument' => ['const LEDGER_TOTAL = new \\Illuminate\\Database\\Query\\Expression(\'count(*) as total\');
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->select(LEDGER_TOTAL)->first());', 'Route closure contains raw database queries'],
            'round 1: global constant held in a variable' => ['const LEDGER_TOTAL = new \\Illuminate\\Database\\Query\\Expression(\'count(*) as total\');
Route::get(\'/l\', function () { $total = LEDGER_TOTAL; return DB::table(\'ledgers\')->select($total)->first(); });', 'Route closure contains raw database queries'],
            'round 1: global constant as a parameter default' => ['const LEDGER_TOTAL = new \\Illuminate\\Database\\Query\\Expression(\'count(*) as total\');
Route::get(\'/l\', fn ($total = LEDGER_TOTAL) => DB::table(\'ledgers\')->select($total)->first());', 'Route closure contains raw database queries'],
            'round 1: defined constant argument' => ['define(\'LEDGER_TOTAL\', DB::raw(\'count(*) as total\'));
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->select(LEDGER_TOTAL)->first());', 'Route closure contains raw database queries'],
            'round 1: static call argument' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->select(\\App\\Reports\\Columns::total())->first());', 'Route closure contains raw database queries'],
            'round 1: static property argument' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->select(\\App\\Reports\\Columns::$total)->first());', 'Route closure contains raw database queries'],
            'round 1: whereRowValues() operator' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->whereRowValues([\'a\', \'b\'], request(\'op\'), [1, 2])->get());', 'Route closure contains raw database queries'],
            'round 1: orWhereRowValues() operator' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->orWhereRowValues([\'a\', \'b\'], request(\'op\'), [1, 2])->get());', 'Route closure contains raw database queries'],
            'round 1: join() type' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->join(\'owners\', \'owners.id\', \'=\', \'ledgers.owner_id\', request(\'type\'))->get());', 'Route closure contains raw database queries'],
            'round 1: joinSub() type' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->joinSub(DB::table(\'owners\'), \'o\', \'o.id\', \'=\', \'ledgers.owner_id\', request(\'type\'))->get());', 'Route closure contains raw database queries'],
            'round 1: aggregate() function' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->aggregate(request(\'fn\'), [\'id\']));', 'Route closure contains raw database queries'],
            'round 1: lock property' => ['Route::get(\'/l\', function () { $query = DB::table(\'ledgers\')->where(\'a\', 1); $query->lock = request(\'mode\'); return $query->get(); });', 'Route closure contains raw database queries'],
            'round 1: wheres property in a beforeQuery() callback' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->beforeQuery(function ($query) { $query->wheres[] = [\'type\' => \'raw\', \'sql\' => request(\'filter\'), \'boolean\' => \'and\']; })->get());', 'Route closure contains raw database queries'],
            'round 1: array callable invoked' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(fn ($query) => [$query, \'whereRaw\'](request(\'filter\')))->get());', 'Route closure contains raw database queries'],
            'round 1: call_user_func()' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(fn ($query) => call_user_func([$query, \'whereRaw\'], request(\'filter\')))->get());', 'Route closure contains raw database queries'],
            'outside marker: arrow function capturing a DB::raw() expression' => ['$total = DB::raw(\'count(*) as total\');
Route::get(\'/ledgers\', fn () => DB::table(\'ledgers\')->select($total)->first());', 'Route closure contains raw database queries'],
            'outside marker: closure using a DB::raw() expression' => ['$total = DB::raw(\'count(*) as total\');
Route::get(\'/ledgers\', function () use ($total) { return DB::table(\'ledgers\')->select($total)->first(); });', 'Route closure contains raw database queries'],
            'outside marker: filter closure from the file scope' => ['$filter = fn ($query) => $query->whereRaw(request(\'filter\'));
Route::get(\'/ledgers\', fn () => DB::table(\'ledgers\')->where($filter)->get());', 'Route closure contains raw database queries'],
            'outside marker: string callable' => ['function applyLedgerFilter($query) { return $query->whereRaw(request(\'filter\')); }
Route::get(\'/ledgers\', fn () => DB::table(\'ledgers\')->tap(\'applyLedgerFilter\')->get());', 'Route closure contains raw database queries'],
            'outside marker: array callable' => ['Route::get(\'/ledgers\', fn () => DB::table(\'ledgers\')->tap([\\App\\Filters\\LedgerFilter::class, \'apply\'])->get());', 'Route closure contains raw database queries'],
            'outside marker: first-class callable' => ['function applyLedgerFilter($query) { return $query->whereRaw(request(\'filter\')); }
Route::get(\'/ledgers\', fn () => DB::table(\'ledgers\')->tap(applyLedgerFilter(...))->get());', 'Route closure contains raw database queries'],
            'outside marker: invokable object' => ['Route::get(\'/ledgers\', fn () => DB::table(\'ledgers\')->tap(new \\App\\Filters\\LedgerFilter)->get());', 'Route closure contains raw database queries'],
            'outside marker: value from a service parameter' => ['Route::get(\'/ledgers\', fn (\\App\\Reports\\Columns $columns) => DB::table(\'ledgers\')->select($columns->total())->first());', 'Route closure contains raw database queries'],
            'outside marker: value from an unknown static call' => ['Route::get(\'/ledgers\', function () { $total = \\App\\Reports\\Columns::total(); return DB::table(\'ledgers\')->select($total)->first(); });', 'Route closure contains raw database queries'],
            'marker: whereRaw()' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->whereRaw(\'entries > 10\')->get());', 'Route closure contains raw database queries'],
            'marker: WhereRaw() in another case' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->WhereRaw(\'entries > 10\')->get());', 'Route closure contains raw database queries'],
            'marker: selectRaw()' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->selectRaw(\'count(*) as total\')->first());', 'Route closure contains raw database queries'],
            'marker: orderByRaw()' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->orderByRaw(\'entries desc\')->get());', 'Route closure contains raw database queries'],
            'marker: havingRaw()' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->groupBy(\'owner_id\')->havingRaw(\'count(*) > 1\')->get());', 'Route closure contains raw database queries, complex business logic'],
            'marker: selectExpression()' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->selectExpression(\'max(id)\', \'top\')->get());', 'Route closure contains raw database queries'],
            'marker: rawValue()' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->rawValue(\'max(id)\'));', 'Route closure contains raw database queries'],
            'marker: RawValue() in another case' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->RawValue(\'max(id)\'));', 'Route closure contains raw database queries'],
            'marker: builder raw()' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->orderBy(DB::query()->raw(\'rand()\'))->get());', 'Route closure contains raw database queries'],
            'marker: DB::raw() argument' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->select(DB::raw(\'count(*) as total\'))->first());', 'Route closure contains raw database queries'],
            'marker: lock() with a string' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->lock(\'for update nowait\')->get());', 'Route closure contains raw database queries'],
            'marker: lock() with request input' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->lock(request(\'mode\'))->get());', 'Route closure contains raw database queries'],
            'marker: inRandomOrder() with request input' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->inRandomOrder(request(\'seed\'))->get());', 'Route closure contains raw database queries'],
            'marker: forceIndex()' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->forceIndex(\'ledgers_owner_index\')->get());', 'Route closure contains raw database queries'],
            'marker: selectSub() string' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->selectSub(\'select max(id) from owners\', \'m\')->get());', 'Route closure contains raw database queries'],
            'marker: selectSub() named query argument' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->selectSub(as: \'m\', query: \'select max(id) from owners\')->get());', 'Route closure contains raw database queries'],
            'marker: fromSub() string' => ['Route::post(\'/tickets/{id}\', fn () => DB::query()->fromSub(\'select * from ledgers\', \'l\')->get());', 'Route closure contains raw database queries'],
            'marker: joinSub() string' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->joinSub(\'select 1 as id\', \'s\', \'s.id\', \'=\', \'ledgers.id\')->get());', 'Route closure contains raw database queries'],
            'marker: leftJoinLateral() string' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->leftJoinLateral(\'select 1 as id\', \'s\')->get());', 'Route closure contains raw database queries'],
            'marker: fromSub() of a model attribute' => ['use App\\Models\\Ledger;
Route::post(\'/tickets/{id}\', fn ($id) => DB::query()->fromSub(Ledger::findOrFail($id)->getAttribute(\'body\'), \'r\')->get());', 'Route closure contains raw database queries'],
            'marker: fromSub() of plucked rows joined into a string' => ['Route::post(\'/tickets/{id}\', fn () => DB::query()->fromSub(DB::table(\'snippets\')->pluck(\'sql\')->join(\' union \'), \'r\')->get());', 'Route closure contains raw database queries'],
            'marker: fromSub() of value()' => ['use App\\Models\\Ledger;
Route::post(\'/tickets/{id}\', fn () => DB::query()->fromSub(Ledger::where(\'key\', \'q\')->value(\'sql\'), \'r\')->get());', 'Route closure contains raw database queries'],
            'marker: fromSub() of a closure parameter' => ['Route::post(\'/tickets/{id}\', fn ($sql) => DB::query()->fromSub($sql, \'r\')->get());', 'Route closure contains raw database queries'],
            'marker: fromSub() of a variable holding a string' => ['Route::post(\'/tickets/{id}\', function () { $sql = \'select 1 as id\'; return DB::query()->fromSub($sql, \'r\')->get(); });', 'Route closure contains raw database queries'],
            'marker: fromSub() of sprintf()' => ['Route::post(\'/tickets/{id}\', fn () => DB::query()->fromSub(sprintf(\'select * from %s\', request(\'t\')), \'r\')->get());', 'Route closure contains raw database queries'],
            'marker: fully qualified Expression argument' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->where(new \\Illuminate\\Database\\Query\\Expression(\'1=1\'))->get());', 'Route closure contains raw database queries'],
            'marker: imported Expression argument' => ['use Illuminate\\Database\\Query\\Expression as SqlExpression;
Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->where(new SqlExpression(\'1=1\'))->get());', 'Route closure contains raw database queries'],
            'marker: Expression held in a variable' => ['use Illuminate\\Database\\Query\\Expression;
Route::post(\'/tickets/{id}\', function () { $sum = new Expression(\'sum(entries) as total\'); return DB::table(\'ledgers\')->select($sum)->get(); });', 'Route closure contains raw database queries'],
            'marker: Expression as the table' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(new \\Illuminate\\Database\\Query\\Expression(\'ledgers as l\'))->get());', 'Route closure contains raw database queries'],
            'marker: getConnection()->select()' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->getConnection()->select(\'select 1\'));', 'Route closure contains raw database queries'],
            'marker: getPdo()->exec()' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->getConnection()->getPdo()->exec(\'delete from ledgers\'));', 'Route closure contains raw database queries, complex business logic'],
            'marker: connection property' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->where(fn ($query) => $query->connection->statement(\'select 1\'))->get());', 'Route closure contains raw database queries'],
            'marker: dynamic method name' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->where(\'id\', 1)->{\'update\'}([\'closed\' => true]));', 'Route closure contains raw database queries'],
            'marker: unknown builder method, a macro' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->openOnly()->get());', 'Route closure contains raw database queries'],
            'nullsafe: where()?->get()' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->where(\'closed\', 1)?->get());', 'Route closure contains raw database queries'],
            'nullsafe: latest()?->get()' => ['Route::post(\'/tickets/{id}\', fn () => DB::table(\'ledgers\')->latest()?->get());', 'Route closure contains raw database queries'],
            'round 2: array literal to a function' => ['function purgeAll($builders) { foreach ($builders as $query) { $query->delete(); } }
Route::post(\'/l\', fn () => purgeAll([DB::table(\'ledgers\')->where(\'open\', 1)]));', 'Route closure contains raw database queries'],
            'round 2: builder variable in an array to a function' => ['function purgeAll($builders) { foreach ($builders as $query) { $query->delete(); } }
Route::post(\'/l\', function () { $query = DB::table(\'ledgers\')->where(\'open\', 1); return purgeAll([\'q\' => $query]); });', 'Route closure contains raw database queries'],
            'round 2: spread array to a function' => ['function purgeAll($builders) { foreach ($builders as $query) { $query->delete(); } }
Route::post(\'/l\', function () { $query = DB::table(\'ledgers\')->where(\'open\', 1); return purgeAll(...[[$query]]); });', 'Route closure contains raw database queries'],
            'round 2: array to new' => ['Route::post(\'/l\', fn () => new \\App\\Purger([DB::table(\'ledgers\')->where(\'open\', 1)]));', 'Route closure contains raw database queries'],
            'round 2: collect() higher-order delete' => ['Route::post(\'/l\', fn () => collect([DB::table(\'ledgers\')->where(\'open\', 1)])->each->delete());', 'Route closure contains raw database queries'],
            'round 2: array_map() delete' => ['Route::post(\'/l\', fn () => array_map(fn ($query) => $query->delete(), [DB::table(\'ledgers\')->where(\'open\', 1)]));', 'Route closure contains raw database queries'],
            'round 2: appended element' => ['Route::post(\'/l\', function () { $builders = []; $builders[] = DB::table(\'ledgers\')->where(\'open\', 1); return $builders[0]->delete(); });', 'Route closure contains raw database queries'],
            'round 2: keyed element' => ['Route::post(\'/l\', function () { $builders = []; $builders[\'q\'] = DB::table(\'ledgers\')->where(\'open\', 1); return $builders[\'q\']->delete(); });', 'Route closure contains raw database queries'],
            'round 2: indexed array literal' => ['Route::post(\'/l\', fn () => [DB::table(\'ledgers\')->where(\'open\', 1)][0]->delete());', 'Route closure contains raw database queries'],
            'round 2: ternary of builders, write' => ['Route::post(\'/l\', function () { $query = request(\'drafts\') ? DB::table(\'drafts\')->where(\'k\', 1) : DB::table(\'ledgers\')->where(\'k\', 1); return $query->delete(); });', 'Route closure contains raw database queries'],
            'round 2: elvis of builders, write' => ['Route::post(\'/l\', function () { $query = DB::table(\'drafts\')->where(\'k\', 1) ?: DB::table(\'ledgers\')->where(\'k\', 1); return $query->delete(); });', 'Route closure contains raw database queries'],
            'round 2: coalesce of builders, write' => ['Route::post(\'/l\', function () { $query = DB::table(\'drafts\')->where(\'k\', 1) ?? DB::table(\'ledgers\')->where(\'k\', 1); return $query->delete(); });', 'Route closure contains raw database queries'],
            'round 2: ternary of builders, macro' => ['\\Illuminate\\Database\\Query\\Builder::macro(\'openOnly\', function () { return $this->whereRaw(\'closed_at is null\'); });
Route::get(\'/l\', function () { $query = request(\'drafts\') ? DB::table(\'drafts\')->where(\'k\', 1) : DB::table(\'ledgers\')->where(\'k\', 1); return $query->openOnly()->get(); });', 'Route closure contains raw database queries'],
            'round 2: value() closure' => ['Route::post(\'/l\', fn () => value(fn () => DB::table(\'ledgers\')->where(\'open\', 1))->delete());', 'Route closure contains raw database queries'],
            'round 2: map() returning builders' => ['Route::post(\'/l\', fn () => collect([1])->map(fn () => DB::table(\'ledgers\')->where(\'open\', 1))->each->delete());', 'Route closure contains raw database queries'],
            'round 2: ternary receiver' => ['Route::post(\'/l\', function () { $a = DB::table(\'ledgers\')->where(\'open\', 1); $b = DB::table(\'drafts\')->where(\'open\', 1); return (request(\'drafts\') ? $b : $a)->delete(); });', 'Route closure contains raw database queries'],
            'round 2: assignment receiver' => ['Route::post(\'/l\', fn () => ($query = DB::table(\'ledgers\')->where(\'open\', 1))->delete());', 'Route closure contains raw database queries'],
            'round 2: when() value parameter on a builder variable' => ['Route::post(\'/l\', function () { $drafts = DB::table(\'drafts\')->where(\'a\', 1); $ledgers = DB::table(\'ledgers\')->where(\'a\', 1); return $ledgers->when($drafts, fn ($query, $value) => $value->delete())->get(); });', 'Route closure contains raw database queries'],
            'round 2: insertOrIgnoreReturning() after where()' => ['Route::post(\'/l\', fn () => DB::table(\'ledgers\')->where(\'a\', 1)->insertOrIgnoreReturning([[\'name\' => \'Draft\']], [\'id\']));', 'Route closure contains raw database queries'],
            'round 2: insertOrIgnoreReturning() on table()' => ['Route::post(\'/l\', fn () => DB::table(\'ledgers\')->insertOrIgnoreReturning([[\'name\' => \'Draft\']], [\'id\']));', 'Route closure contains raw database queries'],
            'round 2: write through a variable beside a builder read' => ['use App\\Models\\Ledger;
Route::post(\'/l\', function () { $ledger = Ledger::where(\'a\', 1)->first(); $ledger->delete(); return DB::table(\'ledgers\')->get(); });', 'Route closure contains raw database queries'],
            'round 2: domain model write beside a builder read' => ['Route::post(\'/l\', function () { \\App\\Domain\\Blog\\Post::create([]); return DB::table(\'ledgers\')->get(); });', 'Route closure contains raw database queries'],
            'round 2: raw SQL in a called function beside a builder read' => ['function logVisit() { DB::insert(\'insert into visits (at) values (now())\'); }
Route::get(\'/l\', function () { logVisit(); return DB::table(\'ledgers\')->get(); });', 'Route closure contains raw database queries'],
            'round 3: arrow array beside a read' => ['function logVisit() { DB::insert(\'insert into visits (at) values (now())\'); }
Route::get(\'/l\', fn () => [logVisit(), DB::table(\'ledgers\')->get()]);', 'Route closure contains raw database queries'],
            'round 3: arrow coalesce' => ['function logVisit() { DB::insert(\'insert into visits (at) values (now())\'); }
Route::get(\'/l\', fn () => logVisit() ?? DB::table(\'ledgers\')->get());', 'Route closure contains raw database queries'],
            'round 3: returned array beside a read' => ['function logVisit() { DB::insert(\'insert into visits (at) values (now())\'); }
Route::get(\'/l\', function () { return [logVisit(), DB::table(\'ledgers\')->get()]; });', 'Route closure contains raw database queries'],
            'round 3: json response beside a read' => ['function logVisit() { DB::insert(\'insert into visits (at) values (now())\'); }
Route::get(\'/l\', fn () => response()->json([\'rows\' => DB::table(\'ledgers\')->get(), \'v\' => logVisit()]));', 'Route closure contains raw database queries'],
            'round 3: Schema DDL beside a read' => ['Route::get(\'/l\', fn () => [\\Illuminate\\Support\\Facades\\Schema::dropIfExists(\'ledgers_tmp\'), DB::table(\'ledgers\')->get()]);', 'Route closure contains raw database queries'],
            'round 3: model save beside a read' => ['Route::post(\'/l\', fn () => [(new \\App\\Models\\Ledger)->forceFill([\'a\' => 1])->save(), DB::table(\'ledgers\')->get()]);', 'Route closure contains raw database queries'],
            'round 3: string callable variable as when() default' => ['function applyLedgerFilter($query) { return $query->whereRaw(request(\'filter\')); }
Route::get(\'/l\', function () { $cb = \'applyLedgerFilter\'; return DB::table(\'ledgers\')->when(request(\'x\'), fn ($q) => $q, $cb)->get(); });', 'Route closure contains raw database queries'],
            'round 3: string callable variable to tap()' => ['function applyLedgerFilter($query) { return $query->whereRaw(request(\'filter\')); }
Route::get(\'/l\', function () { $cb = \'applyLedgerFilter\'; return DB::table(\'ledgers\')->tap($cb)->get(); });', 'Route closure contains raw database queries'],
            'round 3: string callable parameter default' => ['function applyLedgerFilter($query) { return $query->whereRaw(request(\'filter\')); }
Route::get(\'/l\', fn ($cb = \'applyLedgerFilter\') => DB::table(\'ledgers\')->tap($cb)->get());', 'Route closure contains raw database queries'],
            'round 3: writing callable variable to pipe()' => ['function purgeLedgers($query) { return $query->delete(); }
Route::post(\'/l\', function () { $cb = \'purgeLedgers\'; return DB::table(\'ledgers\')->where(\'open\', 1)->pipe($cb); });', 'Route closure contains raw database queries'],
            'round 3: writing callable variable as unless() default' => ['function purgeLedgers($query) { return $query->delete(); }
Route::post(\'/l\', function () { $cb = \'purgeLedgers\'; return DB::table(\'ledgers\')->unless(request(\'keep\'), fn ($q) => $q, $cb)->get(); });', 'Route closure contains raw database queries'],
            'round 3: config() callable' => ['Route::post(\'/l\', fn () => DB::table(\'ledgers\')->where(\'open\', 1)->when(true, config(\'ledgers.purge\'))->get());', 'Route closure contains raw database queries, complex business logic'],
            'round 3: class constant callable' => ['Route::post(\'/l\', fn () => DB::table(\'ledgers\')->where(\'open\', 1)->tap(\\App\\Filters\\Ledger::PURGE)->get());', 'Route closure contains raw database queries, complex business logic'],
            'round 3: func_get_args() write' => ['Route::post(\'/l\', fn () => DB::table(\'ledgers\')->where(\'open\', 1)->tap(function () { func_get_args()[0]->delete(); })->get());', 'Route closure contains raw database queries, complex business logic'],
            'round 3: func_get_arg() write' => ['Route::post(\'/l\', fn () => DB::table(\'ledgers\')->where(\'open\', 1)->tap(fn () => func_get_arg(0)->delete())->get());', 'Route closure contains raw database queries, complex business logic'],
            'round 3: compact() write' => ['Route::post(\'/l\', fn () => DB::table(\'ledgers\')->where(\'open\', 1)->tap(fn ($query) => compact(\'query\')[\'query\']->delete())->get());', 'Route closure contains raw database queries, complex business logic'],
            'round 3: get_defined_vars() write' => ['Route::post(\'/l\', fn () => DB::table(\'ledgers\')->where(\'open\', 1)->tap(function ($query) { get_defined_vars()[\'query\']->delete(); })->get());', 'Route closure contains raw database queries, complex business logic'],
            'round 3: compact() handed to a function' => ['function purgeAll($builders) { foreach ($builders as $query) { $query->delete(); } }
Route::post(\'/l\', function () { $q = DB::table(\'ledgers\')->where(\'open\', 1); return purgeAll(compact(\'q\')); });', 'Route closure contains raw database queries'],
            'round 3: func_get_args() macro' => ['\\Illuminate\\Database\\Query\\Builder::macro(\'openOnly\', function () { return $this->whereRaw(\'closed_at is null\'); });
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(function () { func_get_args()[0]->openOnly(); })->get());', 'Route closure contains raw database queries'],
            'round 3: where() boolean' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(\'a\', 1)->where(\'b\', \'=\', 2, request(\'bool\'))->get());', 'Route closure contains raw database queries, complex business logic'],
            'round 3: whereNull() named boolean' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(\'a\', 1)->whereNull(\'b\', boolean: request(\'bool\'))->get());', 'Route closure contains raw database queries, complex business logic'],
            'round 3: whereIn() boolean' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(\'a\', 1)->whereIn(\'id\', [1, 2], request(\'bool\'))->get());', 'Route closure contains raw database queries, complex business logic'],
            'round 3: having() boolean' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->groupBy(\'a\')->having(\'a\', \'>\', 1)->having(\'b\', \'>\', 1, request(\'bool\'))->get());', 'Route closure contains raw database queries, complex business logic'],
            'round 3: join on() boolean' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->join(\'o\', fn ($j) => $j->on(\'o.id\', \'=\', \'ledgers.o\')->on(\'o.t\', \'=\', \'ledgers.t\', request(\'bool\')))->get());', 'Route closure contains raw database queries'],
            'round 3: where() of the whole request' => ['Route::get(\'/l\', fn (\\Illuminate\\Http\\Request $request) => DB::table(\'ledgers\')->where($request->all())->get());', 'Route closure contains raw database queries'],
            'round 3: where() of request()->query()' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(request()->query())->get());', 'Route closure contains raw database queries'],
            'round 3: where-prefixed macro' => ['\\Illuminate\\Database\\Query\\Builder::macro(\'whereOpen\', function () { return $this->whereRaw(\'closed_at is null\'); });
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->whereOpen()->get());', 'Route closure contains raw database queries'],
            'round 3: orWhere-prefixed macro' => ['\\Illuminate\\Database\\Query\\Builder::macro(\'orWhereOpen\', function () { return $this->orWhereRaw(\'closed_at is null\'); });
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(\'a\', 1)->orWhereOpen()->get());', 'Route closure contains raw database queries, complex business logic'],
            'round 3: where-prefixed macro on a builder variable' => ['\\Illuminate\\Database\\Query\\Builder::macro(\'whereOpen\', function () { return $this->whereRaw(\'closed_at is null\'); });
Route::get(\'/l\', function () { $q = DB::table(\'ledgers\')->whereOpen(); return $q->get(); });', 'Route closure contains raw database queries'],
        ];
    }

    /**
     * A value that may carry an Expression, which the grammar writes as it is, keeps master's
     * grade: an untyped route parameter (Route::bind() may return one) or one with a default,
     * request('key') (it falls back to the route parameter), config(), a helper a namespaced
     * routes file declares for itself, and a method Laravel 9.0 lacks, which may be a macro.
     *
     * @dataProvider queryBuilderValueKeepsMastersGradeProvider
     *
     * @param  list<array{string, Severity}>  $grade
     */
    #[DataProvider('queryBuilderValueKeepsMastersGradeProvider')]
    public function test_a_value_that_may_carry_an_expression_keeps_masters_grade(string $code, array $grade): void
    {
        foreach ([true, false] as $allowSimpleReads) {
            $issues = $this->analyzeRouteCode($code, $allowSimpleReads)->getIssues();

            $this->assertSame($grade, array_values(array_map(static fn ($issue): array => [$issue->message, $issue->severity], $issues)));
        }
    }

    /**
     * @return array<string, array{string, list<array{string, Severity}>}>
     */
    public static function queryBuilderValueKeepsMastersGradeProvider(): array
    {
        return [
            'review: F1a: parameter default constant Expression' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

const CUTOFF = new \\Illuminate\\Database\\Query\\Expression(\'1 or 1=1\');
Route::get(\'/l\', fn ($v = CUTOFF) => DB::table(\'ledgers\')->where(\'closed_at\', \'<\', $v)->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'review: F1b: parameter default new Expression' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

Route::get(\'/l\', fn ($v = new \\Illuminate\\Database\\Query\\Expression(\'1 or 1=1\')) => DB::table(\'ledgers\')->where(\'id\', $v)->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'review: F1c: parameter default into find()' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

const CUTOFF = new \\Illuminate\\Database\\Query\\Expression(\'1 or 1=1\');
Route::get(\'/l\', fn ($v = CUTOFF) => DB::table(\'ledgers\')->find($v));
', [['Route closure contains raw database queries', Severity::High]]],
            'review: F1d: Route::bind() raw on an untyped parameter' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

Route::bind(\'cutoff\', fn ($value) => DB::raw($value));
Route::get(\'/l/{cutoff}\', fn ($cutoff) => DB::table(\'ledgers\')->where(\'closed_at\', \'<\', $cutoff)->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'review: F2: request() falls back to the bound route parameter' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

Route::bind(\'cutoff\', fn ($value) => DB::raw($value));
Route::get(\'/l/{cutoff}\', fn () => DB::table(\'ledgers\')->where(\'closed_at\', \'<\', request(\'cutoff\'))->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'review: F3: config() holding an Expression' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

config([\'ledgers.cutoff\' => DB::raw(\'now() - interval 1 day\')]);
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(\'closed_at\', \'<\', config(\'ledgers.cutoff\'))->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'review: F4a: now() shadowed in a namespaced routes file' => ['<?php

namespace App\\Routes;

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

function now() { return DB::raw(request(\'t\')); }
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(\'closed_at\', \'<\', now())->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'review: F4b: today() shadowed' => ['<?php

namespace App\\Routes;

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

function today() { return DB::raw(\'1 or 1=1\'); }
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->whereDate(\'d\', today())->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'review: F4c: request() shadowed' => ['<?php

namespace App\\Routes;

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

function request($k) { return DB::raw(\\request($k)); }
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(\'id\', request(\'id\'))->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'review: F4d: config() shadowed' => ['<?php

namespace App\\Routes;

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

function config($k) { return DB::raw($k); }
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(\'id\', config(\'1 or 1=1\'))->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'review: F5: whereLike() macro on Laravel 9/10' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

\\Illuminate\\Database\\Query\\Builder::macro(\'whereLike\', function ($column, $value) { return $this->whereRaw("{$column} like \'%{$value}%\'"); });
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->whereLike(\'name\', request(\'q\'))->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'control: an untyped route parameter' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

Route::get(\'/articles/{id}\', fn ($id) => DB::table(\'articles\')->find($id));
', [['Route closure contains raw database queries', Severity::High]]],
            'control: a scalar route parameter with a default' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

Route::get(\'/articles/{id?}\', fn (int $id = 1) => DB::table(\'articles\')->find($id));
', [['Route closure contains raw database queries', Severity::High]]],
            'control: bare request()' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

Route::get(\'/articles\', fn () => DB::table(\'articles\')->where(\'slug\', request(\'q\'))->first());
', [['Route closure contains raw database queries', Severity::High]]],
            'control: config()' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

Route::get(\'/articles\', fn () => DB::table(\'articles\')->where(\'status\', config(\'blog.status\'))->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'control: now() declared in a namespaced routes file' => ['<?php

namespace App\\Routes;

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

function now() { return \'2020-01-01\'; }
Route::get(\'/articles\', fn () => DB::table(\'articles\')->whereDate(\'published_at\', now())->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'control: whereLike()' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

Route::get(\'/articles\', fn () => DB::table(\'articles\')->whereLike(\'title\', \'%news%\')->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'control: whereNot()' => ['<?php

use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Route;

Route::get(\'/articles\', fn () => DB::table(\'articles\')->whereNot(\'status\', \'draft\')->get());
', [['Route closure contains raw database queries', Severity::High]]],
            'control: an unimported DB in a namespaced routes file' => ['<?php

namespace App\\Routes;

use Illuminate\\Support\\Facades\\Route;

Route::get(\'/articles\', fn () => DB::table(\'articles\')->latest()->get());
', []],
        ];
    }

    /**
     * A file that may replace DB::table() or DB::query() with a macro, or a request reader Laravel
     * 9.0 lacks (so a macro there), keeps master's grade.
     *
     * @dataProvider queryBuilderMacroKeepsMastersGradeProvider
     */
    #[DataProvider('queryBuilderMacroKeepsMastersGradeProvider')]
    public function test_a_macro_that_may_replace_a_root_or_a_value_keeps_masters_grade(string $routes, string $message): void
    {
        foreach ([true, false] as $allowSimpleReads) {
            $this->assertSame([[$message, Severity::High]], $this->dbRouteGrade($routes, $allowSimpleReads));
        }
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function queryBuilderMacroKeepsMastersGradeProvider(): array
    {
        return [
            'F1a: request()->integer() macro' => ['\\Illuminate\\Http\\Request::macro(\'integer\', function ($key) { return DB::raw($this->input($key)); });
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(\'id\', request()->integer(\'id\'))->get());', 'Route closure contains raw database queries'],
            'F1b: request()->string() macro' => ['\\Illuminate\\Http\\Request::macro(\'string\', function ($key) { return DB::raw($this->input($key)); });
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(\'name\', request()->string(\'name\'))->get());', 'Route closure contains raw database queries'],
            'F2a: DB::macro(table)' => ['DB::macro(\'table\', function ($table) { return $this->connection()->table($table)->whereRaw(request(\'filter\')); });
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->latest()->get());', 'Route closure contains raw database queries'],
            'F2b: DB::macro(query)' => ['DB::macro(\'query\', function () { return $this->connection()->query()->whereRaw(request(\'filter\')); });
Route::get(\'/l\', fn () => DB::query()->from(\'ledgers\')->latest()->get());', 'Route closure contains raw database queries, complex business logic'],
            'control: request()->integer()' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(\'id\', request()->integer(\'id\'))->get());', 'Route closure contains raw database queries'],
            'control: request()->string()' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->where(\'name\', request()->string(\'name\'))->get());', 'Route closure contains raw database queries'],
            'control: DatabaseManager::macro(table)' => ['\\Illuminate\\Database\\DatabaseManager::macro(\'table\', fn ($table) => $this->connection()->table($table));
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->latest()->get());', 'Route closure contains raw database queries'],
            'control: app(db)->macro(table)' => ['app(\'db\')->macro(\'table\', fn ($table) => $this->connection()->table($table));
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->latest()->get());', 'Route closure contains raw database queries'],
            'control: DB::getFacadeRoot()->macro(query)' => ['DB::getFacadeRoot()->macro(\'query\', fn () => $this->connection()->query());
Route::get(\'/l\', fn () => DB::query()->from(\'ledgers\')->latest()->get());', 'Route closure contains raw database queries, complex business logic'],
            'control: a TABLE macro registered after the route' => ['Route::get(\'/l\', fn () => DB::table(\'ledgers\')->latest()->get());
DB::macro(\'TABLE\', fn ($table) => $this->connection()->table($table));', 'Route closure contains raw database queries'],
            'control: a macro with a computed name' => ['DB::macro(strtolower(\'TABLE\'), fn ($table) => $this->connection()->table($table));
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->latest()->get());', 'Route closure contains raw database queries'],
            'control: DB::mixin()' => ['DB::mixin(new \\App\\Database\\TableMixin);
Route::get(\'/l\', fn () => DB::table(\'ledgers\')->latest()->get());', 'Route closure contains raw database queries'],
        ];
    }

    /**
     * The issues of a route file importing the DB and Route facades, as [message, severity].
     *
     * @return list<array{string, Severity}>
     */
    private function dbRouteGrade(string $routes, bool $allowSimpleReads): array
    {
        $result = $this->analyzeRouteCode("<?php\n\nuse Illuminate\\Support\\Facades\\DB;\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n", $allowSimpleReads);

        return array_values(array_map(static fn ($issue): array => [$issue->message, $issue->severity], $result->getIssues()));
    }
}
