<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use PhpParser\Node;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\BestPractices\ChunkMissingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class ChunkMissingAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ChunkMissingAnalyzer($this->parser);
    }

    public function test_passes_with_chunk_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processAllUsers()
    {
        User::chunk(1000, function ($users) {
            foreach ($users as $user) {
                // Process user
            }
        });
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

    public function test_passes_with_cursor_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function processOrders()
    {
        foreach (Order::cursor() as $order) {
            // Process order
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_lazy_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function processProducts()
    {
        foreach (Product::lazy() as $product) {
            // Process product
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_all_in_foreach(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processAllUsers()
    {
        foreach (User::all() as $user) {
            // Process user
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('all()', $result);
    }

    public function test_detects_get_in_foreach(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function processOrders()
    {
        foreach (Order::where('status', 'pending')->get() as $order) {
            // Process order
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('get()', $result);
    }

    public function test_detects_query_result_in_foreach(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function updatePrices()
    {
        $products = Product::where('active', true)->get();
        foreach ($products as $product) {
            $product->update(['price' => $product->price * 1.1]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Now detects variable assignment pattern
        $this->assertFailed($result);
        $this->assertHasIssueContaining('variable', $result);
    }

    public function test_provides_chunking_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processUsers()
    {
        foreach (User::all() as $user) {
            // Process
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('chunk method', $issues[0]->recommendation);
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

    public function test_passes_with_lazy_by_id(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processUsers()
    {
        foreach (User::lazyById() as $user) {
            // Process user
        }
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

    public function test_passes_with_chunk_by_id(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function processOrders()
    {
        Order::chunkById(500, function ($orders) {
            foreach ($orders as $order) {
                // Process order
            }
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_limit_modifier(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getRecentUsers()
    {
        foreach (User::limit(10)->get() as $user) {
            // Process limited dataset
        }
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

    public function test_passes_with_take_modifier(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function getFeaturedProducts()
    {
        foreach (Product::take(5)->get() as $product) {
            // Process small dataset
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_multiple_issues_in_file(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use App\Models\Order;

class BatchService
{
    public function processBoth()
    {
        foreach (User::all() as $user) {
            // Process user
        }

        foreach (Order::get() as $order) {
            // Process order
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/BatchService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
    }

    public function test_detects_complex_method_chain(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processActiveUsers()
    {
        foreach (User::with('posts')->where('active', true)->orderBy('name')->get() as $user) {
            // Process user
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('get()', $result);
    }

    public function test_passes_with_paginate(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function listUsers()
    {
        foreach (User::where('active', true)->paginate(20) as $user) {
            // Paginated results are memory-safe
        }
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

    public function test_passes_with_simple_paginate(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function listOrders()
    {
        foreach (Order::simplePaginate(15) as $order) {
            // Simple pagination is memory-safe
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_cursor_paginate(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function listProducts()
    {
        foreach (Product::cursorPaginate(50) as $product) {
            // Cursor pagination is memory-safe
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_find_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getSingleRecords(int $id)
    {
        // These all return single records, not collections
        $user1 = User::find($id);
        $user2 = User::findOrFail($id);
        $user3 = User::where('email', 'test@example.com')->sole();
        $user4 = User::where('email', 'test@example.com')->firstOrFail();
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

    public function test_detects_collection_method_after_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processFilteredUsers()
    {
        // All records loaded into memory, then sorted - should be flagged
        foreach (User::all()->sortBy('name') as $user) {
            // Process user
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_collection_filter_after_get(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function processExpensiveProducts()
    {
        // All records loaded, then filtered in memory - should be flagged
        foreach (Product::where('active', true)->get()->filter(fn($p) => $p->price > 100) as $product) {
            // Process product
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_passes_with_request_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class UserController
{
    public function store(Request $request)
    {
        // $request->all() returns HTTP input, NOT database records
        foreach ($request->all() as $key => $value) {
            // Process form input
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_config_get(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConfigService
{
    public function loadSettings()
    {
        // config()->get() returns config values, NOT database records
        $settings = config()->get('app.settings', []);
        foreach ($settings as $key => $value) {
            // Process config
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ConfigService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_collect_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataService
{
    public function processArray(array $items)
    {
        // collect()->all() creates collection from array, NOT from database
        foreach (collect($items)->all() as $item) {
            // Process item
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_detects_static_model_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processUsers()
    {
        // User::all() IS a database call and SHOULD be flagged
        foreach (User::all() as $user) {
            // Process user
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_no_scope_leak_between_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Project;

class DashboardStatsService
{
    public function methodA(): void
    {
        // This assigns $projects from a DB query in method A
        $projects = Project::all();
        foreach ($projects as $project) {
            // process
        }
    }

    public function methodB(array $projects): void
    {
        // $projects here is a parameter (Collection/array), not a DB query result.
        // The analyzer must NOT flag this foreach because methodA's assignment
        // should not bleed into methodB's scope.
        foreach ($projects as $project) {
            // process
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DashboardStatsService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Only methodA's foreach should be flagged (the direct User::all() in the loop).
        // methodB's foreach must NOT be flagged.
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_passes_with_pluck_then_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Report;

class ReportController
{
    public function index(): void
    {
        // pluck() executes the query and returns a Collection in memory.
        // ->all() here is Collection::all() — converts to array, no extra DB call.
        foreach (Report::orderBy('analyzed_at')->pluck('score', 'id')->all() as $id => $score) {
            // process
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReportController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_for_db_query_with_from_sub(): void
    {
        // Reproduces the false positive from ProjectController::computeProjectScoreDeltas().
        // DB::query()->fromSub(...)->where('rn', '<=', 2)->get() is bounded by the window-
        // function subquery and uses a derived table (fromSub) — explicit SQL engineering
        // where result set size is encoded in the subquery structure, not a terminal method.
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;
use App\Models\Report;

class ProjectController
{
    public function computeProjectScoreDeltas(array $projectIds): array
    {
        $ranked = Report::query()
            ->select(['project_id', 'score', DB::raw('ROW_NUMBER() OVER (PARTITION BY project_id ORDER BY analyzed_at DESC) AS rn')])
            ->whereIn('project_id', $projectIds)
            ->whereIn('environment', ['production', 'staging']);

        $reports = DB::query()
            ->fromSub($ranked, 'ranked')
            ->select(['project_id', 'score', 'rn'])
            ->where('rn', '<=', 2)
            ->orderBy('project_id')
            ->orderByDesc('rn')
            ->get();

        $deltas = [];
        $previousScores = [];

        foreach ($reports as $report) {
            $deltas[$report->project_id] = isset($previousScores[$report->project_id])
                ? $report->score - $previousScores[$report->project_id]
                : null;
            $previousScores[$report->project_id] = $report->score;
        }

        return $deltas;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Controllers/ProjectController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_flags_db_table_without_limit(): void
    {
        // DB::table()->get() without a limit or subquery composition still risks
        // loading an unbounded result set and must remain flagged.
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

class ReportService
{
    public function processAll(): void
    {
        $rows = DB::table('users')->where('active', true)->get();
        foreach ($rows as $row) {
            // process
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReportService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_a_raw_select_is_bounded_by_its_key_filter_not_its_raw_sql(): void
    {
        // A correlated subquery in the select list makes each row dearer to build; it
        // does not bound how many rows come back. The whereIn() on the key does: the
        // fetch returns at most one row per id, as find($ids) would.
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Invoice;
use Illuminate\Support\Facades\DB;

class InvoiceController
{
    private function balances(array $invoiceIds): array
    {
        $rows = Invoice::query()
            ->select([
                'id',
                'total',
                DB::raw('(SELECT SUM(p.amount) FROM payments p WHERE p.invoice_id = invoices.id) AS paid'),
            ])
            ->whereIn('id', $invoiceIds)
            ->get();

        $balances = [];

        foreach ($rows as $row) {
            $balances[$row->id] = $row->total - (int) $row->paid;
        }

        return $balances;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Controllers/InvoiceController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * @dataProvider selectSpellingProvider
     */
    #[DataProvider('selectSpellingProvider')]
    public function test_every_spelling_of_a_select_gets_the_same_verdict(string $fetch): void
    {
        // What the select list holds says nothing about the row count, so no spelling of
        // it, raw or not, exempts the fetch.
        $result = $this->analyzeVisitFetch($fetch);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function selectSpellingProvider(): array
    {
        $raw = "'team_id, MAX(created_at) as last_seen_at'";

        return [
            'select(DB::raw())' => ["Visit::query()->select(DB::raw({$raw}))->groupBy('team_id')->get()"],
            'select([.., DB::raw()])' => ["Visit::query()->select(['team_id', DB::raw('COUNT(*) as visits')])->groupBy('team_id')->get()"],
            'selectRaw()' => ["Visit::query()->selectRaw({$raw})->groupBy('team_id')->get()"],
            'addSelect(DB::raw())' => ["Visit::query()->addSelect(DB::raw({$raw}))->groupBy('team_id')->get()"],
            'static-root select(DB::raw())' => ["Visit::select(DB::raw({$raw}))->groupBy('team_id')->get()"],
            'DB::table()->select(DB::raw())' => ["DB::table('visits')->select(DB::raw({$raw}))->groupBy('team_id')->get()"],
            'plain select()' => ["Visit::query()->select('team_id')->groupBy('team_id')->get()"],
        ];
    }

    /**
     * @dataProvider boundedByFiltersProvider
     */
    #[DataProvider('boundedByFiltersProvider')]
    public function test_passes_a_fetch_its_filters_bound(string $fetch): void
    {
        // A list of keys caps the fetch at one row per key, and grouping on columns that
        // are each pinned to a list caps it at one row per combination of those lists.
        $this->assertPassed($this->analyzeVisitFetch($fetch));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function boundedByFiltersProvider(): array
    {
        $raw = "'team_id, day, MAX(created_at) as last_seen_at'";

        return [
            'whereIn on the key' => ["Visit::query()->whereIn('id', \$ids)->get()"],
            'whereIn on the qualified key' => ["Visit::query()->whereIn('visits.id', \$ids)->get()"],
            'static-root whereIn on the key' => ["Visit::whereIn('id', \$ids)->get()"],
            'whereKey()' => ['Visit::query()->whereKey($ids)->get()'],
            'key list with an orderBy' => ["Visit::query()->whereIn('id', \$ids)->orderBy('created_at')->orderByDesc('id')->get()"],
            'groupBy on whereIn columns' => ["Visit::query()->whereIn('team_id', \$teamIds)->whereIn('day', \$days)->selectRaw({$raw})->groupBy('team_id', 'day')->get()"],
            'groupBy array on an equality where' => ["Visit::query()->where('team_id', \$teamId)->select('team_id')->groupBy(['team_id'])->get()"],
            'groupBy on an explicit = where' => ["Visit::query()->where('team_id', '=', \$teamId)->select('team_id')->groupBy('team_id')->get()"],
            'key list already loaded by pluck()' => ["Visit::query()->whereIn('id', Pageview::query()->select('visit_id')->pluck('visit_id'))->get()"],
            'key list from a collection' => ["Visit::query()->whereIn('id', collect(\$ids)->unique())->get()"],
        ];
    }

    /**
     * @dataProvider unboundedByFiltersProvider
     */
    #[DataProvider('unboundedByFiltersProvider')]
    public function test_still_flags_a_fetch_its_filters_do_not_bound(string $fetch): void
    {
        $result = $this->analyzeVisitFetch($fetch);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unboundedByFiltersProvider(): array
    {
        return [
            'whereIn on a non-key column' => ["Visit::query()->whereIn('team_id', \$teamIds)->get()"],
            'whereNotIn on the key' => ["Visit::query()->whereNotIn('id', \$ids)->get()"],
            'key list widened by orWhere' => ["Visit::query()->whereIn('id', \$ids)->orWhere('pinned', true)->get()"],
            'groupBy on an unfiltered column' => ["Visit::query()->whereIn('team_id', \$teamIds)->groupBy('team_id', 'day')->get()"],
            'grouped filter widened by orWhereIn' => ["Visit::query()->whereIn('team_id', \$teamIds)->orWhereIn('day', \$days)->groupBy('team_id')->get()"],
            'groupBy on a range where' => ["Visit::query()->where('team_id', '>', \$teamId)->groupBy('team_id')->get()"],
            'Collection whereIn after all()' => ["Visit::all()->whereIn('id', \$ids)"],
            'Collection groupBy after get()' => ["Visit::query()->where('team_id', \$teamId)->get()->groupBy('team_id')"],
            'groupBy on a non-literal column' => ["Visit::query()->whereIn('team_id', \$teamIds)->groupBy('team_id', \$column)->get()"],
            'key list over a join' => ["Visit::query()->join('pageviews', 'pageviews.visit_id', '=', 'visits.id')->whereIn('visits.id', \$ids)->get()"],
            'key list over a leftJoin on DB::table()' => ["DB::table('visits')->leftJoin('pageviews', 'pageviews.visit_id', '=', 'visits.id')->whereIn('visits.id', \$ids)->get()"],
            'grouped filter over a crossJoin' => ["Visit::query()->crossJoin('days')->whereIn('team_id', \$teamIds)->groupBy('team_id')->get()"],
            'key list from a closure subquery' => ["Visit::query()->whereIn('id', function (\$query) { \$query->select('visit_id')->from('pageviews'); })->get()"],
            'key list from a model subquery' => ["Visit::query()->whereIn('id', Pageview::select('visit_id'))->get()"],
            'key list from a DB::table() subquery' => ["Visit::query()->whereIn('id', DB::table('pageviews')->select('visit_id'))->get()"],
            'whereKey() given a subquery' => ["Visit::query()->whereKey(Pageview::query()->select('visit_id'))->get()"],
            'groupBy pinned to an arrow fn subquery' => ["Visit::query()->whereIn('team_id', fn (\$query) => \$query->select('id')->from('teams'))->groupBy('team_id')->get()"],
        ];
    }

    /**
     * Analyze a service that assigns one fetch and loops over the rows it returns.
     */
    private function analyzeVisitFetch(string $fetch): ResultInterface
    {
        $code = <<<PHP
<?php

namespace App\Services;

use App\Models\Pageview;
use App\Models\Visit;
use Illuminate\Support\Facades\DB;

class VisitReport
{
    public function build(array \$ids, array \$teamIds, array \$days, int \$teamId, string \$column): void
    {
        \$rows = {$fetch};

        foreach (\$rows as \$row) {
            echo \$row->team_id;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/VisitReport.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        return $analyzer->analyze();
    }

    public function test_grammar_singular_vs_plural(): void
    {
        // Test singular
        $code1 = <<<'PHP'
<?php
namespace App\Services;
use App\Models\User;
class UserService
{
    public function process()
    {
        foreach (User::all() as $user) {}
    }
}
PHP;

        $tempDir1 = $this->createTempDirectory(['Services/UserService.php' => $code1]);
        $analyzer1 = $this->createAnalyzer();
        $analyzer1->setBasePath($tempDir1);
        $analyzer1->setPaths(['.']);
        $result1 = $analyzer1->analyze();

        $this->assertStringContainsString('1 query', $result1->getMessage());
        $this->assertStringNotContainsString('queries', $result1->getMessage());

        // Test plural
        $code2 = <<<'PHP'
<?php
namespace App\Services;
use App\Models\User;
class UserService
{
    public function process()
    {
        foreach (User::all() as $user) {}
        foreach (User::get() as $user) {}
    }
}
PHP;

        $tempDir2 = $this->createTempDirectory(['Services/UserService.php' => $code2]);
        $analyzer2 = $this->createAnalyzer();
        $analyzer2->setBasePath($tempDir2);
        $analyzer2->setPaths(['.']);
        $result2 = $analyzer2->analyze();

        $this->assertStringContainsString('2 queries', $result2->getMessage());
    }

    public function test_passes_when_looping_over_seeded_catalogue_table(): void
    {
        // Pillar is a fixed seeded reference catalogue (literal seeding, no factory), so
        // iterating Pillar::...->get() is bounded by construction — not a chunking problem.
        $seeder = <<<'PHP'
<?php

namespace Database\Seeders;

use App\Models\Pillar;

class PillarSeeder
{
    public function run(): void
    {
        Pillar::create(['slug' => 'governance']);
        Pillar::create(['slug' => 'risk']);
    }
}
PHP;

        $service = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Pillar;

class AssessmentService
{
    public function codes(): void
    {
        foreach (Pillar::with('questions')->orderBy('display_order')->get() as $pillar) {
            // map each pillar's questions
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Services/AssessmentService.php' => $service,
            'database/seeders/PillarSeeder.php' => $seeder,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_flags_non_catalogue_table_even_when_a_catalogue_exists(): void
    {
        // Pillar is a seeded catalogue, but the loop reads users (not seeded). The guard is
        // table-specific, so the unbounded users loop is still flagged.
        $seeder = <<<'PHP'
<?php

namespace Database\Seeders;

use App\Models\Pillar;

class PillarSeeder
{
    public function run(): void
    {
        Pillar::create(['slug' => 'governance']);
    }
}
PHP;

        $service = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function process(): void
    {
        foreach (User::where('active', true)->get() as $user) {
            // process user
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Services/UserService.php' => $service,
            'database/seeders/PillarSeeder.php' => $seeder,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('get()', $result);
    }

    public function test_flags_factory_seeded_table_loop(): void
    {
        // A table seeded via factory grows with volume — not a fixed catalogue, still flagged.
        $seeder = <<<'PHP'
<?php

namespace Database\Seeders;

use App\Models\User;

class UserSeeder
{
    public function run(): void
    {
        User::factory()->count(50)->create();
    }
}
PHP;

        $service = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function process(): void
    {
        foreach (User::where('active', true)->get() as $user) {
            // process user
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Services/UserService.php' => $service,
            'database/seeders/UserSeeder.php' => $seeder,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('get()', $result);
    }

    public function test_downgrades_relationship_accessor_read_to_warning(): void
    {
        // A read rooted at an instance relationship accessor ($order->lineItems()) reads one
        // parent's children — far more often bounded than a table-wide scan — so it is a warning,
        // not a hard failure.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function totals(Order $order): void
    {
        foreach ($order->lineItems()->get() as $line) {
            // sum each line
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('get()', $result);
    }

    public function test_downgrades_variable_assigned_relationship_read_to_warning(): void
    {
        // Same downgrade applies when the relationship read is assigned to a variable first.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function totals(Order $order): void
    {
        $lines = $order->lineItems()->get();
        foreach ($lines as $line) {
            // sum each line
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('variable', $result);
    }

    public function test_static_scan_still_fails_when_mixed_with_relationship_read(): void
    {
        // A table-wide Model::all() scan stays High, so a file mixing it with a downgraded
        // relationship read still fails overall (High dominates).
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;
use App\Models\User;

class ReportService
{
    public function build(Order $order): void
    {
        foreach (User::all() as $user) {
            // process user
        }

        foreach ($order->lineItems()->get() as $line) {
            // sum each line
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReportService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(2, $result->getIssues());
    }

    public function test_passes_with_cache_facade_get(): void
    {
        $code = <<<'PHP'
<?php
namespace App\Services;
use Illuminate\Support\Facades\Cache;
class CartService {
    public function render() {
        foreach (Cache::get('cart.items', []) as $item) { echo $item; }
    }
}
PHP;
        $tempDir = $this->createTempDirectory(['Services/CartService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);
        $this->assertPassed($analyzer->analyze());
    }

    public function test_passes_with_http_client_json(): void
    {
        $code = <<<'PHP'
<?php
namespace App\Services;
use Illuminate\Support\Facades\Http;
class ApiService {
    public function sync() {
        foreach (Http::get('https://api.example.com/items')->json() as $item) { echo $item; }
    }
}
PHP;
        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);
        $this->assertPassed($analyzer->analyze());
    }

    public function test_passes_with_request_facade_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Request;

class ImportController
{
    public function store()
    {
        // Request::all() returns HTTP input, NOT database records
        foreach (Request::all() as $key => $value) {
            echo $key;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Controllers/ImportController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_passes_with_variable_assigned_from_facade_get(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;

class BasketService
{
    public function render()
    {
        $items = Cache::get('basket.items', []);

        foreach ($items as $item) {
            echo $item;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/BasketService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_still_flags_model_scan_alongside_facade_read(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\Cache;

class DigestService
{
    public function send()
    {
        foreach (Cache::get('digest.settings', []) as $setting) {
            echo $setting;
        }

        foreach (User::where('active', true)->get() as $user) {
            echo $user->email;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DigestService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('->get()', $result);
    }

    public function test_still_flags_model_whose_name_matches_a_facade(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Event;

class ScheduleService
{
    public function rebuild()
    {
        foreach (Event::all() as $event) {
            echo $event->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ScheduleService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('->all()', $result);
    }

    public function test_still_flags_model_named_like_a_facade_through_a_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\File;

class ArchiveService
{
    public function archive()
    {
        $files = File::where('archived', false)->get();

        foreach ($files as $file) {
            echo $file->path;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ArchiveService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_passes_with_aliased_facade_import(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache as C;

class AliasService
{
    public function render()
    {
        foreach (C::get('menu.items', []) as $item) {
            echo $item;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/AliasService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_passes_with_unqualified_facade_alias_in_global_namespace(): void
    {
        $code = <<<'PHP'
<?php

class LegacyReport
{
    public function render()
    {
        foreach (Cache::get('report.rows', []) as $row) {
            echo $row;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['LegacyReport.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_still_flags_rows_reached_through_the_request_facade(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Request;

class OrderHistory
{
    public function render()
    {
        foreach (Request::user()->orders()->get() as $order) {
            echo $order->id;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderHistory.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('->get()', $result);
    }

    public function test_a_closure_does_not_erase_the_enclosing_method_assignments(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function process()
    {
        $users = User::all();

        $format = function (string $name): string {
            return strtoupper($name);
        };

        foreach ($users as $user) {
            echo $format($user->name);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('assigned with ->all() or ->get()', $result);
    }

    public function test_an_assignment_inside_a_closure_does_not_escape_it(): void
    {
        // The outer $users is a cursor, which is the remedy this analyzer recommends.
        // The closure's own same-named variable must not make it look unbounded.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function process()
    {
        $users = User::cursor();

        $warm = function (): void {
            $users = User::all();
            $users->count();
        };

        $warm();

        foreach ($users as $user) {
            echo $user->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_a_by_reference_assignment_inside_a_closure_does_escape_it(): void
    {
        // The closure rebinds the outer $users by reference, and it rebinds it to a cursor,
        // which is the remedy this analyzer recommends. The loop below reads that cursor.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function process()
    {
        $users = User::all();

        $swap = function () use (&$users): void {
            $users = User::cursor();
        };

        $swap();

        foreach ($users as $user) {
            echo $user->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_a_by_reference_rebind_to_an_unbounded_fetch_is_still_reported(): void
    {
        // The mirror of the test above: a by-reference rebind that makes the variable
        // unbounded must be picked up, so the fix cannot simply drop the name and go quiet.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function process()
    {
        $users = User::cursor();

        $swap = function () use (&$users): void {
            $users = User::all();
        };

        $swap();

        foreach ($users as $user) {
            echo $user->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('assigned with ->all() or ->get()', $result);
    }

    public function test_a_closure_sees_the_collection_it_captured_by_reference(): void
    {
        // The other direction of the same capture: what travels in, rather than out. The
        // closure did not fetch this collection, it was handed the caller's variable, so a
        // loop over it inside the closure reads the same unbounded result set.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function process()
    {
        $users = User::all();

        $warm = function () use (&$users): void {
            foreach ($users as $user) {
                echo $user->name;
            }
        };

        $warm();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('assigned with ->all() or ->get()', $result);
    }

    public function test_a_closure_sees_the_collection_it_captured_by_value(): void
    {
        // A by-value capture is a copy, but a copy of the same unbounded result set, so the
        // loop over it inside the closure loads every row just the same.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Account;

class ReminderService
{
    public function send()
    {
        $accounts = Account::all();

        retry(3, function () use ($accounts): void {
            foreach ($accounts as $account) {
                $account->notify();
            }
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReminderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertHasIssueContaining('assigned with ->all() or ->get()', $result);
    }

    public function test_a_by_value_capture_rebound_inside_a_closure_leaves_the_caller_unbounded(): void
    {
        // The closure replaced its own copy with something bounded. The caller's variable still
        // holds the full result set, so the loop after the closure is still reported.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Account;

class ReminderService
{
    public function send()
    {
        $accounts = Account::all();

        $trim = function () use ($accounts): void {
            $accounts = collect();
        };

        $trim();

        foreach ($accounts as $account) {
            $account->notify();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReminderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
    }

    public function test_a_by_value_capture_rebound_to_a_fetch_inside_a_closure_does_not_reach_the_caller(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Account;

class ReminderService
{
    public function send()
    {
        $accounts = collect();

        $load = function () use ($accounts): void {
            $accounts = Account::all();
        };

        $load();

        foreach ($accounts as $account) {
            $account->notify();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReminderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_a_closure_inside_an_arrow_function_sees_what_the_arrow_function_captured(): void
    {
        // An arrow function captures by value every enclosing name its body reads, including
        // the names a closure nested in it captures in turn.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Account;

class ReminderService
{
    public function sender(): callable
    {
        $accounts = Account::all();

        return fn () => function () use ($accounts): void {
            foreach ($accounts as $account) {
                $account->notify();
            }
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReminderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
    }

    public function test_an_arrow_function_parameter_shadows_the_enclosing_name(): void
    {
        // A parameter is a variable of the arrow function's own, so an enclosing local of the
        // same name is not what the body reads, and not what a closure nested in it captures.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Account;

class ReminderService
{
    public function sender(): callable
    {
        $accounts = Account::all();

        return fn (array $accounts) => function () use ($accounts): void {
            foreach ($accounts as $account) {
                $account->notify();
            }
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReminderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_resolves_the_names_that_do_not_collide_in_a_file_php_would_reject(): void
    {
        // Giving up on the whole file costs more than the alias that collided. Matching falls
        // back to every name as written, so `Event` takes the Event facade's exemption on its
        // last segment and the unchunked loop it guards goes unreported. `Event` does not
        // collide, so it still resolves, and the model it names is no facade.
        //
        // Only `Cache` is ambiguous here, and the import table records the collision and keeps
        // the first spelling. That is observable rather than merely documented: the first `use`
        // names the facade, which is exempt, so the `Cache` loop must stay unreported. Were the
        // last spelling to win instead, `App\Models\Cache` is no facade and that loop would be
        // reported too.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Event;
use Illuminate\Support\Facades\Cache;
use App\Models\Cache;

class Probe
{
    public function run()
    {
        foreach (Event::all() as $event) {
            echo $event->id;
        }

        foreach (Cache::get('rows', []) as $row) {
            echo $row;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Probe.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);

        // The message names no class, so the line is what says which loop was reported: the
        // Event read, not the Cache read below it.
        $issues = array_values($result->getIssues());
        $this->assertSame(13, $issues[0]->location?->line);
    }

    public function test_does_not_write_resolution_into_the_shared_parser_cache(): void
    {
        // A resolving pass does not leave the tree it read alone. With replaceNodes off the
        // Name survives, but a resolvedName attribute and a namespacedName on the declaration
        // take its place, and parseFile() hands back a shared, mtime-cached tree, so both
        // outlive this analyzer. Collecting imports during the walk writes nothing, and this
        // visitor is the only one in its traverser, so the walk is cache-clean in full rather
        // than in part. Both halves are asserted, so reinstating a resolving pass fails here
        // instead of in whatever later reads the attribute.
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;

class Report
{
    public function render()
    {
        foreach (Cache::get('report.rows', []) as $row) {
            echo $row;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Report.php' => $code]);

        // Parse first and keep the nodes, so what is inspected afterwards is the very tree the
        // analyzer was handed rather than a second parse of the same file. The cache is keyed
        // by path and mtime with no normalisation, so setPaths() below has to name 'Services'
        // and not '.', or the analyzer would look up '<dir>/./Services/Report.php' and get its
        // own entry.
        $path = $tempDir.'/Services/Report.php';
        $ast = $this->parser->parseFile($path);

        /** @var array<int, Node\Expr\StaticCall> $calls */
        $calls = $this->parser->findNodes($ast, Node\Expr\StaticCall::class);
        $this->assertCount(1, $calls);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['Services']);

        $this->assertPassed($analyzer->analyze());

        // The setPaths() spelling above is load-bearing, so what it buys is asserted rather
        // than left to the comment explaining it. assertPassed() cannot carry that weight: it
        // reads the same whether the file was scanned and exempted, scanned in a tree of its
        // own, or never scanned at all. One cache entry for this path is the difference. Two
        // would mean the analyzer parsed a second spelling of the same file and left the tree
        // below pristine for the wrong reason, which is how a reinstated resolving pass would
        // slip through here.
        $this->assertSame(1, $this->cachedTreesFor($path));

        /** @var array<int, Node\Expr\StaticCall> $reparsed */
        $reparsed = $this->parser->findNodes($this->parser->parseFile($path), Node\Expr\StaticCall::class);
        $this->assertSame($calls[0], $reparsed[0]);

        $class = $calls[0]->class;
        if (! $class instanceof Node\Name) {
            self::fail('Expected the static call to name a class.');
        }

        $this->assertSame(Node\Name::class, $class::class);
        $this->assertNull($class->getAttribute('resolvedName'));

        /** @var array<int, Node\Stmt\Class_> $declarations */
        $declarations = $this->parser->findNodes($ast, Node\Stmt\Class_::class);
        $this->assertCount(1, $declarations);
        $this->assertFalse(isset($declarations[0]->namespacedName));
    }

    public function test_exempts_a_facade_imported_through_a_group_use(): void
    {
        // The prefix of a group use is joined onto each name by hand, so a facade imported
        // this way is exempt only if that join is right.
        // A flagged read shares the file so that the exemption is told apart from the file
        // never being reached: runAnalysis() swallows a per-file throw and reports a pass, so
        // an assertPassed() on a fixture with nothing to find would go green on a file
        // trackImports() had thrown on. One issue, on the model's line, says the walk ran and
        // exempted the facade read rather than skipping both.
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\{Cache, Http};
use App\Models\Item;

class MenuService
{
    public function render()
    {
        foreach (Cache::get('menu.items', []) as $item) {
            echo $item;
        }

        foreach (Item::all() as $item) {
            echo $item->id;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MenuService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);

        $issues = array_values($result->getIssues());
        $this->assertSame(16, $issues[0]->location?->line);
    }

    public function test_exempts_a_fully_qualified_facade_reference(): void
    {
        // A leading backslash needs no import to resolve, and must not need one to be exempt.
        // A flagged read shares the file so that the exemption is told apart from the file
        // never being reached: runAnalysis() swallows a per-file throw and reports a pass, so
        // an assertPassed() on a fixture with nothing to find would go green on a file
        // trackImports() had thrown on. One issue, on the model's line, says the walk ran and
        // exempted the facade read rather than skipping both.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Receipt;

class ReportService
{
    public function render()
    {
        foreach (\Illuminate\Support\Facades\Cache::get('report.rows', []) as $row) {
            echo $row;
        }

        foreach (Receipt::all() as $receipt) {
            echo $receipt->id;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReportService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);

        $issues = array_values($result->getIssues());
        $this->assertSame(15, $issues[0]->location?->line);
    }

    public function test_flags_an_unimported_facade_spelling_in_a_namespaced_file(): void
    {
        // `Cache` with no import inside a namespace is App\Services\Cache, which is a class of
        // the application's own and no facade. The global-namespace spelling is the one that
        // earns the exemption on its last segment, and it is covered separately.
        $code = <<<'PHP'
<?php

namespace App\Services;

class LedgerService
{
    public function render()
    {
        foreach (Cache::get('ledger.rows', []) as $row) {
            echo $row;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LedgerService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_exempts_a_facade_imported_under_an_alias(): void
    {
        // An alias reaches resolution through a branch of NameContext that a plain import does
        // not, and it is the branch deciding whether `C::get()` is the Cache facade or a class
        // of the application's own called C. The model read alongside it says the walk ran.
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache as C;
use App\Models\Invoice;

class BillingService
{
    public function render()
    {
        foreach (C::get('billing.rows', []) as $row) {
            echo $row;
        }

        foreach (Invoice::all() as $invoice) {
            echo $invoice->id;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/BillingService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);

        $issues = array_values($result->getIssues());
        $this->assertSame(16, $issues[0]->location?->line);
    }

    public function test_does_not_carry_an_import_across_a_namespace_block(): void
    {
        // `use` is scoped to the namespace block it sits in, so the second block's `Cache` is
        // App\Reports\Cache, a class of the application's own, and looping over what it returns
        // is a row read. The first block's is the facade and stays exempt. One issue rather
        // than none says the table was reset on entering the second block; one rather than two
        // says the first block still resolved.
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;

class WarmService
{
    public function render()
    {
        foreach (Cache::get('warm.rows', []) as $row) {
            echo $row;
        }
    }
}

namespace App\Reports;

class LedgerReport
{
    public function render()
    {
        foreach (Cache::get('ledger.rows', []) as $row) {
            echo $row;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/TwoBlocks.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);

        $issues = array_values($result->getIssues());
        $this->assertSame(23, $issues[0]->location?->line);
    }

    public function test_does_not_apply_an_import_written_after_the_code_it_would_affect(): void
    {
        // PHP adds an import to the table where it reads the `use`, not for the whole block:
        // ahead of the one below, `Cache` is App\Services\Cache, and only code after it sees
        // the facade. Collecting imports as the walk reaches them is what matches that, so the
        // loop here is a row read and is reported. Were the table instead filled from the
        // namespace's statement list before the walk, the facade would exempt a class PHP
        // resolves to something else, which is the mismatch #423 was filed about.
        $code = <<<'PHP'
<?php

namespace App\Services;

class LedgerService
{
    public function render()
    {
        foreach (Cache::get('ledger.rows', []) as $row) {
            echo $row;
        }
    }
}

use Illuminate\Support\Facades\Cache;
PHP;

        $tempDir = $this->createTempDirectory(['Services/LedgerService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);

        $issues = array_values($result->getIssues());
        $this->assertSame(9, $issues[0]->location?->line);
    }
}
