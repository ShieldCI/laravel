<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\HelperFunctionAbuseAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class HelperFunctionAbuseAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'helper-function-abuse' => [
                            'threshold' => 5,
                        ],
                    ],
                ],
            ],
        ]);

        return new HelperFunctionAbuseAnalyzer($this->parser, $config);
    }

    public function test_detects_excessive_helper_usage(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        $user = auth()->user();
        $data = request()->all();
        cache()->put('key', 'value', 3600);
        logger()->info('Order created');
        event(new OrderCreated());
        session()->flash('success', 'Order created');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('helper', $result);
    }

    public function test_passes_with_dependency_injection(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function __construct(
        private OrderService $orders,
        private CacheManager $cache
    ) {}

    public function store(Request $request)
    {
        $user = $request->user();
        $order = $this->orders->create($request->all());
        $this->cache->put('order', $order, 3600);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_exactly_at_threshold_passes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        $user = auth()->user();
        $data = request()->all();
        cache()->put('key', 'value', 3600);
        logger()->info('Order created');
        event(new OrderCreated());
        // Exactly 5 helpers (threshold)
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_just_below_threshold_passes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        $user = auth()->user();
        $data = request()->all();
        cache()->put('key', 'value', 3600);
        logger()->info('Order created');
        // Only 4 helpers (below threshold)
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_severity_escalation_medium(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        // All dependency-hiding helpers (counted by default)
        auth()->user();
        request()->all();
        cache()->put('a', 'b');
        logger()->info('1');
        event(new E1());
        session()->put('a', 'b');
        config('app.name');
        route('home');
        view('home');
        url('home');
        redirect()->back();
        response()->json([]);
        app()->make('service');
        abort(404);
        dispatch(new Job());
        // 15 dependency-hiding helpers = 10 over threshold (Medium severity)
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('medium', $issues[0]->severity->value);
    }

    public function test_severity_escalation_high(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class MassiveController
{
    public function store()
    {
        // All dependency-hiding helpers (counted by default)
        app()->make('service1');
        auth()->user();
        cache()->put('a', 'b');
        config('app.name');
        cookie('name', 'value');
        event(new E1());
        logger()->info('1');
        old('field');
        redirect()->back();
        request()->all();
        response()->json([]);
        route('home');
        session()->put('a', 'b');
        storage_path('app');
        url('home');
        view('home');
        abort(404);
        abort_if(false, 404);
        abort_unless(true, 404);
        dispatch(new Job());
        info('test');
        policy(User::class);
        resolve(Service::class);
        validator([], []);
        report(new Exception());
        // Need more to hit 26 total (21+ over threshold = High)
        auth()->check();
        // 26 dependency-hiding helpers = 21 over threshold (High severity)
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/MassiveController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('high', $issues[0]->severity->value);
    }

    public function test_custom_threshold_configuration(): void
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'helper-function-abuse' => [
                            'threshold' => 3, // Custom threshold
                        ],
                    ],
                ],
            ],
        ]);

        $analyzer = new HelperFunctionAbuseAnalyzer($this->parser, $config);

        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        auth()->user();
        request()->all();
        cache()->put('key', 'value');
        logger()->info('Order created');
        // 4 helpers - fails with threshold of 3
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_custom_helper_functions_list(): void
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'helper-function-abuse' => [
                            'threshold' => 2,
                            'helper_functions' => ['auth', 'request'], // Only track these two
                        ],
                    ],
                ],
            ],
        ]);

        $analyzer = new HelperFunctionAbuseAnalyzer($this->parser, $config);

        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        auth()->user();
        request()->all();
        cache()->put('key', 'value'); // Not tracked
        logger()->info('test'); // Not tracked
        event(new OrderCreated()); // Not tracked
        session()->put('a', 'b'); // Not tracked
        // Only auth() and request() count = 2, but that's at threshold, so passes
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_empty_helper_functions_array_uses_defaults(): void
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'helper-function-abuse' => [
                            'threshold' => 5,
                            'helper_functions' => [], // Empty array should use defaults
                        ],
                    ],
                ],
            ],
        ]);

        $analyzer = new HelperFunctionAbuseAnalyzer($this->parser, $config);

        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        auth()->user();
        request()->all();
        cache()->put('key', 'value', 3600);
        logger()->info('Order created');
        event(new OrderCreated());
        session()->flash('success', 'Order created');
        // 6 default helpers should be detected
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_multiple_classes_in_same_file(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class GoodController
{
    public function index()
    {
        // No helpers - should pass
    }
}

class BadController
{
    public function store()
    {
        auth()->user();
        request()->all();
        cache()->put('key', 'value', 3600);
        logger()->info('Order created');
        event(new OrderCreated());
        session()->flash('success', 'Order created');
        // 6 helpers - should fail
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/Controllers.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('BadController', $issues[0]->message);
    }

    public function test_anonymous_classes_are_skipped(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

$controller = new class {
    public function store()
    {
        auth()->user();
        request()->all();
        cache()->put('key', 'value', 3600);
        logger()->info('Order created');
        event(new OrderCreated());
        session()->flash('success', 'Order created');
        // 6 helpers but in anonymous class - should be skipped
    }
};
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AnonymousController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_helper_used_multiple_times(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        auth()->check();
        auth()->user();
        auth()->id();
        auth()->guest();
        auth()->guard('api');
        auth()->viaRemember();
        // auth() called 6 times
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals(6, $issues[0]->metadata['count']);
    }

    public function test_empty_php_file(): void
    {
        $code = <<<'PHP'
<?php

// Empty file with no classes
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Empty.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_file_with_no_classes(): void
    {
        $code = <<<'PHP'
<?php

function helper_function() {
    return auth()->user();
}

$variable = request()->all();
PHP;

        $tempDir = $this->createTempDirectory([
            'app/helpers.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_trait_with_excessive_helpers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Traits;

trait LoggableTrait
{
    public function logActivity()
    {
        auth()->user();
        request()->ip();
        cache()->remember('key', 3600, function() { return 'value'; });
        logger()->info('Activity logged');
        event(new ActivityLogged());
        session()->put('last_activity', now());
        // 6 helpers in trait - should fail
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Traits/LoggableTrait.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('LoggableTrait', $result);
    }

    public function test_class_with_no_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

class EmptyModel
{
    // No methods or properties
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/EmptyModel.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_mixed_helpers_different_counts(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        auth()->user();
        auth()->check();
        request()->all();
        cache()->put('key', 'value');
        logger()->info('test');
        logger()->error('error');
        event(new OrderCreated());
        // auth: 2, request: 1, cache: 1, logger: 2, event: 1 = 7 total
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals(7, $issues[0]->metadata['count']);
        $this->assertEquals(2, $issues[0]->metadata['helpers']['auth']);
        $this->assertEquals(2, $issues[0]->metadata['helpers']['logger']);
    }

    public function test_code_snippet_is_included(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        $user = auth()->user();
        $data = request()->all();
        cache()->put('key', 'value', 3600);
        logger()->info('Order created');
        event(new OrderCreated());
        session()->flash('success', 'Order created');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotNull($issues[0]->codeSnippet);
        $this->assertNotEmpty($issues[0]->codeSnippet->getLines());
    }

    // ============================================================
    // Tests for whitelist functionality (false positive reduction)
    // ============================================================

    public function test_excludes_service_providers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Providers;

class AppServiceProvider
{
    public function boot()
    {
        auth()->user();
        request()->all();
        cache()->put('key', 'value');
        logger()->info('test');
        event(new Event());
        session()->put('a', 'b');
        config('app.name');
        // 7 helpers but in ServiceProvider - should pass
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_console_commands(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Console\Commands;

class SyncUsersCommand
{
    public function handle()
    {
        auth()->user();
        request()->all();
        cache()->put('key', 'value');
        logger()->info('test');
        event(new Event());
        session()->put('a', 'b');
        config('app.name');
        // 7 helpers but in Command - should pass
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Console/Commands/SyncUsersCommand.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_test_directory(): void
    {
        $code = <<<'PHP'
<?php

namespace Tests\Feature;

class OrderTest
{
    public function test_order_creation()
    {
        auth()->user();
        request()->all();
        cache()->put('key', 'value');
        logger()->info('test');
        event(new Event());
        session()->put('a', 'b');
        // 6 helpers but in tests directory - should pass
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'tests/Feature/OrderTest.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['tests']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_seeders(): void
    {
        $code = <<<'PHP'
<?php

namespace Database\Seeders;

class UserSeeder
{
    public function run()
    {
        auth()->user();
        request()->all();
        cache()->put('key', 'value');
        logger()->info('test');
        event(new Event());
        session()->put('a', 'b');
        // 6 helpers but in Seeder - should pass
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'database/seeders/UserSeeder.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['database']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_database_migrations(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Database\Migrations\Migration;

class CreateUsersTable extends Migration
{
    public function up()
    {
        app()->make('config');
        config('app.name');
        cache()->put('key', 'value');
        logger()->info('test');
        event(new Event());
        session()->put('a', 'b');
        // 6 helpers but in migrations directory - should pass
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'database/migrations/2024_01_01_000000_create_users_table.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['database']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_utility_helpers_not_counted_by_default(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        // Utility helpers (should NOT be counted)
        collect([1, 2, 3]);
        tap($object, fn($x) => $x);
        value(fn() => 'result');
        optional($user)->name;
        now();
        today();

        // Only 2 dependency-hiding helpers (below threshold)
        auth()->user();
        request()->all();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_dd_not_counted(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        // Debug helpers (handled by DebugModeAnalyzer, not counted here)
        dd($data);
        dump($info);

        // Only 4 dependency-hiding helpers (below threshold of 5)
        auth()->user();
        request()->all();
        cache()->put('key', 'value');
        logger()->info('test');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_custom_whitelist_dirs(): void
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'helper-function-abuse' => [
                            'threshold' => 5,
                            'whitelist_dirs' => ['app/Internal'], // Custom whitelist
                        ],
                    ],
                ],
            ],
        ]);

        $analyzer = new HelperFunctionAbuseAnalyzer($this->parser, $config);

        $code = <<<'PHP'
<?php

namespace App\Internal;

class InternalService
{
    public function process()
    {
        auth()->user();
        request()->all();
        cache()->put('key', 'value');
        logger()->info('test');
        event(new Event());
        session()->put('a', 'b');
        // 6 helpers but in whitelisted directory
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Internal/InternalService.php' => $code,
        ]);

        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_custom_whitelist_classes(): void
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'helper-function-abuse' => [
                            'threshold' => 5,
                            'whitelist_classes' => ['*Handler', '*Manager'], // Custom class patterns
                        ],
                    ],
                ],
            ],
        ]);

        $analyzer = new HelperFunctionAbuseAnalyzer($this->parser, $config);

        $code = <<<'PHP'
<?php

namespace App\Http;

class ExceptionHandler
{
    public function report()
    {
        auth()->user();
        request()->all();
        cache()->put('key', 'value');
        logger()->info('test');
        event(new Event());
        session()->put('a', 'b');
        // 6 helpers but in whitelisted class pattern (*Handler)
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/ExceptionHandler.php' => $code,
        ]);

        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_controller_with_mixed_helpers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        // 5 dependency-hiding helpers (at threshold - passes)
        auth()->user();
        request()->all();
        cache()->put('key', 'value');
        logger()->info('test');
        event(new Event());

        // These should NOT be counted:
        collect([1, 2, 3]);  // utility
        tap($obj, fn($x) => $x);  // utility
        now();  // utility
        dd($debug);  // debug
        bcrypt('password');  // low priority
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_backward_compatibility_custom_helper_list(): void
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'helper-function-abuse' => [
                            'threshold' => 2,
                            // Custom helper_functions should override categorization
                            'helper_functions' => ['auth', 'request', 'collect'],
                        ],
                    ],
                ],
            ],
        ]);

        $analyzer = new HelperFunctionAbuseAnalyzer($this->parser, $config);

        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function store()
    {
        // Custom list includes collect (normally utility)
        auth()->user();
        request()->all();
        collect([1, 2, 3]);
        // 3 helpers from custom list - exceeds threshold of 2
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals(3, $issues[0]->metadata['count']);
    }
}
