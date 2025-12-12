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
                    'best_practices' => [
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
        collect([1,2,3]);
        now();
        today();
        // 15 helpers = 10 over threshold (Medium severity)
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
        collect([1,2,3]);
        now();
        today();
        abort(404);
        bcrypt('pass');
        dispatch(new Job());
        info('test');
        optional($x)->method();
        policy(User::class);
        resolve(Service::class);
        retry(5, function() { return true; });
        tap($obj, function($x) { return $x; });
        throw_if(true, 'error');
        validator([], []);
        value(function() { return 123; });
        // 26 helpers = 21 over threshold (High severity)
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
                    'best_practices' => [
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
                    'best_practices' => [
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
                    'best_practices' => [
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
}
