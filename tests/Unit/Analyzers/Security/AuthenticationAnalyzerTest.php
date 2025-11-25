<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\AuthenticationAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class AuthenticationAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new AuthenticationAnalyzer($this->parser);
    }

    // ==========================================
    // Controller Authentication Tests
    // ==========================================

    public function test_passes_with_auth_middleware(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class DashboardController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
    }

    public function index()
    {
        return view('dashboard');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/DashboardController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_sensitive_methods_without_auth(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController extends Controller
{
    public function destroy($id)
    {
        User::destroy($id);
        return redirect()->back();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('destroy', $result);
    }

    public function test_detects_multiple_sensitive_methods_without_auth(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController extends Controller
{
    public function store()
    {
        return Post::create(request()->all());
    }

    public function update($id)
    {
        Post::find($id)->update(request()->all());
    }

    public function destroy($id)
    {
        Post::destroy($id);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/PostController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
        $this->assertHasIssueContaining('store', $result);
        $this->assertHasIssueContaining('update', $result);
        $this->assertHasIssueContaining('destroy', $result);
    }

    public function test_passes_with_authorize_in_method(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController extends Controller
{
    public function destroy($id)
    {
        $this->authorize('delete', Post::find($id));
        Post::destroy($id);
        return redirect()->back();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/PostController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_gate_check(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Gate;

class PostController extends Controller
{
    public function destroy($id)
    {
        Gate::authorize('delete-post');
        Post::destroy($id);
        return redirect()->back();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/PostController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_gate_allows_check(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Gate;

class PostController extends Controller
{
    public function update($id)
    {
        Gate::allows('update-post');
        Post::find($id)->update(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/PostController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_can_method(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController extends Controller
{
    public function destroy($id)
    {
        $post = Post::find($id);
        $post->can('delete');
        $post->delete();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/PostController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_construct_and_invoke_methods(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class TestController extends Controller
{
    public function __construct()
    {
        // Constructor - should be skipped
    }

    public function __invoke()
    {
        // Invoke method - should be skipped
        return 'test';
    }

    public function middleware()
    {
        // Middleware method - should be skipped
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/TestController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_non_public_methods(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController extends Controller
{
    private function destroy($id)
    {
        Post::destroy($id);
    }

    protected function update($id)
    {
        Post::find($id)->update(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/PostController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_when_no_controllers_found(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        // Should skip when no routes or controllers exist
        $this->assertFalse($analyzer->shouldRun());
    }

    // ==========================================
    // Route Authentication Tests
    // ==========================================

    public function test_detects_post_route_without_auth_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/users', [UserController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_detects_put_route_without_auth_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::put('/users/{id}', [UserController::class, 'update']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('PUT route without authentication middleware', $result);
    }

    public function test_detects_patch_route_without_auth_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::patch('/users/{id}', [UserController::class, 'update']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('PATCH route without authentication middleware', $result);
    }

    public function test_detects_delete_route_without_auth_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::delete('/users/{id}', [UserController::class, 'destroy']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('DELETE route without authentication middleware', $result);
    }

    public function test_detects_resource_route_without_auth_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::resource('posts', PostController::class);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('RESOURCE route without authentication middleware', $result);
    }

    public function test_detects_api_resource_route_without_auth_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::apiResource('posts', PostController::class);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('APIRESOURCE route without authentication middleware', $result);
    }

    public function test_passes_with_route_auth_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/users', [UserController::class, 'store'])->middleware('auth');
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_route_auth_middleware_array(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/users', [UserController::class, 'store'])->middleware(['auth', 'verified']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_multiline_route_auth_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/users', [UserController::class, 'store'])
    ->name('users.store')
    ->middleware('auth');
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_get_routes_without_auth(): void
    {
        $routes = <<<'PHP'
<?php

Route::get('/about', [PageController::class, 'about']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_public_login_route(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/login', [AuthController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_public_register_route(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/register', [AuthController::class, 'register']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_password_reset_routes(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/password/reset', [PasswordController::class, 'reset']);
Route::post('/forgot-password', [PasswordController::class, 'forgot']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_health_check_routes(): void
    {
        $routes = <<<'PHP'
<?php

Route::get('/health', fn() => 'OK');
Route::get('/status', fn() => 'UP');
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==========================================
    // Route Group Tests
    // ==========================================

    public function test_detects_route_group_without_auth_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['prefix' => 'admin'], function () {
    Route::get('/dashboard', [AdminController::class, 'dashboard']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Medium severity issues result in warning status
        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('Route group without authentication middleware', $result);
    }

    public function test_passes_with_route_group_auth_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => 'auth', 'prefix' => 'admin'], function () {
    Route::get('/dashboard', [AdminController::class, 'dashboard']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_routes_in_middleware_group_without_explicit_auth(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware(['auth'])->group(function () {
    Route::post('/posts', [PostController::class, 'store']);
    Route::delete('/posts/{id}', [PostController::class, 'destroy']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // The analyzer checks individual routes, not the middleware() wrapper
        // This is a limitation - it only detects ->middleware('auth') on routes, not Route::middleware()
        $this->assertFalse($result->isSuccess());
    }

    public function test_detects_route_group_even_with_public_route_names(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['prefix' => 'auth'], function () {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/register', [AuthController::class, 'register']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Route group itself is flagged (prefix contains 'auth' but that's just a name)
        // The individual routes inside are skipped because they contain 'login' and 'register'
        $this->assertFalse($result->isSuccess());
    }

    // ==========================================
    // Auth::user() Safety Tests
    // ==========================================

    public function test_detects_unsafe_auth_user_without_null_check(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class ProfileController extends Controller
{
    public function show()
    {
        $name = Auth::user()->name;
        return view('profile', ['name' => $name]);
    }
}
PHP;

        $routes = '<?php';  // Empty routes file so shouldRun() passes

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ProfileController.php' => $controller,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Medium severity issues result in warning status
        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('Unsafe Auth::user() usage without null check', $result);
    }

    public function test_passes_with_auth_check_before_usage(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class ProfileController extends Controller
{
    public function show()
    {
        if (Auth::check()) {
            $name = Auth::user()->name;
            return view('profile', ['name' => $name]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/ProfileController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_if_auth_user_check(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class ProfileController extends Controller
{
    public function show()
    {
        if (Auth::user()) {
            $name = Auth::user()->name;
            return view('profile', ['name' => $name]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/ProfileController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_unsafe_auth_helper_user_without_null_check(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ProfileController extends Controller
{
    public function show()
    {
        $email = auth()->user()->email;
        return view('profile', ['email' => $email]);
    }
}
PHP;

        $routes = '<?php';  // Empty routes file so shouldRun() passes

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ProfileController.php' => $controller,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Medium severity issues result in warning status
        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('Unsafe auth()->user() usage without null check', $result);
    }

    public function test_passes_with_auth_helper_check_before_usage(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ProfileController extends Controller
{
    public function show()
    {
        if (auth()->check()) {
            $email = auth()->user()->email;
            return view('profile', ['email' => $email]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/ProfileController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_if_auth_helper_user_check(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ProfileController extends Controller
{
    public function show()
    {
        if (auth()->user()) {
            $email = auth()->user()->email;
            return view('profile', ['email' => $email]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/ProfileController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_multiple_unsafe_auth_usages(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class ProfileController extends Controller
{
    public function show()
    {
        $name = Auth::user()->name;
        $email = auth()->user()->email;
        return view('profile', ['name' => $name, 'email' => $email]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/ProfileController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Medium severity issues result in warning status
        $this->assertFalse($result->isSuccess());
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
        $this->assertHasIssueContaining('Auth::user()', $result);
        $this->assertHasIssueContaining('auth()->user()', $result);
    }

    // ==========================================
    // Edge Cases and Integration Tests
    // ==========================================

    public function test_handles_empty_route_files(): void
    {
        $routes = <<<'PHP'
<?php

// Empty route file
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_malformed_route_definitions(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/users'
    // Missing closing
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should not crash - just verify we got a valid result
        $this->assertInstanceOf(ResultInterface::class, $result);
    }

    public function test_handles_controllers_without_class_definitions(): void
    {
        $controller = <<<'PHP'
<?php

// File without class definition
function helper() {
    return 'test';
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/Helper.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_mixed_routes_with_and_without_auth(): void
    {
        $routes = <<<'PHP'
<?php

Route::get('/home', [HomeController::class, 'index']);
Route::post('/posts', [PostController::class, 'store']);
Route::post('/comments', [CommentController::class, 'store'])->middleware('auth');
Route::delete('/posts/{id}', [PostController::class, 'destroy']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues); // posts and posts/{id} without auth
    }

    public function test_complex_application_structure(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/posts', [PostController::class, 'store']);
PHP;

        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class PostController extends Controller
{
    public function store()
    {
        $user = Auth::user()->name;
        return Post::create(['title' => request('title'), 'user' => $user]);
    }

    public function destroy($id)
    {
        Post::destroy($id);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/PostController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Should detect: 1) route without auth, 2) unsafe Auth::user(), 3) destroy without auth
        $this->assertGreaterThanOrEqual(3, count($issues));
    }

    // ==========================================
    // shouldRun and getSkipReason Tests
    // ==========================================

    public function test_should_not_run_without_routes_or_controllers(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString('No routes or controllers found', $analyzer->getSkipReason());
    }

    public function test_should_run_with_empty_routes_but_controllers(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class TestController extends Controller
{
    public function index() {}
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/TestController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_with_route_files(): void
    {
        $routes = <<<'PHP'
<?php

Route::get('/', fn() => 'home');
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    // ==========================================
    // Metadata Tests
    // ==========================================

    public function test_issues_contain_proper_metadata(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/users', [UserController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertArrayHasKey('method', $issue->metadata);
        $this->assertEquals('POST', $issue->metadata['method']);
    }

    public function test_auth_usage_issues_contain_metadata(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class ProfileController extends Controller
{
    public function show()
    {
        $name = Auth::user()->name;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/ProfileController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Medium severity issues result in warning status
        $this->assertFalse($result->isSuccess());
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));

        $authIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'Auth::user()')) {
                $authIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($authIssue);
        $this->assertArrayHasKey('method', $authIssue->metadata);
        $this->assertArrayHasKey('check_method', $authIssue->metadata);
        $this->assertEquals('Auth::user()', $authIssue->metadata['method']);
        $this->assertEquals('Auth::check()', $authIssue->metadata['check_method']);
    }

    public function test_route_group_issues_contain_metadata(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['prefix' => 'admin'], function () {
    Route::get('/dashboard', [AdminController::class, 'dashboard']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Medium severity issues result in warning status with resultBySeverity()
        $this->assertFalse($result->isSuccess());
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertArrayHasKey('route_type', $issue->metadata);
        $this->assertEquals('group', $issue->metadata['route_type']);
    }

    // ==========================================
    // Severity Tests
    // ==========================================

    public function test_sensitive_methods_have_high_severity(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController extends Controller
{
    public function destroy($id)
    {
        User::destroy($id);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::High, $issues[0]->severity);
    }

    public function test_unsafe_auth_usage_has_medium_severity(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class ProfileController extends Controller
{
    public function show()
    {
        $name = Auth::user()->name;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/ProfileController.php' => $controller]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Medium severity issues result in warning status
        $this->assertFalse($result->isSuccess());
        $authIssue = null;
        foreach ($result->getIssues() as $issue) {
            if (str_contains($issue->message, 'Auth::user()')) {
                $authIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($authIssue);
        $this->assertEquals(Severity::Medium, $authIssue->severity);
    }

    public function test_route_groups_have_medium_severity(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['prefix' => 'admin'], function () {
    Route::get('/dashboard', [AdminController::class, 'dashboard']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Medium severity issues result in warning status with resultBySeverity()
        $this->assertFalse($result->isSuccess());
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Medium, $issues[0]->severity);
    }
}
