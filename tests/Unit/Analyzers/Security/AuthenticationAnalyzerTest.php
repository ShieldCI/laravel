<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\Security\AuthenticationAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class AuthenticationAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        // Default public routes (same as in config file)
        $defaultPublicRoutes = [
            'login',
            'register',
            'password',
            'forgot-password',
            'reset-password',
            'verify',
            'health',
            'status',
            'up',
            'webhook',
        ];

        // Get custom public routes from config if provided
        $customPublicRoutes = $config['authentication-authorization']['public_routes'] ?? [];
        $publicRoutes = is_array($customPublicRoutes) && ! empty($customPublicRoutes)
            ? array_merge($defaultPublicRoutes, $customPublicRoutes)
            : $defaultPublicRoutes;

        // Build security config
        $securityConfig = [
            'enabled' => true,
            'authentication-authorization' => [
                'public_routes' => $publicRoutes,
            ],
        ];

        // Remove authentication-authorization from config to avoid conflicts
        unset($config['authentication-authorization']);

        // Merge any remaining config
        if (! empty($config)) {
            $securityConfig = array_merge_recursive($securityConfig, $config);
        }

        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'security' => $securityConfig,
                ],
            ],
        ]);

        return new AuthenticationAnalyzer($this->parser, $configRepo);
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

    public function test_passes_with_middleware_method(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController extends Controller
{
    public function middleware()
    {
        return [
            'auth' => ['except' => ['index', 'show']],
        ];
    }

    public function store()
    {
        return Post::create(request()->all());
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

        $this->assertPassed($result);
    }

    public function test_passes_with_middleware_method_only_constraint(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController extends Controller
{
    public function middleware()
    {
        return [
            'auth' => ['only' => ['store', 'update', 'destroy']],
        ];
    }

    public function store()
    {
        return User::create(request()->all());
    }

    public function update($id)
    {
        User::find($id)->update(request()->all());
    }

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

        $this->assertPassed($result);
    }

    public function test_detects_sensitive_methods_without_middleware_method_protection(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController extends Controller
{
    public function middleware()
    {
        return [
            'auth' => ['only' => ['index', 'show']], // Only protects index/show, not store/destroy
        ];
    }

    public function store()
    {
        return Post::create(request()->all());
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
        $this->assertHasIssueContaining('store', $result);
        $this->assertHasIssueContaining('destroy', $result);
    }

    public function test_passes_with_middleware_method_all_methods(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AdminController extends Controller
{
    public function middleware()
    {
        return [
            'auth' => [], // Applies to all methods
        ];
    }

    public function store()
    {
        return Admin::create(request()->all());
    }

    public function destroy($id)
    {
        Admin::destroy($id);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AdminController.php' => $controller]);

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
    public function __construct()
    {
        $this->middleware('auth');
    }

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
    public function __construct()
    {
        $this->middleware('auth');
    }

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
    public function __construct()
    {
        $this->middleware('auth');
    }

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
    public function __construct()
    {
        $this->middleware('auth');
    }

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

    public function test_skips_custom_public_routes_from_config(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/api/public', [PublicApiController::class, 'endpoint']);
Route::post('/oauth/callback', [OAuthController::class, 'callback']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        // Create analyzer with custom public routes
        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => [
                    'api/public',
                    'oauth/callback',
                ],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes should not be flagged because they're in the public routes list
        $this->assertPassed($result);
    }

    public function test_detects_routes_not_in_custom_public_routes(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/api/private', [PrivateApiController::class, 'endpoint']);
Route::post('/custom/endpoint', [CustomController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        // Create analyzer with custom public routes that don't include these routes
        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => [
                    'api/public',
                    'oauth/callback',
                ],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes should be flagged because they're not in the public routes list
        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
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

        // The analyzer now correctly detects Route::middleware() wrappers
        $this->assertPassed($result);
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

    public function test_without_middleware_removes_auth_from_route(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('auth')->group(function () {
    Route::post('/login', [AuthController::class, 'login'])
        ->withoutMiddleware('auth');
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Route explicitly removes auth — should NOT be flagged
        $this->assertPassed($result);
    }

    public function test_without_middleware_array_removes_auth(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware(['auth', 'verified'])->group(function () {
    Route::post('/callback', [WebhookController::class, 'handle'])
        ->withoutMiddleware(['auth']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_nested_group_without_middleware_removes_parent_auth(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('auth')->group(function () {
    Route::group(['prefix' => 'public'], function () {
        Route::post('/callback', [WebhookController::class, 'handle'])
            ->withoutMiddleware('auth');
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_group_without_middleware_removes_parent_auth(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('auth')->group(function () {
    Route::withoutMiddleware('auth')->group(function () {
        Route::post('/login', [AuthController::class, 'login']);
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Public login route should not be flagged
        $this->assertPassed($result);
    }

    public function test_mixed_routes_with_and_without_without_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('auth')->group(function () {
    Route::post('/secure', [SecureController::class, 'store']);
    Route::post('/public', [PublicController::class, 'store'])
        ->withoutMiddleware('auth');
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Secure route should NOT be flagged
        // Public route explicitly removes auth — also should NOT be flagged
        $this->assertPassed($result);
    }

    public function test_auth_not_reapplied_after_without_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('auth')->group(function () {
    Route::post('/login', [AuthController::class, 'login'])
        ->withoutMiddleware('auth');

    Route::post('/admin', [AdminController::class, 'store']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // /login is public
        // /admin is protected
        $this->assertPassed($result);
    }

    public function test_passes_routes_inside_protected_route_group_with_string_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => 'auth', 'prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store']);
    Route::put('/users/{id}', [UserController::class, 'update']);
    Route::delete('/users/{id}', [UserController::class, 'destroy']);
    Route::resource('posts', PostController::class);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes inside protected group should not be flagged
        $this->assertPassed($result);
    }

    public function test_passes_routes_inside_protected_route_group_with_array_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => ['auth'], 'prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store']);
    Route::delete('/users/{id}', [UserController::class, 'destroy']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes inside protected group should not be flagged
        $this->assertPassed($result);
    }

    public function test_passes_routes_inside_protected_route_group_with_multiple_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => ['login.user', 'auth', 'auth.admin'], 'prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store']);
    Route::put('/users/{id}', [UserController::class, 'update']);
    Route::delete('/users/{id}', [UserController::class, 'destroy']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes inside protected group should not be flagged
        $this->assertPassed($result);
    }

    public function test_passes_routes_inside_protected_route_group_with_multiline_middleware_array(): void
    {
        $routes = <<<'PHP'
<?php

Route::group([
    'as' => 'admin.',
    'prefix' => 'admin',
    'middleware' => [
        'login.user',
        'auth',
        'auth.admin'
    ]
], function () {
    Route::post('/users', [UserController::class, 'store']);
    Route::put('/users/{id}', [UserController::class, 'update']);
    Route::delete('/users/{id}', [UserController::class, 'destroy']);
    Route::resource('posts', PostController::class);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes inside protected group should not be flagged
        $this->assertPassed($result);
    }

    public function test_detects_routes_inside_unprotected_route_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store']);
    Route::delete('/users/{id}', [UserController::class, 'destroy']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should flag both the route group and the routes inside
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(3, count($issues)); // Route group + 2 routes
        $this->assertHasIssueContaining('Route group without authentication middleware', $result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
        $this->assertHasIssueContaining('DELETE route without authentication middleware', $result);
    }

    public function test_detects_routes_outside_protected_route_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/public-endpoint', [PublicController::class, 'store']);

Route::group(['middleware' => 'auth', 'prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store']);
    Route::get('/dashboard', [AdminController::class, 'dashboard']);
});

Route::delete('/another-public', [PublicController::class, 'destroy']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should flag routes outside the protected group, but not routes inside
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues); // Only the 2 routes outside the group
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
        $this->assertHasIssueContaining('DELETE route without authentication middleware', $result);

        // Verify routes inside protected group are not flagged
        $messages = array_map(fn ($issue) => $issue->message, $issues);
        $messagesString = implode(' ', $messages);
        $this->assertStringNotContainsString('users', $messagesString);
        $this->assertStringNotContainsString('dashboard', $messagesString);
    }

    public function test_detects_mixed_routes_in_and_outside_protected_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/public', [PublicController::class, 'store']);

Route::group(['middleware' => ['auth'], 'prefix' => 'admin'], function () {
    Route::post('/protected', [AdminController::class, 'store']);
    Route::delete('/protected/{id}', [AdminController::class, 'destroy']);
});

Route::put('/another-public', [PublicController::class, 'update']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should flag only routes outside the protected group
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues); // Only the 2 routes outside the group
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
        $this->assertHasIssueContaining('PUT route without authentication middleware', $result);
    }

    public function test_passes_routes_with_own_middleware_inside_unprotected_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store'])->middleware('auth');
    Route::delete('/users/{id}', [UserController::class, 'destroy'])->middleware('auth');
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Route group is flagged, but individual routes with their own auth middleware should pass
        // However, the route group itself will be flagged
        $this->assertFalse($result->isSuccess());
        $issues = $result->getIssues();
        // Should only flag the route group, not the individual routes
        $this->assertCount(1, $issues);
        $this->assertHasIssueContaining('Route group without authentication middleware', $result);
    }

    public function test_handles_nested_route_groups(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => 'auth', 'prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store']);
    
    Route::group(['prefix' => 'settings'], function () {
        Route::put('/profile', [SettingsController::class, 'update']);
        Route::delete('/account', [SettingsController::class, 'destroy']);
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes in nested group should be protected by parent group's auth middleware
        // Inner group should NOT be flagged because it's inside a protected parent group
        $this->assertPassed($result);
    }

    public function test_passes_routes_in_nested_protected_groups(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => 'auth', 'prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store']);
    
    Route::group(['middleware' => ['auth', 'verified'], 'prefix' => 'settings'], function () {
        Route::put('/profile', [SettingsController::class, 'update']);
        Route::delete('/account', [SettingsController::class, 'destroy']);
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // All routes should be protected by their respective groups
        $this->assertPassed($result);
    }

    public function test_passes_routes_in_nested_unprotected_group_inside_protected_parent(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => 'auth', 'prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store']);
    
    // Nested group without explicit auth, but protected by parent
    Route::group(['prefix' => 'settings'], function () {
        Route::put('/profile', [SettingsController::class, 'update']);
        Route::delete('/account', [SettingsController::class, 'destroy']);
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes should be protected by parent group's auth middleware
        // Inner group should NOT be flagged because it's inside a protected parent group
        $this->assertPassed($result);
    }

    public function test_passes_routes_in_nested_protected_group_inside_unprotected_parent(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store']);
    
    // Nested group with auth, protecting its routes
    Route::group(['middleware' => 'auth', 'prefix' => 'settings'], function () {
        Route::put('/profile', [SettingsController::class, 'update']);
        Route::delete('/account', [SettingsController::class, 'destroy']);
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes in nested protected group should not be flagged
        // Parent group and route outside nested group should be flagged
        $this->assertFalse($result->isSuccess());
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, $issues); // Parent group + route outside nested group

        // Verify nested group routes are not flagged
        $messages = array_map(fn ($issue) => $issue->message, $issues);
        $messagesString = implode(' ', $messages);
        $this->assertStringNotContainsString('PUT route', $messagesString);
        $this->assertStringNotContainsString('DELETE route', $messagesString);
    }

    public function test_detects_routes_in_nested_unprotected_groups(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store']);
    
    // Nested group also without auth
    Route::group(['prefix' => 'settings'], function () {
        Route::put('/profile', [SettingsController::class, 'update']);
        Route::delete('/account', [SettingsController::class, 'destroy']);
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // All routes should be flagged since neither group has auth
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(4, $issues); // 2 groups + 3 routes
        $this->assertHasIssueContaining('POST route', $result);
        $this->assertHasIssueContaining('PUT route', $result);
        $this->assertHasIssueContaining('DELETE route', $result);
    }

    public function test_handles_triple_nested_groups(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => 'auth', 'prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store']);
    
    Route::group(['prefix' => 'settings'], function () {
        Route::put('/profile', [SettingsController::class, 'update']);
        
        Route::group(['prefix' => 'advanced'], function () {
            Route::delete('/account', [SettingsController::class, 'destroy']);
        });
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // All routes should be protected by top-level parent group's auth
        // Inner groups should NOT be flagged because they're inside a protected parent group
        $this->assertPassed($result);
    }

    public function test_passes_routes_in_nested_group_with_multiple_middleware_keys(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['as' => 'admin.', 'prefix' => 'admin', 'middleware' => ['login.user', 'auth', 'auth.admin']], function () {
    Route::group(['as' => 'airports.', 'prefix' => 'airports'], function () {
        Route::post('/create', [AirportController::class, 'store']);
        Route::delete('/{id}', [AirportController::class, 'destroy']);
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes should be protected by parent group's auth middleware
        // Inner group should NOT be flagged because it's inside a protected parent group
        $this->assertPassed($result);
    }

    public function test_passes_routes_in_nested_group_with_multiline_middleware_array(): void
    {
        $routes = <<<'PHP'
<?php

Route::group([
    'as' => 'admin.',
    'prefix' => 'admin',
    'middleware' => [
        'login.user',
        'auth',
        'auth.admin'
    ]
], function () {
    Route::group(['as' => 'airports.', 'prefix' => 'airports'], function () {
        Route::post('/create', [AirportController::class, 'store']);
        Route::delete('/{id}', [AirportController::class, 'destroy']);
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes should be protected by parent group's auth middleware
        // Inner group should NOT be flagged because it's inside a protected parent group
        $this->assertPassed($result);
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

    public function test_passes_routes_in_multiple_nested_groups_with_same_name(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\AdminController;
use App\Http\Controllers\AirportController;
use App\Http\Controllers\NoFlyRecordController;
use App\Http\Controllers\PageController;
use Illuminate\Support\Facades\Route;

Route::get('/nvhb', [LoginController::class, 'healthCheck'])->name('envoyer.health.check');

Route::group(['as' => 'admin.', 'prefix' => 'admin', 'middleware' => ['login.user', 'auth', 'auth.admin']], function () {
    Route::get('/', [AdminController::class, 'adminDashboard'])->name('dashboard');
    
    Route::group(['as' => 'airports.', 'prefix' => 'airports'], function () {
        Route::get('/members', [AirportController::class, 'getMemberAirports'])->name('members');
        Route::post('/nofly/{nofly}/archive', [NoFlyRecordController::class, 'archive'])->name('nofly.archive');
    });
});

Route::group(['middleware' => ['login.user', 'auth']], function () {
    Route::get('/', [PageController::class, 'getDashboard'])->name('dashboard');
    
    Route::group(['as' => 'airports.', 'prefix' => 'airports'], function () {
        Route::get('/', [AirportController::class, 'getMemberAirportsHunterSide'])->name('index');
        Route::post('/{airport}/deals/check', [AirportDealController::class, 'checkDeal'])->name('deals.check');
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes should be protected by their respective parent groups
        // Nested route groups should NOT be flagged because they're inside protected parent groups
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

    public function test_route_groups_have_high_severity(): void
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

        $this->assertFalse($result->isSuccess());
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::High, $issues[0]->severity);
    }

    public function test_passes_controller_without_auth_middleware_but_all_routes_protected(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('auth')->group(function () {
    Route::post('/posts', [PostController::class, 'store']);
    Route::put('/posts/{id}', [PostController::class, 'update']);
    Route::delete('/posts/{id}', [PostController::class, 'destroy']);
});
PHP;

        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers;

class PostController extends Controller
{
    // No auth middleware in constructor

    public function store()
    {
        return response()->json(['status' => 'created']);
    }

    public function update($id)
    {
        return response()->json(['status' => 'updated']);
    }

    public function destroy($id)
    {
        return response()->json(['status' => 'deleted']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/PostController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass because all routes are protected at route level
        $this->assertPassed($result);
    }

    public function test_fails_controller_without_auth_middleware_with_mixed_route_protection(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('auth')->group(function () {
    Route::post('/posts', [PostController::class, 'store']);
    Route::put('/posts/{id}', [PostController::class, 'update']);
});

// This route is NOT protected
Route::delete('/posts/{id}', [PostController::class, 'destroy']);
PHP;

        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers;

class PostController extends Controller
{
    // No auth middleware in constructor

    public function store()
    {
        return response()->json(['status' => 'created']);
    }

    public function update($id)
    {
        return response()->json(['status' => 'updated']);
    }

    public function destroy($id)
    {
        return response()->json(['status' => 'deleted']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/PostController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail because destroy() method is not protected
        $this->assertFalse($result->isSuccess());
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(1, count($issues));
    }

    public function test_passes_invokable_controller_without_auth_middleware_but_route_protected(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('auth')->group(function () {
    Route::post('/webhook/callback', WebhookController::class);
});
PHP;

        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers;

class WebhookController extends Controller
{
    // No auth middleware in constructor

    public function __invoke()
    {
        return response()->json(['status' => 'ok']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/WebhookController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass because route is protected at route level
        $this->assertPassed($result);
    }

    // ==========================================
    // Nullsafe Operator Tests
    // ==========================================

    public function test_passes_with_nullsafe_operator_auth_user(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class ProfileController extends Controller
{
    public function show()
    {
        $name = Auth::user()?->name;
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

        // Should pass - nullsafe operator is safe
        $this->assertPassed($result);
    }

    public function test_passes_with_nullsafe_operator_auth_helper(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ProfileController extends Controller
{
    public function show()
    {
        $email = auth()->user()?->email;
        return view('profile', ['email' => $email]);
    }
}
PHP;

        $routes = '<?php';

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ProfileController.php' => $controller,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_nullsafe_operator_request_user(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function show(Request $request)
    {
        $name = $request->user()?->name;
        return view('profile', ['name' => $name]);
    }
}
PHP;

        $routes = '<?php';

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ProfileController.php' => $controller,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_unsafe_request_user_without_null_check(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function show(Request $request)
    {
        $name = $request->user()->name;
        return view('profile', ['name' => $name]);
    }
}
PHP;

        $routes = '<?php';

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ProfileController.php' => $controller,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('Unsafe $request->user() usage without null check', $result);
    }

    // ==========================================
    // Auth Middleware Variant Tests
    // ==========================================

    public function test_passes_with_auth_api_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware(['auth:api'])->group(function () {
    Route::post('/api/posts', [PostController::class, 'store']);
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_auth_sanctum_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('auth:sanctum')->group(function () {
    Route::put('/api/profile', [ProfileController::class, 'update']);
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_auth_web_middleware_in_controller(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class DashboardController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:web');
    }

    public function destroy($id)
    {
        return redirect('/');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/DashboardController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_auth_guard_on_route(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/admin/users', [UserController::class, 'store'])
    ->middleware('auth:admin');
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==========================================
    // FormRequest Tests
    // ==========================================

    public function test_detects_form_request_authorize_returns_true(): void
    {
        $formRequest = <<<'PHP'
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdatePostRequest extends FormRequest
{
    public function authorize()
    {
        return true;
    }

    public function rules()
    {
        return [
            'title' => 'required|string',
        ];
    }
}
PHP;

        $routes = '<?php';

        $tempDir = $this->createTempDirectory([
            'app/Http/Requests/UpdatePostRequest.php' => $formRequest,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('UpdatePostRequest::authorize() returns true without authorization checks', $result);
    }

    public function test_passes_form_request_without_authorize_method(): void
    {
        $formRequest = <<<'PHP'
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StorePostRequest extends FormRequest
{
    // No authorize() method - defaults to false (secure)

    public function rules()
    {
        return [
            'title' => 'required|string',
        ];
    }
}
PHP;

        $routes = '<?php';

        $tempDir = $this->createTempDirectory([
            'app/Http/Requests/StorePostRequest.php' => $formRequest,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - missing authorize() defaults to false (secure)
        $this->assertPassed($result);
    }

    public function test_passes_form_request_with_authorization_logic(): void
    {
        $formRequest = <<<'PHP'
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdatePostRequest extends FormRequest
{
    public function authorize()
    {
        return $this->user()->can('update', $this->post);
    }

    public function rules()
    {
        return [
            'title' => 'required|string',
        ];
    }
}
PHP;

        $routes = '<?php';

        $tempDir = $this->createTempDirectory([
            'app/Http/Requests/UpdatePostRequest.php' => $formRequest,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - has proper authorization logic
        $this->assertPassed($result);
    }

    // ==========================================
    // Resource Route Tests
    // ==========================================

    public function test_passes_resource_route_in_protected_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['as' => 'admin.', 'prefix' => 'admin', 'middleware' => ['login.user', 'auth', 'auth.admin']], function () {
    Route::resource('permissions', PermissionController::class);
});
PHP;

        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PermissionController extends Controller
{
    public function index()
    {
        return view('permissions.index');
    }

    public function create()
    {
        return view('permissions.create');
    }

    public function store()
    {
        // Store logic
    }

    public function show($id)
    {
        return view('permissions.show');
    }

    public function edit($id)
    {
        return view('permissions.edit');
    }

    public function update($id)
    {
        // Update logic
    }

    public function destroy($id)
    {
        // Delete logic
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/PermissionController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - all resource methods are protected by route group auth middleware
        $this->assertPassed($result);
    }

    public function test_detects_resource_route_without_auth(): void
    {
        $routes = <<<'PHP'
<?php

Route::resource('posts', PostController::class);
PHP;

        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController extends Controller
{
    public function store()
    {
        // Store logic
    }

    public function update($id)
    {
        // Update logic
    }

    public function destroy($id)
    {
        // Delete logic
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/PostController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should detect unprotected resource routes (store, update, destroy are mutation routes)
        $this->assertFalse($result->isSuccess());
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
    }

    public function test_passes_api_resource_route_in_protected_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('auth:sanctum')->group(function () {
    Route::apiResource('users', UserController::class);
});
PHP;

        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController extends Controller
{
    public function index()
    {
        return response()->json([]);
    }

    public function store()
    {
        // Store logic
    }

    public function show($id)
    {
        return response()->json([]);
    }

    public function update($id)
    {
        // Update logic
    }

    public function destroy($id)
    {
        // Delete logic
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routes,
            'app/Http/Controllers/UserController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass - all API resource methods are protected by auth:sanctum middleware
        $this->assertPassed($result);
    }

    // ==========================================
    // Authorization Middleware Tests (can:, role:, permission:)
    // ==========================================

    public function test_passes_with_can_middleware_on_route(): void
    {
        $routes = <<<'PHP'
<?php

Route::put('/posts/{post}', [PostController::class, 'update'])
    ->middleware(['auth', 'can:update,post']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_role_middleware_in_controller(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AdminController extends Controller
{
    public function __construct()
    {
        $this->middleware(['auth', 'role:admin']);
    }

    public function destroy($id)
    {
        // Admin action
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AdminController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_permission_middleware_in_route_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware(['auth', 'permission:delete-users'])->group(function () {
    Route::delete('/users/{user}', [UserController::class, 'destroy']);
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==========================================
    // Closure Route Tests
    // ==========================================

    public function test_detects_closure_route_without_auth(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/admin/process', function (Request $request) {
    DB::table('users')->update(['active' => false]);
    return response()->json(['status' => 'ok']);
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    public function test_passes_closure_route_with_auth_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/webhook', function (Request $request) {
    return response()->json(['status' => 'ok']);
})->middleware('auth');
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_closure_route_in_protected_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('auth:sanctum')->group(function () {
    Route::post('/api/process', function (Request $request) {
        return response()->json(['processed' => true]);
    });
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==========================================
    // Suppression Comment Tests (@shieldci-ignore)
    // ==========================================
    // Note: @shieldci-ignore is now handled centrally by AnalyzeCommand.
    // See tests/Unit/Support/InlineSuppressionParserTest.php for suppression tests.

    public function test_does_not_suppress_without_specific_tag(): void
    {
        $routes = <<<'PHP'
<?php

// Some other comment
Route::post('/admin/delete-all', [AdminController::class, 'deleteAll']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should detect issue - comment doesn't contain @shieldci-ignore
        $this->assertFalse($result->isSuccess());
    }
}
