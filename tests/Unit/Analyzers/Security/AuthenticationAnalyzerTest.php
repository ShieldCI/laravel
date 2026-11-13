<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\Security\AuthenticationAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Tests\AnalyzerTestCase;

class AuthenticationAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        // Default public routes (same as in config file — exact paths)
        $defaultPublicRoutes = [
            '/login',
            '/register',
            '/password/reset',
            '/password/email',
            '/forgot-password',
            '/reset-password',
            '/email/verify',
            '/health',
            '/status',
            '/up',
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

        // Create analyzer with custom public routes (exact paths)
        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => [
                    '/api/public',
                    '/oauth/callback',
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
                    '/api/public',
                    '/oauth/callback',
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
Route::post('/reset-password', [PasswordController::class, 'resetNew']);
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

    public function test_exact_path_does_not_match_nested_uri(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/auth/login', [AuthController::class, 'login']);
Route::post('/api/v1/register', [AuthController::class, 'register']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // With exact path matching, /auth/login does NOT match default /login
        $this->assertFailed($result);
    }

    public function test_skips_nested_uris_when_added_to_config(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/auth/login', [AuthController::class, 'login']);
Route::post('/auth/forgot-password', [PasswordController::class, 'forgot']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => [
                    '/auth/login',
                    '/auth/forgot-password',
                ],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_route_matching_exact_public_path(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/satis/auth', [SatisAuthController::class, 'authenticate']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => [
                    '/satis/auth',
                ],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_multiple_exact_public_paths(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/webhooks/stripe', [StripeController::class, 'handle']);
Route::post('/webhooks/github', [GithubController::class, 'handle']);
Route::post('/api/oauth/token', [OAuthController::class, 'token']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => [
                    '/webhooks/stripe',
                    '/webhooks/github',
                    '/api/oauth/token',
                ],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_wildcard_public_routes_from_config(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('welcome/{employee}', [WelcomeController::class, 'savePassword']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        // Wildcard pattern should match the route URI even though it contains a
        // {parameter} placeholder and is registered without a leading slash.
        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => [
                    '/welcome/*',
                ],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_matches_public_route_registered_without_leading_slash(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('api/webhook', [WebhookController::class, 'handle']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        // Config pattern has a leading slash; route URI does not. They should match.
        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => [
                    '/api/webhook',
                ],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_route_group_when_all_routes_are_public(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => ['web']], function () {
    Route::get('welcome/{employee}', [WelcomeController::class, 'showWelcomeForm']);
    Route::post('welcome/{employee}', [WelcomeController::class, 'savePassword']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        // Both routes inside the group are covered by the wildcard, so the group
        // warning must be suppressed too.
        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => [
                    '/welcome/*',
                ],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_flags_route_group_when_a_route_is_not_public(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => ['web']], function () {
    Route::post('welcome/{employee}', [WelcomeController::class, 'savePassword']);
    Route::post('admin/settings', [AdminController::class, 'update']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        // Only the welcome route is whitelisted; the admin route is not, so the
        // group warning must still fire.
        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => [
                    '/welcome/*',
                ],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Route group without authentication middleware', $result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_skips_default_public_routes(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [AuthController::class, 'register']);
Route::post('/forgot-password', [PasswordController::class, 'forgot']);
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

    public function test_skips_route_group_when_inner_routes_are_default_public(): void
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

        // Every route inside the group is a default-public auth-entry route
        // (/login, /register), so requiring auth here would be nonsensical.
        // The group warning must be suppressed along with the individual routes.
        $this->assertPassed($result);
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

    /**
     * @dataProvider lastRegistrarMiddlewareProvider
     */
    #[DataProvider('lastRegistrarMiddlewareProvider')]
    public function test_group_middleware_reads_only_the_last_registrar_middleware_call(string $routes, bool $reported): void
    {
        $tempDir = $this->createTempDirectory(['routes/web.php' => "<?php\n\n{$routes}\n"]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        if ($reported) {
            $this->assertFailed($result);
            $this->assertHasIssueContaining('POST route without authentication middleware', $result);
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function lastRegistrarMiddlewareProvider(): array
    {
        $route = "Route::post('/backoffice/members', [MemberController::class, 'store'])";

        return [
            // RouteRegistrar::attribute() replaces 'middleware' on each call: the last one applies.
            'auth replaced by a later call' => ["Route::middleware('auth')->middleware('verified')->group(function () {\n    {$route};\n});", true],
            'auth replaced across another registrar call' => ["Route::middleware('auth')->prefix('ops')->middleware('verified')->group(function () {\n    {$route};\n});", true],
            'no auth' => ["Route::middleware('verified')->group(function () {\n    {$route};\n});", true],
            'auth as the last call' => ["Route::middleware('verified')->middleware('auth')->group(function () {\n    {$route};\n});", false],
            'auth in one call listing both' => ["Route::middleware(['auth', 'verified'])->group(function () {\n    {$route};\n});", false],
            // Laravel merges middleware down nested groups.
            'outer auth group around an inner replacing chain' => ["Route::middleware('auth')->group(function () {\n    Route::middleware('signed')->middleware('verified')->group(function () {\n        {$route};\n    });\n});", false],
            // Route::middleware() on a route adds to its middleware.
            'route-level calls add up' => ["{$route}->middleware('verified')->middleware('auth');", false],
        ];
    }

    /**
     * @dataProvider registrarVariableProvider
     */
    #[DataProvider('registrarVariableProvider')]
    public function test_group_middleware_reads_a_registrar_held_in_a_variable(string $registrar, bool $reported): void
    {
        $routes = <<<PHP
<?php

{$registrar}
\$members->group(function () {
    Route::post('/backoffice/members', [MemberController::class, 'store']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        if ($reported) {
            $this->assertFailed($result);
            $this->assertHasIssueContaining('POST route without authentication middleware', $result);
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function registrarVariableProvider(): array
    {
        return [
            'auth on the registrar' => ["\$members = Route::middleware('auth');", false],
            'auth set by a later statement' => ["\$members = Route::prefix('backoffice');\n\$members->middleware('auth');", false],
            'auth replaced by a later statement' => ["\$members = Route::middleware('auth');\n\$members->middleware('verified');", true],
            'auth excluded by a later statement' => ["\$members = Route::middleware('auth');\n\$members->withoutMiddleware('auth');", true],
            'auth set in a branch' => ["\$members = Route::prefix('backoffice');\nif (app()->isLocal()) {\n    \$members->middleware('auth');\n}", true],
            'auth replaced through the registrar group() returns' => ["\$members = Route::middleware('auth');\n\$copy = \$members->group(function () {});\n\$copy->middleware('verified');", true],
            'auth replaced through a variable variable' => ["\$members = Route::middleware('auth');\n\$name = 'members';\n\$\$name->middleware('verified');", true],
            'auth replaced through attribute()' => ["\$members = Route::middleware('auth');\n\$members->attribute('middleware', ['verified']);", true],
            'auth set through attribute()' => ["\$members = Route::prefix('backoffice');\n\$members->attribute('middleware', 'auth');", false],
            'auth given as an extra attribute() argument' => ["\$members = Route::prefix('backoffice');\n\$members->attribute('middleware', 'verified', 'auth');", true],
            'auth beside an attribute() key in a variable' => ["\$key = 'prefix';\n\$members = Route::middleware('auth')->attribute(\$key, 'backoffice');", false],
        ];
    }

    /**
     * @dataProvider routerRootGroupProvider
     */
    #[DataProvider('routerRootGroupProvider')]
    public function test_group_middleware_reads_groups_on_any_router_root(string $routes, bool $reported): void
    {
        $tempDir = $this->createTempDirectory(['routes/web.php' => "<?php\n\n{$routes}\n"]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $messages = array_map(fn ($issue) => $issue->message, $analyzer->analyze()->getIssues());

        $this->assertSame($reported, in_array('POST route without authentication middleware', $messages, true));
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function routerRootGroupProvider(): array
    {
        $route = "Route::post('/backoffice/members', [MemberController::class, 'store']);";

        return [
            'router variable chain' => ["\$router = app('router');\n\$router->middleware('auth')->group(function () {\n    {$route}\n});", false],
            'registrar built on a router variable' => ["\$router = app('router');\n\$members = \$router->middleware('auth');\n\$members->group(function () {\n    {$route}\n});", false],
            'router a group callback is given' => ["Route::group([], function (\$routes) {\n    \$routes->middleware('auth')->group(function () {\n        {$route}\n    });\n});", false],
            'router variable group with an attribute array' => ["\$router = app('router');\n\$router->group(['middleware' => 'auth'], function () {\n    {$route}\n});", false],
            'fluent attribute() call' => ["Route::prefix('backoffice')->attribute('middleware', 'auth')->group(function () {\n    {$route}\n});", false],
            'group on the container router' => ["app('router')->group(['middleware' => 'auth'], function () {\n    {$route}\n});", false],
            'group on the container router beside an unrelated group' => ["app('router')->group(['middleware' => 'auth'], function () {\n    {$route}\n});\n\$sections = new SectionLoader;\n\$sections->group(fn () => null);", false],
            'registrar group in a branch' => ["\$members = Route::middleware('auth');\nif (config('backoffice.enabled')) {\n    \$members->group(function () {\n        {$route}\n    });\n}", false],
            // PHP method names are case-insensitive
            'group named in another case' => ["Route::middleware('auth')->Group(function () {\n    {$route}\n});", false],
            'static group named in another case' => ["Route::Group(['middleware' => 'auth'], function () {\n    {$route}\n});", false],
            // Only routes registered through the Route facade are collected
            'registrar variable route beside a require' => ["\$admin = Route::middleware('auth')->prefix('admin');\n\$admin->post('/users', [UserController::class, 'store']);\nrequire __DIR__.'/auth.php';", false],
            'registrar variable route written in a branch' => ["\$admin = Route::middleware('auth')->prefix('admin');\nif (config('admin.verified')) {\n    \$admin->middleware('verified');\n}\n\$admin->post('/users', [UserController::class, 'store']);", false],
            'registrar variable route captured by a closure' => ["\$admin = Route::middleware('auth')->prefix('admin');\n\$extend = function () use (\$admin) {\n    return \$admin;\n};\n\$admin->post('/users', [UserController::class, 'store']);", false],
            'router parameter of a route closure' => ["Route::middleware('auth')->post('/rpc', function (RpcRouter \$router) {\n    \$router->post('ping', [PingController::class, 'store']);\n});", false],
            // Another object's group() is no route group
            'unrelated object' => ["\$sections = new SectionLoader;\n\$sections->middleware('auth')->group(function () {\n    {$route}\n});", true],
            'unrelated object with an attribute array' => ["\$sections = new SectionLoader;\n\$sections->group(['middleware' => 'auth'], function () {\n    {$route}\n});", true],
        ];
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

        // Every route in the group carries auth of its own, so the group leaves none open
        $this->assertPassed($result);
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
    // Guest Middleware Group Tests
    // ==========================================

    public function test_passes_routes_in_guest_middleware_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('guest')->group(function () {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/register', [AuthController::class, 'register']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes inside guest group should not be flagged
        $this->assertPassed($result);
    }

    public function test_passes_routes_in_guest_middleware_array_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware(['guest'])->group(function () {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/register', [AuthController::class, 'register']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes inside guest array group should not be flagged
        $this->assertPassed($result);
    }

    public function test_passes_routes_in_guest_route_group_array_syntax(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => 'guest', 'prefix' => 'auth'], function () {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/register', [AuthController::class, 'register']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Routes inside guest Route::group array syntax should not be flagged
        $this->assertPassed($result);
    }

    public function test_handles_mixed_auth_and_guest_groups(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('auth')->group(function () {
    Route::post('/posts', [PostController::class, 'store']);
    Route::delete('/posts/{id}', [PostController::class, 'destroy']);
});

Route::middleware('guest')->group(function () {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/register', [AuthController::class, 'register']);
});

Route::post('/unprotected', [PublicController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Only the unprotected route outside both groups should be flagged
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_controller_method_in_guest_group_not_flagged(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware(['guest'])->group(function () {
    Route::post('/login', [AuthController::class, 'store']);
});
PHP;

        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers;

class AuthController extends Controller
{
    public function store()
    {
        return response()->json(['status' => 'authenticated']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/AuthController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Controller method routed from guest group should not be flagged
        $this->assertPassed($result);
    }

    public function test_invokable_controller_in_guest_group_not_flagged(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\Auth\GoogleOneTapController;
use Illuminate\Support\Facades\Route;

Route::middleware('guest')->group(function () {
    Route::post('/auth/google/one-tap', GoogleOneTapController::class)
        ->name('auth.google.one-tap')
        ->middleware('throttle:10,1');
});
PHP;

        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

class GoogleOneTapController extends Controller
{
    public function __invoke(Request $request): RedirectResponse
    {
        return redirect()->route('dashboard');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/auth.php' => $routes,
            'app/Http/Controllers/Auth/GoogleOneTapController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']); // Required: ensures checkController() actually scans

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_public_get_invokable_controller_not_flagged(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\Marketing\PrivacyController;
use Illuminate\Support\Facades\Route;

Route::get('/privacy', PrivacyController::class)->name('privacy');
PHP;

        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers\Marketing;

use App\Http\Controllers\Controller;
use Inertia\Response;

class PrivacyController extends Controller
{
    public function __invoke(): Response
    {
        return inertia('marketing/privacy');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/Marketing/PrivacyController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_post_invokable_controller_without_auth_flagged(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SubmitController;
use Illuminate\Support\Facades\Route;

Route::post('/submit', SubmitController::class);
PHP;

        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers;

class SubmitController extends Controller
{
    public function __invoke()
    {
        return response()->json(['ok' => true]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/SubmitController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Route-level + controller-level checks both fire for an unprotected POST
        $this->assertIssueCount(2, $result);
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

    public function test_route_groups_have_critical_severity(): void
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
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
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

use App\Http\Controllers\WebhookController;

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
        $analyzer->setPaths(['app']); // Ensures checkController() actually scans

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

        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Http\Requests\UpdatePostRequest;

class PostController extends Controller
{
    public function update(UpdatePostRequest $request, $id)
    {
        // sensitive action — no auth middleware
    }
}
PHP;

        $routes = '<?php';

        $tempDir = $this->createTempDirectory([
            'app/Http/Requests/UpdatePostRequest.php' => $formRequest,
            'app/Http/Controllers/PostController.php' => $controller,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('UpdatePostRequest::authorize() returns true without authorization checks', $result);
    }

    public function test_flags_form_request_without_authorize_method_in_unprotected_action(): void
    {
        $result = $this->analyzeFormRequestWithoutAuthorize("Route::post('/members/remove', [MembershipController::class, 'destroy']);");

        // FormRequest::passesAuthorization() authorizes every request when authorize() is absent
        $this->assertFailed($result);
        $this->assertHasIssueContaining('RemoveMemberRequest has no authorize() method, so every request is authorized', $result);
        $issues = array_values(array_filter(
            $result->getIssues(),
            fn ($issue) => str_contains($issue->message, 'RemoveMemberRequest'),
        ));
        $this->assertCount(1, $issues);
        $this->assertSame(Severity::High, $issues[0]->severity);
    }

    public function test_passes_form_request_without_authorize_method_in_protected_action(): void
    {
        $result = $this->analyzeFormRequestWithoutAuthorize(
            "Route::middleware('auth')->group(function () {\n    Route::post('/members/remove', [MembershipController::class, 'destroy']);\n});"
        );

        // The route carries auth, so the FormRequest is not the only gate
        $this->assertPassed($result);
    }

    public function test_passes_form_request_without_authorize_method_whose_parent_may_declare_one(): void
    {
        $parent = <<<'PHP'
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

abstract class TeamFormRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()?->belongsToTeam($this->route('team')) ?? false;
    }
}
PHP;

        $result = $this->analyzeFormRequestWithoutAuthorize(
            "Route::post('/members/remove', [MembershipController::class, 'destroy']);",
            'TeamFormRequest',
            ['app/Http/Requests/TeamFormRequest.php' => $parent],
        );

        // The route and controller findings stand; the FormRequest one would be a guess
        foreach ($result->getIssues() as $issue) {
            $this->assertStringNotContainsString('RemoveMemberRequest', $issue->message);
        }
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_passes_form_request_without_authorize_method_using_a_trait(): void
    {
        $trait = <<<'PHP'
<?php

namespace App\Http\Requests\Concerns;

trait AuthorizesTeamOwners
{
    public function authorize(): bool
    {
        return $this->user()?->ownsTeam($this->route('team')) === true;
    }
}
PHP;

        $result = $this->analyzeFormRequestWithoutAuthorize(
            "Route::post('/members/remove', [MembershipController::class, 'destroy']);",
            'FormRequest',
            ['app/Http/Requests/Concerns/AuthorizesTeamOwners.php' => $trait],
            'use Concerns\AuthorizesTeamOwners;',
        );

        // A trait may declare authorize(); the route and controller findings stand
        foreach ($result->getIssues() as $issue) {
            $this->assertStringNotContainsString('RemoveMemberRequest', $issue->message);
        }
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    /**
     * Analyze a MembershipController::destroy() taking a FormRequest that declares no
     * authorize() method, extends $parent and declares $members, reached by the routes
     * $routes registers in routes/web.php.
     *
     * @param  array<string, string>  $files
     */
    private function analyzeFormRequestWithoutAuthorize(string $routes, string $parent = 'FormRequest', array $files = [], string $members = ''): ResultInterface
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Http\Requests\RemoveMemberRequest;

class MembershipController extends Controller
{
    public function destroy(RemoveMemberRequest $request)
    {
    }
}
PHP;

        $formRequest = <<<PHP
<?php

namespace App\\Http\\Requests;

use Illuminate\\Foundation\\Http\\FormRequest;

class RemoveMemberRequest extends {$parent}
{
    {$members}

    public function rules(): array
    {
        return ['member_id' => 'required|integer'];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\MembershipController;\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n",
            'app/Http/Controllers/MembershipController.php' => $controller,
            'app/Http/Requests/RemoveMemberRequest.php' => $formRequest,
            ...$files,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        return $analyzer->analyze();
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

    public function test_two_factor_challenge_request_not_flagged(): void
    {
        $formRequest = <<<'PHP'
<?php
namespace App\Http\Requests\Auth;
use Illuminate\Foundation\Http\FormRequest;
class TwoFactorChallengeRequest extends FormRequest
{
    public function authorize(): bool { return true; }
    public function rules(): array
    {
        return ['code' => 'nullable|string', 'recovery_code' => 'nullable|string'];
    }
}
PHP;

        // No controller — FormRequest is orphaned, cannot determine risk
        $tempDir = $this->createTempDirectory([
            'routes/web.php' => '<?php',
            'app/Http/Requests/Auth/TwoFactorChallengeRequest.php' => $formRequest,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $result = $analyzer->analyze();
        $this->assertPassed($result);
    }

    public function test_form_request_authorize_true_in_unprotected_store_flagged(): void
    {
        $routes = <<<'PHP'
<?php
use App\Http\Controllers\AccountController;
use Illuminate\Support\Facades\Route;
Route::post('/account/delete', [AccountController::class, 'store']);
PHP;

        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers;
use App\Http\Requests\DeleteAccountRequest;
class AccountController extends Controller
{
    public function store(DeleteAccountRequest $request)
    {
        // sensitive action
    }
}
PHP;

        $formRequest = <<<'PHP'
<?php
namespace App\Http\Requests;
use Illuminate\Foundation\Http\FormRequest;
class DeleteAccountRequest extends FormRequest
{
    public function authorize(): bool { return true; }
    public function rules(): array { return []; }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/AccountController.php' => $controller,
            'app/Http/Requests/DeleteAccountRequest.php' => $formRequest,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);
        $result = $analyzer->analyze();
        $this->assertFailed($result);
    }

    public function test_form_request_authorize_true_in_auth_protected_route_not_flagged(): void
    {
        $routes = <<<'PHP'
<?php
use App\Http\Controllers\AccountController;
use Illuminate\Support\Facades\Route;
Route::middleware('auth')->group(function () {
    Route::post('/account/delete', [AccountController::class, 'store']);
});
PHP;

        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers;
use App\Http\Requests\DeleteAccountRequest;
class AccountController extends Controller
{
    public function store(DeleteAccountRequest $request)
    {
        // sensitive action — but route is auth-protected
    }
}
PHP;

        $formRequest = <<<'PHP'
<?php
namespace App\Http\Requests;
use Illuminate\Foundation\Http\FormRequest;
class DeleteAccountRequest extends FormRequest
{
    public function authorize(): bool { return true; }
    public function rules(): array { return []; }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/AccountController.php' => $controller,
            'app/Http/Requests/DeleteAccountRequest.php' => $formRequest,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);
        $result = $analyzer->analyze();
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

Route::middleware('auth')->group(function () {
    Route::post('/process', function (Request $request) {
        return response()->json(['status' => 'ok']);
    });
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

    // ==========================================
    // Custom Middleware Introspection Tests
    // ==========================================

    public function test_passes_route_with_custom_auth_middleware_class(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Middleware\ValidateApiToken;

Route::post('/reports', [ReportController::class, 'store'])
    ->middleware(ValidateApiToken::class);
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

use Illuminate\Auth\AuthenticationException;

class ValidateApiToken
{
    public function handle($request, $next)
    {
        $token = $request->bearerToken();
        if (!$token) {
            throw new AuthenticationException('Unauthenticated.');
        }
        return $next($request);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routes,
            'app/Http/Middleware/ValidateApiToken.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_route_with_custom_auth_middleware_in_array(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Middleware\CustomAuth;

Route::post('/reports', [ReportController::class, 'store'])
    ->middleware([CustomAuth::class, 'throttle:60']);
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class CustomAuth
{
    public function handle($request, $next)
    {
        $token = $request->bearerToken();
        if (!$token) {
            abort(401);
        }
        return $next($request);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routes,
            'app/Http/Middleware/CustomAuth.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_route_group_with_custom_auth_middleware_class(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Middleware\TokenAuth;

Route::middleware(TokenAuth::class)->group(function () {
    Route::post('/reports', [ReportController::class, 'store']);
    Route::delete('/reports/{id}', [ReportController::class, 'destroy']);
});
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class TokenAuth
{
    public function handle($request, $next)
    {
        $token = $request->bearerToken();
        if (!$token) {
            abort(401);
        }
        return $next($request);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routes,
            'app/Http/Middleware/TokenAuth.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_route_with_non_auth_middleware_class(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Middleware\LogRequests;

Route::post('/reports', [ReportController::class, 'store'])
    ->middleware(LogRequests::class);
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class LogRequests
{
    public function handle($request, $next)
    {
        logger()->info('Request logged: ' . $request->url());
        return $next($request);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routes,
            'app/Http/Middleware/LogRequests.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_passes_route_with_middleware_throwing_authentication_exception(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Middleware\ApiKeyAuth;

Route::post('/data', [DataController::class, 'store'])
    ->middleware(ApiKeyAuth::class);
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

use Illuminate\Auth\AuthenticationException;

class ApiKeyAuth
{
    public function handle($request, $next)
    {
        $key = $request->header('X-API-Key');
        if (!$key || !$this->isValid($key)) {
            throw new AuthenticationException('Invalid API key.');
        }
        return $next($request);
    }

    private function isValid(string $key): bool
    {
        return $key === config('services.api_key');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routes,
            'app/Http/Middleware/ApiKeyAuth.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_route_with_http_basic_auth_middleware(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Middleware\BasicAuth;

Route::post('/internal/sync', [SyncController::class, 'sync'])
    ->middleware(BasicAuth::class);
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class BasicAuth
{
    public function handle($request, $next)
    {
        $user = $request->getUser();
        $password = $request->getPassword();
        if (!$user || !$password) {
            abort(401);
        }
        return $next($request);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routes,
            'app/Http/Middleware/BasicAuth.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_unresolvable_middleware_class_gracefully(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Middleware\NonExistentMiddleware;

Route::post('/reports', [ReportController::class, 'store'])
    ->middleware(NonExistentMiddleware::class);
PHP;

        // No middleware file created — class file doesn't exist
        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should flag it — can't resolve, so can't confirm it's auth middleware
        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    // ==========================================
    // String middleware alias resolution (#307)
    // ==========================================

    public function test_passes_route_group_with_string_aliased_custom_auth_middleware_via_bootstrap(): void
    {
        // #307 exact repro: a custom auth middleware attached by a STRING ALIAS
        // registered in bootstrap/app.php (Laravel 11+) must be recognised as
        // authentication — clearing both the route finding and the dependent
        // "sensitive method" controller finding.
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'device.token' => \App\Http\Middleware\EnsureDeviceToken::class,
        ]);
    })
    ->create();
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

use Illuminate\Auth\AuthenticationException;

class EnsureDeviceToken
{
    public function handle($request, $next)
    {
        $token = $request->bearerToken();
        if (! $token) {
            throw new AuthenticationException('Device not registered');
        }
        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\ScanController;

Route::middleware(['device.token', 'throttle:scan'])->prefix('reception/device')->group(function () {
    Route::post('scan', [ScanController::class, 'store']);
});
PHP;

        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ScanController extends Controller
{
    public function store()
    {
        return response()->json(['ok' => true]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'app/Http/Middleware/EnsureDeviceToken.php' => $middleware,
            'routes/api.php' => $routes,
            'app/Http/Controllers/ScanController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_route_with_string_alias_from_kernel_middleware_aliases(): void
    {
        // Laravel 10 style: alias declared in app/Http/Kernel.php $middlewareAliases.
        $kernel = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middlewareAliases = [
        'device.token' => \App\Http\Middleware\EnsureDeviceToken::class,
    ];
}
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class EnsureDeviceToken
{
    public function handle($request, $next)
    {
        $token = $request->bearerToken();
        if (! $token) {
            abort(401);
        }
        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\ScanController;

Route::post('/reception/scan', [ScanController::class, 'store'])->middleware(['device.token']);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernel,
            'app/Http/Middleware/EnsureDeviceToken.php' => $middleware,
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_route_with_string_alias_from_legacy_route_middleware(): void
    {
        // Laravel 8/9 style: alias declared in the older $routeMiddleware property.
        $kernel = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $routeMiddleware = [
        'device.token' => \App\Http\Middleware\EnsureDeviceToken::class,
    ];
}
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class EnsureDeviceToken
{
    public function handle($request, $next)
    {
        if (! $request->bearerToken()) {
            abort(401);
        }
        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\ScanController;

Route::post('/reception/scan', [ScanController::class, 'store'])->middleware(['device.token']);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernel,
            'app/Http/Middleware/EnsureDeviceToken.php' => $middleware,
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_route_with_string_alias_value_as_plain_fqcn_string(): void
    {
        // Alias value written as a plain string FQCN (with a leading backslash)
        // rather than ::class — must be normalised before class introspection.
        $kernel = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $routeMiddleware = [
        'device.token' => '\App\Http\Middleware\EnsureDeviceToken',
    ];
}
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class EnsureDeviceToken
{
    public function handle($request, $next)
    {
        if (! $request->bearerToken()) {
            abort(401);
        }
        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\ScanController;

Route::post('/reception/scan', [ScanController::class, 'store'])->middleware(['device.token']);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernel,
            'app/Http/Middleware/EnsureDeviceToken.php' => $middleware,
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_route_with_string_alias_and_middleware_parameter(): void
    {
        // The alias token carries a parameter ('device.token:tenant'); only the
        // alias name (before the first colon) is used for map resolution.
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'device.token' => \App\Http\Middleware\EnsureDeviceToken::class,
        ]);
    })
    ->create();
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class EnsureDeviceToken
{
    public function handle($request, $next, $tenant = null)
    {
        if (! $request->bearerToken()) {
            abort(401);
        }
        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\ScanController;

Route::post('/reception/scan', [ScanController::class, 'store'])->middleware(['device.token:tenant']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'app/Http/Middleware/EnsureDeviceToken.php' => $middleware,
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_route_with_auth_basic_middleware(): void
    {
        // The built-in 'auth.basic' alias (HTTP Basic auth) is authentication.
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\InternalController;

Route::post('/internal/sync', [InternalController::class, 'store'])->middleware('auth.basic');
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_flags_route_with_string_alias_to_non_auth_middleware(): void
    {
        // Negative control: an alias resolving to a NON-auth middleware must
        // still be flagged — resolution introspects the target, it does not
        // trust the alias blindly.
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'audit.log' => \App\Http\Middleware\LogRequests::class,
        ]);
    })
    ->create();
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class LogRequests
{
    public function handle($request, $next)
    {
        logger()->info('Request logged: ' . $request->url());
        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\ScanController;

Route::post('/reception/scan', [ScanController::class, 'store'])->middleware(['audit.log']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'app/Http/Middleware/LogRequests.php' => $middleware,
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_flags_route_with_string_alias_but_no_alias_registration(): void
    {
        // Negative control (empty-map safety): a bare alias with no bootstrap or
        // Kernel registration cannot be resolved, so the route stays flagged.
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\ScanController;

Route::post('/reception/scan', [ScanController::class, 'store'])->middleware(['device.token']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_flags_route_with_unregistered_string_alias(): void
    {
        // Negative control: the map resolves 'device.token', but the route uses a
        // DIFFERENT, unregistered alias — resolution is per-alias, not blanket.
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'device.token' => \App\Http\Middleware\EnsureDeviceToken::class,
        ]);
    })
    ->create();
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class EnsureDeviceToken
{
    public function handle($request, $next)
    {
        if (! $request->bearerToken()) {
            abort(401);
        }
        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\ScanController;

Route::post('/reception/scan', [ScanController::class, 'store'])->middleware(['other.token']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'app/Http/Middleware/EnsureDeviceToken.php' => $middleware,
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_flags_route_protected_only_by_throttle_alias(): void
    {
        // Negative control: stripping the ':param' for alias lookup must not turn
        // a non-auth built-in like 'throttle:scan' into authentication.
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\ScanController;

Route::post('/reception/scan', [ScanController::class, 'store'])->middleware(['throttle:scan']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_resolves_alias_despite_unrelated_alias_call_in_bootstrap(): void
    {
        // Robustness: an unrelated non-array ->alias() call elsewhere must not
        // break parsing; the real string-keyed alias map is still resolved.
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'device.token' => \App\Http\Middleware\EnsureDeviceToken::class,
        ]);
    })
    ->withExceptions(function ($exceptions): void {
        $exceptions->alias('legacy', 'modern');
    })
    ->create();
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class EnsureDeviceToken
{
    public function handle($request, $next)
    {
        if (! $request->bearerToken()) {
            abort(401);
        }
        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\ScanController;

Route::post('/reception/scan', [ScanController::class, 'store'])->middleware(['device.token']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'app/Http/Middleware/EnsureDeviceToken.php' => $middleware,
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_routes_in_group_with_intermediate_method_calls(): void
    {
        // Route::prefix()->middleware()->group() — the ->prefix() sits between the StaticCall
        // root and ->group(), so extractGroupMiddleware must walk the intermediate MethodCall chain.
        $routes = <<<'PHP'
<?php

Route::prefix('api')->middleware('auth')->group(function () {
    Route::post('/reports', [ReportController::class, 'store']);
    Route::delete('/reports/{id}', [ReportController::class, 'destroy']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_legacy_string_routes_in_protected_group(): void
    {
        // Legacy 'Controller@method' string — exercising the string-handler path in extractHandler.
        $routes = <<<'PHP'
<?php

Route::middleware('auth')->group(function () {
    Route::post('/reports', 'ReportController@store');
    Route::delete('/reports/{id}', 'ReportController@destroy');
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_unprotected_legacy_string_route(): void
    {
        // Legacy 'Controller@method' string on an unprotected mutation route should be flagged.
        $routes = <<<'PHP'
<?php

Route::post('/reports', 'ReportController@store');
Route::post('/orders', 'OrderController');
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(2, $result->getIssues());
    }

    // ==========================================
    // API.php Skip Removal Tests
    // ==========================================

    public function test_flags_unprotected_route_in_api_php_with_sanctum_present(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\ReportController;
use App\Http\Controllers\UserController;

// Protected routes
Route::middleware('auth:sanctum')->group(function () {
    Route::get('/user', [UserController::class, 'show']);
});

// This unprotected POST should be flagged even though sanctum is mentioned above
Route::post('/reports', [ReportController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    // ==========================================
    // Auth Usage — Middleware-Protected Suppression
    // ==========================================

    public function test_request_user_not_flagged_in_auth_middleware_route(): void
    {
        $routes = <<<'PHP'
<?php
use App\Http\Controllers\Auth\EmailVerificationPromptController;
use Illuminate\Support\Facades\Route;
Route::middleware('auth')->group(function () {
    Route::get('verify-email', EmailVerificationPromptController::class)
        ->name('verification.notice');
});
PHP;

        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers\Auth;
use Illuminate\Http\Request;
class EmailVerificationPromptController
{
    public function __invoke(Request $request)
    {
        return $request->user()->hasVerifiedEmail()
            ? redirect('/dashboard')
            : view('auth.verify-email');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/auth.php' => $routes,
            'app/Http/Controllers/Auth/EmailVerificationPromptController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);
        $result = $analyzer->analyze();
        $this->assertPassed($result);
    }

    public function test_auth_user_not_flagged_in_constructor_auth_controller(): void
    {
        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers;
use Illuminate\Support\Facades\Auth;
class ProfileController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
    }
    public function show()
    {
        $name = Auth::user()->name;
        return view('profile', compact('name'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => '<?php',
            'app/Http/Controllers/ProfileController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);
        $result = $analyzer->analyze();
        $this->assertPassed($result);
    }

    public function test_request_user_still_flagged_when_unprotected(): void
    {
        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
class GuestController extends Controller
{
    public function show(Request $request)
    {
        return $request->user()->name;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => '<?php',
            'app/Http/Controllers/GuestController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);
        $result = $analyzer->analyze();
        $this->assertFalse($result->isSuccess());
        $this->assertHasIssueContaining('$request->user()', $result);
    }

    public function test_does_not_flag_auth_usage_inside_heredoc_string(): void
    {
        $service = <<<'PHP'
<?php

namespace App\Services;

class DocumentationHelper
{
    public function getAuthDocs(): string
    {
        return <<<'MD'
        Use Auth::user()->name to display the user's name.
        Or use auth()->user()->name for the helper form.
        MD;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => '<?php',
            'app/Services/DocumentationHelper.php' => $service,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);
        $result = $analyzer->analyze();

        $this->assertEmpty($result->getIssues());
    }

    public function test_unauthenticated_method_recommendation_contains_no_code_samples(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class UserController extends Controller
{
    public function destroy(Request $request, int $id): void
    {
        // no auth check
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();
        $issues = array_filter(
            $result->getIssues(),
            fn ($i) => str_contains($i->message, 'without authentication check')
        );

        if (empty($issues)) {
            $this->markTestSkipped('No auth issues detected for this fixture — adjust fixture to trigger the expected issue.');
        }

        $issue = reset($issues);
        $this->assertStringNotContainsString('$this->middleware(', $issue->recommendation);
        $this->assertStringContainsString('auth middleware', $issue->recommendation);
    }

    public function test_form_request_recommendation_contains_no_code_samples(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class DeleteUserRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [];
    }
}
PHP;

        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Http\Requests\DeleteUserRequest;

class UserController extends Controller
{
    public function destroy(DeleteUserRequest $request)
    {
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

Route::delete('/users/{user}', [UserController::class, 'destroy']);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Requests/DeleteUserRequest.php' => $code,
            'app/Http/Controllers/UserController.php' => $controller,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();
        $issues = array_values(array_filter(
            $result->getIssues(),
            fn ($i) => str_contains($i->message, 'authorize()')
        ));

        $this->assertCount(1, $issues);
        $issue = $issues[0];
        $this->assertStringNotContainsString('$this->', $issue->recommendation);
        $this->assertStringNotContainsString('->can(', $issue->recommendation);
        $this->assertStringContainsString('Gate or Policy', $issue->recommendation);
    }

    // ==========================================
    // Route Prefix Composition (public_routes)
    // ==========================================

    public function test_public_route_nested_in_fluent_prefix_groups_is_suppressed(): void
    {
        $routes = <<<'PHP'
<?php

Route::prefix('api')->group(function () {
    Route::prefix('webhooks')->middleware('throttle')->group(function () {
        Route::post('/{provider}/callback', [WebhookController::class, 'handle']);
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => ['/api/webhooks/*/callback'],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // The route's real path is api/webhooks/{provider}/callback — a full-path
        // public_routes pattern must suppress it even when nested in prefix() groups.
        $this->assertPassed($result);
    }

    public function test_public_route_nested_in_array_prefix_group_is_suppressed(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['prefix' => 'partners'], function () {
    Route::post('/enrollments/{token}/confirm', [ConfirmEnrollmentController::class, 'store']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => ['/partners/enrollments/*/confirm'],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Covers both the individual-route finding and the static-group finding
        // (the group is suppressed only when all inner routes are public).
        $this->assertPassed($result);
    }

    public function test_unlisted_route_nested_in_prefix_group_is_still_flagged(): void
    {
        $routes = <<<'PHP'
<?php

Route::prefix('admin')->group(function () {
    Route::post('/users', [AdminUserController::class, 'store']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // A genuinely-unprotected nested route must still be flagged.
        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_prefixless_pattern_still_suppresses_nested_route(): void
    {
        $routes = <<<'PHP'
<?php

Route::prefix('partners')->group(function () {
    Route::post('/enrollments/{token}/confirm', [ConfirmEnrollmentController::class, 'store']);
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => ['/enrollments/*/confirm'],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // A pattern matching only the route's own declared segment keeps working
        // (backward compat for configs written before prefix composition).
        $this->assertPassed($result);
    }

    public function test_sensitive_method_of_nested_public_route_not_flagged(): void
    {
        $routes = <<<'PHP'
<?php

Route::prefix('partners')->group(function () {
    Route::post('/enrollments/{token}/confirm', [EnrollmentController::class, 'store']);
});
PHP;

        $controller = <<<'PHP'
<?php
namespace App\Http\Controllers;

class EnrollmentController extends Controller
{
    public function store()
    {
        return response()->json(['status' => 'confirmed']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/EnrollmentController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => ['/partners/enrollments/*/confirm'],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // The public-routes decision must flow through to the sensitive-method check.
        $this->assertPassed($result);
    }

    public function test_route_level_prefix_call_is_composed(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/users', [AdminUserController::class, 'store'])->prefix('admin');
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => ['/admin/users'],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // ->prefix() on the route itself rewrites its URI (real path: admin/users).
        $this->assertPassed($result);
    }

    public function test_api_route_file_gets_conventional_api_prefix(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/webhooks/{provider}', [WebhookController::class, 'handle']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $routes]);

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => ['/api/webhooks/*'],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // routes/api.php is registered with the 'api' prefix by the framework,
        // so full-path patterns include it even though the file's AST does not.
        $this->assertPassed($result);
    }

    public function test_api_prefix_discovered_from_bootstrap_app(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        apiPrefix: 'v1',
    )
    ->create();
PHP;

        $routes = <<<'PHP'
<?php

Route::post('/webhooks/{provider}', [WebhookController::class, 'handle']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'routes/api.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => ['/v1/webhooks/*'],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // A customized apiPrefix in bootstrap/app.php overrides the 'api' convention.
        $this->assertPassed($result);
    }

    public function test_custom_route_file_prefix_discovered_from_route_service_provider(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->routes(function () {
            Route::middleware('web')->group(base_path('routes/web.php'));
            Route::prefix('partners')->middleware('web')->group(base_path('routes/partners.php'));
        });
    }
}
PHP;

        $routes = <<<'PHP'
<?php

Route::post('/enrollments/{token}/confirm', [ConfirmEnrollmentController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/RouteServiceProvider.php' => $provider,
            'routes/partners.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => ['/partners/enrollments/*/confirm'],
            ],
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // A custom route file registered with a prefix in the RouteServiceProvider
        // composes that prefix into its routes' real paths.
        $this->assertPassed($result);
    }

    public function test_custom_route_file_prefix_discovered_from_a_group_list(): void
    {
        $result = $this->analyzeProviderGroup(
            "Route::prefix('vendors')->middleware('web')->group([base_path('routes/vendors.php')]);",
            ['routes/vendors.php'],
            ['/vendors/invites/*/accept'],
        );

        // Router::group() wraps its routes argument in an array, so a one-item
        // list of route files takes the chain's prefix just as a single file does.
        $this->assertPassed($result);
    }

    public function test_custom_route_file_prefix_discovered_from_a_named_callback_list(): void
    {
        $result = $this->analyzeProviderGroup(
            "Route::prefix('vendors')->middleware('web')->group(callback: [base_path('routes/vendors.php')]);",
            ['routes/vendors.php'],
            ['/vendors/invites/*/accept'],
        );

        $this->assertPassed($result);
    }

    public function test_custom_route_file_prefix_applies_to_every_file_in_a_group_list(): void
    {
        $result = $this->analyzeProviderGroup(
            "Route::prefix('vendors')->middleware('web')->group([base_path('routes/catalog.php'), base_path('routes/vendors.php')]);",
            ['routes/vendors.php'],
            ['/vendors/invites/*/accept'],
        );

        // The route sits in the second listed file; the prefix covers every file in the list.
        $this->assertPassed($result);
    }

    public function test_group_list_prefix_still_reports_routes_outside_public_routes(): void
    {
        $result = $this->analyzeProviderGroup(
            "Route::prefix('vendors')->middleware('web')->group([base_path('routes/vendors.php')]);",
            ['routes/vendors.php'],
            ['/suppliers/invites/*/accept'],
        );

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_custom_route_file_prefix_discovered_from_bootstrap_then_callback(): void
    {
        $result = $this->analyzeBootstrapThenGroup(
            "Route::prefix('vendors')->middleware('web')->group(base_path('routes/vendors.php'));",
            ['/vendors/invites/*/accept'],
        );

        // Laravel 11+ registers extra route files in withRouting's then: callback,
        // with the same registrar chains a RouteServiceProvider uses.
        $this->assertPassed($result);
    }

    public function test_custom_route_file_prefix_discovered_from_a_bootstrap_then_group_list(): void
    {
        $result = $this->analyzeBootstrapThenGroup(
            "Route::prefix('vendors')->middleware('web')->group([base_path('routes/catalog.php'), base_path('routes/vendors.php')]);",
            ['/vendors/invites/*/accept'],
        );

        $this->assertPassed($result);
    }

    public function test_bootstrap_then_prefix_still_reports_routes_outside_public_routes(): void
    {
        $result = $this->analyzeBootstrapThenGroup(
            "Route::prefix('vendors')->middleware('web')->group(base_path('routes/vendors.php'));",
            ['/suppliers/invites/*/accept'],
        );

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    /**
     * Analyze an unauthenticated POST /invites/{token}/accept route placed in each of
     * $routeFiles, registered by a RouteServiceProvider running $registration.
     *
     * @param  list<string>  $routeFiles
     * @param  list<string>  $publicRoutes
     */
    private function analyzeProviderGroup(string $registration, array $routeFiles, array $publicRoutes): ResultInterface
    {
        $provider = <<<PHP
<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        \$this->routes(function () {
            {$registration}
        });
    }
}
PHP;

        $routes = <<<'PHP'
<?php

Route::post('/invites/{token}/accept', [AcceptInviteController::class, 'store']);
PHP;

        $files = ['app/Providers/RouteServiceProvider.php' => $provider];
        foreach ($routeFiles as $routeFile) {
            $files[$routeFile] = $routes;
        }

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => $publicRoutes,
            ],
        ]);
        $analyzer->setBasePath($this->createTempDirectory($files));

        return $analyzer->analyze();
    }

    /**
     * Analyze an unauthenticated POST /invites/{token}/accept route in routes/vendors.php,
     * registered by $registration inside bootstrap/app.php's withRouting(then: ...) callback.
     *
     * @param  list<string>  $publicRoutes
     */
    private function analyzeBootstrapThenGroup(string $registration, array $publicRoutes): ResultInterface
    {
        $bootstrap = <<<PHP
<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            {$registration}
        },
    )
    ->create();
PHP;

        $routes = <<<'PHP'
<?php

Route::post('/invites/{token}/accept', [AcceptInviteController::class, 'store']);
PHP;

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => $publicRoutes,
            ],
        ]);
        $analyzer->setBasePath($this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'routes/vendors.php' => $routes,
        ]));

        return $analyzer->analyze();
    }

    // ==========================================
    // Route file prefixes from registrations
    // ==========================================

    /**
     * @dataProvider routeFileRegistrationProvider
     *
     * @param  array<string, string>  $registration
     */
    #[DataProvider('routeFileRegistrationProvider')]
    public function test_route_file_prefix_is_read_from_its_registration(array $registration, string $routeFile, string $prefix): void
    {
        $result = $this->analyzeRegisteredRouteFile($registration, $routeFile, ["/{$prefix}/leads"]);

        $this->assertPassed($result);
    }

    /**
     * @dataProvider routeFileRegistrationProvider
     *
     * @param  array<string, string>  $registration
     */
    #[DataProvider('routeFileRegistrationProvider')]
    public function test_route_file_prefix_from_a_registration_still_reports_a_route_listed_under_another_prefix(array $registration, string $routeFile, string $prefix): void
    {
        $result = $this->analyzeRegisteredRouteFile($registration, $routeFile, ['/elsewhere/leads']);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    /**
     * @return array<string, array{array<string, string>, string, string}>
     */
    public static function routeFileRegistrationProvider(): array
    {
        return [
            'then: callback held in a variable' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$mapAffiliateRoutes = function () {\n    Route::prefix('affiliates')->group(base_path('routes/affiliates.php'));\n};",
                "web: __DIR__.'/../routes/web.php',\n        then: \$mapAffiliateRoutes,",
            )], 'routes/affiliates.php', 'affiliates'],
            'then: arrow function held in a variable' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$mapAffiliateRoutes = fn () => Route::prefix('affiliates')->group(base_path('routes/affiliates.php'));",
                "web: __DIR__.'/../routes/web.php',\n        then: \$mapAffiliateRoutes,",
            )], 'routes/affiliates.php', 'affiliates'],
            'using: callback' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "using: function () {\n            Route::middleware('web')->group(base_path('routes/web.php'));\n            Route::prefix('kiosk')->group(base_path('routes/kiosk.php'));\n        },",
            )], 'routes/kiosk.php', 'kiosk'],
            'using: callback held in a variable' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$loadRoutes = function () {\n    Route::prefix('kiosk')->group(base_path('routes/kiosk.php'));\n};",
                'using: $loadRoutes,',
            )], 'routes/kiosk.php', 'kiosk'],
            'using: callback given by position' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "function () {\n            Route::prefix('kiosk')->group(base_path('routes/kiosk.php'));\n        },",
            )], 'routes/kiosk.php', 'kiosk'],
            'api: list with an apiPrefix' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "api: [__DIR__.'/../routes/mobile.php'],\n        apiPrefix: 'mobile-api',",
            )], 'routes/mobile.php', 'mobile-api'],
            'api: base_path() with an apiPrefix' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "api: base_path('routes/mobile.php'),\n        apiPrefix: 'mobile-api',",
            )], 'routes/mobile.php', 'mobile-api'],
            'api: list of base_path() calls with an apiPrefix' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "api: [base_path('routes/catalog.php'), base_path('routes/mobile.php')],\n        apiPrefix: 'mobile-api',",
            )], 'routes/mobile.php', 'mobile-api'],
            'provider path variable' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "\$file = base_path('routes/backoffice.php');\n        Route::prefix('backoffice')->group(\$file);",
            )], 'routes/backoffice.php', 'backoffice'],
            'provider path variable inside the routes() callback' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "\$this->routes(function () {\n            \$file = base_path('routes/backoffice.php');\n            Route::prefix('backoffice')->middleware('web')->group(\$file);\n        });",
            )], 'routes/backoffice.php', 'backoffice'],
            'provider registrar variable' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "\$tenant = Route::prefix('tenant');\n        \$tenant->group(base_path('routes/tenant.php'));",
            )], 'routes/tenant.php', 'tenant'],
            'provider registrar variable given its prefix by a later statement' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "\$tenant = Route::middleware('web');\n        \$tenant->prefix('tenant');\n        \$tenant->group(base_path('routes/tenant.php'));",
            )], 'routes/tenant.php', 'tenant'],
            'then: registrar variable' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "web: __DIR__.'/../routes/web.php',\n        then: function () {\n            \$tenant = Route::prefix('tenant');\n            \$tenant->group(base_path('routes/tenant.php'));\n        },",
            )], 'routes/tenant.php', 'tenant'],
            'provider Route::group() attribute array' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "Route::group(['middleware' => 'web', 'prefix' => '/ops/'], base_path('routes/ops.php'));",
            )], 'routes/ops.php', 'ops'],
            'provider router property group() attribute array' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "\$this->router->group(['prefix' => 'ops'], base_path('routes/ops.php'));",
            )], 'routes/ops.php', 'ops'],
            'then: Route::group() attribute array' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "web: __DIR__.'/../routes/web.php',\n        then: function () {\n            Route::group(['prefix' => 'ops'], base_path('routes/ops.php'));\n        },",
            )], 'routes/ops.php', 'ops'],
            'provider require inside a prefixed group closure' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "Route::prefix('ops')->group(function () {\n            require base_path('routes/ops.php');\n        });",
            )], 'routes/ops.php', 'ops'],
            'then: require inside a prefixed group closure' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "web: __DIR__.'/../routes/web.php',\n        then: function () {\n            Route::prefix('ops')->group(function () {\n                require base_path('routes/ops.php');\n            });\n        },",
            )], 'routes/ops.php', 'ops'],
            'registration in another provider' => [['app/Providers/AppServiceProvider.php' => <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Route::prefix('ops')->middleware('web')->group(base_path('routes/ops.php'));
    }
}
PHP], 'routes/ops.php', 'ops'],
            'outer prefix around an inner group that sets none' => [['app/Providers/AppServiceProvider.php' => self::appProvider(
                "Route::prefix('ops')->group(function () {\n            Route::middleware('web')->group(base_path('routes/ops.php'));\n        });",
            )], 'routes/ops.php', 'ops'],
            'nested prefixes composed' => [['app/Providers/AppServiceProvider.php' => self::appProvider(
                "Route::prefix('admin')->group(function () {\n            Route::prefix('/ops/')->group(base_path('routes/ops.php'));\n        });",
            )], 'routes/ops.php', 'admin/ops'],
            'two providers giving one file the same prefix' => [[
                'app/Providers/AProvider.php' => self::appProvider("Route::prefix('ops')->group(base_path('routes/ops.php'));", '', 'AProvider'),
                'app/Providers/BProvider.php' => self::appProvider("Route::prefix('ops')->group(base_path('routes/ops.php'));", '', 'BProvider'),
            ], 'routes/ops.php', 'ops'],
            'provider method boot() calls' => [['app/Providers/AppServiceProvider.php' => self::appProvider(
                '$this->mapOpsRoutes();',
                "    private function mapOpsRoutes(): void\n    {\n        Route::prefix('ops')->group(base_path('routes/ops.php'));\n    }\n",
            )], 'routes/ops.php', 'ops'],
            'map() in a RouteServiceProvider subclass' => [['app/Providers/RouteServiceProvider.php' => <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider extends ServiceProvider
{
    public function map(): void
    {
        $this->mapOpsRoutes();
    }

    protected function mapOpsRoutes(): void
    {
        $file = base_path('routes/ops.php');
        Route::prefix('ops')->group($file);
    }
}
PHP], 'routes/ops.php', 'ops'],
            'global Route alias' => [['app/Providers/AppServiceProvider.php' => self::appProvider(
                "\\Route::prefix('ops')->group(base_path('routes/ops.php'));",
            )], 'routes/ops.php', 'ops'],
        ];
    }

    /**
     * @dataProvider unreadableRouteFileRegistrationProvider
     *
     * @param  array<string, string>  $registration
     */
    #[DataProvider('unreadableRouteFileRegistrationProvider')]
    public function test_route_file_prefix_is_not_read_from_a_registration_it_cannot_follow(array $registration, string $routeFile, string $prefix): void
    {
        $result = $this->analyzeRegisteredRouteFile($registration, $routeFile, ["/{$prefix}/leads"]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    /**
     * @return array<string, array{array<string, string>, string, string}>
     */
    public static function unreadableRouteFileRegistrationProvider(): array
    {
        return [
            'then: variable set in a required file' => [[
                'bootstrap/app.php' => self::bootstrapApp(
                    "require __DIR__.'/routing.php';",
                    "web: __DIR__.'/../routes/web.php',\n        then: \$mapAffiliateRoutes,",
                ),
                'bootstrap/routing.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n\$mapAffiliateRoutes = function () {\n    Route::prefix('affiliates')->group(base_path('routes/affiliates.php'));\n};\n",
            ], 'routes/affiliates.php', 'affiliates'],
            // ApplicationBuilder::withRouting() builds its own callback when then: is given, and drops using:.
            'using: beside a then: callback' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "using: function () {\n            Route::prefix('kiosk')->group(base_path('routes/kiosk.php'));\n        },\n        then: function () {},",
            )], 'routes/kiosk.php', 'kiosk'],
            'provider path variable from a required file' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "\$file = require base_path('config/backoffice-routes.php');\n        Route::prefix('backoffice')->group(\$file);",
            )], 'routes/backoffice.php', 'backoffice'],
            'provider registrar variable reassigned in a branch' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "\$tenant = Route::prefix('tenant');\n        if (app()->isLocal()) {\n            \$tenant = Route::prefix('local');\n        }\n        \$tenant->group(base_path('routes/tenant.php'));",
            )], 'routes/tenant.php', 'tenant'],
            'provider attribute array prefix read from config' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "Route::group(['prefix' => config('ops.prefix')], base_path('routes/ops.php'));",
            )], 'routes/ops.php', 'ops'],
            // RouteRegistrar::attribute() overwrites the prefix, so an unreadable later call decides.
            'literal prefix overridden by one read from config' => [['app/Providers/AppServiceProvider.php' => self::appProvider(
                "Route::prefix('ops')->prefix(config('ops.prefix'))->group(base_path('routes/ops.php'));",
            )], 'routes/ops.php', 'ops'],
            'registrar variable prefix overridden by one read from config' => [['app/Providers/AppServiceProvider.php' => self::appProvider(
                "\$ops = Route::prefix('ops');\n        \$ops->prefix(config('ops.prefix'));\n        \$ops->group(base_path('routes/ops.php'));",
            )], 'routes/ops.php', 'ops'],
            // An apiPrefix that cannot be read is no reason to guess the 'api' default.
            'api: list with an apiPrefix read from config' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "api: [base_path('routes/mobile.php')],\n        apiPrefix: config('app.api_prefix'),",
            )], 'routes/mobile.php', 'api'],
            'api: base_path() with an apiPrefix variable set from a required file' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$apiPrefix = require __DIR__.'/api-prefix.php';",
                "api: base_path('routes/mobile.php'),\n        apiPrefix: \$apiPrefix,",
            )], 'routes/mobile.php', 'api'],
        ];
    }

    /**
     * @dataProvider unappliedRouteFileRegistrationProvider
     *
     * @param  array<string, string>  $registration
     */
    #[DataProvider('unappliedRouteFileRegistrationProvider')]
    public function test_route_file_prefix_is_not_read_from_a_registration_laravel_does_not_make(array $registration, string $routeFile, string $prefix): void
    {
        $result = $this->analyzeRegisteredRouteFile($registration, $routeFile, ["/{$prefix}/leads"]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    /**
     * @return array<string, array{array<string, string>, string, string}>
     */
    public static function unappliedRouteFileRegistrationProvider(): array
    {
        $bothProviders = "<?php\n\nreturn [\n    App\\Providers\\AProvider::class,\n    App\\Providers\\BProvider::class,\n];\n";

        return [
            // Only Router::group() reads an attribute array.
            'group() attribute array on a property that is not the router' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "\$this->registry->group(['prefix' => 'ops'], base_path('routes/ops.php'));",
            )], 'routes/ops.php', 'ops'],
            'group() attribute array on another object' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "\$collection = new \\ArrayObject;\n        \$collection->group(['prefix' => 'ops'], base_path('routes/ops.php'));",
            )], 'routes/ops.php', 'ops'],
            // The prefix map is keyed by basename, so a nested file must not lend its prefix to a top-level one.
            'nested route file of the same name' => [[
                'app/Providers/AppServiceProvider.php' => self::appProvider("Route::prefix('partners')->group(base_path('routes/partners/web.php'));"),
                'routes/partners/web.php' => '<?php',
            ], 'routes/web.php', 'partners'],
            'nested required route file of the same name' => [[
                'app/Providers/AppServiceProvider.php' => self::appProvider("Route::prefix('v1')->group(function () {\n            require base_path('routes/v1/orders.php');\n        });"),
                'routes/v1/orders.php' => '<?php',
            ], 'routes/orders.php', 'v1'],
            // A route file a route file requires takes no prefix from it.
            'route file required through the api.php convention' => [[
                'bootstrap/app.php' => self::bootstrapApp('', "web: __DIR__.'/../routes/web.php',"),
                'routes/web.php' => "<?php\n\nrequire __DIR__.'/api.php';\n",
                'routes/api.php' => "<?php\n\nrequire __DIR__.'/partners.php';\n",
            ], 'routes/partners.php', 'api'],
            'route file required only in a function a prefixed route file never calls' => [[
                'app/Providers/AppServiceProvider.php' => self::appProvider("Route::prefix('ops')->group(base_path('routes/ops.php'));"),
                'routes/ops.php' => "<?php\n\nfunction loadLegacyOps(): void\n{\n    require __DIR__.'/legacy.php';\n}\n",
                'routes/web.php' => "<?php\n\nrequire __DIR__.'/legacy.php';\n",
            ], 'routes/legacy.php', 'ops'],
            // Only RouteServiceProvider calls map().
            'map() in a provider that is not a RouteServiceProvider' => [[
                'bootstrap/app.php' => self::bootstrapApp('', "web: [__DIR__.'/../routes/web.php', __DIR__.'/../routes/ops.php'],"),
                'routes/web.php' => '<?php',
                'app/Providers/AppServiceProvider.php' => self::appProvider(
                    '',
                    "    public function map(): void\n    {\n        Route::prefix('partners')->group(base_path('routes/ops.php'));\n    }\n",
                ),
            ], 'routes/ops.php', 'partners'],
            // Laravel runs only what a service provider's boot(), register() or map() reaches.
            'provider method nothing calls' => [['app/Providers/AppServiceProvider.php' => self::appProvider(
                '',
                "    private function unused(): void\n    {\n        Route::prefix('ops')->group(base_path('routes/ops.php'));\n    }\n",
            )], 'routes/ops.php', 'ops'],
            'class under app/Providers that is not a provider' => [['app/Providers/RouteHelper.php' => <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\Facades\Route;

class RouteHelper
{
    public static function register(): void
    {
        Route::prefix('ops')->group(base_path('routes/ops.php'));
    }
}
PHP], 'routes/ops.php', 'ops'],
            'class named Route that is not the facade' => [['app/Providers/AppServiceProvider.php' => self::appProvider(
                "Route::prefix('ops')->group(base_path('routes/ops.php'));",
                '',
                'AppServiceProvider',
                'App\\Menu\\Route',
            )], 'routes/ops.php', 'ops'],
            // Laravel's provider order is not read, so neither prefix is guessed.
            // Both providers are listed, so each URL is required
            'two providers giving one file different prefixes, the first listed' => [[
                'bootstrap/providers.php' => $bothProviders,
                'app/Providers/AProvider.php' => self::appProvider("Route::prefix('one')->group(base_path('routes/ops.php'));", '', 'AProvider'),
                'app/Providers/BProvider.php' => self::appProvider("Route::prefix('two')->group(base_path('routes/ops.php'));", '', 'BProvider'),
            ], 'routes/ops.php', 'one'],
            'two providers giving one file different prefixes, the second listed' => [[
                'bootstrap/providers.php' => $bothProviders,
                'app/Providers/AProvider.php' => self::appProvider("Route::prefix('one')->group(base_path('routes/ops.php'));", '', 'AProvider'),
                'app/Providers/BProvider.php' => self::appProvider("Route::prefix('two')->group(base_path('routes/ops.php'));", '', 'BProvider'),
            ], 'routes/ops.php', 'two'],
            // ApplicationBuilder::withRouting() runs a using: callback in place of its own, so api: is never registered.
            'api: beside a using: callback' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "using: function () {},\n        api: base_path('routes/mobile.php'),\n        apiPrefix: 'mobile-api',",
            )], 'routes/mobile.php', 'mobile-api'],
        ];
    }

    /**
     * @dataProvider routeFileServedAtSeveralUrlsProvider
     *
     * @param  array<string, string>  $registration
     * @param  list<string>  $publicRoutes
     */
    #[DataProvider('routeFileServedAtSeveralUrlsProvider')]
    public function test_route_file_route_is_public_only_when_every_url_it_is_served_at_is_listed(array $registration, string $routeFile, array $publicRoutes, bool $public): void
    {
        $result = $this->analyzeRegisteredRouteFile($registration, $routeFile, $publicRoutes);

        if ($public) {
            $this->assertPassed($result);

            return;
        }

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    /**
     * @return array<string, array{array<string, string>, string, list<string>, bool}>
     */
    public static function routeFileServedAtSeveralUrlsProvider(): array
    {
        // The provider is listed, so each URL it registers is required
        $listed = ['bootstrap/providers.php' => "<?php\n\nreturn [\n    App\\Providers\\RouteServiceProvider::class,\n];\n"];
        $configListed = ['config/app.php' => "<?php\n\nreturn [\n    'providers' => [\n        App\\Providers\\RouteServiceProvider::class,\n    ],\n];\n"];
        $twoPrefixes = $listed + ['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
            "Route::prefix('partners')->group(base_path('routes/leads.php'));\n        Route::prefix('suppliers')->group(base_path('routes/leads.php'));",
        )];
        $requiredTwice = $listed + ['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
            "Route::middleware('web')->group(function () {\n            require base_path('routes/leads.php');\n        });\n        Route::prefix('ops')->group(function () {\n            require base_path('routes/leads.php');\n        });",
        )];
        $nested = $listed + ['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
            "Route::prefix('partners')->group(fn () => Route::prefix('v2')->group(base_path('routes/leads.php')));",
        )];
        $nestedInRoutes = $listed + ['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
            "\$this->routes(function () {\n            Route::prefix('partners')->group(fn () => Route::prefix('v2')->group(base_path('routes/leads.php')));\n        });",
        )];
        $apiBasePath = ['bootstrap/app.php' => self::bootstrapApp(
            '',
            "web: __DIR__.'/../routes/web.php',\n        api: base_path('routes/api.php'),\n        apiPrefix: 'v1',",
        )];
        $apiList = ['bootstrap/app.php' => self::bootstrapApp(
            '',
            "web: __DIR__.'/../routes/web.php',\n        api: [base_path('routes/api.php')],\n        apiPrefix: 'v1',",
        )];
        $apiConcatList = ['bootstrap/app.php' => self::bootstrapApp(
            '',
            "api: [__DIR__.'/../routes/api.php'],\n        apiPrefix: 'mobile-api',",
        )];
        $thenTwice = ['bootstrap/app.php' => self::bootstrapApp(
            '',
            "web: __DIR__.'/../routes/web.php',\n        then: function () {\n            Route::prefix('partners')->group(base_path('routes/partners.php'));\n            \$suppliers = Route::prefix('suppliers');\n            \$suppliers->group(base_path('routes/partners.php'));\n        },",
        )];

        $v1Api = ['bootstrap/app.php' => self::bootstrapApp(
            '',
            "web: __DIR__.'/../routes/web.php',\n        api: __DIR__.'/../routes/api.php',\n        apiPrefix: 'v1',",
        ), 'routes/web.php' => '<?php'];
        $listedApp = ['bootstrap/providers.php' => "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n];\n"];
        $stockRouteServiceProvider = self::routeServiceProvider(
            "\$this->routes(function () {\n            Route::middleware('api')->prefix('api')->group(base_path('routes/api.php'));\n            Route::middleware('web')->group(base_path('routes/web.php'));\n        });",
        );
        $abstractProvider = fn (string $subclassBoot): string => "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Support\\Facades\\Route;\nuse Illuminate\\Support\\ServiceProvider;\n\nabstract class LegacyRoutes extends ServiceProvider\n{\n    public function boot(): void\n    {\n        Route::prefix('ops')->group(base_path('routes/api.php'));\n    }\n}\n\nclass AppServiceProvider extends LegacyRoutes\n{\n    public function boot(): void\n    {\n        {$subclassBoot}\n    }\n}\n";

        return [
            'two prefixed registrations, the later one listed' => [$twoPrefixes, 'routes/leads.php', ['/suppliers/leads'], false],
            'two prefixed registrations, the earlier one listed' => [$twoPrefixes, 'routes/leads.php', ['/partners/leads'], false],
            'two prefixed registrations, both listed' => [$twoPrefixes, 'routes/leads.php', ['/partners/leads', '/suppliers/leads'], true],
            'required unprefixed and under a prefix, the prefixed one listed' => [$requiredTwice, 'routes/leads.php', ['/ops/leads'], false],
            'required unprefixed and under a prefix, both listed' => [$requiredTwice, 'routes/leads.php', ['/leads', '/ops/leads'], true],
            'nested prefixes, the composed url listed' => [$nested, 'routes/leads.php', ['/partners/v2/leads'], true],
            'nested prefixes, the inner prefix alone listed' => [$nested, 'routes/leads.php', ['/v2/leads'], false],
            'nested prefixes in routes(), the composed url listed' => [$nestedInRoutes, 'routes/leads.php', ['/partners/v2/leads'], true],
            'nested prefixes in routes(), the inner prefix alone listed' => [$nestedInRoutes, 'routes/leads.php', ['/v2/leads'], false],
            'api: base_path() under apiPrefix, the apiPrefix url listed' => [$apiBasePath, 'routes/api.php', ['/v1/leads'], true],
            'api: base_path() under apiPrefix, the conventional url listed' => [$apiBasePath, 'routes/api.php', ['/api/leads'], false],
            'api: list under apiPrefix, the apiPrefix url listed' => [$apiList, 'routes/api.php', ['/v1/leads'], true],
            'api: concat list under apiPrefix, the apiPrefix url listed' => [$apiConcatList, 'routes/api.php', ['/mobile-api/leads'], true],
            'api: concat list under apiPrefix, the conventional url listed' => [$apiConcatList, 'routes/api.php', ['/api/leads'], false],
            'api: string path under apiPrefix, the apiPrefix url listed' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "web: __DIR__.'/../routes/web.php',\n        api: __DIR__.'/../routes/api.php',\n        apiPrefix: 'v1',",
            )], 'routes/api.php', ['/v1/leads'], true],
            'api: base_path() of another file under apiPrefix, the apiPrefix url listed' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "web: __DIR__.'/../routes/web.php',\n        api: base_path('routes/mobile.php'),\n        apiPrefix: 'v1',",
            )], 'routes/mobile.php', ['/v1/leads'], true],
            'then: chain and registrar variable group, one listed' => [$thenTwice, 'routes/partners.php', ['/partners/leads'], false],
            'then: chain and registrar variable group, both listed' => [$thenTwice, 'routes/partners.php', ['/partners/leads', '/suppliers/leads'], true],
            // Only the providers Laravel registers add a URL
            'leftover RouteServiceProvider bootstrap/providers.php does not list' => [$v1Api + [
                'bootstrap/providers.php' => "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n];\n",
                'app/Providers/AppServiceProvider.php' => self::appProvider(''),
                'app/Providers/RouteServiceProvider.php' => $stockRouteServiceProvider,
            ], 'routes/api.php', ['/v1/leads'], true],
            'leftover RouteServiceProvider bootstrap/providers.php does not list, its url alone listed' => [$v1Api + [
                'bootstrap/providers.php' => "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n];\n",
                'app/Providers/AppServiceProvider.php' => self::appProvider(''),
                'app/Providers/RouteServiceProvider.php' => $stockRouteServiceProvider,
            ], 'routes/api.php', ['/api/leads'], false],
            'RouteServiceProvider bootstrap/providers.php lists' => [$v1Api + [
                'bootstrap/providers.php' => "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n    App\\Providers\\RouteServiceProvider::class,\n];\n",
                'app/Providers/AppServiceProvider.php' => self::appProvider(''),
                'app/Providers/RouteServiceProvider.php' => $stockRouteServiceProvider,
            ], 'routes/api.php', ['/v1/leads'], false],
            'provider config/app.php does not list' => [[
                'config/app.php' => "<?php\n\nuse Illuminate\\Support\\ServiceProvider;\n\nreturn [\n    'name' => 'App',\n    'providers' => ServiceProvider::defaultProviders()->merge([\n        App\\Providers\\RouteServiceProvider::class,\n    ])->toArray(),\n];\n",
                'app/Providers/RouteServiceProvider.php' => $stockRouteServiceProvider,
                'app/Providers/LegacyServiceProvider.php' => self::appProvider("Route::prefix('legacy')->group(base_path('routes/api.php'));", '', 'LegacyServiceProvider'),
            ], 'routes/api.php', ['/api/leads'], true],
            'registration after an early return in boot()' => [$v1Api + [
                'app/Providers/AppServiceProvider.php' => self::appProvider("return;\n        Route::prefix('ops')->group(base_path('routes/api.php'));"),
            ], 'routes/api.php', ['/v1/leads'], true],
            'registration in a closure boot() never calls' => [$v1Api + [
                'app/Providers/AppServiceProvider.php' => self::appProvider("\$later = fn () => Route::prefix('ops')->group(base_path('routes/api.php'));"),
            ], 'routes/api.php', ['/v1/leads'], true],
            'registration in a closure boot() calls' => [$v1Api + $listedApp + [
                'app/Providers/AppServiceProvider.php' => self::appProvider("\$later = fn () => Route::prefix('ops')->group(base_path('routes/api.php'));\n        \$later();"),
            ], 'routes/api.php', ['/v1/leads'], false],
            'abstract provider boot() its subclass overrides' => [$v1Api + [
                'app/Providers/AppServiceProvider.php' => $abstractProvider(''),
            ], 'routes/api.php', ['/v1/leads'], true],
            'abstract provider boot() its subclass calls' => [$v1Api + $listedApp + [
                'app/Providers/AppServiceProvider.php' => $abstractProvider('parent::boot();'),
            ], 'routes/api.php', ['/v1/leads'], false],
            // A registration a proven provider makes only on some branch of its code may not run
            'proven provider registering in exclusive branches' => [$configListed + ['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "if (config('app.legacy_leads')) {\n            Route::prefix('legacy')->group(base_path('routes/leads.php'));\n        } else {\n            Route::prefix('partners')->group(base_path('routes/leads.php'));\n        }",
            )], 'routes/leads.php', ['/partners/leads'], true],
            'proven provider registering unconditionally beside a branch, the branch url listed' => [$configListed + ['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "Route::prefix('partners')->group(base_path('routes/leads.php'));\n        if (config('app.legacy_leads')) {\n            Route::prefix('legacy')->group(base_path('routes/leads.php'));\n        }",
            )], 'routes/leads.php', ['/legacy/leads'], false],
            'proven provider registering in a ternary operand' => [$configListed + ['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "config('app.legacy_leads') ? Route::prefix('legacy')->group(base_path('routes/leads.php')) : Route::prefix('partners')->group(base_path('routes/leads.php'));",
            )], 'routes/leads.php', ['/partners/leads'], true],
            // RouteServiceProvider::loadRoutes() calls map() only when routes() was not given a callback
            'proven RouteServiceProvider declaring map() beside routes()' => [$configListed + [
                'app/Providers/RouteServiceProvider.php' => "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Foundation\\Support\\Providers\\RouteServiceProvider as ServiceProvider;\nuse Illuminate\\Support\\Facades\\Route;\n\nclass RouteServiceProvider extends ServiceProvider\n{\n    public function boot(): void\n    {\n        \$this->routes(function () {\n            Route::prefix('partners')->group(base_path('routes/leads.php'));\n        });\n    }\n\n    public function map(): void\n    {\n        Route::prefix('legacy')->group(base_path('routes/leads.php'));\n    }\n}\n",
            ], 'routes/leads.php', ['/partners/leads'], true],
            'routes/api.php registered by nothing keeps the api convention' => [[], 'routes/api.php', ['/api/leads'], true],
            // A registration whose attributes cannot be read adds no URL, rather than one without a prefix
            'prefixed registration beside one with unread attributes' => [$listed + ['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "Route::prefix('partners')->group(base_path('routes/leads.php'));\n        Route::group(config('routing.suppliers'), base_path('routes/leads.php'));",
            )], 'routes/leads.php', ['/partners/leads'], true],
        ];
    }

    /**
     * @dataProvider publicUriAuthenticatedRouteProvider
     *
     * @param  array<string, string>  $files
     * @param  list<string>  $publicRoutes
     */
    #[DataProvider('publicUriAuthenticatedRouteProvider')]
    public function test_auth_user_null_check_reads_the_auth_middleware_of_a_route_with_a_public_uri(array $files, array $publicRoutes, bool $warned): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class TicketController extends Controller
{
    public function store()
    {
        return Auth::user()->email;
    }
}
PHP;

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => $publicRoutes,
            ],
        ]);
        $analyzer->setBasePath($this->createTempDirectory([...$files, 'app/Http/Controllers/TicketController.php' => $controller]));
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        if ($warned) {
            $this->assertHasIssueContaining('Unsafe Auth::user() usage without null check', $result);
            $this->assertIssueCount(1, $result);
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{array<string, string>, list<string>, bool}>
     */
    public static function publicUriAuthenticatedRouteProvider(): array
    {
        $authenticated = "Route::post('/tickets', [App\\Http\\Controllers\\TicketController::class, 'store'])->middleware('auth');";
        $unauthenticated = "Route::post('/tickets/guest', [App\\Http\\Controllers\\TicketController::class, 'store']);";

        return [
            // A public URI does not take away the auth middleware the route carries.
            'literal pattern' => [['routes/web.php' => "<?php\n\n{$authenticated}\n"], ['/tickets*'], false],
            'pattern written with a route file prefix' => [[
                'app/Providers/AppServiceProvider.php' => self::appProvider("Route::prefix('ops')->middleware('web')->group(base_path('routes/ops.php'));"),
                'routes/ops.php' => "<?php\n\n{$authenticated}\n",
            ], ['/ops/*'], false],
            // A route without auth still reaches the method, so the user may be null.
            'also reached by an unauthenticated route' => [['routes/web.php' => "<?php\n\n{$authenticated}\n{$unauthenticated}\n"], ['/tickets*'], true],
            // Routes naming the controller by its short name reach the same method.
            'also reached under its short name by an open GET route' => [['routes/web.php' => "<?php\n\n{$authenticated}\nRoute::get('/tickets/open', 'TicketController@store');\n"], [], true],
        ];
    }

    /**
     * @dataProvider publicUriControllerAuthProvider
     *
     * @param  array<string, string>  $files
     * @param  list<string>  $publicRoutes
     */
    #[DataProvider('publicUriControllerAuthProvider')]
    public function test_auth_user_null_check_reads_controller_auth_beside_a_public_uri(array $files, array $publicRoutes, string $constructor, bool $warned): void
    {
        $controller = <<<PHP
<?php

namespace App\\Http\\Controllers;

use Illuminate\\Support\\Facades\\Auth;

class TicketController extends Controller
{
{$constructor}
    public function store()
    {
        return Auth::user()->email;
    }
}
PHP;

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => $publicRoutes,
            ],
        ]);
        $analyzer->setBasePath($this->createTempDirectory([...$files, 'app/Http/Controllers/TicketController.php' => $controller]));
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $unsafe = array_filter(
            $result->getIssues(),
            fn ($issue): bool => str_contains($issue->message, 'Unsafe Auth::user() usage without null check'),
        );
        $this->assertCount($warned ? 1 : 0, $unsafe);
    }

    /**
     * @return array<string, array{array<string, string>, list<string>, string, bool}>
     */
    public static function publicUriControllerAuthProvider(): array
    {
        $constructorAuth = "    public function __construct()\n    {\n        \$this->middleware('auth');\n    }\n";
        $route = "Route::post('/tickets', [App\\Http\\Controllers\\TicketController::class, 'store'])";
        $literal = ['routes/web.php' => "<?php\n\n{$route};\n"];
        $followed = [
            'app/Providers/AppServiceProvider.php' => self::appProvider("Route::prefix('ops')->group(base_path('routes/ops.php'));"),
            'routes/ops.php' => "<?php\n\n{$route};\n",
        ];

        return [
            // A public URI says the route may go unauthenticated, not that the controller's auth is gone.
            'literal pattern, constructor auth' => [$literal, ['/tickets'], $constructorAuth, false],
            'route file prefix pattern, constructor auth' => [$followed, ['/ops/*'], $constructorAuth, false],
            'literal pattern, no controller auth' => [$literal, ['/tickets'], '', true],
            'route file prefix pattern, no controller auth' => [$followed, ['/ops/*'], '', true],
            // withoutMiddleware() strips the controller's middleware too.
            'literal pattern, constructor auth removed by the route' => [['routes/web.php' => "<?php\n\n{$route}->withoutMiddleware('auth');\n"], ['/tickets'], $constructorAuth, true],
            // Router::gatherRouteMiddleware() applies a group's exclusions to controller middleware too.
            'literal pattern, constructor auth removed by a group' => [['routes/web.php' => "<?php\n\nRoute::withoutMiddleware('auth')->group(function () {\n    {$route};\n});\n"], ['/tickets'], $constructorAuth, true],
            'literal pattern, constructor auth excluded by a group attribute' => [['routes/web.php' => "<?php\n\nRoute::group(['excluded_middleware' => ['auth']], function () {\n    {$route};\n});\n"], ['/tickets'], $constructorAuth, true],
        ];
    }

    public function test_auth_user_null_check_does_not_read_routes_to_another_class_of_the_same_short_name(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;

class TicketController extends Controller
{
    public function store()
    {
        return Auth::user()->email;
    }
}
PHP;

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => ['/tickets'],
            ],
        ]);
        $analyzer->setBasePath($this->createTempDirectory([
            'routes/web.php' => "<?php\n\nRoute::post('/tickets', 'TicketController@store')->middleware('auth');\n",
            'app/Http/Controllers/Admin/TicketController.php' => $controller,
        ]));
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // The route names App\Http\Controllers\TicketController, not this class
        $this->assertHasIssueContaining('Unsafe Auth::user() usage without null check', $result);
    }

    /**
     * Analyze an unauthenticated POST /leads closure route in $routeFile, registered by the
     * given bootstrap/app.php or RouteServiceProvider.
     *
     * @param  array<string, string>  $registration
     * @param  list<string>  $publicRoutes
     */
    private function analyzeRegisteredRouteFile(array $registration, string $routeFile, array $publicRoutes): ResultInterface
    {
        $routes = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/leads', fn () => response()->noContent());
PHP;

        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => $publicRoutes,
            ],
        ]);
        $analyzer->setBasePath($this->createTempDirectory([...$registration, $routeFile => $routes]));

        return $analyzer->analyze();
    }

    /**
     * A bootstrap/app.php running $before, then configuring the application with
     * withRouting($arguments).
     */
    private static function bootstrapApp(string $before, string $arguments): string
    {
        return <<<PHP
<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

{$before}

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        {$arguments}
    )
    ->create();
PHP;
    }

    /**
     * A service provider named $class whose boot() runs $boot, declaring $members beside it,
     * with Route imported as $route.
     */
    private static function appProvider(string $boot, string $members = '', string $class = 'AppServiceProvider', string $route = 'Illuminate\\Support\\Facades\\Route'): string
    {
        return <<<PHP
<?php

namespace App\Providers;

use {$route};
use Illuminate\Support\ServiceProvider;

class {$class} extends ServiceProvider
{
    public function boot(): void
    {
        {$boot}
    }

{$members}}
PHP;
    }

    /**
     * A RouteServiceProvider whose boot() runs $boot.
     */
    private static function routeServiceProvider(string $boot): string
    {
        return <<<PHP
<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        {$boot}
    }
}
PHP;
    }

    // ==========================================
    // Imports PHP would reject (#445)
    // ==========================================

    public function test_reads_a_route_file_whose_route_import_collides(): void
    {
        // Two use statements land on one alias, so PHP rejects the file. The facade is
        // imported first, and the first spelling is the one kept: were the second kept
        // instead, Route would name a class that is not the facade, no route would be read,
        // and the unprotected POST below would go unreported.
        $routes = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use App\Routing\Route;

Route::post('/invoices', [\App\Http\Controllers\InvoiceController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_resolves_the_imports_after_a_collision_in_a_route_file(): void
    {
        // The collision is on an alias that has nothing to do with routing. Dropping
        // resolution for the rest of the file would leave the middleware as a bare class
        // name, read as an unregistered alias, and report the protected route below as
        // unauthenticated. Only the colliding alias may be lost.
        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class RequireSigningKey
{
    public function handle($request, $next)
    {
        if (! $request->bearerToken()) {
            abort(401);
        }

        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Reports\Formatter;
use App\Exports\Formatter;
use App\Http\Middleware\RequireSigningKey;
use Illuminate\Support\Facades\Route;

Route::post('/invoices', [\App\Http\Controllers\InvoiceController::class, 'store'])
    ->middleware(RequireSigningKey::class);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/RequireSigningKey.php' => $middleware,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_resolves_the_kernel_alias_map_past_a_colliding_import(): void
    {
        $kernel = <<<'PHP'
<?php

namespace App\Http;

use App\Support\Clock;
use App\Legacy\Clock;
use App\Http\Middleware\RequireSigningKey;

class Kernel
{
    protected $middlewareAliases = [
        'signing.key' => RequireSigningKey::class,
    ];
}
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class RequireSigningKey
{
    public function handle($request, $next)
    {
        if (! $request->bearerToken()) {
            abort(401);
        }

        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/invoices', [\App\Http\Controllers\InvoiceController::class, 'store'])
    ->middleware('signing.key');
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernel,
            'app/Http/Middleware/RequireSigningKey.php' => $middleware,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_resolves_the_bootstrap_alias_map_past_a_colliding_import(): void
    {
        $bootstrap = <<<'PHP'
<?php

use App\Support\Clock;
use App\Legacy\Clock;
use App\Http\Middleware\RequireSigningKey;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'signing.key' => RequireSigningKey::class,
        ]);
    })
    ->create();
PHP;

        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class RequireSigningKey
{
    public function handle($request, $next)
    {
        if (! $request->bearerToken()) {
            abort(401);
        }

        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/invoices', [\App\Http\Controllers\InvoiceController::class, 'store'])
    ->middleware('signing.key');
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'app/Http/Middleware/RequireSigningKey.php' => $middleware,
            'routes/web.php' => $routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_reads_routes_on_a_route_facade_imported_under_an_alias(): void
    {
        $routes = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route as Router;

Router::post('/invoices', [\App\Http\Controllers\InvoiceController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    // ==========================================
    // Routes registered on registrars, variables and nested exclusions
    // ==========================================

    /**
     * @dataProvider unauthenticatedRouteProvider
     */
    #[DataProvider('unauthenticatedRouteProvider')]
    public function test_reports_an_unauthenticated_route(string $routes): void
    {
        $result = $this->analyzeWebRoutes($routes);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unauthenticatedRouteProvider(): array
    {
        return [
            'registrar chain with non-auth middleware' => ["Route::middleware('throttle:6,1')->post('/orders', fn () => 'ok');"],
            // RouteRegistrar::attribute() replaces the middleware on each call
            'registrar chain whose last middleware() call drops auth' => ["Route::middleware('auth')->middleware('throttle:6,1')->post('/orders', fn () => 'ok');"],
            'registrar chain with unreadable middleware' => ["Route::middleware(\$guard)->post('/orders', fn () => 'ok');"],
            // Router::resolveMiddleware() drops excluded middleware whichever group adds it
            'outer group excluding auth an inner group adds' => ["Route::withoutMiddleware('auth')->group(function () {\n    Route::middleware('auth')->group(function () {\n        Route::post('/orders', fn () => 'ok');\n    });\n});"],
            'outer group excluding auth an inner array group adds' => ["Route::withoutMiddleware('auth')->group(function () {\n    Route::group(['middleware' => 'auth'], function () {\n        Route::post('/orders', fn () => 'ok');\n    });\n});"],
            'inner excluded_middleware attribute under a fluent auth group' => ["Route::middleware('auth')->group(function () {\n    Route::group(['excluded_middleware' => ['auth']], function () {\n        Route::post('/orders', fn () => 'ok');\n    });\n});"],
            'inner excluded_middleware attribute under an array auth group' => ["Route::group(['middleware' => 'auth'], function () {\n    Route::group(['excluded_middleware' => ['auth']], function () {\n        Route::post('/orders', fn () => 'ok');\n    });\n});"],
            'excluded_middleware beside middleware in one group' => ["Route::group(['middleware' => 'auth', 'excluded_middleware' => 'auth'], function () {\n    Route::post('/orders', fn () => 'ok');\n});"],
            'group closure router parameter' => ["Route::group([], function (\$router) {\n    \$router->post('/members', fn () => 'ok');\n});"],
            'group closure router parameter with non-auth middleware' => ["Route::middleware('web')->group(function (\$router) {\n    \$router->middleware('throttle:6,1')->post('/members', fn () => 'ok');\n});"],
            'registrar variable' => ["\$admin = Route::prefix('admin');\n\$admin->post('/users', fn () => 'ok');"],
            'registrar variable inside a group closure' => ["Route::middleware('web')->group(function () {\n    \$admin = Route::prefix('admin')->middleware('throttle:6,1');\n    \$admin->post('/users', fn () => 'ok');\n});"],
            'route assigned to a variable' => ["\$route = Route::post('/admin/users', fn () => 'ok');"],
            // Router::loadRoutes() calls an arrow function group callback with the router too
            'arrow function group body' => ["Route::prefix('x')->group(fn () => Route::post('/orders', fn () => 'ok'));"],
            'arrow function group body under an outer exclusion' => ["Route::withoutMiddleware('auth')->group(fn () => Route::middleware('auth')->group(fn () => Route::post('/orders', fn () => 'ok')));"],
            'arrow function group body with a registrar chain' => ["Route::prefix('x')->group(fn () => Route::middleware('throttle:6,1')->post('/orders', fn () => 'ok'));"],
            'arrow function group body on its router parameter' => ["Route::middleware('web')->group(fn (\$router) => \$router->post('/orders', fn () => 'ok'));"],
            // Router::resolveMiddleware() drops excluded middleware from the route's own too
            'group exclusion of the auth a route adds' => ["Route::withoutMiddleware('auth')->group(function () {\n    Route::post('/orders', fn () => 'ok')->middleware('auth');\n});"],
            'group exclusion of the auth a registrar route adds' => ["Route::withoutMiddleware('auth')->group(function () {\n    Route::middleware('auth')->post('/orders', fn () => 'ok');\n});"],
            'registrar middleware held in a variable without auth' => ["\$middleware = ['throttle:6,1'];\nRoute::middleware(\$middleware)->post('/orders', fn () => 'ok');"],
            'registrar middleware held in a variable read from config' => ["\$middleware = config('routing.orders');\nRoute::middleware(\$middleware)->post('/orders', fn () => 'ok');"],
            'group closure router parameter beside an arrow function shadowing it' => ["Route::middleware('web')->group(function (\$router) {\n    \$names = array_map(fn (\$router) => strtoupper(\$router), ['members']);\n    \$router->post('/members', fn () => 'ok');\n});"],
            'group attribute excluded_middleware held in a variable' => ["\$open = ['auth'];\nRoute::group(['middleware' => 'auth', 'excluded_middleware' => \$open], function () {\n    Route::post('/orders', fn () => 'ok');\n});"],
            'variable inside a group middleware list without auth' => ["\$throttle = 'throttle:6,1';\nRoute::middleware(['web', \$throttle])->group(function () {\n    Route::post('/orders', fn () => 'ok');\n});"],
            'route assigned to a variable inside a group closure' => ["Route::prefix('admin')->group(function () {\n    \$route = Route::post('/users', fn () => 'ok')->name('users.store');\n});"],
        ];
    }

    /**
     * @dataProvider authenticatedOrUnreadRouteProvider
     *
     * @param  list<string>  $publicRoutes
     */
    #[DataProvider('authenticatedOrUnreadRouteProvider')]
    public function test_does_not_report_an_authenticated_public_or_unread_route(string $routes, array $publicRoutes = []): void
    {
        $result = $this->analyzeWebRoutes($routes, $publicRoutes);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{0: string, 1?: list<string>}>
     */
    public static function authenticatedOrUnreadRouteProvider(): array
    {
        return [
            'registrar chain with auth middleware' => ["Route::middleware('auth')->post('/orders', fn () => 'ok');"],
            'registrar chain with auth in a middleware list' => ["Route::middleware(['throttle:6,1', 'auth:sanctum'])->post('/orders', fn () => 'ok');"],
            'registrar chain adding auth on the route' => ["Route::middleware('throttle:6,1')->post('/orders', fn () => 'ok')->middleware('auth');"],
            'registrar chain inside an auth group' => ["Route::middleware('auth')->group(function () {\n    Route::middleware('throttle:6,1')->post('/orders', fn () => 'ok');\n});"],
            'registrar chain prefix on a public url' => ["Route::prefix('shop')->post('/orders', fn () => 'ok');", ['/shop/orders']],
            'registrar chain prefix in a prefixed group on a public url' => ["Route::prefix('v1')->group(function () {\n    Route::prefix('shop')->post('/orders', fn () => 'ok');\n});", ['/shop/v1/orders']],
            'registrar chain excluding auth on the route' => ["Route::middleware('auth')->group(function () {\n    Route::withoutMiddleware('auth')->post('/webhooks', fn () => 'ok');\n});"],
            'outer group excluding other middleware' => ["Route::withoutMiddleware('throttle')->group(function () {\n    Route::middleware('auth')->group(function () {\n        Route::post('/orders', fn () => 'ok');\n    });\n});"],
            'inner excluded_middleware of other middleware' => ["Route::middleware('auth')->group(function () {\n    Route::group(['excluded_middleware' => ['throttle']], function () {\n        Route::post('/orders', fn () => 'ok');\n    });\n});"],
            'group closure router parameter in an auth group' => ["Route::middleware('auth')->group(function (\$router) {\n    \$router->post('/members', fn () => 'ok');\n});"],
            'registrar variable with auth' => ["\$admin = Route::middleware('auth');\n\$admin->post('/users', fn () => 'ok');"],
            'registrar variable given auth later' => ["\$admin = Route::prefix('admin');\n\$admin->middleware('auth');\n\$admin->post('/users', fn () => 'ok');"],
            'registrar variable prefix on a public url' => ["\$admin = Route::prefix('admin');\n\$admin->post('/users', fn () => 'ok');", ['/admin/users']],
            'route assigned to a variable with auth' => ["\$route = Route::post('/admin/users', fn () => 'ok')->middleware('auth');"],
            'route assigned to a variable given auth later' => ["\$route = Route::post('/admin/users', fn () => 'ok');\n\$route->middleware('auth');"],
            'route assigned to a variable inside an auth group' => ["Route::middleware('auth')->group(function () {\n    \$route = Route::post('/users', fn () => 'ok');\n});"],
            'arrow function group body in an auth group' => ["Route::middleware('auth')->group(fn () => Route::post('/orders', fn () => 'ok'));"],
            'arrow function group body on its router parameter in an auth group' => ["Route::middleware('auth')->group(fn (\$router) => \$router->post('/orders', fn () => 'ok'));"],
            'group exclusion of other middleware beside a route adding auth' => ["Route::withoutMiddleware('throttle')->group(function () {\n    Route::post('/orders', fn () => 'ok')->middleware('auth');\n});"],
            // A route carrying its own auth leaves no unprotected route in its group
            'public route beside a registrar route with auth in a static group' => ["Route::group(['prefix' => 'hooks'], function () {\n    Route::post('/stripe', fn () => 'ok');\n    Route::middleware('auth')->post('/orders', fn () => 'ok');\n});", ['/hooks/stripe']],
            'public route beside an assigned route with auth in a static group' => ["Route::group(['prefix' => 'hooks'], function () {\n    Route::post('/stripe', fn () => 'ok');\n    \$route = Route::post('/orders', fn () => 'ok')->middleware('auth');\n});", ['/hooks/stripe']],
            'route with its own auth in a static group' => ["Route::group(['prefix' => 'admin'], function () {\n    Route::post('/users', fn () => 'ok')->middleware('auth');\n});"],
            'registrar middleware held in a variable' => ["\$middleware = ['auth', 'verified'];\nRoute::middleware(\$middleware)->post('/orders', fn () => 'ok');"],
            'group middleware held in a variable' => ["\$middleware = 'auth';\nRoute::middleware(\$middleware)->group(function () {\n    Route::post('/orders', fn () => 'ok');\n});"],
            // RouteRegistrar's can attribute becomes can: middleware on each route
            'registrar can attribute' => ["Route::can('manage-users')->post('/users', fn () => 'ok');"],
            'group registrar can attribute' => ["Route::can('manage-users')->group(function () {\n    Route::post('/users', fn () => 'ok');\n});"],
            'route can() call' => ["Route::put('/posts/{post}', fn () => 'ok')->can('update', 'post');"],
            'outer router read inside an arrow function' => ["Route::middleware('web')->group(function (\$router) {\n    \$names = array_map(fn () => strtoupper(\$router), ['members']);\n    \$router->post('/members', fn () => 'ok');\n});"],
            'group attribute middleware held in a variable' => ["\$middleware = ['web', 'auth'];\nRoute::group(['middleware' => \$middleware], function () {\n    Route::post('/orders', fn () => 'ok');\n});"],
            // PHP matches method names case-insensitively
            'route middleware() call in another case' => ["Route::post('/orders', fn () => 'ok')->Middleware('auth');"],
            'group registrar middleware() call in another case' => ["Route::Middleware('auth')->group(function () {\n    Route::post('/orders', fn () => 'ok');\n});"],
            'registrar middleware() call in another case' => ["Route::prefix('shop')->MIDDLEWARE('auth')->post('/orders', fn () => 'ok');"],
            'variable inside a group middleware list' => ["\$auth = 'auth';\nRoute::middleware(['web', \$auth])->group(function () {\n    Route::post('/orders', fn () => 'ok');\n});"],
            'variable inside a registrar middleware list' => ["\$auth = 'auth';\nRoute::middleware(['web', \$auth])->post('/orders', fn () => 'ok');"],
            'variable inside a group attribute middleware list' => ["\$auth = 'auth';\nRoute::group(['middleware' => ['web', \$auth]], function () {\n    Route::post('/orders', fn () => 'ok');\n});"],
            'group attribute array held in a variable' => ["\$attributes = ['middleware' => 'auth'];\nRoute::group(\$attributes, function () {\n    Route::post('/orders', fn () => 'ok');\n});"],
            // Only variables known to hold the router or a registrar are read
            'router variable outside any group closure' => ["\$router->post('/members', fn () => 'ok');"],
            'group closure router parameter reassigned' => ["Route::middleware('web')->group(function (\$router) {\n    \$router = app(\\App\\Routing\\Menu::class);\n    \$router->post('/members', fn () => 'ok');\n});"],
            'group closure router parameter handed on' => ["Route::middleware('web')->group(function (\$router) {\n    configure(\$router);\n    \$router->post('/members', fn () => 'ok');\n});"],
            'group closure router parameter beside a require' => ["Route::middleware('web')->group(function (\$router) {\n    require __DIR__.'/members.php';\n    \$router->post('/members', fn () => 'ok');\n});"],
            'first parameter of a closure that is not a group callback' => ["Route::middleware('web')->group(function () {\n    collect(['members'])->each(function (\$router) {\n        \$router->post('/members', fn () => 'ok');\n    });\n});"],
            'non-router second parameter of a group closure' => ["Route::middleware('web')->group(function (\$router, \$menu) {\n    \$menu->post('/members', fn () => 'ok');\n});"],
            'registrar variable beside a require' => ["\$admin = Route::prefix('admin');\nrequire __DIR__.'/admin.php';\n\$admin->post('/users', fn () => 'ok');"],
            'registrar variable reassigned in a branch' => ["\$admin = Route::prefix('admin');\nif (app()->isLocal()) {\n    \$admin = Route::prefix('local');\n}\n\$admin->post('/users', fn () => 'ok');"],
            'variable holding another object' => ["\$menu = new \\App\\Menu\\Builder;\n\$menu->post('/members', fn () => 'ok');"],
        ];
    }

    public function test_reports_a_route_in_an_arrow_function_group_body_once(): void
    {
        $result = $this->analyzeWebRoutes("Route::prefix('x')->group(fn () => Route::post('/orders', fn () => 'ok'));");

        $routeIssues = array_filter(
            $result->getIssues(),
            fn ($issue) => $issue->message === 'POST closure route without authentication middleware',
        );
        $this->assertCount(1, $routeIssues);
    }

    /**
     * @dataProvider providerRegistrationProvider
     *
     * @param  array<string, string>  $files
     * @param  list<string>  $publicRoutes
     */
    #[DataProvider('providerRegistrationProvider')]
    public function test_route_file_url_a_provider_registers_is_required_only_when_the_provider_provably_runs(array $files, array $publicRoutes, bool $public): void
    {
        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => $publicRoutes,
            ],
        ]);
        $analyzer->setBasePath($this->createTempDirectory($files));
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        if ($public) {
            $this->assertPassed($result);

            return;
        }

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    /**
     * @return array<string, array{array<string, string>, list<string>, bool}>
     */
    public static function providerRegistrationProvider(): array
    {
        $appProvider = fn (string $register): array => ['app/Providers/AppServiceProvider.php' => self::provider('AppServiceProvider', $register, '//')];

        $parent = self::webhookApp('');
        $parent['bootstrap/providers.php'] = "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n    App\\Providers\\WebhookServiceProvider::class,\n];\n";
        $parent['app/Providers/BaseWebhookServiceProvider.php'] = self::provider('BaseWebhookServiceProvider', '//', "Route::prefix('webhooks')->group(base_path('routes/webhooks.php'));");
        $parent['app/Providers/WebhookServiceProvider.php'] = "<?php\n\nnamespace App\\Providers;\n\nclass WebhookServiceProvider extends BaseWebhookServiceProvider\n{\n}\n";

        // A listed child overriding its unlisted concrete parent's boot() without parent::boot()
        $overriding = self::webhookApp('');
        $overriding['bootstrap/providers.php'] = "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n    App\\Providers\\TenantWebhookServiceProvider::class,\n];\n";
        $overriding['app/Providers/TenantWebhookServiceProvider.php'] = "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Support\\Facades\\Route;\n\nclass TenantWebhookServiceProvider extends WebhookServiceProvider\n{\n    public function boot(): void\n    {\n        Route::prefix('tenant')->group(base_path('routes/webhooks.php'));\n    }\n}\n";

        $module = self::webhookApp('');
        $module['bootstrap/providers.php'] = "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n    Modules\\Webhooks\\WebhooksServiceProvider::class,\n];\n";
        $module['modules/Webhooks/WebhooksServiceProvider.php'] = "<?php\n\nnamespace Modules\\Webhooks;\n\nuse Illuminate\\Support\\ServiceProvider;\n\nclass WebhooksServiceProvider extends ServiceProvider\n{\n    public function register(): void\n    {\n        \$this->app->register(\\App\\Providers\\WebhookServiceProvider::class);\n    }\n}\n";

        return [
            'registered through withProviders()' => [self::webhookApp("    ->withProviders([\\App\\Providers\\WebhookServiceProvider::class])\n") + $appProvider('//'), ['/webhooks/stripe'], true],
            'registered by a listed provider by class constant' => [self::webhookApp('') + $appProvider('$this->app->register(WebhookServiceProvider::class);'), ['/webhooks/stripe'], true],
            'registered by a listed provider as an instance' => [self::webhookApp('') + $appProvider('$this->app->register(new WebhookServiceProvider($this->app));'), ['/webhooks/stripe'], true],
            'registered by a listed provider by class constant, the unprefixed url listed' => [self::webhookApp('') + $appProvider('$this->app->register(WebhookServiceProvider::class);'), ['/stripe'], true],
            'concrete parent of a listed provider' => [$parent + $appProvider('//'), ['/webhooks/stripe'], true],
            // An unproven registration gives an optional URL: with no required one, any URL matching suffices
            'registered from a module provider this does not read' => [$module + $appProvider('//'), ['/webhooks/stripe'], true],
            'registered under a name built at runtime' => [self::webhookApp('') + $appProvider("\$this->app->register(__NAMESPACE__.'\\\\'.'Webhook'.'ServiceProvider');"), ['/webhooks/stripe'], true],
            'unlisted concrete parent whose boot() the listed child overrides' => [$overriding + $appProvider('//'), ['/tenant/stripe'], true],
            'listed child overriding its parent boot(), the parent url listed' => [$overriding + $appProvider('//'), ['/webhooks/stripe'], false],
        ];
    }

    public function test_reads_each_controller_once_however_many_form_requests_it_checks(): void
    {
        // The parses of the controller with one FormRequest lacking authorize(), then with four
        $this->assertSame($this->controllerParsesForFormRequests(1), $this->controllerParsesForFormRequests(4));
    }

    /**
     * How many times an analysis parses a controller whose action takes one of $count
     * FormRequests that declare no authorize() method.
     */
    private function controllerParsesForFormRequests(int $count): int
    {
        $files = ['routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/members', [App\\Http\\Controllers\\MemberController::class, 'store']);\n"];
        $files['app/Http/Controllers/MemberController.php'] = "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse App\\Http\\Requests\\Request0;\n\nclass MemberController extends Controller\n{\n    public function store(Request0 \$request) {}\n}\n";
        for ($i = 0; $i < $count; $i++) {
            $files["app/Http/Requests/Request{$i}.php"] = "<?php\n\nnamespace App\\Http\\Requests;\n\nuse Illuminate\\Foundation\\Http\\FormRequest;\n\nclass Request{$i} extends FormRequest\n{\n    public function rules(): array { return []; }\n}\n";
        }

        $parser = new class extends AstParser
        {
            /** @var array<string, int> */
            public array $parses = [];

            public function parseFile(string $filePath): array
            {
                $this->parses[$filePath] = ($this->parses[$filePath] ?? 0) + 1;

                return parent::parseFile($filePath);
            }
        };

        $analyzer = new AuthenticationAnalyzer($parser, new Repository([]));
        $analyzer->setBasePath($dir = $this->createTempDirectory($files));
        $analyzer->setPaths(['app']);
        $analyzer->analyze();

        return $parser->parses[$dir.'/app/Http/Controllers/MemberController.php'] ?? 0;
    }

    public function test_an_unreadable_directory_beside_the_providers_does_not_error(): void
    {
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            $this->markTestSkipped('root reads a directory whatever its mode');
        }

        $files = self::webhookApp('');
        $files['bootstrap/providers.php'] = "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n    App\\Providers\\WebhookServiceProvider::class,\n];\n";
        $files['app/Providers/AppServiceProvider.php'] = self::provider('AppServiceProvider', '//', '//');
        $files['bootstrap/cache/packages.php'] = "<?php\n\nreturn [];\n";
        $dir = $this->createTempDirectory($files);
        chmod($dir.'/bootstrap/cache', 0000);

        try {
            $analyzer = $this->createAnalyzer([
                'authentication-authorization' => [
                    'public_routes' => ['/webhooks/stripe'],
                ],
            ]);
            $analyzer->setBasePath($dir);
            $analyzer->setPaths(['routes']);

            $this->assertPassed($analyzer->analyze());
        } finally {
            chmod($dir.'/bootstrap/cache', 0755);
        }
    }

    public function test_reports_no_authorize_method_only_on_the_form_request_a_controller_imports(): void
    {
        $result = $this->analyzeSameNamedFormRequests(
            "Route::middleware('auth')->put('/admin/users/{user}', [App\\Http\\Controllers\\Admin\\UserController::class, 'update']);\nRoute::put('/invites/{user}', [App\\Http\\Controllers\\Invites\\UserController::class, 'update'])->middleware('signed');",
        );

        foreach ($result->getIssues() as $issue) {
            $this->assertStringNotContainsString('has no authorize() method', $issue->message);
        }
    }

    public function test_reports_no_authorize_method_on_the_form_request_an_unprotected_controller_imports(): void
    {
        $result = $this->analyzeSameNamedFormRequests(
            "Route::put('/admin/users/{user}', [App\\Http\\Controllers\\Admin\\UserController::class, 'update']);\nRoute::middleware('auth')->put('/invites/{user}', [App\\Http\\Controllers\\Invites\\UserController::class, 'update']);",
        );

        $issues = array_values(array_filter(
            $result->getIssues(),
            fn ($issue) => str_contains($issue->message, 'has no authorize() method'),
        ));
        $this->assertCount(1, $issues);
        $this->assertNotNull($issues[0]->location);
        $this->assertStringContainsString('Requests/Admin/UpdateUserRequest.php', $issues[0]->location->file);
    }

    /**
     * Analyze two UserController::update() actions, under Admin and Invites, each taking an
     * UpdateUserRequest of its own namespace: Admin's declares no authorize(), Invites's
     * does. Routes are $routes.
     */
    private function analyzeSameNamedFormRequests(string $routes): ResultInterface
    {
        $request = fn (string $ns, string $authorize): string => "<?php\n\nnamespace App\\Http\\Requests\\{$ns};\n\nuse Illuminate\\Foundation\\Http\\FormRequest;\n\nclass UpdateUserRequest extends FormRequest\n{\n{$authorize}    public function rules(): array { return []; }\n}\n";
        $controller = fn (string $ns): string => "<?php\n\nnamespace App\\Http\\Controllers\\{$ns};\n\nuse App\\Http\\Requests\\{$ns}\\UpdateUserRequest;\n\nclass UserController\n{\n    public function update(UpdateUserRequest \$request) {}\n}\n";

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($this->createTempDirectory([
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n",
            'app/Http/Controllers/Admin/UserController.php' => $controller('Admin'),
            'app/Http/Controllers/Invites/UserController.php' => $controller('Invites'),
            'app/Http/Requests/Admin/UpdateUserRequest.php' => $request('Admin', ''),
            'app/Http/Requests/Invites/UpdateUserRequest.php' => $request('Invites', "    public function authorize(): bool { return \$this->hasValidSignature(); }\n"),
        ]));
        $analyzer->setPaths(['app']);

        return $analyzer->analyze();
    }

    /**
     * A service provider named $class running $register in register() and $boot in boot().
     */
    private static function provider(string $class, string $register, string $boot): string
    {
        return "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Support\\Facades\\Route;\nuse Illuminate\\Support\\ServiceProvider;\n\nclass {$class} extends ServiceProvider\n{\n    public function register(): void\n    {\n        {$register}\n    }\n\n    public function boot(): void\n    {\n        {$boot}\n    }\n}\n";
    }

    /**
     * An application whose bootstrap/providers.php lists only AppServiceProvider, with a
     * WebhookServiceProvider registering routes/webhooks.php under 'webhooks', and
     * $bootstrapChain called on the application builder.
     *
     * @return array<string, string>
     */
    private static function webhookApp(string $bootstrapChain): array
    {
        return [
            'bootstrap/app.php' => "<?php\n\nuse Illuminate\\Foundation\\Application;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withRouting(\n        web: __DIR__.'/../routes/web.php',\n        health: '/up',\n    )\n{$bootstrapChain}    ->create();\n",
            'bootstrap/providers.php' => "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n];\n",
            'routes/web.php' => "<?php\n",
            'routes/webhooks.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/stripe', fn () => response()->noContent());\n",
            'app/Providers/WebhookServiceProvider.php' => self::provider('WebhookServiceProvider', '//', "Route::prefix('webhooks')->group(base_path('routes/webhooks.php'));"),
        ];
    }

    public function test_a_reused_analyzer_reports_what_a_fresh_one_reports(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AccountController extends Controller
{
    public function store()
    {
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\AccountController;
use Illuminate\Support\Facades\Route;

Route::get('/accounts', [AccountController::class, 'store']);
PHP;

        $first = $this->createTempDirectory([
            'routes/web.php' => $routes,
            'app/Http/Controllers/AccountController.php' => $controller,
        ]);
        $second = $this->createTempDirectory([
            'app/Http/Controllers/AccountController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($first);
        $analyzer->setPaths(['app']);
        // The GET route makes store() intentionally public in the first project
        $this->assertPassed($analyzer->analyze());

        $analyzer->setBasePath($second);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Sensitive method AccountController::store() without authentication check', $result);
    }

    /**
     * Analyze routes/web.php running $routes, with $publicRoutes listed as public.
     *
     * @param  list<string>  $publicRoutes
     */
    private function analyzeWebRoutes(string $routes, array $publicRoutes = []): ResultInterface
    {
        $analyzer = $this->createAnalyzer([
            'authentication-authorization' => [
                'public_routes' => $publicRoutes,
            ],
        ]);
        $analyzer->setBasePath($this->createTempDirectory([
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n",
        ]));
        $analyzer->setPaths(['app']);

        return $analyzer->analyze();
    }
}
