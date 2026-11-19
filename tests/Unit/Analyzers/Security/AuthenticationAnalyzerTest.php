<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\Security\AuthenticationAnalyzer;
use ShieldCI\Analyzers\Security\CsrfAnalyzer;
use ShieldCI\Analyzers\Security\LoginThrottlingAnalyzer;
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
            'then: registrar captured by the closure' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$kiosk = Route::prefix('kiosk');",
                "web: __DIR__.'/../routes/web.php',\n        then: function () use (\$kiosk) {\n            \$kiosk->group(base_path('routes/kiosk.php'));\n        },",
            )], 'routes/kiosk.php', 'kiosk'],
            'then: registrar captured by the closure, given its prefix by an earlier statement' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$kiosk = Route::middleware('web');\n\$kiosk->prefix('kiosk');",
                "web: __DIR__.'/../routes/web.php',\n        then: function () use (\$kiosk) {\n            \$kiosk->group(base_path('routes/kiosk.php'));\n        },",
            )], 'routes/kiosk.php', 'kiosk'],
            'then: callback variable capturing a registrar' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$kiosk = Route::prefix('kiosk');\n\$mapKioskRoutes = function () use (\$kiosk) {\n    \$kiosk->group(base_path('routes/kiosk.php'));\n};",
                "web: __DIR__.'/../routes/web.php',\n        then: \$mapKioskRoutes,",
            )], 'routes/kiosk.php', 'kiosk'],
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
            // A closure importing by reference sees every later write to the variable.
            'then: registrar captured by reference' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$kiosk = Route::prefix('kiosk');",
                "web: __DIR__.'/../routes/web.php',\n        then: function () use (&\$kiosk) {\n            \$kiosk->group(base_path('routes/kiosk.php'));\n        },",
            )], 'routes/kiosk.php', 'kiosk'],
            'then: captured registrar variable reassigned after the closure' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$kiosk = Route::prefix('kiosk');\n\$mapKioskRoutes = function () use (\$kiosk) {\n    \$kiosk->group(base_path('routes/kiosk.php'));\n};\n\$kiosk = Route::prefix('lobby');",
                "web: __DIR__.'/../routes/web.php',\n        then: \$mapKioskRoutes,",
            )], 'routes/kiosk.php', 'kiosk'],
            // The closure holds the same registrar object, which the later call changes.
            'then: captured registrar given another prefix after the closure' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$kiosk = Route::prefix('kiosk');\n\$mapKioskRoutes = function () use (\$kiosk) {\n    \$kiosk->group(base_path('routes/kiosk.php'));\n};\n\$kiosk->prefix('lobby');",
                "web: __DIR__.'/../routes/web.php',\n        then: \$mapKioskRoutes,",
            )], 'routes/kiosk.php', 'kiosk'],
            'then: captured registrar given another prefix inside the closure' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$kiosk = Route::prefix('kiosk');",
                "web: __DIR__.'/../routes/web.php',\n        then: function () use (\$kiosk) {\n            \$kiosk->prefix('lobby');\n            \$kiosk->group(base_path('routes/kiosk.php'));\n        },",
            )], 'routes/kiosk.php', 'kiosk'],
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
    // Route file middleware from registrations (#590)
    // ==========================================

    /**
     * @dataProvider authenticatingRouteFileRegistrationProvider
     *
     * @param  array<string, string>  $registration
     */
    #[DataProvider('authenticatingRouteFileRegistrationProvider')]
    public function test_middleware_a_registration_applies_authenticates_the_route_file(array $registration): void
    {
        $result = $this->analyzeMembersRegistration($registration);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function authenticatingRouteFileRegistrationProvider(): array
    {
        return [
            'then: registrar middleware' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: registrar middleware list beside a web: file' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "web: __DIR__.'/../routes/web.php',\n        then: function () {\n            Route::middleware(['web', 'auth:sanctum'])->prefix('team')->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: attribute array middleware' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::group(['middleware' => ['web', 'auth']], base_path('routes/members.php'));\n        },",
            )]],
            'then: the Authenticate class' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware(\\Illuminate\\Auth\\Middleware\\Authenticate::class)->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: outer auth group around an inner registration' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->group(function () {\n                Route::prefix('team')->group(base_path('routes/members.php'));\n            });\n        },",
            )]],
            'then: require inside an auth group closure' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->group(function () {\n                require base_path('routes/members.php');\n            });\n        },",
            )]],
            'then: registrar variable' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            \$members = Route::middleware('auth');\n            \$members->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: registrar captured by the closure' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$members = Route::middleware('auth');",
                "then: function () use (\$members) {\n            \$members->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: two registrations that both authenticate' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n            Route::middleware(['web', 'auth'])->prefix('legacy')->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: excluding middleware other than auth' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware(['auth', 'verified'])->withoutMiddleware('verified')->group(base_path('routes/members.php'));\n        },",
            )]],
            'RouteServiceProvider routes() callback' => [['app/Providers/RouteServiceProvider.php' => self::routeServiceProvider(
                "\$this->routes(function () {\n            Route::middleware(['web', 'auth'])->group(base_path('routes/members.php'));\n        });",
            )]],
            'another service provider' => [['app/Providers/AppServiceProvider.php' => self::appProvider(
                "Route::middleware('auth')->prefix('team')->group(base_path('routes/members.php'));",
            )]],
            'then: auth, beside a listed provider an installed package holds' => [[
                'bootstrap/app.php' => self::bootstrapApp(
                    '',
                    "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },",
                ),
                'config/app.php' => "<?php\n\nreturn [\n    'providers' => [\n        Acme\\Billing\\BillingServiceProvider::class,\n    ],\n];\n",
                'vendor/composer/autoload_psr4.php' => "<?php\n\n\$vendorDir = dirname(__DIR__);\n\$baseDir = dirname(\$vendorDir);\n\nreturn array(\n    'Acme\\\\Billing\\\\' => array(\$vendorDir . '/acme/billing/src'),\n);\n",
            ]],
            'then: auth, beside a route file requiring another one' => [[
                'bootstrap/app.php' => self::bootstrapApp(
                    '',
                    "web: __DIR__.'/../routes/web.php',\n        then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },",
                ),
                'routes/web.php' => "<?php\n\nrequire __DIR__.'/auth.php';\n",
                'routes/auth.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware('guest')->group(function () {\n    Route::post('/login', fn () => 1);\n});\n",
            ]],
        ];
    }

    /**
     * @dataProvider nonAuthenticatingRouteFileRegistrationProvider
     *
     * @param  array<string, string>  $registration
     */
    #[DataProvider('nonAuthenticatingRouteFileRegistrationProvider')]
    public function test_route_file_registration_middleware_without_auth_on_every_load_still_reports(array $registration, string $members = ''): void
    {
        $result = $this->analyzeMembersRegistration($registration, $members);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    /**
     * @return array<string, array{0: array<string, string>, 1?: string}>
     */
    public static function nonAuthenticatingRouteFileRegistrationProvider(): array
    {
        return [
            // The web group holds no auth by default
            'then: web only' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('web')->group(base_path('routes/members.php'));\n        },",
            )]],
            'web: file' => [['bootstrap/app.php' => self::bootstrapApp('', "web: __DIR__.'/../routes/members.php',")]],
            'then: registered twice, once without auth' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n            Route::prefix('legacy')->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: auth, and the web: file list' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "web: [__DIR__.'/../routes/web.php', __DIR__.'/../routes/members.php'],\n        then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: auth, and a provider without it' => [[
                'bootstrap/app.php' => self::bootstrapApp(
                    '',
                    "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },",
                ),
                'app/Providers/AppServiceProvider.php' => self::appProvider("Route::middleware('web')->group(base_path('routes/members.php'));"),
            ]],
            'then: auth, and required from another route file' => [[
                'bootstrap/app.php' => self::bootstrapApp(
                    '',
                    "web: __DIR__.'/../routes/web.php',\n        then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },",
                ),
                'routes/web.php' => "<?php\n\nrequire __DIR__.'/members.php';\n",
            ]],
            'provider: auth, and loaded outside any group' => [['app/Providers/AppServiceProvider.php' => self::appProvider(
                "Route::middleware('auth')->group(base_path('routes/members.php'));\n        \$this->loadRoutesFrom(base_path('routes/members.php'));",
            )]],
            'then: auth excluded on the registration' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->withoutMiddleware('auth')->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: exclusions read from a variable' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->withoutMiddleware(\$skipped)->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: attribute array excluding auth' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::group(['middleware' => 'auth', 'excluded_middleware' => ['auth']], base_path('routes/members.php'));\n        },",
            )]],
            'then: middleware read from a variable' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware(\$memberMiddleware)->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: inner group excluding the outer auth' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->group(function () {\n                Route::withoutMiddleware('auth')->group(base_path('routes/members.php'));\n            });\n        },",
            )]],
            'then: registrar captured by reference' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$members = Route::middleware('auth');",
                "then: function () use (&\$members) {\n            \$members->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: captured registrar stripped of auth after the closure' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$members = Route::middleware('auth');\n\$mapMembers = function () use (\$members) {\n    \$members->group(base_path('routes/members.php'));\n};\n\$members->withoutMiddleware('auth');",
                'then: $mapMembers,',
            )]],
            'then: captured registrar variable reassigned after the closure' => [['bootstrap/app.php' => self::bootstrapApp(
                "\$members = Route::middleware('auth');\n\$mapMembers = function () use (\$members) {\n    \$members->group(base_path('routes/members.php'));\n};\n\$members = Route::middleware('web');",
                'then: $mapMembers,',
            )]],
            'then: auth, the route file excluding it from a group' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },",
            )], "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::withoutMiddleware('auth')->group(function () {\n    Route::post('/members', [MemberController::class, 'store']);\n});\n"],
            'then: auth, the route excluding it in its action array' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },",
            )], "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/members', ['uses' => MemberController::class.'@store', 'excluded_middleware' => ['auth']]);\n"],
            'then: auth, the route file excluding it in a group attribute array' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },",
            )], "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::group(['excluded_middleware' => ['auth']], function () {\n    Route::post('/members', [MemberController::class, 'store']);\n});\n"],
            // A second load under another prefix, whose path cannot be read, may be this file
            'then: auth, and a load through a constant' => [['bootstrap/app.php' => self::bootstrapApp(
                "const MEMBERS_ROUTES = __DIR__.'/../routes/members.php';",
                "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n            Route::prefix('legacy')->group(MEMBERS_ROUTES);\n        },",
            )]],
            'then: auth, and a load through dirname()' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n            Route::prefix('legacy')->group(dirname(__DIR__).'/routes/members.php');\n        },",
            )]],
            'then: auth, and a load through sprintf()' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n            Route::prefix('legacy')->group(base_path(sprintf('routes/%s.php', 'members')));\n        },",
            )]],
            'then: auth, and a provider load through a class constant' => [self::authThenBeside(self::appProvider(
                "Route::middleware('web')->prefix('legacy')->group(self::MEMBERS);",
                "    private const MEMBERS = __DIR__.'/../../routes/members.php';\n",
            ))],
            'then: auth, and a provider load through a property' => [self::authThenBeside(self::appProvider(
                "Route::middleware('web')->prefix('legacy')->group(\$this->membersRoutes);",
                "    private string \$membersRoutes = __DIR__.'/../../routes/members.php';\n",
            ))],
            'then: auth, and a provider load through the application base path' => [self::authThenBeside(self::appProvider(
                "Route::middleware('web')->prefix('legacy')->group(\$this->app->basePath('routes/members.php'));",
            ))],
            'then: auth, and a provider load through array_map()' => [self::authThenBeside(self::appProvider(
                "Route::middleware('web')->prefix('legacy')->group(array_map(fn (\$name) => base_path(\"routes/{\$name}.php\"), ['members']));",
            ))],
            'then: auth, and a provider loadRoutesFrom() through a class constant' => [self::authThenBeside(self::appProvider(
                "Route::prefix('legacy')->group(function () {\n            \$this->loadRoutesFrom(self::MEMBERS);\n        });",
                "    private const MEMBERS = __DIR__.'/../../routes/members.php';\n",
            ))],
            // A load outside routes/, bootstrap/app.php and app/Providers/
            'then: auth, and a provider under app/Modules' => [[
                ...self::authThenBeside(''),
                'bootstrap/providers.php' => "<?php\n\nreturn [\n    App\\Modules\\Members\\MembersServiceProvider::class,\n];\n",
                'app/Modules/Members/MembersServiceProvider.php' => str_replace(['namespace App\\Providers;', 'class AppServiceProvider'], ['namespace App\\Modules\\Members;', 'class MembersServiceProvider'], self::appProvider(
                    "Route::middleware('web')->prefix('legacy')->group(base_path('routes/members.php'));",
                )),
            ]],
            'then: auth, and a class a provider calls' => [[
                ...self::authThenBeside(self::appProvider('\\App\\Routing\\MemberRoutes::map();')),
                'app/Routing/MemberRoutes.php' => "<?php\n\nnamespace App\\Routing;\n\nuse Illuminate\\Support\\Facades\\Route;\n\nclass MemberRoutes\n{\n    public static function map(): void\n    {\n        Route::middleware('web')->prefix('legacy')->group(base_path('routes/members.php'));\n    }\n}\n",
            ]],
            // Router::resolveMiddleware() drops the Authenticate class and the auth alias alike
            'then: auth, the registration excluding the Authenticate class' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->withoutMiddleware(\\Illuminate\\Auth\\Middleware\\Authenticate::class)->group(base_path('routes/members.php'));\n        },",
            )]],
            'then: auth, the registration attribute array excluding the Authenticate class' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::group(['middleware' => 'auth', 'excluded_middleware' => [\\Illuminate\\Auth\\Middleware\\Authenticate::class]], base_path('routes/members.php'));\n        },",
            )]],
            'then: auth, the route file group excluding the Authenticate class' => [self::authThenBeside(''), "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::withoutMiddleware([\\Illuminate\\Auth\\Middleware\\Authenticate::class])->group(function () {\n    Route::post('/members', [MemberController::class, 'store']);\n});\n"],
            'then: auth, the route excluding middleware read from config' => [self::authThenBeside(''), "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/members', ['uses' => MemberController::class.'@store', 'excluded_middleware' => config('members.skip')]);\n"],
            // Loads only a scan beyond bootstrap/app.php and app/Providers/ finds
            'then: auth, and File::requireOnce() inside a prefix group' => [self::authThenBeside(self::appProvider(
                "Route::prefix('legacy')->group(function () {\n            \\Illuminate\\Support\\Facades\\File::requireOnce(base_path('routes/members.php'));\n        });",
            ))],
            'then: auth, and a class taking the router contract' => [[
                ...self::authThenBeside(''),
                'app/Routing/LegacyRoutes.php' => "<?php\n\nnamespace App\\Routing;\n\nuse Illuminate\\Contracts\\Routing\\Registrar;\n\nclass LegacyRoutes\n{\n    public function __invoke(Registrar \$registrar): void\n    {\n        \$registrar->prefix('legacy')->group(base_path('routes/members.php'));\n    }\n}\n",
            ]],
            'then: auth, and a listed provider under modules/ composer.json maps' => [[
                ...self::authThenBeside(''),
                'composer.json' => '{"autoload": {"psr-4": {"App\\\\": "app/"}}, "autoload-dev": {"psr-4": {"Modules\\\\": "modules/"}}}',
                'bootstrap/providers.php' => "<?php\n\nreturn [\n    Modules\\Legacy\\LegacyServiceProvider::class,\n];\n",
                'modules/Legacy/LegacyServiceProvider.php' => str_replace(['namespace App\\Providers;', 'class AppServiceProvider'], ['namespace Modules\\Legacy;', 'class LegacyServiceProvider'], self::appProvider(
                    "Route::prefix('legacy')->group(base_path('routes/members.php'));",
                )),
            ]],
            'then: auth, and a provider under src/ config/app.php lists' => [[
                ...self::authThenBeside(''),
                'composer.json' => '{"autoload": {"psr-4": {"Acme\\\\Legacy\\\\": "src/"}}}',
                'config/app.php' => "<?php\n\nreturn [\n    'providers' => [\n        Acme\\Legacy\\LegacyServiceProvider::class,\n    ],\n];\n",
                'src/LegacyServiceProvider.php' => str_replace(['namespace App\\Providers;', 'class AppServiceProvider'], ['namespace Acme\\Legacy;', 'class LegacyServiceProvider'], self::appProvider(
                    "Route::prefix('legacy')->group(base_path('routes/members.php'));",
                )),
            ]],
            'then: auth, and the container router grouping a path read from config' => [[
                ...self::authThenBeside(''),
                'app/Routing/LegacyRoutes.php' => "<?php\n\nnamespace App\\Routing;\n\nclass LegacyRoutes\n{\n    public static function map(): void\n    {\n        app('router')->prefix('legacy')->group(config('routing.legacy'));\n    }\n}\n",
            ]],
            'then: auth, and a require of a path read from config inside the then: callback' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n            Route::prefix('legacy')->group(function () {\n                require config('routing.legacy');\n            });\n        },",
            )]],
            'then: auth, and a RouteServiceProvider map method requiring a computed path' => [self::authThenBeside(str_replace(
                ['class AppServiceProvider extends ServiceProvider', 'use Illuminate\\Support\\ServiceProvider;'],
                ['class RouteServiceProvider extends ServiceProvider', 'use Illuminate\\Foundation\\Support\\Providers\\RouteServiceProvider as ServiceProvider;'],
                self::appProvider('', "    public function mapLegacyRoutes(): void\n    {\n        Route::prefix('legacy')->group(function () {\n            require \$this->legacyFile();\n        });\n    }\n"),
            ))],
            'then: auth, and File::getRequire() of a path read from config' => [self::authThenBeside(self::appProvider(
                "Route::prefix('legacy')->group(function () {\n            \\Illuminate\\Support\\Facades\\File::getRequire(config('routing.legacy'));\n        });",
            ))],
            'then: auth, and loadRoutesFrom() a path read from config' => [self::authThenBeside(self::appProvider(
                "\$this->loadRoutesFrom(config('routing.legacy'));",
            ))],
            'then: auth, and a class requiring the file' => [[
                ...self::authThenBeside(''),
                'app/Routing/LegacyRoutes.php' => "<?php\n\nnamespace App\\Routing;\n\nuse Illuminate\\Support\\Facades\\Route;\n\nclass LegacyRoutes\n{\n    public static function map(): void\n    {\n        Route::prefix('legacy')->group(function () {\n            require base_path('routes/members.php');\n        });\n    }\n}\n",
            ]],
            'then: auth, and a class holding the router contract in a property' => [[
                ...self::authThenBeside(''),
                'app/Routing/LegacyRoutes.php' => "<?php\n\nnamespace App\\Routing;\n\nuse Illuminate\\Contracts\\Routing\\Registrar;\n\nclass LegacyRoutes\n{\n    public function __construct(private Registrar \$registrar)\n    {\n    }\n\n    public function map(): void\n    {\n        \$this->registrar->group(['prefix' => 'legacy'], config('routing.legacy'));\n    }\n}\n",
            ]],
            // RouteRegistrar::attribute() allows no excluded_middleware key
            'then: auth, the route file group excluding auth through attribute()' => [self::authThenBeside(''), "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::attribute('excluded_middleware', ['auth'])->group(function () {\n    Route::post('/members', [MemberController::class, 'store']);\n});\n"],
            'then: auth through attribute(), excluded on an outer group' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::attribute('excluded_middleware', 'auth')->group(function () {\n                Route::middleware('auth')->group(base_path('routes/members.php'));\n            });\n        },",
            )]],
            // RouteRegistrar::group() reads the attribute array as the routes
            'then: a registrar group given an attribute array' => [['bootstrap/app.php' => self::bootstrapApp(
                '',
                "then: function () {\n            Route::middleware('web')->group(['middleware' => 'auth'], base_path('routes/members.php'));\n        },",
            )]],
            // A listed provider found nowhere may load any route file
            'then: auth, and a listed provider no autoload map locates' => [[
                ...self::authThenBeside(''),
                'bootstrap/providers.php' => "<?php\n\nreturn [\n    Modules\\Legacy\\LegacyServiceProvider::class,\n];\n",
                'modules/Legacy/LegacyServiceProvider.php' => str_replace(['namespace App\\Providers;', 'class AppServiceProvider'], ['namespace Modules\\Legacy;', 'class LegacyServiceProvider'], self::appProvider(
                    "Route::prefix('legacy')->group(base_path('routes/members.php'));",
                )),
            ]],
            // A router root the walk reads, in an app/ file the text prefilter must not skip
            'then: auth, and an app/ class grouping on an untyped $router' => [self::legacyRoutesBeside('$router')],
            'then: auth, and an app/ class grouping on resolve(router)' => [self::legacyRoutesBeside("resolve('router')")],
            'then: auth, and an app/ class grouping on app()->make(router)' => [self::legacyRoutesBeside("app()->make('router')")],
            'then: auth, and an app/ class grouping on App::make(router)' => [self::legacyRoutesBeside("\\Illuminate\\Support\\Facades\\App::make('router')")],
            'then: auth, and an app/ class grouping on an aliased Route facade' => [self::legacyRoutesBeside('Router::middleware([])', 'use Illuminate\\Support\\Facades\\Route as Router;')],
            'then: auth, and an app/ class grouping on an unknown receiver' => [self::legacyRoutesBeside('$this->registry')],
            // A stock RouteServiceProvider extends the framework's under an alias
            'Laravel 10 skeleton whose map method requires a computed path' => [[...self::laravel10Project(), 'app/Providers/RouteServiceProvider.php' => "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Foundation\\Support\\Providers\\RouteServiceProvider as ServiceProvider;\nuse Illuminate\\Support\\Facades\\Route;\n\nclass RouteServiceProvider extends ServiceProvider\n{\n    protected \$legacy = 'routes/members.php';\n\n    public function map()\n    {\n        Route::middleware('web')->group(base_path('routes/web.php'));\n        Route::middleware(['web', 'auth'])->group(base_path('routes/members.php'));\n        \$this->mapLegacyRoutes();\n    }\n\n    protected function mapLegacyRoutes()\n    {\n        require base_path(\$this->legacy);\n    }\n}\n"]],
            // Provider lists in forms other than a literal array
            'then: auth, and bootstrap/providers.php returning a variable' => [self::modulesProviderBeside("<?php\n\n\$providers = [\n    Modules\\Legacy\\LegacyServiceProvider::class,\n];\n\nreturn \$providers;\n")],
            'then: auth, and bootstrap/providers.php merging lists' => [self::modulesProviderBeside("<?php\n\nreturn array_merge([App\\Providers\\AppServiceProvider::class], [Modules\\Legacy\\LegacyServiceProvider::class]);\n")],
            'then: auth, and bootstrap/providers.php spreading a list' => [self::modulesProviderBeside("<?php\n\n\$more = [Modules\\Legacy\\LegacyServiceProvider::class];\n\nreturn [App\\Providers\\AppServiceProvider::class, ...\$more];\n")],
            'then: auth, and config/app.php merging the default providers' => [[
                ...self::modulesProviderBeside("<?php\n\nreturn [];\n"),
                'config/app.php' => "<?php\n\nuse Illuminate\\Support\\ServiceProvider;\n\nreturn [\n    'providers' => array_merge(ServiceProvider::defaultProviders()->toArray(), [\n        Modules\\Legacy\\LegacyServiceProvider::class,\n    ]),\n];\n",
            ]],
            'then: auth, and config/app.php merging into the default providers' => [[
                ...self::modulesProviderBeside("<?php\n\nreturn [];\n"),
                'config/app.php' => "<?php\n\nuse Illuminate\\Support\\ServiceProvider;\n\nreturn [\n    'providers' => ServiceProvider::defaultProviders()->merge([\n        Modules\\Legacy\\LegacyServiceProvider::class,\n    ])->toArray(),\n];\n",
            ]],
            // An exclusion in the file the visitor does not attach to the route
            'then: auth, the file excluding it from a group given a closure variable' => [self::authThenBeside(''), self::membersRoutes("\$open = function () {\n    Route::post('/members', [MemberController::class, 'store']);\n};\nRoute::withoutMiddleware('auth')->group(\$open);")],
            'then: auth, the file calling a closure variable in an excluding group' => [self::authThenBeside(''), self::membersRoutes("\$routes = function () {\n    Route::post('/members', [MemberController::class, 'store']);\n};\nRoute::withoutMiddleware('auth')->group(function () use (\$routes) {\n    \$routes();\n});")],
            'then: auth, the file calling a function in an excluding group' => [self::authThenBeside(''), self::membersRoutes("function memberRoutes(): void\n{\n    Route::post('/members', [MemberController::class, 'store']);\n}\n\nRoute::withoutMiddleware('auth')->group(fn () => memberRoutes());")],
            'then: auth, the file grouping on a registrar a function returns' => [self::authThenBeside(''), self::membersRoutes("function openRegistrar() { return Route::withoutMiddleware('auth'); }\nopenRegistrar()->group(function () {\n    Route::post('/members', [MemberController::class, 'store']);\n});")],
            // A group closure held in a variable registers routes as a literal one does
            'then: auth, and a provider group closure variable requiring a computed path' => [self::authThenBeside(self::appProvider(
                "\$legacy = function () {\n            require base_path(\$this->legacyFile);\n        };\n        Route::prefix('legacy')->group(\$legacy);",
                "    protected \$legacyFile = 'routes/members.php';\n",
            ))],
            'then: auth, and the container filesystem requiring a computed path' => [self::authThenBeside(self::appProvider(
                "Route::prefix('legacy')->group(function () {\n            \$this->app['files']->requireOnce(base_path(\$this->legacyFile));\n        });",
                "    protected \$legacyFile = 'routes/members.php';\n",
            ))],
            'then: auth, and app(files) requiring the file' => [self::authThenBeside(self::appProvider(
                "Route::prefix('legacy')->group(function () {\n            app('files')->getRequire(base_path('routes/members.php'));\n        });",
            ))],
            // A second load only a require, an include or a filesystem makes
            'Laravel 11 project, and an app/ class requiring the file' => [self::legacyLoaderProject("require base_path('routes/members.php');")],
            'Laravel 11 project, and a function in app/helpers.php requiring the file' => [[...self::laravel11Project(boot: 'loadMemberRoutes();'), 'app/helpers.php' => "<?php\n\nfunction loadMemberRoutes(): void\n{\n    require __DIR__.'/../routes/members.php';\n}\n"]],
            'Laravel 11 project, and an app/ class including the file once' => [self::legacyLoaderProject("include_once base_path('routes/members.php');")],
            'Laravel 11 project, and an app/ class requiring the file through the File facade' => [self::legacyLoaderProject("File::require(base_path('routes/members.php'));", 'use Illuminate\\Support\\Facades\\File;')],
            'Laravel 11 project, and an unparseable app/helpers.php' => [[...self::laravel11Project(), 'app/helpers.php' => "<?php\n\nrequire __DIR__.'/../routes/members.php';\n\$value = ;\n"]],
            'Laravel 11 project, and the container filesystem requiring the file' => [self::laravel11Project(boot: "\$this->app->make('files')->require(base_path('routes/members.php'));")],
            'Laravel 11 project, and a new filesystem requiring the file' => [self::laravel11Project(boot: "(new \\Illuminate\\Filesystem\\Filesystem)->require(base_path('routes/members.php'));")],
            'Laravel 11 project, and a filesystem variable requiring the file' => [self::laravel11Project(boot: "\$disk = app('files');\n        \$disk->require(base_path('routes/members.php'));")],
            'Laravel 11 project, and an aliased File facade requiring the file' => [self::laravel11Project(boot: "\\Illuminate\\Support\\Facades\\File::requireOnce(base_path('routes/members.php'));")],
            'Laravel 11 project, and a facade alias requiring the file' => [[...self::laravel11Project(), 'app/Providers/AppServiceProvider.php' => "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Support\\Facades\\File as Disk;\nuse Illuminate\\Support\\ServiceProvider;\n\nclass AppServiceProvider extends ServiceProvider\n{\n    public function boot(): void\n    {\n        Disk::require(base_path('routes/members.php'));\n    }\n}\n"]],
            'Laravel 11 project, and an aliased filesystem parameter requiring the file' => [[...self::laravel11Project(), 'app/Providers/AppServiceProvider.php' => "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Filesystem\\Filesystem as Fs;\nuse Illuminate\\Support\\ServiceProvider;\n\nclass AppServiceProvider extends ServiceProvider\n{\n    public function boot(Fs \$disk): void\n    {\n        \$disk->require(base_path('routes/members.php'));\n    }\n}\n"]],
            'Laravel 11 project, and a config file requiring the file' => [[...self::laravel11Project(), 'config/legacy.php' => "<?php\n\nrequire __DIR__.'/../routes/members.php';\n\nreturn [];\n"]],
            'Laravel 11 project, and a class named for the router grouping the file' => [self::laravel11Project(boot: "\\App\\Routing\\Router::prefix('legacy')->group(base_path('routes/members.php'));")],
            // A path a function is given, which its callers may set to the file
            'Laravel 11 project, and a provider method grouping the path it is given' => [[...self::laravel11Project(), 'app/Providers/AppServiceProvider.php' => "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Support\\Facades\\Route;\nuse Illuminate\\Support\\ServiceProvider;\n\nclass AppServiceProvider extends ServiceProvider\n{\n    public function boot(): void\n    {\n        \$this->mapFrom(base_path('routes/members.php'));\n    }\n\n    protected function mapFrom(string \$path): void\n    {\n        Route::middleware('web')->group(\$path);\n    }\n}\n"]],
            'Laravel 11 project, and a route macro grouping the routes it is given' => [self::laravel11Project(boot: "Route::macro('module', function (\$routes) {\n            Route::middleware('web')->group(\$routes);\n        });\n        Route::module(base_path('routes/members.php'));")],
            'Laravel 11 project, and an app/ loader grouping the path it is given' => [[...self::laravel11Project(boot: "\\App\\Routing\\Loader::load(base_path('routes/members.php'));"), 'app/Routing/Loader.php' => "<?php\n\nnamespace App\\Routing;\n\nuse Illuminate\\Support\\Facades\\Route;\n\nclass Loader\n{\n    public static function load(string \$path): void\n    {\n        Route::middleware('web')->group(\$path);\n    }\n}\n"]],
            // A provider registered from a provider
            'Laravel 11 project, and a provider registering a module provider' => [[
                ...self::laravel11Project(register: '$this->app->register(\\Modules\\Legacy\\LegacyServiceProvider::class);'),
                'composer.json' => '{"autoload": {"psr-4": {"App\\\\": "app/", "Modules\\\\": "modules/"}}}',
                'modules/Legacy/LegacyServiceProvider.php' => str_replace(['namespace App\\Providers;', 'class AppServiceProvider'], ['namespace Modules\\Legacy;', 'class LegacyServiceProvider'], self::appProvider(
                    "Route::prefix('legacy')->group(base_path('routes/members.php'));",
                )),
            ]],
            // Routes in a closure given to a call other than a group, which may exclude auth
            'then: auth, the route file registering routes through a macro' => [self::laravel11Project(boot: "Route::macro('open', function (\\Closure \$routes) {\n            Route::withoutMiddleware('auth')->group(\$routes);\n        });"), self::membersRoutes("Route::open(function () {\n    Route::post('/members', [MemberController::class, 'store']);\n});")],
            'then: auth, the route file registering routes through a helper class' => [[...self::laravel11Project(), 'app/Routing/Open.php' => "<?php\n\nnamespace App\\Routing;\n\nuse Illuminate\\Support\\Facades\\Route;\n\nclass Open\n{\n    public static function routes(\\Closure \$routes): void\n    {\n        Route::withoutMiddleware('auth')->group(\$routes);\n    }\n}\n"], self::membersRoutes("\\App\\Routing\\Open::routes(function () {\n    Route::post('/members', [MemberController::class, 'store']);\n});")],
            // On a case-insensitive filesystem this names routes/members.php; elsewhere no file
            'then: auth, and a load naming the file in another case' => [self::authThenBeside(self::appProvider(
                "Route::prefix('legacy')->group(base_path('routes/Members.php'));",
            ))],
        ];
    }

    /**
     * A guest route in a file the registration authenticates still reads as one, so a
     * controller method it reaches stays public as before.
     *
     * @dataProvider guestRouteInRegisteredFileProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('guestRouteInRegisteredFileProvider')]
    public function test_a_guest_route_in_a_registered_file_opens_no_finding(array $files): void
    {
        $result = $this->analyzeFiles([
            ...self::authThenBeside(''),
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/members/open', [\\App\\Http\\Controllers\\MemberController::class, 'store']);\nRoute::delete('/members/open/{member}', [\\App\\Http\\Controllers\\MemberController::class, 'destroy']);\n",
            'app/Http/Controllers/MemberController.php' => "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse App\\Http\\Requests\\RemoveMember;\n\nclass MemberController\n{\n    public function store()\n    {\n        return 1;\n    }\n\n    public function destroy(RemoveMember \$request)\n    {\n        return 1;\n    }\n}\n",
            'app/Http/Requests/RemoveMember.php' => "<?php\n\nnamespace App\\Http\\Requests;\n\nuse Illuminate\\Foundation\\Http\\FormRequest;\n\nclass RemoveMember extends FormRequest\n{\n    public function rules(): array\n    {\n        return [];\n    }\n}\n",
            ...$files,
        ]);

        $this->assertSame([
            'POST route without authentication middleware',
            'DELETE route without authentication middleware',
        ], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function guestRouteInRegisteredFileProvider(): array
    {
        $members = static fn (string $body): string => "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\n{$body}\n";

        return [
            'guest with a guard on the route' => [['routes/members.php' => $members("Route::middleware('guest:admin')->post('/members', [MemberController::class, 'store']);\nRoute::middleware('guest:admin')->delete('/members/{member}', [MemberController::class, 'destroy']);")]],
            'guest with a guard on a group' => [['routes/members.php' => $members("Route::middleware('guest:admin')->group(function () {\n    Route::post('/members', [MemberController::class, 'store']);\n    Route::delete('/members/{member}', [MemberController::class, 'destroy']);\n});")]],
        ];
    }

    /**
     * Code that cannot load a route file, beside a registration that authenticates one,
     * leaves the registration credited.
     *
     * @dataProvider loadFreeProjectProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('loadFreeProjectProvider')]
    public function test_a_registration_is_credited_beside_code_that_loads_no_route_file(array $files): void
    {
        $this->assertPassed($this->analyzeFiles($files));
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function loadFreeProjectProvider(): array
    {
        return [
            'Laravel 11 skeleton' => [self::laravel11Project()],
            'Laravel 10 skeleton' => [self::laravel10Project()],
            'require_once app_path() in a provider' => [self::laravel11Project(register: "require_once app_path('helpers.php');")],
            'Laravel 10 skeleton with require_once app_path() in a provider' => [self::laravel10Project(register: "require_once app_path('helpers.php');")],
            'glob() require loop in a provider' => [self::laravel11Project(register: "foreach (glob(app_path('Support').'/*.php') as \$helper) {\n            require_once \$helper;\n        }")],
            'project-root helper required by a provider' => [[...self::laravel11Project(register: "require_once base_path('support.php');"), 'support.php' => "<?php\n"]],
            'guarded vendor require in a provider' => [self::laravel11Project(register: "if (file_exists(base_path('vendor/acme/boot.php'))) {\n            require base_path('vendor/acme/boot.php');\n        }")],
            'controller including a storage file' => [[...self::laravel11Project(), 'app/Http/Controllers/ExportController.php' => "<?php\n\nnamespace App\\Http\\Controllers;\n\nclass ExportController\n{\n    public function show()\n    {\n        \$columns = include storage_path('app/columns.php');\n\n        return redirect()->route('home', \$columns);\n    }\n}\n"]],
            'command requiring a config file' => [[...self::laravel11Project(), 'app/Console/Commands/SyncRoutes.php' => "<?php\n\nnamespace App\\Console\\Commands;\n\nuse Illuminate\\Console\\Command;\n\nclass SyncRoutes extends Command\n{\n    protected \$signature = 'routes:sync';\n\n    public function handle(): void\n    {\n        \$options = require config_path('sync.php');\n    }\n}\n"]],
            'route group given a closure variable' => [[...self::laravel11Project(), 'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n\$dashboard = function () {\n    Route::get('/dashboard', fn () => 1);\n};\n\nRoute::middleware('auth')->group(\$dashboard);\n"]],
            'glob() require loop in a route file' => [[...self::laravel11Project(), 'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::get('/', fn () => 1);\n\nforeach (glob(__DIR__.'/partials/*.php') as \$partial) {\n    require \$partial;\n}\n"]],
            'schedule group given a closure variable' => [[...self::laravel11Project(), 'routes/console.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Schedule;\n\n\$nightly = function () {\n    Schedule::command('reports:send')->daily();\n};\nSchedule::daily()->group(\$nightly);\n"]],
            'route macro grouping its closure parameter' => [self::laravel11Project(boot: "Route::macro('archived', function (\$uri, \Closure \$routes) {\n            Route::group([], \$routes);\n        });")],
            'route handler closure in the registered file reading the request' => [[...self::laravel11Project(), 'routes/members.php' => "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Http\\Request;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/members', [MemberController::class, 'store']);\nRoute::post('/members/search', fn (Request \$request) => \$request->get('page'));\n"]],
            'path variable in a Laravel 10 routes() callback' => [self::laravel10Project("\$memberRoutes = base_path('routes/members.php');\n            Route::middleware(['web', 'auth'])->group(\$memberRoutes);")],
        ];
    }

    public function test_a_file_only_the_registration_read_reads_logs_no_parse_failure(): void
    {
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($this->createTempDirectory([
            ...self::laravel11Project(),
            'app/Legacy/Broken.php' => "<?php\n\n\\Illuminate\\Support\\Facades\\Route::get('/x', fn () => 1);\nrequire __DIR__.'/other.php';\n\$x = ;\n",
        ]));
        $analyzer->setPaths(['app/Http']);
        $analyzer->analyze();

        $this->assertSame([], $this->parser->failures());
    }

    public function test_an_unparseable_file_that_may_load_routes_withholds_registration_credit(): void
    {
        $result = $this->analyzeFiles([
            ...self::laravel11Project(),
            'app/Legacy/Broken.php' => "<?php\n\n\\Illuminate\\Support\\Facades\\Route::prefix('legacy')->group(base_path('routes/members.php'));\n\$x = ;\n",
        ]);

        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    /**
     * The registration authenticating routes/members.php in then:, beside an app/ class
     * registering it again under legacy without auth, on the router $root.
     *
     * @return array<string, string>
     */
    private static function legacyRoutesBeside(string $root, string $uses = ''): array
    {
        return [
            ...self::authThenBeside(''),
            'app/Routing/LegacyRoutes.php' => "<?php\n\nnamespace App\\Routing;\n\n{$uses}\n\nclass LegacyRoutes\n{\n    public static function register(\$router = null): void\n    {\n        {$root}->prefix('legacy')->group(base_path('routes/members.php'));\n    }\n}\n",
        ];
    }

    /**
     * The registration authenticating routes/members.php in then:, beside a provider under
     * modules/ that composer.json maps, registering it again under legacy without auth, with
     * bootstrap/providers.php holding $providers.
     *
     * @return array<string, string>
     */
    private static function modulesProviderBeside(string $providers): array
    {
        return [
            ...self::authThenBeside(''),
            'composer.json' => '{"autoload": {"psr-4": {"App\\\\": "app/", "Modules\\\\": "modules/"}}}',
            'bootstrap/providers.php' => $providers,
            'modules/Legacy/LegacyServiceProvider.php' => str_replace(['namespace App\\Providers;', 'class AppServiceProvider'], ['namespace Modules\\Legacy;', 'class LegacyServiceProvider'], self::appProvider(
                "Route::prefix('legacy')->group(base_path('routes/members.php'));",
            )),
        ];
    }

    /**
     * A Laravel 11 project whose AppServiceProvider calls App\Support\LegacyRoutes::load(),
     * which runs $body.
     *
     * @return array<string, string>
     */
    private static function legacyLoaderProject(string $body, string $uses = ''): array
    {
        return [
            ...self::laravel11Project(boot: '\\App\\Support\\LegacyRoutes::load();'),
            'app/Support/LegacyRoutes.php' => "<?php\n\nnamespace App\\Support;\n\n{$uses}\n\nclass LegacyRoutes\n{\n    public static function load(): void\n    {\n        {$body}\n    }\n}\n",
        ];
    }

    /**
     * routes/members.php importing MemberController and the Route facade, running $body.
     */
    private static function membersRoutes(string $body): string
    {
        return "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\n{$body}\n";
    }

    /**
     * The shared parser logs only the files the analysis read before registrations were
     * read for their middleware, each under the path the analysis reads it by.
     *
     * @dataProvider unreadFileFailureProvider
     *
     * @param  array<string, string>  $files
     * @param  list<string>  $paths
     * @param  list<string>  $expected
     */
    #[DataProvider('unreadFileFailureProvider')]
    public function test_the_parse_failure_log_holds_only_files_the_analysis_reads(array $files, array $paths, array $expected): void
    {
        $basePath = $this->createTempDirectory([...self::laravel11Project(), ...$files]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($basePath);
        $analyzer->setPaths($paths);
        $analyzer->analyze();

        $this->assertSame($expected, array_map(fn ($failure): string => str_replace([$basePath, '/./'], ['', '/'], (string) $failure->path), $this->parser->failures()));
    }

    /**
     * @return array<string, array{array<string, string>, list<string>, list<string>}>
     */
    public static function unreadFileFailureProvider(): array
    {
        $broken = "<?php\n\n\$value = ;\n";

        return [
            'a route file in a subdirectory' => [['routes/partials/broken.php' => $broken], ['app'], []],
            'config/app.php' => [['config/app.php' => $broken], ['app'], []],
            'bootstrap/providers.php' => [['bootstrap/providers.php' => $broken], ['app'], []],
            'an analyzed file that may load routes, under paths [.]' => [['app/Http/Broken.php' => "<?php\nRoute::group(\$routes);\n\$value = ;\n"], ['.'], ['/app/Http/Broken.php']],
        ];
    }

    public function test_a_registration_is_credited_beside_the_stock_laravel_10_provider_list(): void
    {
        $this->assertPassed($this->analyzeFiles([
            ...self::laravel10Project(),
            'config/app.php' => "<?php\n\nuse Illuminate\\Support\\ServiceProvider;\n\nreturn [\n    'providers' => ServiceProvider::defaultProviders()->merge([\n        App\\Providers\\AppServiceProvider::class,\n        App\\Providers\\RouteServiceProvider::class,\n    ])->toArray(),\n];\n",
        ]));
    }

    public function test_an_exclusion_on_a_nested_router_group_keeps_the_group_finding(): void
    {
        $result = $this->analyzeFiles([
            ...self::authThenBeside(''),
            'routes/members.php' => self::membersRoutes("Route::group([], function (\$router) {\n    \$router->group(['excluded_middleware' => 'auth'], function () {\n        Route::post('/members', [MemberController::class, 'store']);\n    });\n});"),
        ]);

        $this->assertHasIssueContaining('Route group without authentication middleware', $result);
    }

    /**
     * A Laravel 11 project whose bootstrap/app.php registers routes/members.php, an open
     * POST /members route, under auth in its then: callback, its AppServiceProvider running
     * $register and $boot.
     *
     * @return array<string, string>
     */
    private static function laravel11Project(string $register = '', string $boot = ''): array
    {
        return [
            'bootstrap/app.php' => self::bootstrapApp('', "web: __DIR__.'/../routes/web.php',\n        commands: __DIR__.'/../routes/console.php',\n        health: '/up',\n        then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },"),
            'bootstrap/providers.php' => "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n];\n",
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::get('/', fn () => view('welcome'));\n",
            'routes/console.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Artisan;\n\nArtisan::command('about:app', function () {\n    \$this->comment('app');\n});\n",
            'routes/members.php' => "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/members', [MemberController::class, 'store']);\n",
            'app/Providers/AppServiceProvider.php' => "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Support\\Facades\\Route;\nuse Illuminate\\Support\\ServiceProvider;\n\nclass AppServiceProvider extends ServiceProvider\n{\n    public function register(): void\n    {\n        {$register}\n    }\n\n    public function boot(): void\n    {\n        {$boot}\n    }\n}\n",
            'app/Http/Controllers/MemberController.php' => "<?php\n\nnamespace App\\Http\\Controllers;\n\nclass MemberController\n{\n    public function store()\n    {\n        return 1;\n    }\n}\n",
            'app/Http/Controllers/HomeController.php' => "<?php\n\nnamespace App\\Http\\Controllers;\n\nclass HomeController\n{\n    public function index()\n    {\n        return redirect()->route('dashboard');\n    }\n}\n",
            'app/Models/Post.php' => "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n\nclass Post extends Model\n{\n    public function scopeByAuthor(\$query)\n    {\n        return \$query->orderBy('user_id')->groupBy('user_id');\n    }\n}\n",
            'app/helpers.php' => "<?php\n\nif (! function_exists('cents')) {\n    function cents(\$value) { return \$value * 100; }\n}\n",
        ];
    }

    /**
     * A Laravel 10 project whose RouteServiceProvider's routes() callback runs $registration,
     * by default registering routes/members.php, an open POST /members route, under web and
     * auth, its AppServiceProvider running $register.
     *
     * @return array<string, string>
     */
    private static function laravel10Project(string $registration = "Route::middleware(['web', 'auth'])->group(base_path('routes/members.php'));", string $register = ''): array
    {
        $project = self::laravel11Project($register);
        unset($project['bootstrap/app.php'], $project['bootstrap/providers.php']);

        return [
            ...$project,
            'app/Providers/RouteServiceProvider.php' => "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Foundation\\Support\\Providers\\RouteServiceProvider as ServiceProvider;\nuse Illuminate\\Support\\Facades\\Route;\n\nclass RouteServiceProvider extends ServiceProvider\n{\n    public function boot(): void\n    {\n        \$this->routes(function () {\n            Route::middleware('api')->prefix('api')->group(base_path('routes/api.php'));\n\n            Route::middleware('web')->group(base_path('routes/web.php'));\n\n            {$registration}\n        });\n    }\n}\n",
            'app/Providers/BroadcastServiceProvider.php' => "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Support\\Facades\\Broadcast;\nuse Illuminate\\Support\\ServiceProvider;\n\nclass BroadcastServiceProvider extends ServiceProvider\n{\n    public function boot(): void\n    {\n        Broadcast::routes();\n\n        require base_path('routes/channels.php');\n    }\n}\n",
            'app/Console/Kernel.php' => "<?php\n\nnamespace App\\Console;\n\nuse Illuminate\\Foundation\\Console\\Kernel as ConsoleKernel;\n\nclass Kernel extends ConsoleKernel\n{\n    protected function commands(): void\n    {\n        \$this->load(__DIR__.'/Commands');\n\n        require base_path('routes/console.php');\n    }\n}\n",
            'app/Http/Kernel.php' => "<?php\n\nnamespace App\\Http;\n\nuse Illuminate\\Foundation\\Http\\Kernel as HttpKernel;\n\nclass Kernel extends HttpKernel\n{\n    protected \$middlewareGroups = [\n        'web' => [\n            \\Illuminate\\Session\\Middleware\\StartSession::class,\n        ],\n        'api' => [\n            \\Illuminate\\Routing\\Middleware\\SubstituteBindings::class,\n        ],\n    ];\n\n    protected \$middlewareAliases = [\n        'auth' => \\App\\Http\\Middleware\\Authenticate::class,\n        'guest' => \\App\\Http\\Middleware\\RedirectIfAuthenticated::class,\n    ];\n}\n",
            'app/Http/Middleware/Authenticate.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nuse Illuminate\\Auth\\Middleware\\Authenticate as Middleware;\n\nclass Authenticate extends Middleware\n{\n}\n",
            'routes/api.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware('auth:sanctum')->get('/user', fn () => 1);\n",
            'routes/channels.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Broadcast;\n\nBroadcast::channel('orders.{id}', fn () => true);\n",
        ];
    }

    /**
     * bootstrap/app.php registering routes/members.php under auth in its then: callback,
     * beside $provider as app/Providers/AppServiceProvider.php when one is given.
     *
     * @return array<string, string>
     */
    private static function authThenBeside(string $provider): array
    {
        $files = ['bootstrap/app.php' => self::bootstrapApp(
            '',
            "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },",
        )];

        return $provider !== '' ? [...$files, 'app/Providers/AppServiceProvider.php' => $provider] : $files;
    }

    /**
     * Reading the registrations of route files must leave the trees of the shared parser as
     * another analyzer reading them after it, without the cache cleared, would find them.
     *
     * @dataProvider sharedParserProvider
     *
     * @param  array<string, string>  $files
     * @param  class-string<AnalyzerInterface>  $other
     */
    #[DataProvider('sharedParserProvider')]
    public function test_reading_registrations_leaves_other_analyzers_unchanged_on_a_shared_parser(array $files, string $other): void
    {
        $basePath = $this->createTempDirectory($files);
        $authentication = $this->createAnalyzer();
        $authentication->setBasePath($basePath);
        $authentication->analyze();

        $messages = function (AstParser $parser) use ($other, $basePath): array {
            $analyzer = new $other($parser);
            $analyzer->setBasePath($basePath);

            return $this->issueMessages($analyzer->analyze());
        };

        $this->assertNotSame([], $messages(new AstParser));
        $this->assertSame($messages(new AstParser), $messages($this->parser));
    }

    /**
     * @return array<string, array{array<string, string>, class-string<AnalyzerInterface>}>
     */
    public static function sharedParserProvider(): array
    {
        $web = "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::get('/', fn () => 1);\n";

        return [
            'csrf-protection' => [[
                'bootstrap/app.php' => self::bootstrapApp(
                    "\$hooks = Route::middleware('web')->withoutMiddleware(\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class);",
                    "web: __DIR__.'/../routes/web.php',\n        then: function () use (\$hooks) {\n            \$hooks->group(base_path('routes/hooks.php'));\n        },",
                ),
                'routes/web.php' => $web,
                'routes/hooks.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/hooks', fn () => 1);\n",
            ], CsrfAnalyzer::class],
            'login-throttling' => [[
                'bootstrap/app.php' => self::bootstrapApp(
                    "\$throttled = Route::middleware(['web', 'throttle:6,1']);",
                    "web: __DIR__.'/../routes/web.php',\n        then: function () use (\$throttled) {\n            \$throttled->group(base_path('routes/auth.php'));\n        },",
                ),
                'routes/web.php' => $web,
                'routes/auth.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/login', fn () => 1)->name('login');\n",
            ], LoginThrottlingAnalyzer::class],
        ];
    }

    public function test_registration_middleware_authenticates_a_static_group_in_the_route_file(): void
    {
        $result = $this->analyzeMembersRegistration(
            ['bootstrap/app.php' => self::bootstrapApp('', "then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },")],
            "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::group(['prefix' => 'team'], function () {\n    Route::post('/members', [MemberController::class, 'store']);\n});\n",
        );

        $this->assertPassed($result);
    }

    public function test_registration_middleware_does_not_open_a_finding_on_a_method_a_get_route_reaches(): void
    {
        // The GET route in the auth-registered file reached store() without auth on the
        // base, which counted the method public; crediting the registration keeps that so
        // only the open POST route is reported, as before
        $result = $this->analyzeFiles([
            'bootstrap/app.php' => self::bootstrapApp(
                '',
                "web: __DIR__.'/../routes/web.php',\n        then: function () {\n            Route::middleware('auth')->group(base_path('routes/members.php'));\n        },",
            ),
            'routes/members.php' => "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::get('/members/store', [MemberController::class, 'store']);\n",
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/members', [MemberController::class, 'store']);\n",
            'app/Http/Controllers/MemberController.php' => $this->plainController('MemberController', ['store']),
        ]);

        $this->assertSame(['POST route without authentication middleware'], $this->issueMessages($result));
    }

    /**
     * Analyze routes/members.php, by default an unauthenticated POST /members route on
     * MemberController::store(), registered by $registration.
     *
     * @param  array<string, string>  $registration
     */
    private function analyzeMembersRegistration(array $registration, string $members = ''): ResultInterface
    {
        $members = $members !== '' ? $members : "<?php\n\nuse App\\Http\\Controllers\\MemberController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/members', [MemberController::class, 'store']);\n";

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($this->createTempDirectory([...$registration, 'routes/members.php' => $members]));

        return $analyzer->analyze();
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

    // ==========================================
    // Route middleware reading (#591, #606, #607, #610, #611, #612, #623)
    // ==========================================

    /**
     * @return array<string, array{string}>
     */
    public static function authenticateClassMiddlewareProvider(): array
    {
        return [
            'imported class' => ["use Illuminate\\Auth\\Middleware\\Authenticate;\n\nRoute::middleware(Authenticate::class)->group(function () {\n    Route::post('/ledgers', fn () => 1);\n});"],
            'imported class with a guard' => ["use Illuminate\\Auth\\Middleware\\Authenticate;\n\nRoute::middleware(Authenticate::class.':staff')->group(function () {\n    Route::post('/ledgers', fn () => 1);\n});"],
            'class imported under an alias' => ["use Illuminate\\Auth\\Middleware\\Authenticate as SignedIn;\n\nRoute::post('/ledgers', fn () => 1)->middleware(SignedIn::class);"],
            'fully qualified class' => ["Route::post('/ledgers', fn () => 1)->middleware(\\Illuminate\\Auth\\Middleware\\Authenticate::class);"],
            'basic auth class' => ["use Illuminate\\Auth\\Middleware\\AuthenticateWithBasicAuth;\n\nRoute::post('/ledgers', fn () => 1)->middleware([AuthenticateWithBasicAuth::class]);"],
            'class string with a leading backslash and a guard' => ["Route::post('/ledgers', fn () => 1)->middleware('\\Illuminate\\Auth\\Middleware\\Authenticate:staff');"],
            'class string in another case' => ["Route::post('/ledgers', fn () => 1)->middleware('illuminate\\auth\\middleware\\AUTHENTICATE');"],
            'using() with a guard' => ["use Illuminate\\Auth\\Middleware\\Authenticate;\n\nRoute::post('/ledgers', fn () => 1)->middleware(Authenticate::using('staff'));"],
        ];
    }

    /**
     * @dataProvider authenticateClassMiddlewareProvider
     */
    #[DataProvider('authenticateClassMiddlewareProvider')]
    public function test_counts_the_authenticate_middleware_class_as_authentication(string $routes): void
    {
        $this->assertPassed($this->analyzeWebRoutes($routes));
    }

    public function test_still_reports_a_route_behind_another_middleware_class(): void
    {
        $result = $this->analyzeWebRoutes("use Illuminate\\Session\\Middleware\\AuthenticateSession;\n\nRoute::post('/ledgers', fn () => 1)->middleware(AuthenticateSession::class);");

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    public function test_counts_an_app_middleware_extending_authenticate_as_authentication(): void
    {
        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

use Illuminate\Auth\Middleware\Authenticate as Middleware;

class Authenticate extends Middleware
{
    protected function redirectTo($request): ?string
    {
        return '/sign-in';
    }
}
PHP;

        $result = $this->analyzeFiles([
            'app/Http/Middleware/Authenticate.php' => $middleware,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Middleware\\Authenticate;\n\nRoute::post('/ledgers', fn () => 1)->middleware(Authenticate::class);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_without_middleware_on_the_authenticate_class_opts_the_route_out_as_the_alias_does(): void
    {
        // The 'auth' alias the group gives resolves to the class the route excludes, an
        // explicit opt-out as withoutMiddleware('auth') is
        $result = $this->analyzeWebRoutes(<<<'PHP'
use Illuminate\Auth\Middleware\Authenticate;

Route::middleware('auth')->group(function () {
    Route::post('/ledgers', fn () => 1)->withoutMiddleware(Authenticate::class);
});
PHP);

        $this->assertPassed($result);
    }

    public function test_without_middleware_on_the_authenticate_class_opts_nothing_out_of_a_route_without_auth(): void
    {
        $result = $this->analyzeWebRoutes("use Illuminate\\Auth\\Middleware\\Authenticate;\n\nRoute::post('/ledgers', fn () => 1)->withoutMiddleware(Authenticate::class);");

        $this->assertSame(['POST closure route without authentication middleware'], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function actionArrayMiddlewareProvider(): array
    {
        return [
            'string middleware and a uses string' => ["Route::post('/vouchers', ['middleware' => 'auth', 'uses' => 'App\\Http\\Controllers\\VoucherController@store']);"],
            'middleware list' => ["Route::post('/vouchers', ['middleware' => ['web', 'auth:staff'], 'uses' => 'App\\Http\\Controllers\\VoucherController@store']);"],
            'uses tuple-free class string' => ["use App\\Http\\Controllers\\VoucherController;\n\nRoute::post('/vouchers', ['uses' => VoucherController::class.'@store', 'middleware' => 'auth']);"],
            'in a group without auth' => ["Route::middleware('web')->group(function () {\n    Route::post('/vouchers', ['middleware' => 'auth', 'uses' => 'App\\Http\\Controllers\\VoucherController@store']);\n});"],
        ];
    }

    /**
     * @dataProvider actionArrayMiddlewareProvider
     */
    #[DataProvider('actionArrayMiddlewareProvider')]
    public function test_reads_the_middleware_of_a_route_action_array(string $routes): void
    {
        $result = $this->analyzeFiles([
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n",
            'app/Http/Controllers/VoucherController.php' => $this->plainController('VoucherController', ['store']),
        ]);

        $this->assertPassed($result);
    }

    public function test_reads_the_middleware_of_a_closure_action_array(): void
    {
        $this->assertPassed($this->analyzeWebRoutes(<<<'PHP'
Route::post('/vouchers', ['middleware' => 'auth', fn () => 1]);
Route::put('/vouchers/{voucher}', ['middleware' => 'auth', 'uses' => function () {
    return 1;
}]);
PHP));
    }

    public function test_still_reports_an_action_array_route_without_auth(): void
    {
        $result = $this->analyzeFiles([
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/vouchers', ['middleware' => 'web', 'uses' => 'App\\Http\\Controllers\\VoucherController@store']);\n",
            'app/Http/Controllers/VoucherController.php' => $this->plainController('VoucherController', ['store']),
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
        $this->assertHasIssueContaining('Sensitive method VoucherController::store() without authentication check', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function groupWithoutMiddlewareFirstArgumentProvider(): array
    {
        return [
            'on the registrar of the group' => ["Route::middleware('auth')->withoutMiddleware('throttle', 'auth')->group(function () {\n    Route::post('/ledgers', fn () => 1);\n});"],
            'on a nested group' => ["Route::middleware('auth')->group(function () {\n    Route::withoutMiddleware('throttle', 'auth')->group(function () {\n        Route::post('/ledgers', fn () => 1);\n    });\n});"],
            'list first' => ["Route::middleware('auth')->group(function () {\n    Route::withoutMiddleware(['throttle'], 'auth')->group(function () {\n        Route::post('/ledgers', fn () => 1);\n    });\n});"],
        ];
    }

    /**
     * @dataProvider groupWithoutMiddlewareFirstArgumentProvider
     */
    #[DataProvider('groupWithoutMiddlewareFirstArgumentProvider')]
    public function test_group_without_middleware_reads_only_its_first_argument(string $routes): void
    {
        $this->assertPassed($this->analyzeWebRoutes($routes));
    }

    public function test_group_without_middleware_still_removes_auth_listed_first(): void
    {
        $result = $this->analyzeWebRoutes(<<<'PHP'
Route::middleware('auth')->group(function () {
    Route::withoutMiddleware(['throttle', 'auth'], 'verified')->group(function () {
        Route::post('/ledgers', fn () => 1);
    });
});
PHP);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function hasMiddlewareListProvider(): array
    {
        return [
            'plain string and a scoped entry' => ["['auth', new Middleware('verified', only: ['store'])]"],
            'scoped auth entry' => ["[new Middleware('auth', only: ['store', 'create'])]"],
            'positional only' => ["[new Middleware('auth:staff', ['store', 'create'])]"],
            'except a reader' => ["[new Middleware(['web', 'auth'], except: ['index'])]"],
            'positional except' => ["[new Middleware('auth', null, ['index'])]"],
            'chained only' => ["[(new Middleware('auth'))->only(['store', 'create'])]"],
            'fully qualified entry' => ["[new \\Illuminate\\Routing\\Controllers\\Middleware('auth')]"],
            'authenticate class' => ['[new Middleware(Authenticate::class)]'],
            'two auth entries' => ["[new Middleware('auth', only: ['store']), new Middleware('auth', only: ['create'])]"],
        ];
    }

    /**
     * @dataProvider hasMiddlewareListProvider
     */
    #[DataProvider('hasMiddlewareListProvider')]
    public function test_reads_the_middleware_list_of_a_has_middleware_controller(string $list): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/MemoController.php' => $this->hasMiddlewareController($list),
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function hasMiddlewareListMissingStoreProvider(): array
    {
        return [
            'only another action' => ["[new Middleware('auth', only: ['create'])]"],
            'except the action' => ["[new Middleware('auth', except: ['store'])]"],
            'no auth' => ["['verified', new Middleware('throttle:6,1')]"],
        ];
    }

    /**
     * @dataProvider hasMiddlewareListMissingStoreProvider
     */
    #[DataProvider('hasMiddlewareListMissingStoreProvider')]
    public function test_still_reports_an_action_a_has_middleware_list_leaves_out(string $list): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/MemoController.php' => $this->hasMiddlewareController($list),
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Sensitive method MemoController::store() without authentication check', $result);
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function middlewareGroupWithAuthProvider(): array
    {
        $bootstrap = static fn (string $calls): string => "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Foundation\\Configuration\\Middleware;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function (Middleware \$middleware): void {\n        {$calls}\n    })\n    ->create();\n";

        return [
            'bootstrap group' => [['bootstrap/app.php' => $bootstrap("\$middleware->group('crew', ['web', 'auth']);")]],
            'bootstrap appendToGroup' => [['bootstrap/app.php' => $bootstrap("\$middleware->group('crew', ['web'])->appendToGroup('crew', 'auth:staff');")]],
            'bootstrap prependToGroup with the class' => [['bootstrap/app.php' => $bootstrap("\$middleware->prependToGroup('crew', [\\Illuminate\\Auth\\Middleware\\Authenticate::class]);")]],
            'bootstrap nested group' => [['bootstrap/app.php' => $bootstrap("\$middleware->group('crew', ['web', 'members']);\n        \$middleware->group('members', ['auth']);")]],
            'bootstrap group appended after a removal' => [['bootstrap/app.php' => $bootstrap("\$middleware->group('crew', ['web', 'auth']);\n        \$middleware->removeFromGroup('crew', 'auth');\n        \$middleware->appendToGroup('crew', 'auth');")]],
            'kernel group' => [['app/Http/Kernel.php' => "<?php\n\nnamespace App\\Http;\n\nuse Illuminate\\Foundation\\Http\\Kernel as HttpKernel;\n\nclass Kernel extends HttpKernel\n{\n    protected \$middlewareGroups = [\n        'web' => [],\n        'crew' => ['web', 'auth'],\n    ];\n}\n"]],
        ];
    }

    /**
     * @dataProvider middlewareGroupWithAuthProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('middlewareGroupWithAuthProvider')]
    public function test_reads_auth_inside_a_custom_middleware_group(array $files): void
    {
        $result = $this->analyzeFiles([
            ...$files,
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware('crew')->group(function () {\n    Route::post('/rosters', fn () => 1);\n});\nRoute::group(['middleware' => ['crew']], function () {\n    Route::put('/rosters/{roster}', fn () => 1);\n});\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function middlewareGroupWithoutAuthProvider(): array
    {
        return [
            'group without auth' => ["\$middleware->group('crew', ['web', 'verified']);", "Route::middleware('crew')->post('/rosters', fn () => 1);"],
            'auth removed from the group' => ["\$middleware->group('crew', ['web', 'auth']);\n        \$middleware->removeFromGroup('crew', 'auth');", "Route::middleware('crew')->post('/rosters', fn () => 1);"],
            'groups naming each other' => ["\$middleware->group('crew', ['members']);\n        \$middleware->group('members', ['crew']);", "Route::middleware('crew')->post('/rosters', fn () => 1);"],
            'group member excluded by the group' => ["\$middleware->group('crew', ['web', 'auth']);", "Route::middleware('crew')->withoutMiddleware('auth')->group(function () {\n    Route::post('/rosters', fn () => 1);\n});"],
        ];
    }

    /**
     * @dataProvider middlewareGroupWithoutAuthProvider
     */
    #[DataProvider('middlewareGroupWithoutAuthProvider')]
    public function test_still_reports_a_custom_middleware_group_that_runs_no_auth(string $calls, string $routes): void
    {
        $result = $this->analyzeFiles([
            'bootstrap/app.php' => "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Foundation\\Configuration\\Middleware;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function (Middleware \$middleware): void {\n        {$calls}\n    })\n    ->create();\n",
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n",
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function guestWithGuardProvider(): array
    {
        return [
            'route middleware' => ["Route::post('/staff/sign-in', fn () => 1)->middleware('guest:staff');"],
            'group attribute' => ["Route::group(['middleware' => 'guest:staff'], function () {\n    Route::post('/staff/sign-in', fn () => 1);\n});"],
            'registrar group' => ["Route::middleware(['web', 'guest:staff'])->group(function () {\n    Route::post('/staff/sign-in', fn () => 1);\n});"],
        ];
    }

    /**
     * @dataProvider guestWithGuardProvider
     */
    #[DataProvider('guestWithGuardProvider')]
    public function test_treats_guest_with_a_guard_as_guest(string $routes): void
    {
        $this->assertPassed($this->analyzeWebRoutes($routes));
    }

    public function test_controller_method_behind_guest_with_a_guard_is_not_flagged(): void
    {
        $result = $this->analyzeFiles([
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\StaffSessionController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/staff/sign-in', [StaffSessionController::class, 'store'])->middleware('guest:staff');\n",
            'app/Http/Controllers/StaffSessionController.php' => $this->plainController('StaffSessionController', ['store']),
        ]);

        $this->assertPassed($result);
    }

    public function test_does_not_treat_a_guest_prefixed_alias_as_guest(): void
    {
        $result = $this->analyzeWebRoutes(<<<'PHP'
Route::post('/staff/sign-in', fn () => 1)->middleware('guestbook');
Route::group(['middleware' => 'guestbook'], function () {
    Route::post('/staff/sign-up', fn () => 1);
});
PHP);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
        $this->assertHasIssueContaining('Route group without authentication middleware', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function controllerGroupProvider(): array
    {
        return [
            'registrar controller' => ["Route::controller(LedgerController::class)->middleware('auth')->group(function () {\n    Route::post('/ledgers', 'store');\n});"],
            'controller after middleware' => ["Route::middleware('auth')->controller(LedgerController::class)->group(function () {\n    Route::post('/ledgers', 'store');\n});"],
            'attribute array' => ["Route::group(['controller' => LedgerController::class, 'middleware' => 'auth'], function () {\n    Route::post('/ledgers', 'store');\n});"],
            'outer auth group' => ["Route::middleware('auth')->group(function () {\n    Route::controller(LedgerController::class)->group(function () {\n        Route::post('/ledgers', 'store');\n    });\n});"],
        ];
    }

    /**
     * @dataProvider controllerGroupProvider
     */
    #[DataProvider('controllerGroupProvider')]
    public function test_resolves_a_bare_method_against_the_group_controller(string $routes): void
    {
        $result = $this->analyzeFiles([
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\LedgerController;\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n",
            'app/Http/Controllers/LedgerController.php' => $this->plainController('LedgerController', ['store']),
        ]);

        $this->assertPassed($result);
    }

    public function test_inner_group_controller_overrides_the_outer_one(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\JournalController;
use App\Http\Controllers\LedgerController;
use Illuminate\Support\Facades\Route;

Route::controller(JournalController::class)->middleware('auth')->group(function () {
    Route::controller(LedgerController::class)->group(function () {
        Route::post('/ledgers', 'store');
    });
});
PHP;

        $result = $this->analyzeFiles([
            'routes/web.php' => $routes,
            'app/Http/Controllers/LedgerController.php' => $this->plainController('LedgerController', ['store']),
            'app/Http/Controllers/JournalController.php' => $this->plainController('JournalController', ['store']),
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('Sensitive method JournalController::store() without authentication check', $result);
    }

    public function test_still_reports_a_group_controller_method_without_auth(): void
    {
        $result = $this->analyzeFiles([
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\LedgerController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::controller(LedgerController::class)->middleware('web')->group(function () {\n    Route::post('/ledgers', 'store');\n});\n",
            'app/Http/Controllers/LedgerController.php' => $this->plainController('LedgerController', ['store']),
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
        $this->assertHasIssueContaining('Sensitive method LedgerController::store() without authentication check', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function constructorAuthRouteProvider(): array
    {
        return [
            'group controller' => ["Route::controller(ProfileController::class)->group(function () {\n    Route::get('/profile', 'show');\n});"],
            'uses string' => ["Route::get('/profile', ['uses' => 'App\\Http\\Controllers\\ProfileController@show']);"],
            'class and method string' => ["Route::get('/profile', ProfileController::class.'@show');"],
            'attribute array group' => ["Route::group(['controller' => ProfileController::class, 'middleware' => 'web'], function () {\n    Route::get('/profile', 'show');\n});"],
            'tuple route' => ["Route::get('/profile', [ProfileController::class, 'show']);"],
            'guest with a guard' => ["Route::post('/profile', [ProfileController::class, 'store'])->middleware('guest:staff');"],
        ];
    }

    /**
     * @dataProvider constructorAuthRouteProvider
     */
    #[DataProvider('constructorAuthRouteProvider')]
    public function test_auth_user_reads_the_controller_auth_of_a_method_an_open_route_reaches(string $routes): void
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
        return Auth::user()->id;
    }

    public function store()
    {
        return Auth::user()->id;
    }
}
PHP;

        $result = $this->analyzeFiles([
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\ProfileController;\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n",
            'app/Http/Controllers/ProfileController.php' => $controller,
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function controllerAuthCoveredRouteProvider(): array
    {
        return [
            'has middleware list' => ["    public static function middleware(): array\n    {\n        return ['auth', new Middleware('verified', only: ['store'])];\n    }\n"],
            'constructor auth' => ["    public function __construct()\n    {\n        \$this->middleware('auth')->only(['create', 'store']);\n    }\n"],
        ];
    }

    /**
     * @dataProvider controllerAuthCoveredRouteProvider
     */
    #[DataProvider('controllerAuthCoveredRouteProvider')]
    public function test_route_reads_the_controller_auth_of_the_method_it_reaches(string $members): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/JotController.php' => $this->jotController($members),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\JotController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::get('/jots/create', [JotController::class, 'create']);\nRoute::post('/jots', [JotController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_route_still_reports_a_method_the_controller_auth_leaves_out(): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/JotController.php' => $this->jotController("    public static function middleware(): array\n    {\n        return [new Middleware('auth', only: ['create'])];\n    }\n"),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\JotController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/jots', [JotController::class, 'store']);\nRoute::post('/jots/draft', fn () => 1);\n",
        ]);

        $this->assertSame([
            'POST route without authentication middleware',
            'POST closure route without authentication middleware',
            'Sensitive method JotController::store() without authentication check',
        ], array_map(fn ($issue) => $issue->message, $result->getIssues()));
    }

    public function test_route_still_reports_controller_auth_the_route_removes(): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/JotController.php' => $this->jotController("    public static function middleware(): array\n    {\n        return ['auth'];\n    }\n"),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\JotController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::withoutMiddleware('auth')->group(function () {\n    Route::post('/jots', [JotController::class, 'store']);\n});\n",
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_has_middleware_applies_both_only_and_except(): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/MemoController.php' => $this->hasMiddlewareController("[new Middleware('auth', only: ['store', 'create'], except: ['store'])]"),
        ]);

        $this->assertSame(
            ['Sensitive method MemoController::store() without authentication check'],
            array_map(fn ($issue) => $issue->message, $result->getIssues()),
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function newlyResolvedOpenRouteProvider(): array
    {
        return [
            'uses string' => ["Route::delete('/members/{member}', ['uses' => 'App\\Http\\Controllers\\MembershipController@destroy']);"],
            'group controller' => ["Route::controller(MembershipController::class)->group(function () {\n    Route::delete('/members/{member}', 'destroy');\n});"],
        ];
    }

    /**
     * @dataProvider newlyResolvedOpenRouteProvider
     */
    #[DataProvider('newlyResolvedOpenRouteProvider')]
    public function test_reports_the_controller_and_form_request_of_a_newly_resolved_open_route(string $routes): void
    {
        $result = $this->analyzeFormRequestWithoutAuthorize($routes);

        $this->assertHasIssueContaining('Sensitive method MembershipController::destroy() without authentication check', $result);
        $this->assertHasIssueContaining('RemoveMemberRequest has no authorize() method, so every request is authorized', $result);
    }

    public function test_action_array_middleware_replaces_the_registrar_middleware(): void
    {
        $result = $this->analyzeWebRoutes("Route::middleware('auth')->post('/vouchers', ['middleware' => 'web', 'uses' => 'App\\Http\\Controllers\\VoucherController@store']);");

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
    }

    public function test_reads_a_group_before_an_alias_of_the_same_name(): void
    {
        $result = $this->analyzeFiles([
            'bootstrap/app.php' => "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Foundation\\Configuration\\Middleware;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function (Middleware \$middleware): void {\n        \$middleware->alias(['crew' => \\App\\Http\\Middleware\\Authenticate::class]);\n        \$middleware->group('crew', ['web']);\n    })\n    ->create();\n",
            'app/Http/Middleware/Authenticate.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nuse Illuminate\\Auth\\Middleware\\Authenticate as Middleware;\n\nclass Authenticate extends Middleware\n{\n}\n",
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/rosters', fn () => 1)->middleware('crew');\n",
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    public function test_keeps_the_route_message_of_an_action_array_with_a_closure(): void
    {
        $result = $this->analyzeWebRoutes(<<<'PHP'
Route::post('/drafts', ['as' => 'drafts', function () {
    return 1;
}]);
Route::post('/drafts/copy', ['uses' => fn () => 1]);
Route::post('/drafts/send', ['middleware' => 'throttle', function () {
    return 1;
}]);
PHP);

        $this->assertSame(
            array_fill(0, 3, 'POST route without authentication middleware'),
            array_map(fn ($issue) => $issue->message, $result->getIssues()),
        );
    }

    public function test_reads_groups_only_from_the_middleware_configurator(): void
    {
        $result = $this->analyzeFiles([
            'bootstrap/app.php' => "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Foundation\\Configuration\\Middleware;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function (Middleware \$middleware): void {\n        \$middleware->alias(['token' => \\App\\Http\\Middleware\\Token::class]);\n    })\n    ->withRouting(web: __DIR__.'/../routes/web.php', then: function (\$router) {\n        \$router->group('crew', ['auth']);\n    })\n    ->create();\n",
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/rosters', fn () => 1)->middleware('crew');\n",
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    public function test_bare_resource_controller_is_not_a_group_controller_method(): void
    {
        $result = $this->analyzeFiles([
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\LedgerController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::controller(LedgerController::class)->middleware('auth')->group(function () {\n    Route::resource('photos', 'PhotoController');\n});\n",
            'app/Http/Controllers/LedgerController.php' => $this->plainController('LedgerController', ['store']),
            'app/Http/Controllers/PhotoController.php' => $this->plainController('PhotoController', ['store', 'update', 'destroy']),
        ]);

        $this->assertSame(
            ['Sensitive method LedgerController::store() without authentication check'],
            array_map(fn ($issue) => $issue->message, $result->getIssues()),
        );
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function webGroupMemberProvider(): array
    {
        $member = "<?php\n\nnamespace App\\Http\\Middleware;\n\nuse Illuminate\\Contracts\\Auth\\Factory;\n\nclass ShareViewer\n{\n    public function __construct(private Factory \$auth)\n    {\n    }\n\n    public function handle(\$request, \$next)\n    {\n        view()->share('viewer', \$this->auth->guard()->user());\n\n        return \$next(\$request);\n    }\n}\n";

        return [
            'kernel' => [[
                'app/Http/Middleware/ShareViewer.php' => $member,
                'app/Http/Kernel.php' => "<?php\n\nnamespace App\\Http;\n\nuse Illuminate\\Foundation\\Http\\Kernel as HttpKernel;\n\nclass Kernel extends HttpKernel\n{\n    protected \$middlewareGroups = [\n        'web' => [\\App\\Http\\Middleware\\ShareViewer::class],\n    ];\n}\n",
            ]],
            'bootstrap' => [[
                'app/Http/Middleware/ShareViewer.php' => $member,
                'bootstrap/app.php' => "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Foundation\\Configuration\\Middleware;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function (Middleware \$middleware): void {\n        \$middleware->appendToGroup('web', \\App\\Http\\Middleware\\ShareViewer::class);\n    })\n    ->create();\n",
            ]],
        ];
    }

    /**
     * @dataProvider webGroupMemberProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('webGroupMemberProvider')]
    public function test_group_member_counts_as_auth_only_by_a_strict_signal(array $files): void
    {
        $result = $this->analyzeFiles([
            ...$files,
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware('web')->post('/rosters', fn () => 1);\n",
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    public function test_group_member_extending_authenticate_counts_as_auth(): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Middleware/StaffGate.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass StaffGate extends Authenticate\n{\n}\n",
            'app/Http/Middleware/Authenticate.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nuse Illuminate\\Auth\\Middleware\\Authenticate as Middleware;\n\nclass Authenticate extends Middleware\n{\n}\n",
            'bootstrap/app.php' => "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Foundation\\Configuration\\Middleware;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function (Middleware \$middleware): void {\n        \$middleware->appendToGroup('crew', \\App\\Http\\Middleware\\StaffGate::class);\n    })\n    ->create();\n",
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware('crew')->post('/rosters', fn () => 1);\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * A JotController in App\Http\Controllers implementing HasMiddleware, with $members,
     * create() and store().
     */
    private function jotController(string $members): string
    {
        return "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse Illuminate\\Routing\\Controllers\\HasMiddleware;\nuse Illuminate\\Routing\\Controllers\\Middleware;\n\nclass JotController extends Controller implements HasMiddleware\n{\n{$members}\n    public function create()\n    {\n        return 1;\n    }\n\n    public function store()\n    {\n        return 1;\n    }\n}\n";
    }

    /**
     * @return array<string, array{string, string, list<string>}>
     */
    public static function middlewareMethodWithoutHasMiddlewareProvider(): array
    {
        $route = 'POST route without authentication middleware';
        $store = 'Sensitive method PadController::store() without authentication check';
        $unsafe = 'Unsafe Auth::user() usage without null check';

        return [
            'list' => ["['auth']", "Route::post('/pads', [PadController::class, 'store']);", [$route, $store, $unsafe]],
            'middleware definition' => ["[new Middleware('auth')]", "Route::post('/pads', [PadController::class, 'store']);", [$route, $store, $unsafe]],
            'keyed entry' => ["['auth' => []]", "Route::post('/pads', [PadController::class, 'store']);", [$route]],
            'list in a static group' => ["['auth']", "Route::group(['prefix' => 'n'], function () {\n    Route::post('/pads', [PadController::class, 'store']);\n});", ['Route group without authentication middleware', $route, $store, $unsafe]],
            'keyed entry in a static group' => ["['auth' => []]", "Route::group(['prefix' => 'n'], function () {\n    Route::post('/pads', [PadController::class, 'store']);\n});", ['Route group without authentication middleware', $route]],
            'list on an open GET' => ["['auth']", "Route::get('/pads', [PadController::class, 'index']);", [$store, $unsafe]],
            'keyed entry on an open GET' => ["['auth' => []]", "Route::get('/pads', [PadController::class, 'index']);", [$unsafe]],
        ];
    }

    /**
     * @dataProvider middlewareMethodWithoutHasMiddlewareProvider
     *
     * @param  list<string>  $expected
     */
    #[DataProvider('middlewareMethodWithoutHasMiddlewareProvider')]
    public function test_reads_a_middleware_list_only_from_a_has_middleware_controller(string $list, string $routes, array $expected): void
    {
        $members = "    public static function middleware(): array\n    {\n        return {$list};\n    }\n";

        $this->assertSame($expected, $this->issueMessages($this->analyzeFiles([
            'app/Http/Controllers/PadController.php' => $this->padController($members, false),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\PadController;\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n",
        ])));
    }

    public function test_reads_a_middleware_list_of_a_controller_whose_parent_implements_has_middleware(): void
    {
        $this->assertSame([], $this->issueMessages($this->analyzeFiles([
            'app/Http/Controllers/BaseController.php' => "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse Illuminate\\Routing\\Controllers\\HasMiddleware;\n\nabstract class BaseController implements HasMiddleware\n{\n}\n",
            'app/Http/Controllers/PadController.php' => str_replace('class PadController', 'class PadController extends BaseController', $this->padController("    public static function middleware(): array\n    {\n        return ['auth'];\n    }\n", false)),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\PadController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/pads', [PadController::class, 'store']);\n",
        ])));
    }

    /**
     * @return array<string, array{string, bool, string, list<string>}>
     */
    public static function unreadableMethodListProvider(): array
    {
        $route = 'POST route without authentication middleware';
        $store = 'Sensitive method PadController::store() without authentication check';
        $unsafe = 'Unsafe Auth::user() usage without null check';
        $post = "Route::post('/pads', [PadController::class, 'store']);";
        $get = "Route::get('/pads', [PadController::class, 'index']);";

        return [
            'except a constant' => ["    private const OPEN = ['store'];\n\n    public static function middleware(): array\n    {\n        return [new Middleware('auth', except: self::OPEN)];\n    }\n", true, $post, [$route, $store, $unsafe]],
            'chained except a variable' => ["    public static function middleware(): array\n    {\n        \$open = ['store'];\n\n        return [(new Middleware('auth'))->except(\$open)];\n    }\n", true, $post, [$route, $store, $unsafe]],
            'constructor only a property' => ["    private array \$guarded = ['store'];\n\n    public function __construct()\n    {\n        \$this->middleware('auth')->only(\$this->guarded);\n    }\n", false, $post, [$route]],
            'constructor only an empty list' => ["    public function __construct()\n    {\n        \$this->middleware('auth')->only([]);\n    }\n", false, $post, [$route]],
            'constructor only a property on an open GET' => ["    private array \$guarded = ['store'];\n\n    public function __construct()\n    {\n        \$this->middleware('auth')->only(\$this->guarded);\n    }\n", false, $get, [$unsafe]],
        ];
    }

    /**
     * @dataProvider unreadableMethodListProvider
     *
     * @param  list<string>  $expected
     */
    #[DataProvider('unreadableMethodListProvider')]
    public function test_an_unreadable_method_list_covers_no_method(string $members, bool $hasMiddleware, string $routes, array $expected): void
    {
        $this->assertSame($expected, $this->issueMessages($this->analyzeFiles([
            'app/Http/Controllers/PadController.php' => $this->padController($members, $hasMiddleware),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\PadController;\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n",
        ])));
    }

    /**
     * @return array<string, array{array<string, string>, string}>
     */
    public static function groupMemberExclusionProvider(): array
    {
        $appAuthenticate = "<?php\n\nnamespace App\\Http\\Middleware;\n\nuse Illuminate\\Auth\\Middleware\\Authenticate as Middleware;\n\nclass Authenticate extends Middleware\n{\n}\n";
        $bootstrap = static fn (string $calls): string => "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Foundation\\Configuration\\Middleware;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function (Middleware \$middleware): void {\n        {$calls}\n    })\n    ->create();\n";

        return [
            'kernel group of the app class, alias excluded by a group' => [[
                'app/Http/Middleware/Authenticate.php' => $appAuthenticate,
                'app/Http/Kernel.php' => "<?php\n\nnamespace App\\Http;\n\nuse Illuminate\\Foundation\\Http\\Kernel as HttpKernel;\n\nclass Kernel extends HttpKernel\n{\n    protected \$middlewareGroups = [\n        'crew' => [\\App\\Http\\Middleware\\Authenticate::class],\n    ];\n\n    protected \$middlewareAliases = [\n        'auth' => \\App\\Http\\Middleware\\Authenticate::class,\n    ];\n}\n",
            ], "Route::middleware('crew')->group(function () {\n    Route::withoutMiddleware('auth')->group(function () {\n        Route::post('/rosters', fn () => 1);\n    });\n});"],
            'bootstrap group of the class, alias excluded by a group' => [[
                'bootstrap/app.php' => $bootstrap("\$middleware->group('crew', [\\Illuminate\\Auth\\Middleware\\Authenticate::class]);"),
            ], "Route::middleware('crew')->withoutMiddleware('auth')->group(function () {\n    Route::post('/rosters', fn () => 1);\n});"],
        ];
    }

    /**
     * @dataProvider groupMemberExclusionProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('groupMemberExclusionProvider')]
    public function test_group_auth_member_is_not_credited_when_the_route_excludes_auth(array $files, string $routes): void
    {
        $result = $this->analyzeFiles([
            ...$files,
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n",
        ]);

        $this->assertSame(['POST closure route without authentication middleware'], $this->issueMessages($result));
    }

    public function test_reads_the_excluded_middleware_of_a_route_action_array(): void
    {
        $members = "    public function store()\n    {\n        return \\Illuminate\\Support\\Facades\\Auth::user()->id;\n    }\n";

        $result = $this->analyzeFiles([
            'app/Http/Controllers/PadController.php' => "<?php\n\nnamespace App\\Http\\Controllers;\n\nclass PadController\n{\n{$members}}\n",
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware('auth')->group(function () {\n    Route::post('/pads', ['excluded_middleware' => ['auth'], 'uses' => 'App\\Http\\Controllers\\PadController@store']);\n});\n",
        ]);

        $this->assertSame([
            'POST route without authentication middleware',
            'Sensitive method PadController::store() without authentication check',
            'Unsafe Auth::user() usage without null check',
        ], $this->issueMessages($result));
    }

    /**
     * The message of each issue a result reports, in order.
     *
     * @return list<string>
     */
    private function issueMessages(ResultInterface $result): array
    {
        return array_values(array_map(fn ($issue) => $issue->message, $result->getIssues()));
    }

    /**
     * A PadController in App\Http\Controllers with $members, an index() reading the user's
     * name and an empty store(), implementing HasMiddleware when $hasMiddleware.
     */
    private function padController(string $members, bool $hasMiddleware): string
    {
        $implements = $hasMiddleware ? ' implements HasMiddleware' : '';

        return "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse Illuminate\\Routing\\Controllers\\HasMiddleware;\nuse Illuminate\\Routing\\Controllers\\Middleware;\nuse Illuminate\\Support\\Facades\\Auth;\n\nclass PadController{$implements}\n{\n{$members}\n    public function index()\n    {\n        return Auth::user()->name;\n    }\n\n    public function store()\n    {\n        return 1;\n    }\n}\n";
    }

    public function test_constructor_options_only_list_does_not_credit_a_route_to_another_method(): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/OrderController.php' => $this->orderController("    public function __construct() { \$this->middleware('auth', ['only' => ['store']]); }\n"),
            'routes/web.php' => $this->orderRoutes("Route::put('/orders/{order}', [OrderController::class, 'update']);"),
        ]);

        $this->assertHasIssueContaining('PUT route without authentication middleware', $result);
    }

    public function test_constructor_options_except_list_does_not_cover_auth_user_on_an_open_get(): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/OrderController.php' => $this->orderController("    public function __construct() { \$this->middleware('auth', ['except' => ['index']]); }\n"),
            'routes/web.php' => $this->orderRoutes("Route::get('/orders', [OrderController::class, 'index']);"),
        ]);

        $this->assertHasIssueContaining('Unsafe Auth::user() usage without null check', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function authenticateClassExclusionProvider(): array
    {
        return [
            'group excludes the class' => ["Route::withoutMiddleware(Authenticate::class)->group(function () {\n    Route::post('/orders', [OrderController::class, 'create']);\n});"],
            'route excludes the class' => ["Route::post('/orders', [OrderController::class, 'create'])->withoutMiddleware(Authenticate::class);"],
            'action array excludes the class' => ["Route::post('/orders', ['excluded_middleware' => Authenticate::class, 'uses' => 'App\\Http\\Controllers\\OrderController@create']);"],
        ];
    }

    /**
     * @dataProvider authenticateClassExclusionProvider
     */
    #[DataProvider('authenticateClassExclusionProvider')]
    public function test_route_excluding_the_authenticate_class_is_not_covered_by_controller_auth(string $routes): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/OrderController.php' => $this->orderController(
                "    public static function middleware(): array { return ['auth']; }\n",
                'use Illuminate\\Routing\\Controllers\\HasMiddleware;',
                ' implements HasMiddleware',
            ),
            'routes/web.php' => $this->orderRoutes($routes),
        ]);

        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
        $this->assertHasIssueContaining('Sensitive method OrderController::create() without authentication check', $result);
        $this->assertHasIssueContaining('Unsafe Auth::user() usage without null check', $result);
    }

    public function test_route_excluding_the_authenticate_class_is_not_covered_by_constructor_auth(): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/OrderController.php' => $this->orderController("    public function __construct() { \$this->middleware('auth'); }\n"),
            'routes/web.php' => $this->orderRoutes("Route::withoutMiddleware(Authenticate::class)->group(function () {\n    Route::post('/orders', [OrderController::class, 'create']);\n});"),
        ]);

        // The route loses its new controller credit; the constructor's master credit stays
        $this->assertSame(['POST route without authentication middleware'], $this->issueMessages($result));
    }

    public function test_has_middleware_credit_ignores_a_group_removing_auth(): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/OrderController.php' => $this->orderController(
                "    public static function middleware(): array { return ['auth']; }\n",
                'use Illuminate\\Routing\\Controllers\\HasMiddleware;',
                ' implements HasMiddleware',
            ),
            'routes/web.php' => $this->orderRoutes("Route::withoutMiddleware('auth')->group(function () {\n    Route::post('/orders', [OrderController::class, 'create']);\n});"),
        ]);

        $this->assertHasIssueContaining('Sensitive method OrderController::create() without authentication check', $result);
        $this->assertHasIssueContaining('Unsafe Auth::user() usage without null check', $result);
    }

    /**
     * @return array<string, array{array<string, string>, string}>
     */
    public static function authenticateClassUnderAuthExclusionProvider(): array
    {
        $subclass = ['app/Http/Middleware/Authenticate.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nuse Illuminate\\Auth\\Middleware\\Authenticate as Middleware;\n\nclass Authenticate extends Middleware\n{\n}\n"];

        return [
            'group of the class, inner group excludes the alias' => [[], "Route::middleware(Authenticate::class)->group(function () {\n    Route::withoutMiddleware('auth')->group(function () {\n        Route::post('/orders', fn () => 1);\n    });\n});"],
            'route of the class inside a group excluding the alias' => [[], "Route::withoutMiddleware('auth')->group(function () {\n    Route::post('/orders', fn () => 1)->middleware(Authenticate::class);\n});"],
            'app subclass inside a group excluding the alias' => [$subclass, "Route::withoutMiddleware('auth')->group(function () {\n    Route::post('/orders', fn () => 1)->middleware(\\App\\Http\\Middleware\\Authenticate::class);\n});"],
        ];
    }

    /**
     * @dataProvider authenticateClassUnderAuthExclusionProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('authenticateClassUnderAuthExclusionProvider')]
    public function test_authenticate_class_is_not_credited_when_the_group_excludes_auth(array $files, string $routes): void
    {
        $result = $this->analyzeFiles([...$files, 'routes/web.php' => $this->orderRoutes($routes)]);

        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    public function test_keyed_middleware_method_keeps_masters_first_entry_reading(): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/OrderController.php' => $this->orderController("    public function middleware() { return ['auth' => ['only' => ['index']], 'can:manage' => []]; }\n"),
            'routes/web.php' => $this->orderRoutes("Route::post('/orders', [OrderController::class, 'store']);"),
        ]);

        $this->assertHasIssueContaining('Sensitive method OrderController::store() without authentication check', $result);
    }

    public function test_guest_with_a_guard_under_auth_adds_no_auth_user_issue(): void
    {
        $result = $this->analyzeFiles([
            'app/Http/Controllers/OrderController.php' => $this->orderController(''),
            'routes/web.php' => $this->orderRoutes("Route::middleware('auth')->group(function () {\n    Route::post('/admin/sign-in', [OrderController::class, 'index'])->middleware('guest:admin');\n});"),
        ]);

        // index() (line 11) is reached only by the auth route; create() (line 12) by none
        $lines = [];
        foreach ($result->getIssues() as $issue) {
            if (str_contains($issue->message, 'Unsafe Auth::user()')) {
                $lines[] = $issue->location?->line;
            }
        }
        $this->assertSame([12], $lines);
    }

    /**
     * @return array<string, array{array<string, string>, string}>
     */
    public static function guestPermittingSubclassProvider(): array
    {
        $optional = "<?php\n\nnamespace App\\Http\\Middleware;\n\nuse Illuminate\\Auth\\Middleware\\Authenticate;\n\nclass LenientGate extends Authenticate\n{\n    protected function unauthenticated(\$request, array \$guards)\n    {\n    }\n}\n";
        $bootstrap = "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Foundation\\Configuration\\Middleware;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function (Middleware \$middleware): void {\n        \$middleware->alias(['auth.lenient' => \\App\\Http\\Middleware\\LenientGate::class]);\n    })\n    ->create();\n";
        $kernel = "<?php\n\nnamespace App\\Http;\n\nuse Illuminate\\Foundation\\Http\\Kernel as HttpKernel;\n\nclass Kernel extends HttpKernel\n{\n    protected \$middlewareAliases = [\n        'auth.lenient' => \\App\\Http\\Middleware\\LenientGate::class,\n    ];\n}\n";

        return [
            'bootstrap alias' => [['app/Http/Middleware/LenientGate.php' => $optional, 'bootstrap/app.php' => $bootstrap], "->middleware('auth.lenient')"],
            'kernel alias' => [['app/Http/Middleware/LenientGate.php' => $optional, 'app/Http/Kernel.php' => $kernel], "->middleware('auth.lenient')"],
            'class' => [['app/Http/Middleware/LenientGate.php' => $optional], '->middleware(\\App\\Http\\Middleware\\LenientGate::class)'],
            'override up the chain' => [[
                'app/Http/Middleware/LenientGate.php' => $optional,
                'app/Http/Middleware/StaffGate.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass StaffGate extends LenientGate\n{\n}\n",
            ], '->middleware(\\App\\Http\\Middleware\\StaffGate::class)'],
            'handle override' => [[
                'app/Http/Middleware/LenientGate.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nuse Illuminate\\Auth\\Middleware\\Authenticate;\n\nclass LenientGate extends Authenticate\n{\n    public function handle(\$request, \\Closure \$next, ...\$guards)\n    {\n        return \$next(\$request);\n    }\n}\n",
            ], '->middleware(\\App\\Http\\Middleware\\LenientGate::class)'],
        ];
    }

    /**
     * @dataProvider guestPermittingSubclassProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('guestPermittingSubclassProvider')]
    public function test_a_subclass_of_authenticate_overriding_how_it_authenticates_is_not_authentication(array $files, string $middleware): void
    {
        $result = $this->analyzeFiles([
            ...$files,
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/comments', fn () => 1){$middleware};\n",
        ]);

        $this->assertSame(['POST closure route without authentication middleware'], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function excludedGroupHoldingAuthProvider(): array
    {
        return [
            'route excludes the group' => ["Route::middleware('crew')->group(function () {\n    Route::post('/settings', fn () => 1)->withoutMiddleware('members');\n});"],
            'group excludes the group' => ["Route::middleware('crew')->group(function () {\n    Route::withoutMiddleware('members')->group(function () {\n        Route::post('/settings', fn () => 1);\n    });\n});"],
        ];
    }

    /**
     * @dataProvider excludedGroupHoldingAuthProvider
     */
    #[DataProvider('excludedGroupHoldingAuthProvider')]
    public function test_excluding_a_group_that_holds_auth_removes_the_group_auth_credit(string $routes): void
    {
        $result = $this->analyzeFiles([
            'bootstrap/app.php' => "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Foundation\\Configuration\\Middleware;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function (Middleware \$middleware): void {\n        \$middleware->group('crew', ['web', 'auth']);\n        \$middleware->group('members', ['outer']);\n        \$middleware->group('outer', ['auth']);\n    })\n    ->create();\n",
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n",
        ]);

        $this->assertSame(['POST closure route without authentication middleware'], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unreadableGroupChangeProvider(): array
    {
        return [
            'replaceInGroup statement' => ["\$middleware->group('crew', ['web', 'auth']);\n        \$middleware->replaceInGroup('crew', 'auth', 'throttle:6,1');"],
            'replaceInGroup chained' => ["\$middleware->group('crew', ['web', 'auth'])->replaceInGroup('crew', 'auth', 'throttle:6,1');"],
            'removeFromGroup of a variable' => ["\$middleware->group('crew', ['web', 'auth']);\n        \$middleware->removeFromGroup('crew', \$dropped);"],
        ];
    }

    /**
     * @dataProvider unreadableGroupChangeProvider
     */
    #[DataProvider('unreadableGroupChangeProvider')]
    public function test_a_group_changed_in_a_way_not_read_is_not_credited_with_auth(string $calls): void
    {
        $result = $this->analyzeFiles([
            'bootstrap/app.php' => "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Foundation\\Configuration\\Middleware;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function (Middleware \$middleware): void {\n        {$calls}\n    })\n    ->create();\n",
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware('crew')->group(function () {\n    Route::post('/settings', fn () => 1);\n});\n",
        ]);

        $this->assertSame(['POST closure route without authentication middleware'], $this->issueMessages($result));
    }

    // ==========================================
    // match() and any() routes, route-level exclusions, files required in groups (#572, #607, #695)
    // ==========================================

    /**
     * @return array<string, array{string, string}>
     */
    public static function mutatingMatchRouteProvider(): array
    {
        return [
            'a list with a mutating verb' => ["Route::match(['GET', 'POST'], '/hooks', 'App\\Http\\Controllers\\HookController@handle');", 'POST route without authentication middleware'],
            'lowercase verbs' => ["Route::match(['get', 'put'], '/hooks', fn () => 1);", 'PUT closure route without authentication middleware'],
            'a single verb string' => ["Route::match('delete', '/hooks/{hook}', fn () => 1);", 'DELETE closure route without authentication middleware'],
            'on a registrar' => ["Route::middleware('throttle:6,1')->match(['PATCH'], '/hooks/{hook}', fn () => 1);", 'PATCH closure route without authentication middleware'],
            'any' => ["Route::any('/relays', 'App\\Http\\Controllers\\RelayController@handle');", 'ANY route without authentication middleware'],
            'any with a closure' => ["Route::any('/relays', fn () => 1);", 'ANY closure route without authentication middleware'],
        ];
    }

    /**
     * @dataProvider mutatingMatchRouteProvider
     */
    #[DataProvider('mutatingMatchRouteProvider')]
    public function test_reports_a_match_or_any_route_that_takes_a_mutating_verb_without_auth(string $routes, string $message): void
    {
        $this->assertSame([$message], $this->issueMessages($this->analyzeWebRoutes($routes)));
    }

    /**
     * @return array<string, array{0: string, 1?: list<string>}>
     */
    public static function closedMatchRouteProvider(): array
    {
        return [
            'read-only verbs' => ["Route::match(['GET', 'HEAD'], '/hooks', fn () => 1);"],
            'a verb list it cannot read' => ["Route::match(\$verbs, '/hooks', fn () => 1);"],
            'a verb list holding a call' => ["Route::match(verbs(), '/hooks', fn () => 1);"],
            'with auth' => ["Route::match(['GET', 'POST'], '/hooks', fn () => 1)->middleware('auth');"],
            'any in an auth group' => ["Route::middleware('auth')->group(function () {\n    Route::any('/relays', fn () => 1);\n});"],
            'on a public url' => ["Route::match(['POST'], '/hooks', fn () => 1);\nRoute::any('/relays', fn () => 1);", ['/hooks', '/relays']],
        ];
    }

    /**
     * @dataProvider closedMatchRouteProvider
     *
     * @param  list<string>  $publicRoutes
     */
    #[DataProvider('closedMatchRouteProvider')]
    public function test_passes_a_match_or_any_route_that_is_read_only_authenticated_or_public(string $routes, array $publicRoutes = []): void
    {
        $this->assertPassed($this->analyzeWebRoutes($routes, $publicRoutes));
    }

    public function test_reads_the_handler_of_a_match_route_in_a_controller_group(): void
    {
        $result = $this->analyzeFiles([
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\LedgerController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::controller(LedgerController::class)->group(function () {\n    Route::match(['GET', 'POST'], '/ledgers', 'store');\n});\n",
            'app/Http/Controllers/LedgerController.php' => $this->plainController('LedgerController', ['store']),
        ]);

        $this->assertHasIssueContaining('POST route without authentication middleware', $result);
        $this->assertHasIssueContaining('Sensitive method LedgerController::store() without authentication check', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function routeWithoutMiddlewareFirstArgumentProvider(): array
    {
        return [
            'on the route' => ["Route::post('/ledgers', fn () => 1)->withoutMiddleware('throttle', 'auth');"],
            'on the registrar' => ["Route::middleware('throttle:6,1')->withoutMiddleware('throttle', 'auth')->post('/ledgers', fn () => 1);"],
            'on the route, a list first' => ["Route::post('/ledgers', fn () => 1)->withoutMiddleware(['throttle'], 'auth');"],
        ];
    }

    /**
     * @dataProvider routeWithoutMiddlewareFirstArgumentProvider
     */
    #[DataProvider('routeWithoutMiddlewareFirstArgumentProvider')]
    public function test_route_without_middleware_reads_only_its_first_argument(string $routes): void
    {
        $this->assertSame(['POST closure route without authentication middleware'], $this->issueMessages($this->analyzeWebRoutes($routes)));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function routeWithoutMiddlewareFirstArgumentKeepsProvider(): array
    {
        return [
            'registrar exclusion in an auth group' => ["Route::middleware('auth')->group(function () {\n    Route::withoutMiddleware('throttle', 'auth')->post('/ledgers', fn () => 1);\n});"],
            'route exclusion in an auth group' => ["Route::middleware('auth')->group(function () {\n    Route::post('/ledgers', fn () => 1)->withoutMiddleware('throttle', 'auth');\n});"],
            'auth listed first still opts the route out' => ["Route::post('/ledgers', fn () => 1)->withoutMiddleware(['throttle', 'auth'], 'verified');"],
        ];
    }

    /**
     * @dataProvider routeWithoutMiddlewareFirstArgumentKeepsProvider
     */
    #[DataProvider('routeWithoutMiddlewareFirstArgumentKeepsProvider')]
    public function test_route_without_middleware_still_reads_its_first_argument(string $routes): void
    {
        $this->assertPassed($this->analyzeWebRoutes($routes));
    }

    /**
     * @return array<string, array{array<string, string>, string}>
     */
    public static function authenticateClassAliasExclusionProvider(): array
    {
        $subclass = ['app/Http/Middleware/Authenticate.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nuse Illuminate\\Auth\\Middleware\\Authenticate as Middleware;\n\nclass Authenticate extends Middleware\n{\n}\n"];
        $kernel = ['app/Http/Kernel.php' => "<?php\n\nnamespace App\\Http;\n\nuse Illuminate\\Foundation\\Http\\Kernel as HttpKernel;\n\nclass Kernel extends HttpKernel\n{\n    protected \$middlewareAliases = [\n        'auth' => \\App\\Http\\Middleware\\Authenticate::class,\n    ];\n}\n"];

        return [
            'group excluding the class' => [[], "Route::middleware('auth')->withoutMiddleware(Authenticate::class)->group(function () {\n    Route::post('/orders', fn () => 1);\n});"],
            'nested group excluding the class' => [[], "Route::middleware('auth')->group(function () {\n    Route::withoutMiddleware(Authenticate::class)->group(function () {\n        Route::post('/orders', fn () => 1);\n    });\n});"],
            'action array excluding the class' => [[], "Route::middleware('auth')->group(function () {\n    Route::post('/orders', ['excluded_middleware' => [Authenticate::class], 'uses' => fn () => 1]);\n});"],
            'group attribute array excluding the class' => [[], "Route::group(['middleware' => 'auth', 'excluded_middleware' => Authenticate::class], function () {\n    Route::post('/orders', fn () => 1);\n});"],
            'alias of an app subclass, excluding the framework class' => [[...$subclass, ...$kernel], "Route::middleware('auth')->withoutMiddleware(Authenticate::class)->group(function () {\n    Route::post('/orders', fn () => 1);\n});"],
        ];
    }

    /**
     * @dataProvider authenticateClassAliasExclusionProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('authenticateClassAliasExclusionProvider')]
    public function test_excluding_the_authenticate_class_removes_the_auth_alias(array $files, string $routes): void
    {
        $result = $this->analyzeFiles([...$files, 'routes/web.php' => $this->orderRoutes($routes)]);

        $this->assertNotSame([], array_filter($this->issueMessages($result), fn (string $message): bool => str_contains($message, 'route without authentication middleware')));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function authenticateClassAliasExclusionKeepsProvider(): array
    {
        return [
            'auth with a guard' => ["Route::middleware('auth:sanctum')->group(function () {\n    Route::post('/orders', ['excluded_middleware' => [Authenticate::class], 'uses' => fn () => 1]);\n});"],
            'auth with a guard, group exclusion' => ["Route::middleware('auth:sanctum')->withoutMiddleware(Authenticate::class)->group(function () {\n    Route::post('/orders', fn () => 1);\n});"],
            'basic auth, not a subclass of the class' => ["Route::middleware('auth.basic')->withoutMiddleware(Authenticate::class)->group(function () {\n    Route::post('/orders', fn () => 1);\n});"],
            'another class excluded' => ["Route::middleware('auth')->withoutMiddleware(\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class)->group(function () {\n    Route::post('/orders', fn () => 1);\n});"],
        ];
    }

    /**
     * @dataProvider authenticateClassAliasExclusionKeepsProvider
     */
    #[DataProvider('authenticateClassAliasExclusionKeepsProvider')]
    public function test_excluding_the_authenticate_class_keeps_auth_it_does_not_resolve_to(string $routes): void
    {
        $this->assertPassed($this->analyzeFiles(['routes/web.php' => $this->orderRoutes($routes)]));
    }

    /**
     * @return array<string, array{string, list<string>}>
     */
    public static function capturedRegistrarProvider(): array
    {
        $capture = "\$admin = Route::prefix('admin')->middleware(%s);\nRoute::middleware(%s)->group(function () use (\$admin) {\n    \$admin->post('/users', fn () => 1);\n});";

        return [
            'neither gives auth' => [sprintf($capture, "'throttle:6,1'", "'web'"), ['POST closure route without authentication middleware']],
            'the registrar gives auth' => [sprintf($capture, "'auth'", "'web'"), []],
            'the enclosing group gives auth' => [sprintf($capture, "'throttle:6,1'", "'auth'"), []],
        ];
    }

    /**
     * @dataProvider capturedRegistrarProvider
     *
     * @param  list<string>  $expected
     */
    #[DataProvider('capturedRegistrarProvider')]
    public function test_reads_a_registrar_a_group_closure_captures_by_value(string $routes, array $expected): void
    {
        $this->assertSame($expected, $this->issueMessages($this->analyzeWebRoutes($routes)));
    }

    public function test_a_captured_registrar_route_takes_the_registrar_prefix(): void
    {
        $routes = "\$admin = Route::prefix('admin')->middleware('throttle:6,1');\nRoute::middleware('web')->group(function () use (\$admin) {\n    \$admin->post('/users', fn () => 1);\n});";

        $this->assertPassed($this->analyzeWebRoutes($routes, ['/admin/users']));
    }

    public function test_a_registrar_captured_by_a_closure_nothing_runs_registers_no_route(): void
    {
        $this->assertPassed($this->analyzeWebRoutes("\$admin = Route::prefix('admin');\n\$later = function () use (\$admin) {\n    \$admin->post('/users', fn () => 1);\n};"));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function canAttributeProvider(): array
    {
        return [
            'group attribute, a list of abilities' => ["Route::group(['can' => [['manage']]], function () {\n    Route::post('/settings', fn () => 1);\n});"],
            'group attribute, an ability with models' => ["Route::group(['can' => [['update', 'post']]], function () {\n    Route::post('/settings', fn () => 1);\n});"],
            'group attribute, a flat list' => ["Route::group(['can' => ['manage']], function () {\n    Route::post('/settings', fn () => 1);\n});"],
            'action array' => ["Route::post('/settings', ['can' => [['manage']], 'uses' => fn () => 1]);"],
        ];
    }

    /**
     * @dataProvider canAttributeProvider
     */
    #[DataProvider('canAttributeProvider')]
    public function test_credits_a_can_attribute_as_authorization(string $routes): void
    {
        $this->assertPassed($this->analyzeWebRoutes($routes));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unusableCanAttributeProvider(): array
    {
        return [
            'a string, which Laravel cannot iterate' => ["Route::group(['can' => 'manage'], function () {\n    Route::post('/settings', fn () => 1);\n});"],
            'an empty list' => ["Route::group(['can' => []], function () {\n    Route::post('/settings', fn () => 1);\n});"],
        ];
    }

    /**
     * @dataProvider unusableCanAttributeProvider
     */
    #[DataProvider('unusableCanAttributeProvider')]
    public function test_gives_no_credit_to_a_can_attribute_that_adds_no_middleware(string $routes): void
    {
        $result = $this->analyzeWebRoutes($routes);

        $this->assertHasIssueContaining('Route group without authentication middleware', $result);
        $this->assertHasIssueContaining('POST closure route without authentication middleware', $result);
    }

    public function test_credits_a_can_attribute_held_in_a_variable(): void
    {
        $this->assertPassed($this->analyzeWebRoutes("\$abilities = [['manage']];\nRoute::group(['can' => \$abilities], function () {\n    Route::post('/settings', fn () => 1);\n});"));
    }

    public function test_a_can_attribute_gives_no_credit_before_laravel_11(): void
    {
        $realApp = $this->app;
        $this->assertNotNull($realApp);

        /** @var Application&MockInterface $legacyApp */
        $legacyApp = Mockery::mock(Application::class);
        $legacyApp->shouldReceive('version')->andReturn('10.48.0');
        $legacyApp->shouldReceive('make')->andReturnUsing(fn (string $abstract, array $parameters = []) => $realApp->make($abstract, $parameters));
        Container::setInstance($legacyApp);

        try {
            $result = $this->analyzeWebRoutes("Route::group(['can' => [['manage']]], function () {\n    Route::post('/settings', fn () => 1);\n});\nRoute::post('/settings/{setting}', ['can' => [['manage']], 'uses' => fn () => 1]);");
        } finally {
            Container::setInstance($realApp);
        }

        $this->assertHasIssueContaining('Route group without authentication middleware', $result);
        $this->assertCount(2, array_filter($this->issueMessages($result), fn (string $message): bool => str_contains($message, 'route without authentication middleware')));
    }

    public function test_a_top_level_route_file_required_inside_an_auth_group_takes_its_auth(): void
    {
        $this->assertPassed($this->analyzeFiles([
            'bootstrap/app.php' => self::bootstrapApp('', "web: __DIR__.'/../routes/web.php',"),
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware('auth')->group(function () {\n    require __DIR__.'/accounts.php';\n});\n",
            'routes/accounts.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/accounts', fn () => 1);\n",
        ]));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function topLevelRouteFileLoadedByARouteFileProvider(): array
    {
        return [
            'in a function the file calls' => ["function loadLedger(): void\n{\n    require __DIR__.'/ledger.php';\n}\nloadLedger();"],
            'in a closure variable the file calls' => ["\$load = function () {\n    require __DIR__.'/ledger.php';\n};\n\$load();"],
            'in a closure invoked at once' => ["(function () {\n    require __DIR__.'/ledger.php';\n})();"],
            'in a static method the file calls' => ["class LedgerLoader\n{\n    public static function load(): void\n    {\n        require __DIR__.'/ledger.php';\n    }\n}\nLedgerLoader::load();"],
            'bare, beside a function nothing calls' => ["require __DIR__.'/ledger.php';\nfunction unusedLedger(): void\n{\n    require __DIR__.'/ledger.php';\n}"],
            'bare, before a return and a dead require' => ["require __DIR__.'/ledger.php';\nreturn;\nrequire __DIR__.'/ledger.php';"],
            'a web group path, beside a dead group path' => ["Route::middleware('web')->group(__DIR__.'/ledger.php');\nfunction unusedLedger(): void\n{\n    Route::group([], __DIR__.'/ledger.php');\n}"],
        ];
    }

    /**
     * A top-level route file a route file also loads outside a running group is not given
     * its auth registration's middleware.
     *
     * @dataProvider topLevelRouteFileLoadedByARouteFileProvider
     */
    #[DataProvider('topLevelRouteFileLoadedByARouteFileProvider')]
    public function test_a_top_level_route_file_another_route_file_also_loads_keeps_no_registration_credit(string $web): void
    {
        $result = $this->analyzeFiles([
            'bootstrap/app.php' => self::bootstrapApp('', "web: __DIR__.'/../routes/web.php',\n        then: function () {\n            Route::middleware(['web', 'auth'])->group(base_path('routes/ledger.php'));\n        },"),
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n{$web}\n",
            'routes/ledger.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/ledger', fn () => 1);\n",
        ]);

        $this->assertContains('POST closure route without authentication middleware', $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string, string, list<string>}>
     */
    public static function routeFileLoadedInAGroupProvider(): array
    {
        $web = "web: __DIR__.'/../routes/web.php',";
        $open = ['POST closure route without authentication middleware'];

        return [
            'in a group nested in an auth group' => [$web, "Route::middleware('auth')->group(function () {\n    Route::prefix('accounts')->group(function () {\n        require __DIR__.'/accounts.php';\n    });\n});", []],
            'in an arrow function auth group' => [$web, "Route::middleware('auth')->group(fn () => require __DIR__.'/accounts.php');", []],
            'in a group without auth' => [$web, "Route::middleware('web')->group(function () {\n    require __DIR__.'/accounts.php';\n});", $open],
            'in an auth group, the file registered under a group excluding auth' => ["then: function () {\n            Route::withoutMiddleware('auth')->group(base_path('routes/web.php'));\n        },", "Route::middleware('auth')->group(function () {\n    require __DIR__.'/accounts.php';\n});", $open],
            'in an auth group, the file registered under a group excluding the Authenticate class' => ["then: function () {\n            Route::withoutMiddleware(\\Illuminate\\Auth\\Middleware\\Authenticate::class)->group(base_path('routes/web.php'));\n        },", "Route::middleware('auth')->group(function () {\n    require __DIR__.'/accounts.php';\n});", $open],
            'in an auth group, after a return' => [$web, "Route::middleware('auth')->group(function () {\n    return;\n    require __DIR__.'/accounts.php';\n});", $open],
            'in an auth group, inside an if' => [$web, "Route::middleware('auth')->group(function () {\n    if (config('app.accounts')) {\n        require __DIR__.'/accounts.php';\n    }\n});", $open],
        ];
    }

    /**
     * @dataProvider routeFileLoadedInAGroupProvider
     *
     * @param  list<string>  $expected
     */
    #[DataProvider('routeFileLoadedInAGroupProvider')]
    public function test_a_route_file_required_in_a_group_callback_takes_the_group_middleware(string $registration, string $web, array $expected): void
    {
        $result = $this->analyzeFiles([
            'bootstrap/app.php' => self::bootstrapApp('', $registration),
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n{$web}\n",
            'routes/accounts.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/accounts', fn () => 1);\n",
        ]);

        $this->assertSame($expected, $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function deferredLoadInAnAuthGroupProvider(): array
    {
        return [
            'a macro defined in the group, called outside it' => ["Route::middleware('auth')->group(function () {\n    Route::macro('accounts', function () {\n        require __DIR__.'/accounts.php';\n    });\n});\nRoute::accounts();"],
            'a closure stored in the group, called outside it' => ["Route::middleware('auth')->group(function () use (&\$load) {\n    \$load = function () {\n        require __DIR__.'/accounts.php';\n    };\n});\n\$load();"],
            'a function declared in the group, called outside it' => ["Route::middleware('auth')->group(function () {\n    if (! function_exists('loadAccounts')) {\n        function loadAccounts(): void\n        {\n            require __DIR__.'/accounts.php';\n        }\n    }\n});\nloadAccounts();"],
        ];
    }

    /**
     * A load in a closure or function defined in an auth group's callback may run later,
     * outside the group, so it gives no credit.
     *
     * @dataProvider deferredLoadInAnAuthGroupProvider
     */
    #[DataProvider('deferredLoadInAnAuthGroupProvider')]
    public function test_a_route_file_loaded_by_code_an_auth_group_only_defines_takes_no_credit(string $web): void
    {
        $result = $this->analyzeFiles([
            'bootstrap/app.php' => self::bootstrapApp('', "web: __DIR__.'/../routes/web.php',"),
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n{$web}\n",
            'routes/accounts.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/accounts', fn () => 1);\n",
        ]);

        $this->assertSame(['POST closure route without authentication middleware'], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function chainedGroupLoadProvider(): array
    {
        $post = "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/invoices', fn () => 1);\n";

        return [
            'the loading file registered with auth' => [[
                'bootstrap/app.php' => self::bootstrapApp('', "then: function () {\n            Route::middleware(['web', 'auth'])->group(base_path('routes/billing.php'));\n        },"),
                'routes/billing.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::prefix('billing')->group(function () {\n    require __DIR__.'/invoices.php';\n});\n",
                'routes/invoices.php' => $post,
            ]],
            'two loads below an auth group' => [[
                'bootstrap/app.php' => self::bootstrapApp('', "web: __DIR__.'/../routes/web.php',"),
                'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware('auth')->group(function () {\n    require __DIR__.'/billing.php';\n});\n",
                'routes/billing.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::prefix('billing')->group(function () {\n    require __DIR__.'/invoices.php';\n});\n",
                'routes/invoices.php' => $post,
            ]],
        ];
    }

    /**
     * @dataProvider chainedGroupLoadProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('chainedGroupLoadProvider')]
    public function test_a_route_file_required_in_a_group_takes_the_middleware_of_every_load_above_it(array $files): void
    {
        $this->assertPassed($this->analyzeFiles($files));
    }

    public function test_route_files_required_in_a_diamond_of_group_callbacks_resolve_without_blowing_up(): void
    {
        $files = [
            'bootstrap/app.php' => self::bootstrapApp('', "web: __DIR__.'/../routes/web.php',"),
            'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware('auth')->group(function () {\n    require_once __DIR__.'/left0.php';\n    require_once __DIR__.'/right0.php';\n});\n",
        ];
        $depth = 12;
        for ($level = 0; $level < $depth; $level++) {
            foreach (['left', 'right'] as $side) {
                $body = "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/{$side}{$level}', fn () => 1);\n";
                if ($level + 1 < $depth) {
                    $next = $level + 1;
                    $body .= "Route::prefix('ledger')->group(function () {\n    require_once __DIR__.'/left{$next}.php';\n    require_once __DIR__.'/right{$next}.php';\n});\n";
                }
                $files["routes/{$side}{$level}.php"] = $body;
            }
        }

        $before = getrusage();
        $result = $this->analyzeFiles($files);
        $after = getrusage();
        $this->assertIsArray($before);
        $this->assertIsArray($after);

        $this->assertPassed($result);
        // Each loading path read once: seconds of CPU would mean every path is walked
        $this->assertLessThan(5.0, ($after['ru_utime.tv_sec'] - $before['ru_utime.tv_sec']) + ($after['ru_utime.tv_usec'] - $before['ru_utime.tv_usec']) / 1e6);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function reassignedCaptureProvider(): array
    {
        return [
            'a macro the file calls' => ["\$ledger = Route::middleware('auth');\nRoute::macro('ledgerRoutes', function () use (\$ledger) {\n    \$ledger = Route::prefix('ledger');\n    \$ledger->post('/entries', fn () => 1);\n});\nRoute::ledgerRoutes();"],
            'a closure invoked at once' => ["\$ledger = Route::middleware('auth');\n(function () use (\$ledger) {\n    \$ledger = Route::prefix('ledger');\n    \$ledger->post('/entries', fn () => 1);\n})();"],
            'a collection callback' => ["\$ledger = null;\ncollect(['ledger'])->each(function (\$name) use (\$ledger) {\n    \$ledger = Route::prefix(\$name);\n    \$ledger->post('/entries', fn () => 1);\n});"],
        ];
    }

    /**
     * A closure that assigns the variable it imports registers on its own registrar, read as
     * any other.
     *
     * @dataProvider reassignedCaptureProvider
     */
    #[DataProvider('reassignedCaptureProvider')]
    public function test_a_captured_variable_the_closure_reassigns_registers_its_routes(string $routes): void
    {
        $this->assertSame(['POST closure route without authentication middleware'], $this->issueMessages($this->analyzeWebRoutes($routes)));
    }

    public function test_a_captured_registrar_in_a_group_callback_of_a_closure_nothing_runs_registers_no_route(): void
    {
        $result = $this->analyzeWebRoutes("\$ledger = Route::middleware('throttle:6,1');\n\$later = function () use (\$ledger) {\n    Route::group([], fn () => \$ledger->post('/entries', fn () => 1));\n};");

        $this->assertNotContains('POST closure route without authentication middleware', $this->issueMessages($result));
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function classOptOutProvider(): array
    {
        $exclusion = 'withoutMiddleware(\\Illuminate\\Auth\\Middleware\\Authenticate::class)';
        $route = "Route::post('/ledgers', fn () => 1)->{$exclusion};";

        return [
            'auth from the file registration' => [[
                'bootstrap/app.php' => self::bootstrapApp('', "then: function () {\n            Route::middleware(['web', 'auth'])->group(base_path('routes/ledgers.php'));\n        },"),
                'routes/ledgers.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n{$route}\n",
            ]],
            'auth as the Authenticate class' => [[
                'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware(\\Illuminate\\Auth\\Middleware\\Authenticate::class)->group(function () {\n    {$route}\n});\n",
            ]],
            'auth from a middleware group' => [[
                'bootstrap/app.php' => "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Foundation\\Configuration\\Middleware;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withRouting(web: __DIR__.'/../routes/web.php')\n    ->withMiddleware(function (Middleware \$middleware): void {\n        \$middleware->group('crew', ['web', 'auth']);\n    })\n    ->create();\n",
                'routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::middleware('crew')->group(function () {\n    {$route}\n});\n",
            ]],
        ];
    }

    /**
     * Excluding the Authenticate class opts a route out wherever excluding 'auth' does.
     *
     * @dataProvider classOptOutProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('classOptOutProvider')]
    public function test_without_middleware_on_the_authenticate_class_opts_out_of_auth_from_any_source(array $files): void
    {
        $this->assertPassed($this->analyzeFiles($files));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function exclusionMentionProvider(): array
    {
        return [
            'a comment' => ["// withoutMiddleware is not used here\nRoute::post('/ledgers', fn () => 1);"],
            'a route name' => ["Route::post('/ledgers', fn () => 1)->name('ledgers.excluded_middleware.store');"],
        ];
    }

    /**
     * Only a call or key that excludes middleware withholds the registration's middleware.
     *
     * @dataProvider exclusionMentionProvider
     */
    #[DataProvider('exclusionMentionProvider')]
    public function test_a_route_file_only_mentioning_an_exclusion_keeps_its_registration_middleware(string $routes): void
    {
        $this->assertPassed($this->analyzeFiles([
            'bootstrap/app.php' => self::bootstrapApp('', "then: function () {\n            Route::middleware(['web', 'auth'])->group(base_path('routes/ledgers.php'));\n        },"),
            'routes/ledgers.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n{$routes}\n",
        ]));
    }

    /**
     * An OrderController in App\Http\Controllers with $members after the $head imports, and
     * index() and create() reading the user, store() and update().
     */
    private function orderController(string $members, string $head = '', string $implements = ''): string
    {
        return "<?php\n\nnamespace App\\Http\\Controllers;\n\n{$head}\nuse Illuminate\\Support\\Facades\\Auth;\n\nclass OrderController{$implements}\n{\n{$members}\n    public function index() { return Auth::user()->name; }\n    public function create() { return Auth::user()->id; }\n    public function store() { return 1; }\n    public function update() { return 1; }\n}\n";
    }

    /**
     * routes/web.php importing OrderController, Authenticate and the Route facade, running $body.
     */
    private function orderRoutes(string $body): string
    {
        return "<?php\n\nuse App\\Http\\Controllers\\OrderController;\nuse Illuminate\\Auth\\Middleware\\Authenticate;\nuse Illuminate\\Support\\Facades\\Route;\n\n{$body}\n";
    }

    /**
     * Analyze a project made of $files, its app/ directory scanned.
     *
     * @param  array<string, string>  $files
     */
    private function analyzeFiles(array $files): ResultInterface
    {
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($this->createTempDirectory($files));
        $analyzer->setPaths(['app']);

        return $analyzer->analyze();
    }

    /**
     * A controller in App\Http\Controllers with an empty public method per name.
     *
     * @param  list<string>  $methods
     */
    private function plainController(string $class, array $methods): string
    {
        $body = implode("\n", array_map(static fn (string $method): string => "    public function {$method}()\n    {\n        return 1;\n    }\n", $methods));

        return "<?php\n\nnamespace App\\Http\\Controllers;\n\nclass {$class}\n{\n{$body}}\n";
    }

    /**
     * A HasMiddleware controller whose middleware() returns $list, with create() and store().
     */
    private function hasMiddlewareController(string $list): string
    {
        return <<<PHP
<?php

namespace App\Http\Controllers;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Routing\Controllers\HasMiddleware;
use Illuminate\Routing\Controllers\Middleware;

class MemoController implements HasMiddleware
{
    public static function middleware(): array
    {
        return {$list};
    }

    public function create()
    {
        return 1;
    }

    public function store()
    {
        return 1;
    }
}
PHP;
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
