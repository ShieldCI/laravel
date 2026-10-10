<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\Security\LoginThrottlingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class LoginThrottlingAnalyzerTest extends AnalyzerTestCase
{
    /** The limiters config fortify:install publishes */
    private const FORTIFY_CONFIG = "<?php\n\nreturn ['limiters' => ['login' => 'login', 'two-factor' => 'two-factor']];\n";

    protected function createAnalyzer(): AnalyzerInterface
    {
        return new LoginThrottlingAnalyzer($this->parser);
    }

    public function test_passes_with_throttle_in_web_middleware_group(): void
    {
        $kernelCode = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Routing\Middleware\ThrottleRequests;

class Kernel extends HttpKernel
{
    protected $middlewareGroups = [
        'web' => [
            ThrottleRequests::class.':60,1',
        ],
    ];
}
PHP;

        $routeCode = <<<'PHP'
<?php

Route::post('/login', [LoginController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernelCode,
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        // Should pass - throttle is in web middleware group
        $this->assertPassed($result);
    }

    public function test_passes_with_throttle_string_in_web_middleware_group(): void
    {
        $kernelCode = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middlewareGroups = [
        'web' => [
            'throttle:60,1',
        ],
    ];
}
PHP;

        $routeCode = <<<'PHP'
<?php

Route::post('/login', [LoginController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernelCode,
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        // Should pass - throttle string is in web middleware group
        $this->assertPassed($result);
    }

    public function test_passes_with_rate_limiter_usage(): void
    {
        $serviceProvider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\Facades\RateLimiter;

class RouteServiceProvider
{
    public function boot()
    {
        RateLimiter::for('login', function ($request) {
            return Limit::perMinute(5);
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/RouteServiceProvider.php' => $serviceProvider,
            'routes/web.php' => '<?php // empty routes',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_no_login_routes_found(): void
    {
        $tempDir = $this->createTempDirectory([
            'routes/web.php' => '<?php // empty routes',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_login_route_has_no_throttle(): void
    {
        $routeCode = <<<'PHP'
<?php

use App\Http\Controllers\LoginController;

Route::post('/login', [LoginController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Login route "/login" lacks rate limiting', $result);
    }

    public function test_passes_when_login_route_has_throttle_middleware(): void
    {
        $routeCode = <<<'PHP'
<?php

use App\Http\Controllers\LoginController;

Route::post('/login', [LoginController::class, 'login'])
     ->middleware('throttle:5,1');
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_login_route_has_throttle_in_array(): void
    {
        $routeCode = <<<'PHP'
<?php

Route::post('/login', [LoginController::class, 'login'])
     ->middleware(['auth', 'throttle:5,1']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_get_login_form_route(): void
    {
        // A GET login route renders the form; credentials arrive on the POST.
        $routeCode = <<<'PHP'
<?php

Route::get('/login', [LoginController::class, 'showLoginForm']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_auth_route_variant(): void
    {
        $routeCode = <<<'PHP'
<?php

Route::post('/auth/login', [AuthController::class, 'handle']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('/auth/login', $result);
    }

    public function test_fails_when_auth_controller_lacks_throttling(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        // Login logic without throttling
        return Auth::attempt($request->only('email', 'password'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/LoginController.php' => $controllerCode,
            'routes/web.php' => '<?php // empty routes',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('lacks rate limiting', $result);
    }

    public function test_passes_when_controller_uses_throttles_logins_trait(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Foundation\Auth\ThrottlesLogins;
use Illuminate\Http\Request;

class LoginController extends Controller
{
    use ThrottlesLogins;

    public function login(Request $request)
    {
        return $this->attemptLogin($request);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/Auth/LoginController.php' => $controllerCode,
            'routes/web.php' => '<?php // empty routes',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_controller_uses_authenticates_users_trait(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Foundation\Auth\AuthenticatesUsers;

class LoginController extends Controller
{
    use AuthenticatesUsers;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/Auth/LoginController.php' => $controllerCode,
            'routes/web.php' => '<?php // empty routes',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_controller_uses_rate_limiter(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\RateLimiter;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        RateLimiter::attempt($key, $maxAttempts, function() {
            // Login logic
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/LoginController.php' => $controllerCode,
            'routes/web.php' => '<?php // empty routes',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_multiple_login_methods_without_throttling(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController extends Controller
{
    public function login() {}

    public function authenticate() {}

    public function postLogin() {}

    public function attempt() {}
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AuthController.php' => $controllerCode,
            'routes/web.php' => '<?php // empty routes',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(4, $result);
    }

    public function test_passes_with_throttle_in_laravel_11_bootstrap(): void
    {
        $bootstrapCode = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->throttleApi();
    })
    ->create();
PHP;

        // A real API login route makes this pass contingent on throttleApi()
        // detection: the global throttle:api it injects must suppress the finding.
        $routeCode = <<<'PHP'
<?php

Route::post('/login', [ApiAuthController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapCode,
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_throttle_api_with_custom_limiter_detected(): void
    {
        $bootstrapCode = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->throttleApi('login');
    })
    ->create();
PHP;

        $routeCode = <<<'PHP'
<?php

Route::post('/login', [ApiAuthController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapCode,
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_throttle_with_redis_alone_does_not_count_as_api_throttle(): void
    {
        // throttleWithRedis() only swaps the throttle driver; it does not enable
        // throttling, so an unthrottled API login route must still be flagged.
        $bootstrapCode = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->throttleWithRedis();
    })
    ->create();
PHP;

        $routeCode = <<<'PHP'
<?php

Route::post('/login', [ApiAuthController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapCode,
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('/login', $result);
    }

    public function test_passes_with_fluent_group_array_throttle(): void
    {
        // The exact fluent form from issue #309: throttle:api in the group's
        // middleware array, applied via Route::middleware([...])->group(...).
        $routeCode = <<<'PHP'
<?php

Route::middleware(['auth:sanctum', 'throttle:api'])->group(function () {
    Route::post('/login', [ApiAuthController::class, 'login']);
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_fluent_group_throttle_login_far_from_opener(): void
    {
        // Login route sits more than 3 lines below the group opener, so the old
        // ±3-line look-back could not see the throttle. AST range covers it.
        $routeCode = <<<'PHP'
<?php

Route::middleware('throttle:5,1')->group(function () {
    Route::get('/a', [AController::class, 'index']);
    Route::get('/b', [BController::class, 'index']);
    Route::get('/c', [CController::class, 'index']);
    Route::get('/d', [DController::class, 'index']);
    Route::post('/login', [LoginController::class, 'login']);
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fluent_group_without_throttle_still_flags_login(): void
    {
        // A fluent group carrying no throttle must not be treated as covered.
        $routeCode = <<<'PHP'
<?php

Route::middleware('auth')->prefix('acct')->group(function () {
    Route::post('/login', [LoginController::class, 'login']);
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('login', $result);
    }

    public function test_nested_throttle_group_does_not_leak_coverage(): void
    {
        // The login route is after the inner group closes but still inside the
        // outer throttle group; overlapping AST ranges keep it covered.
        $routeCode = <<<'PHP'
<?php

Route::middleware('throttle:5,1')->group(function () {
    Route::middleware('throttle:5,1')->prefix('inner')->group(function () {
        Route::get('/ping', [PingController::class, 'index']);
    });

    Route::post('/login', [LoginController::class, 'login']);
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fluent_group_with_path_argument_does_not_leak(): void
    {
        // ->group(base_path(...)) opens no closure, so it must not mark the
        // following top-level login route as covered.
        $routeCode = <<<'PHP'
<?php

Route::middleware('throttle:5,1')->group(base_path('routes/inner.php'));

Route::post('/login', [LoginController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('login', $result);
    }

    public function test_skips_auth_logout_endpoint(): void
    {
        // Matches only on the broad 'auth' substring; logout is token revocation,
        // not a credential brute-force surface.
        $routeCode = <<<'PHP'
<?php

Route::post('/auth/logout', [AuthController::class, 'logout']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_auth_me_endpoint(): void
    {
        $routeCode = <<<'PHP'
<?php

Route::get('/auth/me', [AuthController::class, 'me']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_auth_signout_endpoint(): void
    {
        $routeCode = <<<'PHP'
<?php

Route::post('/auth/signout', [AuthController::class, 'signout']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_flags_auth_login_despite_denylist(): void
    {
        // 'login' is an explicit credential keyword, so the denylist must not
        // suppress it even though it sits under the /auth prefix.
        $routeCode = <<<'PHP'
<?php

Route::post('/auth/login', [AuthController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('/auth/login', $result);
    }

    public function test_still_flags_token_refresh_endpoint(): void
    {
        // 'refresh' is intentionally NOT on the denylist: a token-refresh endpoint
        // accepts a secret and mints tokens, so throttling it is warranted.
        $routeCode = <<<'PHP'
<?php

Route::post('/token/refresh', [TokenController::class, 'refresh']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('token/refresh', $result);
    }

    public function test_issue_309_repro_global_throttle_api_clears_all(): void
    {
        // Exact reproduction from issue #309: a global throttle:api (via
        // throttleApi()) covers every API route, and logout/me are not
        // credential surfaces — so there should be no findings.
        $bootstrapCode = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->throttleApi();
    })
    ->create();
PHP;

        $routeCode = <<<'PHP'
<?php

Route::middleware('auth:sanctum')->group(function () {
    Route::post('auth/logout', [StaffLoginController::class, 'logout']);
    Route::get('auth/me', MeController::class);
});
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapCode,
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_issue_309_repro_without_global_throttle_flags_only_login(): void
    {
        // No global throttle and an unthrottled auth:sanctum group: logout/me are
        // skipped as non-credential endpoints, but the genuine login route is
        // still flagged. Exactly one finding.
        $routeCode = <<<'PHP'
<?php

Route::middleware('auth:sanctum')->group(function () {
    Route::post('auth/logout', [StaffLoginController::class, 'logout']);
    Route::get('auth/me', MeController::class);
    Route::post('login', [StaffLoginController::class, 'login']);
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('login', $result);
    }

    public function test_handles_invalid_php_in_route_file(): void
    {
        $routeCode = 'invalid php {{{';

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should pass gracefully (not crash)
        $this->assertPassed($result);
    }

    public function test_passes_when_routes_directory_missing(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/HomeController.php' => '<?php',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // shouldRun() returns false
        $this->assertSkipped($result);
    }

    public function test_handles_controller_parse_failure(): void
    {
        $controllerCode = 'invalid php {{{';

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/LoginController.php' => $controllerCode,
            'routes/web.php' => '<?php // valid but empty',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        // Should pass gracefully (catches throwable)
        $this->assertPassed($result);
    }

    public function test_detects_api_login_routes(): void
    {
        $routeCode = <<<'PHP'
<?php

// API routes also need throttling to prevent brute force
Route::post('/auth/login', [ApiAuthController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should fail - API login route without throttle
        $this->assertFailed($result);
        $this->assertHasIssueContaining('auth/login', $result);
    }

    public function test_detects_signin_route_variant(): void
    {
        $routeCode = <<<'PHP'
<?php

Route::post('/signin', [AuthController::class, 'signIn']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('/signin', $result);
    }

    public function test_passes_with_throttle_requests_class_reference(): void
    {
        $routeCode = <<<'PHP'
<?php

use Illuminate\Routing\Middleware\ThrottleRequests;

Route::post('/login', [LoginController::class, 'login'])
     ->middleware(ThrottleRequests::class);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_route_group_throttle(): void
    {
        $routeCode = <<<'PHP'
<?php

Route::group(['middleware' => 'throttle:5,1'], function () {
    Route::post('/login', [LoginController::class, 'login']);
    Route::post('/authenticate', [AuthController::class, 'authenticate']);
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_route_group_without_throttle(): void
    {
        $routeCode = <<<'PHP'
<?php

Route::group(['prefix' => 'auth'], function () {
    Route::post('/login', [LoginController::class, 'login']);
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('login', $result);
    }

    public function test_passes_with_middleware_before_route_method(): void
    {
        $routeCode = <<<'PHP'
<?php

Route::middleware('throttle:5,1')->post('/login', [LoginController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_auth_routes_and_throttle(): void
    {
        $routeCode = <<<'PHP'
<?php

Auth::routes();

Route::middleware('throttle:5,1')->group(function () {
    Auth::routes();
});
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // First Auth::routes() should fail (no throttle)
        // Second Auth::routes() should pass (in throttle group)
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Auth::routes()', $result);
    }

    public function test_detects_fortify_without_throttle(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "laravel/fortify",
            "version": "1.0.0"
        }
    ]
}
JSON;

        $fortifyConfig = <<<'PHP'
<?php

use Laravel\Fortify\Actions\AttemptToAuthenticate;
use Laravel\Fortify\Actions\PrepareAuthenticatedSession;

return [
    'features' => [
        'registration' => true,
    ],
    'pipelines' => [
        'login' => [AttemptToAuthenticate::class, PrepareAuthenticatedSession::class],
    ],
];
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
            'config/fortify.php' => $fortifyConfig,
            'routes/web.php' => '<?php // empty',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes', 'config']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Fortify', $result);
    }

    public function test_passes_with_fortify_custom_rate_limiter(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "laravel/fortify",
            "version": "1.0.0"
        }
    ]
}
JSON;

        $providerCode = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;

class FortifyServiceProvider
{
    public function boot()
    {
        RateLimiter::for('login', function () {
            return Limit::perMinute(5);
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
            'app/Providers/FortifyServiceProvider.php' => $providerCode,
            'config/fortify.php' => self::FORTIFY_CONFIG,
            'routes/web.php' => '<?php // empty',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes', 'app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ast_based_detection_finds_rate_limiter_in_nested_auth_method(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\RateLimiter;

class AuthController
{
    public function login()
    {
        // Complex nested structure that might confuse brace-depth tracking
        $validator = function () {
            if (true) {
                return ['error' => 'Invalid {braces} in string'];
            }
        };

        // RateLimiter usage nested deep in the method
        if (RateLimiter::tooManyAttempts('login:'.$request->ip(), 5)) {
            return response()->json(['error' => 'Too many attempts'], 429);
        }

        return $this->attemptLogin();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AuthController.php' => $controllerCode,
            'routes/web.php' => '<?php // empty',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        // Should pass because AST detects RateLimiter usage in login method
        $this->assertPassed($result);
    }

    public function test_breeze_with_default_fortify_passes(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "laravel/breeze",
            "version": "1.0.0"
        },
        {
            "name": "laravel/fortify",
            "version": "1.0.0"
        }
    ]
}
JSON;

        // Fortify's own routes with the config fortify:install publishes (no custom routes/auth.php)
        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
            'config/fortify.php' => self::FORTIFY_CONFIG,
            'routes/web.php' => '<?php // empty - uses Fortify routes',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should pass - the published config throttles Fortify's login route with the 'login' limiter
        $this->assertPassed($result);
    }

    public function test_breeze_custom_unthrottled_login_route_is_reported_once_by_the_route_check(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "laravel/breeze",
            "version": "1.0.0"
        }
    ]
}
JSON;

        $authRoutes = <<<'PHP'
<?php

use App\Http\Controllers\Auth\LoginController;

Route::post('/login', [LoginController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
            'routes/auth.php' => $authRoutes,
            'routes/web.php' => '<?php // empty',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // routes/auth.php is a route file like any other: the route check reports the
        // login route, and no Breeze-specific finding repeats it for the whole file
        $this->assertFailed($result);
        $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_passes_with_laravel_11_throttle_in_bootstrap(): void
    {
        $bootstrapCode = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Routing\Middleware\ThrottleRequests;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->web(append: [
            ThrottleRequests::class.':60,1',
        ]);
    })
    ->create();
PHP;

        $routeCode = <<<'PHP'
<?php

Route::post('/login', [LoginController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapCode,
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'routes']);

        $result = $analyzer->analyze();

        // Should pass - Laravel 11+ throttle in bootstrap/app.php
        $this->assertPassed($result);
    }

    public function test_fails_without_web_middleware_throttle(): void
    {
        $kernelCode = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middlewareGroups = [
        'web' => [
            // No throttle middleware
        ],
    ];
}
PHP;

        $routeCode = <<<'PHP'
<?php

Route::post('/login', [LoginController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernelCode,
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        // Should fail - no throttle in web middleware group
        $this->assertFailed($result);
        $this->assertHasIssueContaining('login', $result);
    }

    public function test_passes_with_throttle_in_api_middleware_group(): void
    {
        $kernelCode = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Routing\Middleware\ThrottleRequests;

class Kernel extends HttpKernel
{
    protected $middlewareGroups = [
        'api' => [
            ThrottleRequests::class.':60,1',
        ],
    ];
}
PHP;

        $routeCode = <<<'PHP'
<?php

Route::post('/login', [ApiAuthController::class, 'login']);
Route::post('/token', [OAuthController::class, 'issueToken']);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernelCode,
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        // Should pass - throttle is in api middleware group
        $this->assertPassed($result);
    }

    public function test_passes_with_laravel_11_throttle_in_api_bootstrap(): void
    {
        $bootstrapCode = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Routing\Middleware\ThrottleRequests;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->api(append: [
            ThrottleRequests::class.':60,1',
        ]);
    })
    ->create();
PHP;

        $routeCode = <<<'PHP'
<?php

Route::post('/login', [ApiAuthController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapCode,
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'routes']);

        $result = $analyzer->analyze();

        // Should pass - Laravel 11+ throttle in api middleware
        $this->assertPassed($result);
    }

    public function test_fails_api_route_without_throttle(): void
    {
        $kernelCode = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middlewareGroups = [
        'api' => [
            // No throttle middleware
        ],
    ];
}
PHP;

        $routeCode = <<<'PHP'
<?php

Route::post('/login', [ApiAuthController::class, 'login']);
Route::post('/oauth/token', [AccessTokenController::class, 'issueToken']);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernelCode,
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        // Should fail - API routes without throttle
        $this->assertFailed($result);
        $this->assertHasIssueContaining('API authentication', $result);
    }

    public function test_detects_sanctum_token_endpoints(): void
    {
        $routeCode = <<<'PHP'
<?php

Route::post('/sanctum/token', [SanctumController::class, 'createToken']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should fail - token endpoint without throttle
        $this->assertFailed($result);
        $this->assertHasIssueContaining('sanctum/token', $result);
    }

    public function test_passes_with_invoke_controller_using_rate_limiter(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\RateLimiter;

class LoginController
{
    public function __invoke()
    {
        if (RateLimiter::tooManyAttempts('login:'.$request->ip(), 5)) {
            return response()->json(['error' => 'Too many attempts'], 429);
        }

        return $this->attemptLogin();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/LoginController.php' => $controllerCode,
            'routes/web.php' => '<?php // empty',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        // Should pass - single-action controller with RateLimiter
        $this->assertPassed($result);
    }

    public function test_fails_with_invoke_controller_without_throttle(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

class LoginController
{
    public function __invoke()
    {
        // No rate limiting
        return $this->attemptLogin();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/LoginController.php' => $controllerCode,
            'routes/web.php' => '<?php // empty',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        // Should fail - single-action controller without RateLimiter
        $this->assertFailed($result);
        $this->assertHasIssueContaining('__invoke', $result);
    }

    public function test_detects_invoke_in_auth_controller(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

class AuthenticateController
{
    public function __invoke()
    {
        // Authenticate user without throttling
        auth()->attempt($credentials);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/Auth/AuthenticateController.php' => $controllerCode,
            'routes/web.php' => '<?php Route::post("/authenticate", AuthenticateController::class);',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $result = $analyzer->analyze();

        // Should fail - __invoke in Auth directory without throttle
        $this->assertFailed($result);
    }

    // ==================== Externally registered web route files ====================

    public function test_flags_login_route_in_web_required_file_when_web_group_is_not_throttled(): void
    {
        // auth.php inherits the web group by being require'd from web.php. That
        // makes it a web route, not a throttled one.
        $result = $this->analyzeApp([
            'routes/web.php' => "<?php\nrequire __DIR__.'/auth.php';\n",
            'routes/auth.php' => "<?php\nRoute::post('/login', [LoginController::class, 'authenticate']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_passes_login_route_in_web_required_file_when_web_group_is_throttled(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->web(append: ['throttle:60,1']);"),
            'routes/web.php' => "<?php\nrequire __DIR__.'/auth.php';\n",
            'routes/auth.php' => "<?php\nRoute::post('/login', [LoginController::class, 'authenticate']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_flags_login_route_in_file_registered_with_web_middleware_in_bootstrap(): void
    {
        // auth.php registered via Route::middleware('web')->group() in bootstrap/app.php
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware('web')
                ->group(base_path('routes/auth.php'));
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/web.php' => '<?php // main routes',
            'routes/auth.php' => "<?php\nRoute::post('/login', [LoginController::class, 'authenticate']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_skips_route_file_registered_with_throttle_in_bootstrap(): void
    {
        // api-v1.php registered with throttle middleware directly on its group
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::prefix('api/v1')
                ->middleware(['api', 'throttle:api.rest'])
                ->group(base_path('routes/api-v1.php'));
        },
    )
    ->create();
PHP;

        $apiV1Php = <<<'PHP'
<?php
Route::post('/auth/login', [AuthController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/web.php' => '<?php // main routes',
            'routes/api-v1.php' => $apiV1Php,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should pass — api-v1.php has throttle applied at group level in bootstrap/app.php
        $this->assertPassed($result);
    }

    public function test_get_token_verify_does_not_trigger_false_positive(): void
    {
        // GET /token/verify is a management endpoint, not a credential submission endpoint
        $apiPhp = <<<'PHP'
<?php
Route::get('/token/verify', [TokenVerificationController::class, 'verify']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $apiPhp,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should pass — GET /token/verify is not a credential submission endpoint
        $this->assertPassed($result);
    }

    public function test_post_token_in_api_route_still_flagged_without_throttle(): void
    {
        // POST /token is a credential/token issuance endpoint — should still be checked
        $apiPhp = <<<'PHP'
<?php
Route::post('/token', [TokenController::class, 'issue']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $apiPhp,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should fail — POST /token is a credential submission endpoint without throttling
        $this->assertFailed($result);
        $this->assertHasIssueContaining('API authentication route "/token" lacks rate limiting', $result);
    }

    public function test_missing_throttle_recommendation_contains_no_code_samples(): void
    {
        $routeCode = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/login', [App\Http\Controllers\Auth\LoginController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();
        $issues = array_filter(
            $result->getIssues(),
            fn ($i) => str_contains(strtolower($i->message), 'rate limit') || str_contains(strtolower($i->message), 'throttl')
        );

        if (empty($issues)) {
            $this->markTestSkipped('No throttle issues detected for this fixture — adjust fixture if needed.');
        }

        foreach ($issues as $issue) {
            $this->assertStringNotContainsString('->', $issue->recommendation);
            $this->assertStringNotContainsString('throttle:', $issue->recommendation);
            $this->assertStringNotContainsString('RateLimiter::for(', $issue->recommendation);
        }
    }

    public function test_passes_when_login_request_throttles_via_form_request(): void
    {
        // Compass repro: the login route delegates throttling to a LoginRequest in
        // app/Http/Requests, which the analyzer previously never scanned.
        $route = <<<'PHP'
<?php

use App\Http\Controllers\Auth\AuthenticatedSessionController;

Route::post('/login', [AuthenticatedSessionController::class, 'store']);
PHP;

        $loginRequest = <<<'PHP'
<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;

class LoginRequest extends FormRequest
{
    public function ensureIsNotRateLimited(): void
    {
        if (! RateLimiter::tooManyAttempts($this->throttleKey(), 5)) {
            return;
        }

        throw ValidationException::withMessages(['email' => 'Too many attempts.']);
    }

    protected function throttleKey(): string
    {
        return 'login';
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $route,
            'app/Http/Controllers/Auth/AuthenticatedSessionController.php' => $this->sessionControllerCallingEnsureIsNotRateLimited(),
            'app/Http/Requests/Auth/LoginRequest.php' => $loginRequest,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_passes_when_form_request_uses_rate_limiter_only_in_ensure_method(): void
    {
        // The only throttling signal is RateLimiter::hit/clear inside
        // ensureIsNotRateLimited(), with no tooManyAttempts text and no 'login' literal.
        // The route is covered through the controller's call into the request.
        $route = <<<'PHP'
<?php

use App\Http\Controllers\Auth\AuthenticatedSessionController;

Route::post('/login', [AuthenticatedSessionController::class, 'store']);
PHP;

        $loginRequest = <<<'PHP'
<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\RateLimiter;

class LoginRequest extends FormRequest
{
    public function ensureIsNotRateLimited(): void
    {
        RateLimiter::hit($this->key());
        RateLimiter::clear($this->key());
    }

    protected function key(): string
    {
        return 'auth-key';
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'composer.lock' => '{"packages": [{"name": "laravel/breeze", "version": "2.0.0"}]}',
            'routes/auth.php' => $route,
            'routes/web.php' => '<?php',
            'app/Http/Controllers/Auth/AuthenticatedSessionController.php' => $this->sessionControllerCallingEnsureIsNotRateLimited(),
            'app/Http/Requests/Auth/LoginRequest.php' => $loginRequest,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_fails_when_login_request_does_not_throttle(): void
    {
        // True positive preserved: a login route whose FormRequest performs no rate
        // limiting (and no route-level throttle) must still be flagged.
        $route = <<<'PHP'
<?php

use App\Http\Controllers\Auth\AuthenticatedSessionController;

Route::post('/login', [AuthenticatedSessionController::class, 'store']);
PHP;

        $loginRequest = <<<'PHP'
<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;

class LoginRequest extends FormRequest
{
    public function rules(): array
    {
        return ['email' => ['required'], 'password' => ['required']];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $route,
            'app/Http/Requests/Auth/LoginRequest.php' => $loginRequest,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'routes']);

        $this->assertFailed($analyzer->analyze());
    }

    // ==================== Group-aware suppression ====================

    public function test_stock_laravel_9_kernel_api_throttle_does_not_clear_web_login(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => $this->stockKernel("'throttle:api'"),
            'app/Providers/RouteServiceProvider.php' => $this->stockRouteServiceProvider(),
            'routes/web.php' => $this->unthrottledWebLogin(),
            'routes/api.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_stock_laravel_10_kernel_api_throttle_does_not_clear_web_login(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => $this->stockKernel("\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class.':api'"),
            'app/Providers/RouteServiceProvider.php' => $this->stockRouteServiceProvider(),
            'routes/web.php' => $this->unthrottledWebLogin(),
            'routes/api.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_stock_laravel_10_kernel_api_throttle_still_clears_api_login(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => $this->stockKernel("\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class.':api'"),
            'app/Providers/RouteServiceProvider.php' => $this->stockRouteServiceProvider(),
            'routes/web.php' => '<?php',
            'routes/api.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_api_group_throttle_clears_a_file_required_from_api_php(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap('$middleware->throttleApi();'),
            'routes/web.php' => '<?php',
            'routes/api.php' => "<?php\n\nrequire __DIR__.'/api-session.php';\n",
            'routes/api-session.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_stock_laravel_11_app_flags_unthrottled_web_login(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap('//'),
            'routes/web.php' => $this->unthrottledWebLogin(),
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_throttle_api_does_not_clear_web_login(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap('$middleware->throttleApi();'),
            'routes/web.php' => $this->unthrottledWebLogin(),
            'routes/api.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_web_group_throttle_clears_web_login_registered_through_with_routing(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->web(append: ['throttle:60,1']);"),
            'routes/web.php' => $this->unthrottledWebLogin(),
        ]);

        $this->assertPassed($result);
    }

    public function test_web_group_throttle_does_not_clear_api_login(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->web(append: ['throttle:60,1']);"),
            'routes/web.php' => '<?php',
            'routes/api.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_stock_laravel_10_kernel_api_throttle_does_not_hide_disabled_fortify_limiter(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

class FortifyServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        RateLimiter::for('login', fn () => Limit::none());
    }
}
PHP;

        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => self::FORTIFY_CONFIG,
            'app/Http/Kernel.php' => $this->stockKernel("\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class.':api'"),
            'app/Providers/FortifyServiceProvider.php' => $provider,
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Fortify login throttling is explicitly disabled'], $this->issueMessages($result));
        $this->assertSame('critical', $result->getIssues()[0]->severity->value);
    }

    public function test_laravel_ui_auth_routes_pass_when_login_controller_uses_authenticates_users(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;

class LoginController extends Controller
{
    use AuthenticatesUsers;

    protected $redirectTo = '/dashboard';
}
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap('//'),
            'app/Http/Controllers/Auth/LoginController.php' => $controller,
            'routes/web.php' => "<?php\n\nAuth::routes();\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_authenticates_users_named_only_in_an_import_and_a_comment_is_not_throttling(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;

class LoginController extends Controller
{
    // Replaced AuthenticatesUsers with a hand-written login().
    public function login()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap('//'),
            'app/Http/Controllers/Auth/LoginController.php' => $controller,
            'routes/web.php' => "<?php\n\nAuth::routes();\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame([
            'Auth::routes() includes login endpoint without explicit rate limiting',
            'Authentication method LoginController::login() lacks rate limiting',
        ], $this->issueMessages($result));
    }

    public function test_get_login_form_is_not_flagged_when_post_is_throttled(): void
    {
        $routes = <<<'PHP'
<?php

Route::get('/session/login', [SessionController::class, 'create'])->name('login');
Route::get('/', HomeController::class);
Route::post('/session/login', [SessionController::class, 'store'])->middleware('throttle:5,1');
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap('//'),
            'routes/web.php' => $routes,
        ]);

        $this->assertPassed($result);
    }

    public function test_authenticates_users_does_not_clear_an_api_token_route(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;

class LoginController extends Controller
{
    use AuthenticatesUsers;
}
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap('//'),
            'app/Http/Controllers/Auth/LoginController.php' => $controller,
            'routes/web.php' => "<?php\n\nAuth::routes();\n",
            'routes/api.php' => "<?php\n\nRoute::post('/session/token', [SessionTokenController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/session/token" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @dataProvider webThrottleMiddlewareProvider
     */
    #[DataProvider('webThrottleMiddlewareProvider')]
    public function test_web_throttle_configured_in_bootstrap_clears_web_login(string $middlewareBody): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap($middlewareBody),
            'routes/web.php' => $this->unthrottledWebLogin(),
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function webThrottleMiddlewareProvider(): array
    {
        return [
            'appendToGroup' => ["\$middleware->appendToGroup('web', 'throttle:60,1');"],
            'prependToGroup' => ["\$middleware->prependToGroup('web', ['throttle:60,1']);"],
            'appendToGroup named arguments' => ["\$middleware->appendToGroup(group: 'web', middleware: 'throttle:60,1');"],
            'group' => ["\$middleware->group('web', [\\Illuminate\\Session\\Middleware\\StartSession::class, 'throttle:60,1']);"],
            'web prepend' => ["\$middleware->web(prepend: [\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class.':60,1']);"],
            'global append' => ['$middleware->append(\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class);'],
            'global prepend' => ["\$middleware->prepend('throttle:60,1');"],
            'global use' => ["\$middleware->use([\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class.':60,1']);"],
        ];
    }

    public function test_api_group_throttle_appended_in_bootstrap_does_not_clear_web_login(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->appendToGroup('api', 'throttle:60,1');"),
            'routes/web.php' => $this->unthrottledWebLogin(),
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_throttle_removed_from_web_group_does_not_clear_web_login(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap('$middleware->web(remove: [\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class]);'),
            'routes/web.php' => $this->unthrottledWebLogin(),
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_global_throttle_in_bootstrap_clears_api_login(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->append('throttle:60,1');"),
            'routes/web.php' => '<?php',
            'routes/api.php' => "<?php\n\nRoute::post('/session/token', [SessionTokenController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_throttle_in_kernel_global_middleware_clears_web_and_api_login(): void
    {
        $kernel = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middleware = [
        \Illuminate\Routing\Middleware\ThrottleRequests::class.':60,1',
    ];

    protected $middlewareGroups = [
        'web' => [
            \Illuminate\Session\Middleware\StartSession::class,
        ],
    ];
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => $kernel,
            'app/Providers/RouteServiceProvider.php' => $this->stockRouteServiceProvider(),
            'routes/web.php' => $this->unthrottledWebLogin(),
            'routes/api.php' => "<?php\n\nRoute::post('/session/token', [SessionTokenController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_route_file_registered_in_the_api_group_is_matched_as_api_routes(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: [__DIR__.'/../routes/api.php', __DIR__.'/../routes/partner_api.php'],
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/api.php' => '<?php',
            'routes/partner_api.php' => "<?php\n\nRoute::post('/session/token', [SessionTokenController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/session/token" lacks rate limiting protection'], $this->issueMessages($result));
        $this->assertSame('api', $result->getIssues()[0]->metadata['route_type']);
    }

    // ==================== A route's throttle stops at its statement ====================

    public function test_next_routes_throttle_does_not_clear_a_one_line_login_route(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/account/signin', [AccountController::class, 'signin']); // keep in sync with the app

Route::put('/settings', [SettingsController::class, 'update'])->middleware('throttle:30,1');
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/account/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_next_routes_throttle_does_not_clear_auth_routes(): void
    {
        $routes = <<<'PHP'
<?php

Auth::routes();
Route::put('/settings', [SettingsController::class, 'update'])->middleware('throttle:30,1');
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Auth::routes() includes login endpoint without explicit rate limiting'], $this->issueMessages($result));
    }

    public function test_next_routes_throttle_does_not_clear_login_controller(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/account/signin', [LoginController::class, 'login']);
Route::put('/settings', [SettingsController::class, 'update'])->middleware('throttle:30,1');
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame([
            'Login route "/account/signin" lacks rate limiting protection',
            'Authentication method LoginController::login() lacks rate limiting',
        ], $this->issueMessages($result));
    }

    public function test_one_line_closure_route_still_reads_its_next_line_throttle(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/account/signin', function () { return view('account.signin'); })
    ->middleware('throttle:6,1');
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertPassed($result);
    }

    public function test_multi_line_closure_route_reads_the_throttle_after_its_body(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/account/signin', function (Request $request) {
    $request->validate(['email' => 'required']);
    $status = 'checked; then signed in';
    logger("Sign-in for {$request->email} from ${ip}");
    Auth::attempt($request->only('email', 'password'));
    session()->regenerate();
    return redirect('/home');
})
    ->middleware('throttle:6,1');
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertPassed($result);
    }

    public function test_multi_line_closure_route_does_not_read_the_next_routes_throttle(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/account/signin', function (Request $request) {
    return redirect('/home');
});
Route::put('/settings', [SettingsController::class, 'update'])->middleware('throttle:30,1');
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/account/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_route_in_arrow_function_group_ends_at_the_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('web')->group(fn () =>
    Route::post('/account/signin', [AccountController::class, 'signin'])
);
Route::put('/settings', [SettingsController::class, 'update'])->middleware('throttle:30,1');
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/account/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_statement_before_the_route_on_its_line_does_not_end_the_routes_chain(): void
    {
        $routes = <<<'PHP'
<?php

Route::prefix('home')->group(function () {
    Route::get('/', [HomeController::class, 'index']);
}); Route::post('/account/signin', [AccountController::class, 'signin'])
    ->middleware('throttle:6,1');
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertPassed($result);
    }

    public function test_group_opened_on_the_routes_line_does_not_extend_the_routes_chain(): void
    {
        $routes = <<<'PHP'
<?php

Route::prefix('account')->group(function () { Route::post('/signin', [AccountController::class, 'signin']);
    Route::put('/settings', [SettingsController::class, 'update'])->middleware('throttle:30,1');
});
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_group_opened_on_the_auth_routes_line_does_not_extend_its_chain(): void
    {
        $routes = <<<'PHP'
<?php

Route::prefix('account')->group(function () { Auth::routes();
    Route::put('/settings', [SettingsController::class, 'update'])->middleware('throttle:30,1');
});
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Auth::routes() includes login endpoint without explicit rate limiting'], $this->issueMessages($result));
    }

    public function test_long_closure_route_reads_the_throttle_after_its_body(): void
    {
        // The body runs past the first eight-line window, which ends inside the
        // multi-line string, so the statement's end is found by widening it.
        $routes = <<<'PHP'
<?php

Route::post('/account/signin', function (Request $request) {
    $request->validate(['email' => 'required']);
    Auth::attempt($request->only('email', 'password'));
    session()->regenerate();
    $request->session()->put('signed_in_at', now());
    event(new SignedIn($request->user()));
    logger()->info('signed in', ['id' => $request->user()->id]);
    $notice = 'Signed in; welcome back.
Close this notice with ) or }; it will not return.';
    return redirect('/home')->with('notice', $notice);
})
    ->middleware('throttle:6,1');
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertPassed($result);
    }

    public function test_long_closure_route_does_not_read_the_next_routes_throttle(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/account/signin', function (Request $request) {
    $request->validate(['email' => 'required']);
    Auth::attempt($request->only('email', 'password'));
    session()->regenerate();
    $request->session()->put('signed_in_at', now());
    event(new SignedIn($request->user()));
    logger()->info('signed in', ['id' => $request->user()->id]);
    $notice = 'Signed in; welcome back.
Close this notice with ) or }; it will not return.';
    return redirect('/home')->with('notice', $notice);
});
Route::put('/settings', [SettingsController::class, 'update'])->middleware('throttle:30,1');
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/account/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_unterminated_route_reads_its_chain_to_the_end_of_the_file(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/account/signin', [AccountController::class, 'signin'])
    ->middleware('throttle:6,1')
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertPassed($result);
    }

    // ==================== Route throttling clears the controller check ====================

    public function test_route_level_throttle_clears_controller_check(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'routes/web.php' => "<?php\n\nRoute::post('/session/login', [LoginController::class, 'login'])->middleware('throttle:6,1');\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_group_level_throttle_clears_controller_check(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('throttle:6,1')->group(function () {
    Route::post('/session/login', [LoginController::class, 'login']);
});
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'routes/web.php' => $routes,
        ]);

        $this->assertPassed($result);
    }

    public function test_web_group_throttle_clears_controller_check(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->web(append: ['throttle:60,1']);"),
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'routes/web.php' => "<?php\n\nRoute::post('/session/login', [LoginController::class, 'login']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_throttle_registered_route_file_clears_controller_check(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::middleware(['web', 'throttle:6,1'])
                ->group(base_path('routes/session.php'));
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'routes/web.php' => '<?php',
            'routes/session.php' => "<?php\n\nRoute::post('/session/login', [LoginController::class, 'login']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_multi_line_and_qualified_route_references_clear_controller_check(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/session/login', [
    \App\Http\Controllers\Auth\LoginController::class,
    'login',
])->middleware('throttle:6,1');
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'routes/web.php' => $routes,
        ]);

        $this->assertPassed($result);
    }

    public function test_string_action_reference_clears_controller_check(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'routes/web.php' => "<?php\n\nRoute::post('/session/login', 'Auth\\LoginController@login')->middleware('throttle:6,1');\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_unthrottled_route_still_reports_route_and_controller(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'routes/web.php' => "<?php\n\nRoute::post('/session/login', [LoginController::class, 'login']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame([
            'Login route "/session/login" lacks rate limiting protection',
            'Authentication method LoginController::login() lacks rate limiting',
        ], $this->issueMessages($result));
    }

    public function test_throttled_route_to_another_controller_does_not_clear_login_controller(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'routes/web.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store'])->middleware('throttle:6,1');\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Authentication method LoginController::login() lacks rate limiting'], $this->issueMessages($result));
    }

    public function test_login_rate_limiter_elsewhere_clears_neither_the_route_nor_the_controller(): void
    {
        $apiController = <<<'PHP'
<?php

namespace App\Http\Controllers\Api;

use Illuminate\Support\Facades\RateLimiter;

class TokenAuthController
{
    public function issue()
    {
        return RateLimiter::attempt('login:'.request()->ip(), 5, fn () => true);
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'app/Http/Controllers/Api/TokenAuthController.php' => $apiController,
            'routes/web.php' => "<?php\n\nRoute::post('/session/login', [LoginController::class, 'login']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame([
            'Login route "/session/login" lacks rate limiting protection',
            'Authentication method LoginController::login() lacks rate limiting',
        ], $this->issueMessages($result));
    }

    public function test_qualified_route_reference_clears_only_that_controller(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'app/Http/Controllers/LoginController.php' => $this->unthrottledLoginController('App\\Http\\Controllers'),
            'routes/api.php' => "<?php\n\nRoute::post('/login', [\\App\\Http\\Controllers\\LoginController::class, 'login'])->middleware('throttle:5,1');\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['app/Http/Controllers/Auth/LoginController.php'], $this->issueFiles($result));
    }

    public function test_imported_route_reference_clears_only_that_controller(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\Auth\LoginController as WebLoginController;

Route::post('/session/login', [WebLoginController::class, 'login'])->middleware('throttle:6,1');
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'app/Http/Controllers/LoginController.php' => $this->unthrottledLoginController('App\\Http\\Controllers'),
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['app/Http/Controllers/LoginController.php'], $this->issueFiles($result));
    }

    // ==================== Throttling delegated to a FormRequest (#485) ====================

    public function test_controller_calling_a_throttling_form_request_is_not_reported(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('$request->authenticate();'),
            'app/Http/Requests/Auth/SignInRequest.php' => $this->signInRequest(),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_controller_calling_the_throttle_guard_directly_is_not_reported(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('$request->ensureIsNotRateLimited();'),
            'app/Http/Requests/Auth/SignInRequest.php' => $this->signInRequest(),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_throttling_reached_through_a_this_call_in_the_request_is_not_reported(): void
    {
        // authenticate() has no RateLimiter call of its own; its guard does.
        $request = <<<'PHP'
<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;

class SignInRequest extends FormRequest
{
    public function authenticate(): void
    {
        $this->guardAttempts();

        Auth::attempt($this->only('email', 'password'));
    }

    private function guardAttempts(): void
    {
        abort_if(RateLimiter::tooManyAttempts('sign-in|'.$this->ip(), 5), 429);
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('$request->authenticate();'),
            'app/Http/Requests/Auth/SignInRequest.php' => $request,
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_controller_that_never_calls_the_throttling_method_is_reported(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('Auth::attempt($request->validated());'),
            'app/Http/Requests/Auth/SignInRequest.php' => $this->signInRequest(),
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Authentication method LoginController::login() lacks rate limiting'], $this->issueMessages($result));
    }

    public function test_throttling_method_called_on_another_variable_does_not_count(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('$other = new \stdClass; $other->authenticate(); Auth::attempt($request->validated());'),
            'app/Http/Requests/Auth/SignInRequest.php' => $this->signInRequest(),
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
    }

    public function test_form_request_that_does_not_throttle_is_reported(): void
    {
        $request = <<<'PHP'
<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;

class SignInRequest extends FormRequest
{
    public function authenticate(): void
    {
        Auth::attempt($this->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('$request->authenticate();'),
            'app/Http/Requests/Auth/SignInRequest.php' => $request,
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Authentication method LoginController::login() lacks rate limiting'], $this->issueMessages($result));
    }

    /**
     * @dataProvider requestResolutionHookProvider
     */
    #[DataProvider('requestResolutionHookProvider')]
    public function test_form_request_throttling_in_a_resolution_hook_is_not_reported(string $hook): void
    {
        // Laravel's validateResolved() runs these itself when it resolves the request.
        $request = str_replace('HOOK', $hook, <<<'PHP'
<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\RateLimiter;

class SignInRequest extends FormRequest
{
    public function HOOK()
    {
        abort_if(RateLimiter::tooManyAttempts('sign-in|'.$this->ip(), 5), 429);

        return true;
    }
}
PHP);

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('Auth::attempt($request->validated());'),
            'app/Http/Requests/Auth/SignInRequest.php' => $request,
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function requestResolutionHookProvider(): array
    {
        return [
            'prepareForValidation' => ['prepareForValidation'],
            'authorize' => ['authorize'],
            'validator' => ['validator'],
            'withValidator' => ['withValidator'],
            'after' => ['after'],
            'passedValidation' => ['passedValidation'],
        ];
    }

    public function test_form_request_throttling_only_on_failed_validation_is_reported(): void
    {
        // failedValidation() runs on a request already being rejected, so a valid
        // credential guess never reaches it.
        $request = <<<'PHP'
<?php

namespace App\Http\Requests\Auth;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\RateLimiter;

class SignInRequest extends FormRequest
{
    protected function failedValidation(Validator $validator): void
    {
        RateLimiter::hit('sign-in|'.$this->ip());

        parent::failedValidation($validator);
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('Auth::attempt($request->validated());'),
            'app/Http/Requests/Auth/SignInRequest.php' => $request,
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
    }

    public function test_throttling_inherited_from_an_app_parent_request_is_not_reported(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('$request->authenticate();'),
            'app/Http/Requests/Auth/SignInRequest.php' => $this->childSignInRequest('use App\Http\Requests\GuardedRequest;', 'extends GuardedRequest'),
            'app/Http/Requests/GuardedRequest.php' => $this->throttleGuardDeclaration('abstract class GuardedRequest extends FormRequest'),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_throttling_from_a_trait_the_request_uses_is_not_reported(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('$request->authenticate();'),
            'app/Http/Requests/Auth/SignInRequest.php' => $this->childSignInRequest('use App\Http\Requests\GuardsAttempts;', 'extends \Illuminate\Foundation\Http\FormRequest', 'use GuardsAttempts;'),
            'app/Http/Requests/GuardsAttempts.php' => $this->throttleGuardDeclaration('trait GuardsAttempts'),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_throttling_from_a_trait_on_the_parent_request_is_not_reported(): void
    {
        $parent = <<<'PHP'
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

abstract class GuardedRequest extends FormRequest
{
    use GuardsAttempts;
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('$request->authenticate();'),
            'app/Http/Requests/Auth/SignInRequest.php' => $this->childSignInRequest('use App\Http\Requests\GuardedRequest;', 'extends GuardedRequest'),
            'app/Http/Requests/GuardedRequest.php' => $parent,
            'app/Http/Requests/GuardsAttempts.php' => $this->throttleGuardDeclaration('trait GuardsAttempts'),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_parent_request_resolves_against_the_request_files_own_imports(): void
    {
        // Spelled with an alias only the request file declares. Resolved against the
        // controller's table instead, GuardBase would land in App\Http\Controllers\Auth.
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('$request->authenticate();'),
            'app/Http/Requests/Auth/SignInRequest.php' => $this->childSignInRequest('use App\Http\Requests\GuardedRequest as GuardBase;', 'extends GuardBase'),
            'app/Http/Requests/GuardedRequest.php' => $this->throttleGuardDeclaration('abstract class GuardedRequest extends FormRequest'),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_reading_a_parent_request_leaves_the_controllers_imports_in_place(): void
    {
        // The request file imports its parent under the alias the controller uses for
        // the request itself. If reading the request left its table behind, the second
        // method's LoginForm would resolve to the parent, which has no authenticate().
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Requests\Auth\SignInRequest as LoginForm;

class LoginController
{
    public function login(LoginForm $request)
    {
        $request->authenticate();
    }

    public function authenticate(LoginForm $request)
    {
        $request->authenticate();
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $controller,
            'app/Http/Requests/Auth/SignInRequest.php' => $this->childSignInRequest('use App\Http\Requests\GuardedRequest as LoginForm;', 'extends LoginForm'),
            'app/Http/Requests/GuardedRequest.php' => $this->throttleGuardDeclaration('abstract class GuardedRequest extends FormRequest'),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_request_inheritance_cycle_ends_and_is_reported(): void
    {
        $cycle = fn (string $class, string $parent): string => "<?php\n\nnamespace App\\Http\\Requests\\Auth;\n\nclass {$class} extends {$parent}\n{\n}\n";

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('$request->authenticate();'),
            'app/Http/Requests/Auth/SignInRequest.php' => $cycle('SignInRequest', 'LoopRequest'),
            'app/Http/Requests/Auth/LoopRequest.php' => $cycle('LoopRequest', 'SignInRequest'),
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Authentication method LoginController::login() lacks rate limiting'], $this->issueMessages($result));
    }

    public function test_unresolvable_form_request_class_is_reported(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->formRequestLoginController('$request->authenticate();'),
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Authentication method LoginController::login() lacks rate limiting'], $this->issueMessages($result));
    }

    /**
     * A SignInRequest whose authenticate() only calls a guard it inherits.
     */
    private function childSignInRequest(string $import, string $extends, string $traitUse = ''): string
    {
        return <<<PHP
<?php

namespace App\\Http\\Requests\\Auth;

{$import}

class SignInRequest {$extends}
{
    {$traitUse}

    public function authenticate(): void
    {
        \$this->ensureIsNotRateLimited();
    }
}
PHP;
    }

    /**
     * A class or trait in App\Http\Requests declaring the throttle guard.
     */
    private function throttleGuardDeclaration(string $declaration): string
    {
        return <<<PHP
<?php

namespace App\\Http\\Requests;

use Illuminate\\Foundation\\Http\\FormRequest;
use Illuminate\\Support\\Facades\\RateLimiter;

{$declaration}
{
    public function ensureIsNotRateLimited(): void
    {
        abort_if(RateLimiter::tooManyAttempts('sign-in|'.\$this->ip(), 5), 429);
    }
}
PHP;
    }

    private function formRequestLoginController(string $body): string
    {
        return str_replace('BODY', $body, <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Requests\Auth\SignInRequest as LoginForm;
use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login(LoginForm $request)
    {
        BODY

        return redirect()->intended('/dashboard');
    }
}
PHP);
    }

    private function signInRequest(): string
    {
        return <<<'PHP'
<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;

class SignInRequest extends FormRequest
{
    public function authenticate(): void
    {
        $this->ensureIsNotRateLimited();

        if (! Auth::attempt($this->only('email', 'password'))) {
            RateLimiter::hit($this->throttleKey());
        }
    }

    public function ensureIsNotRateLimited(): void
    {
        abort_if(RateLimiter::tooManyAttempts($this->throttleKey(), 5), 429);
    }

    private function throttleKey(): string
    {
        return 'sign-in|'.$this->ip();
    }
}
PHP;
    }

    private function unthrottledLoginController(string $namespace = 'App\\Http\\Controllers\\Auth'): string
    {
        $controller = <<<'PHP'
<?php

namespace NAMESPACE;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login(Request $request)
    {
        return Auth::attempt($request->only('email', 'password'));
    }
}
PHP;

        return str_replace('NAMESPACE', $namespace, $controller);
    }

    /**
     * @param  array<string, string>  $files
     */
    private function analyzeApp(array $files): ResultInterface
    {
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($this->createTempDirectory($files));
        $analyzer->setPaths(['app', 'bootstrap', 'config', 'routes']);

        return $analyzer->analyze();
    }

    /**
     * @return list<string>
     */
    private function issueMessages(ResultInterface $result): array
    {
        return array_values(array_map(fn ($issue) => $issue->message, $result->getIssues()));
    }

    /**
     * @return list<string>
     */
    private function issueFiles(ResultInterface $result): array
    {
        return array_values(array_map(fn ($issue) => (string) $issue->location?->file, $result->getIssues()));
    }

    private function unthrottledWebLogin(): string
    {
        return "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n";
    }

    private function stockKernel(string $apiThrottleEntry): string
    {
        return <<<PHP
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected \$middlewareGroups = [
        'web' => [
            \App\Http\Middleware\EncryptCookies::class,
            \Illuminate\Session\Middleware\StartSession::class,
            \App\Http\Middleware\VerifyCsrfToken::class,
            \Illuminate\Routing\Middleware\SubstituteBindings::class,
        ],

        'api' => [
            {$apiThrottleEntry},
            \Illuminate\Routing\Middleware\SubstituteBindings::class,
        ],
    ];
}
PHP;
    }

    private function stockRouteServiceProvider(): string
    {
        return <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->routes(function () {
            Route::middleware('api')
                ->prefix('api')
                ->group(base_path('routes/api.php'));

            Route::middleware('web')
                ->group(base_path('routes/web.php'));
        });
    }
}
PHP;
    }

    private function laravel11Bootstrap(string $middlewareBody): string
    {
        return <<<PHP
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware \$middleware): void {
        {$middlewareBody}
    })
    ->create();
PHP;
    }

    // ==================== Commented-out code ====================

    public function test_commented_out_login_route_is_not_flagged(): void
    {
        $routes = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

// Route::post('/session/login', [SessionController::class, 'store']);
/*
Route::post('/session/signin', [SessionController::class, 'store']);
Auth::routes();
*/

Route::get('/', HomeController::class);
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertPassed($result);
    }

    public function test_commented_out_throttle_does_not_clear_live_login_route(): void
    {
        $routes = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::post('/session/login', [SessionController::class, 'store']);
    // ->middleware('throttle:5,1');
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('Login route "/session/login" lacks rate limiting protection', $result->getIssues()[0]->message);
        $this->assertSame(5, $result->getIssues()[0]->location?->line);
    }

    public function test_commented_out_disabled_fortify_limiter_is_not_reported(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

class FortifyServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // While load testing: RateLimiter::for('login', fn () => Limit::none());
        RateLimiter::for('login', fn () => Limit::perMinute(5));
    }
}
PHP;

        $result = $this->analyzeRoutesOnly([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => self::FORTIFY_CONFIG,
            'app/Providers/FortifyServiceProvider.php' => $provider,
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_commented_out_throttle_step_is_not_in_the_fortify_login_pipeline(): void
    {
        $config = <<<'PHP'
<?php

use Laravel\Fortify\Actions\AttemptToAuthenticate;
use Laravel\Fortify\Actions\EnsureLoginIsNotThrottled;

return [
    'guard' => 'web',
    'pipelines' => [
        'login' => [
            // EnsureLoginIsNotThrottled::class,
            AttemptToAuthenticate::class,
        ],
    ],
];
PHP;

        $result = $this->analyzeRoutesOnly([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => $config,
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Fortify login pipeline does not throttle login attempts'], $this->issueMessages($result));
    }

    public function test_commented_out_login_rate_limiter_in_auth_controller_is_not_throttling(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

class SessionController
{
    public function store()
    {
        // TODO: RateLimiter::attempt('login:'.request()->ip(), 5, fn () => true);
        // if ($this->hasTooManyLoginAttempts(request())) { abort(429); }
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeRoutesOnly([
            'app/Http/Controllers/Auth/SessionController.php' => $controller,
            'routes/api.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame('API authentication route "/session/login" lacks rate limiting protection', $result->getIssues()[0]->message);
    }

    public function test_commented_out_throttle_api_is_not_api_group_throttle(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware): void {
        // $middleware->throttleApi();
    })
    ->create();
PHP;

        $result = $this->analyzeRoutesOnly([
            'bootstrap/app.php' => $bootstrap,
            'routes/api.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame('API authentication route "/session/login" lacks rate limiting protection', $result->getIssues()[0]->message);
    }

    public function test_commented_out_throttle_in_breeze_auth_routes_does_not_count(): void
    {
        $authRoutes = <<<'PHP'
<?php

// Route::middleware('throttle:5,1')->group(function () {
Route::post('login', [SessionController::class, 'store']);
// });
PHP;

        $result = $this->analyzeRoutesOnly([
            'composer.lock' => '{"packages": [{"name": "laravel/breeze", "version": "2.0.0"}]}',
            'routes/auth.php' => $authRoutes,
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    // ==================== Code-level rate limiting covers only the routes that reach it (#487) ====================

    public function test_throttled_web_login_controller_does_not_clear_an_api_token_route(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/SessionSignInController.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Auth', 'SessionSignInController'),
            'routes/api.php' => "<?php\n\nRoute::post('/device/token', [DeviceTokenController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/device/token" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_throttled_api_controller_does_not_clear_a_web_login_route(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SignInController;

Route::post('/signin', [SignInController::class, 'store']);
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Api/TokenLoginController.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Api', 'TokenLoginController'),
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_throttling_middleware_covers_only_the_routes_that_name_it(): void
    {
        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

use Illuminate\Support\Facades\RateLimiter;

class CapSignIns
{
    public function handle($request, $next)
    {
        abort_if(RateLimiter::tooManyAttempts('sign-in|'.$request->ip(), 5), 429);

        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SignInController;
use App\Http\Middleware\CapSignIns;

Route::post('/signin', [SignInController::class, 'store'])->middleware(CapSignIns::class);
Route::post('/admin/signin', [SignInController::class, 'store']);
PHP;

        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $middleware,
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/admin/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_api_route_to_its_own_throttling_controller_passes(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\Api\TokenController;

Route::post('/token', [TokenController::class, 'store']);
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Api/TokenController.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Api', 'TokenController'),
            'routes/api.php' => $routes,
        ]);

        $this->assertPassed($result);
    }

    public function test_string_action_resolves_against_the_default_controller_namespace(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/SignInController.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Auth', 'SignInController'),
            'routes/web.php' => "<?php\n\nRoute::post('/signin', 'Auth\\SignInController@store');\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_auth_routes_is_not_cleared_by_another_controllers_login_trait(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Foundation\Auth\AuthenticatesUsers;

class AdminLoginController
{
    use AuthenticatesUsers;
}
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap('//'),
            'app/Http/Controllers/Auth/AdminLoginController.php' => $controller,
            'routes/web.php' => "<?php\n\nAuth::routes();\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Auth::routes() includes login endpoint without explicit rate limiting'], $this->issueMessages($result));
    }

    public function test_reading_a_routed_controller_leaves_the_route_files_imports_in_place(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\Api\TokenController;
use App\Http\Controllers\Web\SignInController;

Route::post('/signin', [SignInController::class, 'store']);
Route::post('/token/login', [TokenController::class, 'store']);
PHP;

        $signIn = <<<'PHP'
<?php

namespace App\Http\Controllers\Web;

class SignInController
{
    public function store()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Web/SignInController.php' => $signIn,
            'app/Http/Controllers/Api/TokenController.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Api', 'TokenController'),
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_group_middleware_class_covers_the_routes_inside_the_group(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SignInController;
use App\Http\Middleware\CapSignIns;

Route::middleware(CapSignIns::class)->group(function () {
    Route::post('/signin', [SignInController::class, 'store']);
});

Route::post('/admin/signin', [SignInController::class, 'store']);
PHP;

        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/admin/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_array_form_group_middleware_class_covers_the_routes_inside_the_group(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SignInController;
use App\Http\Middleware\CapSignIns;

Route::group(['middleware' => ['web', CapSignIns::class]], function () {
    Route::post('/signin', [SignInController::class, 'store']);
});
PHP;

        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'routes/web.php' => $routes,
        ]);

        $this->assertPassed($result);
    }

    public function test_controller_group_covers_its_routes_with_the_controllers_throttling(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\Auth\SessionGate;

Route::controller(SessionGate::class)->group(function () {
    Route::post('/signin', 'store');
});

Route::post('/admin/signin', 'store');
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/SessionGate.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Auth', 'SessionGate'),
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/admin/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_controller_group_does_not_cover_a_route_that_names_its_own_controller(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\Api\TokenController;
use App\Http\Controllers\Auth\SessionGate;

Route::controller(SessionGate::class)->group(function () {
    Route::post('/token', [TokenController::class, 'store']);
});
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/SessionGate.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Auth', 'SessionGate'),
            'app/Http/Controllers/Api/TokenController.php' => $this->tokenController(''),
            'routes/api.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/token" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_controller_group_does_not_cover_a_closure_route(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\Auth\SessionGate;

Route::controller(SessionGate::class)->group(function () {
    Route::post('/signin', fn () => Auth::attempt(request()->only('email', 'password')));
});
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/SessionGate.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Auth', 'SessionGate'),
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_throttling_in_another_method_does_not_cover_the_routed_method(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Api/TokenController.php' => $this->tokenController(
                "public function refresh()\n    {\n        abort_if(RateLimiter::tooManyAttempts('refresh|'.request()->ip(), 5), 429);\n    }"
            ),
            'routes/api.php' => "<?php\n\nuse App\\Http\\Controllers\\Api\\TokenController;\n\nRoute::post('/token', [TokenController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/token" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_throttling_in_another_method_does_not_cover_an_invokable_route(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Api/TokenController.php' => $this->tokenController(
                "public function __invoke()\n    {\n        return 'token';\n    }\n\n    public function refresh()\n    {\n        abort_if(RateLimiter::tooManyAttempts('refresh|'.request()->ip(), 5), 429);\n    }"
            ),
            'routes/api.php' => "<?php\n\nuse App\\Http\\Controllers\\Api\\TokenController;\n\nRoute::post('/token', TokenController::class);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/token" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_routed_method_throttling_through_its_own_helper_is_credited(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers\Api;

use Illuminate\Support\Facades\RateLimiter;

class TokenController
{
    public function store()
    {
        $this->guardAttempts();

        return 'token';
    }

    private function guardAttempts(): void
    {
        abort_if(RateLimiter::tooManyAttempts('token|'.request()->ip(), 5), 429);
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Api/TokenController.php' => $controller,
            'routes/api.php' => "<?php\n\nuse App\\Http\\Controllers\\Api\\TokenController;\n\nRoute::post('/token', [TokenController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_routed_login_method_checking_has_too_many_login_attempts_is_credited(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\ThrottlesLogins;
use Illuminate\Http\Request;

class SessionController
{
    use ThrottlesLogins;

    public function login(Request $request)
    {
        if ($this->hasTooManyLoginAttempts($request)) {
            return $this->sendLockoutResponse($request);
        }

        return 'session';
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/SessionController.php' => $controller,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\SessionController;\n\nRoute::post('/login', [SessionController::class, 'login']);\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function frameworkThrottleRegistrations(): array
    {
        return [
            'constructor alias' => ["public function __construct()\n    {\n        \$this->middleware('throttle:5,1')->only('store');\n    }"],
            'constructor class' => ["public function __construct()\n    {\n        \$this->middleware(ThrottleRequests::class.':5,1')->only('store');\n    }"],
            'HasMiddleware using()' => ["public static function middleware(): array\n    {\n        return [new Middleware(ThrottleRequests::using('token'), only: ['store'])];\n    }"],
            'HasMiddleware Redis class' => ["public static function middleware(): array\n    {\n        return [new Middleware(ThrottleRequestsWithRedis::class.':5,1', only: ['store'])];\n    }"],
        ];
    }

    #[DataProvider('frameworkThrottleRegistrations')]
    public function test_framework_throttle_a_controller_registers_covers_its_method(string $registration): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Api/TokenController.php' => $this->tokenController($registration),
            'routes/api.php' => "<?php\n\nuse App\\Http\\Controllers\\Api\\TokenController;\n\nRoute::post('/token', [TokenController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_framework_throttle_a_controller_registers_for_another_method_covers_nothing(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Api/TokenController.php' => $this->tokenController(
                "public function __construct()\n    {\n        \$this->middleware('throttle:5,1')->only('refresh');\n    }"
            ),
            'routes/api.php' => "<?php\n\nuse App\\Http\\Controllers\\Api\\TokenController;\n\nRoute::post('/token', [TokenController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/token" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_framework_throttle_registered_on_the_login_controller_clears_the_controller_check(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

class LoginController
{
    public function __construct()
    {
        $this->middleware('throttle:5,1')->only('login');
    }

    public function login()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $controller,
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_controller_group_whose_controller_does_not_throttle_covers_nothing(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class SignInController
{
    public function store()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SignInController;

Route::prefix('account')->controller(SignInController::class)->group(function () {
    Route::post('/signin', 'store');
});
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/SignInController.php' => $controller,
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_group_middleware_that_does_not_throttle_covers_nothing(): void
    {
        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

class TrimSignIns
{
    public function handle($request, $next)
    {
        return $next($request);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SignInController;
use App\Http\Middleware\TrimSignIns;

Route::middleware(TrimSignIns::class)->group(function () {
    Route::post('/signin', [SignInController::class, 'store']);
});
PHP;

        $result = $this->analyzeApp([
            'app/Http/Middleware/TrimSignIns.php' => $middleware,
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_kernel_middleware_alias_resolves_to_its_throttling_class(): void
    {
        $kernel = <<<'PHP'
<?php

namespace App\Http;

use App\Http\Middleware\CapSignIns;
use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middlewareAliases = [
        'auth' => \App\Http\Middleware\Authenticate::class,
        'signin.cap' => CapSignIns::class,
    ];
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SignInController;

Route::post('/signin', [SignInController::class, 'store'])->middleware('signin.cap:5,1');
Route::post('/admin/signin', [SignInController::class, 'store'])->middleware('auth');
PHP;

        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => $kernel,
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/admin/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function fileGroupRegistrations(): array
    {
        return [
            'base_path()' => ["Route::middleware(CapSignIns::class)->group(base_path('routes/signin.php'));"],
            'require in closure' => ["Route::middleware(CapSignIns::class)->group(function () {\n    require __DIR__.'/signin.php';\n});"],
            'attribute array' => ["Route::group(['middleware' => [CapSignIns::class]], base_path('routes/signin.php'));"],
        ];
    }

    #[DataProvider('fileGroupRegistrations')]
    public function test_group_middleware_covers_the_route_file_it_registers(string $registration): void
    {
        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Middleware\\CapSignIns;\n\n{$registration}\n",
            'routes/signin.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', [SignInController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_group_middleware_a_provider_registers_covers_the_route_file(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use App\Http\Middleware\CapSignIns;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider
{
    public function boot(): void
    {
        Route::middleware(['web', CapSignIns::class])->group(base_path('routes/signin.php'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'app/Providers/RouteServiceProvider.php' => $provider,
            'routes/web.php' => '<?php',
            'routes/signin.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', [SignInController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_group_middleware_that_does_not_throttle_covers_nothing_in_the_route_file(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Middleware/TrackVisits.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass TrackVisits\n{\n    public function handle(\$request, \$next)\n    {\n        return \$next(\$request);\n    }\n}\n",
            'routes/web.php' => "<?php\n\nuse App\\Http\\Middleware\\TrackVisits;\n\nRoute::middleware(TrackVisits::class)->group(base_path('routes/signin.php'));\n",
            'routes/signin.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', [SignInController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_controller_group_covers_the_route_file_it_registers(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/SessionGate.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Auth', 'SessionGate'),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\Auth\\SessionGate;\n\nRoute::controller(SessionGate::class)->group(base_path('routes/signin.php'));\n",
            'routes/signin.php' => "<?php\n\nRoute::post('/signin', 'store');\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function kernelMiddlewareGroupNames(): array
    {
        return [
            'class entry' => ['signin'],
            'alias entry' => ['guarded'],
        ];
    }

    #[DataProvider('kernelMiddlewareGroupNames')]
    public function test_kernel_middleware_group_resolves_to_its_throttling_classes(string $group): void
    {
        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => $this->kernelWithMiddlewareGroups(),
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', [SignInController::class, 'store'])->middleware('{$group}');\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_kernel_middleware_group_that_names_itself_covers_nothing(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => $this->kernelWithMiddlewareGroups(),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', [SignInController::class, 'store'])->middleware('loop');\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_bootstrap_middleware_group_resolves_to_its_throttling_classes(): void
    {
        $bootstrap = <<<'PHP'
<?php

use App\Http\Middleware\CapSignIns;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->appendToGroup('signin', [CapSignIns::class]);
    })
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', [SignInController::class, 'store'])->middleware('signin');\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_middleware_the_route_removes_does_not_cover_it(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SignInController;
use App\Http\Middleware\CapSignIns;

Route::post('/signin', [SignInController::class, 'store'])->withoutMiddleware(CapSignIns::class);
PHP;

        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_login_route_chained_after_another_route_call_is_reported(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SignInController;

Route::middleware('guest')->post('/signin', [SignInController::class, 'store']);
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
        $this->assertSame(5, $result->getIssues()[0]->location?->line);
    }

    public function test_login_route_chained_across_lines_is_reported_on_its_verb(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SignInController;

Route::middleware('guest')
    ->name('signin')
    ->post('/signin', [SignInController::class, 'store']);
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
        $this->assertSame(7, $result->getIssues()[0]->location?->line);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function chainedThrottles(): array
    {
        return [
            'throttle alias before the verb' => ["Route::middleware('throttle:6,1')->post('/signin', [SignInController::class, 'store']);"],
            'throttle alias on an earlier line' => ["Route::middleware(['guest', 'throttle:6,1'])\n    ->post('/signin', [SignInController::class, 'store']);"],
            'middleware class before the verb' => ["Route::middleware(CapSignIns::class)->post('/signin', [SignInController::class, 'store']);"],
            'middleware class after a chained verb' => ["Route::prefix('account')->post('/signin', [SignInController::class, 'store'])->middleware(CapSignIns::class);"],
        ];
    }

    #[DataProvider('chainedThrottles')]
    public function test_throttle_on_a_chained_login_route_covers_it(string $route): void
    {
        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\nuse App\\Http\\Middleware\\CapSignIns;\n\n{$route}\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_chained_login_route_is_judged_for_the_method_it_calls(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Api/TokenController.php' => $this->tokenController(
                "public function __construct()\n    {\n        \$this->middleware('throttle:5,1')->only('refresh');\n    }"
            ),
            'routes/api.php' => "<?php\n\nuse App\\Http\\Controllers\\Api\\TokenController;\n\nRoute::prefix('v1')->post('/token', [TokenController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/token" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_chained_login_route_is_credited_with_middleware_registered_for_its_method(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Api/TokenController.php' => $this->tokenController(
                "public function __construct()\n    {\n        \$this->middleware('throttle:5,1')->only('store');\n    }"
            ),
            'routes/api.php' => "<?php\n\nuse App\\Http\\Controllers\\Api\\TokenController;\n\nRoute::prefix('v1')->post('/token', [TokenController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_chained_login_route_reads_its_chain_from_its_own_verb(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\HomeController;
use App\Http\Controllers\SignInController;

Route::get('/', [HomeController::class, 'index'])->name('home'); Route::middleware('guest')->post('/signin', [SignInController::class, 'store'])
    ->middleware('throttle:6,1');
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertPassed($result);
    }

    public function test_chained_match_route_reads_its_uri_after_the_methods(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SignInController;

Route::middleware('guest')->match(['get', 'post'], '/signin', [SignInController::class, 'store']);
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_chained_routes_follow_the_web_and_api_route_rules(): void
    {
        $result = $this->analyzeRoutesOnly([
            'routes/web.php' => "<?php\n\nRoute::middleware('guest')->get('/signin', fn () => view('signin'));\nRoute::middleware('auth')->post('/auth/logout', fn () => Auth::logout());\n",
            'routes/api.php' => "<?php\n\nRoute::middleware('guest')->post('/session/token', fn () => 'token');\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/session/token" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_verb_chained_on_something_other_than_route_is_not_a_route(): void
    {
        $routes = <<<'PHP'
<?php

use Illuminate\Support\Facades\Http;

Route::get('/proxy', fn () => Http::acceptJson()->post('https://id.example.test/signin', ['user' => 'demo']));
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertPassed($result);
    }

    public function test_bootstrap_middleware_alias_covers_a_group(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\SignInController;

Route::middleware(['guest', 'signin.cap'])->group(function () {
    Route::post('/signin', [SignInController::class, 'store']);
});
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->alias(['signin.cap' => \\App\\Http\\Middleware\\CapSignIns::class]);"),
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'routes/web.php' => $routes,
        ]);

        $this->assertPassed($result);
    }

    public function test_route_to_a_controller_whose_parent_throttles_passes(): void
    {
        $parent = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Support\Facades\RateLimiter;

abstract class GuardedSignIn
{
    public function store()
    {
        abort_if(RateLimiter::tooManyAttempts('sign-in|'.request()->ip(), 5), 429);
    }
}
PHP;

        $routes = <<<'PHP'
<?php

use App\Http\Controllers\Admin\StaffSignInController;

Route::post('/staff/signin', [StaffSignInController::class, 'store']);
PHP;

        $child = <<<'PHP'
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Auth\GuardedSignIn;

class StaffSignInController extends GuardedSignIn
{
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/GuardedSignIn.php' => $parent,
            'app/Http/Controllers/Admin/StaffSignInController.php' => $child,
            'routes/web.php' => $routes,
        ]);

        $this->assertPassed($result);
    }

    public function test_route_to_a_controller_whose_parent_uses_authenticates_users_passes(): void
    {
        $parent = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Foundation\Auth\AuthenticatesUsers;

abstract class GuardSignIn
{
    use AuthenticatesUsers;
}
PHP;

        $child = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

class StaffSignInController extends GuardSignIn
{
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/GuardSignIn.php' => $parent,
            'app/Http/Controllers/Auth/StaffSignInController.php' => $child,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\Auth\\StaffSignInController;\n\nRoute::post('/staff/login', [StaffSignInController::class, 'login']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_route_to_a_controller_whose_parent_does_not_throttle_is_flagged(): void
    {
        $parent = <<<'PHP'
<?php

namespace App\Http\Controllers;

abstract class Controller
{
}
PHP;

        $child = <<<'PHP'
<?php

namespace App\Http\Controllers;

class SignInController extends Controller
{
    public function store()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Controller.php' => $parent,
            'app/Http/Controllers/SignInController.php' => $child,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', [SignInController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_inheritance_cycle_ends_and_reports_the_route(): void
    {
        $first = "<?php\n\nnamespace App\\Http\\Controllers;\n\nclass SignInController extends StaffSignInController\n{\n}\n";
        $second = "<?php\n\nnamespace App\\Http\\Controllers;\n\nclass StaffSignInController extends SignInController\n{\n}\n";

        $result = $this->analyzeApp([
            'app/Http/Controllers/SignInController.php' => $first,
            'app/Http/Controllers/StaffSignInController.php' => $second,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', [SignInController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_constructor_middleware_class_covers_the_controllers_routes(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Http\Middleware\CapSignIns;

class SignInController
{
    public function __construct()
    {
        $this->middleware(CapSignIns::class);
    }

    public function store()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'app/Http/Controllers/SignInController.php' => $controller,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', [SignInController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_has_middleware_declaration_covers_the_controllers_routes(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Http\Middleware\CapSignIns;
use Illuminate\Routing\Controllers\HasMiddleware;
use Illuminate\Routing\Controllers\Middleware;

class SignInController implements HasMiddleware
{
    public static function middleware(): array
    {
        return [new Middleware(CapSignIns::class)];
    }

    public function store()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'app/Http/Controllers/SignInController.php' => $controller,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', [SignInController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_constructor_middleware_that_does_not_throttle_covers_nothing(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

class SignInController
{
    public function __construct()
    {
        $this->middleware('guest');
    }

    public function store()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/SignInController.php' => $controller,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', [SignInController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @dataProvider controllerMiddlewareCoveringLogin
     */
    #[DataProvider('controllerMiddlewareCoveringLogin')]
    public function test_controller_check_credits_registered_middleware_that_reaches_login(string $registration): void
    {
        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'app/Http/Controllers/Auth/LoginController.php' => $this->loginControllerWith($registration),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function controllerMiddlewareCoveringLogin(): array
    {
        return [
            'constructor, every method' => ['public function __construct() { $this->middleware(CapSignIns::class); }'],
            'constructor, only login' => ['public function __construct() { $this->middleware(CapSignIns::class)->only(\'login\'); }'],
            'constructor, only as varargs' => ['public function __construct() { $this->middleware(CapSignIns::class)->only(\'logout\', \'login\'); }'],
            'constructor, except another method' => ['public function __construct() { $this->middleware(CapSignIns::class)->except([\'logout\']); }'],
            'HasMiddleware, named only' => ['public static function middleware(): array { return [new Middleware(CapSignIns::class, only: [\'login\'])]; }'],
            'HasMiddleware, positional only' => ['public static function middleware(): array { return [new Middleware(CapSignIns::class, [\'login\'])]; }'],
            'HasMiddleware, bare class' => ['public static function middleware(): array { return [CapSignIns::class]; }'],
        ];
    }

    /**
     * @dataProvider controllerMiddlewareMissingLogin
     */
    #[DataProvider('controllerMiddlewareMissingLogin')]
    public function test_controller_check_reports_login_that_registered_middleware_skips(string $registration): void
    {
        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'app/Http/Controllers/Auth/LoginController.php' => $this->loginControllerWith($registration),
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Authentication method LoginController::login() lacks rate limiting'], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function controllerMiddlewareMissingLogin(): array
    {
        return [
            'constructor, only another method' => ['public function __construct() { $this->middleware(CapSignIns::class)->only(\'logout\'); }'],
            'constructor, except login' => ['public function __construct() { $this->middleware(CapSignIns::class)->except(\'login\'); }'],
            'HasMiddleware, named except' => ['public static function middleware(): array { return [new Middleware(CapSignIns::class, except: [\'login\'])]; }'],
            'HasMiddleware, positional except' => ['public static function middleware(): array { return [new Middleware(CapSignIns::class, null, [\'login\'])]; }'],
            'constructor, a middleware that does not throttle' => ['public function __construct() { $this->middleware(\'guest\'); }'],
        ];
    }

    /**
     * @dataProvider controllerMiddlewareCoveringLogin
     */
    #[DataProvider('controllerMiddlewareCoveringLogin')]
    public function test_route_check_credits_registered_middleware_that_reaches_the_routed_method(string $registration): void
    {
        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'app/Http/Controllers/Auth/LoginController.php' => $this->loginControllerWith($registration),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\Auth\\LoginController;\n\nRoute::post('/login', [LoginController::class, 'login']);\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * @dataProvider controllerMiddlewareMissingLogin
     */
    #[DataProvider('controllerMiddlewareMissingLogin')]
    public function test_route_check_reports_a_route_whose_method_registered_middleware_skips(string $registration): void
    {
        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'app/Http/Controllers/Auth/LoginController.php' => $this->loginControllerWith($registration),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\Auth\\LoginController;\n\nRoute::post('/login', [LoginController::class, 'login']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertContains('Login route "/login" lacks rate limiting protection', $this->issueMessages($result));
    }

    public function test_route_check_reads_the_method_of_a_string_action(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'app/Http/Controllers/Auth/LoginController.php' => $this->loginControllerWith('public function __construct() { $this->middleware(CapSignIns::class)->only(\'logout\'); }'),
            'routes/web.php' => "<?php\n\nRoute::post('/login', 'Auth\\LoginController@login');\n",
        ]);

        $this->assertFailed($result);
        $this->assertContains('Login route "/login" lacks rate limiting protection', $this->issueMessages($result));
    }

    public function test_controller_group_route_is_judged_by_the_method_it_names(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\Auth\LoginController;

Route::controller(LoginController::class)->group(function () {
    Route::post('/login', 'login');
    Route::post('/logout', 'logout');
});
PHP;

        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'app/Http/Controllers/Auth/LoginController.php' => $this->loginControllerWith('public function __construct() { $this->middleware(CapSignIns::class)->only(\'logout\'); }'),
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertContains('Login route "/login" lacks rate limiting protection', $this->issueMessages($result));
    }

    public function test_route_check_does_not_credit_a_parent_method_the_controller_overrides(): void
    {
        $parent = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Support\Facades\RateLimiter;

abstract class GuardedSignIn
{
    public function store()
    {
        abort_if(RateLimiter::tooManyAttempts('sign-in|'.request()->ip(), 5), 429);
    }
}
PHP;

        $child = <<<'PHP'
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Auth\GuardedSignIn;

class StaffSignInController extends GuardedSignIn
{
    public function store()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/GuardedSignIn.php' => $parent,
            'app/Http/Controllers/Admin/StaffSignInController.php' => $child,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\Admin\\StaffSignInController;\n\nRoute::post('/staff/signin', [StaffSignInController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/staff/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_route_check_does_not_credit_authenticates_users_for_a_login_method_the_controller_declares(): void
    {
        $parent = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Foundation\Auth\AuthenticatesUsers;

abstract class GuardSignIn
{
    use AuthenticatesUsers;
}
PHP;

        $child = <<<'PHP'
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Auth\GuardSignIn;

class StaffSignInController extends GuardSignIn
{
    public function login()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/GuardSignIn.php' => $parent,
            'app/Http/Controllers/Admin/StaffSignInController.php' => $child,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\Admin\\StaffSignInController;\n\nRoute::post('/staff/login', [StaffSignInController::class, 'login']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/staff/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_route_check_does_not_credit_a_used_authenticates_users_for_a_login_method_the_class_declares(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers\Admin;

use Illuminate\Foundation\Auth\AuthenticatesUsers;

class StaffSignInController
{
    use AuthenticatesUsers;

    public function login()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Admin/StaffSignInController.php' => $controller,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\Admin\\StaffSignInController;\n\nRoute::post('/staff/login', [StaffSignInController::class, 'login']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/staff/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_invokable_route_is_judged_by_the_middleware_that_reaches_invoke(): void
    {
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Http\Middleware\CapSignIns;

class SignInController
{
    public function __construct()
    {
        $this->middleware(CapSignIns::class)->only('store');
    }

    public function __invoke()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'app/Http/Controllers/SignInController.php' => $controller,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', SignInController::class);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_route_check_credits_parent_middleware_for_a_method_the_controller_overrides(): void
    {
        $parent = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Middleware\CapSignIns;

abstract class GuardedSignIn
{
    public function __construct()
    {
        $this->middleware(CapSignIns::class);
    }
}
PHP;

        $child = <<<'PHP'
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Auth\GuardedSignIn;

class StaffSignInController extends GuardedSignIn
{
    public function store()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Middleware/CapSignIns.php' => $this->throttlingMiddleware('CapSignIns'),
            'app/Http/Controllers/Auth/GuardedSignIn.php' => $parent,
            'app/Http/Controllers/Admin/StaffSignInController.php' => $child,
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\Admin\\StaffSignInController;\n\nRoute::post('/staff/signin', [StaffSignInController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_controller_check_does_not_credit_a_parent_for_a_login_method_the_controller_declares(): void
    {
        $parent = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Foundation\Auth\AuthenticatesUsers;

abstract class GuardSignIn
{
    use AuthenticatesUsers;
}
PHP;

        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

class LoginController extends GuardSignIn
{
    public function login()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/GuardSignIn.php' => $parent,
            'app/Http/Controllers/Auth/LoginController.php' => $controller,
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Authentication method LoginController::login() lacks rate limiting'], $this->issueMessages($result));
    }

    // ==================== Fortify is judged on its own route (#487) ====================

    public function test_throttling_auth_controller_does_not_excuse_an_unthrottled_fortify_pipeline(): void
    {
        $config = <<<'PHP'
<?php

use Laravel\Fortify\Actions\AttemptToAuthenticate;
use Laravel\Fortify\Actions\PrepareAuthenticatedSession;

return [
    'guard' => 'web',
    'pipelines' => [
        'login' => [AttemptToAuthenticate::class, PrepareAuthenticatedSession::class],
    ],
];
PHP;

        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => $config,
            'app/Http/Controllers/Auth/SessionController.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Auth', 'SessionController'),
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Fortify login pipeline does not throttle login attempts'], $this->issueMessages($result));
    }

    public function test_throttling_auth_controller_does_not_excuse_disabled_fortify_throttling(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;

class FortifyServiceProvider
{
    public function boot(): void
    {
        RateLimiter::for('login', fn () => Limit::none());
    }
}
PHP;

        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => self::FORTIFY_CONFIG,
            'app/Providers/FortifyServiceProvider.php' => $provider,
            'app/Http/Controllers/Auth/SessionController.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Auth', 'SessionController'),
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Fortify login throttling is explicitly disabled'], $this->issueMessages($result));
    }

    public function test_web_group_throttle_still_covers_fortify(): void
    {
        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => "<?php\n\nreturn ['guard' => 'web'];\n",
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->web(append: \\Illuminate\\Routing\\Middleware\\ThrottleRequests::class.':60,1');"),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_limit_none_on_another_limiter_is_not_disabled_login_throttling(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;

class AppServiceProvider
{
    public function boot(): void
    {
        RateLimiter::for('login', fn () => Limit::perMinute(5));

        RateLimiter::for('reports', function ($request) {
            return $request->user()?->is_staff ? Limit::none() : Limit::perMinute(30);
        });
    }
}
PHP;

        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => self::FORTIFY_CONFIG,
            'app/Providers/AppServiceProvider.php' => $provider,
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_limit_none_inside_the_login_limiter_is_disabled_throttling_after_another_limiter(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;

class AppServiceProvider
{
    public function boot(): void
    {
        RateLimiter::for('reports', fn () => Limit::perMinute(30));

        RateLimiter::for('login', function () {
            return Limit::none();
        });
    }
}
PHP;

        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => self::FORTIFY_CONFIG,
            'app/Providers/AppServiceProvider.php' => $provider,
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Fortify login throttling is explicitly disabled'], $this->issueMessages($result));
    }

    public function test_fortify_check_is_skipped_when_fortify_routes_are_ignored(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Laravel\Fortify\Fortify;

class FortifyServiceProvider
{
    public function register(): void
    {
        Fortify::ignoreRoutes();
    }
}
PHP;

        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'app/Providers/FortifyServiceProvider.php' => $provider,
            'config/fortify.php' => "<?php\n\nreturn ['guard' => 'web'];\n",
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\SignInController;\n\nRoute::post('/signin', [SignInController::class, 'store']);\n",
        ]);

        // Fortify registers no login route, so only the app's own route is judged
        $this->assertFailed($result);
        $this->assertSame(['Login route "/signin" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_commented_out_ignore_routes_does_not_skip_the_fortify_check(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Laravel\Fortify\Fortify;

class FortifyServiceProvider
{
    public function register(): void
    {
        // Fortify::ignoreRoutes();
    }
}
PHP;

        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'app/Providers/FortifyServiceProvider.php' => $provider,
            'config/fortify.php' => $this->unthrottledFortifyPipelineConfig(),
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Fortify login pipeline does not throttle login attempts'], $this->issueMessages($result));
    }

    private function loginControllerWith(string $registration): string
    {
        return str_replace('REGISTRATION', $registration, <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Middleware\CapSignIns;
use Illuminate\Routing\Controllers\HasMiddleware;
use Illuminate\Routing\Controllers\Middleware;

class LoginController implements HasMiddleware
{
    REGISTRATION

    public function login()
    {
        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP);
    }

    private function throttlingMiddleware(string $class): string
    {
        return str_replace('CLASS', $class, <<<'PHP'
<?php

namespace App\Http\Middleware;

use Illuminate\Support\Facades\RateLimiter;

class CLASS
{
    public function handle($request, $next)
    {
        abort_if(RateLimiter::tooManyAttempts('sign-in|'.$request->ip(), 5), 429);

        return $next($request);
    }
}
PHP);
    }

    private function sessionControllerCallingEnsureIsNotRateLimited(): string
    {
        return <<<'PHP'
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Requests\Auth\LoginRequest;

class AuthenticatedSessionController
{
    public function store(LoginRequest $request)
    {
        $request->ensureIsNotRateLimited();

        return redirect()->intended('/dashboard');
    }
}
PHP;
    }

    private function selfThrottlingController(string $namespace, string $class): string
    {
        return str_replace(['NAMESPACE', 'CLASS'], [$namespace, $class], <<<'PHP'
<?php

namespace NAMESPACE;

use Illuminate\Support\Facades\RateLimiter;

class CLASS
{
    public function store()
    {
        abort_if(RateLimiter::tooManyAttempts('sign-in|'.request()->ip(), 5), 429);

        return Auth::attempt(request()->only('email', 'password'));
    }
}
PHP);
    }

    /**
     * A FortifyServiceProvider whose boot() runs the given statements.
     */
    private function unthrottledFortifyPipelineConfig(): string
    {
        return <<<'PHP'
<?php

use Laravel\Fortify\Actions\AttemptToAuthenticate;
use Laravel\Fortify\Actions\PrepareAuthenticatedSession;

return [
    'guard' => 'web',
    'pipelines' => [
        'login' => [AttemptToAuthenticate::class, PrepareAuthenticatedSession::class],
    ],
];
PHP;
    }

    private function fortifyPipelineProvider(string $steps): string
    {
        return <<<PHP
<?php

namespace App\\Providers;

use Laravel\\Fortify\\Actions\\AttemptToAuthenticate;
use Laravel\\Fortify\\Actions\\EnsureLoginIsNotThrottled;
use Laravel\\Fortify\\Fortify;

class FortifyServiceProvider
{
    public function boot(): void
    {
        Fortify::authenticateThrough(function (\$request) {
            return array_filter([
                {$steps}
            ]);
        });
    }
}
PHP;
    }

    /**
     * App\Http\Controllers\Api\TokenController, whose store() does not throttle,
     * with $extra added as further class members.
     */
    private function tokenController(string $extra): string
    {
        return <<<PHP
<?php

namespace App\\Http\\Controllers\\Api;

use Illuminate\\Routing\\Controllers\\Middleware;
use Illuminate\\Routing\\Middleware\\ThrottleRequests;
use Illuminate\\Routing\\Middleware\\ThrottleRequestsWithRedis;
use Illuminate\\Support\\Facades\\RateLimiter;

class TokenController
{
    {$extra}

    public function store()
    {
        return 'token';
    }
}
PHP;
    }

    private function kernelWithMiddlewareGroups(): string
    {
        return <<<'PHP'
<?php

namespace App\Http;

use App\Http\Middleware\CapSignIns;
use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middlewareGroups = [
        'web' => [],
        'signin' => [CapSignIns::class],
        'guarded' => ['signin.cap'],
        'loop' => ['loop'],
    ];

    protected $middlewareAliases = [
        'signin.cap' => CapSignIns::class,
    ];
}
PHP;
    }

    private function fortifyProvider(string $boot): string
    {
        return <<<PHP
<?php

namespace App\\Providers;

use Illuminate\\Cache\\RateLimiting\\Limit;
use Illuminate\\Support\\Facades\\RateLimiter;

class FortifyServiceProvider
{
    public function boot(): void
    {
        {$boot}
    }
}
PHP;
    }

    /**
     * @param  array<string, string>  $files
     */
    private function analyzeRoutesOnly(array $files): ResultInterface
    {
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($this->createTempDirectory($files));
        $analyzer->setPaths(['app', 'bootstrap', 'config', 'routes']);

        return $analyzer->analyze();
    }

    public function test_limit_none_on_a_login_limiter_the_fortify_config_never_names_is_not_reported(): void
    {
        // Without limiters.login Fortify throttles in its login pipeline and never
        // reads the 'login' limiter, so disabling that limiter changes nothing.
        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => "<?php\n\nreturn ['guard' => 'web'];\n",
            'app/Providers/FortifyServiceProvider.php' => $this->fortifyProvider("RateLimiter::for('login', fn () => Limit::none());"),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_null_fortify_login_limiter_leaves_the_pipeline_throttle(): void
    {
        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => "<?php\n\nreturn ['limiters' => ['login' => null, 'two-factor' => 'two-factor']];\n",
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_unpublished_fortify_config_leaves_the_pipeline_throttle(): void
    {
        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_empty_fortify_login_limiter_still_reads_the_login_pipeline(): void
    {
        $config = <<<'PHP'
<?php

use Laravel\Fortify\Actions\AttemptToAuthenticate;

return [
    'limiters' => ['login' => ''],
    'pipelines' => ['login' => [AttemptToAuthenticate::class]],
];
PHP;

        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => $config,
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Fortify login pipeline does not throttle login attempts'], $this->issueMessages($result));
        $this->assertSame('config/fortify.php', $result->getIssues()[0]->location?->file);
    }

    public function test_authenticate_through_without_the_throttle_step_is_reported(): void
    {
        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'app/Providers/FortifyServiceProvider.php' => $this->fortifyPipelineProvider('AttemptToAuthenticate::class,'),
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Fortify login pipeline does not throttle login attempts'], $this->issueMessages($result));
        $this->assertSame('app/Providers/FortifyServiceProvider.php', $result->getIssues()[0]->location?->file);
    }

    public function test_authenticate_through_with_the_documented_conditional_throttle_step_passes(): void
    {
        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'app/Providers/FortifyServiceProvider.php' => $this->fortifyPipelineProvider(
                "config('fortify.limiters.login') ? null : EnsureLoginIsNotThrottled::class,\n                AttemptToAuthenticate::class,"
            ),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_authenticate_through_replaces_the_config_pipeline(): void
    {
        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => $this->unthrottledFortifyPipelineConfig(),
            'app/Providers/FortifyServiceProvider.php' => $this->fortifyPipelineProvider(
                "EnsureLoginIsNotThrottled::class,\n                AttemptToAuthenticate::class,"
            ),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_route_limiter_covers_a_custom_pipeline_without_the_throttle_step(): void
    {
        $config = <<<'PHP'
<?php

use Laravel\Fortify\Actions\AttemptToAuthenticate;

return [
    'limiters' => ['login' => 'login'],
    'pipelines' => ['login' => [AttemptToAuthenticate::class]],
];
PHP;

        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => $config,
            'app/Providers/FortifyServiceProvider.php' => $this->fortifyProvider("RateLimiter::for('login', fn () => Limit::perMinute(5));"),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_fortify_login_limiter_named_by_env_throttles_fortify(): void
    {
        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => "<?php\n\nreturn ['limiters' => ['login' => env('FORTIFY_LOGIN_LIMITER', 'login')]];\n",
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_limit_none_on_the_limiter_the_fortify_config_names_is_disabled_throttling(): void
    {
        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => "<?php\n\nreturn ['limiters' => ['login' => 'sign-in']];\n",
            'app/Providers/FortifyServiceProvider.php' => $this->fortifyProvider("RateLimiter::for('sign-in', fn () => Limit::none());"),
            'routes/web.php' => '<?php',
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Fortify login throttling is explicitly disabled'], $this->issueMessages($result));
    }

    public function test_limit_none_on_a_login_limiter_fortify_does_not_use_is_not_disabled_throttling(): void
    {
        $result = $this->analyzeApp([
            'composer.lock' => '{"packages": [{"name": "laravel/fortify", "version": "1.0.0"}]}',
            'config/fortify.php' => "<?php\n\nreturn ['limiters' => ['login' => 'sign-in']];\n",
            'app/Providers/FortifyServiceProvider.php' => $this->fortifyProvider(
                "RateLimiter::for('sign-in', fn () => Limit::perMinute(5));\n        RateLimiter::for('login', fn () => Limit::none());"
            ),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }
}
