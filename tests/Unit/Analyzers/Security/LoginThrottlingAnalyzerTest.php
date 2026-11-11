<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\Security\LoginThrottlingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class LoginThrottlingAnalyzerTest extends AnalyzerTestCase
{
    /** The limiters config fortify:install publishes */
    /** A login route grouped under a held registrar, with a statement between them */
    private const HELD = "<?php\nuse Illuminate\\Support\\Facades\\Route;\n\$r = Route::middleware('throttle:5,1');\n%s\n\$r->group(function () {\n    Route::post('/login', [LoginController::class, 'login']);\n});\n";

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
            'web append using' => ["\$middleware->web(append: [\\Illuminate\\Routing\\Middleware\\ThrottleRequests::using('login')]);"],
            'appendToGroup with' => ["\$middleware->appendToGroup('web', \\Illuminate\\Routing\\Middleware\\ThrottleRequests::with(5, 1));"],
            'chained after alias' => ["\$middleware->alias(['admin' => \\App\\Http\\Middleware\\Admin::class])->web(append: ['throttle:60,1']);"],
        ];
    }

    public function test_web_throttle_under_an_aliased_import_in_bootstrap_clears_web_login(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap(
                '$middleware->web(append: [Throttle::class]);',
                'use Illuminate\\Routing\\Middleware\\ThrottleRequests as Throttle;',
            ),
            'routes/web.php' => $this->unthrottledWebLogin(),
        ]);

        $this->assertPassed($result);
    }

    public function test_web_throttle_under_an_aliased_import_in_kernel_clears_web_login(): void
    {
        $kernel = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Routing\Middleware\ThrottleRequests as Throttle;

class Kernel extends HttpKernel
{
    protected $middlewareGroups = [
        'web' => [
            \Illuminate\Session\Middleware\StartSession::class,
            Throttle::class.':60,1',
        ],
    ];
}
PHP;

        // No RouteServiceProvider registers routes/web.php in the 'web' group, so the
        // route-level group resolution has nothing to read and only the group check
        // can clear the login.
        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => $kernel,
            'routes/web.php' => $this->unthrottledWebLogin(),
        ]);

        $this->assertPassed($result);
    }

    /**
     * No RouteServiceProvider registers routes/web.php in the 'web' group, so only the
     * group check can clear the login.
     *
     * @param  array<string, string>  $files
     *
     * @dataProvider resolvedWebGroupThrottleProvider
     */
    #[DataProvider('resolvedWebGroupThrottleProvider')]
    public function test_web_group_throttle_resolved_by_name_clears_web_login(array $files): void
    {
        $result = $this->analyzeApp($files + ['routes/web.php' => $this->unthrottledWebLogin()]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function resolvedWebGroupThrottleProvider(): array
    {
        return [
            'kernel alias' => [[
                'app/Http/Kernel.php' => self::appKernel(
                    "protected \$middlewareAliases = ['login.cap' => \\Illuminate\\Routing\\Middleware\\ThrottleRequests::class];\n"
                    ."    protected \$middlewareGroups = ['web' => [\\Illuminate\\Session\\Middleware\\StartSession::class, 'login.cap:5,1']];"
                ),
            ]],
            'bootstrap alias' => [[
                'bootstrap/app.php' => self::laravel11Bootstrap(
                    "\$middleware->alias(['login.cap' => \\Illuminate\\Routing\\Middleware\\ThrottleRequests::class])->web(append: ['login.cap:5,1']);"
                ),
            ]],
            'nested group' => [[
                'app/Http/Kernel.php' => self::appKernel(
                    "protected \$middlewareGroups = ['web' => ['login-limits'], 'login-limits' => ['throttle:5,1']];"
                ),
            ]],
            'app subclass of ThrottleRequests' => [[
                'app/Http/Kernel.php' => self::appKernel(
                    "protected \$middlewareGroups = ['web' => [\\App\\Http\\Middleware\\ThrottleRequests::class.':5,1']];"
                ),
                'app/Http/Middleware/ThrottleRequests.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nuse Illuminate\\Routing\\Middleware\\ThrottleRequests as BaseThrottleRequests;\n\nclass ThrottleRequests extends BaseThrottleRequests\n{\n}\n",
            ]],
            'throttle alias re-registered to a package class' => [[
                'app/Http/Kernel.php' => self::appKernel(
                    "protected \$middlewareAliases = ['throttle' => \\Acme\\Limits\\Throttle::class];\n"
                    ."    protected \$middlewareGroups = ['web' => ['throttle:60,1']];"
                ),
            ]],
        ];
    }

    /**
     * @param  array<string, string>  $files
     *
     * @dataProvider unresolvedWebGroupThrottleProvider
     */
    #[DataProvider('unresolvedWebGroupThrottleProvider')]
    public function test_web_group_middleware_that_only_names_a_throttle_does_not_clear_web_login(array $files): void
    {
        $result = $this->analyzeApp($files + ['routes/web.php' => $this->unthrottledWebLogin()]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function unresolvedWebGroupThrottleProvider(): array
    {
        return [
            'app class with the name in it' => [[
                'app/Http/Kernel.php' => self::appKernel(
                    "protected \$middlewareGroups = ['web' => [\\App\\Http\\Middleware\\ThrottleRequestsAudit::class]];"
                ),
                'app/Http/Middleware/ThrottleRequestsAudit.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass ThrottleRequestsAudit\n{\n    public function handle(\$request, \\Closure \$next)\n    {\n        logger()->info('request', ['path' => \$request->path()]);\n\n        return \$next(\$request);\n    }\n}\n",
            ]],
            'unregistered alias with the word in it' => [[
                'app/Http/Kernel.php' => self::appKernel("protected \$middlewareGroups = ['web' => ['skip-throttle']];"),
            ]],
            'throttle alias re-registered to a non-throttle' => [[
                'app/Http/Kernel.php' => self::appKernel(
                    "protected \$middlewareAliases = ['throttle' => \\App\\Http\\Middleware\\NoopThrottle::class];\n"
                    ."    protected \$middlewareGroups = ['web' => ['throttle:60,1']];"
                ),
                'app/Http/Middleware/NoopThrottle.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass NoopThrottle\n{\n    public function handle(\$request, \\Closure \$next)\n    {\n        return \$next(\$request);\n    }\n}\n",
            ]],
        ];
    }

    /**
     * The login route sits far enough inside its group that no line of the group's
     * opening falls in the window the per-line throttle check reads.
     *
     * @param  array<string, string>  $files
     *
     * @dataProvider throttleClassGroupProvider
     */
    #[DataProvider('throttleClassGroupProvider')]
    public function test_throttle_class_on_the_route_group_covers_the_login_controller(array $files): void
    {
        $result = $this->analyzeApp($files + [
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function throttleClassGroupProvider(): array
    {
        $sessionRoutes = "<?php\n\nuse App\\Http\\Controllers\\Auth\\LoginController;\n\nRoute::post('/session/login', [LoginController::class, 'login']);\n";
        $bootstrap = static fn (string $registration): string => "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Routing\\Middleware\\ThrottleRequests;\nuse Illuminate\\Support\\Facades\\Route;\n\n"
            ."return Application::configure(basePath: dirname(__DIR__))\n    ->withRouting(\n        web: __DIR__.'/../routes/web.php',\n        then: function () {\n            {$registration}\n        },\n    )\n    ->create();\n";

        return [
            'in-file group on an aliased import' => [[
                'routes/web.php' => self::groupedLoginRoutes('Route::middleware(Cap::class)->group(function () {'),
            ]],
            'in-file group on ::using()' => [[
                'routes/web.php' => self::groupedLoginRoutes("Route::middleware(['web', ThrottleRequests::using('login')])->group(function () {"),
            ]],
            'in-file array-form group' => [[
                'routes/web.php' => self::groupedLoginRoutes("Route::group(['middleware' => ThrottleRequests::class], function () {"),
            ]],
            'bootstrap registration on ::using()' => [[
                'bootstrap/app.php' => $bootstrap("Route::middleware(['web', ThrottleRequests::using('login')])->group(base_path('routes/session.php'));"),
                'routes/web.php' => '<?php',
                'routes/session.php' => $sessionRoutes,
            ]],
            'bootstrap array-form registration' => [[
                'bootstrap/app.php' => $bootstrap("Route::group(['middleware' => ['web', ThrottleRequests::class]], base_path('routes/session.php'));"),
                'routes/web.php' => '<?php',
                'routes/session.php' => $sessionRoutes,
            ]],
            'in-file group given a list' => [[
                'routes/web.php' => str_replace("\n});", "\n}]);", self::groupedLoginRoutes('Route::middleware(ThrottleRequests::class)->group([function () {')),
            ]],
            'bootstrap registration of a list' => [[
                'bootstrap/app.php' => $bootstrap("Route::middleware(['web', ThrottleRequests::class])->group([base_path('routes/orders.php'), base_path('routes/session.php')]);"),
                'routes/web.php' => '<?php',
                'routes/orders.php' => '<?php',
                'routes/session.php' => $sessionRoutes,
            ]],
        ];
    }

    public function test_route_files_listed_on_an_api_group_are_graded_as_api_routes(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->bootstrapThen("Route::prefix('api')->middleware('api')->group([base_path('routes/partner.php'), base_path('routes/mobile.php')]);"),
            'routes/web.php' => '<?php',
            'routes/partner.php' => "<?php\n\nRoute::post('/partner/login', [PartnerSessionController::class, 'store']);\n",
            'routes/mobile.php' => "<?php\n\nRoute::post('/mobile/login', [MobileSessionController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame([
            'API authentication route "/mobile/login" lacks rate limiting protection',
            'API authentication route "/partner/login" lacks rate limiting protection',
        ], $this->sortedIssueMessages($result));
    }

    public function test_throttle_on_a_group_given_a_list_covers_every_listed_file(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->bootstrapThen("Route::group(['middleware' => ['web', 'throttle:5,1']], [base_path('routes/partner.php'), __DIR__.'/../routes/mobile.php']);"),
            'routes/web.php' => '<?php',
            'routes/partner.php' => "<?php\n\nRoute::post('/partner/login', [PartnerSessionController::class, 'store']);\n",
            'routes/mobile.php' => "<?php\n\nRoute::post('/mobile/login', [MobileSessionController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_throttled_in_file_group_given_a_list_covers_each_closure(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('throttle:5,1')->group([function () {
    Route::post('/partner/login', [PartnerSessionController::class, 'store']);
}, fn () => Route::post('/mobile/login', [MobileSessionController::class, 'store'])]);
Route::middleware('auth')->group([function () {
    Route::post('/kiosk/login', [KioskSessionController::class, 'store']);
}]);
PHP;

        $result = $this->analyzeApp(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/kiosk/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @dataProvider throttledGroupRouteVariableProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('throttledGroupRouteVariableProvider')]
    public function test_throttle_on_a_group_given_its_routes_in_a_variable_covers_login(array $files): void
    {
        $result = $this->analyzeApp($files);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function throttledGroupRouteVariableProvider(): array
    {
        $bootstrap = fn (string $registration): string => <<<PHP
<?php

use Illuminate\\Foundation\\Application;
use Illuminate\\Support\\Facades\\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            {$registration}
        },
    )
    ->create();
PHP;
        $adminRoutes = "<?php\n\nRoute::post('/admin/login', [AdminSessionController::class, 'store']);\n";

        return [
            'bootstrap list variable' => [[
                'bootstrap/app.php' => $bootstrap("\$files = [base_path('routes/admin.php')]; Route::middleware(['web', 'throttle:5,1'])->group(\$files);"),
                'routes/web.php' => '<?php',
                'routes/admin.php' => $adminRoutes,
            ]],
            'bootstrap scalar variable' => [[
                'bootstrap/app.php' => $bootstrap("\$file = base_path('routes/admin.php'); Route::middleware(['web', 'throttle:5,1'])->group(\$file);"),
                'routes/web.php' => '<?php',
                'routes/admin.php' => $adminRoutes,
            ]],
            'route file path variable' => [[
                'routes/web.php' => "<?php\n\n\$f = base_path('routes/admin.php');\nRoute::middleware('throttle:5,1')->group(\$f);\n",
                'routes/admin.php' => $adminRoutes,
            ]],
        ];
    }

    public function test_route_file_held_in_a_variable_on_an_api_group_is_graded_as_api_routes(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->bootstrapThen("\$file = base_path('routes/mobile.php'); Route::middleware('api')->prefix('api')->group(\$file);"),
            'routes/web.php' => '<?php',
            'routes/mobile.php' => "<?php\n\nRoute::post('/mobile/login', [MobileSessionController::class, 'store']);\nRoute::post('/mobile/token', [MobileTokenController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame([
            'API authentication route "/mobile/login" lacks rate limiting protection',
            'API authentication route "/mobile/token" lacks rate limiting protection',
        ], $this->sortedIssueMessages($result));
    }

    public function test_throttle_group_given_a_closure_held_in_a_variable_does_not_cover_login(): void
    {
        // Only route paths held in a variable are read, so this is judged as before
        $routes = <<<'PHP'
<?php

$auth = function () {
    Route::post('/login', [LoginController::class, 'store']);
};
Route::middleware('throttle:5,1')->group($auth);
PHP;

        $result = $this->analyzeApp(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_route_file_a_branch_may_reassign_is_not_covered_by_the_throttle_group_given_its_variable(): void
    {
        $result = $this->analyzeApp([
            'routes/web.php' => "<?php\n\n\$f = base_path('routes/admin.php');\nif (app()->isLocal()) {\n    \$f = base_path('routes/mobile.php');\n}\nRoute::middleware('throttle:5,1')->group(\$f);\n",
            'routes/admin.php' => '<?php',
            'routes/mobile.php' => "<?php\n\nRoute::post('/mobile/login', [MobileSessionController::class, 'store']);\n",
        ]);

        // The group loads admin.php or mobile.php, so neither is known to be throttled
        $this->assertFailed($result);
        $this->assertSame(['Login route "/mobile/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_route_file_variable_written_in_one_branch_is_not_read_in_another(): void
    {
        $routes = <<<'PHP'
<?php

$f = base_path('routes/auth.php');
if (config('app.admin')) {
    $f = base_path('routes/admin.php');
    Route::middleware('web')->group($f);
} else {
    Route::middleware(['web', 'throttle:5,1'])->group($f);
}
PHP;

        $result = $this->analyzeApp([
            'routes/web.php' => $routes,
            'routes/auth.php' => '<?php',
            'routes/admin.php' => "<?php\n\nRoute::post('/admin/login', [AdminSessionController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/admin/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_app_alias_for_throttle_on_the_route_group_covers_the_login_controller(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => self::appKernel(
                "protected \$middlewareAliases = ['signin.cap' => \\Illuminate\\Routing\\Middleware\\ThrottleRequests::class];"
            ),
            'routes/web.php' => self::groupedLoginRoutes("Route::middleware('signin.cap')->group(function () {"),
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
        ]);

        $this->assertPassed($result);
    }

    public function test_throttle_alias_re_registered_to_a_non_throttle_does_not_cover_the_route_group(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => self::appKernel(
                "protected \$middlewareAliases = ['throttle' => \\App\\Http\\Middleware\\NoopThrottle::class];"
            ),
            'app/Http/Middleware/NoopThrottle.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass NoopThrottle\n{\n    public function handle(\$request, \\Closure \$next)\n    {\n        return \$next(\$request);\n    }\n}\n",
            'routes/web.php' => self::groupedLoginRoutes("Route::middleware('throttle:60,1')->group(function () {"),
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
        ]);

        $this->assertFailed($result);
        $this->assertSame([
            'Login route "/session/login" lacks rate limiting protection',
            'Authentication method LoginController::login() lacks rate limiting',
        ], $this->issueMessages($result));
    }

    /**
     * @param  array<string, string>  $files
     *
     * @dataProvider unreadableThrottleClassProvider
     */
    #[DataProvider('unreadableThrottleClassProvider')]
    public function test_throttle_re_registered_to_a_class_it_cannot_read_covers_the_route_group(array $files): void
    {
        $result = $this->analyzeApp($files + [
            'routes/web.php' => self::groupedLoginRoutes("Route::middleware('throttle:6,1')->group(function () {"),
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
        ]);

        $this->assertPassed($result);
    }

    /**
     * 'throttle' re-registered to a class the analyzer cannot read, or cannot read all of.
     *
     * @return array<string, array{array<string, string>}>
     */
    public static function unreadableThrottleClassProvider(): array
    {
        $kernel = static fn (string $class): string => self::appKernel("protected \$middlewareAliases = ['throttle' => {$class}::class];");
        $middleware = static fn (string $declaration): string => "<?php\n\nnamespace App\\Http\\Middleware;\n\n{$declaration}\n";

        return [
            'package class in bootstrap/app.php' => [[
                'bootstrap/app.php' => self::laravel11Bootstrap("\$middleware->alias(['throttle' => \\Acme\\Limits\\Throttle::class]);"),
            ]],
            'package class in the Kernel' => [[
                'app/Http/Kernel.php' => $kernel('\\Acme\\Limits\\Throttle'),
            ]],
            'app class with no file' => [[
                'app/Http/Kernel.php' => $kernel('\\App\\Http\\Middleware\\LimitAttempts'),
            ]],
            'app class whose file does not parse' => [[
                'app/Http/Kernel.php' => $kernel('\\App\\Http\\Middleware\\LimitAttempts'),
                'app/Http/Middleware/LimitAttempts.php' => $middleware("class LimitAttempts\n{\n    public function handle(\$request, \\Closure \$next)\n    {\n        return \$next(\$request)\n    }\n}"),
            ]],
            'app file that declares another class' => [[
                'app/Http/Kernel.php' => $kernel('\\App\\Http\\Middleware\\LimitAttempts'),
                'app/Http/Middleware/LimitAttempts.php' => $middleware("class AttemptLimiter\n{\n}"),
            ]],
            'app class extending a package class' => [[
                'app/Http/Kernel.php' => $kernel('\\App\\Http\\Middleware\\LimitAttempts'),
                'app/Http/Middleware/LimitAttempts.php' => $middleware("use Acme\\Limits\\Throttle;\n\nclass LimitAttempts extends Throttle\n{\n}"),
            ]],
            'app class using a package trait' => [[
                'app/Http/Kernel.php' => $kernel('\\App\\Http\\Middleware\\LimitAttempts'),
                'app/Http/Middleware/LimitAttempts.php' => $middleware("class LimitAttempts\n{\n    use \\Acme\\Limits\\LimitsAttempts;\n}"),
            ]],
        ];
    }

    public function test_throttle_re_registered_to_a_package_class_covers_the_route_it_is_on(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => self::laravel11Bootstrap("\$middleware->alias(['throttle' => \\Acme\\Limits\\Throttle::class]);"),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\Auth\\LoginController;\n\nRoute::post('/session/login', [LoginController::class, 'login'])->middleware('throttle:6,1');\n",
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
        ]);

        $this->assertPassed($result);
    }

    public function test_throttle_re_registered_to_a_package_class_on_the_login_controller_clears_the_controller_check(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => self::laravel11Bootstrap("\$middleware->alias(['throttle' => \\Acme\\Limits\\Throttle::class]);"),
            'app/Http/Controllers/Auth/LoginController.php' => $this->loginControllerWith("public function __construct() { \$this->middleware('throttle:5,1')->only('login'); }"),
            'routes/web.php' => '<?php',
        ]);

        $this->assertPassed($result);
    }

    public function test_other_alias_registered_to_a_class_it_cannot_read_does_not_cover_the_route_group(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => self::appKernel("protected \$middlewareAliases = ['signin.cap' => \\Acme\\Limits\\Throttle::class];"),
            'routes/web.php' => self::groupedLoginRoutes("Route::middleware('signin.cap:6,1')->group(function () {"),
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
        ]);

        $this->assertFailed($result);
        $this->assertSame([
            'Login route "/session/login" lacks rate limiting protection',
            'Authentication method LoginController::login() lacks rate limiting',
        ], $this->issueMessages($result));
    }

    public function test_throttle_re_registered_to_a_non_throttle_with_a_readable_parent_does_not_cover_the_route_group(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => self::appKernel(
                "protected \$middlewareAliases = ['throttle' => \\App\\Http\\Middleware\\NoopThrottle::class];"
            ),
            'app/Http/Middleware/NoopThrottle.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass NoopThrottle extends PassThrough\n{\n}\n",
            'app/Http/Middleware/PassThrough.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass PassThrough\n{\n    public function handle(\$request, \\Closure \$next)\n    {\n        return \$next(\$request);\n    }\n}\n",
            'routes/web.php' => self::groupedLoginRoutes("Route::middleware('throttle:60,1')->group(function () {"),
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
        ]);

        $this->assertFailed($result);
        $this->assertSame([
            'Login route "/session/login" lacks rate limiting protection',
            'Authentication method LoginController::login() lacks rate limiting',
        ], $this->issueMessages($result));
    }

    /**
     * @param  array<string, string>  $files
     *
     * @dataProvider knownNonThrottleClassProvider
     */
    #[DataProvider('knownNonThrottleClassProvider')]
    public function test_throttle_re_registered_to_a_class_known_not_to_throttle_does_not_cover_the_route_group(array $files): void
    {
        $result = $this->analyzeApp($files + [
            'routes/web.php' => self::groupedLoginRoutes("Route::middleware('throttle:6,1')->group(function () {"),
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
        ]);

        $this->assertFailed($result);
        $this->assertSame([
            'Login route "/session/login" lacks rate limiting protection',
            'Authentication method LoginController::login() lacks rate limiting',
        ], $this->issueMessages($result));
    }

    /**
     * 'throttle' re-registered to a class that does not throttle, though it is the
     * framework's, reaches framework code the analyzer does not read, or its file
     * declares it in another case, as PHP allows.
     *
     * @return array<string, array{array<string, string>}>
     */
    public static function knownNonThrottleClassProvider(): array
    {
        $kernel = static fn (string $class): string => self::appKernel("protected \$middlewareAliases = ['throttle' => {$class}::class];");
        $passThrough = "class PassThrough\n{\n    public function handle(\$request, \\Closure \$next)\n    {\n        return \$next(\$request);\n    }\n}";
        $middleware = static fn (string $declaration): string => "<?php\n\nnamespace App\\Http\\Middleware;\n\n{$declaration}\n";

        return [
            'framework class in bootstrap/app.php' => [[
                'bootstrap/app.php' => self::laravel11Bootstrap("\$middleware->alias(['throttle' => \\Illuminate\\Auth\\Middleware\\Authenticate::class]);"),
            ]],
            'framework class in the Kernel' => [[
                'app/Http/Kernel.php' => $kernel('\\Illuminate\\Auth\\Middleware\\Authenticate'),
            ]],
            'app class using a framework trait' => [[
                'app/Http/Kernel.php' => $kernel('\\App\\Http\\Middleware\\PassThrough'),
                'app/Http/Middleware/PassThrough.php' => $middleware(str_replace("PassThrough\n{\n", "PassThrough\n{\n    use \\Illuminate\\Support\\Traits\\Macroable;\n\n", $passThrough)),
            ]],
            'app class extending a framework class' => [[
                'app/Http/Kernel.php' => $kernel('\\App\\Http\\Middleware\\PassThrough'),
                'app/Http/Middleware/PassThrough.php' => $middleware("use Illuminate\\Http\\Middleware\\TrustHosts;\n\n".str_replace('class PassThrough', 'class PassThrough extends TrustHosts', $passThrough)),
            ]],
            'app class declared in another case' => [[
                'app/Http/Kernel.php' => $kernel('\\App\\Http\\Middleware\\PassThrough'),
                'app/Http/Middleware/PassThrough.php' => $middleware(str_replace('class PassThrough', 'class passthrough', $passThrough)),
            ]],
        ];
    }

    public function test_chained_throttle_removed_from_web_group_does_not_clear_web_login(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->alias([])->web(remove: ['throttle:60,1']);"),
            'routes/web.php' => $this->unthrottledWebLogin(),
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_chained_api_group_throttle_does_not_clear_web_login(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->alias([])->api(append: ['throttle:60,1']);"),
            'routes/web.php' => $this->unthrottledWebLogin(),
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
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

    public function test_route_file_registered_in_an_api_group_attribute_array_is_matched_as_api_routes(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::group(['middleware' => ['api']], base_path('routes/partner_api.php'));
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner_api.php' => "<?php\n\nRoute::post('/session/token', [SessionTokenController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/session/token" lacks rate limiting protection'], $this->issueMessages($result));
        $this->assertSame('api', $result->getIssues()[0]->metadata['route_type']);
    }

    public function test_file_required_through_base_path_inside_an_api_group_is_judged_as_an_api_file(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware('api')->group(function () {
                require base_path('routes/partner_api.php');
            });
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner_api.php' => "<?php\n\nRoute::post('/session/token', [SessionTokenController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/session/token" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_web_group_throttle_does_not_clear_a_file_registered_in_an_api_group_attribute_array(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::group(['middleware' => ['api']], base_path('routes/partner_api.php'));
        },
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->web(append: ['throttle:60,1']);
    })
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner_api.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_route_file_inherits_api_from_an_enclosing_group(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware('api')->group(function () {
                Route::prefix('partner')->group(base_path('routes/partner_api.php'));
            });
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner_api.php' => "<?php\n\nRoute::post('/session/token', [SessionTokenController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame('api', $result->getIssues()[0]->metadata['route_type']);
    }

    public function test_route_file_inherits_throttle_from_an_enclosing_group(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware(['api', 'throttle:5,1'])->group(function () {
                Route::prefix('partner')->group(base_path('routes/partner_api.php'));
            });
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner_api.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_excluding_another_throttle_keeps_the_group_throttle(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware(['api', 'throttle:5,1'])->group(function () {
                Route::withoutMiddleware('throttle:api')->group(base_path('routes/partner_api.php'));
            });
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner_api.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_throttle_on_a_group_off_the_router_does_not_cover_login(): void
    {
        $routes = <<<'PHP'
<?php

$jobs->middleware('throttle:5,1')->group(function () {
    Route::post('/login', [LoginController::class, 'store']);
});

Jobs::group(['middleware' => 'throttle:5,1'], function () {
    Route::post('/signin', [LoginController::class, 'store']);
});
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame([
            'Login route "/login" lacks rate limiting protection',
            'Login route "/signin" lacks rate limiting protection',
        ], $this->issueMessages($result));
    }

    public function test_throttle_on_a_router_variable_group_covers_login(): void
    {
        $routes = <<<'PHP'
<?php

$router->middleware('throttle:5,1')->group(function () {
    Route::post('/login', [LoginController::class, 'store']);
});
PHP;

        $this->assertPassed($this->analyzeRoutesOnly(['routes/web.php' => $routes]));
    }

    public function test_throttle_on_a_group_of_a_router_typed_parameter_covers_login(): void
    {
        $routes = <<<'PHP'
<?php

use Illuminate\Routing\Router;

Route::group([], function (Router $r) {
    $r->group(['middleware' => 'throttle:5,1'], function () {
        Route::post('/login', [LoginController::class, 'store']);
    });
});
PHP;

        $this->assertPassed($this->analyzeRoutesOnly(['routes/web.php' => $routes]));
    }

    public function test_throttle_on_a_group_of_a_variable_holding_the_router_covers_login(): void
    {
        $routes = <<<'PHP'
<?php

$r = app('router');
$r->middleware('throttle:5,1')->group(function () {
    Route::post('/login', [LoginController::class, 'store']);
});
PHP;

        $this->assertPassed($this->analyzeRoutesOnly(['routes/web.php' => $routes]));
    }

    public function test_provider_registering_through_the_containers_router_is_read(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class RouteServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->app->make('router')->middleware(['web', 'throttle:5,1'])->group(base_path('routes/auth.php'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Providers/RouteServiceProvider.php' => $provider,
            'routes/web.php' => '<?php',
            'routes/auth.php' => "<?php\n\nRoute::post('/login', [LoginController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_throttle_on_an_aliased_route_facade_group_covers_login(): void
    {
        $routes = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route as Routes;

Routes::group(['middleware' => 'throttle:5,1'], function () {
    Route::post('/login', [LoginController::class, 'store']);
});
PHP;

        $this->assertPassed($this->analyzeRoutesOnly(['routes/web.php' => $routes]));
    }

    // ==================== Throttle exclusion matches the exact name (#551) ====================

    public function test_nested_group_excluding_the_throttle_by_name_uncovers_login(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('throttle:5,1')->group(function () {
    Route::withoutMiddleware('throttle:5,1')->group(function () {
        Route::post('/login', [LoginController::class, 'store']);
    });
});
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @dataProvider routeExclusionProvider
     */
    #[DataProvider('routeExclusionProvider')]
    public function test_route_excluding_its_group_throttle(string $exclusion, bool $reported): void
    {
        $routes = <<<PHP
<?php

use Illuminate\\Routing\\Middleware\\ThrottleRequests;

Route::middleware('throttle:5,1')->group(function () {
    Route::post('/login', [LoginController::class, 'store']){$exclusion};
});
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        if ($reported) {
            $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function routeExclusionProvider(): array
    {
        return [
            'the same name' => ["->withoutMiddleware('throttle:5,1')", true],
            'the class with the same parameters' => ["->withoutMiddleware([ThrottleRequests::class.':5,1'])", true],
            'another limiter' => ["->withoutMiddleware('throttle:api')", false],
            'the bare class' => ['->withoutMiddleware(ThrottleRequests::class)', false],
            'the bare alias' => ["->withoutMiddleware('throttle')", false],
            'a later argument, which Laravel drops' => ["->withoutMiddleware('auth', 'throttle:5,1')", false],
            'the first argument' => ["->withoutMiddleware('throttle:5,1', 'auth')", true],
        ];
    }

    public function test_group_excluding_the_throttle_in_a_later_argument_keeps_it(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('throttle:5,1')->group(function () {
    Route::withoutMiddleware('auth', 'throttle:5,1')->group(function () {
        Route::post('/login', [LoginController::class, 'store']);
    });
});
PHP;

        $this->assertPassed($this->analyzeRoutesOnly(['routes/web.php' => $routes]));
    }

    /**
     * @dataProvider sameLineExclusionProvider
     */
    #[DataProvider('sameLineExclusionProvider')]
    public function test_an_exclusion_does_not_reach_another_route_on_its_line(string $routes): void
    {
        $this->assertPassed($this->analyzeRoutesOnly(['routes/web.php' => "<?php\n\nRoute::middleware('throttle:5,1')->group(function () {\n{$routes}\n});\n"]));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function sameLineExclusionProvider(): array
    {
        return [
            'another route excluding it' => ["    Route::post('/login', [LoginController::class, 'store']); Route::get('/ping', fn () => 1)->withoutMiddleware('throttle:5,1');"],
            'a group opening on the line' => ["    Route::post('/login', [LoginController::class, 'store']); Route::withoutMiddleware('throttle:5,1')->group(function () {\n        Route::get('/ping', fn () => 1);\n    });"],
            'a $router route excluding it' => ["    \$router->post('/hook')->withoutMiddleware('throttle:5,1'); Route::post('/login', [LoginController::class, 'store']);"],
            'a group closing on the line' => ["    Route::withoutMiddleware('throttle:5,1')->group(function () {\n        Route::get('/ping', fn () => 1);\n    }); Route::post('/login', [LoginController::class, 'store']);"],
        ];
    }

    public function test_registration_excluding_the_throttle_by_name_uncovers_login(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware(['web', 'throttle:5,1'])->group(function () {
                Route::withoutMiddleware('throttle:5,1')->group(base_path('routes/partner.php'));
            });
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @dataProvider lastRegistrarMiddlewareRouteProvider
     */
    #[DataProvider('lastRegistrarMiddlewareRouteProvider')]
    public function test_only_the_last_registrar_middleware_call_throttles_a_route_file(string $routes, bool $reported): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => "<?php\n\n{$routes}\n"]);

        if ($reported) {
            $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function lastRegistrarMiddlewareRouteProvider(): array
    {
        $route = "Route::post('/session/login', [SessionController::class, 'store'])";

        return [
            // RouteRegistrar::attribute() replaces 'middleware' on each call: the last one applies.
            'closure group throttle replaced by a later call' => ["Route::middleware('throttle:4,1')->middleware('verified')->group(function () {\n    {$route};\n});", true],
            'registrar route throttle replaced by a later call' => ["Route::middleware('throttle:4,1')->middleware('verified')->post('/session/login', [SessionController::class, 'store']);", true],
            'closure group without a throttle' => ["Route::middleware('verified')->group(function () {\n    {$route};\n});", true],
            'closure group throttle as the last call' => ["Route::middleware('verified')->middleware('throttle:4,1')->group(function () {\n    {$route};\n});", false],
            'registrar route throttle as the last call' => ["Route::middleware('verified')->middleware('throttle:4,1')->post('/session/login', [SessionController::class, 'store']);", false],
            // Route::middleware() on a route adds to its middleware.
            'route-level calls add up' => ["{$route}->middleware('throttle:4,1')->middleware('verified');", false],
            'registrar throttle then a route-level call' => ["Route::middleware('throttle:4,1')->post('/session/login', [SessionController::class, 'store'])->middleware('verified');", false],
            // withoutMiddleware() calls merge, so an earlier exclusion still holds.
            'closure group throttle excluded by an earlier of several exclusions' => ["Route::middleware('throttle:4,1')->group(function () {\n    Route::withoutMiddleware('throttle:4,1')->withoutMiddleware('verified')->group(function () {\n        {$route};\n    });\n});", true],
        ];
    }

    /**
     * @dataProvider lastRegistrarMiddlewareRegistrationProvider
     */
    #[DataProvider('lastRegistrarMiddlewareRegistrationProvider')]
    public function test_only_the_last_registrar_middleware_call_throttles_a_registered_file(string $chain, bool $reported): void
    {
        $bootstrap = <<<PHP
<?php

use Illuminate\\Foundation\\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            {$chain}->group(base_path('routes/portal.php'));
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/portal.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        if ($reported) {
            $this->assertFailed($result);
            $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function lastRegistrarMiddlewareRegistrationProvider(): array
    {
        return [
            'throttle replaced by a later call' => ["Route::middleware('throttle:4,1')->middleware('verified')", true],
            'no throttle' => ["Route::middleware('verified')", true],
            'throttle as the last call' => ["Route::middleware('verified')->middleware('throttle:4,1')", false],
            'throttle in one call listing both' => ["Route::middleware(['throttle:4,1', 'verified'])", false],
            'throttle excluded by an earlier of several exclusions' => ["Route::withoutMiddleware('throttle:4,1')->withoutMiddleware('verified')->middleware('throttle:4,1')", true],
        ];
    }

    /**
     * @dataProvider registrarVariableRouteProvider
     */
    #[DataProvider('registrarVariableRouteProvider')]
    public function test_a_registrar_held_in_a_variable_throttles_its_closure_group(string $registrar, bool $reported): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => <<<PHP
<?php

{$registrar}
\$guarded->group(function () {
    Route::post('/session/login', [SessionController::class, 'store']);
});
PHP]);

        if ($reported) {
            $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function registrarVariableRouteProvider(): array
    {
        return [
            'throttle on the registrar' => ["\$guarded = Route::middleware('throttle:5,1');", false],
            'throttle set by a later statement' => ["\$guarded = Route::prefix('account');\n\$guarded->middleware('throttle:5,1');", false],
            'throttle replaced by a later statement' => ["\$guarded = Route::middleware('throttle:5,1');\n\$guarded->middleware('verified');", true],
            'throttle excluded by a later statement' => ["\$guarded = Route::middleware('throttle:5,1');\n\$guarded->withoutMiddleware('throttle:5,1');", true],
            'throttle set in a branch' => ["\$guarded = Route::prefix('account');\nif (app()->isLocal()) {\n    \$guarded->middleware('throttle:5,1');\n}", true],
            'throttle replaced through the registrar group() returns' => ["\$guarded = Route::middleware('throttle:5,1');\n\$copy = \$guarded->group(function () {});\n\$copy->middleware('verified');", true],
            'throttle replaced through a variable variable' => ["\$guarded = Route::middleware('throttle:5,1');\n\$name = 'guarded';\n\$\$name->middleware('verified');", true],
            'throttle replaced through attribute()' => ["\$guarded = Route::middleware('throttle:5,1');\n\$guarded->attribute('middleware', ['verified']);", true],
            'throttle set through attribute()' => ["\$guarded = Route::prefix('account');\n\$guarded->attribute('middleware', 'throttle:5,1');", false],
            'throttle given as an extra attribute() argument' => ["\$guarded = Route::prefix('account');\n\$guarded->attribute('middleware', 'verified', 'throttle:5,1');", true],
            'throttle beside an attribute() key in a variable' => ["\$key = 'prefix';\n\$guarded = Route::middleware('throttle:5,1')->attribute(\$key, 'account');", false],
        ];
    }

    /**
     * @dataProvider escapingRegistrarRouteProvider
     */
    #[DataProvider('escapingRegistrarRouteProvider')]
    public function test_a_group_whose_registrar_escapes_reads_it(string $statement): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => "<?php\n\n\$guarded = Route::middleware('throttle:5,1');\n{$statement}\n"]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function escapingRegistrarRouteProvider(): array
    {
        $group = "\$guarded->group(function () {\n    Route::post('/session/login', [SessionController::class, 'store']);\n})";

        return [
            'returned' => ["return {$group};"],
            'in a ternary' => ["\$registered = config('auth.sessions') ? {$group} : null;"],
        ];
    }

    public function test_a_registrar_held_in_a_variable_throttles_its_closure_group_in_a_branch(): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => <<<'PHP'
<?php

$guarded = Route::middleware('throttle:5,1');
if (config('auth.sessions')) {
    $guarded->group(function () {
        Route::post('/session/login', [SessionController::class, 'store']);
    });
}
PHP]);

        $this->assertPassed($result);
    }

    /**
     * @dataProvider registrarVariableRegistrationProvider
     */
    #[DataProvider('registrarVariableRegistrationProvider')]
    public function test_a_registrar_held_in_a_variable_throttles_the_file_its_group_registers(string $registration, bool $reported): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->bootstrapThen($registration),
            'routes/web.php' => "<?php\n",
            'routes/portal.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        if ($reported) {
            $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function registrarVariableRegistrationProvider(): array
    {
        $group = "->group(base_path('routes/portal.php'));";

        return [
            'throttle on the registrar' => ["\$guarded = Route::middleware('throttle:4,1'); \$guarded{$group}", false],
            'throttle set by a later statement' => ["\$guarded = Route::prefix('portal'); \$guarded->middleware('throttle:4,1'); \$guarded{$group}", false],
            'throttle replaced by a later statement' => ["\$guarded = Route::middleware('throttle:4,1'); \$guarded->middleware('verified'); \$guarded{$group}", true],
            'fluent throttle replaced through attribute()' => ["Route::middleware('throttle:4,1')->attribute('middleware', ['verified']){$group}", true],
        ];
    }

    public function test_a_file_registered_twice_is_reported_when_one_registration_leaves_it_unthrottled(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware('throttle:5,1')->prefix('partners')->group(base_path('routes/partner.php'));
            Route::withoutMiddleware('throttle:5,1')->prefix('legacy')->group(base_path('routes/partner.php'));
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_api_group_throttle_excluded_from_a_registration_uncovers_login(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::group(['middleware' => 'api', 'excluded_middleware' => ['throttle:api']], base_path('routes/partner_api.php'));
        },
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->throttleApi();
    })
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner_api.php' => "<?php\n\nRoute::post('/session/token', [SessionTokenController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/session/token" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_kernel_api_throttle_excluded_by_its_alias_uncovers_login(): void
    {
        $routes = <<<'PHP'
<?php

Route::withoutMiddleware('throttle:api')->group(function () {
    Route::post('/session/login', [SessionController::class, 'store']);
});

Route::post('/session/token', [SessionTokenController::class, 'store']);
PHP;

        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => $this->stockKernel("\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class.':api'"),
            'app/Providers/RouteServiceProvider.php' => $this->stockRouteServiceProvider(),
            'routes/web.php' => '<?php',
            'routes/api.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_excluding_the_web_group_removes_the_throttle_it_appends(): void
    {
        $routes = <<<'PHP'
<?php

Route::withoutMiddleware('web')->group(function () {
    Route::post('/login', [LoginController::class, 'store']);
});

Route::post('/signin', [LoginController::class, 'store']);
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->web(append: ['throttle:5,1']);"),
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_excluding_the_plain_class_keeps_the_redis_api_throttle(): void
    {
        $routes = <<<'PHP'
<?php

use Illuminate\Routing\Middleware\ThrottleRequests;

Route::post('/session/login', [SessionController::class, 'store'])->withoutMiddleware(ThrottleRequests::class.':api');
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->throttleApi('api', true);"),
            'routes/web.php' => '<?php',
            'routes/api.php' => $routes,
        ]);

        $this->assertPassed($result);
    }

    public function test_a_global_throttle_is_never_excluded(): void
    {
        $routes = <<<'PHP'
<?php

Route::withoutMiddleware(['throttle:600,1', 'web'])->group(function () {
    Route::post('/login', [LoginController::class, 'store']);
});
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $this->laravel11Bootstrap("\$middleware->append('throttle:600,1');"),
            'routes/web.php' => $routes,
        ]);

        $this->assertPassed($result);
    }

    // ==================== Registrations follow require chains (#551) ====================

    /**
     * @dataProvider requireChainProvider
     */
    #[DataProvider('requireChainProvider')]
    public function test_file_loaded_from_a_throttle_registered_file_inherits_its_throttle(string $load, bool $reported): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware(['web', 'throttle:5,1'])->group(base_path('routes/partner.php'));
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner.php' => "<?php\n\n{$load}\n",
            'routes/partner_session.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        if ($reported) {
            $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function requireChainProvider(): array
    {
        return [
            'top-level require' => ["require __DIR__.'/partner_session.php';", false],
            'require through base_path' => ["require base_path('routes/partner_session.php');", false],
            'require inside a plain group' => ["Route::prefix('v2')->group(function () {\n    require __DIR__.'/partner_session.php';\n});", false],
            'group path argument' => ["Route::prefix('v2')->group(__DIR__.'/partner_session.php');", false],
            'require inside a group excluding the throttle' => ["Route::withoutMiddleware('throttle:5,1')->group(function () {\n    require __DIR__.'/partner_session.php';\n});", true],
        ];
    }

    /**
     * @dataProvider chainFileNamesProvider
     */
    #[DataProvider('chainFileNamesProvider')]
    public function test_a_file_reached_only_through_an_excluding_registration_is_reported_whatever_the_file_order(string $first, string $second): void
    {
        $bootstrap = <<<PHP
<?php

use Illuminate\\Foundation\\Application;
use Illuminate\\Foundation\\Configuration\\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::withoutMiddleware('throttle:60,1')->group(base_path('routes/{$first}.php'));
        },
    )
    ->withMiddleware(function (Middleware \$middleware): void {
        \$middleware->web(append: ['throttle:60,1']);
    })
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            "routes/{$first}.php" => "<?php\n\nrequire __DIR__.'/{$second}.php';\n",
            "routes/{$second}.php" => "<?php\n\nrequire __DIR__.'/mm_session.php';\n",
            'routes/mm_session.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function chainFileNamesProvider(): array
    {
        return [
            'loader sorts first' => ['aa_partner', 'zz_partner_auth'],
            'loader sorts last' => ['zz_partner', 'aa_partner_auth'],
        ];
    }

    public function test_file_api_php_loads_through_a_group_is_judged_as_an_api_file(): void
    {
        $result = $this->analyzeRoutesOnly([
            'routes/api.php' => "<?php\n\nRoute::prefix('mobile')->group(base_path('routes/mobile.php'));\n",
            'routes/mobile.php' => "<?php\n\nRoute::post('/session/token', [SessionTokenController::class, 'store']);\n",
        ]);

        $this->assertSame(['API authentication route "/session/token" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_throttle_follows_a_require_chain_of_any_depth_and_a_cycle_ends(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware('throttle:5,1')->group(base_path('routes/partner.php'));
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner.php' => "<?php\n\nrequire __DIR__.'/partner_auth.php';\n",
            'routes/partner_auth.php' => "<?php\n\nrequire_once __DIR__.'/partner_session.php';\n",
            'routes/partner_session.php' => "<?php\n\nrequire_once __DIR__.'/partner_auth.php';\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * @dataProvider indistinguishableRegistrationProvider
     */
    #[DataProvider('indistinguishableRegistrationProvider')]
    public function test_registrations_registering_the_same_routes_are_covered_by_any_of_them(string $registrations): void
    {
        $provider = <<<PHP
<?php

namespace App\\Providers;

use Illuminate\\Support\\ServiceProvider;

class RouteServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        {$registrations}
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Providers/RouteServiceProvider.php' => $provider,
            'routes/web.php' => '<?php',
            'routes/auth.php' => "<?php\n\nRoute::post('/login', [LoginController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function indistinguishableRegistrationProvider(): array
    {
        return [
            'if/else of the same prefix' => ["if (app()->isProduction()) {\n            Route::middleware(['web', 'throttle:5,1'])->group(base_path('routes/auth.php'));\n        } else {\n            Route::middleware('web')->group(base_path('routes/auth.php'));\n        }"],
        ];
    }

    public function test_a_file_required_from_web_php_and_registered_with_a_throttle_is_covered(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware(['web', 'throttle:5,1'])->group(base_path('routes/auth.php'));
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => "<?php\n\nrequire_once __DIR__.'/auth.php';\n",
            'routes/auth.php' => "<?php\n\nRoute::post('/login', [LoginController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * @dataProvider mutualRequireOrderProvider
     */
    #[DataProvider('mutualRequireOrderProvider')]
    public function test_mutual_require_once_gives_the_same_result_whatever_the_registration_order(string $first, string $second): void
    {
        $provider = <<<PHP
<?php

namespace App\\Providers;

use Illuminate\\Support\\ServiceProvider;

class RouteServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Route::middleware('throttle:5,1')->group(base_path('routes/{$first}.php'));
        Route::middleware('throttle:5,1')->group(base_path('routes/{$second}.php'));
    }
}
PHP;

        $result = $this->analyzeApp([
            'app/Providers/RouteServiceProvider.php' => $provider,
            'routes/web.php' => '<?php',
            'routes/a.php' => "<?php\n\nrequire_once __DIR__.'/b.php';\n\nRoute::post('/login', [LoginController::class, 'store']);\n",
            'routes/b.php' => "<?php\n\nRoute::withoutMiddleware('throttle:5,1')->group(function () {\n    require_once __DIR__.'/a.php';\n});\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function mutualRequireOrderProvider(): array
    {
        return [
            'a first' => ['a', 'b'],
            'b first' => ['b', 'a'],
        ];
    }

    /**
     * @dataProvider registrationScopeProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('registrationScopeProvider')]
    public function test_registrations_are_judged_per_domain_and_prefix(string $then, array $files, bool $reported): void
    {
        $bootstrap = <<<PHP
<?php

use Illuminate\\Foundation\\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        then: function () {
            {$then}
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp(['bootstrap/app.php' => $bootstrap, 'routes/web.php' => '<?php', 'routes/api.php' => '<?php', ...$files]);

        if ($reported) {
            $this->assertCount(1, $result->getIssues());
            $this->assertStringContainsString('"/session/login" lacks rate limiting protection', $this->issueMessages($result)[0]);
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, array<string, string>, bool}>
     */
    public static function registrationScopeProvider(): array
    {
        $login = "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n";

        return [
            'web.php also loads the file under no prefix' => [
                "Route::middleware(['web', 'throttle:5,1'])->prefix('partner')->group(base_path('routes/partner.php'));",
                ['routes/web.php' => "<?php\n\nrequire __DIR__.'/partner.php';\n", 'routes/partner.php' => $login],
                true,
            ],
            'api.php loads the file under its own api prefix' => [
                "Route::middleware(['api', 'throttle:5,1'])->prefix('api')->group(base_path('routes/partner.php'));",
                ['routes/api.php' => "<?php\n\nrequire __DIR__.'/partner.php';\n", 'routes/partner.php' => $login],
                false,
            ],
            'a second domain is unthrottled' => [
                "Route::middleware(['web', 'throttle:5,1'])->domain('a.example.test')->group(base_path('routes/partner.php'));\n            Route::middleware('web')->domain('b.example.test')->group(base_path('routes/partner.php'));",
                ['routes/partner.php' => $login],
                true,
            ],
            'an inner domain replaces the outer one' => [
                "Route::domain('a.example.test')->group(function () {\n                Route::middleware(['web', 'throttle:5,1'])->group(base_path('routes/partner.php'));\n                Route::domain('b.example.test')->middleware('web')->group(base_path('routes/partner.php'));\n            });",
                ['routes/partner.php' => $login],
                true,
            ],
            'an unthrottled prefix reaches a file the registered one requires' => [
                "Route::middleware(['web', 'throttle:5,1'])->prefix('x')->group(base_path('routes/partner.php'));\n            Route::middleware('web')->prefix('y')->group(base_path('routes/partner.php'));",
                ['routes/partner.php' => "<?php\n\nrequire __DIR__.'/partner_auth.php';\n", 'routes/partner_auth.php' => $login],
                true,
            ],
            'a computed prefix is a scope of its own' => [
                "Route::middleware(['web', 'throttle:5,1'])->prefix(config('auth.prefix'))->group(base_path('routes/partner.php'));\n            Route::middleware('web')->prefix('legacy')->group(base_path('routes/partner.php'));",
                ['routes/partner.php' => $login],
                true,
            ],
            'the last prefix in a chain wins' => [
                "Route::middleware(['web', 'throttle:5,1'])->prefix('old')->prefix('x')->group(base_path('routes/partner.php'));\n            Route::middleware('web')->prefix('x')->group(base_path('routes/partner.php'));",
                ['routes/partner.php' => $login],
                false,
            ],
            'a throttled require_once does not cover another prefix' => [
                "Route::middleware('web')->prefix('admin')->group(base_path('routes/partner.php'));",
                ['routes/web.php' => "<?php\n\nRoute::middleware('throttle:5,1')->group(function () {\n    require_once __DIR__.'/partner.php';\n});\n", 'routes/partner.php' => $login],
                true,
            ],
            'a require_once is read as a require' => [
                "Route::middleware('web')->prefix('admin')->group(function () {\n                require_once base_path('routes/partner.php');\n            });",
                ['routes/web.php' => "<?php\n\nRoute::middleware('throttle:5,1')->group(function () {\n    require_once __DIR__.'/partner.php';\n});\n", 'routes/partner.php' => $login],
                true,
            ],
        ];
    }

    public function test_a_computed_api_prefix_is_a_scope_of_its_own(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        api: __DIR__.'/../routes/api.php',
        apiPrefix: config('app.api_prefix'),
        then: function () {
            Route::middleware(['api', 'throttle:5,1'])->prefix('partner')->group(base_path('routes/partner.php'));
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/api.php' => "<?php\n\nrequire __DIR__.'/partner.php';\n",
            'routes/partner.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertSame(['API authentication route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @dataProvider unregisteredApiFileProvider
     */
    #[DataProvider('unregisteredApiFileProvider')]
    public function test_api_php_the_framework_does_not_register_gets_no_registration_of_its_own(string $routing): void
    {
        $bootstrap = <<<PHP
<?php

use Illuminate\\Foundation\\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        {$routing}
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => "<?php\n\nRoute::middleware('throttle:5,1')->group(function () {\n    require __DIR__.'/api.php';\n});\n",
            'routes/api.php' => "<?php\n\nrequire __DIR__.'/partner.php';\n",
            'routes/partner.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unregisteredApiFileProvider(): array
    {
        return [
            'no api: file' => ["web: __DIR__.'/../routes/web.php',"],
            'api: names another file' => ["web: __DIR__.'/../routes/web.php',\n        api: __DIR__.'/../routes/v1.php',"],
            'a using: callback' => ["using: function () {\n            Route::middleware('web')->group(base_path('routes/web.php'));\n        },\n        api: __DIR__.'/../routes/api.php',"],
        ];
    }

    public function test_require_once_back_to_a_loaded_file_adds_no_registration(): void
    {
        $web = <<<'PHP'
<?php

Route::post('/login', [LoginController::class, 'store']);

Route::middleware('throttle:5,1')->group(function () {
    require_once __DIR__.'/admin.php';
});
PHP;

        $result = $this->analyzeRoutesOnly([
            'routes/web.php' => $web,
            'routes/admin.php' => "<?php\n\nrequire_once __DIR__.'/web.php';\n",
        ]);

        $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_an_unloaded_route_file_does_not_uncover_a_file_it_requires_that_is_registered(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware(['web', 'throttle:5,1'])->prefix('partner')->group(base_path('routes/partner.php'));
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/legacy.php' => "<?php\n\nrequire __DIR__.'/partner.php';\n",
            'routes/partner.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_file_loaded_from_an_api_registered_file_is_judged_as_an_api_file(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware('api')->group(base_path('routes/partner_api.php'));
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner_api.php' => "<?php\n\nrequire __DIR__.'/partner_tokens.php';\n",
            'routes/partner_tokens.php' => "<?php\n\nRoute::post('/session/token', [SessionTokenController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['API authentication route "/session/token" lacks rate limiting protection'], $this->issueMessages($result));
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

    public function test_route_file_that_does_not_parse_is_left_to_the_parse_failure_notice(): void
    {
        // No analyzer reads a file that does not parse, and the report says so: a
        // verdict read from its text would be a guess about code PHP cannot run.
        $routes = <<<'PHP'
<?php

Route::post('/account/signin', [AccountController::class, 'signin'])
PHP;

        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertPassed($result);
    }

    public function test_middleware_name_that_only_starts_with_throttle_does_not_clear_the_login_route(): void
    {
        $result = $this->analyzeRoutesOnly([
            'routes/web.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store'])->middleware('throttles.audit');\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_app_class_named_throttle_requests_does_not_clear_the_login_route(): void
    {
        $middleware = <<<'PHP'
<?php

namespace App\Support;

class ThrottleRequests
{
    public function handle($request, $next)
    {
        return $next($request);
    }
}
PHP;
        $routes = <<<'PHP'
<?php

use App\Support\ThrottleRequests;

Route::post('/session/login', [SessionController::class, 'store'])->middleware(ThrottleRequests::class);
PHP;

        $result = $this->analyzeRoutesOnly([
            'app/Support/ThrottleRequests.php' => $middleware,
            'routes/web.php' => $routes,
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @dataProvider variadicThrottleRouteProvider
     */
    #[DataProvider('variadicThrottleRouteProvider')]
    public function test_variadic_throttle_middleware_clears_the_route_and_the_controller(string $routes): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'routes/web.php' => "<?php\n\n".$routes."\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function variadicThrottleRouteProvider(): array
    {
        return [
            'after the verb' => ["Route::post('/session/login', [LoginController::class, 'login'])->middleware('auth', 'throttle:6,1');"],
            'before the verb' => ["Route::middleware('auth', 'throttle:6,1')->post('/session/login', [LoginController::class, 'login']);"],
            'on the group' => ["Route::middleware('auth', 'throttle:6,1')->group(function () {\n    Route::post('/session/login', [LoginController::class, 'login']);\n});"],
        ];
    }

    /**
     * @dataProvider computedThrottleRouteProvider
     */
    #[DataProvider('computedThrottleRouteProvider')]
    public function test_throttle_with_a_computed_limit_clears_the_login_route(string $middleware): void
    {
        $result = $this->analyzeRoutesOnly([
            'routes/web.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store'])->middleware(".$middleware.");\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function computedThrottleRouteProvider(): array
    {
        return [
            'concatenated limit' => ["'throttle:'.config('auth.login_limit')"],
            'interpolated limit' => ['"throttle:{$loginLimit},1"'],
            'concatenated limit in a list' => ["['guest', 'throttle:'.\$loginLimit.',1']"],
        ];
    }

    public function test_concatenated_name_that_only_starts_with_throttle_does_not_clear_the_login_route(): void
    {
        $result = $this->analyzeRoutesOnly([
            'routes/web.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store'])->middleware('throttle'.\$suffix);\n",
        ]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_concatenated_name_that_only_starts_with_throttle_does_not_clear_a_registered_file(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware(['web', 'throttle'.config('auth.login_limit')])->group(base_path('routes/partner.php'));
        },
    )
    ->create();
PHP;

        $result = $this->analyzeApp([
            'bootstrap/app.php' => $bootstrap,
            'routes/web.php' => '<?php',
            'routes/partner.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_auth_routes_in_a_throttled_group_clear_the_login_controller(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('throttle:6,1')->group(function () {
    Auth::routes();
});
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'routes/web.php' => $routes,
        ]);

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

    private static function appKernel(string $properties): string
    {
        return <<<PHP
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    {$properties}
}
PHP;
    }

    private function bootstrapThen(string $registration): string
    {
        return "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Support\\Facades\\Route;\n\n"
            ."return Application::configure(basePath: dirname(__DIR__))\n    ->withRouting(\n        web: __DIR__.'/../routes/web.php',\n        then: function () {\n            {$registration}\n        },\n    )\n    ->create();\n";
    }

    /**
     * @return list<string>
     */
    private function sortedIssueMessages(ResultInterface $result): array
    {
        $messages = $this->issueMessages($result);
        sort($messages);

        return $messages;
    }

    /**
     * A route file whose login route sits five lines inside the group the given
     * line opens, with ThrottleRequests imported as itself and as Cap.
     */
    private static function groupedLoginRoutes(string $groupOpening): string
    {
        return <<<PHP
<?php

use App\Http\Controllers\Auth\LoginController;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Illuminate\Routing\Middleware\ThrottleRequests as Cap;

{$groupOpening}
    Route::get('/session', fn () => 'form');
    Route::get('/session/help', fn () => 'help');
    Route::get('/session/terms', fn () => 'terms');
    Route::get('/session/privacy', fn () => 'privacy');
    Route::post('/session/login', [LoginController::class, 'login']);
});
PHP;
    }

    private static function laravel11Bootstrap(string $middlewareBody, string $imports = ''): string
    {
        return <<<PHP
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;
{$imports}

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

    public function test_controller_group_given_a_list_covers_each_closure_and_file(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\Auth\SessionGate;

Route::controller(SessionGate::class)->group([
    function () {
        Route::post('/signin', 'store');
    },
    base_path('routes/signin.php'),
    fn () => Route::post('/session/login', 'store'),
]);

Route::post('/admin/signin', 'store');
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/SessionGate.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Auth', 'SessionGate'),
            'routes/web.php' => $routes,
            'routes/signin.php' => "<?php\n\nRoute::post('/partner/signin', 'store');\n",
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

    /**
     * @dataProvider frameworkThrottleRegistrations
     */
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

    /**
     * @dataProvider fileGroupRegistrations
     */
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

    /**
     * @dataProvider kernelMiddlewareGroupNames
     */
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

    /**
     * @dataProvider chainedThrottles
     */
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

    public function test_resource_route_is_judged_on_its_whole_controller(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/SessionGate.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Auth', 'SessionGate'),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\Auth\\SessionGate;\n\nRoute::resource('login', SessionGate::class);\n",
        ]);

        $this->assertPassed($result);
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

    /**
     * @dataProvider middlewareAsLaravelAppliesItProvider
     *
     * @param  array<string, string>  $files
     * @param  list<string>  $expected
     */
    #[DataProvider('middlewareAsLaravelAppliesItProvider')]
    public function test_middleware_reaches_a_login_route_as_laravel_applies_it(array $files, array $expected): void
    {
        $result = $this->analyzeApp($files);

        $this->assertSame($expected, $this->issueMessages($result));
    }

    /**
     * @return array<string, array{array<string, string>, list<string>}>
     */
    public static function middlewareAsLaravelAppliesItProvider(): array
    {
        $web = 'Login route "/login" lacks rate limiting protection';
        $api = 'API authentication route "/login" lacks rate limiting protection';
        $login = "Route::post('/login', [LoginController::class, 'store'])";
        $apiApp = static fn (string $middleware): array => [
            'bootstrap/app.php' => self::routingBootstrap("web: __DIR__.'/../routes/web.php',\n        api: __DIR__.'/../routes/api.php',", $middleware),
            'routes/web.php' => '<?php',
            'routes/api.php' => "<?php\n\n{$login};\n",
        ];
        $hooks = static fn (string $registration): array => [
            'bootstrap/app.php' => self::routingBootstrap(
                "web: __DIR__.'/../routes/web.php',\n        then: function () {\n            {$registration}\n        },",
                "\$middleware->web(append: ['throttle:5,1']);",
            ),
            'routes/web.php' => '<?php',
            'routes/hooks.php' => "<?php\n\n{$login};\n",
        ];
        $webRoutes = static fn (string $routes): array => ['routes/web.php' => "<?php\n\n{$routes}\n"];
        $authFile = static fn (string $routes): array => [
            'routes/web.php' => "<?php\n\n{$routes}\n",
            'routes/auth.php' => "<?php\n\nRoute::post('/login', [LoginController::class, 'authenticate']);\n",
        ];
        $grouped = static fn (string $opening): string => "{$opening}(function () {\n    {$login};\n});";

        return [
            'api(remove:) takes out the throttle throttleApi() adds' => [
                $apiApp("\$middleware->throttleApi();\n        \$middleware->api(remove: ['throttle:api']);"),
                [$api],
            ],
            'throttleApi() throttles the api group' => [$apiApp('$middleware->throttleApi();'), []],
            'api(remove:) takes out a throttle group() lists' => [
                $apiApp("\$middleware->group('api', ['throttle:5,1']);\n        \$middleware->api(remove: ['throttle:5,1']);"),
                [$api],
            ],
            'removeFromGroup() leaves a throttle appended to the group' => [
                $apiApp("\$middleware->appendToGroup('api', ['throttle:5,1']);\n        \$middleware->removeFromGroup('api', 'throttle:5,1');"),
                [],
            ],
            'api(remove:) of another limiter leaves the throttle' => [
                $apiApp("\$middleware->throttleApi();\n        \$middleware->api(remove: ['throttle:global']);"),
                [],
            ],
            'a route drops middleware after a leading array' => [$webRoutes("{$login}->middleware(['auth'], 'throttle:5,1');"), [$web]],
            'a group drops middleware after a leading array' => [$webRoutes($grouped("Route::middleware(['auth'], 'throttle:5,1')->group")), [$web]],
            'a route list holding the throttle' => [$webRoutes("{$login}->middleware(['auth', 'throttle:5,1']);"), []],
            'a file registered without web does not get the web group' => [
                $hooks("Route::prefix('hooks')->group(base_path('routes/hooks.php'));"),
                [$web],
            ],
            'a file registered with web gets the web group' => [
                $hooks("Route::middleware('web')->prefix('hooks')->group(base_path('routes/hooks.php'));"),
                [],
            ],
            'a file web.php requires gets the web group' => [
                [...$hooks(''), 'routes/web.php' => "<?php\n\nrequire __DIR__.'/hooks.php';\n"],
                [],
            ],
            'excluding a class drops its parameterless subclass' => [
                $webRoutes("use Illuminate\\Routing\\Middleware\\ThrottleRequests;\nuse Illuminate\\Routing\\Middleware\\ThrottleRequestsWithRedis;\n\n"
                    ."Route::middleware(ThrottleRequestsWithRedis::class)->group(function () {\n    {$login}->withoutMiddleware(ThrottleRequests::class);\n});\n\n"
                    ."{$login}->middleware(ThrottleRequestsWithRedis::class)->withoutMiddleware(ThrottleRequests::class);"),
                [$web, $web],
            ],
            'excluding a class keeps a subclass with parameters' => [
                $webRoutes("use Illuminate\\Routing\\Middleware\\ThrottleRequests;\nuse Illuminate\\Routing\\Middleware\\ThrottleRequestsWithRedis;\n\n"
                    ."{$login}->middleware(ThrottleRequestsWithRedis::class.':5,1')->withoutMiddleware(ThrottleRequests::class);"),
                [],
            ],
            'excluding a class drops a parameterless subclass a file registration applies' => [
                [
                    'bootstrap/app.php' => self::routingBootstrap(
                        "web: __DIR__.'/../routes/web.php',\n        then: function () {\n            Route::middleware(['web', \\Illuminate\\Routing\\Middleware\\ThrottleRequestsWithRedis::class])->group(base_path('routes/hooks.php'));\n        },",
                    ),
                    'routes/web.php' => '<?php',
                    'routes/hooks.php' => "<?php\n\nuse Illuminate\\Routing\\Middleware\\ThrottleRequests;\n\n{$login}->withoutMiddleware(ThrottleRequests::class);\n",
                ],
                [$web],
            ],
            'a backslashed class string does not exclude the alias' => [
                $webRoutes("Route::middleware('throttle:5,1')->group(function () {\n    {$login}->withoutMiddleware('\\Illuminate\\Routing\\Middleware\\ThrottleRequests:5,1');\n});"),
                [],
            ],
            'a class string excludes the alias' => [
                $webRoutes("Route::middleware('throttle:5,1')->group(function () {\n    {$login}->withoutMiddleware('Illuminate\\Routing\\Middleware\\ThrottleRequests:5,1');\n});"),
                [$web],
            ],
            'a held registrar keeps its middleware for a closure' => [
                $webRoutes("\$limited = Route::middleware('throttle:5,1');\n\n".$grouped('$limited->group')),
                [],
            ],
            'a held registrar without a throttle' => [$webRoutes("\$limited = Route::prefix('auth');\n\n".$grouped('$limited->group')), [$web]],
            'a held registrar keeps its middleware for a file' => [
                $authFile("\$r = Route::middleware('throttle:5,1');\n\$r->group(base_path('routes/auth.php'));"),
                [],
            ],
            'a held registrar keeps its middleware for a held file' => [
                $authFile("\$file = base_path('routes/auth.php');\n\$r = Route::middleware('throttle:5,1');\n\$r->group(\$file);"),
                [],
            ],
            'a held registrar keeps its exclusion' => [
                [
                    'bootstrap/app.php' => self::routingBootstrap("web: __DIR__.'/../routes/web.php',", "\$middleware->web(append: ['throttle:5,1']);"),
                    ...$webRoutes("\$open = Route::withoutMiddleware('throttle:5,1');\n\n".$grouped('$open->group')),
                ],
                [$web],
            ],
            'a held registrar reassigned before the group' => [
                $webRoutes("\$limited = Route::middleware('throttle:5,1');\n\$limited = Route::prefix('auth');\n\n".$grouped('$limited->group')),
                [$web],
            ],
            'a held middleware name for a file' => [
                $authFile("\$mw = 'throttle:5,1';\nRoute::middleware(\$mw)->group(base_path('routes/auth.php'));"),
                [],
            ],
            'a held middleware name for a closure' => [$webRoutes("\$mw = 'throttle:5,1';\n\n".$grouped('Route::middleware($mw)->group')), []],
            'a held middleware name that does not throttle' => [$webRoutes("\$mw = 'auth';\n\n".$grouped('Route::middleware($mw)->group')), [$web]],
            'held group attributes for a file' => [
                $authFile("\$attrs = ['middleware' => 'throttle:5,1'];\nRoute::group(\$attrs, base_path('routes/auth.php'));"),
                [],
            ],
            'held group attributes for a closure' => [
                $webRoutes("\$attrs = ['middleware' => 'throttle:5,1'];\n\nRoute::group(\$attrs, function () {\n    {$login};\n});"),
                [],
            ],
        ];
    }

    /**
     * @dataProvider controllerMiddlewareExclusionProvider
     */
    #[DataProvider('controllerMiddlewareExclusionProvider')]
    public function test_a_route_exclusion_reaches_the_middleware_its_controller_registers(string $route, bool $reported): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->loginControllerWith('public function __construct() { $this->middleware(\'throttle:5,1\'); }'),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\Auth\\LoginController;\n\n{$route};\n",
        ]);

        $this->assertSame($reported ? ['Login route "/login" lacks rate limiting protection'] : [], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function controllerMiddlewareExclusionProvider(): array
    {
        return [
            'excluded on the route' => ["Route::post('/login', [LoginController::class, 'login'])->withoutMiddleware('throttle:5,1')", true],
            'excluded by its class' => ["Route::post('/login', [LoginController::class, 'login'])->withoutMiddleware(\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class.':5,1')", true],
            'excluded by a group' => ["Route::withoutMiddleware('throttle:5,1')->group(function () {\n    Route::post('/login', [LoginController::class, 'login']);\n})", true],
            'another limiter excluded' => ["Route::post('/login', [LoginController::class, 'login'])->withoutMiddleware('throttle:60,1')", false],
            'nothing excluded' => ["Route::post('/login', [LoginController::class, 'login'])", false],
        ];
    }

    /**
     * @dataProvider apiFileRegistrationProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('apiFileRegistrationProvider')]
    public function test_routes_api_php_keeps_its_api_scope_however_it_is_registered(array $files, string $expected): void
    {
        $result = $this->analyzeApp($files);

        $this->assertContains($expected, $this->issueMessages($result));
    }

    /**
     * @return array<string, array{array<string, string>, string}>
     */
    public static function apiFileRegistrationProvider(): array
    {
        $routes = [
            'routes/web.php' => "<?php\n\nRoute::middleware('throttle:5,1')->group(function () {\n    require __DIR__.'/api.php';\n});\n",
            'routes/api.php' => "<?php\n\nRoute::post('/login', [LoginController::class, 'store']);\n",
        ];
        $api = 'API authentication route "/login" lacks rate limiting protection';
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
            Route::middleware('api')->prefix('api')->group($this->path('api'));
            Route::middleware('web')->group(base_path('routes/web.php'));
        });
    }

    private function path(string $name): string
    {
        return base_path("routes/{$name}.php");
    }
}
PHP;

        return [
            'a provider method computes the path' => [['app/Providers/RouteServiceProvider.php' => $provider, ...$routes], $api],
            'positional withRouting() arguments' => [
                ['bootstrap/app.php' => self::routingBootstrap("null,\n        __DIR__.'/../routes/web.php',\n        __DIR__.'/../routes/api.php',"), ...$routes],
                $api,
            ],
            'named withRouting() arguments, api.php loading nothing' => [
                ['bootstrap/app.php' => self::routingBootstrap("web: __DIR__.'/../routes/web.php',\n        api: __DIR__.'/../routes/api.php',"), ...$routes],
                $api,
            ],
            'a variable names the api file' => [
                [
                    'bootstrap/app.php' => str_replace(
                        'return Application',
                        "\$api = __DIR__.'/../routes/auth.php';\n\nreturn Application",
                        self::routingBootstrap("web: __DIR__.'/../routes/web.php',\n        api: \$api,", "\$middleware->web(append: ['throttle:5,1']);"),
                    ),
                    'routes/web.php' => '<?php',
                    'routes/auth.php' => "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n",
                ],
                'API authentication route "/session/login" lacks rate limiting protection',
            ],
        ];
    }

    public function test_unreadable_registration_middleware_keeps_the_web_group(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => self::routingBootstrap("web: __DIR__.'/../routes/web.php',\n        then: function () {\n            Route::middleware(config('auth.route_middleware'))->group(base_path('routes/auth.php'));\n        },", "\$middleware->web(append: ['throttle:5,1']);"),
            'routes/web.php' => '<?php',
            'routes/auth.php' => "<?php\n\nRoute::post('/login', [LoginController::class, 'store']);\n",
        ]);

        $this->assertSame([], $this->issueMessages($result));
    }

    public function test_unreadable_provider_registration_middleware_keeps_the_kernel_web_group(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => self::appKernel("protected \$middlewareGroups = ['web' => ['throttle:5,1']];"),
            'app/Providers/RouteServiceProvider.php' => self::bootingProvider('RouteServiceProvider', "Route::middleware('web')->group(base_path('routes/web.php'));\n        Route::middleware(\$this->tenantMiddleware)->group(base_path('routes/auth.php'));"),
            'routes/web.php' => '<?php',
            'routes/auth.php' => "<?php\n\nRoute::post('/login', [LoginController::class, 'store']);\n",
        ]);

        $this->assertSame([], $this->issueMessages($result));
    }

    public function test_a_registration_with_any_unreadable_middleware_entry_keeps_the_web_group(): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => self::routingBootstrap("web: __DIR__.'/../routes/web.php',\n        then: function () {\n            Route::middleware(['auth', \$guard])->group(base_path('routes/auth.php'));\n        },", "\$middleware->web(append: ['throttle:5,1']);"),
            'routes/web.php' => '<?php',
            'routes/auth.php' => "<?php\n\nRoute::post('/login', [LoginController::class, 'store']);\n",
        ]);

        // An unreadable entry may be 'web' itself, so the web group is kept
        $this->assertSame([], $this->issueMessages($result));
    }

    /**
     * @dataProvider mutatedRegistrarProvider
     */
    #[DataProvider('mutatedRegistrarProvider')]
    public function test_a_held_registrar_is_read_with_the_calls_made_on_it(string $routes, bool $reported): void
    {
        $result = $this->analyzeApp(['routes/web.php' => "<?php\n\n{$routes}\n\$r->group(function () {\n    Route::post('/login', [LoginController::class, 'store']);\n});\n"]);

        $this->assertSame($reported ? ['Login route "/login" lacks rate limiting protection'] : [], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function mutatedRegistrarProvider(): array
    {
        return [
            'a later middleware() replaces the throttle' => ["\$r = Route::middleware('throttle:5,1');\n\$r->middleware('auth');", true],
            'a later withoutMiddleware() excludes the throttle' => ["\$r = Route::middleware('throttle:5,1');\n\$r->withoutMiddleware('throttle:5,1');", true],
            'a later middleware() adds the throttle' => ["\$r = Route::prefix('auth');\n\$r->middleware('throttle:5,1');", false],
            'a later prefix() keeps the throttle' => ["\$r = Route::middleware('throttle:5,1');\n\$r->prefix('auth')->name('auth.');", false],
            'a call in a branch is not read' => ["\$r = Route::middleware('throttle:5,1');\nif (\$local) {\n    \$r->middleware('auth');\n}", true],
            'a call that also registers a route is not read' => ["\$r = Route::middleware('throttle:5,1');\n\$r->middleware('auth')->get('/x', fn () => 'x');", true],
        ];
    }

    /**
     * @dataProvider registrationExclusionScopeProvider
     */
    #[DataProvider('registrationExclusionScopeProvider')]
    public function test_one_registrations_exclusion_does_not_reach_another(string $second, bool $reported): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => self::routingBootstrap("web: __DIR__.'/../routes/web.php',\n        then: function () {\n            Route::middleware(['web', 'throttle:10,1'])->withoutMiddleware('throttle:5,1')->prefix('a')->group(base_path('routes/auth.php'));\n            {$second}\n        },"),
            'routes/web.php' => '<?php',
            'routes/auth.php' => "<?php\n\nuse App\\Http\\Controllers\\Auth\\LoginController;\n\nRoute::post('/login', [LoginController::class, 'login']);\n",
            'app/Http/Controllers/Auth/LoginController.php' => "<?php\n\nnamespace App\\Http\\Controllers\\Auth;\n\nclass LoginController\n{\n    public function __construct() { \$this->middleware('throttle:5,1'); }\n\n    public function login() { return Auth::attempt(request()->only('email', 'password')); }\n}\n",
        ]);

        $this->assertSame($reported ? ['Login route "/login" lacks rate limiting protection'] : [], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function registrationExclusionScopeProvider(): array
    {
        return [
            'the other registration keeps the controller throttle' => ["Route::middleware('web')->prefix('b')->group(base_path('routes/auth.php'));", false],
            'the other registration excludes it too' => ["Route::middleware('web')->withoutMiddleware('throttle:5,1')->prefix('b')->group(base_path('routes/auth.php'));", true],
        ];
    }

    /**
     * @dataProvider heldApiFileListProvider
     */
    #[DataProvider('heldApiFileListProvider')]
    public function test_an_api_file_list_holding_a_variable_registers_the_file(string $routing): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => str_replace('return Application', "\$v2 = __DIR__.'/../routes/v2.php';\n\nreturn Application", self::routingBootstrap($routing, '$middleware->throttleApi();')),
            'routes/web.php' => '<?php',
            'routes/v2.php' => "<?php\n\nRoute::post('/login', [LoginController::class, 'store']);\n",
        ]);

        $this->assertSame([], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function heldApiFileListProvider(): array
    {
        return [
            'named' => ["web: __DIR__.'/../routes/web.php',\n        api: [\$v2],"],
            'positional' => ["null,\n        __DIR__.'/../routes/web.php',\n        [\$v2],"],
        ];
    }

    public function test_a_registrar_copied_to_another_variable_shares_its_middleware(): void
    {
        $result = $this->analyzeApp(['routes/web.php' => "<?php\n\n\$a = Route::middleware('throttle:5,1');\n\$b = \$a;\n\$b->middleware('auth');\n\$a->group(function () {\n    Route::post('/login', [LoginController::class, 'store']);\n});\n"]);

        $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_a_registrar_mutated_in_a_closure_by_value_is_not_read(): void
    {
        $result = $this->analyzeApp(['routes/web.php' => "<?php\n\n\$r = Route::middleware('throttle:5,1');\n\$f = function () use (\$r) {\n    \$r->middleware('auth');\n};\n\$f();\n\$r->group(function () {\n    Route::post('/login', [LoginController::class, 'store']);\n});\n"]);

        $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    public function test_a_middleware_statement_on_the_router_is_discarded(): void
    {
        $result = $this->analyzeApp(['routes/web.php' => "<?php\n\n\$router = app('router');\n\$router->middleware('throttle:5,1');\n\$router->group([], function () {\n    Route::post('/login', [LoginController::class, 'store']);\n});\n"]);

        $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @dataProvider heldRouteProvider
     */
    #[DataProvider('heldRouteProvider')]
    public function test_a_route_held_in_a_variable_keeps_its_later_middleware(string $routes, bool $reported): void
    {
        $result = $this->analyzeApp(['routes/web.php' => "<?php\n\n{$routes}\n"]);

        $this->assertSame($reported ? ['Login route "/login" lacks rate limiting protection'] : [], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function heldRouteProvider(): array
    {
        $route = "\$route = Route::post('/login', [LoginController::class, 'store'])";

        return [
            'a later middleware()' => ["{$route};\n\$route->middleware('throttle:5,1');", false],
            'a later name()' => ["{$route};\n\$route->name('login');", true],
            'a later withoutMiddleware()' => ["{$route}->middleware('throttle:5,1');\n\$route->withoutMiddleware('throttle:5,1');", true],
        ];
    }

    /**
     * @dataProvider unknownRegistrarCallProvider
     */
    #[DataProvider('unknownRegistrarCallProvider')]
    public function test_a_held_registrar_given_a_call_this_cannot_read_is_not_followed(string $call): void
    {
        $result = $this->analyzeApp(['routes/web.php' => sprintf(self::HELD, $call)]);

        $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unknownRegistrarCallProvider(): array
    {
        return [
            'attribute() replaces the middleware' => ["\$r->attribute('middleware', ['auth']);"],
            'a dynamic method name' => ["\$m = 'middleware';\n\$r->\$m('auth');"],
        ];
    }

    public function test_an_untracked_registrar_variable_keeps_the_web_group(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Kernel.php' => self::appKernel("protected \$middlewareGroups = ['web' => ['throttle:5,1'], 'api' => []];"),
            'app/Providers/RouteServiceProvider.php' => "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Foundation\\Support\\Providers\\RouteServiceProvider as ServiceProvider;\nuse Illuminate\\Support\\Facades\\Route;\n\nclass RouteServiceProvider extends ServiceProvider\n{\n    public function boot(): void\n    {\n        \$this->routes(function () {\n            \$web = Route::middleware('web');\n            \$web->group(base_path('routes/web.php'));\n            \$web->prefix('admin')->group(base_path('routes/admin.php'));\n        });\n    }\n}\n",
            'routes/web.php' => "<?php\n\nRoute::post('/login', [LoginController::class, 'store']);\n",
            'routes/admin.php' => '<?php',
        ]);

        $this->assertSame([], $this->issueMessages($result));
    }

    /**
     * @dataProvider untrackedRegistrationProvider
     */
    #[DataProvider('untrackedRegistrationProvider')]
    public function test_a_registration_through_an_untracked_variable_keeps_the_web_group(string $then): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => self::routingBootstrap("then: function () {\n            {$then}\n        },", "\$middleware->web(append: ['throttle:5,1']);"),
            'routes/web.php' => "<?php\n\nRoute::post('/login', [LoginController::class, 'store']);\n",
            'routes/admin.php' => '<?php',
        ]);

        $this->assertSame([], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function untrackedRegistrationProvider(): array
    {
        return [
            'a registrar changed in a branch' => ["\$web = Route::middleware('web');\n            if (app()->isLocal()) {\n                \$web->prefix('dev');\n            }\n            \$web->group(base_path('routes/web.php'));"],
            'attributes written by key' => ["\$attrs = ['middleware' => 'web'];\n            \$attrs['prefix'] = 'x';\n            Route::group(\$attrs, base_path('routes/web.php'));"],
            'a registrar reused for a second group' => ["\$web = Route::middleware('web');\n            \$web->group(base_path('routes/web.php'));\n            \$web->prefix('admin')->group(base_path('routes/admin.php'));"],
        ];
    }

    /**
     * @dataProvider groupAttributeReadabilityProvider
     */
    #[DataProvider('groupAttributeReadabilityProvider')]
    public function test_unreadable_group_attributes_keep_the_web_group(string $then, bool $reported): void
    {
        $result = $this->analyzeApp([
            'bootstrap/app.php' => self::routingBootstrap("web: __DIR__.'/../routes/web.php',\n        then: function () {\n            {$then}\n        },", "\$middleware->web(append: ['throttle:5,1']);"),
            'config/routes.php' => "<?php\n\nreturn ['web' => ['middleware' => 'web']];\n",
            'routes/web.php' => '<?php',
            'routes/auth.php' => "<?php\n\nRoute::post('/login', [LoginController::class, 'store']);\n",
        ]);

        $this->assertSame($reported ? ['Login route "/login" lacks rate limiting protection'] : [], $this->issueMessages($result));
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function groupAttributeReadabilityProvider(): array
    {
        return [
            'named untracked' => ["\$attrs = ['middleware' => 'web'];\n\$attrs['prefix'] = 'x';\nRoute::group(attributes: \$attrs, routes: base_path('routes/auth.php'));", false],
            'config() in a variable' => ["\$attrs = config('routes.web');\nRoute::group(\$attrs, base_path('routes/auth.php'));", false],
            'config() inline' => ["Route::group(config('routes.web'), base_path('routes/auth.php'));", false],
            'array union' => ["\$extra = ['prefix' => 'x'];\nRoute::group(['prefix' => 'y'] + \$extra, base_path('routes/auth.php'));", false],
            'spread' => ["Route::group([...config('routes.web')], base_path('routes/auth.php'));", false],
            'array_merge()' => ["Route::group(array_merge(['prefix' => 'x'], config('routes.web')), base_path('routes/auth.php'));", false],
            'a readable literal without middleware' => ["Route::group(['prefix' => 'x'], base_path('routes/auth.php'));", true],
            'a named readable literal with web' => ["Route::group(attributes: ['middleware' => 'web'], routes: base_path('routes/auth.php'));", false],
        ];
    }

    public function test_a_middleware_statement_on_the_facade_root_router_is_discarded(): void
    {
        $result = $this->analyzeApp(['routes/web.php' => "<?php\n\n\$router = Route::getFacadeRoot();\n\$router->middleware('throttle:5,1');\n\$router->group([], function () {\n    Route::post('/login', [LoginController::class, 'store']);\n});\n"]);

        $this->assertSame(['Login route "/login" lacks rate limiting protection'], $this->issueMessages($result));
    }

    /**
     * @dataProvider unthrottledLoginRouteFormProvider
     */
    #[DataProvider('unthrottledLoginRouteFormProvider')]
    public function test_an_unthrottled_login_route_is_reported_at_its_verb_in_any_form(string $routes, int $line): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertFailed($result);
        $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
        $this->assertSame($line, $result->getIssues()[0]->location?->line);
    }

    /**
     * @return array<string, array{string, int}>
     */
    public static function unthrottledLoginRouteFormProvider(): array
    {
        return [
            'arguments on later lines' => ["<?php\n\nRoute::post(\n    '/session/login',\n    [SessionController::class, 'store']\n);\n", 3],
            'verb on a later line of its chain' => ["<?php\n\nRoute::name('session.store')\n    ->post(\n        '/session/login',\n        [SessionController::class, 'store']\n    );\n", 4],
            'match() with a methods list' => ["<?php\n\nRoute::match(['GET', 'POST'], '/session/login', [SessionController::class, 'store']);\n", 3],
            'match() with one method' => ["<?php\n\nRoute::match('post', '/session/login', [SessionController::class, 'store']);\n", 3],
            'match() with named arguments' => ["<?php\n\nRoute::match(methods: ['POST'], uri: '/session/login', action: [SessionController::class, 'store']);\n", 3],
            'an aliased facade' => ["<?php\n\nuse Illuminate\\Support\\Facades\\Route as R;\n\nR::post('/session/login', [SessionController::class, 'store']);\n", 5],
            'a chain on an aliased facade' => ["<?php\n\nuse Illuminate\\Support\\Facades\\Route as R;\n\nR::middleware('guest')->post('/session/login', [SessionController::class, 'store']);\n", 5],
            'named arguments' => ["<?php\n\nRoute::post(uri: '/session/login', action: [SessionController::class, 'store']);\n", 3],
            'named arguments out of order' => ["<?php\n\nRoute::post(action: [SessionController::class, 'store'], uri: '/session/login');\n", 3],
            'a router variable in a group' => ["<?php\n\n\$router = app('router');\n\$router->middleware('guest')->group(function () use (\$router) {\n    \$router->post('/session/login', [SessionController::class, 'store']);\n});\n", 5],
            'the router a group callback receives' => ["<?php\n\nRoute::middleware('guest')->group(function (\$routes) {\n    \$routes->post('/session/login', [SessionController::class, 'store']);\n});\n", 4],
            'the container router' => ["<?php\n\napp('router')->post('/session/login', [SessionController::class, 'store']);\n", 3],
            'a registrar variable' => ["<?php\n\n\$guest = Route::middleware('guest');\n\$guest->post('/session/login', [SessionController::class, 'store']);\n", 4],
        ];
    }

    /**
     * @dataProvider throttledLoginRouteFormProvider
     */
    #[DataProvider('throttledLoginRouteFormProvider')]
    public function test_a_throttled_login_route_passes_in_any_form(string $routes): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function throttledLoginRouteFormProvider(): array
    {
        return [
            'arguments on later lines, throttled after them' => ["<?php\n\nRoute::post(\n    '/session/login',\n    [SessionController::class, 'store']\n)->middleware('throttle:5,1');\n"],
            'arguments on later lines, in a throttled group' => ["<?php\n\nRoute::middleware('throttle:5,1')->group(function () {\n    Route::post(\n        '/session/login',\n        [SessionController::class, 'store']\n    );\n});\n"],
            'match() throttled' => ["<?php\n\nRoute::match(['GET', 'POST'], '/session/login', [SessionController::class, 'store'])->middleware('throttle:5,1');\n"],
            'an aliased facade throttled' => ["<?php\n\nuse Illuminate\\Support\\Facades\\Route as R;\n\nR::post('/session/login', [SessionController::class, 'store'])->middleware('throttle:5,1');\n"],
            'a chain on an aliased facade throttled' => ["<?php\n\nuse Illuminate\\Support\\Facades\\Route as R;\n\nR::middleware('throttle:5,1')->post('/session/login', [SessionController::class, 'store']);\n"],
            'named arguments in a throttled group' => ["<?php\n\nRoute::middleware('throttle:5,1')->group(function () {\n    Route::post(uri: '/session/login', action: [SessionController::class, 'store']);\n});\n"],
            'a router variable in a throttled group' => ["<?php\n\n\$router = app('router');\n\$router->middleware('throttle:5,1')->group(function () use (\$router) {\n    \$router->post('/session/login', [SessionController::class, 'store']);\n});\n"],
            'a router variable throttling its route' => ["<?php\n\n\$router = app('router');\n\$router->middleware('throttle:5,1')->post('/session/login', [SessionController::class, 'store']);\n"],
            'a throttling registrar variable' => ["<?php\n\n\$limited = Route::middleware('throttle:5,1');\n\$limited->post('/session/login', [SessionController::class, 'store']);\n"],
            'a registrar variable throttled by a later statement' => ["<?php\n\n\$limited = Route::prefix('account');\n\$limited->middleware('throttle:5,1');\n\$limited->post('/session/login', [SessionController::class, 'store']);\n"],
        ];
    }

    public function test_a_registrar_variable_whose_middleware_cannot_be_read_is_not_reported(): void
    {
        // A closure that imports the registrar may change it, so its middleware is unread
        $result = $this->analyzeRoutesOnly(['routes/web.php' => "<?php\n\n\$limited = Route::middleware('throttle:5,1');\nRoute::prefix('account')->group(function () use (\$limited) {\n    \$limited->post('/session/login', [SessionController::class, 'store']);\n});\n"]);

        $this->assertPassed($result);
    }

    public function test_a_named_argument_route_is_credited_with_the_throttle_its_controller_applies(): void
    {
        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/SessionSignInController.php' => $this->selfThrottlingController('App\\Http\\Controllers\\Auth', 'SessionSignInController'),
            'routes/web.php' => "<?php\n\nuse App\\Http\\Controllers\\Auth\\SessionSignInController;\n\nRoute::post(action: [SessionSignInController::class, 'store'], uri: '/session/login');\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_a_throttled_route_written_over_many_lines_covers_its_controller(): void
    {
        $routes = <<<'PHP'
<?php

use App\Http\Controllers\Auth\LoginController;

Route::post(
    '/session/login',

    // Signs the user in


    [LoginController::class, 'login'],
)->middleware('throttle:5,1');
PHP;

        $result = $this->analyzeApp([
            'app/Http/Controllers/Auth/LoginController.php' => $this->unthrottledLoginController(),
            'routes/web.php' => $routes,
        ]);

        $this->assertPassed($result);
    }

    /**
     * @dataProvider matchMethodsProvider
     */
    #[DataProvider('matchMethodsProvider')]
    public function test_a_match_route_is_judged_by_the_methods_it_lists(string $file, string $methods, ?string $message): void
    {
        $result = $this->analyzeRoutesOnly([$file => "<?php\n\nRoute::match({$methods}, '/session/login', [SessionController::class, 'store']);\n"]);

        if ($message === null) {
            $this->assertPassed($result);
        } else {
            $this->assertSame([$message], $this->issueMessages($result));
        }
    }

    /**
     * @return array<string, array{string, string, ?string}>
     */
    public static function matchMethodsProvider(): array
    {
        return [
            'GET and HEAD in a web file' => ['routes/web.php', "['GET', 'HEAD']", null],
            'POST in an API file' => ['routes/api.php', "['POST']", 'API authentication route "/session/login" lacks rate limiting protection'],
            'GET in an API file' => ['routes/api.php', "['GET']", 'API authentication route "/session/login" lacks rate limiting protection'],
            'methods in a variable' => ['routes/web.php', '$methods', null],
            'a computed method' => ['routes/web.php', "[config('auth.method')]", null],
        ];
    }

    public function test_a_commented_out_route_over_several_lines_is_not_found(): void
    {
        $routes = <<<'PHP'
<?php

/*
Route::post(
    '/session/login',
    [SessionController::class, 'store']
);
*/
// Route::post(uri: '/session/login', action: [SessionController::class, 'store']);
PHP;

        $this->assertPassed($this->analyzeRoutesOnly(['routes/web.php' => $routes]));
    }

    public function test_route_text_inside_a_string_is_not_a_route(): void
    {
        $routes = <<<'PHP'
<?php

$example = "Route::post('/session/login', [SessionController::class, 'store']);";
$help = <<<TEXT
Route::post('/session/login', [SessionController::class, 'store']);
TEXT;
logger()->info('/session/login');
PHP;

        $this->assertPassed($this->analyzeRoutesOnly(['routes/web.php' => $routes]));
    }

    public function test_a_one_line_login_route_keeps_its_line_message_and_metadata(): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::post('/session/login', [SessionController::class, 'store']);\n"]);

        $this->assertCount(1, $result->getIssues());
        $issue = $result->getIssues()[0];
        $this->assertSame('Login route "/session/login" lacks rate limiting protection', $issue->message);
        $this->assertSame(5, $issue->location?->line);
        $this->assertSame(Severity::High, $issue->severity);
        $this->assertSame('Apply rate limiting middleware to this route to cap authentication attempts and prevent brute force attacks.', $issue->recommendation);
        $this->assertSame(['route' => '/session/login', 'route_type' => 'web', 'issue_type' => 'missing_route_throttle'], $issue->metadata);
    }

    /**
     * @dataProvider writtenRouteParityProvider
     *
     * @param  list<string>  $messages
     */
    #[DataProvider('writtenRouteParityProvider')]
    public function test_a_route_keeps_the_finding_the_route_text_gave_it(string $file, string $routes, array $messages): void
    {
        $this->assertSame($messages, $this->issueMessages($this->analyzeRoutesOnly([$file => $routes])));
    }

    /**
     * @return array<string, array{string, string, list<string>}>
     */
    public static function writtenRouteParityProvider(): array
    {
        return [
            'two routes on one line report the first' => ['routes/web.php', "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']); Route::post('/signin', [SignInController::class, 'store']);\n", ['Login route "/session/login" lacks rate limiting protection']],
            'a written route before a chained one on its line' => ['routes/web.php', "<?php\n\nRoute::name('x')->post('/signin', [SignInController::class, 'store']); Route::post('/session/login', [SessionController::class, 'store']);\n", ['Login route "/session/login" lacks rate limiting protection']],
            'an API POST before a GET on its line' => ['routes/api.php', "<?php\n\nRoute::get('/auth/session', [SessionController::class, 'show']); Route::post('/token', [TokenController::class, 'store']);\n", ['API authentication route "/token" lacks rate limiting protection']],
            'an interpolated URI kept as written' => ['routes/web.php', "<?php\n\nRoute::post(\"/{\$locale}/login\", [SessionController::class, 'store']);\n", ['Login route "/{$locale}/login" lacks rate limiting protection']],
            'a URI kept as written' => ['routes/web.php', "<?php\n\nRoute::post('/session\\\\login', [SessionController::class, 'store']);\n", ['Login route "/session\\\\login" lacks rate limiting protection']],
            'a string controller' => ['routes/web.php', "<?php\n\nRoute::controller('auth', 'AuthController');\n", ['Login route "auth" lacks rate limiting protection']],
            'a resource' => ['routes/web.php', "<?php\n\nRoute::resource('auth', AuthController::class);\n", ['Login route "auth" lacks rate limiting protection']],
            'a facade name ending in Route' => ['routes/web.php', "<?php\n\nApiRoute::post('/session/login', [SessionController::class, 'store']);\n", ['Login route "/session/login" lacks rate limiting protection']],
            'a logout route' => ['routes/web.php', "<?php\n\nRoute::post('/auth/logout', [SessionController::class, 'destroy']);\n", []],
            'a GET login form' => ['routes/web.php', "<?php\n\nRoute::get('/session/login', [SessionController::class, 'create']);\n", []],
            'a URI concatenated after its literal' => ['routes/web.php', "<?php\n\nRoute::post('/session/login'.\$suffix, [SessionController::class, 'store']);\n", ['Login route "/session/login" lacks rate limiting protection']],
            'a URI literal around a variable' => ['routes/web.php', "<?php\n\nRoute::post('/auth/'.\$provider.'/callback', [SessionController::class, 'store']);\n", ['Login route "/auth/" lacks rate limiting protection']],
            'a route on the router beside a written one' => ['routes/web.php', "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']); \$router->middleware('throttle:5,1')->post('/x', [XController::class, 'store']);\n", ['Login route "/session/login" lacks rate limiting protection']],
            'two chained routes on one line report the last' => ['routes/web.php', "<?php\n\nRoute::name('a')->post('/login', [SessionController::class, 'store']); Route::name('b')->post('/signin', [SignInController::class, 'store']);\n", ['Login route "/signin" lacks rate limiting protection']],
            'two chained API routes on one line report the last' => ['routes/api.php', "<?php\n\nRoute::name('a')->post('/login', [SessionController::class, 'store']); Route::name('b')->post('/signin', [SignInController::class, 'store']);\n", ['API authentication route "/signin" lacks rate limiting protection']],
            'Auth::routes() beside a throttled route on the router' => ['routes/web.php', "<?php\n\nAuth::routes(); app('router')->middleware('throttle:5,1')->post('/x', [XController::class, 'store']);\n", ['Auth::routes() includes login endpoint without explicit rate limiting']],
            'a string controller beside a throttled route on the router' => ['routes/web.php', "<?php\n\nRoute::controller('auth', 'AuthController'); app('router')->middleware('throttle:5,1')->post('/x', [XController::class, 'store']);\n", ['Login route "auth" lacks rate limiting protection']],
            'a lookup on the facade route collection' => ['routes/api.php', "<?php\n\nRoute::getRoutes()->get('auth/login');\n", ['API authentication route "auth/login" lacks rate limiting protection']],
            'a route on the container router beside a written one' => ['routes/web.php', "<?php\n\nRoute::post('/session/login', [SessionController::class, 'store']); app('router')->middleware('throttle:5,1')->post('/x', [XController::class, 'store']);\n", ['Login route "/session/login" lacks rate limiting protection']],
        ];
    }

    /**
     * @dataProvider interpolatedUriProvider
     */
    #[DataProvider('interpolatedUriProvider')]
    public function test_an_interpolated_uri_is_read_as_written_in_any_form(string $route): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => "<?php\n\n{$route}\n"]);

        $this->assertSame(['Login route "/{$locale}/login" lacks rate limiting protection'], $this->issueMessages($result));
        $this->assertSame(3, $result->getIssues()[0]->location?->line);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function interpolatedUriProvider(): array
    {
        return [
            'named arguments' => ["Route::post(uri: \"/{\$locale}/login\", action: [SessionController::class, 'store']);"],
            'match()' => ["Route::match(['POST'], \"/{\$locale}/login\", [SessionController::class, 'store']);"],
            'the container router' => ["app('router')->post(\"/{\$locale}/login\", [SessionController::class, 'store']);"],
        ];
    }

    /**
     * @dataProvider routeOnNoRouterProvider
     */
    #[DataProvider('routeOnNoRouterProvider')]
    public function test_a_verb_on_what_may_not_be_the_bare_router_is_not_a_reported_route(string $routes): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes, 'routes/partials.php' => "<?php\n"]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function routeOnNoRouterProvider(): array
    {
        $route = "->post('/session/login', [SessionController::class, 'store']);";

        return [
            'a registrar off a router variable, imported by a closure' => ["<?php\n\n\$limited = \$router->middleware('throttle:5,1');\nRoute::prefix('account')->group(function () use (\$limited) {\n    \$limited{$route}\n});\n"],
            'a registrar off the container router, assigned in branches' => ["<?php\n\nif (\$strict) {\n    \$limited = app('router')->middleware('throttle:5,1');\n} else {\n    \$limited = app('router')->middleware('throttle:10,1');\n}\n\$limited{$route}\n"],
            'a registrar off a router variable, past a require' => ["<?php\n\n\$limited = \$router->middleware('throttle:5,1');\nrequire __DIR__.'/partials.php';\n\$limited{$route}\n"],
            'a router variable reassigned a registrar' => ["<?php\n\nRoute::prefix('account')->group(function () use (\$router) {\n    \$router = \$router->middleware('throttle:5,1');\n    \$router{$route}\n});\n"],
            'the facade root registrar, imported by a closure' => ["<?php\n\n\$limited = Route::getFacadeRoot()->middleware('throttle:5,1');\nRoute::prefix('account')->group(function () use (\$limited) {\n    \$limited{$route}\n});\n"],
            'an HTTP client named router' => ["<?php\n\n\$router = new \\GuzzleHttp\\Client();\n\$router->post('/session/login', ['json' => []]);\n"],
            'a router variable reassigned an HTTP client' => ["<?php\n\n\$router = app('router');\n\$router = new Client();\n\$router->post('/session/login', []);\n"],
            'a class imported as another Route' => ["<?php\n\nuse App\\Support\\Route as R;\n\nR::middleware('guest'){$route}\n"],
            'a copy of an HTTP client named router' => ["<?php\n\n\$router = new Client();\n\$client = \$router;\n\$client->post('/session/login', []);\n"],
            'a router bound by foreach' => ["<?php\n\nforeach (\$clients as \$router) {\n    \$router->post('/session/login', []);\n}\n"],
            'a router bound by destructuring' => ["<?php\n\n[\$router] = \$clients;\n\$router->post('/session/login', []);\n"],
            'a router bound by ??=' => ["<?php\n\n\$router ??= new Client();\n\$router->post('/session/login', []);\n"],
            'a router bound by reference' => ["<?php\n\n\$router = &\$client;\n\$router->post('/session/login', []);\n"],
            'a router bound by catch' => ["<?php\n\ntry {\n    report_now();\n} catch (\\Exception \$router) {\n    \$router->post('/session/login', []);\n}\n"],
            'a global router' => ["<?php\n\nglobal \$router;\n\$router->post('/session/login', []);\n"],
            'a static router' => ["<?php\n\nstatic \$router;\n\$router->post('/session/login', []);\n"],
            'a function parameter named router' => ["<?php\n\nfunction send(\$router)\n{\n    \$router->post('/session/login', []);\n}\n"],
            'a route action parameter named router' => ["<?php\n\nRoute::get('/x', function (\$router) {\n    \$router->post('/session/login', []);\n});\n"],
            'the second group callback parameter' => ["<?php\n\nRoute::group([], function (\$routes, \$router) {\n    \$router->post('/session/login', []);\n});\n"],
            'extract() binding router' => ["<?php\n\nextract(['router' => new \\GuzzleHttp\\Client()]);\n\$router->post('/session/login', []);\n"],
            'a variable variable binding router' => ["<?php\n\n\$name = 'router';\n\$\$name = new Client();\n\$router->post('/session/login', []);\n"],
            'a router property of a class' => ["<?php\n\nclass SsoClient\n{\n    public function __construct(private \\GuzzleHttp\\Client \$router) {}\n\n    public function signIn()\n    {\n        return \$this->router->post('/session/login', []);\n    }\n}\n"],
            'a free router variable' => ["<?php\n\n\$router{$route}\n"],
            'a group callback held in a variable' => ["<?php\n\n\$auth = function (\$router) {\n    \$router{$route}\n};\nRoute::middleware('throttle:5,1')->group(\$auth);\n"],
        ];
    }

    public function test_a_file_required_after_router_is_assigned_does_not_read_router_as_the_router(): void
    {
        $result = $this->analyzeRoutesOnly([
            'routes/web.php' => "<?php\n\n\$router = Route::middleware('throttle:5,1');\nrequire __DIR__.'/auth.php';\n",
            'routes/auth.php' => "<?php\n\n\$router->post('/session/login', [LoginController::class, 'login']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_a_free_router_variable_in_a_required_route_file_registers_no_route(): void
    {
        // Laravel requires a route file with $router in scope, but nothing in the file says
        // what it holds, so the name alone records no route
        $result = $this->analyzeRoutesOnly([
            'routes/web.php' => "<?php\n\nrequire __DIR__.'/auth.php';\n",
            'routes/auth.php' => "<?php\n\n\$router->post('/session/login', [LoginController::class, 'login']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_a_router_variable_bound_before_a_provider_requires_a_route_file_registers_no_route(): void
    {
        $result = $this->analyzeRoutesOnly([
            'app/Providers/AccountRouteProvider.php' => self::bootingProvider('AccountRouteProvider', "\$router = Route::middleware('throttle:5,1');\n        require base_path('routes/auth.php');"),
            'routes/web.php' => "<?php\n",
            'routes/auth.php' => "<?php\n\n\$router->post('/session/login', [SessionController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    /**
     * @dataProvider routeHeldOffARegistrarProvider
     */
    #[DataProvider('routeHeldOffARegistrarProvider')]
    public function test_middleware_on_a_route_held_in_a_variable_reaches_it(string $routes, bool $reported): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        if ($reported) {
            $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
            $this->assertSame(4, $result->getIssues()[0]->location?->line);
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function routeHeldOffARegistrarProvider(): array
    {
        $route = "\$route = \$guest->post('/session/login', [SessionController::class, 'store']);";

        return [
            'throttled' => ["<?php\n\n\$guest = Route::middleware('guest');\n{$route}\n\$route->middleware('throttle:5,1');\n", false],
            'throttled in a group' => ["<?php\n\nRoute::prefix('account')->group(function () {\n    \$guest = Route::middleware('guest'); {$route}\n    \$route->middleware('throttle:5,1');\n});\n", false],
            'given other middleware' => ["<?php\n\n\$guest = Route::middleware('guest');\n{$route}\n\$route->middleware('verified');\n", true],
        ];
    }

    /**
     * @dataProvider registrarDerivedFromARegistrarProvider
     */
    #[DataProvider('registrarDerivedFromARegistrarProvider')]
    public function test_middleware_set_on_a_registrar_derived_from_another_reaches_its_group(string $middleware, bool $reported): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => "<?php\n\n\$base = Route::name('session.');\n\$scoped = \$base->prefix('account');\n\$scoped->middleware('{$middleware}');\n\n\$scoped->group(function () {\n    Route::post('/session/login', [SessionController::class, 'store']);\n});\n"]);

        if ($reported) {
            $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function registrarDerivedFromARegistrarProvider(): array
    {
        return [
            'throttled' => ['throttle:5,1', false],
            'given other middleware' => ['verified', true],
        ];
    }

    /**
     * @dataProvider routeHeldOffARouterProvider
     */
    #[DataProvider('routeHeldOffARouterProvider')]
    public function test_middleware_on_a_route_held_off_a_known_router_reaches_it(string $routes, bool $reported): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        if ($reported) {
            $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function routeHeldOffARouterProvider(): array
    {
        $action = "('/session/login', [SessionController::class, 'store']);";
        $cases = [];
        foreach (['throttle:5,1' => false, 'verified' => true] as $middleware => $reported) {
            $later = "\$route->middleware('{$middleware}');";
            $cases += [
                "the group callback router, given {$middleware}" => ["<?php\n\nRoute::group([], function (\$r) {\n    \$route = \$r->post{$action}\n    {$later}\n});\n", $reported],
                "a router variable, given {$middleware}" => ["<?php\n\n\$r = app('router');\n\$route = \$r->post{$action}\n{$later}\n", $reported],
                "a named route off a router variable, given {$middleware}" => ["<?php\n\n\$r = app('router');\n\$route = \$r->name('login')->post{$action}\n{$later}\n", $reported],
                "a registrar off the container router, given {$middleware}" => ["<?php\n\n\$route = app('router')->middleware('guest')->post{$action}\n{$later}\n", $reported],
            ];
        }

        return $cases + [
            'the group throttle excluded later' => ["<?php\n\nRoute::middleware('throttle:5,1')->group(function (\$r) {\n    \$route = \$r->post{$action}\n    \$route->withoutMiddleware('throttle:5,1');\n});\n", true],
        ];
    }

    /**
     * @dataProvider shadowedRouterProvider
     */
    #[DataProvider('shadowedRouterProvider')]
    public function test_a_parameter_shadowing_a_router_variable_is_not_the_router(string $routes, bool $reported): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes]);

        if ($reported) {
            $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function shadowedRouterProvider(): array
    {
        return [
            'an arrow function parameter' => ["<?php\n\n\$r = app('router');\ncollect(\$clients)->each(fn (\$r) => \$r->post('/session/login', ['json' => []]));\n", false],
            'an arrow function parameter in a group callback' => ["<?php\n\nRoute::middleware('guest')->group(function (\$router) {\n    collect(\$clients)->each(fn (\$router) => \$router->post('/session/login', []));\n});\n", false],
            'an arrow function reading the router' => ["<?php\n\n\$r = app('router');\ncollect(\$clients)->each(fn () => \$r->post('/session/login', [SessionController::class, 'store']));\n", true],
        ];
    }

    /**
     * @dataProvider routerPastARequireProvider
     */
    #[DataProvider('routerPastARequireProvider')]
    public function test_a_router_variable_is_unread_past_a_require(string $routes, bool $reported): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => $routes, 'routes/limits.php' => "<?php\n\n\$r = \$r->middleware('throttle:5,1');\n"]);

        if ($reported) {
            $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function routerPastARequireProvider(): array
    {
        $route = "\$r->post('/session/login', [SessionController::class, 'store']);";

        return [
            'after a require' => ["<?php\n\n\$r = app('router');\nrequire __DIR__.'/limits.php';\n{$route}\n", false],
            'after an include_once' => ["<?php\n\n\$r = app('router');\ninclude_once __DIR__.'/limits.php';\n{$route}\n", false],
            'before a require' => ["<?php\n\n\$r = app('router');\n{$route}\nrequire __DIR__.'/limits.php';\n", true],
        ];
    }

    /**
     * @dataProvider routeCollectionLookupProvider
     */
    #[DataProvider('routeCollectionLookupProvider')]
    public function test_a_lookup_on_the_route_collection_is_not_a_route(string $routes): void
    {
        $this->assertPassed($this->analyzeRoutesOnly(['routes/web.php' => "<?php\n", 'routes/api.php' => $routes]));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function routeCollectionLookupProvider(): array
    {
        return [
            'held off the facade' => ["<?php\n\n\$routes = Route::getRoutes();\n\$found = \$routes->get('auth/login');\n"],
            'off the container router' => ["<?php\n\napp('router')->getRoutes()->get('api/auth/login');\n"],
            'off a router variable' => ["<?php\n\n\$r = app('router');\n\$r->getRoutes()->get('api/auth/login');\n"],
        ];
    }

    /**
     * @dataProvider knownRouterChainProvider
     */
    #[DataProvider('knownRouterChainProvider')]
    public function test_a_chain_on_a_known_router_is_read_from_its_calls(string $routes, bool $reported, bool $webThrottle = false): void
    {
        $kernel = "<?php\n\nnamespace App\\Http;\n\nuse Illuminate\\Foundation\\Http\\Kernel as HttpKernel;\n\nclass Kernel extends HttpKernel\n{\n    protected \$middlewareGroups = ['web' => ['throttle:60,1']];\n}\n";
        $files = $webThrottle ? ['app/Http/Kernel.php' => $kernel] : [];
        $result = $this->analyzeRoutesOnly([...$files, 'routes/web.php' => $routes]);

        if ($reported) {
            $this->assertSame(['Login route "/session/login" lacks rate limiting protection'], $this->issueMessages($result));
        } else {
            $this->assertPassed($result);
        }
    }

    /**
     * @return array<string, array{0: string, 1: bool, 2?: bool}>
     */
    public static function knownRouterChainProvider(): array
    {
        $action = "('/session/login', [SessionController::class, 'store']);";
        $callback = "<?php\n\nRoute::middleware('guest')->group(function (\$router) {\n    \$router->%s->post{$action}\n});\n";

        return [
            'a prefix on a router variable' => ["<?php\n\n\$r = app('router');\n\$r->prefix('account')->post{$action}\n", true],
            'a registrar held off a router variable' => ["<?php\n\n\$r = app('router');\n\$account = \$r->prefix('account');\n\$account->post{$action}\n", true],
            'a prefix on the group callback router' => [sprintf($callback, "prefix('account')"), true],
            'a name on the group callback router' => [sprintf($callback, "name('session.store')"), true],
            'the web throttle excluded on the group callback router' => [sprintf($callback, "withoutMiddleware('throttle:60,1')"), true, true],
            'a throttle on a router variable' => ["<?php\n\n\$r = app('router');\n\$r->prefix('account')->middleware('throttle:5,1')->post{$action}\n", false],
            'a throttle on the group callback router' => [sprintf($callback, "prefix('account')->middleware('throttle:5,1')"), false],
            'the web throttle on the group callback router' => [sprintf($callback, "prefix('account')"), false, true],
        ];
    }

    public function test_a_match_chained_after_the_facade_is_judged_by_its_methods(): void
    {
        $result = $this->analyzeRoutesOnly(['routes/web.php' => "<?php\n\nRoute::middleware('guest')->match(['GET'], '/session/login', [SessionController::class, 'create']);\n"]);

        $this->assertPassed($result);
    }

    private static function bootingProvider(string $class, string $boot): string
    {
        return "<?php\n\nnamespace App\\Providers;\n\nuse Illuminate\\Support\\Facades\\Route;\nuse Illuminate\\Support\\ServiceProvider;\n\nclass {$class} extends ServiceProvider\n{\n    public function boot(): void\n    {\n        {$boot}\n    }\n}\n";
    }

    private static function routingBootstrap(string $routing, string $middleware = '//'): string
    {
        return "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Foundation\\Configuration\\Middleware;\nuse Illuminate\\Support\\Facades\\Route;\n\n"
            ."return Application::configure(basePath: dirname(__DIR__))\n    ->withRouting(\n        {$routing}\n    )\n"
            ."    ->withMiddleware(function (Middleware \$middleware): void {\n        {$middleware}\n    })\n    ->create();\n";
    }
}
