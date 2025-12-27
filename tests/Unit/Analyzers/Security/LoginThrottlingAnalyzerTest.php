<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\LoginThrottlingAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class LoginThrottlingAnalyzerTest extends AnalyzerTestCase
{
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

    public function test_detects_get_login_routes(): void
    {
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('/login', $result);
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

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapCode,
            'routes/web.php' => '<?php // empty routes',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'routes']);

        $result = $analyzer->analyze();

        // Has global RateLimiter usage (from hasRateLimiterUsage check), so should pass
        $this->assertPassed($result);
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

    public function test_skips_api_routes_file(): void
    {
        $routeCode = <<<'PHP'
<?php

// API routes typically use token auth
Route::post('/auth/login', [ApiAuthController::class, 'login']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/api.php' => $routeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // api.php is skipped (line 147-148)
        $this->assertPassed($result);
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

return [
    'features' => [
        'registration' => true,
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

        // Breeze with default Fortify routes (no custom routes/auth.php)
        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
            'routes/web.php' => '<?php // empty - uses Fortify routes',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should pass - Breeze uses Fortify which includes throttling by default
        // No custom routes/auth.php means using defaults
        $this->assertPassed($result);
    }

    public function test_breeze_with_custom_unthrottled_routes_fails(): void
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

        // Should fail - custom routes without throttling
        $this->assertFailed($result);
        $this->assertHasIssueContaining('custom authentication routes', $result);
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
}
