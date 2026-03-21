<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Support\BootstrapRouteParser;

class BootstrapRouteParserTest extends TestCase
{
    private AstParser $parser;

    protected function setUp(): void
    {
        parent::setUp();
        $this->parser = new AstParser;
    }

    /**
     * Create a temporary directory with the given files and return the path.
     *
     * @param  array<string, string>  $files
     */
    private function createTempDir(array $files = []): string
    {
        $tempDir = sys_get_temp_dir().'/bootstrap_route_parser_test_'.uniqid();
        mkdir($tempDir, 0755, true);

        foreach ($files as $filename => $content) {
            $filepath = $tempDir.'/'.$filename;
            $dirname = dirname($filepath);
            if (! is_dir($dirname)) {
                mkdir($dirname, 0755, true);
            }
            file_put_contents($filepath, $content);
        }

        return $tempDir;
    }

    private function removeDir(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }
        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $path = $dir.'/'.$file;
            is_dir($path) ? $this->removeDir($path) : unlink($path);
        }
        rmdir($dir);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        // Cleanup happens per-test via reference
    }

    public function test_returns_empty_when_no_web_php_or_bootstrap_exists(): void
    {
        $tempDir = $this->createTempDir(['routes/auth.php' => '<?php // empty']);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_require_from_web_php(): void
    {
        $webPhp = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

require __DIR__.'/auth.php';
PHP;

        $tempDir = $this->createTempDir([
            'routes/web.php' => $webPhp,
            'routes/auth.php' => '<?php // auth routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/auth.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_require_once_from_web_php(): void
    {
        $webPhp = <<<'PHP'
<?php

require_once __DIR__.'/auth.php';
PHP;

        $tempDir = $this->createTempDir([
            'routes/web.php' => $webPhp,
            'routes/auth.php' => '<?php // auth routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/auth.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_chained_web_middleware_group_in_bootstrap(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
        then: function () {
            Route::middleware('web')
                ->prefix('auth')
                ->group(base_path('routes/auth.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/auth.php' => '<?php // auth routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/auth.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_ignores_api_middleware_group_in_bootstrap(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::middleware('api')
                ->group(base_path('routes/auth.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/auth.php' => '<?php // auth routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            // 'api' middleware should NOT be considered web-protected
            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_handles_multi_segment_chain_in_bootstrap(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::middleware('web')
                ->prefix('admin')
                ->name('admin.')
                ->group(base_path('routes/admin.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/admin.php' => '<?php // admin routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/admin.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_deduplicates_files_found_in_both_sources(): void
    {
        // auth.php is both require'd from web.php AND registered in bootstrap/app.php
        $webPhp = <<<'PHP'
<?php
require __DIR__.'/auth.php';
PHP;

        $bootstrapApp = <<<'PHP'
<?php

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::middleware('web')
                ->group(base_path('routes/auth.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'routes/web.php' => $webPhp,
            'routes/auth.php' => '<?php // auth routes',
            'bootstrap/app.php' => $bootstrapApp,
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            // Should not duplicate the same file
            $this->assertCount(1, $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_does_not_include_nonexistent_required_file(): void
    {
        $webPhp = <<<'PHP'
<?php
require __DIR__.'/nonexistent.php';
PHP;

        $tempDir = $this->createTempDir([
            'routes/web.php' => $webPhp,
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            // File doesn't exist — should not be included
            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_returns_empty_when_web_php_is_unparseable(): void
    {
        $tempDir = $this->createTempDir([
            'routes/web.php' => '<?php = = invalid syntax',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_returns_empty_when_bootstrap_is_unparseable(): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => '<?php = = invalid syntax',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_ignores_group_call_with_no_arguments(): void
    {
        $bootstrapApp = <<<'PHP'
<?php
Route::middleware('web')->group();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_ignores_group_call_with_bare_string_argument(): void
    {
        $bootstrapApp = <<<'PHP'
<?php
Route::middleware('web')->group('routes/auth.php');
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/auth.php' => '<?php // auth routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            // Bare string (not base_path()) — should not be detected
            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_ignores_group_call_with_non_base_path_function(): void
    {
        $bootstrapApp = <<<'PHP'
<?php
Route::middleware('web')->group(app_path('routes/auth.php'));
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/auth.php' => '<?php // auth routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            // app_path() is not base_path() — should not be detected
            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_ignores_group_with_base_path_and_no_arguments(): void
    {
        $bootstrapApp = <<<'PHP'
<?php
Route::middleware('web')->group(base_path());
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            // base_path() with no args — unresolvable
            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_ignores_group_with_base_path_and_variable_argument(): void
    {
        $bootstrapApp = <<<'PHP'
<?php
Route::middleware('web')->group(base_path($routeFile));
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            // base_path($var) — dynamic path, unresolvable statically
            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_require_with_bare_relative_string(): void
    {
        $webPhp = <<<'PHP'
<?php
require 'auth.php';
PHP;

        $tempDir = $this->createTempDir([
            'routes/web.php' => $webPhp,
            'routes/auth.php' => '<?php // auth routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/auth.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_ignores_dynamic_variable_require(): void
    {
        $webPhp = <<<'PHP'
<?php
require $file;
PHP;

        $tempDir = $this->createTempDir([
            'routes/web.php' => $webPhp,
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            // Variable require — cannot be resolved statically
            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    // ==================== getApiRegisteredRouteFiles Tests ====================

    public function test_detects_api_string_middleware_group_in_bootstrap(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::middleware('api')
                ->group(base_path('routes/api-v1.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/api-v1.php' => '<?php // v1 api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getApiRegisteredRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/api-v1.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_api_array_middleware_group_in_bootstrap(): void
    {
        // Platform's exact pattern: ->middleware(['api', 'throttle:api.rest'])
        $bootstrapApp = <<<'PHP'
<?php

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

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/api-v1.php' => '<?php // v1 api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getApiRegisteredRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/api-v1.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_require_from_api_php(): void
    {
        $apiPhp = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/user', function () {});

require __DIR__.'/api-v1.php';
PHP;

        $tempDir = $this->createTempDir([
            'routes/api.php' => $apiPhp,
            'routes/api-v1.php' => '<?php // v1 api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getApiRegisteredRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/api-v1.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    // ==================== getThrottleProtectedRouteFiles Tests ====================

    public function test_detects_throttle_string_middleware_group_in_bootstrap(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::prefix('api/v1')
                ->middleware('throttle:5,1')
                ->group(base_path('routes/api-v1.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/api-v1.php' => '<?php // v1 api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getThrottleProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/api-v1.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_throttle_in_array_middleware_group_in_bootstrap(): void
    {
        // Platform's exact pattern: ->middleware(['api', 'throttle:api.rest'])
        $bootstrapApp = <<<'PHP'
<?php

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

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/api-v1.php' => '<?php // v1 api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getThrottleProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/api-v1.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_ignores_files_without_throttle_middleware(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::prefix('api/v1')
                ->middleware(['api'])
                ->group(base_path('routes/api-v1.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/api-v1.php' => '<?php // v1 api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getThrottleProtectedRouteFiles();

            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttle_returns_empty_when_no_bootstrap_exists(): void
    {
        $tempDir = $this->createTempDir(['routes/api-v1.php' => '<?php // empty']);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getThrottleProtectedRouteFiles();

            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttle_returns_empty_when_bootstrap_is_unparseable(): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => '<?php = = invalid syntax',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getThrottleProtectedRouteFiles();

            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttle_ignores_group_call_with_no_arguments(): void
    {
        $bootstrapApp = <<<'PHP'
<?php
Route::middleware('throttle:5,1')->group();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getThrottleProtectedRouteFiles();

            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttle_ignores_group_call_with_non_base_path_function(): void
    {
        $bootstrapApp = <<<'PHP'
<?php
Route::middleware('throttle:5,1')->group(app_path('routes/api-v1.php'));
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/api-v1.php' => '<?php // v1 api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getThrottleProtectedRouteFiles();

            // app_path() is not base_path() — should not be detected
            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    // ==================== withRouting(api:/web:) named argument Tests ====================

    public function test_detects_single_api_file_in_with_routing_api_arg(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/api.php' => '<?php // api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getApiRegisteredRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/api.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_array_of_api_files_in_with_routing_api_arg(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        api: [__DIR__.'/../routes/v1/api.php', __DIR__.'/../routes/v2/api.php'],
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/v1/api.php' => '<?php // v1 api routes',
            'routes/v2/api.php' => '<?php // v2 api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getApiRegisteredRouteFiles();

            $this->assertCount(2, $result);
            $this->assertStringEndsWith('/routes/v1/api.php', $result[0]);
            $this->assertStringEndsWith('/routes/v2/api.php', $result[1]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_web_file_in_with_routing_web_arg(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/web.php' => '<?php // web routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/web.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_base_path_form_in_with_routing_api_arg(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        api: base_path('routes/api.php'),
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/api.php' => '<?php // api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getApiRegisteredRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/api.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_api_list_does_not_include_web_registered_files(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::middleware('web')
                ->group(base_path('routes/auth.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/auth.php' => '<?php // web auth routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getApiRegisteredRouteFiles();

            // 'web' middleware group — should NOT appear in the API list
            $this->assertSame([], $result);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    // ==================== app/Providers/ RouteServiceProvider Tests ====================

    public function test_detects_api_middleware_group_in_providers_dir(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Route;

class RoutingServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->routes(function () {
            Route::middleware('api')
                ->prefix('api')
                ->group(base_path('routes/api.php'));
        });
    }
}
PHP;

        $tempDir = $this->createTempDir([
            'app/Providers/RoutingServiceProvider.php' => $provider,
            'routes/api.php' => '<?php // api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getApiRegisteredRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/api.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_web_middleware_group_in_providers_dir(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Route;

class RoutingServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->routes(function () {
            Route::middleware('web')
                ->group(base_path('routes/web.php'));
        });
    }
}
PHP;

        $tempDir = $this->createTempDir([
            'app/Providers/RoutingServiceProvider.php' => $provider,
            'routes/web.php' => '<?php // web routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/web.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_versioned_api_files_in_providers_dir(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Route;

class RoutingServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->routes(function () {
            Route::middleware('api')
                ->prefix('api/v1')
                ->group(base_path('routes/v1/api.php'));

            Route::middleware('api')
                ->prefix('api/v2')
                ->group(base_path('routes/v2/api.php'));
        });
    }
}
PHP;

        $tempDir = $this->createTempDir([
            'app/Providers/RoutingServiceProvider.php' => $provider,
            'routes/v1/api.php' => '<?php // v1 api routes',
            'routes/v2/api.php' => '<?php // v2 api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getApiRegisteredRouteFiles();

            $this->assertCount(2, $result);
            $this->assertStringEndsWith('/routes/v1/api.php', $result[0]);
            $this->assertStringEndsWith('/routes/v2/api.php', $result[1]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_returns_empty_when_providers_dir_missing(): void
    {
        $tempDir = $this->createTempDir([
            'routes/api.php' => '<?php // api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame([], $parser->getApiRegisteredRouteFiles());
            $this->assertSame([], $parser->getWebProtectedRouteFiles());
        } finally {
            $this->removeDir($tempDir);
        }
    }
}
