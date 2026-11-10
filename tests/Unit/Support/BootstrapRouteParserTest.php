<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Support\BootstrapRouteParser;
use ShieldCI\Tests\Concerns\CreatesTemporaryPaths;

class BootstrapRouteParserTest extends TestCase
{
    use CreatesTemporaryPaths;

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
        $tempDir = $this->uniqueTempPath('bootstrap_route_parser_test_');
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

    public function test_with_routing_taken_as_a_first_class_callable_registers_no_files(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

$routing = Application::configure(basePath: dirname(__DIR__))->withRouting(...);
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/api.php' => '<?php // api routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame([], $parser->getApiRegisteredRouteFiles());
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

    // ==================== Middleware given as several arguments ====================

    /**
     * @dataProvider groupMiddlewareArgumentsProvider
     */
    #[DataProvider('groupMiddlewareArgumentsProvider')]
    public function test_group_membership_reads_every_middleware_argument(string $registration, string $group, bool $expected): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $this->bootstrapRegistering('', $registration),
            'routes/partner.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $group === 'web'
                ? $parser->getWebProtectedRouteFiles()
                : $parser->getApiRegisteredRouteFiles();

            if ($expected) {
                $this->assertCount(1, $result);
                $this->assertStringEndsWith('/routes/partner.php', $result[0]);
            } else {
                $this->assertSame([], $result);
            }
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function groupMiddlewareArgumentsProvider(): array
    {
        $file = "base_path('routes/partner.php')";

        return [
            'web as a later argument' => ["Route::middleware('auth', 'web')->group({$file});", 'web', true],
            'web as a later argument mid-chain' => ["Route::prefix('partner')->middleware('auth', 'web')->group({$file});", 'web', true],
            'api as a later argument' => ["Route::middleware('auth:sanctum', 'api')->group({$file});", 'api', true],
            // Laravel takes only the array when the first argument is one, and drops the rest.
            'web after a leading array' => ["Route::middleware(['auth'], 'web')->group({$file});", 'web', false],
            'name that only starts with web' => ["Route::middleware('auth', 'webhooks')->group({$file});", 'web', false],
        ];
    }

    public function test_detects_web_given_as_a_later_middleware_argument_in_providers_dir(): void
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
            Route::middleware('auth', 'web')
                ->group(base_path('routes/partner.php'));
        });
    }
}
PHP;

        $tempDir = $this->createTempDir([
            'app/Providers/RouteServiceProvider.php' => $provider,
            'routes/partner.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/partner.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    // ==================== Middleware in the group attribute array ====================

    /**
     * @dataProvider groupAttributeArrayProvider
     * @dataProvider groupNestingProvider
     */
    #[DataProvider('groupAttributeArrayProvider')]
    #[DataProvider('groupNestingProvider')]
    public function test_group_membership_reads_the_group_attribute_array(string $registration, string $group, bool $expected): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $this->bootstrapRegistering('', $registration),
            'routes/partner.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $group === 'web'
                ? $parser->getWebProtectedRouteFiles()
                : $parser->getApiRegisteredRouteFiles();

            if ($expected) {
                $this->assertCount(1, $result);
                $this->assertStringEndsWith('/routes/partner.php', $result[0]);
            } else {
                $this->assertSame([], $result);
            }
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function groupAttributeArrayProvider(): array
    {
        $file = "base_path('routes/partner.php')";

        return [
            'web as a string' => ["Route::group(['middleware' => 'web'], {$file});", 'web', true],
            'web in a list after another middleware' => ["Route::group(['middleware' => ['auth', 'web']], {$file});", 'web', true],
            'api in a list' => ["Route::group(['middleware' => ['api']], {$file});", 'api', true],
            'api next to a prefix' => ["Route::group(['prefix' => 'partner', 'middleware' => 'api'], {$file});", 'api', true],
            'web on a router variable' => ["\$router->group(['middleware' => 'web'], {$file});", 'web', true],
            'web on a closure that requires the file' => ["Route::group(['middleware' => 'web'], function () { require __DIR__.'/../routes/partner.php'; });", 'web', true],
            'web under another key' => ["Route::group(['prefix' => 'web'], {$file});", 'web', false],
            'name that only starts with web' => ["Route::group(['middleware' => 'webhooks'], {$file});", 'web', false],
            'api is not web' => ["Route::group(['middleware' => 'api'], {$file});", 'web', false],
            'web that is excluded' => ["Route::group(['middleware' => 'web', 'excluded_middleware' => 'web'], {$file});", 'web', false],
            'web excluded from a list' => ["Route::group(['middleware' => 'web', 'excluded_middleware' => ['auth', 'web']], {$file});", 'web', false],
            'group method in another case' => ["Route::Group(['middleware' => 'web'], {$file});", 'web', true],
            'file given relative to __DIR__' => ["Route::group(['middleware' => 'web'], __DIR__.'/../routes/partner.php');", 'web', true],
            // Laravel requires a bare string from the working directory, not the declaring file's
            'file given as a bare relative string' => ["Route::group(['middleware' => 'web'], '../routes/partner.php');", 'web', false],
        ];
    }

    /**
     * Group middleware as Laravel merges it: from every enclosing group, with exclusion at
     * any level winning.
     *
     * @return array<string, array{string, string, bool}>
     */
    public static function groupNestingProvider(): array
    {
        $file = "base_path('routes/partner.php')";

        return [
            'web excluded on the chain' => ["Route::middleware('web')->withoutMiddleware('web')->group({$file});", 'web', false],
            'chain group method in another case' => ["Route::middleware('api')->Group({$file});", 'api', true],
            'web from an enclosing group' => ["Route::middleware('web')->group(function () { Route::group(['prefix' => 'partner'], {$file}); });", 'web', true],
            'api from an enclosing attribute array' => ["Route::group(['middleware' => 'api'], function () { Route::prefix('partner')->group({$file}); });", 'api', true],
            'require two groups deep' => ["Route::middleware('web')->group(function () { Route::prefix('partner')->group(function () { require __DIR__.'/../routes/partner.php'; }); });", 'web', true],
            'web excluded by an inner group' => ["Route::middleware('web')->group(function () { Route::withoutMiddleware('web')->group({$file}); });", 'web', false],
            'web excluded by an outer group' => ["Route::group(['excluded_middleware' => 'web'], function () { Route::middleware('web')->group({$file}); });", 'web', false],
            'sibling group does not reach' => ["Route::middleware('web')->group(function () {}); Route::prefix('partner')->group({$file});", 'web', false],
        ];
    }

    public function test_detects_api_group_attribute_array_in_providers_dir(): void
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
            Route::group(['middleware' => 'api', 'prefix' => 'partner'], base_path('routes/partner.php'));
        });
    }
}
PHP;

        $tempDir = $this->createTempDir([
            'app/Providers/RouteServiceProvider.php' => $provider,
            'routes/partner.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getApiRegisteredRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/partner.php', $result[0]);
            $this->assertSame([], $parser->getWebProtectedRouteFiles());
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_files_required_inside_web_middleware_group_closure(): void
    {
        // Compass pattern: route files are require'd inside a ->group(Closure) on a
        // Route::domain()->middleware('web') chain, rather than via ->group(base_path()).
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::domain(config('app.domain'))
                ->middleware('web')
                ->group(function () {
                    require __DIR__.'/../routes/auth.php';
                    require __DIR__.'/../routes/settings.php';
                });
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/auth.php' => '<?php // auth routes',
            'routes/settings.php' => '<?php // settings routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getWebProtectedRouteFiles();

            $this->assertCount(2, $result);
            $this->assertTrue($this->endsWithMatch($result, '/routes/auth.php'));
            $this->assertTrue($this->endsWithMatch($result, '/routes/settings.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_ignores_files_required_inside_group_closure_without_web_middleware(): void
    {
        // True positive preserved: a closure group with no 'web' middleware must NOT
        // mark the required file as web-protected.
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::prefix('legacy')
                ->group(function () {
                    require __DIR__.'/../routes/legacy.php';
                });
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/legacy.php' => '<?php // legacy routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame([], $parser->getWebProtectedRouteFiles());
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_files_required_through_base_path_inside_a_provider_group(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class PartnerRouteServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Route::middleware('api')->prefix('partner')->group(function () {
            require base_path('routes/partner.php');
        });
    }
}
PHP;

        $tempDir = $this->createTempDir([
            'app/Providers/PartnerRouteServiceProvider.php' => $provider,
            'routes/partner.php' => '<?php // partner routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertTrue($this->endsWithMatch($parser->getApiRegisteredRouteFiles(), '/routes/partner.php'));
            $registered = array_column($parser->getGroupRegisteredRouteFiles(), 'file');
            $this->assertTrue($this->endsWithMatch($registered, '/routes/partner.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_detects_files_required_through_base_path_from_web_php(): void
    {
        $tempDir = $this->createTempDir([
            'routes/web.php' => "<?php\n\nrequire base_path('routes/account.php');\n",
            'routes/account.php' => '<?php // account routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertTrue($this->endsWithMatch($parser->getWebProtectedRouteFiles(), '/routes/account.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @dataProvider groupReceiverProvider
     */
    #[DataProvider('groupReceiverProvider')]
    public function test_only_groups_on_the_router_register_route_files(string $imports, string $registration, bool $registers): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $this->bootstrapRegistering($imports, $registration),
            'routes/partner.php' => '<?php // partner routes',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame($registers, $this->endsWithMatch($parser->getWebProtectedRouteFiles(), '/routes/partner.php'));
            $this->assertSame($registers, $this->endsWithMatch(array_column($parser->getGroupRegisteredRouteFiles(), 'file'), '/routes/partner.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function groupReceiverProvider(): array
    {
        $require = "function () { require base_path('routes/partner.php'); }";

        return [
            'Route facade' => ['', "Route::middleware('web')->group({$require});", true],
            'Route facade static group' => ['', "Route::group(['middleware' => 'web'], {$require});", true],
            'aliased Route facade' => ['use Illuminate\Support\Facades\Route as Routes;', "Routes::middleware('web')->group({$require});", true],
            '$router variable' => ['', "\$router->middleware('web')->group({$require});", true],
            '$this->router' => ['', "\$this->router->middleware('web')->group({$require});", true],
            "container's router by array access" => ['', "\$this->app['router']->middleware('web')->group({$require});", true],
            "app('router')" => ['', "app('router')->middleware('web')->group({$require});", true],
            'resolve(Router::class)' => ['use Illuminate\Routing\Router;', "resolve(Router::class)->middleware('web')->group({$require});", true],
            'app()->make(Registrar::class)' => ['use Illuminate\Contracts\Routing\Registrar;', "app()->make(Registrar::class)->middleware('web')->group({$require});", true],
            'another container binding' => ['', "app('pipeline')->middleware('web')->group({$require});", false],
            'parameter typed Router' => ['use Illuminate\Routing\Router;', "(function (Router \$routes) { \$routes->middleware('web')->group(function () { require base_path('routes/partner.php'); }); })(app('router'));", true],
            "group callback's first parameter" => ['', "Route::prefix('v1')->group(function (\$r) { \$r->middleware('web')->group(function () { require base_path('routes/partner.php'); }); });", true],
            'router captured by use()' => ['', "Route::prefix('v1')->group(function (\$r) { collect([1])->each(function () use (\$r) { \$r->middleware('web')->group(function () { require base_path('routes/partner.php'); }); }); });", true],
            "container's make('router')" => ['', "\$this->app->make('router')->middleware('web')->group({$require});", true],
            "container's router property" => ['', "\$this->app->router->middleware('web')->group({$require});", true],
            "container's get(Router::class)" => ['use Illuminate\Routing\Router;', "\$this->app->get(Router::class)->middleware('web')->group({$require});", true],
            'App facade make' => ['use Illuminate\Support\Facades\App;', "App::make('router')->middleware('web')->group({$require});", true],
            'Container::getInstance()' => ['use Illuminate\Container\Container;', "Container::getInstance()['router']->middleware('web')->group({$require});", true],
            'variable assigned the router' => ['', "\$r = \$this->app['router']; \$r->middleware('web')->group({$require});", true],
            'variable assigned something else afterwards' => ['', "\$r = app('router'); \$r = collect(); \$r->middleware('web')->group({$require});", false],
            "container's other binding" => ['', "\$this->app->make('pipeline')->middleware('web')->group({$require});", false],
            'parameter typed ?Router' => ['use Illuminate\Routing\Router;', "(function (?Router \$routes) { \$routes->middleware('web')->group(function () { require base_path('routes/partner.php'); }); })(app('router'));", true],
            'parameter typed Router|Registrar' => ['use Illuminate\Routing\Router; use Illuminate\Contracts\Routing\Registrar;', "(function (Router|Registrar \$routes) { \$routes->middleware('web')->group(function () { require base_path('routes/partner.php'); }); })(app('router'));", true],
            'arrow function inheriting a router variable' => ['', "Route::prefix('v1')->group(function (\$r) { collect([1])->each(fn () => \$r->middleware('web')->group(function () { require base_path('routes/partner.php'); })); });", true],
            "container's makeWith" => ['', "\$this->app->makeWith('router', [])->middleware('web')->group({$require});", true],
            'router class as a string' => ['', "app('Illuminate\\Routing\\Router')->middleware('web')->group({$require});", true],
            '$container variable' => ['', "\$container['router']->middleware('web')->group({$require});", true],
            'parameter of a union type naming no router' => ['', "(function (Foo|Bar \$routes) { \$routes->middleware('web')->group(function () { require base_path('routes/partner.php'); }); })(app('router'));", false],
            'untyped parameter of another callback' => ['', "collect([1])->each(function (\$r) { \$r->middleware('web')->group(function () { require base_path('routes/partner.php'); }); });", false],
            'another variable' => ['', "\$pipeline->middleware('web')->group({$require});", false],
            'another facade' => ['use Illuminate\Support\Facades\Http;', "Http::middleware('web')->group({$require});", false],
            'another class static group' => ['', "Schedule::group(['middleware' => 'web'], {$require});", false],
            "listed group callback's first parameter" => ['', "Route::prefix('v1')->group([base_path('routes/other.php'), function (\$r) { \$r->middleware('web')->group(function () { require base_path('routes/partner.php'); }); }]);", true],
            "list on a group callback's router" => ['', "Route::prefix('v1')->group(function (\$r) { \$r->middleware('web')->group([base_path('routes/partner.php')]); });", true],
        ];
    }

    public function test_throttled_group_ranges_ignore_groups_off_the_router(): void
    {
        $routes = <<<'PHP'
<?php

$jobs->middleware('throttle:5,1')->group(function () {
    Route::post('/login', [LoginController::class, 'store']);
});

Route::middleware('throttle:5,1')->group(function () {
    Route::post('/signin', [LoginController::class, 'store']);
});
PHP;

        $tempDir = $this->createTempDir(['routes/web.php' => $routes]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame([['start' => 7, 'end' => 9]], $parser->getThrottledGroupLineRanges($tempDir.'/routes/web.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttled_group_ranges_leave_out_a_nested_group_excluding_the_throttle(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('throttle:5,1')->group(function () {
    Route::post('/signin', [LoginController::class, 'store']);

    Route::withoutMiddleware('throttle:5,1')->group(function () {
        Route::post('/login', [LoginController::class, 'store']);

        Route::middleware('throttle:10,1')->group(function () {
            Route::post('/auth', [LoginController::class, 'store']);
        });
    });

    Route::post('/authenticate', [LoginController::class, 'store']);
});
PHP;

        $tempDir = $this->createTempDir(['routes/web.php' => $routes]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame(
                [['start' => 3, 'end' => 6], ['start' => 12, 'end' => 15], ['start' => 9, 'end' => 11]],
                $parser->getThrottledGroupLineRanges($tempDir.'/routes/web.php'),
            );
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @dataProvider throttleExclusionProvider
     */
    #[DataProvider('throttleExclusionProvider')]
    public function test_throttled_group_ranges_read_exclusion_by_exact_name(string $outer, string $inner, bool $throttled): void
    {
        $routes = <<<PHP
<?php

use Illuminate\\Routing\\Middleware\\ThrottleRequests;

{$outer}->group(function () {
    {$inner}->group(function () {
        Route::post('/login', [LoginController::class, 'store']);
    });
});
PHP;

        $tempDir = $this->createTempDir(['routes/web.php' => $routes]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $covered = false;
            foreach ($parser->getThrottledGroupLineRanges($tempDir.'/routes/web.php') as $range) {
                $covered = $covered || ($range['start'] <= 7 && $range['end'] >= 7);
            }

            $this->assertSame($throttled, $covered);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function throttleExclusionProvider(): array
    {
        return [
            'same name' => ["Route::middleware('throttle:5,1')", "Route::withoutMiddleware('throttle:5,1')", false],
            'class with the same parameters' => ["Route::middleware('throttle:5,1')", "Route::withoutMiddleware(ThrottleRequests::class.':5,1')", false],
            'another limiter' => ["Route::middleware('throttle:5,1')", "Route::withoutMiddleware('throttle:api')", true],
            'the bare class' => ["Route::middleware('throttle:5,1')", 'Route::withoutMiddleware(ThrottleRequests::class)', true],
            'a later argument' => ["Route::middleware('throttle:5,1')", "Route::withoutMiddleware('auth', 'throttle:5,1')", true],
            'a list' => ["Route::middleware('throttle:5,1')", "Route::withoutMiddleware(['auth', 'throttle:5,1'])", false],
            'no argument' => ["Route::middleware('throttle:5,1')", 'Route::withoutMiddleware()', true],
            'excluded before it is applied' => ["Route::withoutMiddleware('throttle:5,1')", "Route::middleware('throttle:5,1')", false],
        ];
    }

    public function test_throttle_protected_route_files_read_exclusion_by_exact_name(): void
    {
        $registrations = <<<'PHP'
Route::middleware('throttle:5,1')->group(function () {
                Route::withoutMiddleware('throttle:5,1')->group(base_path('routes/excluded.php'));
                Route::withoutMiddleware('throttle:api')->group(base_path('routes/kept.php'));
                Route::group(['excluded_middleware' => 'throttle:5,1'], function () {
                    require base_path('routes/attribute.php');
                });
            });
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $this->bootstrapRegistering('', $registrations),
            'routes/excluded.php' => '<?php',
            'routes/kept.php' => '<?php',
            'routes/attribute.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $files = $parser->getThrottleProtectedRouteFiles();

            $this->assertTrue($this->endsWithMatch($files, '/routes/kept.php'));
            $this->assertFalse($this->endsWithMatch($files, '/routes/excluded.php'));
            $this->assertFalse($this->endsWithMatch($files, '/routes/attribute.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    // ==================== Chained middleware() calls before group() ====================

    /**
     * @dataProvider lastChainedMiddlewareProvider
     */
    #[DataProvider('lastChainedMiddlewareProvider')]
    public function test_group_registered_route_files_read_only_the_last_chained_middleware_call(string $source, string $reader, string $chain, bool $expected): void
    {
        $registration = "{$chain}->group(base_path('routes/portal.php'));";
        $file = $source === 'bootstrap' ? 'bootstrap/app.php' : 'app/Providers/PortalRouteProvider.php';
        $contents = $source === 'bootstrap'
            ? $this->bootstrapRegistering('', $registration)
            : <<<PHP
<?php

namespace App\\Providers;

use Illuminate\\Foundation\\Support\\Providers\\RouteServiceProvider as ServiceProvider;
use Illuminate\\Support\\Facades\\Route;

class PortalRouteProvider extends ServiceProvider
{
    public function boot(): void
    {
        \$this->routes(function () {
            {$registration}
        });
    }
}
PHP;

        $tempDir = $this->createTempDir([
            $file => $contents,
            'routes/portal.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $files = match ($reader) {
                'web' => $parser->getWebProtectedRouteFiles(),
                'api' => $parser->getApiRegisteredRouteFiles(),
                default => $parser->getThrottleProtectedRouteFiles(),
            };

            $this->assertSame($expected, $this->endsWithMatch($files, '/routes/portal.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, string, string, bool}>
     */
    public static function lastChainedMiddlewareProvider(): array
    {
        return [
            // RouteRegistrar::attribute() replaces 'middleware' on each call: the last one applies.
            'bootstrap web replaced by a later call' => ['bootstrap', 'web', "Route::middleware('web')->middleware('verified')", false],
            'bootstrap api replaced by a later call' => ['bootstrap', 'api', "Route::middleware('api')->middleware('auth:token')", false],
            'provider web replaced by a later call' => ['provider', 'web', "Route::middleware('web')->middleware('verified')", false],
            'provider api replaced by a later call' => ['provider', 'api', "Route::middleware('api')->middleware('auth:token')", false],
            'bootstrap throttle replaced by a later call' => ['bootstrap', 'throttle', "Route::middleware('throttle:30,1')->middleware('verified')", false],
            'provider throttle replaced by a later call' => ['provider', 'throttle', "Route::middleware('throttle:30,1')->middleware('verified')", false],
            'web replaced across another registrar call' => ['bootstrap', 'web', "Route::middleware('web')->prefix('portal')->middleware('verified')", false],
            'bootstrap web as the last call' => ['bootstrap', 'web', "Route::middleware('verified')->middleware('web')", true],
            'provider web as the last call' => ['provider', 'web', "Route::middleware('verified')->middleware('web')", true],
            'bootstrap api as the last call' => ['bootstrap', 'api', "Route::middleware('auth:token')->middleware('api')", true],
            'bootstrap throttle as the last call' => ['bootstrap', 'throttle', "Route::middleware('verified')->middleware('throttle:30,1')", true],
            'web in one call listing both' => ['bootstrap', 'web', "Route::middleware(['web', 'verified'])", true],
            'a single throttle call' => ['provider', 'throttle', "Route::middleware('throttle:30,1')", true],
            // withoutMiddleware() calls merge, so an earlier exclusion still drops the file.
            'web excluded by an earlier of several exclusions' => ['bootstrap', 'web', "Route::withoutMiddleware('web')->withoutMiddleware('verified')->middleware('web')", false],
            'throttle excluded by an earlier of several exclusions' => ['bootstrap', 'throttle', "Route::withoutMiddleware('throttle:30,1')->withoutMiddleware('verified')->middleware('throttle:30,1')", false],
        ];
    }

    /**
     * @dataProvider lastChainedClosureMiddlewareProvider
     */
    #[DataProvider('lastChainedClosureMiddlewareProvider')]
    public function test_throttled_group_ranges_read_only_the_last_chained_middleware_call(string $chain, bool $throttled): void
    {
        $routes = <<<PHP
<?php

{$chain}->group(function () {
    Route::post('/session', [SessionController::class, 'store']);
});
PHP;

        $tempDir = $this->createTempDir(['routes/web.php' => $routes]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame(
                $throttled ? [['start' => 3, 'end' => 5]] : [],
                $parser->getThrottledGroupLineRanges($tempDir.'/routes/web.php'),
            );
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function lastChainedClosureMiddlewareProvider(): array
    {
        return [
            'throttle replaced by a later call' => ["Route::middleware('throttle:8,1')->middleware('verified')", false],
            'throttle as the last call' => ["Route::middleware('verified')->middleware('throttle:8,1')", true],
            'throttle in one call listing both' => ["Route::middleware(['throttle:8,1', 'verified'])", true],
            'throttle excluded by an earlier of several exclusions' => ["Route::withoutMiddleware('throttle:8,1')->withoutMiddleware('verified')->middleware('throttle:8,1')", false],
        ];
    }

    // ==================== Registrars held in a variable ====================

    /**
     * @dataProvider registrarVariableProvider
     */
    #[DataProvider('registrarVariableProvider')]
    public function test_a_registrar_held_in_a_variable_applies_its_middleware_to_the_files_its_groups_register(string $source, string $reader, string $registration, bool $expected): void
    {
        $file = $source === 'bootstrap' ? 'bootstrap/app.php' : 'app/Providers/MembersRouteProvider.php';
        $contents = $source === 'bootstrap'
            ? $this->bootstrapRegistering('', $registration)
            : <<<PHP
<?php

namespace App\\Providers;

use Illuminate\\Foundation\\Support\\Providers\\RouteServiceProvider as ServiceProvider;
use Illuminate\\Support\\Facades\\Route;

class MembersRouteProvider extends ServiceProvider
{
    public function boot(): void
    {
        \$this->routes(function () {
            {$registration}
        });
    }
}
PHP;

        $tempDir = $this->createTempDir([
            $file => $contents,
            'routes/members.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $files = match ($reader) {
                'web' => $parser->getWebProtectedRouteFiles(),
                'api' => $parser->getApiRegisteredRouteFiles(),
                default => $parser->getThrottleProtectedRouteFiles(),
            };

            $this->assertSame($expected, $this->endsWithMatch($files, '/routes/members.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, string, string, bool}>
     */
    public static function registrarVariableProvider(): array
    {
        $group = "->group(base_path('routes/members.php'));";

        return [
            // Route::middleware() returns one RouteRegistrar, and each call on it sets its attributes
            'bootstrap web' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$members{$group}", true],
            'provider web' => ['provider', 'web', "\$members = Route::middleware('web');\n\$members{$group}", true],
            'bootstrap api' => ['bootstrap', 'api', "\$members = Route::middleware('api');\n\$members{$group}", true],
            'provider api' => ['provider', 'api', "\$members = Route::middleware('api');\n\$members{$group}", true],
            'bootstrap throttle' => ['bootstrap', 'throttle', "\$members = Route::middleware('throttle:30,1');\n\$members{$group}", true],
            'provider throttle' => ['provider', 'throttle', "\$members = Route::middleware('throttle:30,1');\n\$members{$group}", true],
            'built on a router variable' => ['bootstrap', 'web', "\$router = app('router');\n\$members = \$router->middleware('web');\n\$members{$group}", true],
            'middleware set by a later statement' => ['bootstrap', 'web', "\$members = Route::prefix('members');\n\$members->middleware('web');\n\$members{$group}", true],
            'middleware kept through another call on the group chain' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$members->prefix('members'){$group}", true],
            'middleware set by an earlier group statement' => ['bootstrap', 'web', "\$members = Route::prefix('members');\n\$members->middleware('web')->group(function () {});\n\$members{$group}", true],
            'middleware set before a route the statement registers' => ['bootstrap', 'web', "\$members = Route::prefix('members');\n\$members->middleware('web')->get('/ping', fn () => 'pong')->middleware('auth');\n\$members{$group}", true],
            'assigned a chain of calls' => ['bootstrap', 'web', "\$members = Route::getFacadeRoot()->prefix('members')->middleware('web');\n\$members{$group}", true],
            'attribute named in an expression' => ['bootstrap', 'web', "\$members = Route::{'middleware'}('web');\n\$members{$group}", false],
            'attribute named in an expression on a later statement' => ['bootstrap', 'web', "\$members = Route::prefix('members');\n\$members->{'middleware'}('web');\n\$members{$group}", false],
            'middleware replaced by a later statement' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$members->middleware('auth');\n\$members{$group}", false],
            'middleware replaced on the group chain' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$members->middleware('auth'){$group}", false],
            'middleware excluded by a later statement' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$members->withoutMiddleware('web');\n\$members{$group}", false],
            'throttle replaced by a later statement' => ['provider', 'throttle', "\$members = Route::middleware('throttle:30,1');\n\$members->middleware('verified');\n\$members{$group}", false],
            // Each call on the router itself makes a fresh registrar
            'router variable call as its own statement' => ['bootstrap', 'web', "\$router = app('router');\n\$router->middleware('web');\n\$router->prefix('members'){$group}", false],
            'facade root call as its own statement' => ['bootstrap', 'web', "\$routes = Route::getFacadeRoot();\n\$routes->middleware('web');\n\$routes->prefix('members'){$group}", false],
            'router variable chain' => ['bootstrap', 'web', "\$router = app('router');\n\$router->middleware('web'){$group}", true],
            'fluent chain' => ['bootstrap', 'web', "Route::middleware('web'){$group}", true],
            // A registrar written anywhere but a plain statement of its own scope is not read
            'middleware set in a branch' => ['bootstrap', 'web', "\$members = Route::prefix('members');\nif (app()->isLocal()) {\n    \$members->middleware('web');\n}\n\$members{$group}", false],
            'reassigned in a branch' => ['bootstrap', 'web', "\$members = Route::middleware('web');\nif (app()->isLocal()) {\n    \$members = Route::middleware('auth');\n}\n\$members{$group}", false],
            'middleware set inside an expression' => ['bootstrap', 'web', "\$members = Route::prefix('members');\n\$copy = \$members->middleware('web');\n\$members{$group}", false],
            'passed to a call' => ['bootstrap', 'web', "\$members = Route::middleware('web');\nconfigure_members(\$members);\n\$members{$group}", false],
            'captured by a closure' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$narrow = function () use (\$members) {\n    \$members->middleware('auth');\n};\n\$narrow();\n\$members{$group}", false],
            'aliased' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$alias = \$members;\n\$alias{$group}", false],
            'set after an earlier group' => ['bootstrap', 'web', "\$members = Route::prefix('members');\n\$members->group(function () {})->middleware('web');\n\$members{$group}", true],
            'returned by group()' => ['bootstrap', 'web', "\$members = Route::middleware('web');\nreturn \$members{$group}", true],
            'aliased through group()' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$copy = \$members->group(function () {});\n\$copy->middleware('auth');\n\$members{$group}", false],
            'passed through group() to a call' => ['bootstrap', 'web', "\$members = Route::middleware('web');\nnarrow_members(\$members->group(function () {}));\n\$members{$group}", false],
            'variable variable' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$name = 'members';\n\$\$name->middleware('auth');\n\$members{$group}", false],
            'aliased through a variable variable' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$name = 'members';\n\$alias = \$\$name;\n\$alias->middleware('auth');\n\$members{$group}", false],
            'a function declared beside it' => ['bootstrap', 'web', "\$members = Route::middleware('web');\nfunction members_label(): string\n{\n    return 'members';\n}\n\$members{$group}", true],
            // attribute() given a key that is not written out, or unpacked arguments, is not read
            'attribute() given unpacked arguments' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$pair = ['middleware', ['auth']];\n\$members->attribute(...\$pair);\n\$members{$group}", true],
            'fluent attribute() given a key in a variable' => ['bootstrap', 'web', "\$key = 'prefix';\nRoute::middleware('web')->attribute(\$key, 'members'){$group}", true],
            'variable named in braces' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\${'members'}->middleware('auth');\n\$members{$group}", false],
            // attribute() sets what the method of the same name does
            'middleware replaced through attribute()' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$members->attribute('middleware', ['auth']);\n\$members{$group}", false],
            'middleware set through attribute()' => ['bootstrap', 'web', "\$members = Route::prefix('members');\n\$members->attribute('middleware', ['web']);\n\$members{$group}", true],
            'middleware excluded through attribute()' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$members->attribute('withoutMiddleware', 'web');\n\$members{$group}", false],
            'attribute key in a variable' => ['bootstrap', 'web', "\$members = Route::middleware('web');\n\$key = 'middleware';\n\$members->attribute(\$key, ['auth']);\n\$members{$group}", true],
            // RouteRegistrar::attribute() takes its value from the second argument only
            'fluent attribute() given extra arguments' => ['bootstrap', 'web', "Route::prefix('members')->attribute('middleware', 'api', 'web'){$group}", false],
            'attribute() given extra arguments' => ['bootstrap', 'web', "\$members = Route::prefix('members');\n\$members->attribute('middleware', 'api', 'web');\n\$members{$group}", false],
            // compact() and get_defined_vars() hand the registrar on
            'handed on by compact()' => ['bootstrap', 'web', "\$members = Route::middleware('web');\ncompact('members')['members']->middleware('auth');\n\$members{$group}", false],
            'handed on by get_defined_vars()' => ['bootstrap', 'web', "\$members = Route::middleware('web');\nget_defined_vars()['members']->middleware('auth');\n\$members{$group}", false],
            'overwritten by extract()' => ['bootstrap', 'web', "\$members = Route::middleware('web');\nextract(\$overrides);\n\$members{$group}", false],
            // A group on it in a nested block only reads it
            'group in a branch' => ['bootstrap', 'web', "\$members = Route::middleware('web');\nif (file_exists(base_path('routes/members.php'))) {\n    \$members{$group}\n}", true],
            'group in a loop' => ['bootstrap', 'web', "\$members = Route::middleware('web');\nforeach ([1] as \$pass) {\n    \$members{$group}\n}", true],
            'group in a try block' => ['bootstrap', 'web', "\$members = Route::middleware('web');\ntry {\n    \$members{$group}\n} finally {\n}", true],
            'fluent middleware replaced through attribute()' => ['bootstrap', 'web', "Route::middleware('web')->attribute('middleware', ['auth']){$group}", false],
            'fluent middleware set through attribute()' => ['bootstrap', 'web', "Route::prefix('members')->attribute('middleware', 'web'){$group}", true],
            'fluent throttle replaced through attribute()' => ['provider', 'throttle', "Route::middleware('throttle:30,1')->attribute('middleware', 'verified'){$group}", false],
        ];
    }

    /**
     * @dataProvider registrarVariableClosureProvider
     */
    #[DataProvider('registrarVariableClosureProvider')]
    public function test_throttled_group_ranges_read_a_registrar_held_in_a_variable(string $registrar, bool $throttled): void
    {
        $routes = <<<PHP
<?php

{$registrar}
\$members->group(function () {
    Route::post('/session', [SessionController::class, 'store']);
});
PHP;

        $tempDir = $this->createTempDir(['routes/web.php' => $routes]);
        $start = substr_count($routes, "\n", 0, (int) strpos($routes, '$members->group')) + 1;

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame(
                $throttled ? [['start' => $start, 'end' => $start + 2]] : [],
                $parser->getThrottledGroupLineRanges($tempDir.'/routes/web.php'),
            );
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function registrarVariableClosureProvider(): array
    {
        return [
            'throttle on the registrar' => ["\$members = Route::middleware('throttle:8,1');", true],
            'throttle set by a later statement' => ["\$members = Route::prefix('members');\n\$members->middleware('throttle:8,1');", true],
            'throttle replaced by a later statement' => ["\$members = Route::middleware('throttle:8,1');\n\$members->middleware('verified');", false],
            'throttle excluded by a later statement' => ["\$members = Route::middleware('throttle:8,1');\n\$members->withoutMiddleware('throttle:8,1');", false],
            'throttle set in a branch' => ["\$members = Route::prefix('members');\nif (app()->isLocal()) {\n    \$members->middleware('throttle:8,1');\n}", false],
            // A route file runs inside RouteFileRegistrar::register(), so its variables are locals
            // neither \$GLOBALS nor a global statement reaches
            'throttle beside \$GLOBALS' => ["\$members = Route::middleware('throttle:8,1');\n\$GLOBALS['members']->middleware('verified');", true],
            'throttle beside \$GLOBALS in a function' => ["\$members = Route::middleware('throttle:8,1');\nfunction narrow_members(): void\n{\n    \$GLOBALS['members']->middleware('verified');\n}\nnarrow_members();", true],
            'throttle beside a global statement' => ["\$members = Route::middleware('throttle:8,1');\nfunction narrow_members(): void\n{\n    global \$members;\n    \$members->middleware('verified');\n}\nnarrow_members();", true],
        ];
    }

    /**
     * @dataProvider providerRouterVariableProvider
     */
    #[DataProvider('providerRouterVariableProvider')]
    public function test_a_router_variable_in_a_provider_applies_its_middleware(string $router, string $reader, string $middleware): void
    {
        $tempDir = $this->createTempDir([
            'app/Providers/MembersRouteProvider.php' => <<<PHP
<?php

namespace App\\Providers;

use Illuminate\\Support\\ServiceProvider;

class MembersRouteProvider extends ServiceProvider
{
    public function boot(): void
    {
        \$router = {$router};
        \$router->middleware('{$middleware}')->group(base_path('routes/members.php'));
    }
}
PHP,
            'routes/members.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $files = match ($reader) {
                'web' => $parser->getWebProtectedRouteFiles(),
                'api' => $parser->getApiRegisteredRouteFiles(),
                default => $parser->getThrottleProtectedRouteFiles(),
            };

            $this->assertTrue($this->endsWithMatch($files, '/routes/members.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function providerRouterVariableProvider(): array
    {
        // \$router names the router by its name, whatever it is assigned
        return [
            'a getter' => ['$this->getRouter()', 'web', 'web'],
            'a getter, api' => ['$this->getRouter()', 'api', 'api'],
            'a getter, throttle' => ['$this->getRouter()', 'throttle', 'throttle:30,1'],
            'another container' => ["\$application->make('router')", 'web', 'web'],
            'a null-coalesced property' => ["\$this->router ?? app('router')", 'web', 'web'],
        ];
    }

    /**
     * @dataProvider bootstrapFileScopeRegistrarProvider
     */
    #[DataProvider('bootstrapFileScopeRegistrarProvider')]
    public function test_a_registrar_in_bootstrap_file_scope_is_unread_beside_globals(string $statement, bool $expected): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => "<?php\n\nuse Illuminate\\Foundation\\Application;\nuse Illuminate\\Support\\Facades\\Route;\n\n\$members = Route::middleware('web');\n{$statement}\n\$members->group(base_path('routes/members.php'));\n\nreturn Application::configure(basePath: dirname(__DIR__))->create();\n",
            'routes/members.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame($expected, $this->endsWithMatch($parser->getWebProtectedRouteFiles(), '/routes/members.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function bootstrapFileScopeRegistrarProvider(): array
    {
        return [
            // public/index.php requires bootstrap/app.php at its file scope, so its variables are globals
            'beside \$GLOBALS' => ["\$GLOBALS['members']->middleware('auth');", false],
            'beside a global statement' => ["function narrow_members(): void\n{\n    global \$members;\n    \$members->middleware('auth');\n}", false],
            'alone' => ['', true],
        ];
    }

    /**
     * @dataProvider routerVariablePathProvider
     */
    #[DataProvider('routerVariablePathProvider')]
    public function test_a_group_on_a_router_variable_reads_a_path_variable(string $registration, bool $expected): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $this->bootstrapRegistering('', $registration),
            'routes/members.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame($expected, $this->endsWithMatch($parser->getWebProtectedRouteFiles(), '/routes/members.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function routerVariablePathProvider(): array
    {
        $file = "\$file = base_path('routes/members.php');";

        return [
            'facade root' => ["\$routes = Route::getFacadeRoot();\n{$file}\n\$routes->middleware('web')->group(\$file);", true],
            'container router' => ["\$routes = app('router');\n{$file}\n\$routes->middleware('web')->group(\$file);", true],
            'registrar variable' => ["\$members = Route::middleware('web');\n{$file}\n\$members->group(\$file);", true],
            // Any other object's group() may take the variable by reference
            'another object given the path first' => ["\$sections = new SectionLoader;\n{$file}\n\$sections->group(\$file);\nRoute::middleware('web')->group(\$file);", false],
            'variable assigned something else too' => ["\$routes = app('router');\nif (app()->isLocal()) {\n    \$routes = new SectionLoader;\n}\n{$file}\n\$routes->group(\$file);\nRoute::middleware('web')->group(\$file);", false],
        ];
    }

    public function test_route_file_loads_list_every_load_with_the_groups_around_it(): void
    {
        $partner = <<<'PHP'
<?php

require __DIR__.'/partner_auth.php';

Route::middleware('throttle:5,1')->group(function () {
    require base_path('routes/partner_session.php');
});

Route::prefix('v2')->group(__DIR__.'/partner_v2.php');
PHP;

        $tempDir = $this->createTempDir([
            'routes/partner.php' => $partner,
            'routes/partner_auth.php' => '<?php',
            'routes/partner_session.php' => '<?php',
            'routes/partner_v2.php' => '<?php',
            'routes/empty.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $loads = $parser->getRouteFileLoads();

            $this->assertSame([(string) realpath($tempDir.'/routes/partner.php')], array_keys($loads));
            $partnerLoads = $loads[(string) realpath($tempDir.'/routes/partner.php')];
            $this->assertSame(
                [
                    [(string) realpath($tempDir.'/routes/partner_auth.php'), 0],
                    [(string) realpath($tempDir.'/routes/partner_session.php'), 1],
                    [(string) realpath($tempDir.'/routes/partner_v2.php'), 1],
                ],
                array_map(fn (array $load): array => [$load['file'], count($load['calls'])], $partnerLoads),
            );

            // An ungrouped require is not a group registration
            $registered = array_column($parser->getGroupRegisteredRouteFiles(), 'file');
            $this->assertFalse($this->endsWithMatch($registered, '/routes/partner_auth.php'));
            $this->assertTrue($this->endsWithMatch($registered, '/routes/partner_session.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_external_route_file_loads_list_bootstrap_and_provider_loads_group_or_not(): void
    {
        $bootstrap = <<<'PHP'
<?php

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            require base_path('routes/depot.php');
            Route::prefix('yard')->group(base_path('routes/yard.php'));
        },
    )
    ->create();
PHP;

        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class DepotServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->loadRoutesFrom(base_path('routes/dock.php'));
        $this->loadRoutesFrom('routes/relative.php');
        $other->loadRoutesFrom(base_path('routes/other.php'));

        Route::middleware('api')->group(function () {
            $this->LoadRoutesFrom(__DIR__.'/../../routes/gate.php');
        });
    }
}
PHP;

        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrap,
            'app/Providers/DepotServiceProvider.php' => $provider,
            'routes/depot.php' => '<?php',
            'routes/yard.php' => '<?php',
            'routes/dock.php' => '<?php',
            'routes/relative.php' => '<?php',
            'routes/other.php' => '<?php',
            'routes/gate.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $loads = array_map(
                fn (array $load): array => [basename($load['file']), basename($load['source']), count($load['calls'])],
                $parser->getExternalRouteFileLoads(),
            );
            $this->assertSame([
                ['depot.php', 'app.php', 0],
                ['yard.php', 'app.php', 1],
                ['dock.php', 'DepotServiceProvider.php', 0],
                ['gate.php', 'DepotServiceProvider.php', 1],
            ], $loads);

            // loadRoutesFrom() is not a group registration or a route file load
            $this->assertFalse($this->endsWithMatch(array_column($parser->getGroupRegisteredRouteFiles(), 'file'), '/routes/gate.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttled_group_ranges_returns_empty_for_missing_file(): void
    {
        $parser = new BootstrapRouteParser('/nonexistent', $this->parser);

        $this->assertSame([], $parser->getThrottledGroupLineRanges('/nonexistent/routes/api.php'));
    }

    public function test_throttled_group_ranges_returns_empty_when_ast_is_empty(): void
    {
        // A file with only an opening tag parses to an empty statement list.
        $tempDir = $this->createTempDir(['routes/api.php' => '<?php']);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame([], $parser->getThrottledGroupLineRanges($tempDir.'/routes/api.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttled_group_ranges_detects_array_list_middleware_throttle(): void
    {
        // Array-config form where 'middleware' is itself a list of strings.
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => ['auth:sanctum', 'throttle:api']], function () {
    Route::post('/login', [LoginController::class, 'login']);
});
PHP;
        $tempDir = $this->createTempDir(['routes/api.php' => $routes]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $ranges = $parser->getThrottledGroupLineRanges($tempDir.'/routes/api.php');

            $this->assertCount(1, $ranges);
            $this->assertSame(3, $ranges[0]['start']);
            $this->assertSame(5, $ranges[0]['end']);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttled_group_ranges_ignores_array_list_middleware_without_throttle(): void
    {
        // Array-config 'middleware' list that carries no throttle entry.
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => ['auth:sanctum', 'verified']], function () {
    Route::post('/login', [LoginController::class, 'login']);
});
PHP;
        $tempDir = $this->createTempDir(['routes/api.php' => $routes]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame([], $parser->getThrottledGroupLineRanges($tempDir.'/routes/api.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttled_group_ranges_ignores_group_without_closure(): void
    {
        // Route::group with no closure argument yields no range.
        $routes = <<<'PHP'
<?php

Route::group(['prefix' => 'admin']);
PHP;
        $tempDir = $this->createTempDir(['routes/web.php' => $routes]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame([], $parser->getThrottledGroupLineRanges($tempDir.'/routes/web.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttled_group_ranges_returns_closure_span_for_fluent_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('throttle:5,1')->group(function () {
    Route::post('/login', [LoginController::class, 'login']);
});
PHP;
        $tempDir = $this->createTempDir(['routes/web.php' => $routes]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $ranges = $parser->getThrottledGroupLineRanges($tempDir.'/routes/web.php');

            $this->assertCount(1, $ranges);
            $this->assertSame(3, $ranges[0]['start']);
            $this->assertSame(5, $ranges[0]['end']);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_group_registered_route_files_record_the_group_that_registers_them(): void
    {
        $web = <<<'PHP'
<?php

Route::middleware('signin')->group(base_path('routes/signin.php'));
Route::group(['middleware' => 'signin'], function () {
    require __DIR__.'/admin.php';
});
Route::middleware('signin')->group(...);
Route::prefix('ignored')->get('/', fn () => 'home');
PHP;
        $tempDir = $this->createTempDir([
            'routes/web.php' => $web,
            'routes/signin.php' => '<?php',
            'routes/admin.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $registrations = $parser->getGroupRegisteredRouteFiles();

            $this->assertCount(2, $registrations);
            $this->assertStringEndsWith('/routes/signin.php', $registrations[0]['file']);
            $this->assertStringEndsWith('/routes/web.php', $registrations[0]['source']);
            $this->assertCount(1, $registrations[0]['calls']);
            $this->assertInstanceOf(MethodCall::class, $registrations[0]['calls'][0]);
            $this->assertStringEndsWith('/routes/admin.php', $registrations[1]['file']);
            $this->assertCount(1, $registrations[1]['calls']);
            $this->assertInstanceOf(StaticCall::class, $registrations[1]['calls'][0]);
            $this->assertSame([], $parser->getGroupRegisteredRouteFiles(routeFiles: false));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_group_registered_route_files_record_every_enclosing_group_outermost_first(): void
    {
        $bootstrap = <<<'PHP'
<?php

Route::middleware('signin')->group(function () {
    Route::group(['prefix' => 'admin'], base_path('routes/admin.php'));
});
PHP;
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $bootstrap,
            'routes/admin.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $registrations = $parser->getGroupRegisteredRouteFiles();

            $this->assertCount(1, $registrations);
            $this->assertStringEndsWith('/routes/admin.php', $registrations[0]['file']);
            $this->assertCount(2, $registrations[0]['calls']);
            $this->assertInstanceOf(MethodCall::class, $registrations[0]['calls'][0]);
            $this->assertInstanceOf(StaticCall::class, $registrations[0]['calls'][1]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_group_registered_route_files_are_read_from_bootstrap_and_providers(): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => "<?php\n\nRoute::middleware('web')->group(base_path('routes/admin.php'));\n",
            'app/Providers/RouteServiceProvider.php' => "<?php\n\nRoute::middleware('api')->group(base_path('routes/partner.php'));\n",
            'app/Providers/README.md' => 'not php',
            'routes/admin.php' => '<?php',
            'routes/partner.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $files = array_column($parser->getGroupRegisteredRouteFiles(), 'file');

            $this->assertCount(2, $files);
            $this->assertTrue($this->endsWithMatch($files, '/routes/admin.php'));
            $this->assertTrue($this->endsWithMatch($files, '/routes/partner.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    // ==================== Throttle class forms ====================

    /**
     * @dataProvider throttleClassRegistrationProvider
     */
    #[DataProvider('throttleClassRegistrationProvider')]
    public function test_throttle_protected_route_files_recognise_throttle_class_forms(string $imports, string $registration): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $this->bootstrapRegistering($imports, $registration),
            'routes/partner.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getThrottleProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/partner.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function throttleClassRegistrationProvider(): array
    {
        $import = 'use Illuminate\\Routing\\Middleware\\ThrottleRequests;';
        $file = "base_path('routes/partner.php')";

        return [
            'fully qualified ::class' => ['', "Route::middleware(\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class)->group({$file});"],
            '::class with parameters' => [$import, "Route::middleware(ThrottleRequests::class.':5,1')->group({$file});"],
            '::using() in a list' => [$import, "Route::middleware(['api', ThrottleRequests::using('partner')])->group({$file});"],
            '::with()' => [$import, "Route::middleware(ThrottleRequests::with(5, 1))->group({$file});"],
            'Redis variant' => ['use Illuminate\\Routing\\Middleware\\ThrottleRequestsWithRedis;', "Route::middleware(ThrottleRequestsWithRedis::class)->group({$file});"],
            'aliased import' => ['use Illuminate\\Routing\\Middleware\\ThrottleRequests as Cap;', "Route::middleware(Cap::class)->group({$file});"],
            'array-form group on a class' => [$import, "Route::group(['middleware' => ThrottleRequests::class], {$file});"],
            'array-form group on a string' => ['', "Route::group(['middleware' => ['api', 'throttle:5,1']], {$file});"],
            'variadic names' => ['', "Route::middleware('api', 'throttle:5,1')->group({$file});"],
            'class as a later argument mid-chain' => [$import, "Route::prefix('partner')->middleware('auth', ThrottleRequests::class)->group({$file});"],
            'file required inside the closure' => ['', "Route::middleware('throttle:5,1')->group(function () { require __DIR__.'/../routes/partner.php'; });"],
            'throttle from an enclosing group' => ['', "Route::middleware('throttle:5,1')->group(function () { Route::prefix('partner')->group({$file}); });"],
            'group method in another case' => ['', "Route::GROUP(['middleware' => 'throttle:5,1'], {$file});"],
            // Laravel excludes only an exact name, so throttle:login survives
            'another throttle excluded' => ['', "Route::middleware('throttle:login')->withoutMiddleware('throttle:api')->group({$file});"],
        ];
    }

    /**
     * @dataProvider unthrottledRegistrationProvider
     */
    #[DataProvider('unthrottledRegistrationProvider')]
    public function test_throttle_protected_route_files_ignore_names_that_only_look_like_a_throttle(string $registration): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $this->bootstrapRegistering('', $registration),
            'routes/partner.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame([], $parser->getThrottleProtectedRouteFiles());
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unthrottledRegistrationProvider(): array
    {
        $file = "base_path('routes/partner.php')";

        return [
            'app class with the name in it' => ["Route::middleware(\\App\\Http\\Middleware\\ThrottleRequestsAudit::class)->group({$file});"],
            'alias that only starts with throttle' => ["Route::middleware('throttles.audit')->group({$file});"],
            'array-form group without a throttle' => ["Route::group(['middleware' => 'auth'], {$file});"],
            // Laravel takes only the array when the first argument is one, and drops the rest.
            'throttle after a leading array' => ["Route::middleware(['auth'], 'throttle:5,1')->group({$file});"],
        ];
    }

    public function test_throttle_protected_route_files_resolve_class_names_against_the_provider_imports(): void
    {
        // The unimported short name resolves into the provider's own namespace, so it
        // names App\Providers\ThrottleRequests rather than the framework's class.
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Routing\Middleware\ThrottleRequests as Cap;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider
{
    public function boot(): void
    {
        Route::middleware(Cap::class)->group(base_path('routes/partner.php'));
        Route::middleware(ThrottleRequests::class)->group(base_path('routes/admin.php'));
    }
}
PHP;
        $tempDir = $this->createTempDir([
            'app/Providers/RouteServiceProvider.php' => $provider,
            'routes/partner.php' => '<?php',
            'routes/admin.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $parser->getThrottleProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/partner.php', $result[0]);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttle_judge_decides_which_middleware_names_throttle(): void
    {
        $registrations = "Route::middleware('signin.cap')->group(base_path('routes/partner.php'));\n"
            ."            Route::middleware(ThrottleRequests::class)->group(base_path('routes/admin.php'));";
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $this->bootstrapRegistering('use Illuminate\\Routing\\Middleware\\ThrottleRequests;', $registrations),
            'routes/partner.php' => '<?php',
            'routes/admin.php' => '<?php',
        ]);

        try {
            $judged = [];
            $parser = new BootstrapRouteParser($tempDir, $this->parser, function (string $name) use (&$judged): bool {
                $judged[] = $name;

                return $name === 'signin.cap';
            });
            $result = $parser->getThrottleProtectedRouteFiles();

            $this->assertCount(1, $result);
            $this->assertStringEndsWith('/routes/partner.php', $result[0]);
            $this->assertContains('signin.cap', $judged);
            $this->assertContains('\\Illuminate\\Routing\\Middleware\\ThrottleRequests', $judged);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @dataProvider throttleClassGroupProvider
     */
    #[DataProvider('throttleClassGroupProvider')]
    public function test_throttled_group_ranges_recognise_throttle_class_forms(string $groupOpening): void
    {
        $routes = <<<PHP
<?php

use Illuminate\Routing\Middleware\ThrottleRequests;
use Illuminate\Routing\Middleware\ThrottleRequests as Cap;

{$groupOpening}
    Route::post('/session/login', [SessionController::class, 'store']);
});
PHP;
        $tempDir = $this->createTempDir(['routes/web.php' => $routes]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame([['start' => 6, 'end' => 8]], $parser->getThrottledGroupLineRanges($tempDir.'/routes/web.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function throttleClassGroupProvider(): array
    {
        return [
            'fluent ::class' => ['Route::middleware(ThrottleRequests::class)->group(function () {'],
            'fluent aliased ::using() in a list' => ["Route::middleware(['web', Cap::using('login')])->group(function () {"],
            'fluent ::with() after another middleware' => ["Route::middleware('auth')->middleware(ThrottleRequests::with(5, 1))->group(function () {"],
            'fluent variadic' => ["Route::middleware('auth', ThrottleRequests::class)->group(function () {"],
            'array form ::class' => ["Route::group(['middleware' => ThrottleRequests::class], function () {"],
            'array form aliased list' => ["Route::group(['middleware' => ['auth', Cap::class.':5,1']], function () {"],
        ];
    }

    // ==================== A list of route files passed to group() ====================

    /**
     * @dataProvider groupRouteListProvider
     *
     * @param  list<string>  $expected
     */
    #[DataProvider('groupRouteListProvider')]
    public function test_group_reads_every_route_file_in_a_list(string $registration, string $reader, array $expected): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $this->bootstrapRegistering('', $registration),
            'routes/orders.php' => '<?php',
            'routes/reports.php' => '<?php',
            'routes/admin.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = match ($reader) {
                'web' => $parser->getWebProtectedRouteFiles(),
                'api' => $parser->getApiRegisteredRouteFiles(),
                default => $parser->getThrottleProtectedRouteFiles(),
            };
            $names = array_map('basename', $result);
            sort($names);

            $this->assertSame($expected, $names);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, string, list<string>}>
     */
    public static function groupRouteListProvider(): array
    {
        $list = "[base_path('routes/orders.php'), base_path('routes/reports.php')]";
        $both = ['orders.php', 'reports.php'];

        return [
            'fluent web list' => ["Route::middleware('web')->group({$list});", 'web', $both],
            'fluent api list' => ["Route::middleware('api')->group({$list});", 'api', $both],
            'fluent throttle list' => ["Route::middleware('throttle:5,1')->group({$list});", 'throttle', $both],
            'attribute array with a web list' => ["Route::group(['middleware' => 'web'], {$list});", 'web', $both],
            'attribute array with an api list' => ["Route::group(['middleware' => 'api'], {$list});", 'api', $both],
            'attribute array with a throttle list' => ["Route::group(['middleware' => ['api', 'throttle:api']], {$list});", 'throttle', $both],
            'router variable with a list' => ["\$router->group(['middleware' => 'web'], {$list});", 'web', $both],
            'named routes argument' => ["Route::group(routes: {$list}, attributes: ['middleware' => 'api']);", 'api', $both],
            'named callback argument' => ["Route::middleware('web')->group(callback: {$list});", 'web', $both],
            '__DIR__ entries' => ["Route::middleware('web')->group([__DIR__.'/../routes/orders.php', __DIR__.'/../routes/reports.php']);", 'web', $both],
            'list inside an enclosing group' => ["Route::middleware('api')->group(function () { Route::prefix('v1')->group({$list}); });", 'api', $both],
            'closure entry beside a file' => ["Route::middleware('web')->group([function () { require __DIR__.'/../routes/admin.php'; }, base_path('routes/orders.php')]);", 'web', ['admin.php', 'orders.php']],
            'bare string entry is not read' => ["Route::middleware('web')->group(['routes/orders.php', base_path('routes/reports.php')]);", 'web', ['reports.php']],
            'missing file entry is skipped' => ["Route::middleware('web')->group([base_path('routes/missing.php'), base_path('routes/reports.php')]);", 'web', ['reports.php']],
            'list under another middleware' => ["Route::middleware('auth')->group({$list});", 'web', []],
            'list excluding the middleware' => ["Route::middleware('web')->withoutMiddleware('web')->group({$list});", 'web', []],
            'unpacked arguments are not expanded' => ["Route::middleware('web')->group(...[base_path('routes/orders.php'), base_path('routes/reports.php')]);", 'web', []],
            'named argument in another case' => ["Route::group(ROUTES: {$list}, attributes: ['middleware' => 'web']);", 'web', []],
            'a file in the attribute array is not loaded' => ["Route::group(['middleware' => 'web', 'prefix' => base_path('routes/admin.php')], {$list});", 'web', $both],
        ];
    }

    public function test_group_registered_route_files_record_each_listed_file(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\Facades\Route;

class RouteServiceProvider
{
    public function boot(): void
    {
        Route::middleware('signin')->group([base_path('routes/orders.php'), base_path('routes/reports.php')]);
    }
}
PHP;
        $tempDir = $this->createTempDir([
            'app/Providers/RouteServiceProvider.php' => $provider,
            'routes/orders.php' => '<?php',
            'routes/reports.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $registrations = $parser->getGroupRegisteredRouteFiles(routeFiles: false);

            $this->assertCount(2, $registrations);
            $this->assertStringEndsWith('/routes/orders.php', $registrations[0]['file']);
            $this->assertStringEndsWith('/routes/reports.php', $registrations[1]['file']);
            $this->assertSame($registrations[0]['calls'], $registrations[1]['calls']);
            $this->assertCount(1, $registrations[0]['calls']);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttled_group_ranges_cover_each_closure_in_a_list(): void
    {
        $routes = <<<'PHP'
<?php

Route::middleware('throttle:5,1')->group([function () {
    Route::post('/login', [LoginController::class, 'store']);
}, base_path('routes/orders.php'), fn () => Route::post('/two-factor', [TwoFactorController::class, 'store'])]);
Route::group(['middleware' => 'throttle:api'], [function () {
    Route::post('/token', [TokenController::class, 'store']);
}]);
Route::middleware('auth')->group([function () {
    Route::post('/logout', [LoginController::class, 'destroy']);
}]);
PHP;
        $tempDir = $this->createTempDir(['routes/web.php' => $routes, 'routes/orders.php' => '<?php']);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame(
                [['start' => 3, 'end' => 5], ['start' => 5, 'end' => 5], ['start' => 6, 'end' => 8]],
                $parser->getThrottledGroupLineRanges($tempDir.'/routes/web.php'),
            );
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_throttled_group_ranges_read_the_router_a_listed_callback_is_given(): void
    {
        $routes = <<<'PHP'
<?php

Route::prefix('v1')->group([function ($r) {
    $r->middleware('throttle:5,1')->group(function () {
        Route::post('/login', [LoginController::class, 'store']);
    });
}]);
Route::group(['prefix' => function ($r) {
    $r->middleware('throttle:5,1')->group(function () {
        Route::post('/signin', [LoginController::class, 'store']);
    });
}], []);
PHP;
        $tempDir = $this->createTempDir(['routes/web.php' => $routes]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame([['start' => 4, 'end' => 6]], $parser->getThrottledGroupLineRanges($tempDir.'/routes/web.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    // ==================== A group's routes held in a variable ====================

    /**
     * @dataProvider groupRouteVariableProvider
     *
     * @param  list<string>  $expected
     */
    #[DataProvider('groupRouteVariableProvider')]
    public function test_group_reads_route_files_held_in_a_variable(string $registration, string $reader, array $expected): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $this->bootstrapRegistering('', $registration),
            'routes/admin.php' => '<?php',
            'routes/mobile.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = match ($reader) {
                'web' => $parser->getWebProtectedRouteFiles(),
                'api' => $parser->getApiRegisteredRouteFiles(),
                'registered' => array_column($parser->getGroupRegisteredRouteFiles(routeFiles: false), 'file'),
                default => $parser->getThrottleProtectedRouteFiles(),
            };
            $names = array_map('basename', $result);
            sort($names);

            $this->assertSame($expected, $names);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, string, list<string>}>
     */
    public static function groupRouteVariableProvider(): array
    {
        return [
            'list variable on a web group' => ["\$files = [base_path('routes/admin.php')]; Route::middleware('web')->group(\$files);", 'web', ['admin.php']],
            'list variable registers the file' => ["\$files = [base_path('routes/admin.php')]; Route::middleware('web')->group(\$files);", 'registered', ['admin.php']],
            'scalar variable on a web group' => ["\$file = base_path('routes/admin.php'); Route::middleware('web')->group(\$file);", 'web', ['admin.php']],
            'scalar variable on an api group' => ["\$file = base_path('routes/mobile.php'); Route::middleware('api')->prefix('api')->group(\$file);", 'api', ['mobile.php']],
            'scalar variable on a throttle group' => ["\$file = base_path('routes/admin.php'); Route::middleware(['web', 'throttle:5,1'])->group(\$file);", 'throttle', ['admin.php']],
            '__DIR__ variable in an attribute-array group' => ["\$file = __DIR__.'/../routes/admin.php'; Route::group(['middleware' => 'web'], \$file);", 'web', ['admin.php']],
            'variables listed in a literal list' => ["\$a = base_path('routes/admin.php'); \$m = base_path('routes/mobile.php'); Route::middleware('web')->group([\$a, \$m]);", 'web', ['admin.php', 'mobile.php']],
            'list variable naming path variables' => ["\$a = base_path('routes/admin.php'); \$files = [\$a, base_path('routes/mobile.php')]; Route::middleware('web')->group(\$files);", 'web', ['admin.php', 'mobile.php']],
            'list unpacking a path list' => ["\$files = [base_path('routes/admin.php')]; \$f = [...\$files]; Route::middleware('web')->group(\$f);", 'web', []],
            'variable closure requiring a file' => ["\$routes = function () { require base_path('routes/admin.php'); }; Route::middleware('web')->group(\$routes);", 'web', []],
            'last assignment before the call wins' => ["\$file = base_path('routes/mobile.php'); \$file = base_path('routes/admin.php'); Route::middleware('web')->group(\$file);", 'web', ['admin.php']],
            'reassigned to an unresolvable value' => ["\$file = base_path('routes/admin.php'); \$file = config('routes.admin'); Route::middleware('web')->group(\$file);", 'web', []],
            'assigned after the call' => ["Route::middleware('web')->group(\$file); \$file = base_path('routes/admin.php');", 'web', []],
            'assigned in another closure' => ["\$load = function () { \$file = base_path('routes/admin.php'); }; Route::middleware('web')->group(\$file);", 'web', []],
            'outer variable not captured by the closure' => ["\$file = base_path('routes/admin.php'); \$load = function () { Route::middleware('web')->group(\$file); }; \$load();", 'web', []],
            'outer variable captured through use()' => ["\$file = base_path('routes/admin.php'); \$load = function () use (\$file) { Route::middleware('web')->group(\$file); }; \$load();", 'web', ['admin.php']],
            'variable on a group under another middleware' => ["\$file = base_path('routes/admin.php'); Route::middleware('auth')->group(\$file);", 'web', []],
            'overwritten by a foreach value' => ["\$file = base_path('routes/admin.php'); foreach (glob(base_path('routes/web/*.php')) as \$file) { Route::middleware('web')->group(\$file); }", 'web', []],
            'overwritten by a foreach key' => ["\$file = base_path('routes/admin.php'); foreach (\$map as \$file => \$x) { Route::middleware('web')->group(\$file); }", 'web', []],
            'overwritten by a foreach list target' => ["\$file = base_path('routes/admin.php'); foreach (\$pairs as [\$file, \$x]) { Route::middleware('web')->group(\$file); }", 'web', []],
            'overwritten by destructuring' => ["\$file = base_path('routes/admin.php'); [\$file] = \$paths; Route::middleware('web')->group(\$file);", 'web', []],
            'overwritten by list()' => ["\$file = base_path('routes/admin.php'); list(\$file) = \$paths; Route::middleware('web')->group(\$file);", 'web', []],
            'made a reference' => ["\$file = base_path('routes/admin.php'); \$file = &\$other; Route::middleware('web')->group(\$file);", 'web', []],
            'referenced by another variable' => ["\$file = base_path('routes/admin.php'); \$alias = &\$file; \$alias = \$other; Route::middleware('web')->group(\$file);", 'web', []],
            'appended to with .=' => ["\$file = base_path('routes/admin.php'); \$file .= \$suffix; Route::middleware('web')->group(\$file);", 'web', []],
            'incremented' => ["\$file = base_path('routes/admin.php'); \$file++; Route::middleware('web')->group(\$file);", 'web', []],
            'appended to with []' => ["\$files = [base_path('routes/admin.php')]; \$files[] = \$other; Route::middleware('web')->group(\$files);", 'web', []],
            'declared static' => ["\$file = base_path('routes/admin.php'); static \$file; Route::middleware('web')->group(\$file);", 'web', []],
            'declared global' => ["\$file = base_path('routes/admin.php'); global \$file; Route::middleware('web')->group(\$file);", 'web', []],
            'overwritten by a catch variable' => ["\$file = base_path('routes/admin.php'); try { load(); } catch (Exception \$file) { } Route::middleware('web')->group(\$file);", 'web', []],
            'passed to a call that may write it' => ["\$files = [base_path('routes/admin.php'), base_path('routes/mobile.php')]; array_shift(\$files); Route::middleware('web')->group(\$files);", 'web', []],
            'unset' => ["\$file = base_path('routes/admin.php'); unset(\$file); Route::middleware('web')->group(\$file);", 'web', []],
            'closure reads what it captured where it is defined' => ["\$f = base_path('routes/mobile.php'); \$cb = function () use (\$f) { Route::middleware('web')->group(\$f); }; \$f = base_path('routes/admin.php'); Route::prefix('admin')->group(\$f); \$cb();", 'web', ['mobile.php']],
            'arrow function reads its parent scope where it is defined' => ["\$f = base_path('routes/mobile.php'); \$cb = fn () => Route::middleware('web')->group(\$f); \$f = base_path('routes/admin.php'); Route::prefix('admin')->group(\$f); \$cb();", 'web', ['mobile.php']],
            'variable captured by reference is not read' => ["\$f = base_path('routes/admin.php'); \$reg = function () use (&\$f) { Route::middleware('web')->group(\$f); }; Route::prefix('admin')->group(\$f); \$f = base_path('routes/mobile.php'); \$reg();", 'web', []],
            'reassigned in an if' => ["\$f = base_path('routes/admin.php'); if (app()->isLocal()) { \$f = base_path('routes/mobile.php'); } Route::middleware('web')->group(\$f);", 'web', []],
            'reassigned in an else' => ["\$f = base_path('routes/admin.php'); if (app()->isLocal()) { } else { \$f = base_path('routes/mobile.php'); } Route::middleware('web')->group(\$f);", 'web', []],
            'reassigned in a switch' => ["\$f = base_path('routes/admin.php'); switch (\$env) { case 'local': \$f = base_path('routes/mobile.php'); } Route::middleware('web')->group(\$f);", 'web', []],
            'reassigned in a ternary' => ["\$f = base_path('routes/admin.php'); \$local ? \$f = base_path('routes/mobile.php') : null; Route::middleware('web')->group(\$f);", 'web', []],
            'reassigned behind &&' => ["\$f = base_path('routes/admin.php'); \$local && \$f = base_path('routes/mobile.php'); Route::middleware('web')->group(\$f);", 'web', []],
            'reassigned in a try' => ["\$f = base_path('routes/admin.php'); try { \$f = base_path('routes/mobile.php'); load(); } catch (Exception \$e) { } Route::middleware('web')->group(\$f);", 'web', []],
            'reassigned in a loop' => ["\$f = base_path('routes/admin.php'); while (\$more) { \$f = base_path('routes/mobile.php'); \$more = false; } Route::middleware('web')->group(\$f);", 'web', []],
            'reassigned later in a loop body' => ["\$f = base_path('routes/admin.php'); for (\$i = 0; \$i < 2; \$i++) { Route::middleware('web')->group(\$f); \$f = base_path('routes/mobile.php'); }", 'web', []],
            'written in a branch, read in the same branch' => ["if (app()->isLocal()) { \$f = base_path('routes/mobile.php'); Route::middleware('web')->group(\$f); }", 'web', []],
            'written in a branch, read outside any branch' => ["\$f = base_path('routes/admin.php'); if (app()->isLocal()) { \$f = base_path('routes/mobile.php'); } else { \$other = 1; } Route::middleware('web')->group(\$f);", 'web', []],
            'read in the else of an if that writes it' => ["\$f = base_path('routes/mobile.php'); if (app()->isLocal()) { \$f = base_path('routes/admin.php'); Route::middleware('auth')->group(\$f); } else { Route::middleware('web')->group(\$f); }", 'web', []],
            'read in an elseif after an if that writes it' => ["\$f = base_path('routes/mobile.php'); if (\$a) { \$f = base_path('routes/admin.php'); } elseif (\$b) { Route::middleware('web')->group(\$f); }", 'web', []],
            'read in the other arm of a ternary' => ["\$f = base_path('routes/mobile.php'); \$c ? (\$f = base_path('routes/admin.php')) : Route::middleware('web')->group(\$f);", 'web', []],
            'read in a later switch case' => ["\$f = base_path('routes/mobile.php'); switch (\$env) { case 'a': \$f = base_path('routes/admin.php'); break; case 'b': Route::middleware('web')->group(\$f); }", 'web', []],
            'read in another match arm' => ["\$f = base_path('routes/mobile.php'); match (\$env) { 'a' => \$f = base_path('routes/admin.php'), default => Route::middleware('web')->group(\$f) };", 'web', []],
            'read in the else of an alternative-syntax if' => ["\$f = base_path('routes/mobile.php'); if (\$a): \$f = base_path('routes/admin.php'); else: Route::middleware('web')->group(\$f); endif;", 'web', []],
            'scope calls extract()' => ["\$f = base_path('routes/admin.php'); extract(\$vars); Route::middleware('web')->group(\$f);", 'web', []],
            'scope writes a variable variable' => ["\$f = base_path('routes/admin.php'); \$n = 'f'; \$\$n = \$other; Route::middleware('web')->group(\$f);", 'web', []],
            'scope writes a braced variable variable' => ["\$f = base_path('routes/admin.php'); \${'f'} = \$other; Route::middleware('web')->group(\$f);", 'web', []],
            'written through an earlier reference' => ["\$g = &\$f; \$f = base_path('routes/admin.php'); \$g = \$other; Route::middleware('web')->group(\$f);", 'web', []],
            'by-reference closure called later' => ["\$f = base_path('routes/admin.php'); \$set = function () use (&\$f) { \$f = \$GLOBALS['x']; }; Route::middleware('web')->group(\$f); \$set();", 'web', []],
            'scope uses goto' => ["\$f = base_path('routes/admin.php'); goto done; done: Route::middleware('web')->group(\$f);", 'web', []],
            'scope requires a file' => ["\$f = base_path('routes/admin.php'); require base_path('routes/mobile.php'); Route::middleware('web')->group(\$f);", 'web', []],
            'by-reference import forgets the outer variable' => ["\$f = base_path('routes/admin.php'); \$set = function () use (&\$f) { \$f = base_path('routes/mobile.php'); }; \$set(); Route::middleware('web')->group(\$f);", 'web', []],
            'F1 import then a foreach over it' => ["\$f = base_path('routes/admin.php'); \$cb = function () use (\$f) { foreach ([base_path('routes/mobile.php')] as \$f) { Route::middleware('web')->group(\$f); } }; \$cb();", 'web', []],
            'F1 import then destructuring' => ["\$f = base_path('routes/admin.php'); \$cb = function () use (\$f) { [\$f] = [base_path('routes/mobile.php')]; Route::middleware('web')->group(\$f); }; \$cb();", 'web', []],
            'F1 import then unset' => ["\$f = base_path('routes/admin.php'); \$cb = function () use (\$f) { unset(\$f); Route::middleware('web')->group(\$f); }; \$cb();", 'web', []],
            'F1 import then a nested by-reference closure' => ["\$f = base_path('routes/admin.php'); \$cb = function () use (\$f) { \$s = function () use (&\$f) { \$f = base_path('routes/mobile.php'); }; \$s(); Route::middleware('web')->group(\$f); }; \$cb();", 'web', []],
            'F1 import then extract()' => ["\$f = base_path('routes/admin.php'); \$cb = function () use (\$f) { extract(['f' => base_path('routes/mobile.php')]); Route::middleware('web')->group(\$f); }; \$cb();", 'web', []],
            'F1 import then require' => ["\$f = base_path('routes/admin.php'); \$cb = function () use (\$f) { require base_path('routes/mobile.php'); Route::middleware('web')->group(\$f); }; \$cb();", 'web', []],
            'F1 import then goto' => ["\$f = base_path('routes/admin.php'); \$cb = function () use (\$f) { goto x; x: Route::middleware('web')->group(\$f); }; \$cb();", 'web', []],
            'F1 import then a direct and another write' => ["\$f = base_path('routes/admin.php'); \$cb = function () use (\$f) { \$f = base_path('routes/mobile.php'); \$f .= ''; Route::middleware('web')->group(\$f); }; \$cb();", 'web', []],
            'F1 import read by an arrow function after a foreach' => ["\$f = base_path('routes/admin.php'); \$cb = function () use (\$f) { foreach ([base_path('routes/mobile.php')] as \$f) { } (fn () => Route::middleware('web')->group(\$f))(); }; \$cb();", 'web', []],
            'list rewritten through a by-reference foreach' => ["\$f = [base_path('routes/admin.php')]; foreach (\$f as &\$x) { \$x = base_path('routes/mobile.php'); } unset(\$x); Route::middleware('web')->group(\$f);", 'web', []],
            'list holding a reference' => ["\$x = base_path('routes/admin.php'); \$f = [&\$x]; \$x = base_path('routes/mobile.php'); Route::middleware('web')->group(\$f);", 'web', []],
            'list destructured by reference' => ["\$f = [base_path('routes/admin.php')]; [&\$a] = \$f; \$a = base_path('routes/mobile.php'); Route::middleware('web')->group(\$f);", 'web', []],
            'scope calls eval()' => ["\$f = base_path('routes/admin.php'); eval('\$f = 1;'); Route::middleware('web')->group(\$f);", 'web', []],
            'scope writes GLOBALS' => ["\$f = base_path('routes/admin.php'); \$GLOBALS['f'] = base_path('routes/mobile.php'); Route::middleware('web')->group(\$f);", 'web', []],
            'scope declares a function with global' => ["\$f = base_path('routes/admin.php'); function swap() { global \$f; \$f = 1; } swap(); Route::middleware('web')->group(\$f);", 'web', []],
            'importing closure rebinds the variable directly' => ["\$f = base_path('routes/mobile.php'); \$cb = function () use (\$f) { \$f = base_path('routes/admin.php'); Route::middleware('web')->group(\$f); }; \$cb();", 'web', ['admin.php']],
            'callback variable reassigned to a path' => ["\$f = function () { }; \$f = base_path('routes/admin.php'); Route::middleware('web')->group(\$f);", 'web', ['admin.php']],
            'passed to a group() on another class' => ["\$file = base_path('routes/admin.php'); (new RouteFiles)->group(\$file); Route::middleware('web')->group(\$file);", 'web', []],
            'passed to a static group() on another class' => ["\$file = base_path('routes/admin.php'); RouteFiles::group(\$file); Route::middleware('web')->group(\$file);", 'web', []],
            'a reference the closure imports' => ["\$cb = function () use (&\$file) { \$file = base_path('routes/admin.php'); swapRoutes(); Route::middleware('web')->group(\$file); }; \$cb();", 'web', []],
            'a reference parameter' => ["\$cb = function (&\$file) { \$file = base_path('routes/admin.php'); swapRoutes(); Route::middleware('web')->group(\$file); }; \$cb(\$x);", 'web', []],
            'held group attributes' => ["\$attrs = ['middleware' => 'web']; Route::group(\$attrs, base_path('routes/admin.php'));", 'web', ['admin.php']],
            'a held middleware name' => ["\$mw = 'web'; Route::middleware(\$mw)->group(base_path('routes/admin.php'));", 'web', ['admin.php']],
            'a held middleware list' => ["\$mw = ['web']; Route::middleware(\$mw)->group(base_path('routes/admin.php'));", 'web', ['admin.php']],
            'a held middleware list without web' => ["\$mw = ['auth']; Route::middleware(\$mw)->group(base_path('routes/admin.php'));", 'web', []],
            'a held exclusion list of another name' => ["\$skip = ['auth']; Route::middleware(['web', 'throttle:5,1'])->withoutMiddleware(\$skip)->group(base_path('routes/admin.php'));", 'throttle', ['admin.php']],
            'a held exclusion list' => ["\$skip = ['throttle:5,1']; Route::middleware(['web', 'throttle:5,1'])->withoutMiddleware(\$skip)->group(base_path('routes/admin.php'));", 'throttle', []],
            'a held middleware name in held group attributes' => ["\$mw = 'web'; \$attrs = ['middleware' => \$mw]; Route::group(\$attrs, base_path('routes/admin.php'));", 'web', ['admin.php']],
            'passed to a registrar a variable holds' => ["\$file = base_path('routes/admin.php'); \$r = Route::middleware('web'); \$r->group(\$file);", 'registered', ['admin.php']],
            'passed to another call on the router' => ["\$file = base_path('routes/admin.php'); Route::pattern('file', \$file); Route::middleware('web')->group(\$file);", 'web', ['admin.php']],
            'passed to a variable reassigned from the router' => ["\$file = base_path('routes/admin.php'); \$r = Route::middleware('web'); \$r = new RouteFiles; \$r->group(\$file);", 'registered', []],
            'a list doubled many times stays bounded' => ["\$f = [base_path('routes/admin.php')];".str_repeat(' $f = [$f, $f];', 30)." Route::middleware('web')->group(\$f);", 'web', ['admin.php']],
        ];
    }

    public function test_provider_group_reads_route_files_held_in_a_variable(): void
    {
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\Facades\Route;

class RouteServiceProvider
{
    public function boot(): void
    {
        $this->routes(function () {
            $file = base_path('routes/admin.php');
            Route::middleware('web')->group($file);

            $files = [base_path('routes/billing.php')];
            Route::middleware('web')->group($files);
        });
    }

    public function map(): void
    {
        Route::middleware('web')->group($file);
    }
}
PHP;
        $tempDir = $this->createTempDir([
            'app/Providers/RouteServiceProvider.php' => $provider,
            'routes/admin.php' => '<?php',
            'routes/billing.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $names = array_map('basename', $parser->getWebProtectedRouteFiles());
            sort($names);

            $this->assertSame(['admin.php', 'billing.php'], $names);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @dataProvider computedProviderPathProvider
     *
     * @param  list<string>  $expected
     */
    #[DataProvider('computedProviderPathProvider')]
    public function test_provider_group_reads_a_path_a_method_of_its_class_computes(string $method, string $call, array $expected): void
    {
        $provider = <<<PHP
<?php

namespace App\\Providers;

use Illuminate\\Support\\Facades\\Route;

class RouteServiceProvider
{
    public function boot(): void
    {
        Route::middleware('api')->prefix('api')->group({$call});
    }

    {$method}
}
PHP;
        $tempDir = $this->createTempDir([
            'app/Providers/RouteServiceProvider.php' => $provider,
            'routes/api.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame($expected, array_map('basename', $parser->getApiRegisteredRouteFiles()));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, string, list<string>}>
     */
    public static function computedProviderPathProvider(): array
    {
        return [
            'interpolated parameter' => ['private function path(string $name): string { return base_path("routes/{$name}.php"); }', "\$this->path('api')", ['api.php']],
            'concatenated parameter' => ["protected function path(\$name) { return base_path('routes/'.\$name.'.php'); }", "\$this->path('api')", ['api.php']],
            'the method name in another case' => ['private function path(string $name): string { return base_path("routes/{$name}.php"); }', "\$this->PATH('api')", ['api.php']],
            'another variable' => ['private function path(string $name): string { return base_path("routes/{$this->dir}/{$name}.php"); }', "\$this->path('api')", []],
            'a variable that is not the parameter' => ['private function path(string $name): string { return base_path("routes/{$other}.php"); }', "\$this->path('api')", []],
            'a call in the concatenation' => ["private function path(\$name) { return base_path('routes/'.strtolower(\$name).'.php'); }", "\$this->path('api')", []],
            'more than a return' => ['private function path(string $name): string { $name = "api"; return base_path("routes/{$name}.php"); }', "\$this->path('web')", []],
            'another function' => ['private function path(string $name): string { return app_path("routes/{$name}.php"); }', "\$this->path('api')", []],
            'two parameters' => ['private function path(string $dir, string $name): string { return base_path("{$dir}/{$name}.php"); }', "\$this->path('routes', 'api')", []],
            'a computed argument' => ['private function path(string $name): string { return base_path("routes/{$name}.php"); }', '$this->path($this->name)', []],
            'a method of another object' => ['private function path(string $name): string { return base_path("routes/{$name}.php"); }', "\$paths->path('api')", []],
            'a method the class does not declare' => ['', "\$this->path('api')", []],
        ];
    }

    public function test_route_file_loads_read_a_group_path_held_in_a_variable(): void
    {
        $web = <<<'PHP'
<?php

$f = base_path('routes/billing.php');
Route::prefix('billing')->group($f);

$files = [__DIR__.'/admin.php'];
Route::prefix('admin')->group($files);
PHP;
        $tempDir = $this->createTempDir([
            'routes/web.php' => $web,
            'routes/billing.php' => '<?php',
            'routes/admin.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $loads = $parser->getRouteFileLoads()[(string) realpath($tempDir.'/routes/web.php')] ?? [];

            $this->assertSame(
                [[(string) realpath($tempDir.'/routes/billing.php'), 1], [(string) realpath($tempDir.'/routes/admin.php'), 1]],
                array_map(fn (array $load): array => [$load['file'], count($load['calls'])], $loads),
            );
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @dataProvider heldRegistrarRegistrationProvider
     *
     * @param  list<string>  $expected
     */
    #[DataProvider('heldRegistrarRegistrationProvider')]
    public function test_a_held_registrar_registers_the_files_its_group_loads(string $registration, string $reader, array $expected): void
    {
        $tempDir = $this->createTempDir([
            'bootstrap/app.php' => $this->bootstrapRegistering('', $registration),
            'routes/auth.php' => '<?php',
        ]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $result = $reader === 'web' ? $parser->getWebProtectedRouteFiles() : $parser->getThrottleProtectedRouteFiles();

            $this->assertSame($expected, array_map('basename', $result));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    /**
     * @return array<string, array{string, string, list<string>}>
     */
    public static function heldRegistrarRegistrationProvider(): array
    {
        $file = "base_path('routes/auth.php')";

        return [
            'a held registrar' => ["\$r = Route::middleware(['web', 'throttle:5,1']);\n            \$r->group({$file});", 'throttle', ['auth.php']],
            'a held registrar a later call changes' => ["\$r = Route::middleware(['web', 'throttle:5,1']);\n            \$r->middleware('web');\n            \$r->group({$file});", 'throttle', []],
        ];
    }

    public function test_throttled_group_ranges_read_a_held_middleware_name(): void
    {
        $routes = <<<'PHP'
<?php

$mw = 'throttle:5,1';
Route::middleware($mw)->group(function () {
    Route::post('/login', [LoginController::class, 'store']);
});
PHP;
        $tempDir = $this->createTempDir(['routes/web.php' => $routes]);

        try {
            $this->assertSame([['start' => 4, 'end' => 6]], (new BootstrapRouteParser($tempDir, $this->parser))->getThrottledGroupLineRanges($tempDir.'/routes/web.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_a_walk_gives_a_read_variable_the_value_it_holds(): void
    {
        $ast = $this->parser->parseCode(<<<'PHP'
<?php

$name = 'throttle:5,1';
$limited = Route::middleware($name);
$limited->group(function () {});

$open = Route::prefix('open');
if ($local) {
    $open = Route::prefix('local');
}
$open->group(function () {});
PHP);

        (new BootstrapRouteParser('/app', $this->parser))->routerGroupCalls($ast);

        $held = [];
        foreach ($this->parser->findNodes($ast, Node\Expr\Variable::class) as $variable) {
            $this->assertInstanceOf(Node\Expr\Variable::class, $variable);
            $value = $variable->getAttribute(BootstrapRouteParser::HELD_VALUE);
            $held[] = [$variable->name, $value instanceof Node ? $value::class : null];
        }

        $this->assertSame([
            ['name', null],
            ['limited', null],
            ['name', Node\Scalar\String_::class],
            ['limited', StaticCall::class],
            ['open', null],
            ['local', null],
            ['open', null],
            ['open', null],
        ], $held);
    }

    public function test_throttled_group_ranges_do_not_read_a_closure_held_in_a_variable(): void
    {
        $routes = <<<'PHP'
<?php

$routes = function () {
    Route::post('/login', [LoginController::class, 'store']);
};
Route::middleware('throttle:5,1')->group($routes);

$other = fn () => Route::post('/signin', [LoginController::class, 'store']);
$other = 'not a callback';
Route::middleware('throttle:5,1')->group($other);
PHP;
        $tempDir = $this->createTempDir(['routes/web.php' => $routes]);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            // A callback held in a variable is read only by csrf-protection's own walk
            $this->assertSame([], $parser->getThrottledGroupLineRanges($tempDir.'/routes/web.php'));
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_global_scope_variable_a_function_may_rewrite_is_not_read(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

$admin = base_path('routes/admin.php');
function useMobileRoutes(): void { $GLOBALS['admin'] = base_path('routes/mobile.php'); }
useMobileRoutes();

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(then: function () use ($admin) { Route::middleware('web')->group($admin); })
    ->create();
PHP;
        $tempDir = $this->createTempDir(['bootstrap/app.php' => $bootstrap, 'routes/admin.php' => '<?php', 'routes/mobile.php' => '<?php']);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);

            $this->assertSame([], $parser->getWebProtectedRouteFiles());
        } finally {
            $this->removeDir($tempDir);
        }
    }

    public function test_route_file_loads_stay_linear_in_deeply_nested_branches(): void
    {
        $routes = "<?php\n\$f = base_path('routes/admin.php');\n"
            .str_repeat('if ($a) { ', 500).'$f = base_path(\'routes/admin.php\');'.str_repeat(' }', 500)."\n"
            .'$ok = $a'.str_repeat(' && $a', 1999).";\n"
            ."Route::middleware('web')->group(\$f);\n";
        $tempDir = $this->createTempDir(['routes/web.php' => $routes, 'routes/admin.php' => '<?php']);

        try {
            $parser = new BootstrapRouteParser($tempDir, $this->parser);
            $before = $this->cpuSeconds();
            $parser->getRouteFileLoads();
            $seconds = $this->cpuSeconds() - $before;

            $this->assertLessThan(1.0, $seconds);
        } finally {
            $this->removeDir($tempDir);
        }
    }

    private function cpuSeconds(): float
    {
        $usage = getrusage();
        $this->assertIsArray($usage);

        return $usage['ru_utime.tv_sec'] + $usage['ru_utime.tv_usec'] / 1e6;
    }

    private function bootstrapRegistering(string $imports, string $registration): string
    {
        return <<<PHP
<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
{$imports}

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            {$registration}
        },
    )
    ->create();
PHP;
    }

    /**
     * @param  array<string>  $paths
     */
    private function endsWithMatch(array $paths, string $suffix): bool
    {
        foreach ($paths as $path) {
            if (str_ends_with($path, $suffix)) {
                return true;
            }
        }

        return false;
    }
}
