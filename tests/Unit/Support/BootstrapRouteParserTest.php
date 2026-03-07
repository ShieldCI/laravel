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
}
