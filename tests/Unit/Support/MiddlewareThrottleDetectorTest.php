<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PhpParser\Node\Expr;
use PhpParser\Node\Stmt\Expression;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Support\MiddlewareThrottleDetector;
use ShieldCI\Tests\Concerns\CreatesTemporaryPaths;

class MiddlewareThrottleDetectorTest extends TestCase
{
    use CreatesTemporaryPaths;

    /** @var array<int, string> */
    private array $tempDirs = [];

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            $this->removeDir($dir);
        }

        parent::tearDown();
    }

    public function test_no_kernel_and_no_bootstrap_throttles_nothing(): void
    {
        $this->assertFalse($this->detector([])->throttlesGroups(['web', 'api']));
    }

    public function test_kernel_global_middleware_throttles_every_group(): void
    {
        $detector = $this->detector(['app/Http/Kernel.php' => $this->kernel(
            "protected \$middleware = [\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class.':60,1'];"
        )]);

        $this->assertTrue($detector->throttlesGroups(['web']));
        $this->assertTrue($detector->throttlesGroups(['api']));
    }

    public function test_kernel_group_throttles_only_the_groups_it_is_listed_under(): void
    {
        $detector = $this->detector(['app/Http/Kernel.php' => $this->kernel(
            "protected \$middlewareGroups = ['web' => [\\Illuminate\\Session\\Middleware\\StartSession::class], 'admin' => ['throttle:10,1']];"
        )]);

        $this->assertFalse($detector->throttlesGroups(['web']));
        $this->assertTrue($detector->throttlesGroups(['admin']));
        $this->assertTrue($detector->throttlesGroups(['web', 'admin']));
    }

    public function test_kernel_property_without_an_array_default_throttles_nothing(): void
    {
        $detector = $this->detector(['app/Http/Kernel.php' => $this->kernel(
            "protected \$middlewareGroups;\n    protected \$routeMiddleware = ['throttle' => \\Illuminate\\Routing\\Middleware\\ThrottleRequests::class];"
        )]);

        $this->assertFalse($detector->throttlesGroups(['web', 'api']));
    }

    public function test_kernel_reads_an_aliased_import(): void
    {
        $detector = $this->detector(['app/Http/Kernel.php' => $this->kernel(
            "protected \$middlewareGroups = ['web' => [Throttle::class]];",
            'use Illuminate\\Routing\\Middleware\\ThrottleRequests as Throttle;',
        )]);

        $this->assertTrue($detector->throttlesGroups(['web']));
    }

    /**
     * @dataProvider throttlingConfiguratorCalls
     */
    #[DataProvider('throttlingConfiguratorCalls')]
    public function test_configurator_call_throttles_the_web_group(string $body): void
    {
        $this->assertTrue($this->bootstrapDetector($body)->throttlesGroups(['web']));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function throttlingConfiguratorCalls(): array
    {
        return [
            'append' => ["\$middleware->append('throttle:60,1');"],
            'prepend' => ['$middleware->prepend(\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class);'],
            'use' => ["\$middleware->use(['throttle:60,1']);"],
            'appendToGroup' => ["\$middleware->appendToGroup('web', 'throttle:60,1');"],
            'prependToGroup named' => ["\$middleware->prependToGroup(middleware: ['throttle:60,1'], group: 'web');"],
            'group' => ["\$middleware->group('web', ['throttle:60,1']);"],
            'web append' => ["\$middleware->web(['throttle:60,1']);"],
            'web prepend' => ["\$middleware->web(prepend: ['throttle:60,1']);"],
            'web replace' => ["\$middleware->web(replace: [\\App\\Http\\Middleware\\Limit::class => 'throttle:60,1']);"],
            'using' => ["\$middleware->web(append: [\\Illuminate\\Routing\\Middleware\\ThrottleRequests::using('login')]);"],
            'with' => ['$middleware->web(append: [\\Illuminate\\Routing\\Middleware\\ThrottleRequestsWithRedis::with(5, 1)]);'],
            'chained' => ["\$middleware->alias(['admin' => \\App\\Http\\Middleware\\Admin::class])->web(append: ['throttle:60,1']);"],
        ];
    }

    /**
     * @dataProvider nonThrottlingConfiguratorCalls
     */
    #[DataProvider('nonThrottlingConfiguratorCalls')]
    public function test_configurator_call_does_not_throttle_the_web_group(string $body): void
    {
        $this->assertFalse($this->bootstrapDetector($body)->throttlesGroups(['web']));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonThrottlingConfiguratorCalls(): array
    {
        return [
            'web remove' => ["\$middleware->web(remove: ['throttle:60,1']);"],
            'chained web remove' => ["\$middleware->alias([])->web(remove: ['throttle:60,1']);"],
            'api append' => ["\$middleware->api(append: ['throttle:60,1']);"],
            'chained api append' => ["\$middleware->alias([])->api(append: ['throttle:60,1']);"],
            'other group' => ["\$middleware->appendToGroup('admin', 'throttle:60,1');"],
            'group name not a string' => ["\$middleware->appendToGroup(\$name, 'throttle:60,1');"],
            'throttleApi' => ['$middleware->throttleApi();'],
            'throttleWithRedis' => ['$middleware->throttleWithRedis();'],
            'first-class callable' => ['$middleware->append(...);'],
            'non-throttle middleware' => ['$middleware->append(\\Illuminate\\Session\\Middleware\\StartSession::class);'],
            'other class using' => ["\$middleware->append(\\App\\Http\\Middleware\\Limit::using('login'));"],
            'other throttle factory' => ["\$middleware->append(\\Illuminate\\Routing\\Middleware\\ThrottleRequests::make('login'));"],
            'dynamic method name' => ["\$middleware->{\$method}('throttle:60,1');"],
            'chain rooted at a static call' => ["Route::middleware('web')->append('throttle:60,1');"],
            'unknown method' => ["\$middleware->redirectGuestsTo('throttle');"],
        ];
    }

    public function test_throttle_api_covers_the_api_group_only(): void
    {
        $detector = $this->bootstrapDetector('$middleware->throttleApi();');

        $this->assertTrue($detector->throttlesGroups(['api']));
        $this->assertFalse($detector->throttlesGroups(['web']));
    }

    public function test_bootstrap_reads_an_aliased_import(): void
    {
        $detector = $this->bootstrapDetector(
            '$middleware->web(append: [Throttle::using(\'login\')]);',
            'use Illuminate\\Routing\\Middleware\\ThrottleRequests as Throttle;',
        );

        $this->assertTrue($detector->throttlesGroups(['web']));
    }

    public function test_colliding_imports_keep_the_first_and_resolve_the_rest(): void
    {
        // Two imports land on 'Limit': the first, a non-throttle, wins, as PHP would have
        // had to refuse the second. The import after the collision still resolves.
        $imports = "use App\\Http\\Middleware\\Admin as Limit;\nuse Illuminate\\Routing\\Middleware\\ThrottleRequests as Limit;\nuse Illuminate\\Routing\\Middleware\\ThrottleRequests as Throttle;";

        $this->assertFalse($this->bootstrapDetector('$middleware->web(append: [Limit::class]);', $imports)->throttlesGroups(['web']));
        $this->assertTrue($this->bootstrapDetector('$middleware->web(append: [Throttle::class]);', $imports)->throttlesGroups(['web']));
    }

    public function test_expression_is_throttle_reads_an_unresolved_name_as_written(): void
    {
        $detector = $this->detector([]);
        $parser = new AstParser;

        $this->assertTrue($detector->expressionIsThrottle($this->expression($parser, "ThrottleRequests::class.':60,1'")));
        $this->assertTrue($detector->expressionIsThrottle($this->expression($parser, "['auth', ThrottleRequests::using('login')]")));
        $this->assertFalse($detector->expressionIsThrottle($this->expression($parser, 'Throttle::class')));
        $this->assertFalse($detector->expressionIsThrottle($this->expression($parser, '$throttle::class')));
        $this->assertFalse($detector->expressionIsThrottle($this->expression($parser, "\$throttle::using('login')")));
        $this->assertFalse($detector->expressionIsThrottle($this->expression($parser, "\$middleware ?? 'throttle'")));
    }

    private function expression(AstParser $parser, string $code): Expr
    {
        $stmt = $parser->parseCode("<?php {$code};")[0] ?? null;
        $this->assertInstanceOf(Expression::class, $stmt);

        return $stmt->expr;
    }

    private function bootstrapDetector(string $body, string $imports = ''): MiddlewareThrottleDetector
    {
        $bootstrap = <<<PHP
<?php

use Illuminate\\Foundation\\Application;
use Illuminate\\Foundation\\Configuration\\Middleware;
{$imports}

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware \$middleware): void {
        {$body}
    })
    ->create();
PHP;

        return $this->detector(['bootstrap/app.php' => $bootstrap]);
    }

    private function kernel(string $properties, string $imports = ''): string
    {
        return <<<PHP
<?php

namespace App\\Http;

use Illuminate\\Foundation\\Http\\Kernel as HttpKernel;
{$imports}

class Kernel extends HttpKernel
{
    {$properties}
}
PHP;
    }

    /**
     * @param  array<string, string>  $files
     */
    private function detector(array $files): MiddlewareThrottleDetector
    {
        $dir = $this->uniqueTempPath('middleware_throttle_detector_test_');
        mkdir($dir, 0755, true);
        $this->tempDirs[] = $dir;

        foreach ($files as $path => $content) {
            @mkdir(dirname($dir.'/'.$path), 0755, true);
            file_put_contents($dir.'/'.$path, $content);
        }

        return new MiddlewareThrottleDetector($dir, new AstParser);
    }

    private function removeDir(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        foreach (array_diff(scandir($dir) ?: [], ['.', '..']) as $file) {
            $path = $dir.'/'.$file;
            is_dir($path) ? $this->removeDir($path) : unlink($path);
        }

        rmdir($dir);
    }
}
