<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use Closure;
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
            'unregistered name with the word in it' => ["\$middleware->web(append: ['skip-throttle']);"],
            'class with the name in it' => ['$middleware->web(append: [\\App\\Http\\Middleware\\ThrottleRequestsAudit::class]);'],
            'class constant other than class' => ['$middleware->web(append: [\\Illuminate\\Routing\\Middleware\\ThrottleRequests::KEY]);'],
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

    public function test_kernel_group_class_whose_name_contains_throttle_requests_is_not_a_throttle(): void
    {
        $detector = $this->detector(['app/Http/Kernel.php' => $this->kernel(
            "protected \$middlewareGroups = ['web' => [\\App\\Http\\Middleware\\ThrottleRequestsAudit::class]];"
        )]);

        $this->assertFalse($detector->throttlesGroups(['web']));
    }

    public function test_judge_decides_which_names_throttle(): void
    {
        $detector = $this->detector(
            ['app/Http/Kernel.php' => $this->kernel("protected \$middlewareGroups = ['web' => ['login.cap:5,1'], 'api' => ['throttle:60,1']];")],
            fn (string $name): bool => $name === 'login.cap:5,1',
        );

        $this->assertTrue($detector->throttlesGroups(['web']));
        $this->assertFalse($detector->throttlesGroups(['api']));
    }

    public function test_judge_receives_a_class_reference_fully_qualified_with_a_leading_backslash(): void
    {
        $names = [];
        $detector = $this->detector(
            ['bootstrap/app.php' => $this->bootstrap(
                "\$middleware->web(append: [Throttle::class.':5,1', Throttle::using('login'), 'login.cap']);",
                'use Illuminate\\Routing\\Middleware\\ThrottleRequests as Throttle;',
            )],
            function (string $name) use (&$names): bool {
                $names[] = $name;

                return false;
            },
        );

        $this->assertFalse($detector->throttlesGroups(['web']));
        $this->assertSame([
            '\\Illuminate\\Routing\\Middleware\\ThrottleRequests:5,1',
            '\\Illuminate\\Routing\\Middleware\\ThrottleRequests:login',
            'login.cap',
        ], $names);
    }

    public function test_expression_is_throttle_reads_an_unresolved_name_as_written(): void
    {
        $detector = $this->detector([]);
        $parser = new AstParser;

        // As written, a short name in the global namespace names \ThrottleRequests, not the framework class
        $this->assertFalse($detector->expressionIsThrottle($this->expression($parser, "ThrottleRequests::class.':60,1'")));
        $this->assertTrue($detector->expressionIsThrottle($this->expression($parser, "\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class.':60,1'")));
        $this->assertTrue($detector->expressionIsThrottle($this->expression($parser, "['auth', \\Illuminate\\Routing\\Middleware\\ThrottleRequestsWithRedis::using('login')]")));
        $this->assertTrue($detector->expressionIsThrottle($this->expression($parser, "'throttle:'.\$perMinute")));
        $this->assertFalse($detector->expressionIsThrottle($this->expression($parser, 'Throttle::class')));
        $this->assertFalse($detector->expressionIsThrottle($this->expression($parser, '$throttle::class')));
        $this->assertFalse($detector->expressionIsThrottle($this->expression($parser, "\$throttle::using('login')")));
        $this->assertFalse($detector->expressionIsThrottle($this->expression($parser, "\$middleware ?? 'throttle'")));
    }

    /**
     * @dataProvider exclusionProvider
     */
    #[DataProvider('exclusionProvider')]
    public function test_throttle_survives_only_an_exclusion_of_another_name(string $applied, string $excluded, bool $throttles): void
    {
        $detector = $this->detector([]);
        $parser = new AstParser;

        $this->assertSame($throttles, $detector->throttlesAfterExclusion(
            [$this->expression($parser, $applied)],
            [$this->expression($parser, $excluded)],
        ));
    }

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function exclusionProvider(): array
    {
        $class = '\\Illuminate\\Routing\\Middleware\\ThrottleRequests';

        return [
            'same alias and parameters' => ["'throttle:5,1'", "'throttle:5,1'", false],
            'alias against its class with the same parameters' => ["'throttle:5,1'", "{$class}::class.':5,1'", false],
            'class against the alias' => ["{$class}::with(5, 1)", "'throttle:5,1'", false],
            'using against the alias' => ["{$class}::using('login')", "'throttle:login'", false],
            'excluded within a list' => ["['auth', 'throttle:5,1']", "['throttle:5,1']", false],
            'other parameters' => ["'throttle:5,1'", "'throttle:api'", true],
            'bare class against a parameterised throttle' => ["'throttle:5,1'", "{$class}::class", true],
            'parameterised against the bare alias' => ["'throttle:5,1'", "'throttle'", true],
            'computed parameters never match' => ["'throttle:'.\$limit", "'throttle:'.\$limit", true],
            'computed with() arguments never match' => ["{$class}::with(\$max, 1)", "{$class}::with(\$max, 1)", true],
            'another middleware' => ["'throttle:5,1'", "'auth'", true],
            'nothing throttles' => ["'auth'", "'throttle:5,1'", false],
            'a concatenation naming nothing' => ["\$name.':5,1'", "'throttle:5,1'", false],
        ];
    }

    /**
     * @dataProvider redisThrottleProvider
     */
    #[DataProvider('redisThrottleProvider')]
    public function test_the_throttle_alias_resolves_to_the_redis_class_when_the_app_throttles_with_redis(string $body): void
    {
        $detector = $this->bootstrapDetector($body);
        $parser = new AstParser;
        $applied = [$this->expression($parser, "'throttle:api'")];

        $this->assertTrue($detector->throttlesAfterExclusion($applied, [$this->expression($parser, "\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class.':api'")]));
        $this->assertFalse($detector->throttlesAfterExclusion($applied, [$this->expression($parser, "\\Illuminate\\Routing\\Middleware\\ThrottleRequestsWithRedis::class.':api'")]));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function redisThrottleProvider(): array
    {
        return [
            'throttleWithRedis()' => ['$middleware->throttleWithRedis();'],
            'throttleApi() with redis' => ["\$middleware->throttleApi('api', true);"],
            'throttleApi() with a named redis' => ['$middleware->throttleApi(redis: true);'],
        ];
    }

    /**
     * @dataProvider appThrottleAliasProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('appThrottleAliasProvider')]
    public function test_the_throttle_alias_resolves_to_the_class_the_app_registers_for_it(array $files): void
    {
        $detector = $this->detector($files);
        $parser = new AstParser;
        $applied = [$this->expression($parser, "'throttle:5,1'")];

        $this->assertTrue($detector->throttlesAfterExclusion($applied, [$this->expression($parser, "\\Illuminate\\Routing\\Middleware\\ThrottleRequests::class.':5,1'")]));
        $this->assertFalse($detector->throttlesAfterExclusion($applied, [$this->expression($parser, "\\App\\Http\\Middleware\\CapLogins::class.':5,1'")]));
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function appThrottleAliasProvider(): array
    {
        $kernel = <<<'PHP'
<?php

namespace App\Http;

use App\Http\Middleware\CapLogins;
use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middlewareAliases = ['throttle' => CapLogins::class];
}
PHP;
        $bootstrap = <<<'PHP'
<?php

use App\Http\Middleware\CapLogins;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->throttleWithRedis();
        $middleware->alias(['throttle' => CapLogins::class]);
    })
    ->create();
PHP;

        return [
            'Kernel alias' => [['app/Http/Kernel.php' => $kernel]],
            'bootstrap alias over the redis default' => [['bootstrap/app.php' => $bootstrap]],
        ];
    }

    public function test_group_throttle_names_skip_a_dynamic_configurator_call_and_an_alias_list_without_throttle(): void
    {
        $detector = $this->bootstrapDetector("\$middleware->{\$method}('throttle:5,1');\n\$middleware->alias(['auth.cap' => 'App\\\\Http\\\\Middleware\\\\Cap']);\n\$middleware->throttleApi();");

        $this->assertSame(['global' => false, 'names' => ['throttle:api']], $detector->groupThrottleNames(['api']));
        $aliasClass = new \ReflectionMethod($detector, 'throttleAliasClass');
        $aliasClass->setAccessible(true);
        $this->assertSame('Illuminate\\Routing\\Middleware\\ThrottleRequests', $aliasClass->invoke($detector));
    }

    public function test_group_throttle_names_list_each_group_throttle_with_its_parameters(): void
    {
        $detector = $this->bootstrapDetector(
            "\$middleware->throttleApi('partners');\n"
            ."\$middleware->web(append: ['auth', Throttle::class.':5,1']);\n"
            ."\$middleware->appendToGroup('web', 'throttle:login');",
            'use Illuminate\\Routing\\Middleware\\ThrottleRequests as Throttle;',
        );

        $this->assertSame(['global' => false, 'names' => ['throttle:partners']], $detector->groupThrottleNames(['api']));
        $this->assertSame(
            ['global' => false, 'names' => ['\\Illuminate\\Routing\\Middleware\\ThrottleRequests:5,1', 'throttle:login']],
            $detector->groupThrottleNames(['web']),
        );
    }

    public function test_group_throttle_names_default_the_api_limiter_and_flag_a_global_throttle(): void
    {
        $detector = $this->bootstrapDetector("\$middleware->throttleApi();\n\$middleware->append('throttle:600,1');");

        $this->assertSame(['global' => true, 'names' => ['throttle:api']], $detector->groupThrottleNames(['api']));
        $this->assertSame(['global' => true, 'names' => []], $detector->groupThrottleNames(['web']));
    }

    public function test_group_throttle_names_read_the_kernel(): void
    {
        $detector = $this->detector(['app/Http/Kernel.php' => $this->kernel(
            "protected \$middlewareGroups = ['web' => ['auth'], 'api' => [ThrottleRequests::class.':api', 'bindings']];",
            'use Illuminate\\Routing\\Middleware\\ThrottleRequests;',
        )]);

        $this->assertSame(['global' => false, 'names' => ['\\Illuminate\\Routing\\Middleware\\ThrottleRequests:api']], $detector->groupThrottleNames(['api']));
        $this->assertSame(['global' => false, 'names' => []], $detector->groupThrottleNames(['web']));
    }

    private function expression(AstParser $parser, string $code): Expr
    {
        $stmt = $parser->parseCode("<?php {$code};")[0] ?? null;
        $this->assertInstanceOf(Expression::class, $stmt);

        return $stmt->expr;
    }

    private function bootstrapDetector(string $body, string $imports = ''): MiddlewareThrottleDetector
    {
        return $this->detector(['bootstrap/app.php' => $this->bootstrap($body, $imports)]);
    }

    private function bootstrap(string $body, string $imports = ''): string
    {
        return <<<PHP
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
     * @param  (Closure(string): bool)|null  $nameThrottles
     */
    private function detector(array $files, ?Closure $nameThrottles = null): MiddlewareThrottleDetector
    {
        $dir = $this->uniqueTempPath('middleware_throttle_detector_test_');
        mkdir($dir, 0755, true);
        $this->tempDirs[] = $dir;

        foreach ($files as $path => $content) {
            @mkdir(dirname($dir.'/'.$path), 0755, true);
            file_put_contents($dir.'/'.$path, $content);
        }

        return new MiddlewareThrottleDetector($dir, new AstParser, $nameThrottles);
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
