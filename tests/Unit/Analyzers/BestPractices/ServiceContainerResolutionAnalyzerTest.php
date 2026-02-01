<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\ServiceContainerResolutionAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class ServiceContainerResolutionAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        // Build best-practices config with defaults
        $bestPracticesConfig = [
            'enabled' => true,
            'service-container-resolution' => [
                'whitelist_dirs' => $config['whitelist_dirs'] ?? [
                    'tests',
                    'database/seeders',
                    'database/factories',
                ],
                'whitelist_classes' => $config['whitelist_classes'] ?? [
                    '*Command',
                    '*Seeder',
                    'DatabaseSeeder',
                ],
                'whitelist_methods' => $config['whitelist_methods'] ?? [
                    'environment',
                    'isLocal',
                    'isProduction',
                    'runningInConsole',
                    'runningUnitTests',
                ],
                'whitelist_services' => $config['whitelist_services'] ?? [
                    'config',
                    'request',
                    'log',
                    'cache',
                    'session',
                ],
                'detect_psr_get' => $config['detect_psr_get'] ?? false,
                'detect_manual_instantiation' => $config['detect_manual_instantiation'] ?? false,
                'manual_instantiation_patterns' => $config['manual_instantiation_patterns'] ?? [
                    '*Service',
                    '*Repository',
                ],
            ],
        ];

        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => $bestPracticesConfig,
                ],
            ],
        ]);

        return new ServiceContainerResolutionAnalyzer($this->parser, $configRepo);
    }

    public function test_detects_manual_service_resolution(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderProcessor
{
    public function process($orderId)
    {
        $repository = app(OrderRepository::class);
        $payment = resolve(PaymentGateway::class);
        $mailer = App::make('mailer');

        $order = $repository->find($orderId);
        $result = $payment->charge($order);
        $mailer->send(new OrderConfirmation($order));

        return $result;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderProcessor.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('service resolution', $result);
        $this->assertHasIssueContaining('OrderProcessor::process', $result);
    }

    public function test_passes_with_constructor_injection(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderProcessor
{
    public function __construct(
        private OrderRepository $repository,
        private PaymentGateway $payment,
        private Mailer $mailer
    ) {}

    public function process($orderId)
    {
        $order = $this->repository->find($orderId);
        $result = $this->payment->charge($order);
        $this->mailer->send(new OrderConfirmation($order));

        return $result;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderProcessor.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_app_make(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function process()
    {
        $repo = app()->make(UserRepository::class);
        return $repo->all();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('app()->make()', $result);
    }

    public function test_detects_app_make_with(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function create($data)
    {
        $processor = app()->makeWith(OrderProcessor::class, ['data' => $data]);
        return $processor->process();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('app()->makeWith()', $result);
    }

    public function test_detects_app_static_make(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\App;

class ProductService
{
    public function fetch()
    {
        $repo = App::make(ProductRepository::class);
        return $repo->all();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ProductService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('App::make()', $result);
    }

    public function test_detects_resolve_function(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PaymentService
{
    public function charge()
    {
        $gateway = resolve(PaymentGateway::class);
        return $gateway->charge();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/PaymentService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('resolve()', $result);
    }

    public function test_detects_container_get_instance(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Container\Container;

class CacheService
{
    public function get($key)
    {
        $cache = Container::getInstance()->make(CacheInterface::class);
        return $cache->get($key);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/CacheService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Container::getInstance()->make()', $result);
    }

    public function test_detects_bind_outside_service_provider(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function setup()
    {
        app()->bind(UserInterface::class, UserRepository::class);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('app()->bind()', $result);
        // Should be high severity for binding
        $issues = $result->getIssues();
        $this->assertSame(Severity::High, $issues[0]->severity);
    }

    public function test_detects_singleton_outside_service_provider(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConfigService
{
    public function init()
    {
        app()->singleton(Config::class, FileConfig::class);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ConfigService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('app()->singleton()', $result);
        $issues = $result->getIssues();
        $this->assertSame(Severity::High, $issues[0]->severity);
    }

    public function test_skips_actual_service_provider(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->bind(UserInterface::class, UserRepository::class);
        $this->app->singleton(Config::class, FileConfig::class);
        $cache = app()->make(CacheInterface::class);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_whitelisted_directory_tests(): void
    {
        $code = <<<'PHP'
<?php

namespace Tests\Feature;

use Tests\TestCase;

class UserTest extends TestCase
{
    public function test_user_creation()
    {
        $service = app(UserService::class);
        $service->createUser(['name' => 'John']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'tests/Feature/UserTest.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['tests']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_whitelisted_directory_seeders(): void
    {
        $code = <<<'PHP'
<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;

class UserSeeder extends Seeder
{
    public function run()
    {
        $factory = app(UserFactory::class);
        $factory->create(100);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'database/seeders/UserSeeder.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['database']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_whitelisted_class_command(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

class ProcessOrdersCommand extends Command
{
    public function handle()
    {
        $processor = app(OrderProcessor::class);
        $processor->processAll();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Console/Commands/ProcessOrdersCommand.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_whitelisted_class_seeder(): void
    {
        $code = <<<'PHP'
<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    public function run()
    {
        $userSeeder = resolve(UserSeeder::class);
        $userSeeder->run();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'database/seeders/DatabaseSeeder.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['database']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_whitelisted_method_environment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConfigService
{
    public function getMode()
    {
        return app()->environment();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ConfigService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_whitelisted_method_is_local(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DebugService
{
    public function shouldDebug()
    {
        return app()->isLocal();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/DebugService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_severity_by_argument_type_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function fetch()
    {
        $repo = app(UserRepository::class);
        return $repo->all();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertSame(Severity::Medium, $issues[0]->severity);
        $this->assertSame('class', $issues[0]->metadata['argument_type']);
    }

    public function test_severity_by_argument_type_string(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CacheService
{
    public function get()
    {
        $cache = app('cache.store');
        return $cache->get('key');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/CacheService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertSame(Severity::High, $issues[0]->severity);
        $this->assertSame('string', $issues[0]->metadata['argument_type']);
    }

    public function test_severity_by_argument_type_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DynamicService
{
    public function resolve($serviceName)
    {
        $service = app($serviceName);
        return $service->process();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/DynamicService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertSame(Severity::Medium, $issues[0]->severity);
        $this->assertSame('variable', $issues[0]->metadata['argument_type']);
    }

    public function test_handles_parse_errors_gracefully(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class InvalidSyntax
{
    public function broken(
        // Missing closing paren - syntax error
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/InvalidSyntax.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because file is skipped due to parse error
        $this->assertPassed($result);
    }

    public function test_detects_in_anonymous_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function createHandler()
    {
        return new class {
            public function handle()
            {
                $repo = app(UserRepository::class);
                return $repo->all();
            }
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('app()', $result);
    }

    public function test_detects_in_global_scope(): void
    {
        $code = <<<'PHP'
<?php

$service = app(GlobalService::class);
$service->init();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('global scope', $result);
    }

    public function test_detects_multiple_patterns_in_one_file(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class MultiService
{
    public function method1()
    {
        $repo = app(Repository::class);
        return $repo->all();
    }

    public function method2()
    {
        $cache = resolve(CacheInterface::class);
        return $cache->get('key');
    }

    public function method3()
    {
        $mailer = App::make('mailer');
        return $mailer->send();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/MultiService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
        $this->assertHasIssueContaining('app()', $result);
        $this->assertHasIssueContaining('resolve()', $result);
        $this->assertHasIssueContaining('App::make()', $result);
    }

    public function test_tracks_class_and_method_context(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function processOrder()
    {
        $repo = app(OrderRepository::class);
        return $repo->find(1);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertSame('OrderService::processOrder', $issues[0]->metadata['location']);
        $this->assertSame('OrderService', $issues[0]->metadata['class']);
    }

    public function test_provides_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function fetch()
    {
        $repo = app(UserRepository::class);
        return $repo->all();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('constructor injection', $issues[0]->recommendation);
    }

    public function test_detects_non_service_provider_in_providers_directory(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Providers;

class DataProvider
{
    public function getData()
    {
        $repo = app(DataRepository::class);
        return $repo->all();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/DataProvider.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should detect because it doesn't extend ServiceProvider
        $this->assertFailed($result);
        $this->assertHasIssueContaining('app()', $result);
    }

    public function test_custom_config_whitelist_dirs(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Middleware;

class CustomMiddleware
{
    public function handle($request, $next)
    {
        $handler = app(RequestHandler::class);
        return $handler->process($request);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Middleware/CustomMiddleware.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer([
            'whitelist_dirs' => ['app/Middleware'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_custom_config_whitelist_classes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Middleware;

class AuthMiddleware
{
    public function handle($request, $next)
    {
        $auth = app(AuthService::class);
        return $auth->check($request) ? $next($request) : abort(401);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/AuthMiddleware.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer([
            'whitelist_classes' => ['*Middleware'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_custom_config_whitelist_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CustomService
{
    public function check()
    {
        return app()->customMethod();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/CustomService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer([
            'whitelist_methods' => ['customMethod'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_metadata_contains_all_fields(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function fetch()
    {
        $repo = app(UserRepository::class);
        return $repo->all();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $metadata = $issues[0]->metadata;

        $this->assertArrayHasKey('pattern', $metadata);
        $this->assertArrayHasKey('location', $metadata);
        $this->assertArrayHasKey('class', $metadata);
        $this->assertArrayHasKey('file', $metadata);
        $this->assertArrayHasKey('argument_type', $metadata);
        $this->assertSame('app()', $metadata['pattern']);
        $this->assertSame('class', $metadata['argument_type']);
    }

    // ============================================================
    // NEW TESTS FOR IMPROVED FEATURES
    // ============================================================

    public function test_skips_resolution_in_closures(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class EventService
{
    public function register()
    {
        Event::listen(function () {
            // Closures don't support constructor DI, this is legitimate
            $handler = app(EventHandler::class);
            $handler->handle();
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/EventService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because resolution in closures is legitimate
        $this->assertPassed($result);
    }

    public function test_detects_binding_in_closures(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class SetupService
{
    public function setup()
    {
        Route::get('/', function () {
            // Binding inside closures is ALWAYS problematic
            app()->bind(UserInterface::class, UserRepository::class);
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/SetupService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should detect binding even in closures
        $this->assertFailed($result);
        $this->assertHasIssueContaining('app()->bind()', $result);
    }

    public function test_skips_whitelisted_service_aliases(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConfigService
{
    public function getConfig()
    {
        // These are common Laravel service aliases - legitimate usage
        $config = app('config');
        $request = app('request');
        $log = app('log');
        $cache = app('cache');
        $session = app('session');

        return $config->get('app.name');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ConfigService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because these are whitelisted service aliases
        $this->assertPassed($result);
    }

    public function test_detects_non_whitelisted_service_aliases(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CacheService
{
    public function get()
    {
        // 'cache.store' is NOT in whitelist
        $cache = app('cache.store');
        return $cache->get('key');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/CacheService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('app()', $result);
    }

    public function test_deduplicates_issues_on_same_line(): void
    {
        // This tests that the same pattern on the same line is only reported once
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function fetch()
    {
        $repo = app(UserRepository::class);
        return $repo->all();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Should have exactly 1 issue, not duplicated
        $this->assertCount(1, $issues);
    }

    public function test_provides_binding_specific_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class SetupService
{
    public function init()
    {
        app()->singleton(CacheInterface::class, RedisCache::class);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/SetupService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('ServiceProvider', $issues[0]->recommendation);
        $this->assertStringContainsString('register()', $issues[0]->recommendation);
    }

    public function test_psr_get_not_detected_by_default(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ContainerService
{
    public function resolve()
    {
        // PSR-11 get() method - not commonly used in Laravel
        $service = app()->get(SomeService::class);
        return $service;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ContainerService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer([
            'detect_psr_get' => false,
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because detect_psr_get is false
        $this->assertPassed($result);
    }

    public function test_psr_get_detected_when_enabled(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ContainerService
{
    public function resolve()
    {
        $service = app()->get(SomeService::class);
        return $service;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ContainerService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer([
            'detect_psr_get' => true,
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('app()->get()', $result);
    }

    public function test_manual_instantiation_not_detected_by_default(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function process()
    {
        // Manual instantiation of service - DI violation
        $repo = new OrderRepository();
        return $repo->all();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer([
            'detect_manual_instantiation' => false,
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because detect_manual_instantiation is false
        $this->assertPassed($result);
    }

    public function test_manual_instantiation_detected_when_enabled(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function process()
    {
        $repo = new OrderRepository();
        return $repo->all();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer([
            'detect_manual_instantiation' => true,
            'manual_instantiation_patterns' => ['*Repository'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('new OrderRepository()', $result);
    }

    public function test_manual_instantiation_skips_non_matching_patterns(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function process()
    {
        // UserDTO doesn't match *Service or *Repository patterns
        $dto = new UserDTO(['name' => 'John']);
        return $dto;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/OrderService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer([
            'detect_manual_instantiation' => true,
            'manual_instantiation_patterns' => ['*Service', '*Repository'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because UserDTO doesn't match patterns
        $this->assertPassed($result);
    }

    public function test_namespace_aware_whitelist_matching(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Jobs;

class ProcessOrderJob
{
    public function handle()
    {
        $repo = app(OrderRepository::class);
        return $repo->process();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Jobs/ProcessOrderJob.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer([
            'whitelist_classes' => ['*Job'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because ProcessOrderJob matches *Job pattern
        $this->assertPassed($result);
    }

    public function test_skips_resolution_in_arrow_functions(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CollectionService
{
    public function transform()
    {
        return collect([1, 2, 3])->map(fn($item) => app(Transformer::class)->transform($item));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/CollectionService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because arrow functions also don't support constructor DI
        $this->assertPassed($result);
    }

    public function test_skips_route_service_provider(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;

class RouteServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->routes(function () {
            $router = app('router');
            $router->middleware('api');
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/RouteServiceProvider.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because it extends RouteServiceProvider
        $this->assertPassed($result);
    }

    public function test_skips_event_service_provider(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;

class EventServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $events = app('events');
        $events->listen('*', function ($event) {
            // ...
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/EventServiceProvider.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because it extends EventServiceProvider
        $this->assertPassed($result);
    }

    public function test_detects_scoped_binding_outside_provider(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class SetupService
{
    public function init()
    {
        app()->scoped(RequestContext::class, function () {
            return new RequestContext();
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/SetupService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('app()->scoped()', $result);
    }

    public function test_detects_instance_binding_outside_provider(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class SetupService
{
    public function init()
    {
        $config = new AppConfig();
        app()->instance(ConfigInterface::class, $config);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/SetupService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('app()->instance()', $result);
    }

    public function test_resolve_in_nested_closures_is_skipped(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class EventService
{
    public function register()
    {
        Event::listen(function () {
            collect([1, 2, 3])->each(function ($item) {
                // Nested closure - still should be skipped
                $handler = resolve(ItemHandler::class);
                $handler->handle($item);
            });
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/EventService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because resolution in nested closures is also legitimate
        $this->assertPassed($result);
    }

    public function test_resolve_after_closure_is_detected(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class EventService
{
    public function register()
    {
        Event::listen(function () {
            // This is inside closure - skipped
        });

        // This is OUTSIDE closure - should be detected
        $service = app(SomeService::class);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/EventService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should fail because app() is outside the closure
        $this->assertFailed($result);
        $this->assertHasIssueContaining('app()', $result);
    }
}
