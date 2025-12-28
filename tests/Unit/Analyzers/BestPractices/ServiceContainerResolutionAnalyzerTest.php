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
        $this->assertStringContainsString('manual service container resolution', $issues[0]->recommendation);
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
}
