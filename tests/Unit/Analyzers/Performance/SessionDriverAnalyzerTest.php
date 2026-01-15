<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Mockery;
use ShieldCI\Analyzers\Performance\SessionDriverAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class SessionDriverAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $configValues
     * @param  array<string>  $globalMiddleware
     */
    protected function createAnalyzer(
        array $configValues = [],
        bool $usesSession = true,
        array $globalMiddleware = [],
        ?Kernel $kernelInstance = null
    ): AnalyzerInterface {
        /** @var ConfigRepository&\Mockery\MockInterface $config */
        $config = Mockery::mock(ConfigRepository::class);

        // Set up default config values
        $defaults = [
            'app' => [
                'env' => 'production', // Default to production so tests actually run
            ],
            'session' => [
                'driver' => 'redis',
            ],
        ];

        $configMap = array_replace_recursive($defaults, $configValues);

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $config->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) use ($configMap) {
                // Handle dotted key access (e.g., 'session.driver', 'app.env')
                $keys = explode('.', $key);
                $value = $configMap;

                foreach ($keys as $segment) {
                    if (is_array($value) && array_key_exists($segment, $value)) {
                        $value = $value[$segment];
                    } else {
                        return $default;
                    }
                }

                return $value ?? $default;
            });

        /** @var Router&\Mockery\MockInterface $router */
        $router = Mockery::mock(Router::class);

        // Mock router - directly mock getRoutes() to avoid RouteCollection complexities
        $mockRoutes = [];
        if ($usesSession) {
            $route = Mockery::mock(Route::class);
            /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
            $route->shouldReceive('middleware')
                ->andReturn(['web']);
            $mockRoutes[] = $route;
        }

        /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
        $router->shouldReceive('getRoutes')
            ->andReturn($mockRoutes);

        if ($kernelInstance !== null) {
            $kernel = $kernelInstance;
        } else {
            /** @var Kernel&\Mockery\MockInterface $kernel */
            $kernel = Mockery::mock(Kernel::class);

            // Mock kernel - return provided global middleware
            /** @phpstan-ignore-next-line Mockery methods are not recognized by PHPStan */
            $kernel->shouldReceive('getGlobalMiddleware')
                ->andReturn($globalMiddleware);
        }

        return new SessionDriverAnalyzer($config, $router, $kernel);
    }

    public function test_passes_with_redis_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => [
                'driver' => 'redis',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_database_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => [
                'driver' => 'database',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_null_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => [
                'driver' => 'null',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('null', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('null', $issues[0]->metadata['driver'] ?? '');
    }

    public function test_warns_about_file_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => [
                'driver' => 'file',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('file', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('file', $issues[0]->metadata['driver'] ?? '');
        $this->assertEquals('production', $issues[0]->metadata['environment'] ?? '');
    }

    public function test_passes_with_file_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'session' => [
                'driver' => 'file',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_array_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => [
                'driver' => 'array',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('array', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('array', $issues[0]->metadata['driver'] ?? '');
    }

    public function test_passes_with_array_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'session' => [
                'driver' => 'array',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_about_cookie_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => [
                'driver' => 'cookie',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('cookie', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('cookie', $issues[0]->metadata['driver'] ?? '');
    }

    public function test_passes_with_cookie_driver_in_local(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'local',
            ],
            'session' => [
                'driver' => 'cookie',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_when_app_is_stateless(): void
    {
        $analyzer = $this->createAnalyzer(
            [
                'session' => [
                    'driver' => 'null',
                ],
            ],
            usesSession: false
        );

        $this->assertFalse($analyzer->shouldRun());
        $this->assertSame('Application does not use sessions (stateless)', $analyzer->getSkipReason());

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_warns_about_file_driver_in_staging(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'staging',
            ],
            'session' => [
                'driver' => 'file',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('file', $result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals('staging', $issues[0]->metadata['environment'] ?? '');
    }

    public function test_passes_with_file_driver_in_testing_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'testing',
            ],
            'session' => [
                'driver' => 'file',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_array_driver_in_testing_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => [
                'env' => 'testing',
            ],
            'session' => [
                'driver' => 'array',
            ],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_should_run_when_global_middleware_uses_sessions(): void
    {
        /** @var array<string> $middleware */
        $middleware = ['Illuminate\Session\Middleware\StartSession'];

        $kernel = new class($middleware) implements Kernel
        {
            /** @param array<string> $middleware */
            public function __construct(private array $middleware) {}

            public function bootstrap(): void {}

            /** @return mixed */
            public function handle($request)
            {
                return $request;
            }

            public function terminate($request, $response): void {}

            /** @return \Illuminate\Contracts\Foundation\Application */
            public function getApplication()
            {
                /** @var \Illuminate\Contracts\Foundation\Application */
                return \Mockery::mock('Illuminate\\Contracts\\Foundation\\Application');
            }

            /** @return array<string> */
            public function getGlobalMiddleware(): array
            {
                return $this->middleware;
            }
        };

        /** @var SessionDriverAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer(
            usesSession: false,
            kernelInstance: $kernel
        );

        $this->assertTrue($analyzer->shouldRun());

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ============================================================
    // Category 1: Result Type and Severity Validation (5 tests)
    // ============================================================

    public function test_returns_failed_result_when_critical_severity_null_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => ['driver' => 'null'],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('configuration issues', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
    }

    public function test_returns_failed_result_when_critical_severity_array_driver_in_production(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'production'],
            'session' => ['driver' => 'array'],
        ]);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('configuration issues', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
    }

    public function test_returns_warning_result_when_medium_severity_file_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'production'],
            'session' => ['driver' => 'file'],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('configuration issues', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
    }

    public function test_returns_warning_result_when_low_severity_cookie_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'production'],
            'session' => ['driver' => 'cookie'],
        ]);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertStringContainsString('configuration issues', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $issues[0]->severity);
    }

    public function test_passed_result_includes_environment_in_message(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'production'],
            'session' => ['driver' => 'redis'],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('production environment', $result->getMessage());
        $this->assertStringContainsString('properly configured', $result->getMessage());
    }

    // ============================================================
    // Category 2: Metadata Validation (4 tests)
    // ============================================================

    public function test_null_driver_metadata_is_complete(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'production'],
            'session' => ['driver' => 'null'],
        ]);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('driver', $metadata);
        $this->assertArrayHasKey('environment', $metadata);
        $this->assertArrayHasKey('uses_sessions', $metadata);

        $this->assertEquals('null', $metadata['driver']);
        $this->assertEquals('production', $metadata['environment']);
        $this->assertTrue($metadata['uses_sessions']);
    }

    public function test_array_driver_metadata_is_complete(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'production'],
            'session' => ['driver' => 'array'],
        ]);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('driver', $metadata);
        $this->assertArrayHasKey('environment', $metadata);

        $this->assertEquals('array', $metadata['driver']);
        $this->assertEquals('production', $metadata['environment']);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
    }

    public function test_file_driver_metadata_is_complete(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'production'],
            'session' => ['driver' => 'file'],
        ]);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('driver', $metadata);
        $this->assertArrayHasKey('environment', $metadata);

        $this->assertEquals('file', $metadata['driver']);
        $this->assertEquals('production', $metadata['environment']);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
    }

    public function test_cookie_driver_metadata_is_complete(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'staging'],
            'session' => ['driver' => 'cookie'],
        ]);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('driver', $metadata);
        $this->assertArrayHasKey('environment', $metadata);

        $this->assertEquals('cookie', $metadata['driver']);
        $this->assertEquals('staging', $metadata['environment']);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Low, $issues[0]->severity);
    }

    // ============================================================
    // Category 3: Additional Drivers (3 tests)
    // ============================================================

    public function test_passes_with_memcached_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'production'],
            'session' => ['driver' => 'memcached'],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('memcached', $result->getMessage());
        $this->assertStringContainsString('properly configured', $result->getMessage());
    }

    public function test_passes_with_dynamodb_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'production'],
            'session' => ['driver' => 'dynamodb'],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('dynamodb', $result->getMessage());
        $this->assertStringContainsString('properly configured', $result->getMessage());
    }

    public function test_handles_unknown_custom_driver(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'production'],
            'session' => ['driver' => 'custom-session-driver'],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('custom-session-driver', $result->getMessage());
        $this->assertStringContainsString('properly configured', $result->getMessage());
    }

    // ============================================================
    // Category 4: Edge Cases and Error Handling (4 tests)
    // ============================================================

    public function test_handles_non_string_driver_configuration(): void
    {
        $analyzer = $this->createAnalyzer([
            'session' => ['driver' => ['invalid' => 'array']],
        ]);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('Invalid session driver', $result->getMessage());
    }

    public function test_null_driver_always_fails_regardless_of_environment(): void
    {
        $environments = ['local', 'testing', 'staging', 'production'];

        foreach ($environments as $env) {
            $analyzer = $this->createAnalyzer([
                'app' => ['env' => $env],
                'session' => ['driver' => 'null'],
            ]);

            $result = $analyzer->analyze();

            $this->assertFailed($result);

            $issues = $result->getIssues();
            $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
        }
    }

    public function test_array_driver_in_development_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'development'],
            'session' => ['driver' => 'array'],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('development', $result->getMessage());
    }

    public function test_file_driver_in_development_environment(): void
    {
        $analyzer = $this->createAnalyzer([
            'app' => ['env' => 'development'],
            'session' => ['driver' => 'file'],
        ]);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('development', $result->getMessage());
    }

    // ============================================================
    // Category 5: Session Detection Logic (2 tests)
    // ============================================================

    public function test_detects_startsession_middleware_without_namespace(): void
    {
        /** @var array<string> $middleware */
        $middleware = ['StartSession'];

        $kernel = new class($middleware) implements Kernel
        {
            /** @param array<string> $middleware */
            public function __construct(private array $middleware) {}

            public function bootstrap(): void {}

            /** @return mixed */
            public function handle($request)
            {
                return $request;
            }

            public function terminate($request, $response): void {}

            /** @return \Illuminate\Contracts\Foundation\Application */
            public function getApplication()
            {
                /** @var \Illuminate\Contracts\Foundation\Application */
                return \Mockery::mock('Illuminate\\Contracts\\Foundation\\Application');
            }

            /** @return array<string> */
            public function getGlobalMiddleware(): array
            {
                return $this->middleware;
            }
        };

        /** @var SessionDriverAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer(
            usesSession: false,
            kernelInstance: $kernel
        );

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_analyzer_metadata_values(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('session-driver', $metadata->id);
        $this->assertEquals('Session Driver Configuration Analyzer', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $metadata->severity);
        $this->assertContains('session', $metadata->tags);
        $this->assertContains('performance', $metadata->tags);
        $this->assertEquals(30, $metadata->timeToFix);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
