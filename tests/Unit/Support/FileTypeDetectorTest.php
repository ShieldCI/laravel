<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Support\FileTypeDetector;
use ShieldCI\Tests\TestCase;

class FileTypeDetectorTest extends TestCase
{
    #[Test]
    public function it_detects_controller_files(): void
    {
        $type = FileTypeDetector::detect('/app/Http/Controllers/UserController.php');

        $this->assertEquals('controller', $type);
    }

    #[Test]
    public function it_detects_model_files(): void
    {
        $type = FileTypeDetector::detect('/app/Models/User.php');

        $this->assertEquals('model', $type);
    }

    #[Test]
    public function it_detects_service_files(): void
    {
        $type = FileTypeDetector::detect('/app/Services/PaymentService.php');

        $this->assertEquals('service', $type);
    }

    #[Test]
    public function it_detects_middleware_files(): void
    {
        $type = FileTypeDetector::detect('/app/Http/Middleware/AuthMiddleware.php');

        $this->assertEquals('middleware', $type);
    }

    #[Test]
    public function it_detects_provider_files(): void
    {
        $type = FileTypeDetector::detect('/app/Providers/AppServiceProvider.php');

        $this->assertEquals('provider', $type);
    }

    #[Test]
    public function it_detects_console_files(): void
    {
        $type = FileTypeDetector::detect('/app/Console/Commands/ProcessData.php');

        $this->assertEquals('console', $type);
    }

    #[Test]
    public function it_detects_job_files(): void
    {
        $type = FileTypeDetector::detect('/app/Jobs/SendEmail.php');

        $this->assertEquals('job', $type);
    }

    #[Test]
    public function it_detects_event_files(): void
    {
        $type = FileTypeDetector::detect('/app/Events/UserRegistered.php');

        $this->assertEquals('event', $type);
    }

    #[Test]
    public function it_detects_listener_files(): void
    {
        $type = FileTypeDetector::detect('/app/Listeners/SendWelcomeEmail.php');

        $this->assertEquals('listener', $type);
    }

    #[Test]
    public function it_detects_policy_files(): void
    {
        $type = FileTypeDetector::detect('/app/Policies/PostPolicy.php');

        $this->assertEquals('policy', $type);
    }

    #[Test]
    public function it_detects_route_files(): void
    {
        $type = FileTypeDetector::detect('/routes/web.php');

        $this->assertEquals('route', $type);
    }

    #[Test]
    public function it_detects_view_files(): void
    {
        $type = FileTypeDetector::detect('/resources/views/welcome.blade.php');

        $this->assertEquals('view', $type);
    }

    #[Test]
    public function it_detects_migration_files(): void
    {
        $type = FileTypeDetector::detect('/database/migrations/2024_01_01_000000_create_users_table.php');

        $this->assertEquals('migration', $type);
    }

    #[Test]
    public function it_detects_seeder_files(): void
    {
        $type = FileTypeDetector::detect('/database/seeders/DatabaseSeeder.php');

        $this->assertEquals('seeder', $type);
    }

    #[Test]
    public function it_detects_factory_files(): void
    {
        $type = FileTypeDetector::detect('/database/factories/UserFactory.php');

        $this->assertEquals('factory', $type);
    }

    #[Test]
    public function it_returns_application_for_unknown_paths(): void
    {
        $type = FileTypeDetector::detect('/app/SomeCustomClass.php');

        $this->assertEquals('application', $type);
    }

    #[Test]
    public function it_returns_application_for_root_app_files(): void
    {
        $type = FileTypeDetector::detect('/app/Helpers.php');

        $this->assertEquals('application', $type);
    }

    #[Test]
    public function it_checks_if_file_is_specific_type(): void
    {
        $this->assertTrue(FileTypeDetector::is('/app/Http/Controllers/HomeController.php', 'controller'));
        $this->assertFalse(FileTypeDetector::is('/app/Http/Controllers/HomeController.php', 'model'));
    }

    #[Test]
    public function it_returns_supported_types(): void
    {
        $types = FileTypeDetector::supportedTypes();

        $this->assertIsArray($types);
        $this->assertContains('controller', $types);
        $this->assertContains('model', $types);
        $this->assertContains('service', $types);
        $this->assertContains('middleware', $types);
        $this->assertContains('provider', $types);
        $this->assertContains('console', $types);
        $this->assertContains('job', $types);
        $this->assertContains('event', $types);
        $this->assertContains('listener', $types);
        $this->assertContains('policy', $types);
        $this->assertContains('route', $types);
        $this->assertContains('view', $types);
        $this->assertContains('migration', $types);
        $this->assertContains('seeder', $types);
        $this->assertContains('factory', $types);
    }

    #[Test]
    #[DataProvider('filePathProvider')]
    public function it_correctly_detects_type_for_various_paths(string $path, string $expectedType): void
    {
        $this->assertEquals($expectedType, FileTypeDetector::detect($path));
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function filePathProvider(): array
    {
        return [
            'nested_controller' => ['/app/Http/Controllers/Admin/UserController.php', 'controller'],
            'nested_model' => ['/app/Models/User/Profile.php', 'model'],
            'api_route' => ['/routes/api.php', 'route'],
            'partial_view' => ['/resources/views/partials/header.blade.php', 'view'],
            'kernel' => ['/app/Console/Kernel.php', 'console'],
            'form_request' => ['/app/Http/Middleware/TrustProxies.php', 'middleware'],
            'job_in_subdir' => ['/app/Jobs/Mail/SendNewsletter.php', 'job'],
            'config_file' => ['/config/app.php', 'application'],
            'bootstrap_file' => ['/bootstrap/app.php', 'application'],
            'tests_file' => ['/tests/Feature/ExampleTest.php', 'application'],
        ];
    }
}
