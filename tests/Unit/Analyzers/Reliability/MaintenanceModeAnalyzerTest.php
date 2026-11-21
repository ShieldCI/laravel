<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\Reliability\MaintenanceModeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class MaintenanceModeAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MaintenanceModeAnalyzer($this->application());
    }

    private function application(): Application
    {
        $app = $this->app;
        $this->assertNotNull($app);

        return $app;
    }

    /**
     * An analyzer pointed at the application running the test, in production, which is the
     * shape of a real shield:analyze run: AnalyzerManager sets the base path to base_path().
     */
    private function runningAppAnalyzer(): MaintenanceModeAnalyzer
    {
        $app = $this->application();
        $app['config']->set('app.env', 'production');

        $analyzer = new MaintenanceModeAnalyzer($app);
        $analyzer->setBasePath($app->basePath());

        return $analyzer;
    }

    /** @test */
    #[Test]
    public function it_passes_when_not_in_maintenance_mode(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/.gitkeep' => '',
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('Application is not in maintenance mode', $result->getMessage());
        $this->assertEmpty($result->getIssues());
    }

    /** @test */
    #[Test]
    public function it_fails_when_maintenance_file_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => '',
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Application is in maintenance mode', $result->getMessage());

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $issue = $issues[0];
        $this->assertStringContainsString('maintenance', strtolower($issue->message));
        $this->assertSame(Severity::High, $issue->severity);
        $this->assertStringContainsString('php artisan up', $issue->recommendation);
    }

    /** @test */
    #[Test]
    public function it_fails_when_maintenance_file_contains_json(): void
    {
        $maintenanceData = json_encode([
            'time' => time(),
            'retry' => 60,
            'refresh' => 60,
            'secret' => 'test-secret',
        ], JSON_PRETTY_PRINT);

        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => $maintenanceData,
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertStringContainsString('Application is in maintenance mode', $result->getMessage());
        $this->assertCount(1, $result->getIssues());
    }

    /** @test */
    #[Test]
    public function it_includes_maintenance_file_path_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => '',
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $issue = $issues[0];
        $metadata = $issue->metadata;

        $this->assertTrue($metadata['is_down']);
        $this->assertIsString($metadata['maintenance_file']);
        $this->assertStringContainsString('storage/framework/down', $metadata['maintenance_file']);
        $this->assertArrayHasKey('environment', $metadata);
        $this->assertSame('production', $metadata['environment']);
    }

    /** @test */
    #[Test]
    public function it_includes_proper_recommendation(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => '',
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $issue = $issues[0];
        $recommendation = $issue->recommendation;

        $this->assertStringContainsString('php artisan up', $recommendation);
        $this->assertStringContainsString('maintenance is complete', $recommendation);
        $this->assertStringContainsString('users are properly notified', $recommendation);
    }

    /** @test */
    #[Test]
    public function it_sets_correct_location_for_maintenance_file(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => '',
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $issue = $issues[0];

        $this->assertNull($issue->location);
        $this->assertEquals('storage/framework/down', $issue->metadata['detected_via']);
    }

    /** @test */
    #[Test]
    public function it_does_not_include_code_snippet(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => '',
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $issue = $issues[0];

        // No issue type code for maintenance mode issues
        $this->assertArrayNotHasKey('code', $issue->metadata);
    }

    /** @test */
    #[Test]
    public function it_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('maintenance-mode-status', $metadata->id);
        $this->assertSame('Maintenance Mode Status Analyzer', $metadata->name);
        $this->assertSame(Severity::High, $metadata->severity);
        $this->assertSame(5, $metadata->timeToFix);
        $this->assertContains('maintenance', $metadata->tags);
        $this->assertContains('availability', $metadata->tags);
        $this->assertContains('reliability', $metadata->tags);
        $this->assertContains('downtime', $metadata->tags);
    }

    /** @test */
    #[Test]
    public function it_handles_multiple_checks_consistently(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => '',
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        // Run analysis multiple times
        $result1 = $analyzer->analyze();
        $result2 = $analyzer->analyze();

        // Results should be consistent
        $this->assertFailed($result1);
        $this->assertFailed($result2);
        $this->assertSame($result1->getMessage(), $result2->getMessage());
    }

    // =========================================================================
    // Environment Relevance Tests
    // =========================================================================

    /** @test */
    #[Test]
    public function it_runs_in_production_environment(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => '',
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $issue = $issues[0];

        // Production should get High severity - users affected
        $this->assertSame(Severity::High, $issue->severity);
        $this->assertSame('production', $issue->metadata['environment']);
        $this->assertStringContainsString('users are affected', $issue->message);
        $this->assertStringContainsString('affects real users', $issue->recommendation);
    }

    /** @test */
    #[Test]
    public function it_runs_in_staging_environment(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => '',
            '.env' => 'APP_ENV=staging',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $issue = $issues[0];

        // Staging should get High severity - users affected
        $this->assertSame(Severity::High, $issue->severity);
        $this->assertSame('staging', $issue->metadata['environment']);
        $this->assertStringContainsString('users are affected', $issue->message);
    }

    /** @test */
    #[Test]
    public function it_skips_in_development_environment(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => '',
            '.env' => 'APP_ENV=development',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString("Not relevant in 'development' environment", $analyzer->getSkipReason());
        $this->assertStringContainsString('production, staging', $analyzer->getSkipReason());
    }

    /** @test */
    #[Test]
    public function it_skips_in_local_environment(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => '',
            '.env' => 'APP_ENV=local',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString("Not relevant in 'local' environment", $analyzer->getSkipReason());
    }

    /** @test */
    #[Test]
    public function it_skips_in_testing_environment(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => '',
            '.env' => 'APP_ENV=testing',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString("Not relevant in 'testing' environment", $analyzer->getSkipReason());
    }

    /** @test */
    #[Test]
    public function it_includes_production_language_in_recommendations(): void
    {
        $tempDir = $this->createTempDirectory([
            'storage/framework/down' => '',
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $result = $analyzer->analyze();
        $recommendation = $result->getIssues()[0]->recommendation;

        // Should have urgent, production-focused language
        $this->assertStringContainsString('immediately', $recommendation);
        $this->assertStringContainsString('affects real users', $recommendation);
        $this->assertStringContainsString('php artisan up', $recommendation);
    }

    // =========================================================================
    // Running Application Tests
    // =========================================================================

    /** @test */
    #[Test]
    public function it_passes_when_the_running_application_is_up(): void
    {
        $app = $this->application();
        $this->assertFileDoesNotExist($app->storagePath().'/framework/down');

        $result = $this->runningAppAnalyzer()->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('Application is not in maintenance mode', $result->getMessage());
    }

    /** @test */
    #[Test]
    public function it_fails_when_the_cache_driver_reports_maintenance_mode(): void
    {
        $app = $this->application();
        $app['config']->set('app.maintenance.driver', 'cache');
        $app['config']->set('app.maintenance.store', 'array');

        $app->maintenanceMode()->activate([]);

        try {
            $result = $this->runningAppAnalyzer()->analyze();
        } finally {
            $app->maintenanceMode()->deactivate();
        }

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());

        $issue = $result->getIssues()[0];
        $this->assertSame('Application is in maintenance mode in production environment - users are affected', $issue->message);
        $this->assertSame(Severity::High, $issue->severity);
        $this->assertSame('cache', $issue->metadata['detected_via']);
        $this->assertArrayNotHasKey('maintenance_file', $issue->metadata);
    }

    /** @test */
    #[Test]
    public function it_fails_when_relocated_storage_holds_the_down_file(): void
    {
        $app = $this->application();
        $originalStoragePath = $app->storagePath();

        $storage = $this->makeTempDirectory();
        @mkdir($storage.'/framework', 0755, true);
        file_put_contents($storage.'/framework/down', '{}');

        $app->useStoragePath($storage);

        try {
            $result = $this->runningAppAnalyzer()->analyze();
        } finally {
            $app->useStoragePath($originalStoragePath);
        }

        $this->assertFailed($result);

        $issue = $result->getIssues()[0];
        $this->assertSame('storage/framework/down', $issue->metadata['detected_via']);
        $this->assertSame($storage.DIRECTORY_SEPARATOR.'framework'.DIRECTORY_SEPARATOR.'down', $issue->metadata['maintenance_file']);
    }

    /** @test */
    #[Test]
    public function it_warns_when_maintenance_status_cannot_be_determined(): void
    {
        $app = $this->application();
        $app['config']->set('app.maintenance.driver', 'cache');
        $app['config']->set('app.maintenance.store', 'shieldci-undefined-store');

        $result = $this->runningAppAnalyzer()->analyze();

        $this->assertWarning($result);
        $this->assertCount(1, $result->getIssues());

        $issue = $result->getIssues()[0];
        $this->assertSame(Severity::Medium, $issue->severity);
        $this->assertSame('Maintenance mode status could not be determined in production environment', $issue->message);
        $this->assertStringContainsString('shieldci-undefined-store', $issue->recommendation);
        $this->assertIsString($issue->metadata['error']);
        $this->assertStringContainsString('shieldci-undefined-store', $issue->metadata['error']);
        $this->assertSame('cache', $issue->metadata['detected_via']);
    }

    /** @test */
    #[Test]
    public function it_reads_the_analyzed_directory_when_it_is_not_the_running_application(): void
    {
        $app = $this->application();
        $app['config']->set('app.maintenance.driver', 'cache');
        $app['config']->set('app.maintenance.store', 'array');

        $tempDir = $this->createTempDirectory([
            'storage/framework/.gitkeep' => '',
            '.env' => 'APP_ENV=production',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $app->maintenanceMode()->activate([]);

        try {
            $result = $analyzer->analyze();
        } finally {
            $app->maintenanceMode()->deactivate();
        }

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function it_does_not_run_in_ci(): void
    {
        $this->assertFalse(MaintenanceModeAnalyzer::$runInCI);
    }
}
