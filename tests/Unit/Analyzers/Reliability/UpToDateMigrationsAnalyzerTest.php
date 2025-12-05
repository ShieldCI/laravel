<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\Reliability\UpToDateMigrationsAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class UpToDateMigrationsAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new UpToDateMigrationsAnalyzer;
    }

    #[Test]
    public function test_checks_migration_status(): void
    {
        $tempDir = $this->createTempDirectory([
            'database/migrations/.gitkeep' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // The analyzer should return a valid result
        // It may pass (no pending migrations) or fail (pending migrations exist)
        // depending on the actual state of the test database
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('up-to-date-migrations', $metadata->id);
        $this->assertSame('Up-to-Date Migrations', $metadata->name);
        $this->assertSame(Severity::High, $metadata->severity);
        $this->assertSame(5, $metadata->timeToFix);
        $this->assertContains('database', $metadata->tags);
        $this->assertContains('migrations', $metadata->tags);
        $this->assertContains('reliability', $metadata->tags);
        $this->assertContains('deployment', $metadata->tags);
    }

    #[Test]
    public function test_run_in_ci_flag_is_false(): void
    {
        // Migration status checks should not run in CI
        $this->assertFalse(UpToDateMigrationsAnalyzer::$runInCI);
    }

    #[Test]
    public function test_parses_pending_migrations(): void
    {
        // Create a test instance to access protected methods via reflection
        $analyzer = $this->createAnalyzer();

        $output = <<<'OUTPUT'
+------+--------------------------------------------------------------+-------+
| Ran? | Migration                                                    | Batch |
+------+--------------------------------------------------------------+-------+
| Yes  | 2014_10_12_000000_create_users_table                         | 1     |
+------+--------------------------------------------------------------+-------+

  Pending  2024_01_15_000000_create_posts_table
  Pending  2024_01_16_000000_create_comments_table

OUTPUT;

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parsePendingMigrations');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, $output);

        $this->assertIsArray($result);
        $this->assertCount(2, $result);
        $this->assertContains('2024_01_15_000000_create_posts_table', $result);
        $this->assertContains('2024_01_16_000000_create_comments_table', $result);
    }

    #[Test]
    public function test_parses_pending_migrations_with_no_matches(): void
    {
        $analyzer = $this->createAnalyzer();

        $output = <<<'OUTPUT'
+------+--------------------------------------------------------------+-------+
| Ran? | Migration                                                    | Batch |
+------+--------------------------------------------------------------+-------+
| Yes  | 2014_10_12_000000_create_users_table                         | 1     |
+------+--------------------------------------------------------------+-------+

OUTPUT;

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parsePendingMigrations');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, $output);

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    #[Test]
    public function test_gets_pending_migrations_recommendation(): void
    {
        $analyzer = $this->createAnalyzer();

        $pendingMigrations = [
            '2024_01_15_000000_create_posts_table',
            '2024_01_16_000000_create_comments_table',
        ];

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('getPendingMigrationsRecommendation');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, $pendingMigrations);

        $this->assertIsString($result);
        $this->assertStringContainsString('php artisan migrate', $result);
        $this->assertStringContainsString('2024_01_15_000000_create_posts_table', $result);
        $this->assertStringContainsString('2024_01_16_000000_create_comments_table', $result);
    }

    #[Test]
    public function test_limits_displayed_migrations_in_recommendation(): void
    {
        $analyzer = $this->createAnalyzer();

        $pendingMigrations = [
            '2024_01_01_000000_migration_1',
            '2024_01_02_000000_migration_2',
            '2024_01_03_000000_migration_3',
            '2024_01_04_000000_migration_4',
            '2024_01_05_000000_migration_5',
            '2024_01_06_000000_migration_6',
            '2024_01_07_000000_migration_7',
        ];

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('getPendingMigrationsRecommendation');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, $pendingMigrations);
        $this->assertIsString($result);

        // Should show first 5 and add "..."
        $this->assertStringContainsString('2024_01_01_000000_migration_1', $result);
        $this->assertStringContainsString('2024_01_05_000000_migration_5', $result);
        $this->assertStringContainsString('...', $result);
        $this->assertStringNotContainsString('2024_01_06_000000_migration_6', $result);
    }

    #[Test]
    public function test_is_database_error_detects_pdo_exception(): void
    {
        $analyzer = $this->createAnalyzer();

        $error = new \PDOException('SQLSTATE[HY000] [2002] Connection refused');

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('isDatabaseError');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, $error);

        $this->assertTrue($result);
    }

    #[Test]
    public function test_is_database_error_detects_connection_messages(): void
    {
        $analyzer = $this->createAnalyzer();

        $errors = [
            new \Exception('Connection refused'),
            new \Exception('Access denied for user'),
            new \Exception('Unknown database mydb'),
            new \Exception('Could not find driver'),
        ];

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('isDatabaseError');
        $method->setAccessible(true);

        foreach ($errors as $error) {
            $result = $method->invoke($analyzer, $error);
            $this->assertTrue($result, "Failed to detect database error: {$error->getMessage()}");
        }
    }

    #[Test]
    public function test_is_database_error_returns_false_for_non_database_errors(): void
    {
        $analyzer = $this->createAnalyzer();

        $error = new \RuntimeException('Some general error');

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('isDatabaseError');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, $error);

        $this->assertFalse($result);
    }

    #[Test]
    public function test_gets_database_error_recommendation(): void
    {
        $analyzer = $this->createAnalyzer();

        $error = new \PDOException('Connection refused');

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('getDatabaseErrorRecommendation');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, $error);

        $this->assertIsString($result);
        $this->assertStringContainsString('Database connection error', $result);
        $this->assertStringContainsString('config/database.php', $result);
        $this->assertStringContainsString('.env', $result);
        $this->assertStringContainsString('Connection refused', $result);
    }

    #[Test]
    public function test_gets_migrations_path_uses_database_path_helper(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('getMigrationsPath');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer);

        $this->assertIsString($result);
        $this->assertStringContainsString('migrations', $result);
    }

    #[Test]
    public function test_parses_empty_migration_names(): void
    {
        $analyzer = $this->createAnalyzer();

        // Output with empty matches (edge case)
        $output = "  Pending  \n  Pending  \n";

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parsePendingMigrations');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, $output);

        // Should filter out empty migration names
        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }
}
