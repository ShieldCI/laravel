<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Console\Kernel as FoundationConsoleKernel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;
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

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        // Testbench's default connection differs across Laravel versions (MySQL on 9 and 10),
        // so pin an in-memory SQLite database for the migrations tables these tests create.
        /** @var Repository $config */
        $config = $app->make('config');
        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
    }

    /** @test */
    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('up-to-date-migrations', $metadata->id);
        $this->assertSame('Up-to-Date Migrations Analyzer', $metadata->name);
        $this->assertSame(Severity::High, $metadata->severity);
        $this->assertSame(5, $metadata->timeToFix);
        $this->assertContains('database', $metadata->tags);
        $this->assertContains('migrations', $metadata->tags);
        $this->assertContains('reliability', $metadata->tags);
        $this->assertContains('deployment', $metadata->tags);
    }

    /** @test */
    #[Test]
    public function test_run_in_ci_flag_is_false(): void
    {
        // Migration status checks should not run in CI
        $this->assertFalse(UpToDateMigrationsAnalyzer::$runInCI);
    }

    /** @test */
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

    /** @test */
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

    /** @test */
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

    /** @test */
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

    /** @test */
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

    /** @test */
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

    /** @test */
    #[Test]
    public function test_redacts_connection_credentials_from_the_database_error_recommendation(): void
    {
        // A PDO failure names the user and host it failed against, and this recommendation
        // quotes the message back verbatim.
        $analyzer = $this->createAnalyzer();

        $error = new \PDOException('Access denied for user "deploy"@"10.0.0.5" password=hunter2pass');

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('getDatabaseErrorRecommendation');
        $method->setAccessible(true);

        $result = $method->invoke($analyzer, $error);

        $this->assertIsString($result);
        $this->assertStringNotContainsString('hunter2pass', $result);
        $this->assertStringNotContainsString('10.0.0.5', $result);
        $this->assertStringContainsString('Access denied', $result);

        // Classification reads the raw message, so it must still recognise this as a database
        // error even though what gets emitted is redacted.
        $isDatabaseError = $reflection->getMethod('isDatabaseError');
        $isDatabaseError->setAccessible(true);
        $this->assertTrue($isDatabaseError->invoke($analyzer, $error));
    }

    /** @test */
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

    /** @test */
    #[Test]
    public function test_passes_when_every_migration_has_run(): void
    {
        $this->createMigrationsTable('migrations');
        $this->recordRan('migrations', '2023_03_01_000000_create_widgets_table');
        $this->registerMigrationDirectory(['2023_03_01_000000_create_widgets_table']);

        $result = $this->createAnalyzer()->analyze();

        $this->assertPassed($result);
        $this->assertSame('All migrations are up to date', $result->getMessage());
    }

    /** @test */
    #[Test]
    public function test_reports_a_pending_migration_and_not_the_ones_that_ran(): void
    {
        $this->createMigrationsTable('migrations');
        $this->recordRan('migrations', '2023_03_01_000000_create_widgets_table');
        $this->registerMigrationDirectory([
            '2023_03_01_000000_create_widgets_table',
            '2023_04_01_000000_create_gadgets_table',
        ]);

        $result = $this->createAnalyzer()->analyze();

        $this->assertFailed($result);
        $this->assertSame('Found 1 pending migration(s)', $result->getMessage());
        $this->assertIssueCount(1, $result);

        $issue = $result->getIssues()[0];
        $this->assertSame('Pending migrations detected', $issue->message);
        $this->assertSame('pending-migrations', $issue->metadata['code']);
        $this->assertSame(1, $issue->metadata['pending_count']);
        $this->assertSame(['2023_04_01_000000_create_gadgets_table'], $issue->metadata['pending_migrations']);
    }

    /** @test */
    #[Test]
    public function test_lists_pending_migrations_from_every_path_in_name_order(): void
    {
        $this->createMigrationsTable('migrations');

        // The application's own database/migrations directory is scanned alongside the
        // paths packages register on the migrator, as migrate:status does.
        $databasePath = $this->makeTempDirectory();
        mkdir($databasePath.'/migrations');
        file_put_contents($databasePath.'/migrations/2023_06_01_000000_create_sprockets_table.php', $this->migrationStub());
        $app = $this->app;
        $this->assertNotNull($app);
        $app->useDatabasePath($databasePath);

        $this->registerMigrationDirectory(['2023_05_01_000000_create_cogs_table']);

        $result = $this->createAnalyzer()->analyze();

        $this->assertFailed($result);
        $this->assertSame('Found 2 pending migration(s)', $result->getMessage());
        $this->assertSame(
            ['2023_05_01_000000_create_cogs_table', '2023_06_01_000000_create_sprockets_table'],
            $result->getIssues()[0]->metadata['pending_migrations']
        );
    }

    /** @test */
    #[Test]
    public function test_passes_a_fully_migrated_app_whose_migrate_status_has_no_pending_option(): void
    {
        // Laravel 9.0's migrate:status declares no --pending option.
        $this->registerLegacyStatusCommand();
        $this->createMigrationsTable('migrations');
        $this->recordRan('migrations', '2023_03_01_000000_create_widgets_table');
        $this->registerMigrationDirectory(['2023_03_01_000000_create_widgets_table']);

        $result = $this->createAnalyzer()->analyze();

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_reports_pending_migrations_when_migrate_status_has_no_pending_option(): void
    {
        $this->registerLegacyStatusCommand();
        $this->createMigrationsTable('migrations');
        $this->recordRan('migrations', '2023_03_01_000000_create_widgets_table');
        $this->registerMigrationDirectory([
            '2023_03_01_000000_create_widgets_table',
            '2023_04_01_000000_create_gadgets_table',
        ]);

        $result = $this->createAnalyzer()->analyze();

        $this->assertFailed($result);
        $this->assertSame('pending-migrations', $result->getIssues()[0]->metadata['code']);
        $this->assertSame(['2023_04_01_000000_create_gadgets_table'], $result->getIssues()[0]->metadata['pending_migrations']);
    }

    /** @test */
    #[Test]
    public function test_matches_a_digit_only_migration_name_against_the_ran_list(): void
    {
        // A digit-only name becomes an integer array key, but the repository records it as a
        // string; migrate:status treats it as ran.
        $this->createMigrationsTable('migrations');
        $this->recordRan('migrations', '20230101000000');

        $dir = $this->makeTempDirectory();
        file_put_contents($dir.'/20230101000000.php', $this->migrationStub());
        $migrator = app('migrator');
        $this->assertInstanceOf(Migrator::class, $migrator);
        $migrator->path($dir.'/20230101000000.php');

        $result = $this->createAnalyzer()->analyze();

        $this->assertPassed($result);
    }

    /** @test */
    #[Test]
    public function test_reports_a_migrator_that_fails_to_resolve_instead_of_skipping(): void
    {
        $this->createMigrationsTable('migrations');
        $app = $this->app;
        $this->assertNotNull($app);
        $app->singleton('migrator', fn () => throw new \RuntimeException('provider misconfigured'));

        $result = $this->createAnalyzer()->analyze();

        $this->assertFailed($result);
        $this->assertSame('Unable to check migration status', $result->getMessage());
        $this->assertSame('migration-check-error', $result->getIssues()[0]->metadata['code']);
        $this->assertHasIssueContaining('provider misconfigured', $result);
    }

    /** @test */
    #[Test]
    public function test_reports_a_migrator_binding_of_the_wrong_type_instead_of_skipping(): void
    {
        $app = $this->app;
        $this->assertNotNull($app);
        $app->singleton('migrator', fn () => new \stdClass);

        $result = $this->createAnalyzer()->analyze();

        $this->assertFailed($result);
        $this->assertSame('Unable to check migration status', $result->getMessage());
        $this->assertHasIssueContaining('stdClass', $result);
    }

    /** @test */
    #[Test]
    public function test_skips_when_no_migrator_is_bound(): void
    {
        $app = $this->app;
        $this->assertNotNull($app);
        $app->offsetUnset('migrator');

        $analyzer = $this->createAnalyzer();

        $this->assertFalse($analyzer->shouldRun());
        $this->assertSkipped($analyzer->analyze());
        $this->assertSame('Laravel migrator not available. Ensure Laravel is properly bootstrapped.', $analyzer->getSkipReason());
    }

    /**
     * @dataProvider renamedMigrationsTableConfigProvider
     */
    #[Test]
    #[DataProvider('renamedMigrationsTableConfigProvider')]
    public function test_passes_with_a_renamed_migrations_table(mixed $migrationsConfig): void
    {
        config(['database.migrations' => $migrationsConfig]);
        $this->createMigrationsTable('ledger_migrations');
        $this->recordRan('ledger_migrations', '2023_03_01_000000_create_widgets_table');
        $this->registerMigrationDirectory(['2023_03_01_000000_create_widgets_table']);

        $result = $this->createAnalyzer()->analyze();

        $this->assertPassed($result);
    }

    /**
     * @dataProvider renamedMigrationsTableConfigProvider
     */
    #[Test]
    #[DataProvider('renamedMigrationsTableConfigProvider')]
    public function test_reports_a_missing_renamed_migrations_table_by_its_configured_name(mixed $migrationsConfig): void
    {
        config(['database.migrations' => $migrationsConfig]);

        // A table under the default name does not stand in for the configured one.
        $this->createMigrationsTable('migrations');

        $result = $this->createAnalyzer()->analyze();

        $this->assertFailed($result);
        $this->assertSame('Migrations table does not exist', $result->getMessage());
        $issue = $result->getIssues()[0];
        $this->assertSame('migrations-table-missing', $issue->metadata['code']);
        $this->assertSame('ledger_migrations', $issue->metadata['table']);
    }

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function renamedMigrationsTableConfigProvider(): array
    {
        return [
            'string form' => ['ledger_migrations'],
            'array form' => [['table' => 'ledger_migrations', 'update_date_on_publish' => true]],
        ];
    }

    /** @test */
    #[Test]
    public function test_detects_missing_migrations_table(): void
    {
        $result = $this->createAnalyzer()->analyze();

        $this->assertFailed($result);
        $this->assertSame('Migrations table does not exist', $result->getMessage());
        $this->assertIssueCount(1, $result);

        $issue = $result->getIssues()[0];
        $this->assertSame('The migrations table has not been created yet', $issue->message);
        $this->assertStringContainsString('migrate:install', $issue->recommendation);
        $this->assertSame('migrations', $issue->metadata['table']);
        $this->assertSame('migrations-table-missing', $issue->metadata['code']);
    }

    private function createMigrationsTable(string $table): void
    {
        Schema::create($table, function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('migration');
            $blueprint->integer('batch');
        });
    }

    private function recordRan(string $table, string $migration): void
    {
        DB::table($table)->insert(['migration' => $migration, 'batch' => 1]);
    }

    /**
     * Register a directory of migration files on the migrator, as a package's
     * loadMigrationsFrom() does.
     *
     * @param  list<string>  $names
     */
    private function registerMigrationDirectory(array $names): void
    {
        $dir = $this->makeTempDirectory();

        foreach ($names as $name) {
            file_put_contents($dir.'/'.$name.'.php', $this->migrationStub());
        }

        $migrator = app('migrator');
        $this->assertInstanceOf(Migrator::class, $migrator);
        $migrator->path($dir);
    }

    private function migrationStub(): string
    {
        return "<?php\n\nreturn new class extends \\Illuminate\\Database\\Migrations\\Migration\n{\n    public function up(): void {}\n};\n";
    }

    /**
     * Replace migrate:status with Laravel 9.0's shape: no --pending option, and a
     * Ran?/Migration/Batch table in which the word "Pending" never appears.
     */
    private function registerLegacyStatusCommand(): void
    {
        $kernel = app(ConsoleKernel::class);
        $this->assertInstanceOf(FoundationConsoleKernel::class, $kernel);

        $kernel->registerCommand(new class extends Command
        {
            /** @var string */
            protected $signature = 'migrate:status {--database=} {--path=*} {--realpath}';

            /** @var string */
            protected $description = 'Show the status of each migration';

            public function handle(): int
            {
                $this->table(['Ran?', 'Migration', 'Batch'], [
                    ['Yes', '2023_03_01_000000_create_widgets_table', '1'],
                    ['No', '2023_04_01_000000_create_gadgets_table', ''],
                ]);

                return 0;
            }
        });
    }
}
