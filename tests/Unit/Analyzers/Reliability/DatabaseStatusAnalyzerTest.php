<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Illuminate\Contracts\Config\Repository as Config;
use Mockery;
use Mockery\MockInterface;
use ShieldCI\Analyzers\Reliability\DatabaseStatusAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Support\DatabaseConnectionChecker;
use ShieldCI\Support\DatabaseConnectionResult;
use ShieldCI\Tests\AnalyzerTestCase;

class DatabaseStatusAnalyzerTest extends AnalyzerTestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('shieldci.analyzers.reliability.database-status.connections', []);

        parent::tearDown();
    }

    protected function createAnalyzer(null|DatabaseConnectionChecker|MockInterface $checker = null): AnalyzerInterface
    {
        if ($checker === null) {
            $checker = new DatabaseConnectionChecker(app('db'));
        }

        if (! $checker instanceof DatabaseConnectionChecker) {
            $this->fail('Database connection checker mock must extend '.DatabaseConnectionChecker::class);
        }

        return new DatabaseStatusAnalyzer($checker);
    }

    public function test_passes_when_connection_succeeds(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(true));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_connection_returns_null_pdo(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Connection returned null PDO instance.'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('null PDO', $result);
    }

    public function test_fails_when_connection_throws_exception(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Connection refused', 'PDOException'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Connection refused', $result);
    }

    public function test_warns_when_default_connection_not_set(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('database.default', null);

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldNotReceive('check');

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertSame('Unable to determine default database connection', $result->getMessage());
    }

    public function test_limits_error_message_length_in_recommendation(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $longMessage = str_repeat('A', 300);

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, $longMessage));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issue = $result->getIssues()[0];
        $this->assertStringNotContainsString($longMessage, $issue->recommendation);
        $this->assertStringContainsString(str_repeat('A', 200).'...', $issue->recommendation);
    }

    public function test_checks_configured_connections_from_shieldci_config(): void
    {
        $connections = [
            'sqlite' => [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
                'foreign_key_constraints' => true,
            ],
        ];

        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig($connections),
        ]);

        $this->applyDatabaseConfig($connections);
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('shieldci.analyzers.reliability.database-status.connections', ['sqlite']);

        $checker = Mockery::mock(DatabaseConnectionChecker::class);

        /** @var Mockery\ExpectationInterface $mysqlExpectation */
        /** @phpstan-ignore-next-line Mockery expectation chaining */
        $mysqlExpectation = $checker->shouldReceive('check')->with('mysql');
        $mysqlExpectation->andReturn(new DatabaseConnectionResult(false, 'Connection refused', 'PDOException'));

        /** @var Mockery\ExpectationInterface $sqliteExpectation */
        /** @phpstan-ignore-next-line Mockery expectation chaining */
        $sqliteExpectation = $checker->shouldReceive('check')->with('sqlite');
        $sqliteExpectation->andReturn(new DatabaseConnectionResult(false, 'Access denied', 'PDOException'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(2, $result);

        $issues = $result->getIssues();
        $this->assertSame('mysql', $issues[0]->metadata['connection']);
        $this->assertSame('sqlite', $issues[1]->metadata['connection']);
    }

    // =========================================================================
    // Connection String Format Tests
    // =========================================================================

    public function test_handles_comma_separated_connection_string(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('shieldci.analyzers.reliability.database-status.connections', 'mysql,sqlite');

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        /** @phpstan-ignore-next-line */
        $checker->shouldReceive('check')->with('mysql')->andReturn(new DatabaseConnectionResult(true));
        /** @phpstan-ignore-next-line */
        $checker->shouldReceive('check')->with('sqlite')->andReturn(new DatabaseConnectionResult(true));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_array_with_non_string_values(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('shieldci.analyzers.reliability.database-status.connections', ['mysql', null, 123, '', 'valid']);

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        /** @phpstan-ignore-next-line */
        $checker->shouldReceive('check')->with('mysql')->times(1)->andReturn(new DatabaseConnectionResult(true));
        /** @phpstan-ignore-next-line */
        $checker->shouldReceive('check')->with('valid')->times(1)->andReturn(new DatabaseConnectionResult(true));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_array_with_whitespace(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('shieldci.analyzers.reliability.database-status.connections', 'mysql , sqlite ');

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        /** @phpstan-ignore-next-line */
        $checker->shouldReceive('check')->with('mysql')->andReturn(new DatabaseConnectionResult(true));
        /** @phpstan-ignore-next-line */
        $checker->shouldReceive('check')->with('sqlite')->andReturn(new DatabaseConnectionResult(true));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // Error-Specific Recommendation Tests
    // =========================================================================

    public function test_access_denied_error_recommendation(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Access denied for user'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('username and password', $issues[0]->recommendation);
    }

    public function test_connection_refused_error_recommendation(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Connection refused'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('database server is running', $issues[0]->recommendation);
        $this->assertStringContainsString('pdo_mysql', $issues[0]->recommendation);
    }

    public function test_unknown_database_error_recommendation(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Unknown database'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('database does not exist', $issues[0]->recommendation);
    }

    public function test_generic_error_fallback_recommendation(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Some other error'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('Common issues:', $issues[0]->recommendation);
    }

    // =========================================================================
    // Metadata Validation Tests
    // =========================================================================

    public function test_includes_driver_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Connection failed'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertArrayHasKey('driver', $issues[0]->metadata);
        $this->assertSame('mysql', $issues[0]->metadata['driver']);
    }

    public function test_does_not_expose_host_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Connection failed'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Host should not be exposed to prevent infrastructure disclosure
        $this->assertArrayNotHasKey('host', $issues[0]->metadata);
    }

    public function test_does_not_expose_database_name_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Connection failed'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Database name should not be exposed to prevent infrastructure disclosure
        $this->assertArrayNotHasKey('database', $issues[0]->metadata);
    }

    public function test_includes_exception_class_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Connection failed', 'PDOException'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertArrayHasKey('exception', $issues[0]->metadata);
        $this->assertSame('PDOException', $issues[0]->metadata['exception']);
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    public function test_handles_missing_config_file(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Connection failed'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should not crash despite missing config file
    }

    public function test_deduplicates_connection_names(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();
        // Default is 'mysql', and we configure 'mysql' again
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('shieldci.analyzers.reliability.database-status.connections', ['mysql']);

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        // Should only be called once for mysql (deduplicated)
        /** @phpstan-ignore-next-line */
        $checker->shouldReceive('check')->with('mysql')->once()->andReturn(new DatabaseConnectionResult(true));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // PHP Extension Mapping Tests
    // =========================================================================

    public function test_maps_mysql_driver_to_pdo_mysql_extension(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'could not find driver'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('pdo_mysql PHP extension', $issues[0]->recommendation);
    }

    public function test_maps_pgsql_driver_to_pdo_pgsql_extension(): void
    {
        $connections = [
            'pgsql' => [
                'driver' => 'pgsql',
                'host' => '127.0.0.1',
                'database' => 'test',
            ],
        ];

        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig($connections),
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('database.default', 'pgsql');
        $config->set('database.connections', $connections);

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'could not find driver'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('pdo_pgsql PHP extension', $issues[0]->recommendation);
    }

    public function test_maps_sqlsrv_driver_to_pdo_sqlsrv_extension(): void
    {
        $connections = [
            'sqlsrv' => [
                'driver' => 'sqlsrv',
                'host' => '127.0.0.1',
                'database' => 'test',
            ],
        ];

        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig($connections),
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('database.default', 'sqlsrv');
        $config->set('database.connections', $connections);

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'could not find driver'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('pdo_sqlsrv PHP extension', $issues[0]->recommendation);
    }

    public function test_maps_sqlite_driver_to_pdo_sqlite_extension(): void
    {
        $connections = [
            'sqlite' => [
                'driver' => 'sqlite',
                'database' => ':memory:',
            ],
        ];

        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig($connections),
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('database.default', 'sqlite');
        $config->set('database.connections', $connections);

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'could not find driver'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('pdo_sqlite PHP extension', $issues[0]->recommendation);
    }

    public function test_defaults_to_pdo_for_unknown_driver(): void
    {
        $connections = [
            'custom' => [
                'driver' => 'custom',
                'host' => '127.0.0.1',
            ],
        ];

        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig($connections),
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('database.default', 'custom');
        $config->set('database.connections', $connections);

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'could not find driver'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('PDO PHP extension', $issues[0]->recommendation);
    }

    // =========================================================================
    // Exception Class Detection Tests
    // =========================================================================

    public function test_doctrine_driver_exception_is_persistent(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        // Doctrine DriverException with connection refused message
        $checker->shouldReceive('check')->andReturn(
            new DatabaseConnectionResult(false, 'Connection refused', 'Doctrine\DBAL\Exception\DriverException')
        );

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Should be persistent (Critical) even though message says "Connection refused"
        $this->assertSame('critical', $issues[0]->severity->value);
    }

    public function test_pdoexception_with_access_denied_is_persistent(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        // PDOException with access denied (persistent error)
        $checker->shouldReceive('check')->andReturn(
            new DatabaseConnectionResult(false, 'Access denied for user', 'PDOException')
        );

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Should be persistent (Critical)
        $this->assertSame('critical', $issues[0]->severity->value);
    }

    public function test_pdoexception_with_connection_refused_is_transient(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        // PDOException with connection refused (transient error)
        $checker->shouldReceive('check')->andReturn(
            new DatabaseConnectionResult(false, 'Connection refused', 'PDOException')
        );

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Should be transient (High)
        $this->assertSame('high', $issues[0]->severity->value);
    }

    public function test_null_exception_class_falls_back_to_message_parsing(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        // No exception class, transient message
        $checker->shouldReceive('check')->andReturn(
            new DatabaseConnectionResult(false, 'Connection timed out', null)
        );

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Should detect as transient from message
        $this->assertSame('high', $issues[0]->severity->value);
    }

    public function test_unknown_database_is_persistent_regardless_of_exception(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        // Generic exception but persistent error message
        $checker->shouldReceive('check')->andReturn(
            new DatabaseConnectionResult(false, 'Unknown database "test_db"', 'PDOException')
        );

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Should be persistent (Critical)
        $this->assertSame('critical', $issues[0]->severity->value);
    }

    public function test_could_not_find_driver_is_persistent(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        // Driver missing is a persistent issue
        $checker->shouldReceive('check')->andReturn(
            new DatabaseConnectionResult(false, 'could not find driver', 'PDOException')
        );

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Should be persistent (Critical)
        $this->assertSame('critical', $issues[0]->severity->value);
    }

    // =========================================================================
    // Dynamic Severity Tests
    // =========================================================================

    public function test_default_connection_persistent_error_is_critical(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        // Persistent error: Access denied
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Access denied for user'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertSame('critical', $issues[0]->severity->value);
        $this->assertTrue($issues[0]->metadata['is_default']);
    }

    public function test_default_connection_transient_error_is_high(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig(),
        ]);

        $this->applyDatabaseConfig();

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        // Transient error: Connection refused
        $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, 'Connection refused'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertSame('high', $issues[0]->severity->value);
        $this->assertTrue($issues[0]->metadata['is_default']);
    }

    public function test_non_default_connection_persistent_error_is_high(): void
    {
        $connections = [
            'sqlite' => [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
                'foreign_key_constraints' => true,
            ],
        ];

        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig($connections),
        ]);

        $this->applyDatabaseConfig($connections);
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('shieldci.analyzers.reliability.database-status.connections', ['sqlite']);

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        /** @phpstan-ignore-next-line */
        $checker->shouldReceive('check')->with('mysql')->andReturn(new DatabaseConnectionResult(true));
        // Persistent error on non-default connection
        /** @phpstan-ignore-next-line */
        $checker->shouldReceive('check')->with('sqlite')->andReturn(new DatabaseConnectionResult(false, 'Unknown database'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('high', $issues[0]->severity->value);
        $this->assertFalse($issues[0]->metadata['is_default']);
    }

    public function test_non_default_connection_transient_error_is_medium(): void
    {
        $connections = [
            'sqlite' => [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
                'foreign_key_constraints' => true,
            ],
        ];

        $tempDir = $this->createTempDirectory([
            'config/database.php' => $this->databaseConfig($connections),
        ]);

        $this->applyDatabaseConfig($connections);
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('shieldci.analyzers.reliability.database-status.connections', ['sqlite']);

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        /** @phpstan-ignore-next-line */
        $checker->shouldReceive('check')->with('mysql')->andReturn(new DatabaseConnectionResult(true));
        // Transient error on non-default connection
        /** @phpstan-ignore-next-line */
        $checker->shouldReceive('check')->with('sqlite')->andReturn(new DatabaseConnectionResult(false, 'Connection timed out'));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame('medium', $issues[0]->severity->value);
        $this->assertFalse($issues[0]->metadata['is_default']);
    }

    public function test_recognizes_various_transient_error_patterns(): void
    {
        $transientErrors = [
            'Connection refused',
            'Connection timed out',
            'Timeout occurred',
            'Network is unreachable',
            'No route to host',
            'Temporary failure in name resolution',
            'Name or service not known',
        ];

        foreach ($transientErrors as $errorMessage) {
            $tempDir = $this->createTempDirectory([
                'config/database.php' => $this->databaseConfig(),
            ]);

            $this->applyDatabaseConfig();

            $checker = Mockery::mock(DatabaseConnectionChecker::class);
            $checker->shouldReceive('check')->andReturn(new DatabaseConnectionResult(false, $errorMessage));

            $analyzer = $this->createAnalyzer($checker);
            $analyzer->setBasePath($tempDir);

            $result = $analyzer->analyze();

            $this->assertFailed($result);
            $issues = $result->getIssues();
            $this->assertSame('high', $issues[0]->severity->value, "Failed for error: {$errorMessage}");
        }
    }

    /**
     * @param  array<string, array<string, mixed>>  $additionalConnections
     */
    private function databaseConfig(array $additionalConnections = []): string
    {
        $connections = array_merge($this->defaultConnections(), $additionalConnections);
        $connectionBlocks = array_map(
            fn (string $name, array $config) => $this->exportConnectionBlock($name, $config),
            array_keys($connections),
            $connections
        );

        $connectionsString = implode("\n", $connectionBlocks)."\n";

        return <<<PHP
<?php

return [
    'default' => 'mysql',
    'connections' => [
{$connectionsString}
    ],
];
PHP;
    }

    /**
     * @param  array<string, array<string, mixed>>  $additionalConnections
     */
    private function applyDatabaseConfig(array $additionalConnections = []): void
    {
        $connections = array_merge($this->defaultConnections(), $additionalConnections);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('database.default', 'mysql');
        $config->set('database.connections', $connections);
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function defaultConnections(): array
    {
        return [
            'mysql' => [
                'driver' => 'mysql',
                'host' => '127.0.0.1',
                'port' => '3306',
                'database' => 'test',
                'username' => 'root',
                'password' => '',
            ],
        ];
    }

    /**
     * Build one connection block for the generated config file.
     *
     * @param  array<string, mixed>  $config
     */
    private function exportConnectionBlock(string $name, array $config): string
    {
        $lines = ["        '{$name}' => ["];

        foreach ($config as $key => $value) {
            if (is_bool($value)) {
                $valueString = $value ? 'true' : 'false';
            } else {
                $valueString = "'{$value}'";
            }

            $lines[] = "            '{$key}' => {$valueString},";
        }

        $lines[] = '        ],';

        return implode("\n", $lines);
    }
}
