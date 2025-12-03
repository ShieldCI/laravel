<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

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
        config()->set('shieldci.database.connections', []);

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

        config()->set('database.default', null);

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
        config()->set('shieldci.database.connections', ['sqlite']);

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
        config()->set('shieldci.database.connections', 'mysql,sqlite');

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
        config()->set('shieldci.database.connections', ['mysql', null, 123, '', 'valid']);

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
        config()->set('shieldci.database.connections', 'mysql , sqlite ');

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

    public function test_includes_host_in_metadata(): void
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
        $this->assertArrayHasKey('host', $issues[0]->metadata);
        $this->assertSame('127.0.0.1', $issues[0]->metadata['host']);
    }

    public function test_includes_database_name_in_metadata(): void
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
        $this->assertArrayHasKey('database', $issues[0]->metadata);
        $this->assertSame('test', $issues[0]->metadata['database']);
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
        config()->set('shieldci.database.connections', ['mysql']);

        $checker = Mockery::mock(DatabaseConnectionChecker::class);
        // Should only be called once for mysql (deduplicated)
        /** @phpstan-ignore-next-line */
        $checker->shouldReceive('check')->with('mysql')->once()->andReturn(new DatabaseConnectionResult(true));

        $analyzer = $this->createAnalyzer($checker);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
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

        config()->set('database.default', 'mysql');
        config()->set('database.connections', $connections);
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
