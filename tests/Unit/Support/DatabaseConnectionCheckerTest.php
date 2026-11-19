<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\Connectors\ConnectionFactory;
use Illuminate\Database\DatabaseManager;
use Illuminate\Foundation\Application;
use Mockery;
use PDO;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Support\DatabaseConnectionChecker;
use ShieldCI\Support\DatabaseConnectionResult;
use ShieldCI\Tests\TestCase;

class DatabaseConnectionCheckerTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    /** @test */
    #[Test]
    public function it_returns_success_for_valid_connection(): void
    {
        $pdo = Mockery::mock(PDO::class);

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('getPdo')->andReturn($pdo);

        $manager = Mockery::mock(DatabaseManager::class);
        $manager->shouldReceive('connection')->with('mysql')->andReturn($connection);

        $checker = new DatabaseConnectionChecker($manager);
        $result = $checker->check('mysql');

        $this->assertInstanceOf(DatabaseConnectionResult::class, $result);
        $this->assertTrue($result->successful);
        $this->assertNull($result->message);
    }

    /** @test */
    #[Test]
    public function it_returns_failure_for_null_pdo(): void
    {
        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('getPdo')->andReturn(null);

        $manager = Mockery::mock(DatabaseManager::class);
        $manager->shouldReceive('connection')->with('mysql')->andReturn($connection);

        $checker = new DatabaseConnectionChecker($manager);
        $result = $checker->check('mysql');

        $this->assertFalse($result->successful);
        $this->assertStringContainsString('null PDO', $result->message);
    }

    /** @test */
    #[Test]
    public function it_returns_failure_for_connection_exception(): void
    {
        $manager = Mockery::mock(DatabaseManager::class);
        $manager->shouldReceive('connection')
            ->with('invalid')
            ->andThrow(new \RuntimeException('Connection failed: host not found'));

        $checker = new DatabaseConnectionChecker($manager);
        $result = $checker->check('invalid');

        $this->assertFalse($result->successful);
        $this->assertStringContainsString('Connection failed', $result->message);
        $this->assertEquals('RuntimeException', $result->exceptionClass);
    }

    /** @test */
    #[Test]
    public function it_captures_exception_class_on_failure(): void
    {
        $manager = Mockery::mock(DatabaseManager::class);
        $manager->shouldReceive('connection')
            ->with('test')
            ->andThrow(new \InvalidArgumentException('Invalid argument'));

        $checker = new DatabaseConnectionChecker($manager);
        $result = $checker->check('test');

        $this->assertFalse($result->successful);
        $this->assertEquals('InvalidArgumentException', $result->exceptionClass);
    }

    /** @test */
    #[Test]
    public function it_handles_pdo_exception(): void
    {
        $manager = Mockery::mock(DatabaseManager::class);
        $manager->shouldReceive('connection')
            ->with('mysql')
            ->andThrow(new \PDOException('SQLSTATE[HY000] [2002] No such file or directory'));

        $checker = new DatabaseConnectionChecker($manager);
        $result = $checker->check('mysql');

        $this->assertFalse($result->successful);
        $this->assertStringContainsString('SQLSTATE', $result->message);
    }

    /** @test */
    #[Test]
    public function it_works_with_real_database_manager(): void
    {
        // Test with the actual database manager from the container
        $checker = new DatabaseConnectionChecker($this->app->make(DatabaseManager::class));

        // This should work with SQLite in-memory by default
        config(['database.default' => 'sqlite']);
        config(['database.connections.sqlite.database' => ':memory:']);

        $result = $checker->check('sqlite');

        $this->assertTrue($result->successful);
    }

    /** @test */
    #[Test]
    public function it_returns_failure_when_a_read_endpoint_cannot_be_resolved(): void
    {
        config(['database.connections.split' => [
            'driver' => 'mysql',
            'read' => ['host' => 'replica.internal'],
            'write' => ['host' => 'primary.internal'],
        ]]);

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('getPdo')->andReturn(Mockery::mock(PDO::class));

        $manager = Mockery::mock(DatabaseManager::class);
        $manager->shouldReceive('connection')->with('split')->andReturn($connection);

        $probe = Mockery::mock(Connection::class);
        $probe->shouldReceive('getPdo')
            ->andThrow(new \PDOException('SQLSTATE[HY000] [2002] Connection refused'));

        $factory = Mockery::mock(ConnectionFactory::class);
        $factory->shouldReceive('make')
            ->once()
            ->withArgs(fn (array $config, string $name): bool => $name === 'split'
                && $config['host'] === 'replica.internal'
                && ! isset($config['read'])
                && ! isset($config['write']))
            ->andReturn($probe);

        $checker = new DatabaseConnectionChecker($manager, $factory);
        $result = $checker->check('split');

        $this->assertFalse($result->successful);
        $this->assertSame('Read connection: SQLSTATE[HY000] [2002] Connection refused', $result->message);
        $this->assertEquals('PDOException', $result->exceptionClass);
    }

    /** @test */
    #[Test]
    public function it_does_not_probe_the_read_side_when_the_write_pdo_fails(): void
    {
        config(['database.connections.split' => [
            'driver' => 'mysql',
            'read' => ['host' => 'replica.internal'],
            'write' => ['host' => 'primary.internal'],
        ]]);

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('getPdo')
            ->andThrow(new \PDOException('SQLSTATE[HY000] [2002] Connection refused'));

        $manager = Mockery::mock(DatabaseManager::class);
        $manager->shouldReceive('connection')->with('split')->andReturn($connection);

        $factory = Mockery::mock(ConnectionFactory::class);
        $factory->shouldNotReceive('make');

        $checker = new DatabaseConnectionChecker($manager, $factory);
        $result = $checker->check('split');

        $this->assertFalse($result->successful);
        $this->assertSame('SQLSTATE[HY000] [2002] Connection refused', $result->message);
    }

    /** @test */
    #[Test]
    public function it_probes_the_read_config_of_a_custom_driver_without_a_resolver(): void
    {
        // With no DB::extend() resolver the manager can only have built the connection through
        // the factory, so the config describes it whatever the driver is called.
        config(['database.connections.custom' => [
            'driver' => 'custom-driver',
            'read' => ['host' => 'replica.internal'],
            'write' => ['host' => 'primary.internal'],
        ]]);

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('getPdo')->andReturn(Mockery::mock(PDO::class));
        $connection->shouldNotReceive('getReadPdo');

        $manager = Mockery::mock(DatabaseManager::class);
        $manager->shouldReceive('connection')->with('custom')->andReturn($connection);

        $probe = Mockery::mock(Connection::class);
        $probe->shouldReceive('getPdo')
            ->andThrow(new \PDOException('SQLSTATE[HY000] [2002] Connection refused'));

        $factory = Mockery::mock(ConnectionFactory::class);
        $factory->shouldReceive('make')
            ->once()
            ->withArgs(fn (array $config, string $name): bool => $name === 'custom'
                && $config['driver'] === 'custom-driver'
                && $config['host'] === 'replica.internal')
            ->andReturn($probe);

        $checker = new DatabaseConnectionChecker($manager, $factory);
        $result = $checker->check('custom');

        $this->assertFalse($result->successful);
        $this->assertSame('Read connection: SQLSTATE[HY000] [2002] Connection refused', $result->message);
    }

    /** @test */
    #[Test]
    public function it_checks_the_live_read_pdo_of_a_connection_missing_from_config(): void
    {
        // A connection registered at runtime, such as through DB::connectUsing(), has no config
        // entry to probe, so only the live connection can show its read side.
        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('getPdo')->andReturn(Mockery::mock(PDO::class));
        $connection->shouldReceive('getReadPdo')
            ->once()
            ->andThrow(new \PDOException('SQLSTATE[HY000] [2002] Connection refused'));

        $manager = Mockery::mock(DatabaseManager::class);
        $manager->shouldReceive('connection')->with('runtime')->andReturn($connection);

        $factory = Mockery::mock(ConnectionFactory::class);
        $factory->shouldNotReceive('make');

        $checker = new DatabaseConnectionChecker($manager, $factory);
        $result = $checker->check('runtime');

        $this->assertFalse($result->successful);
        $this->assertSame('Read connection: SQLSTATE[HY000] [2002] Connection refused', $result->message);
    }

    /** @test */
    #[Test]
    public function it_checks_the_live_read_pdo_of_a_connection_without_a_driver(): void
    {
        // A resolver keyed by the connection name runs before the manager reads the driver, so
        // such a config may name none; the factory could not build it from that config.
        config(['database.connections.resolved' => [
            'read' => ['host' => 'replica.internal'],
            'write' => ['host' => 'primary.internal'],
        ]]);

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('getPdo')->andReturn(Mockery::mock(PDO::class));
        $connection->shouldReceive('getReadPdo')->once()->andReturn(Mockery::mock(PDO::class));

        $manager = Mockery::mock(DatabaseManager::class);
        $manager->shouldReceive('connection')->with('resolved')->andReturn($connection);

        $factory = Mockery::mock(ConnectionFactory::class);
        $factory->shouldNotReceive('make');

        $checker = new DatabaseConnectionChecker($manager, $factory);

        $this->assertTrue($checker->check('resolved')->successful);
    }

    /** @test */
    #[Test]
    public function it_checks_the_live_read_pdo_when_a_resolver_is_registered_for_the_driver(): void
    {
        config(['database.connections.split' => [
            'driver' => 'mysql',
            'read' => ['host' => 'replica.internal'],
            'write' => ['host' => 'primary.internal'],
        ]]);

        // The resolver connects somewhere the raw config does not describe; probing that config
        // through the factory would test a replica the app never uses.
        $manager = app('db');
        $manager->extend('mysql', static fn (array $config, string $name) => app('db.factory')
            ->make(['driver' => 'sqlite', 'database' => ':memory:'], $name));

        $factory = Mockery::mock(ConnectionFactory::class);
        $factory->shouldNotReceive('make');

        $checker = new DatabaseConnectionChecker($manager, $factory);

        $this->assertTrue($checker->check('split')->successful);
    }

    /** @test */
    #[Test]
    public function it_probes_every_entry_of_a_read_list(): void
    {
        config(['database.connections.split' => [
            'driver' => 'mysql',
            'read' => [['host' => 'replica-a.internal'], ['host' => 'replica-b.internal']],
            'write' => ['host' => 'primary.internal'],
        ]]);

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('getPdo')->andReturn(Mockery::mock(PDO::class));

        $manager = Mockery::mock(DatabaseManager::class);
        $manager->shouldReceive('connection')->with('split')->andReturn($connection);

        $probed = [];
        $probe = Mockery::mock(Connection::class);
        $probe->shouldReceive('getPdo')->andReturn(Mockery::mock(PDO::class));
        $probe->shouldReceive('disconnect');

        $factory = Mockery::mock(ConnectionFactory::class);
        $factory->shouldReceive('make')
            ->twice()
            ->andReturnUsing(function (array $config) use (&$probed, $probe) {
                $probed[] = $config['host'];

                return $probe;
            });

        $checker = new DatabaseConnectionChecker($manager, $factory);

        $this->assertTrue($checker->check('split')->successful);
        $this->assertSame(['replica-a.internal', 'replica-b.internal'], $probed);
    }

    /** @test */
    #[Test]
    public function it_returns_failure_for_an_unreachable_read_replica_with_real_database_manager(): void
    {
        $missing = sys_get_temp_dir().'/shieldci-'.bin2hex(random_bytes(8)).'/replica.sqlite';

        config(['database.connections.split' => [
            'driver' => 'sqlite',
            'read' => ['database' => $missing],
            'write' => ['database' => ':memory:'],
            'prefix' => '',
        ]]);

        $checker = new DatabaseConnectionChecker($this->app->make(DatabaseManager::class));
        $result = $checker->check('split');

        $this->assertFalse($result->successful);
        $this->assertStringStartsWith('Read connection: ', (string) $result->message);
        $this->assertStringContainsString('does not exist', (string) $result->message);
    }

    /** @test */
    #[Test]
    public function it_returns_success_for_a_non_split_connection_with_real_database_manager(): void
    {
        config(['database.connections.sqlite.database' => ':memory:']);

        $checker = new DatabaseConnectionChecker($this->app->make(DatabaseManager::class));
        $result = $checker->check('sqlite');

        $this->assertTrue($result->successful);
    }

    /** @test */
    #[Test]
    public function it_checks_the_live_read_pdo_of_a_dynamically_built_connection(): void
    {
        if (version_compare(Application::VERSION, '11.0.0', '<')) {
            $this->markTestSkipped('DB::build() arrived in Laravel 11.');
        }

        $missing = sys_get_temp_dir().'/shieldci-'.bin2hex(random_bytes(8)).'/replica.sqlite';

        // The config file names a dead replica, but the app built the connection dynamically.
        config(['database.connections.split' => [
            'driver' => 'sqlite',
            'read' => ['database' => $missing],
            'write' => ['database' => ':memory:'],
        ]]);

        $manager = app('db');
        $manager->build(['name' => 'split', 'driver' => 'sqlite', 'database' => ':memory:']);

        $factory = Mockery::mock(ConnectionFactory::class);
        $factory->shouldNotReceive('make');

        $checker = new DatabaseConnectionChecker($manager, $factory);

        $this->assertTrue($checker->check('split')->successful);
    }

    /** @test */
    #[Test]
    public function it_treats_an_unreadable_manager_property_as_unknown(): void
    {
        $checker = new DatabaseConnectionChecker(app('db'));

        $method = new \ReflectionMethod(DatabaseConnectionChecker::class, 'managerArray');

        $this->assertNull($method->invoke($checker, 'shieldciNoSuchProperty'));
        $this->assertSame([], $method->invoke($checker, 'extensions'));
    }
}
