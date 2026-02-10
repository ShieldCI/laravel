<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
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

    #[Test]
    public function it_works_with_real_database_manager(): void
    {
        // Test with the actual database manager from the container
        $checker = new DatabaseConnectionChecker($this->app['db']);

        // This should work with SQLite in-memory by default
        config(['database.default' => 'sqlite']);
        config(['database.connections.sqlite.database' => ':memory:']);

        $result = $checker->check('sqlite');

        $this->assertTrue($result->successful);
    }
}
