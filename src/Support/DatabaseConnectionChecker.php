<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Illuminate\Database\Connectors\ConnectionFactory;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\ConfigurationUrlParser;
use ReflectionException;
use ReflectionProperty;
use Throwable;

class DatabaseConnectionChecker
{
    private ConnectionFactory $factory;

    public function __construct(private DatabaseManager $manager, ?ConnectionFactory $factory = null)
    {
        $this->factory = $factory ?? app('db.factory');
    }

    /**
     * Attempt to obtain the write PDO, then every read PDO, for the given connection name.
     *
     * When Laravel builds the connection from its config through the factory, the read side
     * is probed from that config: Laravel resolves one entry of a read list at random, and the
     * live connection hands back the write PDO inside a transaction or after a sticky write, so
     * either way a dead replica could hide behind a reachable one. Any other connection is
     * built by something the config does not describe, such as a DB::extend() resolver, so its
     * read side is checked through the live connection the app itself resolved.
     */
    public function check(string $connection): DatabaseConnectionResult
    {
        try {
            $resolved = $this->manager->connection($connection);
            $pdo = $resolved->getPdo();

            if ($pdo === null) {
                return new DatabaseConnectionResult(false, 'Connection returned null PDO instance.');
            }
        } catch (Throwable $exception) {
            return new DatabaseConnectionResult(false, $exception->getMessage(), get_class($exception));
        }

        $endpoints = $this->factoryReadEndpoints($connection);

        if ($endpoints === null) {
            try {
                // Falls back to the write PDO resolved above when there is no separate read side.
                $resolved->getReadPdo();
            } catch (Throwable $exception) {
                return new DatabaseConnectionResult(false, 'Read connection: '.$exception->getMessage(), get_class($exception));
            }

            return new DatabaseConnectionResult(true);
        }

        foreach ($endpoints as $index => $endpoint) {
            try {
                $probe = $this->factory->make($endpoint, $connection);
                $probe->getPdo();
                $probe->disconnect();
            } catch (Throwable $exception) {
                $label = count($endpoints) > 1 ? 'Read connection #'.($index + 1) : 'Read connection';

                return new DatabaseConnectionResult(false, $label.': '.$exception->getMessage(), get_class($exception));
            }
        }

        return new DatabaseConnectionResult(true);
    }

    /**
     * Build one config per read endpoint the way ConnectionFactory::getReadConfig() does: the
     * connection config merged with the read section, minus the read and write keys, as
     * mergeReadWriteConfig() leaves it. A read list yields one config per entry; a host array
     * inside an entry stays one endpoint, since Laravel fails over between those hosts itself.
     *
     * Returns null when Laravel would not build this connection from that config through the
     * factory, mirroring DatabaseManager::makeConnection(): a dynamic configuration or a
     * resolver keyed by the connection name or its driver takes precedence over the factory.
     * With neither, makeConnection() can only have used the factory, so the probe holds for any
     * driver: one the factory cannot build has already failed the write probe as unsupported.
     *
     * @return list<array<string, mixed>>|null
     */
    private function factoryReadEndpoints(string $connection): ?array
    {
        $raw = config("database.connections.{$connection}");

        if (! is_array($raw)) {
            return null;
        }

        // DatabaseManager::configuration() runs the same parser, so a 'url' key expands first.
        $config = (new ConfigurationUrlParser)->parseConfiguration($this->stringKeyed($raw));

        $driver = $config['driver'] ?? null;

        if (! is_string($driver)) {
            return null;
        }

        $extensions = $this->managerArray('extensions');

        if ($extensions === null || isset($extensions[$connection]) || isset($extensions[$driver])) {
            return null;
        }

        // Laravel 11+ only; an older manager has no dynamic configurations to take precedence.
        if (isset($this->managerArray('dynamicConnectionConfigurations')[$connection])) {
            return null;
        }

        if (! isset($config['read']) || ! is_array($config['read'])) {
            return [];
        }

        $entries = isset($config['read'][0]) ? $config['read'] : [$config['read']];
        $endpoints = [];

        foreach ($entries as $entry) {
            if (is_array($entry)) {
                $endpoint = array_merge($config, $this->stringKeyed($entry));
                unset($endpoint['read'], $endpoint['write']);
                $endpoints[] = $endpoint;
            }
        }

        return $endpoints;
    }

    /**
     * Read one of DatabaseManager's protected array properties, which it exposes no getter for.
     * Null means the property is not there, which callers treat as "cannot tell".
     *
     * @return array<mixed>|null
     */
    private function managerArray(string $property): ?array
    {
        try {
            $reflection = new ReflectionProperty(DatabaseManager::class, $property);
        } catch (ReflectionException) {
            return null;
        }

        $value = $reflection->getValue($this->manager);

        return is_array($value) ? $value : null;
    }

    /**
     * Config keys are strings; drop anything else so the result types as a config array.
     *
     * @param  array<mixed>  $values
     * @return array<string, mixed>
     */
    private function stringKeyed(array $values): array
    {
        $keyed = [];

        foreach ($values as $key => $value) {
            if (is_string($key)) {
                $keyed[$key] = $value;
            }
        }

        return $keyed;
    }
}
