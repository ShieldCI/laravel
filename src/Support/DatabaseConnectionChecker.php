<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Illuminate\Database\DatabaseManager;
use Throwable;

class DatabaseConnectionChecker
{
    public function __construct(private DatabaseManager $manager) {}

    /**
     * Attempt to obtain a PDO connection for the given connection name.
     */
    public function check(string $connection): DatabaseConnectionResult
    {
        try {
            $pdo = $this->manager->connection($connection)->getPdo();

            if ($pdo === null) {
                return new DatabaseConnectionResult(false, 'Connection returned null PDO instance.');
            }

            return new DatabaseConnectionResult(true);
        } catch (Throwable $exception) {
            return new DatabaseConnectionResult(false, $exception->getMessage(), get_class($exception));
        }
    }
}
