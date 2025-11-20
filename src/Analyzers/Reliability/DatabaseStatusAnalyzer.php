<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Support\Facades\DB;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Checks that database connections are accessible.
 *
 * Checks for:
 * - Default database connection is accessible
 * - Can establish PDO connection
 * - Database server is reachable
 */
class DatabaseStatusAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Database connectivity checks are not applicable in CI environments.
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'database-status',
            name: 'Database Status',
            description: 'Ensures database connections are accessible and functioning properly',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['database', 'infrastructure', 'reliability', 'availability'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/database-status'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $defaultConnection = config('database.default');

        if (! is_string($defaultConnection)) {
            return $this->warning('Unable to determine default database connection');
        }

        $connections = [$defaultConnection];

        // Check each connection
        foreach ($connections as $connectionName) {
            if (! $connectionName || ! is_string($connectionName)) {
                continue;
            }

            try {
                $pdo = DB::connection($connectionName)->getPdo();

                if (! $pdo) {
                    $issues[] = $this->createIssue(
                        message: "Database connection '{$connectionName}' returned null PDO",
                        location: new Location(ConfigFileHelper::getConfigPath($this->basePath, 'database.php', fn ($file) => function_exists('config_path') ? config_path($file) : null), 1),
                        severity: Severity::Critical,
                        recommendation: "Check database configuration for '{$connectionName}' connection in config/database.php. Ensure the database server is running and credentials are correct.",
                        metadata: [
                            'connection' => $connectionName,
                            'driver' => config("database.connections.{$connectionName}.driver"),
                        ]
                    );
                }
            } catch (\Throwable $e) {
                $issues[] = $this->createIssue(
                    message: "Cannot connect to database '{$connectionName}'",
                    location: new Location(ConfigFileHelper::getConfigPath($this->basePath, 'database.php', fn ($file) => function_exists('config_path') ? config_path($file) : null), 1),
                    severity: Severity::Critical,
                    recommendation: $this->getRecommendation($connectionName, $e),
                    metadata: [
                        'connection' => $connectionName,
                        'driver' => config("database.connections.{$connectionName}.driver"),
                        'host' => config("database.connections.{$connectionName}.host"),
                        'database' => config("database.connections.{$connectionName}.database"),
                        'exception' => get_class($e),
                        'error' => $e->getMessage(),
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('All database connections are accessible');
        }

        return $this->failed(
            sprintf('Failed to connect to %d database connection(s)', count($issues)),
            $issues
        );
    }

    private function getRecommendation(string $connection, \Throwable $e): string
    {
        $driver = config("database.connections.{$connection}.driver");
        $errorMsg = $e->getMessage();

        $recommendation = "Database connection '{$connection}' failed: {$errorMsg}. ";

        // Provide specific recommendations based on error and driver
        if (str_contains($errorMsg, 'Access denied')) {
            $recommendation .= 'Check database username and password in your .env file. ';
        } elseif (str_contains($errorMsg, 'Connection refused') || str_contains($errorMsg, 'could not find driver')) {
            $recommendation .= "Ensure the database server is running and the PHP {$driver} extension is installed. ";
        } elseif (str_contains($errorMsg, 'Unknown database')) {
            $recommendation .= 'The specified database does not exist. Create it or check the DB_DATABASE value in .env. ';
        } else {
            $recommendation .= 'Common issues: 1) Database server not running, 2) Incorrect credentials, 3) Firewall blocking connection, 4) Wrong host/port. ';
        }

        $recommendation .= "Verify settings in .env and config/database.php for the '{$connection}' connection.";

        return $recommendation;
    }
}
