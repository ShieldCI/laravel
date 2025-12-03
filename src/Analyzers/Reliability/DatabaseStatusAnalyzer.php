<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Support\Facades\DB;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Support\DatabaseConnectionChecker;
use ShieldCI\Support\DatabaseConnectionResult;

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

    private DatabaseConnectionChecker $connectionChecker;

    public function __construct(?DatabaseConnectionChecker $connectionChecker = null)
    {
        $this->connectionChecker = $connectionChecker ?? new DatabaseConnectionChecker(DB::getFacadeRoot());
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'database-status',
            name: 'Database Status',
            description: 'Ensures database connections are accessible and functioning properly',
            category: Category::Reliability,
            severity: Severity::Critical,
            tags: ['database', 'infrastructure', 'reliability', 'availability'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/database-status',
            timeToFix: 15
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $defaultConnection = config('database.default');

        if (! is_string($defaultConnection)) {
            return $this->warning('Unable to determine default database connection');
        }

        $connections = $this->getConnectionsToCheck($defaultConnection);

        foreach ($connections as $connectionName) {
            $result = $this->connectionChecker->check($connectionName);
            $configLocation = $this->getDatabaseConfigLocation($connectionName);

            if (! $result->successful) {
                $issues[] = $this->createIssue(
                    message: $result->message ?? "Cannot connect to database '{$connectionName}'",
                    location: $configLocation,
                    severity: Severity::Critical,
                    recommendation: $this->buildRecommendation($connectionName, $result),
                    code: $this->getCodeSnippetSafely($configLocation),
                    metadata: [
                        'connection' => $connectionName,
                        'driver' => $this->getConnectionDriver($connectionName),
                        'host' => $this->getConnectionHost($connectionName),
                        'database' => $this->getConnectionDatabase($connectionName),
                        'exception' => $result->exceptionClass,
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

    /**
     * Get the list of database connections to verify.
     *
     * Always includes the default connection first, then any additional configured connections.
     * Duplicates are automatically removed.
     *
     * @return list<string>
     */
    private function getConnectionsToCheck(string $defaultConnection): array
    {
        $configured = config('shieldci.database.connections', []);

        if (is_string($configured)) {
            $configured = array_filter(array_map('trim', explode(',', $configured)));
        }

        if (! is_array($configured)) {
            $configured = [];
        }

        $connections = [$defaultConnection];

        foreach ($configured as $connection) {
            if (is_string($connection) && $connection !== '') {
                $connections[] = $connection;
            }
        }

        return array_values(array_unique($connections));
    }

    /**
     * Get recommendation message for database connection failure.
     */
    private function buildRecommendation(string $connection, DatabaseConnectionResult $result): string
    {
        $driver = $this->getConnectionDriver($connection);
        $errorMsg = $result->message ?? '';
        $sanitizedError = $this->sanitizeErrorMessage($errorMsg);

        $recommendation = "Database connection '{$connection}' failed: {$sanitizedError}. ";

        // Provide specific recommendations based on error and driver
        if (str_contains($errorMsg, 'Access denied')) {
            $recommendation .= 'Check database username and password in your .env file. ';
        } elseif (str_contains($errorMsg, 'Connection refused') || str_contains($errorMsg, 'could not find driver')) {
            $driverText = is_string($driver) ? $driver : 'database';
            $recommendation .= "Ensure the database server is running and the PHP {$driverText} extension is installed. ";
        } elseif (str_contains($errorMsg, 'Unknown database')) {
            $recommendation .= 'The specified database does not exist. Create it or check the DB_DATABASE value in .env. ';
        } else {
            $recommendation .= 'Common issues: 1) Database server not running, 2) Incorrect credentials, 3) Firewall blocking connection, 4) Wrong host/port. ';
        }

        $recommendation .= "Verify settings in .env and config/database.php for the '{$connection}' connection.";

        return $recommendation;
    }

    /**
     * Get the path to the database configuration file.
     */
    private function getDatabaseConfigPath(): string
    {
        $basePath = $this->getBasePath();

        return ConfigFileHelper::getConfigPath(
            $basePath,
            'database.php',
            fn ($file) => function_exists('config_path') ? config_path($file) : null
        );
    }

    /**
     * Get the location of the database configuration file.
     * Attempts to find the connection line, falls back to line 1.
     */
    private function getDatabaseConfigLocation(string $connectionName): Location
    {
        $configFile = $this->getDatabaseConfigPath();

        if (file_exists($configFile)) {
            // Try to find the connection line number
            $lineNumber = ConfigFileHelper::findNestedKeyLine(
                $configFile,
                'connections',
                'driver',
                $connectionName
            );

            if ($lineNumber < 1) {
                // Fallback to finding the connection name
                $lineNumber = ConfigFileHelper::findKeyLine($configFile, $connectionName, 'connections');
                if ($lineNumber < 1) {
                    $lineNumber = 1;
                }
            }

            return new Location($configFile, $lineNumber);
        }

        return new Location($configFile, 1);
    }

    /**
     * Get a config value for a database connection.
     */
    private function getConnectionConfig(string $connectionName, string $key): ?string
    {
        $value = config("database.connections.{$connectionName}.{$key}");

        return is_string($value) ? $value : null;
    }

    /**
     * Get the driver for a database connection.
     */
    private function getConnectionDriver(string $connectionName): ?string
    {
        return $this->getConnectionConfig($connectionName, 'driver');
    }

    /**
     * Get the host for a database connection.
     */
    private function getConnectionHost(string $connectionName): ?string
    {
        return $this->getConnectionConfig($connectionName, 'host');
    }

    /**
     * Get the database name for a database connection.
     */
    private function getConnectionDatabase(string $connectionName): ?string
    {
        return $this->getConnectionConfig($connectionName, 'database');
    }

    /**
     * Sanitize error message for display in recommendations.
     */
    private function sanitizeErrorMessage(string $error): string
    {
        // Limit error message length to prevent overly long recommendations
        $maxLength = 200;
        if (strlen($error) > $maxLength) {
            return substr($error, 0, $maxLength).'...';
        }

        return $error;
    }

    /**
     * Safely get code snippet, handling missing files.
     */
    private function getCodeSnippetSafely(Location $location): ?string
    {
        if (! file_exists($location->file)) {
            return null;
        }

        return FileParser::getCodeSnippet($location->file, $location->line);
    }
}
