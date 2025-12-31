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
use ShieldCI\Support\MessageHelper;

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
            name: 'Database Status Analyzer',
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
                $severity = $this->determineSeverity($connectionName, $defaultConnection, $result);

                $issues[] = $this->createIssue(
                    message: $result->message ?? "Cannot connect to database '{$connectionName}'",
                    location: $configLocation,
                    severity: $severity,
                    recommendation: $this->buildRecommendation($connectionName, $result),
                    code: $configLocation->line ? FileParser::getCodeSnippet($configLocation->file, $configLocation->line) : null,
                    metadata: [
                        'connection' => $connectionName,
                        'driver' => $this->getConnectionDriver($connectionName),
                        'exception' => $result->exceptionClass,
                        'is_default' => $connectionName === $defaultConnection,
                        // Note: host and database omitted to prevent infrastructure exposure in logs/reports
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
     * Determine the severity of a database connection failure.
     *
     * Factors considered:
     * - Default vs non-default connection
     * - Transient vs persistent error type
     */
    private function determineSeverity(
        string $connectionName,
        string $defaultConnection,
        DatabaseConnectionResult $result
    ): Severity {
        $isDefault = $connectionName === $defaultConnection;
        $isTransient = $this->isTransientError($result);

        // Default connection failures are more severe
        if ($isDefault) {
            // Default connection with persistent error = Critical
            // Default connection with transient error = High
            return $isTransient ? Severity::High : Severity::Critical;
        }

        // Non-default connection failures are less severe
        // Non-default with persistent error = High
        // Non-default with transient error = Medium
        return $isTransient ? Severity::Medium : Severity::High;
    }

    /**
     * Determine if an error is likely transient (temporary/recoverable).
     *
     * Transient errors include:
     * - Connection timeouts
     * - Connection refused (server restarting)
     * - DNS resolution failures
     * - Network unreachable
     *
     * Persistent errors include:
     * - Access denied (wrong credentials)
     * - Unknown database (doesn't exist)
     * - Missing driver
     */
    private function isTransientError(DatabaseConnectionResult $result): bool
    {
        $message = $result->message ?? '';

        // Transient network/connectivity issues
        $transientPatterns = [
            'Connection refused',
            'Connection timed out',
            'Timeout',
            'timed out',
            'Network is unreachable',
            'No route to host',
            'Temporary failure in name resolution',
            'Name or service not known',
        ];

        foreach ($transientPatterns as $pattern) {
            if (stripos($message, $pattern) !== false) {
                return true;
            }
        }

        // Default to persistent for safety (don't downgrade severity incorrectly)
        return false;
    }

    /**
     * Get recommendation message for database connection failure.
     */
    private function buildRecommendation(string $connection, DatabaseConnectionResult $result): string
    {
        $driver = $this->getConnectionDriver($connection);
        $errorMsg = $result->message ?? '';
        $error = strtolower($errorMsg);
        $sanitizedError = MessageHelper::sanitizeErrorMessage($errorMsg);

        $recommendation = "Database connection '{$connection}' failed: {$sanitizedError}. ";

        // Provide specific recommendations based on error and driver
        if (str_contains($error, 'access denied')) {
            $recommendation .= 'Check database username and password in your .env file. ';
        } elseif (str_contains($error, 'connection refused') || str_contains($error, 'could not find driver')) {
            $extension = $this->getPhpExtensionName($driver);
            $recommendation .= "Ensure the database server is running and the {$extension} PHP extension is installed. ";
        } elseif (str_contains($error, 'unknown database')) {
            $recommendation .= 'The specified database does not exist. Create it or check the DB_DATABASE value in .env. ';
        } else {
            $recommendation .= 'Common issues: 1) Database server not running, 2) Incorrect credentials, 3) Firewall blocking connection, 4) Wrong host/port. ';
        }

        $recommendation .= "Verify settings in .env and config/database.php for the '{$connection}' connection.";

        return $recommendation;
    }

    /**
     * Map Laravel database driver names to actual PHP extension names.
     */
    private function getPhpExtensionName(?string $driver): string
    {
        if ($driver === null) {
            return 'PDO';
        }

        $extensionMap = [
            'mysql' => 'pdo_mysql',
            'pgsql' => 'pdo_pgsql',
            'sqlsrv' => 'pdo_sqlsrv',
            'sqlite' => 'pdo_sqlite',
        ];

        return $extensionMap[$driver] ?? 'PDO';
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
            // Find the connection name as a key within the 'connections' array
            $lineNumber = ConfigFileHelper::findKeyLine(
                $configFile,
                $connectionName,
                'connections'
            );

            return new Location($this->getRelativePath($configFile), $lineNumber < 1 ? null : $lineNumber);
        }

        return new Location($this->getRelativePath($configFile));
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
}
