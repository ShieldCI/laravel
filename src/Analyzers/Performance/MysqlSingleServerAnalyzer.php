<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Checks MySQL connection configuration for single-server setups.
 *
 * Checks for:
 * - MySQL connections using TCP instead of Unix sockets
 * - Performance improvements from using Unix sockets
 * - Single-server optimization recommendations
 *
 * Uses Laravel's ConfigRepository for proper configuration access.
 *
 * Environment Relevance:
 * - Production/Staging: Important (Unix sockets provide up to 50% performance improvement)
 * - Local/Development: Not relevant (TCP is acceptable for local development)
 * - Testing: Not relevant (tests typically use SQLite or don't need socket optimization)
 */
class MysqlSingleServerAnalyzer extends AbstractAnalyzer
{
    /**
     * MySQL server configuration is not applicable in CI environments.
     */
    public static bool $runInCI = false;

    /**
     * This analyzer is only relevant in production and staging environments.
     *
     * Unix socket optimization provides significant performance benefits
     * (up to 50% faster according to Percona benchmarks) when MySQL runs
     * on the same server as the application.
     *
     * @var array<string>|null
     */
    protected ?array $relevantEnvironments = ['production', 'staging'];

    public function __construct(
        private ConfigRepository $config
    ) {
        $this->configRepository = $config;
    }

    /**
     * Set relevant environments (for testing).
     *
     * @param  array<string>|null  $environments
     */
    public function setRelevantEnvironments(?array $environments): void
    {
        $this->relevantEnvironments = $environments;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'mysql-single-server-optimization',
            name: 'MySQL Single Server Optimization',
            description: 'Ensures MySQL is configured optimally for single-server setups using Unix sockets',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['mysql', 'database', 'performance', 'sockets', 'optimization'],
            docsUrl: 'https://laravel.com/docs/database#configuration'
        );
    }

    public function shouldRun(): bool
    {
        // Check environment relevance first
        if (! $this->isRelevantForCurrentEnvironment()) {
            return false;
        }

        $defaultConnection = $this->config->get('database.default');

        // Validate default connection is a string
        if (! is_string($defaultConnection) || $defaultConnection === '') {
            return false;
        }

        $driver = $this->config->get("database.connections.{$defaultConnection}.driver");

        return is_string($driver) && $driver === 'mysql';
    }

    public function getSkipReason(): string
    {
        if (! $this->isRelevantForCurrentEnvironment()) {
            $currentEnv = $this->getEnvironment();
            $relevantEnvs = implode(', ', $this->relevantEnvironments ?? []);

            return "Not relevant in '{$currentEnv}' environment (only relevant in: {$relevantEnvs})";
        }

        $defaultConnection = $this->config->get('database.default', 'unknown');
        $driver = $this->config->get("database.connections.{$defaultConnection}.driver", 'unknown');

        if (! is_string($driver)) {
            $driver = 'unknown';
        }

        return "Not using MySQL database driver (current: {$driver})";
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $defaultConnection = $this->config->get('database.default', 'mysql');
        $connections = $this->config->get('database.connections', []);

        // Validate connections is an array
        if (! is_array($connections)) {
            return $this->error('Database connections configuration is invalid');
        }

        // Validate default connection is a string
        if (! is_string($defaultConnection)) {
            $defaultConnection = 'mysql';
        }

        foreach ($connections as $name => $connection) {
            // Validate connection name is a string
            if (! is_string($name)) {
                continue;
            }

            // Validate connection is an array
            if (! is_array($connection)) {
                continue;
            }

            // Check if this is a MySQL connection
            if (! $this->isMysqlConnection($connection)) {
                continue;
            }

            // Check if connection needs optimization
            $issue = $this->checkConnectionOptimization($name, $connection, $defaultConnection);
            if ($issue !== null) {
                $issues[] = $issue;
            }
        }

        if (empty($issues)) {
            return $this->passed('MySQL connections are optimally configured');
        }

        return $this->warning(
            sprintf('Found %d MySQL configuration optimization opportunities', count($issues)),
            $issues
        );
    }

    /**
     * Check if a connection array represents a MySQL connection.
     *
     * @param  array<string, mixed>  $connection
     */
    private function isMysqlConnection(array $connection): bool
    {
        if (! isset($connection['driver'])) {
            return false;
        }

        $driver = $connection['driver'];

        return is_string($driver) && $driver === 'mysql';
    }

    /**
     * Check if a MySQL connection needs optimization (using TCP instead of Unix socket).
     *
     * @param  array<string, mixed>  $connection
     */
    private function checkConnectionOptimization(string $connectionName, array $connection, string $defaultConnection): ?\ShieldCI\AnalyzersCore\ValueObjects\Issue
    {
        $host = $this->getConnectionHost($connection);
        $unixSocket = $this->getConnectionUnixSocket($connection);

        // Check if using localhost/127.0.0.1/::1 without unix_socket
        // All of these indicate local connections that could use Unix sockets
        if ($this->isLocalhostConnection($host) && $this->isEmptySocket($unixSocket)) {
            $severity = $connectionName === $defaultConnection ? Severity::Medium : Severity::Low;
            $basePath = $this->getBasePath();
            $configFile = ConfigFileHelper::getConfigPath($basePath, 'database.php', fn ($file) => function_exists('config_path') ? config_path($file) : null);
            $lineNumber = ConfigFileHelper::findKeyLine($configFile, $connectionName, 'connections');

            return $this->createIssue(
                message: "MySQL connection '{$connectionName}' uses TCP on localhost instead of Unix socket",
                location: new Location($configFile, $lineNumber),
                severity: $severity,
                recommendation: $this->getRecommendation($connectionName),
                metadata: [
                    'connection_name' => $connectionName,
                    'host' => $host,
                    'unix_socket' => $unixSocket,
                    'is_default' => $connectionName === $defaultConnection,
                ]
            );
        }

        return null;
    }

    /**
     * Get the host value from a connection array.
     *
     * @param  array<string, mixed>  $connection
     */
    private function getConnectionHost(array $connection): string
    {
        $host = $connection['host'] ?? null;

        // Handle both string and null values
        if (! is_string($host)) {
            return '';
        }

        return trim($host);
    }

    /**
     * Get the unix_socket value from a connection array.
     *
     * @param  array<string, mixed>  $connection
     */
    private function getConnectionUnixSocket(array $connection): string
    {
        $socket = $connection['unix_socket'] ?? null;

        // Handle both string and null values
        if (! is_string($socket)) {
            return '';
        }

        return trim($socket);
    }

    /**
     * Check if a host value indicates a localhost connection.
     */
    private function isLocalhostConnection(string $host): bool
    {
        // Empty host defaults to localhost in Laravel
        if ($host === '') {
            return true;
        }

        // Check for common localhost values (IPv4, IPv6, and hostname)
        return in_array(strtolower($host), ['localhost', '127.0.0.1', '::1'], true);
    }

    /**
     * Check if a socket value is empty (null, empty string, or whitespace).
     */
    private function isEmptySocket(string $socket): bool
    {
        return $socket === '';
    }

    /**
     * Get the recommendation message for a connection.
     */
    private function getRecommendation(string $connectionName): string
    {
        return 'When MySQL runs on the same server as your application, use Unix sockets instead of TCP for up to 50% performance improvement (Percona benchmark). '.
               "Add 'unix_socket' => env('DB_SOCKET', '/var/run/mysqld/mysqld.sock') to the '{$connectionName}' connection config, ".
               'then set DB_SOCKET in your .env file with the path to your MySQL socket file. Common paths: '.
               '/var/run/mysqld/mysqld.sock (Ubuntu/Debian), /tmp/mysql.sock (macOS), /var/lib/mysql/mysql.sock (RHEL/CentOS).';
    }
}
