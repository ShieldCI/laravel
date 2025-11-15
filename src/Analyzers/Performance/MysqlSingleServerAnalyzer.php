<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
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
 */
class MysqlSingleServerAnalyzer extends AbstractAnalyzer
{
    /**
     * MySQL server configuration is not applicable in CI environments.
     */
    public static bool $runInCI = false;

    public function __construct(
        private ConfigRepository $config
    ) {}

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
        // Skip if user configured to skip in local environment
        if ($this->isLocalAndShouldSkip()) {
            return false;
        }

        $defaultConnection = $this->config->get('database.default');
        $driver = $this->config->get("database.connections.{$defaultConnection}.driver");

        return $driver === 'mysql';
    }

    public function getSkipReason(): string
    {
        if ($this->isLocalAndShouldSkip()) {
            return 'Skipped in local environment (configured)';
        }

        $defaultConnection = $this->config->get('database.default', 'unknown');
        $driver = $this->config->get("database.connections.{$defaultConnection}.driver", 'unknown');

        return "Not using MySQL database driver (current: {$driver})";
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $defaultConnection = $this->config->get('database.default', 'mysql');
        $connections = $this->config->get('database.connections', []);

        foreach ($connections as $name => $connection) {
            // Ensure $name is a string
            if (! is_string($name)) {
                continue;
            }

            if (! isset($connection['driver']) || $connection['driver'] !== 'mysql') {
                continue;
            }

            $host = $connection['host'] ?? '';
            $unixSocket = $connection['unix_socket'] ?? '';

            // Check if using localhost/127.0.0.1 without unix_socket
            // Both localhost and 127.0.0.1 indicate local connections
            if (($host === 'localhost' || $host === '127.0.0.1') && empty($unixSocket)) {
                $severity = $name === $defaultConnection ? Severity::Medium : Severity::Low;

                $issues[] = $this->createIssue(
                    message: "MySQL connection '{$name}' uses TCP on localhost instead of Unix socket",
                    location: new Location('config/database.php', 1),
                    severity: $severity,
                    recommendation: $this->getRecommendation($name),
                    metadata: [
                        'connection_name' => $name,
                        'host' => $host,
                        'unix_socket' => $unixSocket,
                        'is_default' => $name === $defaultConnection,
                    ]
                );
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

    private function getRecommendation(string $connectionName): string
    {
        return 'When MySQL runs on the same server as your application, use Unix sockets instead of TCP for up to 50% performance improvement (Percona benchmark). '.
               "Add 'unix_socket' => env('DB_SOCKET', '/var/run/mysqld/mysqld.sock') to the '{$connectionName}' connection config, ".
               'then set DB_SOCKET in your .env file with the path to your MySQL socket file. Common paths: '.
               '/var/run/mysqld/mysqld.sock (Ubuntu/Debian), /tmp/mysql.sock (macOS), /var/lib/mysql/mysql.sock (RHEL/CentOS).';
    }
}
