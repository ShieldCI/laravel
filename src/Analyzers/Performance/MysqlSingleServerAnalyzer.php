<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
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
 */
class MysqlSingleServerAnalyzer extends AbstractFileAnalyzer
{
    /**
     * MySQL server configuration is not applicable in CI environments.
     */
    public static bool $runInCI = false;

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
        $environment = $this->getEnvironment();

        // Only run in non-local environments
        if ($environment === 'local') {
            return false;
        }

        // Check if MySQL is the database driver
        $databaseConfig = $this->getDatabaseConfig();
        $defaultConnection = $databaseConfig['default'] ?? 'mysql';
        $connection = $databaseConfig['connections'][$defaultConnection] ?? [];
        $driver = $connection['driver'] ?? '';

        return $driver === 'mysql';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $databaseConfig = $this->getDatabaseConfig();
        $defaultConnection = $databaseConfig['default'] ?? 'mysql';
        $connections = $databaseConfig['connections'] ?? [];

        foreach ($connections as $name => $connection) {
            if (! isset($connection['driver']) || $connection['driver'] !== 'mysql') {
                continue;
            }

            $host = $connection['host'] ?? '';
            $unixSocket = $connection['unix_socket'] ?? '';

            // Check if using localhost/127.0.0.1 without unix_socket
            if (($host === 'localhost' || $host === '127.0.0.1') && empty($unixSocket)) {
                $severity = $name === $defaultConnection ? Severity::Medium : Severity::Low;

                $issues[] = $this->createIssue(
                    message: "MySQL connection '{$name}' uses TCP on localhost instead of Unix socket",
                    location: new Location($this->basePath.'/config/database.php', $this->findLineInConfig('database', $name)),
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

    private function getDatabaseConfig(): array
    {
        $configFile = $this->basePath.'/config/database.php';

        if (! file_exists($configFile)) {
            return [];
        }

        return include $configFile;
    }

    private function findLineInConfig(string $file, string $key): int
    {
        $configFile = $this->basePath.'/config/'.$file.'.php';

        if (! file_exists($configFile)) {
            return 1;
        }

        $content = file_get_contents($configFile);

        if ($content === false) {
            return 1;
        }

        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            if (str_contains($line, "'{$key}'") || str_contains($line, "\"{$key}\"")) {
                return $lineNumber + 1;
            }
        }

        return 1;
    }

    private function getEnvironment(): string
    {
        $envFile = $this->basePath.'/.env';

        if (! file_exists($envFile)) {
            return 'production';
        }

        $content = file_get_contents($envFile);

        if ($content === false) {
            return 'production';
        }

        if (preg_match('/^APP_ENV\s*=\s*(\w+)/m', $content, $matches)) {
            return $matches[1];
        }

        return 'production';
    }
}
