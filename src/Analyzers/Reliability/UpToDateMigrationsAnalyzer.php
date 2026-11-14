<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Database\Migrations\Migrator;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Concerns\SanitizesErrorMessages;

/**
 * Checks that all migrations are up to date.
 *
 * Checks for:
 * - No pending migrations
 * - Database schema is in sync with migration files
 * - Migrations table exists and is accessible
 */
class UpToDateMigrationsAnalyzer extends AbstractFileAnalyzer
{
    use SanitizesErrorMessages;

    /**
     * Migration status checks are deployment-specific, not applicable in CI.
     */
    public static bool $runInCI = false;

    public function shouldRun(): bool
    {
        return $this->migratorIsBound();
    }

    public function getSkipReason(): string
    {
        if (! $this->migratorIsBound()) {
            return 'Laravel migrator not available. Ensure Laravel is properly bootstrapped.';
        }

        return 'Unknown reason';
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'up-to-date-migrations',
            name: 'Up-to-Date Migrations Analyzer',
            description: 'Ensures all database migrations are up to date and have been executed',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['database', 'migrations', 'reliability', 'deployment'],
            timeToFix: 5
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $migrationsPath = $this->getMigrationsPath();

        try {
            $migrator = $this->resolveMigrator();

            // The repository is built from config('database.migrations'), so this checks the
            // configured table rather than assuming it is named "migrations".
            if (! $migrator->repositoryExists()) {
                return $this->resultBySeverity(
                    'Migrations table does not exist',
                    [$this->createIssueWithSnippet(
                        message: 'The migrations table has not been created yet',
                        filePath: $migrationsPath,
                        lineNumber: null,
                        severity: $this->metadata()->severity,
                        recommendation: 'This appears to be a new installation. Run "php artisan migrate:install" to create the migrations table, then run "php artisan migrate" to execute all migrations.',
                        metadata: [
                            'table' => $this->migrationsTableName(),
                            'exists' => false,
                            'code' => 'migrations-table-missing',
                        ]
                    )]
                );
            }

            $pendingMigrations = $this->pendingMigrations($migrator);

            if ($pendingMigrations === []) {
                return $this->passed('All migrations are up to date');
            }

            return $this->resultBySeverity(
                sprintf('Found %d pending migration(s)', count($pendingMigrations)),
                [$this->createIssueWithSnippet(
                    message: 'Pending migrations detected',
                    filePath: $migrationsPath,
                    lineNumber: null,
                    severity: Severity::High,
                    recommendation: $this->getPendingMigrationsRecommendation($pendingMigrations),
                    metadata: [
                        'pending_count' => count($pendingMigrations),
                        'pending_migrations' => $pendingMigrations,
                        'code' => 'pending-migrations',
                    ]
                )]
            );
        } catch (\Throwable $e) {
            // Differentiate between database connection errors and other errors
            $isDatabaseError = $this->isDatabaseError($e);

            return $isDatabaseError
                ? $this->failed(
                    'Database connection error while checking migration status',
                    [$this->createIssueWithSnippet(
                        message: 'Migration status check failed due to database connection issue',
                        filePath: $migrationsPath,
                        lineNumber: null,
                        severity: $this->metadata()->severity,
                        recommendation: $this->getDatabaseErrorRecommendation($e),
                        metadata: [
                            'exception' => get_class($e),
                            'error' => $this->sanitizedErrorMessage($e->getMessage()),
                            'error_type' => 'database_connection',
                            'code' => 'database-error',
                        ]
                    )]
                )
                : $this->failed(
                    'Unable to check migration status',
                    [$this->createIssueWithSnippet(
                        message: 'Migration status check failed: '.$this->sanitizedErrorMessage($e->getMessage()),
                        filePath: $migrationsPath,
                        lineNumber: null,
                        severity: $this->metadata()->severity,
                        recommendation: 'Ensure the database connection is working and the migrations table exists. If this is a new installation, run "php artisan migrate:install" followed by "php artisan migrate". Error: '.$this->sanitizedErrorMessage($e->getMessage()),
                        metadata: [
                            'exception' => get_class($e),
                            'error' => $this->sanitizedErrorMessage($e->getMessage()),
                            'code' => 'migration-check-error',
                        ]
                    )]
                );
        }
    }

    /**
     * Get the path to the database migrations directory.
     */
    private function getMigrationsPath(): string
    {
        // Try using Laravel helper if available
        if (function_exists('database_path')) {
            try {
                $path = database_path('migrations');
                if ($path !== '') {
                    return $path;
                }
            } catch (\Throwable $e) {
                // Fall through to default
            }
        }

        // Fallback to default path
        return $this->buildPath('database', 'migrations');
    }

    /**
     * Whether the container binds a migrator. Only its absence skips the analyzer; a binding
     * that fails to resolve is reported by runAnalysis().
     */
    private function migratorIsBound(): bool
    {
        return function_exists('app') && app()->bound('migrator');
    }

    /**
     * Resolve the application's migrator, letting resolution errors propagate.
     */
    private function resolveMigrator(): Migrator
    {
        $migrator = app('migrator');

        if (! $migrator instanceof Migrator) {
            throw new \UnexpectedValueException(sprintf(
                'The migrator binding resolved to %s, not %s.',
                get_debug_type($migrator),
                Migrator::class
            ));
        }

        return $migrator;
    }

    /**
     * List the migrations that have not run, as migrate:status does: every migration file in the
     * paths registered on the migrator plus the application's database/migrations directory,
     * in name order, minus the ones the repository has recorded.
     *
     * @return array<int, string>
     */
    private function pendingMigrations(Migrator $migrator): array
    {
        $paths = array_merge($migrator->paths(), [$this->getMigrationsPath()]);

        $ran = $migrator->getRepository()->getRan();

        $pending = [];

        foreach (array_keys($migrator->getMigrationFiles($paths)) as $name) {
            // A digit-only name comes back as an integer key; the repository stores strings.
            $name = (string) $name;

            if (! in_array($name, $ran, true)) {
                $pending[] = $name;
            }
        }

        return $pending;
    }

    /**
     * The configured migrations table name, read the way MigrationServiceProvider does: either a
     * string or an array with a "table" key.
     */
    private function migrationsTableName(): string
    {
        $config = config('database.migrations');

        if (is_array($config)) {
            $config = $config['table'] ?? null;
        }

        return is_string($config) && $config !== '' ? $config : 'migrations';
    }

    /**
     * Get recommendation message for pending migrations.
     *
     * @param  array<int, string>  $pendingMigrations
     */
    private function getPendingMigrationsRecommendation(array $pendingMigrations): string
    {
        $migrationList = array_slice($pendingMigrations, 0, 5);
        $migrationCount = count($pendingMigrations);
        $displayedCount = count($migrationList);

        $migrationText = implode(', ', $migrationList);
        if ($migrationCount > $displayedCount) {
            $migrationText .= '...';
        }

        return sprintf(
            'Run "php artisan migrate" to execute pending migrations. In production, ensure migrations are run as part of your deployment process. Pending migrations: %s',
            $migrationText
        );
    }

    /**
     * Check if exception is a database connection error.
     */
    private function isDatabaseError(\Throwable $e): bool
    {
        $message = strtolower($e->getMessage());
        $className = get_class($e);

        // Check for common database error patterns
        $databaseErrorPatterns = [
            'connection',
            'could not find driver',
            'access denied',
            'unknown database',
            'connection refused',
            'sqlstate',
            'pdoexception',
            'queryexception',
        ];

        foreach ($databaseErrorPatterns as $pattern) {
            if (str_contains($message, $pattern) || str_contains(strtolower($className), $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get recommendation message for database connection errors.
     */
    private function getDatabaseErrorRecommendation(\Throwable $e): string
    {
        return sprintf(
            'Database connection error detected. Ensure your database configuration is correct in config/database.php and .env file. '.
            'Verify the database server is running and accessible. If this is a new installation, run "php artisan migrate:install" to create the migrations table. '.
            'Error: %s',
            $this->sanitizedErrorMessage($e->getMessage())
        );
    }
}
