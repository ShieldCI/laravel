<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

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
    /**
     * Migration status checks are deployment-specific, not applicable in CI.
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'up-to-date-migrations',
            name: 'Up-to-Date Migrations Analyzer',
            description: 'Ensures all database migrations are up to date and have been executed',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['database', 'migrations', 'reliability', 'deployment'],
            docsUrl: 'https://docs.shieldci.com/analyzers/reliability/up-to-date-migrations',
            timeToFix: 5
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $migrationsPath = $this->getMigrationsPath();

        // Check if Artisan facade is available
        if (! class_exists(Artisan::class)) {
            return $this->warning(
                'Laravel Artisan facade not available',
                [$this->createIssueWithSnippet(
                    message: 'Cannot check migration status - Artisan facade not found',
                    filePath: $migrationsPath,
                    lineNumber: null,
                    severity: Severity::Medium,
                    recommendation: 'Ensure Laravel is properly bootstrapped. Migration status checks require the Artisan facade to be available.',
                    code: 'artisan-unavailable',
                )]
            );
        }

        try {
            // Check if migrations table exists
            if (! Schema::hasTable('migrations')) {
                return $this->failed(
                    'Migrations table does not exist',
                    [$this->createIssueWithSnippet(
                        message: 'The migrations table has not been created yet',
                        filePath: $migrationsPath,
                        lineNumber: null,
                        severity: Severity::High,
                        recommendation: 'This appears to be a new installation. Run "php artisan migrate:install" to create the migrations table, then run "php artisan migrate" to execute all migrations.',
                        code: 'migrations-table-missing',
                        metadata: [
                            'table' => 'migrations',
                            'exists' => false,
                        ]
                    )]
                );
            }

            // Run migrations with --pending flag to check if there are any pending
            Artisan::call('migrate:status', ['--pending' => true, '--no-interaction' => true]);

            $output = Artisan::output();

            // Validate output is a string
            if (! is_string($output)) {
                return $this->error(
                    'Unable to check migration status - invalid Artisan output',
                    []
                );
            }

            // Parse output to find pending migrations
            $pendingMigrations = $this->parsePendingMigrations($output);

            // If no pending migrations found, all migrations are up to date
            // Note: When there are no pending migrations, the output only shows the header
            // and does NOT contain "Pending" status anywhere
            if (empty($pendingMigrations)) {
                return $this->passed('All migrations are up to date');
            }

            return $this->failed(
                sprintf('Found %d pending migration(s)', count($pendingMigrations)),
                [$this->createIssueWithSnippet(
                    message: 'Pending migrations detected',
                    filePath: $migrationsPath,
                    lineNumber: null,
                    severity: Severity::High,
                    recommendation: $this->getPendingMigrationsRecommendation($pendingMigrations),
                    code: 'pending-migrations',
                    metadata: [
                        'pending_count' => count($pendingMigrations),
                        'pending_migrations' => $pendingMigrations,
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
                        severity: Severity::High,
                        recommendation: $this->getDatabaseErrorRecommendation($e),
                        code: 'database-error',
                        metadata: [
                            'exception' => get_class($e),
                            'error' => $e->getMessage(),
                            'error_type' => 'database_connection',
                        ]
                    )]
                )
                : $this->failed(
                    'Unable to check migration status',
                    [$this->createIssueWithSnippet(
                        message: 'Migration status check failed: '.$e->getMessage(),
                        filePath: $migrationsPath,
                        lineNumber: null,
                        severity: Severity::High,
                        recommendation: 'Ensure the database connection is working and the migrations table exists. If this is a new installation, run "php artisan migrate:install" followed by "php artisan migrate". Error: '.$e->getMessage(),
                        code: 'migration-check-error',
                        metadata: [
                            'exception' => get_class($e),
                            'error' => $e->getMessage(),
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
                if (is_string($path) && $path !== '') {
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
     * Parse pending migrations from migrate:status output.
     *
     * @return array<int, string>
     */
    private function parsePendingMigrations(string $output): array
    {
        $migrations = [];

        if (! str_contains($output, 'Pending')) {
            return [];
        }

        foreach (explode("\n", $output) as $line) {
            if (! str_contains($line, 'Pending')) {
                continue;
            }

            // Skip header lines
            if (str_contains($line, 'Migration') || str_contains($line, 'Batch')) {
                continue;
            }

            // Extract migration name (first column)
            $migration = trim(strtok($line, " \t"));

            if ($migration !== '') {
                $migrations[] = $migration;
            }
        }

        return $migrations;
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
            $e->getMessage()
        );
    }
}
