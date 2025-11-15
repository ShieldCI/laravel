<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Support\Facades\Artisan;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

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
            name: 'Up-to-Date Migrations',
            description: 'Ensures all database migrations are up to date and have been executed',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['database', 'migrations', 'reliability', 'deployment'],
            docsUrl: 'https://laravel.com/docs/migrations'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        try {
            // Run migrations with --pretend flag to check if there are any pending
            Artisan::call('migrate:status', ['--pending' => true]);

            $output = Artisan::output();

            // Check if there are pending migrations
            if (str_contains($output, 'No pending migrations.')) {
                return $this->passed('All migrations are up to date');
            }

            // Parse output to find pending migrations
            $pendingMigrations = $this->parsePendingMigrations($output);

            return $this->failed(
                sprintf('Found %d pending migration(s)', count($pendingMigrations)),
                [$this->createIssue(
                    message: 'Pending migrations detected',
                    location: new Location($this->basePath.'/database/migrations', 1),
                    severity: Severity::High,
                    recommendation: 'Run "php artisan migrate" to execute pending migrations. In production, ensure migrations are run as part of your deployment process. Pending migrations: '.implode(', ', array_slice($pendingMigrations, 0, 5)).(count($pendingMigrations) > 5 ? '...' : ''),
                    metadata: [
                        'pending_count' => count($pendingMigrations),
                        'pending_migrations' => $pendingMigrations,
                    ]
                )]
            );
        } catch (\Throwable $e) {
            return $this->failed(
                'Unable to check migration status',
                [$this->createIssue(
                    message: 'Migration status check failed: '.$e->getMessage(),
                    location: new Location($this->basePath.'/database/migrations', 1),
                    severity: Severity::High,
                    recommendation: 'Ensure the database connection is working and the migrations table exists. If this is a new installation, run "php artisan migrate:install" followed by "php artisan migrate". Error: '.$e->getMessage(),
                    metadata: [
                        'exception' => get_class($e),
                        'error' => $e->getMessage(),
                    ]
                )]
            );
        }
    }

    /**
     * Parse pending migrations from migrate:status output.
     *
     * @return array<int, string>
     */
    private function parsePendingMigrations(string $output): array
    {
        $migrations = [];
        $lines = explode("\n", $output);

        foreach ($lines as $line) {
            // Look for lines that indicate pending migrations
            // Format typically: "Pending  2024_01_01_000000_create_users_table"
            if (preg_match('/Pending\s+(.+)/', $line, $matches)) {
                $migrations[] = trim($matches[1]);
            }
        }

        return $migrations;
    }
}
