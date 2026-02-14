<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

/**
 * Trait for classifying files by their role in a Laravel project.
 *
 * Provides helper methods to identify test files, development-only files,
 * and console commands — allowing analyzers to skip files that shouldn't
 * trigger production-focused checks.
 */
trait ClassifiesFiles
{
    /**
     * Check if file is a test file.
     */
    private function isTestFile(string $file): bool
    {
        return str_contains($file, '/tests/') ||
               str_contains($file, '/Tests/') ||
               str_ends_with($file, 'Test.php');
    }

    /**
     * Check if file is a development helper file.
     */
    private function isDevelopmentFile(string $file): bool
    {
        return str_contains($file, '/database/seeders/') ||
               str_contains($file, '/database/factories/') ||
               str_contains($file, '/database/migrations/') ||
               str_ends_with($file, 'Seeder.php') ||
               str_ends_with($file, 'Factory.php');
    }

    /**
     * Check if file is a Console Command.
     */
    private function isConsoleCommand(string $file): bool
    {
        return str_contains($file, '/Console/Commands/') ||
               str_contains($file, '/app/Console/Commands/') ||
               str_contains($file, '\\Console\\Commands\\');
    }
}
