<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Illuminate\Support\Composer as BaseComposer;

/**
 * Extended Composer helper with additional functionality.
 *
 * Extends Laravel's base Composer class to add methods for
 * dependency checking and analysis.
 */
class Composer extends BaseComposer
{
    /**
     * Run a dry run Composer install.
     *
     * @param  array<int, string>  $options
     */
    public function installDryRun(array $options = []): string
    {
        return $this->runCommand(array_merge(['install', '--dry-run'], $options));
    }

    /**
     * Run a dry run Composer update.
     *
     * @param  array<int, string>  $options
     */
    public function updateDryRun(array $options = []): string
    {
        return $this->runCommand(array_merge(['update', '--dry-run'], $options));
    }

    /**
     * Run any Composer command and get the output.
     *
     * @param  array<int, string>  $options
     */
    public function runCommand(array $options = [], bool $includeErrorOutput = true): string
    {
        $composer = $this->findComposer();

        $command = array_merge(
            (array) $composer,
            $options
        );

        $process = $this->getProcess($command);

        $process->run();

        return $process->getOutput().($includeErrorOutput ? $process->getErrorOutput() : '');
    }

    /**
     * Get the composer lock file location.
     */
    public function getLockFile(): ?string
    {
        $lockPath = $this->workingPath.'/composer.lock';

        if ($this->files->exists($lockPath)) {
            return $lockPath;
        }

        return null;
    }

    /**
     * Get the composer.json file location.
     */
    public function getJsonFile(): ?string
    {
        $jsonPath = $this->workingPath.'/composer.json';

        if ($this->files->exists($jsonPath)) {
            return $jsonPath;
        }

        return null;
    }

    /**
     * Get the parsed composer.json content.
     *
     * @return array<string, mixed>|null
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function getJson(): ?array
    {
        $jsonFile = $this->getJsonFile();

        if ($jsonFile === null) {
            return null;
        }

        $content = $this->files->get($jsonFile);

        /** @var array<string, mixed>|null */
        return json_decode($content, true);
    }

    /**
     * Find the line number where a package is defined in composer.lock.
     *
     * Searches for the package name in the composer.lock file and returns
     * the line number where it's defined (1-indexed).
     *
     * Format: "name": "vendor/package"
     *
     * @param  string  $composerLockPath  Path to composer.lock file
     * @param  string  $packageName  Composer package name (e.g., "vendor/package")
     * @return int Line number (1-indexed) or 1 if not found
     */
    public static function findPackageLineNumber(string $composerLockPath, string $packageName): int
    {
        if (! file_exists($composerLockPath)) {
            return 1;
        }

        $lines = file($composerLockPath, FILE_IGNORE_NEW_LINES);

        if ($lines === false || empty($lines)) {
            return 1;
        }

        foreach ($lines as $lineNumber => $line) {
            // Look for "name": "package-name" pattern in composer.lock
            if (preg_match('/"name"\s*:\s*"'.preg_quote($packageName, '/').'"/i', $line)) {
                // Return the line number (1-indexed)
                return $lineNumber + 1;
            }
        }

        // Fallback to line 1 if package not found
        return 1;
    }
}
