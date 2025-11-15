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
}
