<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use RuntimeException;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

class ComposerValidator
{
    /**
     * Execute `composer validate --no-check-publish` in the given working directory.
     */
    public function validate(string $workingDirectory): ComposerValidatorResult
    {
        $composer = $this->findComposerBinary($workingDirectory);

        if ($composer === null) {
            throw new RuntimeException('No composer binary could be located.');
        }

        $process = new Process(array_merge($composer, ['validate', '--no-check-publish']), $workingDirectory);
        $process->run();

        return new ComposerValidatorResult($process->isSuccessful(), $process->getOutput().$process->getErrorOutput());
    }

    /**
     * Determine whether a composer binary can be located for the given working directory.
     */
    public function isAvailable(string $workingDirectory): bool
    {
        return $this->findComposerBinary($workingDirectory) !== null;
    }

    /**
     * Determine the composer binary to execute.
     *
     * @return list<string>|null Null when no composer binary can be located.
     */
    private function findComposerBinary(string $workingDirectory): ?array
    {
        if (file_exists($workingDirectory.'/composer.phar')) {
            return [PHP_BINARY, $workingDirectory.'/composer.phar'];
        }

        $binary = (new ExecutableFinder)->find('composer');

        return $binary !== null ? [$binary] : null;
    }
}
