<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Symfony\Component\Process\Process;

class ComposerValidator
{
    /**
     * Execute `composer validate --no-check-publish` in the given working directory.
     */
    public function validate(string $workingDirectory): ComposerValidatorResult
    {
        $composer = $this->findComposerBinary();
        $process = new Process(array_merge($composer, ['validate', '--no-check-publish']), $workingDirectory);
        $process->run();

        return new ComposerValidatorResult($process->isSuccessful(), $process->getOutput().$process->getErrorOutput());
    }

    /**
     * Determine the composer binary to execute.
     */
    private function findComposerBinary(): array
    {
        if (file_exists(getcwd().'/composer.phar')) {
            return [PHP_BINARY, getcwd().'/composer.phar'];
        }

        return ['composer'];
    }
}
