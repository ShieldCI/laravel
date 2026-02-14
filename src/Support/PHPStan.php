<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Symfony\Component\Process\Process;

/**
 * PHPStan integration for running static analysis and parsing results.
 */
class PHPStan
{
    /**
     * The PHPStan analysis result.
     *
     * @var array<string, mixed>|null
     */
    public ?array $result = null;

    /**
     * The project root path.
     */
    private ?string $rootPath = null;

    /**
     * The PHPStan configuration file path.
     */
    private ?string $configPath = null;

    /**
     * Parse the PHPStan analysis and get the results containing the search string.
     *
     * @param  string|array<int, string>  $search
     * @return array<int, array{path: string, line: int, message: string}>
     */
    public function parseAnalysis(string|array $search): array
    {
        if (! isset($this->result['files'])) {
            return [];
        }

        /** @var array<string, array{messages: array<int, array{line: int, message: string}>}> */
        $files = $this->result['files'];

        /** @phpstan-ignore-next-line Collection methods preserve array structure */
        return collect($files)->map(function ($fileAnalysis, $path) use ($search) {
            /** @var string $path */
            return collect($fileAnalysis['messages'])->filter(function ($message) use ($search) {
                /** @var array{line: int, message: string} $message */
                return Str::contains($message['message'], $search);
            })->map(function ($message) use ($path) {
                /** @var array{line: int, message: string} $message */
                return [
                    'path' => $path,
                    'line' => $message['line'],
                    'message' => $message['message'],
                ];
            })->values()->toArray();
        })->filter()->flatten(1)->toArray();
    }

    /**
     * Parse the PHPStan analysis and get the results matching the pattern.
     *
     * @param  string|array<int, string>  $pattern
     * @return array<int, array{path: string, line: int, message: string}>
     */
    public function match(string|array $pattern): array
    {
        if (! isset($this->result['files'])) {
            return [];
        }

        /** @var array<string, array{messages: array<int, array{line: int, message: string}>}> */
        $files = $this->result['files'];

        /** @phpstan-ignore-next-line Collection methods preserve array structure */
        return collect($files)->map(function ($fileAnalysis, $path) use ($pattern) {
            /** @var string $path */
            return collect($fileAnalysis['messages'])->filter(function ($message) use ($pattern) {
                /** @var array{line: int, message: string} $message */
                return Str::is($pattern, $message['message']);
            })->map(function ($message) use ($path) {
                /** @var array{line: int, message: string} $message */
                return [
                    'path' => $path,
                    'line' => $message['line'],
                    'message' => $message['message'],
                ];
            })->values()->toArray();
        })->filter()->flatten(1)->toArray();
    }

    /**
     * Parse the PHPStan analysis and get the results matching the regex pattern.
     *
     * @return array<int, array{path: string, line: int, message: string}>
     */
    public function pregMatch(string $pattern): array
    {
        if (! isset($this->result['files'])) {
            return [];
        }

        /** @var array<string, array{messages: array<int, array{line: int, message: string}>}> */
        $files = $this->result['files'];

        /** @phpstan-ignore-next-line Collection methods preserve array structure */
        return collect($files)->map(function ($fileAnalysis, $path) use ($pattern) {
            /** @var string $path */
            return collect($fileAnalysis['messages'])->filter(function ($message) use ($pattern) {
                /** @var array{line: int, message: string} $message */
                return preg_match($pattern, $message['message']) === 1;
            })->map(function ($message) use ($path) {
                /** @var array{line: int, message: string} $message */
                return [
                    'path' => $path,
                    'line' => $message['line'],
                    'message' => $message['message'],
                ];
            })->values()->toArray();
        })->filter()->flatten(1)->toArray();
    }

    /**
     * Run the PHPStan analysis and get the output.
     *
     * @param  string|array<int, string>  $paths
     * @return $this
     */
    public function start(string|array $paths, ?string $configPath = null): self
    {
        $configPath = $configPath ?? $this->configPath ?? $this->getDefaultConfigPath();

        $options = ['analyse', '--configuration='.$configPath];

        $options = array_merge($options, $this->getPHPStanOptions());

        foreach (Arr::wrap($paths) as $path) {
            $options[] = $path;
        }

        $output = $this->runCommand($options, false);
        $this->result = json_decode($output, true);

        return $this;
    }

    /**
     * Run any PHPStan command and get the output.
     *
     * @param  array<int, string>  $options
     */
    public function runCommand(array $options = [], bool $includeErrorOutput = true): string
    {
        $phpStan = $this->findPHPStan();

        $command = array_merge((array) $phpStan, $options);

        $process = $this->getProcess($command);

        $process->run();

        return $process->getOutput().($includeErrorOutput ? $process->getErrorOutput() : '');
    }

    /**
     * Set the PHPStan configuration file path.
     */
    public function setConfigPath(string $configPath): self
    {
        $this->configPath = $configPath;

        return $this;
    }

    /**
     * Set the root path used by the class.
     */
    public function setRootPath(string $path): self
    {
        $realPath = realpath($path);
        $this->rootPath = $realPath !== false ? $realPath : $path;

        return $this;
    }

    /**
     * Get the PHPStan command for the environment.
     *
     * @return array<int, string>
     */
    protected function findPHPStan(): array
    {
        $rootPath = $this->rootPath ?? base_path();

        return [$rootPath.'/vendor/bin/phpstan'];
    }

    /**
     * Get a new Symfony process instance.
     *
     * @param  array<int, string>  $command
     */
    protected function getProcess(array $command): Process
    {
        $rootPath = $this->rootPath ?? base_path();

        return (new Process($command, $rootPath))->setTimeout(null);
    }

    /**
     * Get default PHPStan runtime configurations.
     *
     * @return array<int, string>
     */
    protected function getPHPStanOptions(): array
    {
        /** @var array<int, string> */
        $result = [];

        /** @var array<string, string|bool> */
        $configs = config('shieldci.analyzers.reliability.phpstan.options', [
            '--error-format' => 'json',
            '--no-progress' => true,
        ]);

        foreach ($configs as $name => $value) {
            $option = is_bool($value) ? (string) $name : implode('=', [(string) $name, (string) $value]);
            $result[] = $option;
        }

        return $result;
    }

    /**
     * Get the default PHPStan configuration file path.
     */
    protected function getDefaultConfigPath(): string
    {
        return __DIR__.'/../../phpstan-analyzers.neon';
    }
}
