<?php

declare(strict_types=1);

namespace ShieldCI\Support\SecurityAdvisories;

use InvalidArgumentException;
use ShieldCI\AnalyzersCore\Support\FileParser;

class ComposerDependencyReader
{
    /**
     * @return array<string, array{version: string, time: string|null}>
     */
    public function read(string $composerLockPath): array
    {
        if (! is_file($composerLockPath)) {
            throw new InvalidArgumentException('composer.lock file not found.');
        }

        $content = FileParser::readFile($composerLockPath);
        if ($content === null) {
            throw new InvalidArgumentException('Unable to read composer.lock file.');
        }

        $decoded = json_decode($content, true);
        if (json_last_error() !== JSON_ERROR_NONE || ! is_array($decoded)) {
            throw new InvalidArgumentException('composer.lock file is invalid JSON.');
        }

        $packages = [];
        foreach (['packages', 'packages-dev'] as $section) {
            if (! isset($decoded[$section]) || ! is_array($decoded[$section])) {
                continue;
            }

            foreach ($decoded[$section] as $package) {
                if (! is_array($package)) {
                    continue;
                }

                if (! isset($package['name'], $package['version']) || ! is_string($package['name']) || ! is_string($package['version'])) {
                    continue;
                }

                $version = ltrim($package['version'], 'v');
                $packages[$package['name']] = [
                    'version' => $version,
                    'time' => isset($package['time']) && is_string($package['time']) ? $package['time'] : null,
                ];
            }
        }

        return $packages;
    }
}
