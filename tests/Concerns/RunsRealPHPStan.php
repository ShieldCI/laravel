<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Concerns;

/**
 * Runs an analyzer through the real PHPStan and Larastan over a fixture project.
 *
 * The fixture borrows this package's vendor directory through a symlink. Larastan boots
 * Testbench's skeleton application from that vendor, and Testbench links the skeleton's
 * own vendor to the fixture's and rewrites its bootstrap cache. Left behind, the link
 * dangles once the fixture is deleted, and a later test that checks the path with
 * is_dir() and then creates it fails with "File exists". So the skeleton is put back as
 * it was found after every run.
 */
trait RunsRealPHPStan
{
    /**
     * @param  array<string, string|false>  $files
     */
    abstract protected function createTempDirectory(array $files): string;

    /**
     * Build a fixture project from $files, hand its path to $callback, then restore the skeleton.
     *
     * @template T
     *
     * @param  array<string, string>  $files  path => contents, relative to the project root
     * @param  callable(string): T  $callback
     * @return T
     */
    protected function inRealPHPStanProject(array $files, callable $callback): mixed
    {
        $packageRoot = dirname(__DIR__, 2);
        $skeleton = $packageRoot.'/vendor/orchestra/testbench-core/laravel';
        $skeletonVendor = $skeleton.'/vendor';

        $tempDir = $this->createTempDirectory($files);
        $this->assertTrue(symlink($packageRoot.'/vendor', $tempDir.'/vendor'));

        $previousLink = is_link($skeletonVendor) ? readlink($skeletonVendor) : false;
        $cacheFiles = $this->skeletonCacheFiles($skeleton);

        try {
            return $callback($tempDir);
        } finally {
            // Only a link Testbench pointed at this fixture is removed: a real directory or
            // a link that was already there and left alone belongs to someone else.
            $currentLink = is_link($skeletonVendor) ? readlink($skeletonVendor) : false;

            // Testbench links to the resolved path, and the system temp directory sits
            // behind a symlink on macOS.
            $fixtureRoot = realpath($tempDir) ?: $tempDir;

            if ($currentLink !== false && $currentLink !== $previousLink
                && (str_starts_with($currentLink, $fixtureRoot) || str_starts_with($currentLink, $tempDir))) {
                unlink($skeletonVendor);

                if ($previousLink !== false) {
                    symlink($previousLink, $skeletonVendor);
                }
            }

            $this->restoreSkeletonCacheFiles($skeleton, $cacheFiles);
        }
    }

    /**
     * The skeleton's cached manifests, by path.
     *
     * @return array<string, string>
     */
    private function skeletonCacheFiles(string $skeleton): array
    {
        $files = [];

        foreach (glob($skeleton.'/bootstrap/cache/*.php') ?: [] as $path) {
            $contents = file_get_contents($path);

            if ($contents !== false) {
                $files[$path] = $contents;
            }
        }

        return $files;
    }

    /**
     * Put the skeleton's cached manifests back as they were, deleting any the run added.
     *
     * @param  array<string, string>  $previous
     */
    private function restoreSkeletonCacheFiles(string $skeleton, array $previous): void
    {
        $current = $this->skeletonCacheFiles($skeleton);

        foreach (array_diff_key($current, $previous) as $path => $contents) {
            unlink($path);
        }

        foreach ($previous as $path => $contents) {
            if (($current[$path] ?? null) !== $contents) {
                file_put_contents($path, $contents);
            }
        }
    }
}
