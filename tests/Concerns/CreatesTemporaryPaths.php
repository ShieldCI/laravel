<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Concerns;

/**
 * Temporary-path helpers shared by the suite's two base classes.
 *
 * Lives in a trait rather than on ShieldCI\Tests\TestCase because several Support
 * tests extend PHPUnit\Framework\TestCase directly, deliberately: they exercise
 * framework-free code and have no reason to boot an application. Nothing here
 * touches the container, so both hierarchies can use it.
 */
trait CreatesTemporaryPaths
{
    /**
     * Build a temporary path that no concurrently running worker can also produce.
     *
     * uniqid() advances monotonically inside one process, so it cannot collide with
     * itself. But it derives from the clock alone and carries nothing to tell one
     * process from another, and the suite runs several PHPUnit workers at once, so two
     * landing on the same microsecond produced the same path. The process id plus eight
     * random bytes makes that impossible rather than merely unlikely.
     *
     * Nothing is created here, so the caller stays free to create the directory itself,
     * chmod it, or append an extension for a file.
     */
    protected function uniqueTempPath(string $prefix = 'shieldci_test_'): string
    {
        return sys_get_temp_dir().'/'.$prefix.getmypid().'_'.bin2hex(random_bytes(8));
    }

    /**
     * Message from the most recent PHP error, for reporting a suppressed failure.
     */
    protected function lastErrorMessage(): string
    {
        $error = error_get_last();

        return $error['message'] ?? 'unknown error';
    }

    /**
     * Recursively remove a directory.
     */
    protected function removeDirectory(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), ['.', '..']);

        foreach ($files as $file) {
            $path = $dir.'/'.$file;

            // Handle symlinks first (is_link check before is_dir)
            if (is_link($path)) {
                unlink($path);
            } elseif (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                unlink($path);
            }
        }

        rmdir($dir);
    }
}
