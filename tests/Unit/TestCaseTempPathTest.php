<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Tests\TestCase;

/**
 * Guards the temporary-path helpers the whole suite depends on.
 *
 * The suite runs several PHPUnit workers at once. uniqid() advances monotonically
 * inside one process, so a collision is impossible within a worker, but it derives
 * from the clock and carries nothing to distinguish one process from another, so two
 * workers landing on the same microsecond produced the same path. That surfaced twice
 * as "mkdir(): File exists" in unrelated test files.
 */
class TestCaseTempPathTest extends TestCase
{
    #[Test]
    public function test_temp_path_is_namespaced_per_process(): void
    {
        // The property that makes a cross-worker collision impossible rather than
        // merely unlikely: two processes cannot share a process id. Asserting the
        // prefix rather than mere containment matters, because the random half is hex
        // and would otherwise satisfy a contains() check for a short pid on its own.
        $path = $this->uniqueTempPath();

        $this->assertStringStartsWith('shieldci_test_'.getmypid().'_', basename($path));
    }

    #[Test]
    public function test_temp_path_honours_a_custom_prefix(): void
    {
        $path = $this->uniqueTempPath('phpstan_runner_test_');

        $this->assertStringStartsWith('phpstan_runner_test_'.getmypid().'_', basename($path));
    }

    #[Test]
    public function test_unique_temp_path_creates_nothing(): void
    {
        // Callers that chmod the directory, or hand the path to something that insists
        // on creating it, rely on the helper being pure.
        $path = $this->uniqueTempPath();

        $this->assertFileDoesNotExist($path);
    }

    #[Test]
    public function test_repeated_paths_are_distinct(): void
    {
        $seen = [];

        for ($i = 0; $i < 5; $i++) {
            $path = $this->uniqueTempPath();

            $this->assertArrayNotHasKey($path, $seen, 'uniqueTempPath returned a duplicate path');
            $seen[$path] = true;
        }

        $this->assertCount(5, $seen);
    }

    #[Test]
    public function test_make_temp_directory_creates_a_namespaced_directory(): void
    {
        $dir = $this->makeTempDirectory();

        $this->assertDirectoryExists($dir);
        $this->assertStringStartsWith('shieldci_test_'.getmypid().'_', basename($dir));
    }
}
