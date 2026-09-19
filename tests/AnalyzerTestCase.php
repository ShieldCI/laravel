<?php

declare(strict_types=1);

namespace ShieldCI\Tests;

use Illuminate\Foundation\Application as LaravelApplication;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Status;
use ShieldCI\AnalyzersCore\Support\AstParser;

abstract class AnalyzerTestCase extends TestCase
{
    protected AnalyzerInterface $analyzer;

    protected AstParser $parser;

    protected function setUp(): void
    {
        parent::setUp();

        $this->parser = new AstParser;
    }

    /**
     * Create the analyzer instance to test.
     */
    abstract protected function createAnalyzer(): AnalyzerInterface;

    /**
     * Assert that analysis passes.
     */
    protected function assertPassed(ResultInterface $result): void
    {
        $this->assertEquals(
            Status::Passed,
            $result->getStatus(),
            "Expected analysis to pass, but got: {$result->getStatus()->value}. Message: {$result->getMessage()}"
        );
    }

    /**
     * Assert that analysis fails.
     */
    protected function assertFailed(ResultInterface $result): void
    {
        $this->assertEquals(
            Status::Failed,
            $result->getStatus(),
            "Expected analysis to fail, but got: {$result->getStatus()->value}"
        );
    }

    /**
     * Assert that analysis produces a warning.
     */
    protected function assertWarning(ResultInterface $result): void
    {
        $this->assertEquals(
            Status::Warning,
            $result->getStatus(),
            "Expected analysis to warn, but got: {$result->getStatus()->value}"
        );
    }

    /**
     * Assert that analysis was skipped.
     */
    protected function assertSkipped(ResultInterface $result): void
    {
        $this->assertEquals(
            Status::Skipped,
            $result->getStatus(),
            "Expected analysis to be skipped, but got: {$result->getStatus()->value}"
        );
    }

    /**
     * Assert that analysis produces an error.
     */
    protected function assertError(ResultInterface $result): void
    {
        $this->assertEquals(
            Status::Error,
            $result->getStatus(),
            "Expected analysis to error, but got: {$result->getStatus()->value}"
        );
    }

    /**
     * Assert that the result has a specific number of issues.
     */
    protected function assertIssueCount(int $expected, ResultInterface $result): void
    {
        $actual = count($result->getIssues());
        $this->assertEquals(
            $expected,
            $actual,
            "Expected {$expected} issues, but found {$actual}"
        );
    }

    /**
     * Assert that the result has at least one issue containing the given text.
     */
    protected function assertHasIssueContaining(string $text, ResultInterface $result): void
    {
        $found = null;
        foreach ($result->getIssues() as $issue) {
            if (str_contains($issue->message, $text)) {
                $found = $issue;
                break;
            }
        }

        $this->assertNotNull(
            $found,
            "Expected to find an issue containing '{$text}', but none found"
        );
    }

    /**
     * Create a temporary PHP file with the given code.
     */
    protected function createTempPhpFile(string $code): string
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'shieldci_test_');
        file_put_contents($tempFile, $code);

        // Register cleanup
        $this->beforeApplicationDestroyed(function () use ($tempFile) {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        });

        return $tempFile;
    }

    /**
     * Create a temporary directory with PHP files.
     *
     * @param  array<string, string|false>  $files  filename => contents (false, e.g. from a failed json_encode, is written as empty)
     */
    protected function createTempDirectory(array $files): string
    {
        $tempDir = $this->makeTempDirectory();

        foreach ($files as $filename => $content) {
            $filepath = $tempDir.'/'.$filename;
            $dirname = dirname($filepath);

            // Checked for the same reason the directory itself is: an unchecked failure
            // here emits a warning that Testbench rethrows as an ErrorException naming
            // whichever test happened to be running, which reads as a behaviour change
            // rather than a full disk or a bad permission.
            if (! is_dir($dirname) && ! @mkdir($dirname, 0755, true)) {
                throw new \RuntimeException(
                    "Unable to create fixture directory {$dirname}: {$this->lastErrorMessage()}"
                );
            }

            if (@file_put_contents($filepath, $content === false ? '' : $content) === false) {
                throw new \RuntimeException(
                    "Unable to write fixture file {$filepath}: {$this->lastErrorMessage()}"
                );
            }
        }

        return $tempDir;
    }

    /**
     * Run a callback with the application's base path pointed somewhere else.
     *
     * Analyzers extending AbstractAnalyzer resolve getBasePath() through base_path()
     * and have no setBasePath() of their own, so the application's base path is the
     * only lever. Without this they inherit Testbench's skeleton, which does ship
     * config/cache.php, config/queue.php and config/session.php.
     *
     * @template T
     *
     * @param  callable(): T  $callback
     * @return T
     */
    protected function withBasePath(string $basePath, callable $callback): mixed
    {
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($basePath);

        try {
            return $callback();
        } finally {
            $application->setBasePath($originalBasePath);
        }
    }
}
