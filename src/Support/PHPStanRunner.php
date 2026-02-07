<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Illuminate\Support\Collection;
use Symfony\Component\Process\Process;

/**
 * Runs PHPStan analysis on user's application code.
 */
class PHPStanRunner
{
    /**
     * Known false positive patterns to suppress.
     * These are issues PHPStan reports incorrectly for well-known libraries.
     *
     * @var array<string>
     */
    private const KNOWN_FALSE_POSITIVES = [
        // Carbon\CarbonPeriod implements Iterator but PHPStan doesn't recognize it
        '#Argument of an invalid type Carbon\\\\CarbonPeriod supplied for foreach#',
    ];

    /**
     * @var array<string, mixed>|null
     */
    private ?array $result = null;

    public function __construct(
        private string $basePath
    ) {}

    /**
     * Run PHPStan analysis on specified paths.
     *
     * @param  string|array<string>  $paths
     * @return $this
     */
    public function analyze(string|array $paths, int $level = 5): self
    {
        $paths = is_array($paths) ? $paths : [$paths];

        // Build PHPStan command
        $command = [
            $this->basePath.'/vendor/bin/phpstan',
            'analyse',
            '--level='.$level,
            '--error-format=json',
            '--no-progress',
            '--no-interaction',
        ];

        // Add paths
        foreach ($paths as $path) {
            $command[] = $path;
        }

        // Run PHPStan
        $process = new Process($command, $this->basePath);
        $process->setTimeout(300); // 5 minutes timeout
        $process->run();

        // Parse JSON output
        $output = $process->getOutput();
        $this->result = json_decode($output, true);

        if (! is_array($this->result)) {
            $this->result = ['files' => []];
        }

        return $this;
    }

    /**
     * Get all issues from PHPStan analysis.
     *
     * @return Collection<int, array{file: string, line: int, message: string}>
     */
    public function getIssues(): Collection
    {
        if ($this->result === null || ! isset($this->result['files'])) {
            return collect();
        }

        $issues = [];

        foreach ($this->result['files'] as $file => $fileData) {
            if (! is_string($file) || ! is_array($fileData) || ! isset($fileData['messages']) || ! is_array($fileData['messages'])) {
                continue;
            }

            foreach ($fileData['messages'] as $message) {
                if (! is_array($message)) {
                    continue;
                }

                $issues[] = [
                    'file' => $file,
                    'line' => (int) ($message['line'] ?? 0),
                    'message' => (string) ($message['message'] ?? ''),
                ];
            }
        }

        return $this->filterKnownFalsePositives(collect($issues));
    }

    /**
     * Filter out known false positives from issues.
     *
     * @param  Collection<int, array{file: string, line: int, message: string}>  $issues
     * @return Collection<int, array{file: string, line: int, message: string}>
     */
    private function filterKnownFalsePositives(Collection $issues): Collection
    {
        return $issues->reject(function (array $issue) {
            foreach (self::KNOWN_FALSE_POSITIVES as $pattern) {
                if (preg_match($pattern, $issue['message']) === 1) {
                    return true; // Reject this issue (it's a known false positive)
                }
            }

            return false;
        });
    }

    /**
     * Filter issues by message pattern (wildcard match).
     *
     * @param  string|array<string>  $patterns
     * @return Collection<int, array{file: string, line: int, message: string}>
     */
    public function filterByPattern(string|array $patterns): Collection
    {
        $patterns = is_array($patterns) ? $patterns : [$patterns];

        return $this->getIssues()->filter(function (array $issue) use ($patterns) {
            foreach ($patterns as $pattern) {
                if (\Illuminate\Support\Str::is($pattern, $issue['message'])) {
                    return true;
                }
            }

            return false;
        });
    }

    /**
     * Filter issues by regex pattern.
     *
     * @return Collection<int, array{file: string, line: int, message: string}>
     */
    public function filterByRegex(string $regex): Collection
    {
        return $this->getIssues()->filter(function (array $issue) use ($regex) {
            return preg_match($regex, $issue['message']) === 1;
        });
    }

    /**
     * Filter issues containing specific text.
     *
     * @param  string|array<string>  $search
     * @return Collection<int, array{file: string, line: int, message: string}>
     */
    public function filterByText(string|array $search): Collection
    {
        $search = is_array($search) ? $search : [$search];

        return $this->getIssues()->filter(function (array $issue) use ($search) {
            foreach ($search as $text) {
                if (str_contains($issue['message'], $text)) {
                    return true;
                }
            }

            return false;
        });
    }

    /**
     * Check if PHPStan is available in the project.
     */
    public function isAvailable(): bool
    {
        return file_exists($this->basePath.'/vendor/bin/phpstan');
    }
}
