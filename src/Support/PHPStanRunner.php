<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Illuminate\Support\Collection;
use Symfony\Component\Process\Process;

/**
 * Runs PHPStan analysis on user's application code.
 *
 * Uses Larastan and Carbon extensions when available to properly handle
 * Laravel's magic methods and Carbon's iterator types, reducing false positives.
 */
class PHPStanRunner
{
    /**
     * Known false positive patterns to suppress.
     *
     * Most Laravel-specific false positives are handled by including Larastan's
     * extension.neon at analysis time. This array is reserved for edge cases
     * that extensions don't cover.
     *
     * @var array<string>
     */
    private const KNOWN_FALSE_POSITIVES = [
        // HigherOrderProxy is too magical for Larastan/PHPStan to understand
        // @see https://github.com/larastan/larastan/blob/2e9ed291bdc1969e7f270fb33c9cdf3c912daeb2/docs/errors-to-ignore.md
        '#Call to an undefined method Illuminate\\\\Support\\\\HigherOrder#',

        // Faker uses __call() and __get() magic methods to proxy calls through providers.
        // PHPStan cannot resolve these dynamic method/property lookups.
        '#on an unknown class Faker\\\\#',
        '#(undefined method|undefined static method|undefined property) Faker\\\\#',
    ];

    /**
     * @var array<string, mixed>|null
     */
    private ?array $result = null;

    /**
     * Path to temporary config file, if generated.
     */
    private ?string $tempConfigFile = null;

    public function __construct(
        private string $basePath
    ) {}

    /**
     * Run PHPStan analysis on specified paths.
     *
     * Generates a temporary configuration file that includes Larastan and Carbon
     * extensions when available, enabling proper analysis of Laravel code.
     *
     * @param  string|array<string>  $paths
     * @return $this
     */
    public function analyze(string|array $paths, int $level = 5): self
    {
        $paths = is_array($paths) ? $paths : [$paths];

        // Generate config with Larastan/Carbon extensions
        $configFile = $this->generateConfig($level);
        $this->tempConfigFile = $configFile;

        try {
            // Build PHPStan command
            $command = [
                $this->basePath.'/vendor/bin/phpstan',
                'analyse',
                '--configuration='.$configFile,
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
        } finally {
            // Clean up temp config file
            $this->cleanupTempConfig();
        }

        return $this;
    }

    /**
     * Generate a temporary PHPStan configuration file with Larastan extensions.
     *
     * The generated config includes:
     * - Larastan extension (for Eloquent magic methods, facades, etc.)
     * - Carbon extension (for Carbon types and iterators)
     * - User's existing config if present
     */
    private function generateConfig(int $level): string
    {
        $includes = [];

        // Include Larastan extension if available
        $larastanExtension = $this->basePath.'/vendor/larastan/larastan/extension.neon';
        if (file_exists($larastanExtension)) {
            $includes[] = $larastanExtension;
        }

        // Include Carbon extension if available
        $carbonExtension = $this->basePath.'/vendor/nesbot/carbon/extension.neon';
        if (file_exists($carbonExtension)) {
            $includes[] = $carbonExtension;
        }

        // Include user's existing config if present
        $userConfig = $this->basePath.'/phpstan.neon';
        $userConfigDist = $this->basePath.'/phpstan.neon.dist';

        if (file_exists($userConfig)) {
            $includes[] = $userConfig;
        } elseif (file_exists($userConfigDist)) {
            $includes[] = $userConfigDist;
        }

        // Generate NEON content
        $neon = $this->buildNeonConfig($includes, $level);

        // Write to temp file
        $baseTempFile = tempnam(sys_get_temp_dir(), 'shieldci_phpstan_');
        if ($baseTempFile === false) {
            // Fallback if tempnam fails
            $baseTempFile = sys_get_temp_dir().'/shieldci_phpstan_'.uniqid();
        }

        $tempFile = $baseTempFile.'.neon';
        file_put_contents($tempFile, $neon);

        // Clean up the base temp file created by tempnam (without .neon extension)
        if ($baseTempFile !== $tempFile && file_exists($baseTempFile)) {
            unlink($baseTempFile);
        }

        return $tempFile;
    }

    /**
     * Build NEON config string from includes and parameters.
     *
     * @param  array<string>  $includes
     */
    private function buildNeonConfig(array $includes, int $level): string
    {
        $lines = [];

        if ($includes !== []) {
            $lines[] = 'includes:';
            foreach ($includes as $include) {
                $lines[] = '    - '.$include;
            }
            $lines[] = '';
        }

        $lines[] = 'parameters:';
        $lines[] = '    level: '.$level;

        return implode("\n", $lines);
    }

    /**
     * Clean up the temporary config file if it exists.
     */
    private function cleanupTempConfig(): void
    {
        if ($this->tempConfigFile !== null && file_exists($this->tempConfigFile)) {
            unlink($this->tempConfigFile);
            $this->tempConfigFile = null;
        }
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
