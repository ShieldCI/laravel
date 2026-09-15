<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use ShieldCI\AnalyzersCore\Support\PlatformDetector;
use ShieldCI\Concerns\ReadsConfigArrays;
use Symfony\Component\Process\Process;

/**
 * Runs PHPStan analysis on user's application code.
 *
 * Uses Larastan and Carbon extensions when available to properly handle
 * Laravel's magic methods and Carbon's iterator types, reducing false positives.
 *
 * The identifier and tip keys are optional in the shape rather than required-and-
 * nullable. getIssues() always sets them, but Collection's value template is
 * invariant, so a required-key shape could not be passed to consumers that accept
 * hand-built issue arrays without either widening them or editing every caller.
 *
 * @phpstan-type PHPStanIssue array{file: string, line: int, message: string, identifier?: string|null, tip?: string|null}
 */
class PHPStanRunner
{
    use ReadsConfigArrays;

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
     * Longest excerpt kept from a run that produced no analysable output.
     *
     * A run that dies can put a whole stack trace on stderr, and analyzer messages are
     * rendered on one console line. Long enough for PHPStan's own abort reasons, short
     * enough that it cannot flood a report.
     */
    private const MAX_OUTPUT_SNIPPET = 500;

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
     * $parameters lets a caller pin the PHPStan settings its analysis depends on.
     * The generated config includes the user's own phpstan.neon, and a scalar declared
     * here outranks the same key there, so a caller whose rule the user switched off is
     * not left silently reporting nothing. List-valued settings are not supported: NEON
     * appends included lists rather than replacing them, so an override would need the
     * prevent-merging suffix and would overrule tuning the user is entitled to.
     *
     * @param  string|array<string>  $paths
     * @param  array<string, bool>  $parameters
     * @return $this
     */
    public function analyze(string|array $paths, int $level = 5, int $timeout = 300, ?string $memoryLimit = null, array $parameters = []): self
    {
        $paths = is_array($paths) ? $paths : [$paths];

        // Generate config with Larastan/Carbon extensions
        $configFile = $this->generateConfig($level, $parameters);
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

            // Apply the configured memory limit to the PHPStan subprocess. PHPStan's
            // --memory-limit sets the ceiling per process (including parallel workers),
            // so shieldci.memory_limit governs static analysis, not just the main process.
            if ($memoryLimit !== null && self::isValidMemoryLimit($memoryLimit)) {
                $command[] = '--memory-limit='.$memoryLimit;
            }

            // Add paths
            foreach ($paths as $path) {
                $command[] = $path;
            }

            // Run PHPStan
            $process = new Process($command, $this->basePath);
            $process->setTimeout($timeout);
            $process->run();

            // Parse JSON output
            $decoded = json_decode($process->getOutput(), true);

            // PathNotFoundException, "No files found to analyse." and fatal errors all
            // abort before the JSON formatter runs, so there is no report to read and no
            // per-file evidence of the failure. Record the reason in the report's own
            // non-file-specific "errors" list rather than handing back an empty report
            // that reads as clean.
            $this->result = is_array($decoded)
                ? $this->toStringKeyedArray($decoded)
                : ['files' => [], 'errors' => [$this->describeAbortedRun($process)]];
        } finally {
            // Clean up temp config file
            $this->cleanupTempConfig();
        }

        return $this;
    }

    /**
     * Describe a run that produced no analysable output.
     *
     * The exit code plus a snippet of the output is the only evidence such a run leaves.
     * Standard error comes first because PHPStan writes its abort reasons there; standard
     * output is the fallback, since a PHP fatal error or an exhausted memory limit can
     * land there instead.
     */
    private function describeAbortedRun(Process $process): string
    {
        $detail = $this->condenseOutput($process->getErrorOutput());

        if ($detail === '') {
            $detail = $this->condenseOutput($process->getOutput());
        }

        // A null exit code means the process never reported one, which is not the same
        // as exiting cleanly, so it must not be cast to 0.
        $summary = sprintf(
            'PHPStan produced no analysable output (exit code %d)',
            $process->getExitCode() ?? -1
        );

        return $detail === '' ? $summary : $summary.': '.$detail;
    }

    /**
     * Flatten process output to one bounded line.
     */
    private function condenseOutput(string $output): string
    {
        $collapsed = preg_replace('/\s+/', ' ', $output);

        if (! is_string($collapsed)) {
            return '';
        }

        return Str::limit(trim($collapsed), self::MAX_OUTPUT_SNIPPET);
    }

    /**
     * Generate a temporary PHPStan configuration file with Larastan extensions.
     *
     * The generated config includes:
     * - Larastan extension (for Eloquent magic methods, facades, etc.)
     * - Carbon extension (for Carbon types and iterators)
     * - User's existing config if present
     */
    /**
     * @param  array<string, bool>  $parameters
     */
    private function generateConfig(int $level, array $parameters = []): string
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
        $neon = $this->buildNeonConfig($includes, $level, $parameters);

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
     * In serverless environments (Lambda, Cloud Functions), PHPStan's parallel
     * worker processes are constrained to 1 to avoid memory exhaustion and
     * cold-start I/O bottlenecks from spawning multiple PHP processes on
     * ephemeral container filesystems.
     *
     * @param  array<string>  $includes
     * @param  array<string, bool>  $parameters
     */
    private function buildNeonConfig(array $includes, int $level, array $parameters = []): string
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
        $lines[] = '    tmpDir: '.sys_get_temp_dir().'/phpstan';

        // Emitted before the nested parallel block below, which is indented one level
        // deeper and would otherwise swallow these keys.
        foreach ($parameters as $name => $value) {
            $lines[] = '    '.$name.': '.($value ? 'true' : 'false');
        }

        if (PlatformDetector::isServerless()) {
            $lines[] = '    parallel:';
            $lines[] = '        maximumNumberOfProcesses: 1';
        }

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
     * @return Collection<int, PHPStanIssue>
     */
    public function getIssues(): Collection
    {
        $files = $this->result['files'] ?? null;

        if (! is_array($files)) {
            return collect();
        }

        $issues = [];

        foreach ($files as $file => $fileData) {
            if (! is_string($file) || ! is_array($fileData) || ! isset($fileData['messages']) || ! is_array($fileData['messages'])) {
                continue;
            }

            foreach ($fileData['messages'] as $message) {
                if (! is_array($message)) {
                    continue;
                }

                $line = $message['line'] ?? 0;
                $msg = $message['message'] ?? '';

                // PHPStan omits these keys entirely rather than emitting null, and only
                // emits 'identifier' from 1.11 onwards - 1.10 is still inside our
                // "phpstan/phpstan": "^1.10|^2.0" range. Normalise both to null so
                // consumers read one shape regardless of the installed version.
                $identifier = $message['identifier'] ?? null;
                $tip = $message['tip'] ?? null;

                $issues[] = [
                    'file' => $file,
                    'line' => is_int($line) ? $line : 0,
                    'message' => is_string($msg) ? $msg : '',
                    'identifier' => is_string($identifier) && $identifier !== '' ? $identifier : null,
                    'tip' => is_string($tip) && $tip !== '' ? $tip : null,
                ];
            }
        }

        /** @var Collection<int, PHPStanIssue> $collected */
        $collected = collect($issues);

        return $this->filterKnownFalsePositives($collected);
    }

    /**
     * Get the errors PHPStan reported that are not attached to any file.
     *
     * PHPStan reports unmatched ignoreErrors patterns, unusable ignore configuration and
     * its own internal errors in a top-level "errors" list rather than under "files". A
     * run that reports one of these has not produced a trustworthy result even when every
     * analysed file came back clean, and on an internal error PHPStan discards the real
     * findings entirely. analyze() records a run that emitted no report at all here too,
     * so this is the single channel for "the analysis itself did not go through".
     *
     * @return list<string>
     */
    public function getAnalysisErrors(): array
    {
        $errors = $this->result['errors'] ?? null;

        if (! is_array($errors)) {
            return [];
        }

        $messages = [];

        foreach ($errors as $error) {
            if (! is_string($error)) {
                continue;
            }

            $trimmed = trim($error);

            if ($trimmed !== '') {
                $messages[] = $trimmed;
            }
        }

        return $messages;
    }

    /**
     * Filter out known false positives from issues.
     *
     * @param  Collection<int, PHPStanIssue>  $issues
     * @return Collection<int, PHPStanIssue>
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
     * Does a message match any of the given wildcard patterns?
     *
     * Single source of truth for pattern semantics, shared by filterByPattern()
     * and PHPStanAnalyzer's per-issue classification fallback, so the two cannot
     * drift apart.
     *
     * @param  array<string>  $patterns
     */
    public static function matchesAnyPattern(string $message, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (Str::is($pattern, $message)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Filter issues by message pattern (wildcard match).
     *
     * @param  string|array<string>  $patterns
     * @return Collection<int, PHPStanIssue>
     */
    public function filterByPattern(string|array $patterns): Collection
    {
        $patterns = is_array($patterns) ? $patterns : [$patterns];

        return $this->getIssues()->filter(
            static fn (array $issue): bool => self::matchesAnyPattern($issue['message'], $patterns)
        );
    }

    /**
     * Filter issues by regex pattern.
     *
     * @return Collection<int, PHPStanIssue>
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
     * @return Collection<int, PHPStanIssue>
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

    /**
     * Validate a php.ini-style memory limit string (e.g. "512M", "2G", "-1").
     *
     * Invalid values are rejected so a misconfigured shieldci.memory_limit falls
     * back to PHPStan's ambient limit instead of breaking analysis outright.
     */
    public static function isValidMemoryLimit(string $value): bool
    {
        return preg_match('/^(-1|\d+[KMGkmg]?)$/', $value) === 1;
    }
}
