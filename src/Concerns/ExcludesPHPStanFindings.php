<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Support\PathHelper;

/**
 * Applies shieldci.excluded_paths to a PHPStan report.
 *
 * PHPStan is handed the configured paths whole, so the exclude patterns are applied to what
 * it reports instead. Filtering the report rather than writing PHPStan excludePaths keeps one
 * meaning per pattern: PHPStan resolves relative patterns against its config file, reads a
 * wildcard-free directory as everything beneath it, which core's anchored match does not, and
 * aborts on a wildcard-free pattern naming nothing that exists.
 *
 * Each pattern goes through core's matchesPattern(), the glob-to-regex that setExcludePatterns()
 * compiles, against the path relative to the base path and the absolute path, as
 * shouldAnalyzeFile() does. shouldAnalyzeFile() itself cannot be asked: it declines every file
 * that is not .php, which would drop findings from a project's own fileExtensions, and it reads
 * the private compiled list of every pattern, which cannot leave out the ones an explicit path
 * waives.
 *
 * For analyzers extending AbstractFileAnalyzer, which provides the abstract methods and the
 * excludePatterns property.
 */
trait ExcludesPHPStanFindings
{
    /**
     * Drop the findings in files the project excluded from analysis.
     *
     * Two spellings in the report are undone first. An error inside a trait is filed under
     * "<file> (in context of class X)", and PHPStan runs from the resolved working directory,
     * so a base path reached through a symlink (a release directory, macOS's /var) comes back
     * under its real path, which no relative pattern would match.
     *
     * $explicitPaths are paths the user configured for this analyzer alone, and they outrank a
     * shared exclude that would empty them: a pattern covers an explicit path when it matches
     * that path or that path plus "/", relative or absolute, and is then ignored beneath it.
     * So 'tests/*' is ignored under an explicit 'tests', while 'app/Legacy/*' still applies
     * under an explicit 'app'.
     *
     * Callers read the run-stopping errors from the unfiltered report: a file PHPStan stopped
     * at still cut the run short when its own findings are excluded.
     *
     * @param  Collection<int, array{file: string, line: int, message: string, identifier?: string|null, tip?: string|null}>  $issues
     * @param  array<int, string>  $explicitPaths
     * @return Collection<int, array{file: string, line: int, message: string, identifier?: string|null, tip?: string|null}>
     */
    protected function withoutExcludedFiles(Collection $issues, array $explicitPaths = []): Collection
    {
        $basePath = $this->getBasePath();
        $realBasePath = $basePath !== '' ? realpath($basePath) : false;
        $waived = $this->waivedExcludePatterns($explicitPaths, $basePath);

        return $issues
            ->filter(function (array $issue) use ($basePath, $realBasePath, $waived): bool {
                $file = preg_replace('/ \(in context of .+\)$/', '', $issue['file']) ?? $issue['file'];

                if ($realBasePath !== false
                    && $realBasePath !== $basePath
                    && str_starts_with($file, $realBasePath)
                    && in_array(substr($file, strlen($realBasePath), 1), ['/', '\\'], true)) {
                    $file = $basePath.substr($file, strlen($realBasePath));
                }

                $relative = ltrim($this->getRelativePath($file), '/');
                $patterns = $this->excludePatterns;

                foreach ($waived as $root => $rootPatterns) {
                    if ($relative === $root || str_starts_with($relative, $root.'/')) {
                        $patterns = array_diff($patterns, $rootPatterns);
                    }
                }

                return ! $this->matchesAnyExcludePattern($patterns, $relative, $file);
            })
            ->values();
    }

    /**
     * The exclude patterns each explicit path waives, keyed by that path relative to the base.
     *
     * @param  array<int, string>  $explicitPaths
     * @return array<string, array<int, string>>
     */
    private function waivedExcludePatterns(array $explicitPaths, string $basePath): array
    {
        $waived = [];

        foreach ($explicitPaths as $path) {
            $root = trim((string) preg_replace('#^(\./)+#', '', $this->getRelativePath(str_replace('\\', '/', $path))), '/');
            $absolute = PathHelper::join($basePath, $root);

            $waived[$root] = array_values(array_filter(
                $this->excludePatterns,
                fn (string $pattern): bool => $this->matchesAnyExcludePattern([$pattern], $root, $absolute)
                    || $this->matchesAnyExcludePattern([$pattern], $root.'/', $absolute.'/')
            ));
        }

        return $waived;
    }

    /**
     * @param  array<int, string>  $patterns
     */
    private function matchesAnyExcludePattern(array $patterns, string $relative, string $absolute): bool
    {
        foreach ($patterns as $pattern) {
            if ($this->matchesPattern($relative, $pattern) || $this->matchesPattern($absolute, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Provided by AbstractFileAnalyzer.
     */
    abstract protected function getBasePath(): string;

    /**
     * Provided by AbstractAnalyzer.
     */
    abstract protected function getRelativePath(string $file): string;

    /**
     * Provided by AbstractFileAnalyzer: the glob matcher behind its exclude patterns.
     */
    abstract protected function matchesPattern(string $path, string $pattern): bool;
}
