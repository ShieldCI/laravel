<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Support\PathHelper;
use ShieldCI\Support\PHPStanRunner;

/**
 * Applies shieldci.excluded_paths to a PHPStan run and to its report.
 *
 * The exclude patterns are applied before PHPStan starts, not only to what it reports. From
 * PHPStan 1.11.6 a file it cannot parse stops the run and drops every other file's findings,
 * so an excluded file left in the run can still empty it. phpstanExclusions() turns the
 * patterns into excludePaths entries for the generated config, under its analyse key: the
 * files are left out of the analysis but still scanned, so a class declared in one is still
 * discovered. The configured paths reach PHPStan as before, so it walks them itself, with the
 * project's own fileExtensions, and the command line stays as short as the configuration.
 *
 * The entries are concrete, existing, absolute paths that core's matcher chose, never the
 * user's glob patterns, and that keeps one meaning per pattern. PHPStan would read a pattern
 * its own way: it resolves a relative pattern against its config file, reads a wildcard-free
 * directory as everything beneath it, which core's anchored match does not, and aborts on a
 * wildcard-free pattern naming nothing that exists. A path that exists means the same to both,
 * once the characters PHPStan would read as a pattern are escaped. The one pattern entry is
 * *.blade.php, which leaves Blade templates out by extension wherever they live. The entries
 * are written without the prevent-merging suffix, so the project's own excludePaths still
 * apply alongside them.
 *
 * A project still on PHPStan 1.x's excludes_analyse gets only the template entry, under that
 * key: PHPStan 1.x leaves those entries out of symbol discovery as well, and a class declared
 * in an excluded file would then be reported as not found. Its excluded paths are applied to
 * the report alone, as they were before entries were written.
 *
 * The same patterns are then applied to what PHPStan reports, by withoutExcludedFiles(). That
 * is the backstop for what the entries cannot reach: a trait's error filed under the class
 * that uses it, a path PHPStan reports under its real path, and files beneath a symlinked or
 * unreadable directory, which are not walked.
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
     * The excludePaths entries to hand PHPStan for these paths, and whether anything is left.
     *
     * Concrete entries are existing paths, absolute and spelled from the resolved base path as
     * PHPStan sees the files it finds. A directory is one entry when a pattern covers it, one
     * that ends in a wildcard and matches the directory plus "/" (such as 'vendor/*' against
     * vendor/), or when every file beneath it turns out to be excluded. Otherwise each excluded
     * file is its own entry, a configured path that is itself an excluded file included. A
     * covered directory is not read, and a directory is only read when some pattern could match
     * beneath it, so the shipped patterns read nothing under app/.
     *
     * Blade templates are always left out, by extension, with the pattern entry *.blade.php: they
     * hold markup around PHP fragments rather than PHP classes, and one whose PHP does not parse
     * stops the whole run. PHPStan matches it against the absolute path, where * crosses
     * directories, so a template is excluded wherever it lives, a module's own views included.
     *
     * Exclusion is withoutExcludedFiles()'s, patterns waived beneath an explicit path included.
     *
     * 'analysable' is false only when every configured path is itself excluded: covered, an
     * excluded file, or a directory whose every file is excluded. Anything else is left to
     * PHPStan, since only the project's own fileExtensions and excludePaths decide what it finds;
     * a run that then finds nothing is the caller's to read from PHPStanRunner::foundNoFiles().
     * 'excludesConfigured' says an entry other than the template pattern was written, which
     * is what lets such a run be blamed on shieldci.excluded_paths.
     *
     * @param  array<int, string>  $paths
     * @param  array<int, string>  $explicitPaths
     * @return array{excludePaths: list<string>, analysable: bool, excludesConfigured: bool}
     */
    protected function phpstanExclusions(array $paths, array $explicitPaths = []): array
    {
        if ($this->excludePatterns === []) {
            return ['excludePaths' => [PHPStanRunner::BLADE_TEMPLATES_ENTRY], 'analysable' => true, 'excludesConfigured' => false];
        }

        $patterns = $this->excludePatterns;
        $basePath = rtrim(str_replace('\\', '/', $this->getBasePath()), '/');
        $realBasePath = realpath($basePath);
        $realBasePath = $realBasePath !== false ? rtrim(str_replace('\\', '/', $realBasePath), '/') : $basePath;
        $waived = $this->waivedExcludePatterns($explicitPaths, $this->getBasePath());
        $excluded = [];
        $analysable = false;

        foreach ($paths as $path) {
            $absolute = $this->analysedPath($path, $basePath);

            if ($absolute === null) {
                $analysable = true;

                continue;
            }

            if (! is_dir($absolute)) {
                if ($this->isExcludedFile($absolute, $patterns, $waived)) {
                    $excluded[$absolute] = false;
                } else {
                    $analysable = true;
                }

                continue;
            }

            $walk = $this->excludedBeneath($absolute, $basePath, $patterns, $waived);
            $excluded += $walk['entries'];
            $analysable = $analysable || ! $walk['complete'];
        }

        ksort($excluded, SORT_STRING);
        $entries = [];

        foreach ($excluded as $entry => $isDirectory) {
            $entry = (string) $entry;
            $resolved = $entry === $basePath || str_starts_with($entry, $basePath.'/')
                ? $realBasePath.substr($entry, strlen($basePath))
                : $entry;

            $entries[] = $this->literalPhpstanEntry($resolved, $isDirectory);
        }

        $excludesConfigured = $entries !== [];
        $entries[] = PHPStanRunner::BLADE_TEMPLATES_ENTRY;

        return ['excludePaths' => $entries, 'analysable' => $analysable, 'excludesConfigured' => $excludesConfigured];
    }

    /**
     * Does any of these paths hold a Blade template?
     *
     * Asked only after PHPStan found nothing to analyse, to tell a path that held nothing but
     * templates, which PHPStan is not given, from one that held nothing at all. Stops at the
     * first template, and does not follow a symlinked directory.
     *
     * @param  array<int, string>  $paths
     */
    protected function holdsBladeTemplate(array $paths): bool
    {
        $basePath = rtrim(str_replace('\\', '/', $this->getBasePath()), '/');
        $pending = [];

        foreach ($paths as $path) {
            $absolute = $this->analysedPath($path, $basePath);

            if ($absolute === null) {
                continue;
            }

            if (! is_dir($absolute)) {
                if (str_ends_with($absolute, '.blade.php')) {
                    return true;
                }

                continue;
            }

            $pending[] = $absolute;
        }

        while (($directory = array_pop($pending)) !== null) {
            foreach (@scandir($directory) ?: [] as $name) {
                if ($name === '.' || $name === '..') {
                    continue;
                }

                $child = $directory.'/'.$name;

                if (is_dir($child)) {
                    if (! is_link($child)) {
                        $pending[] = $child;
                    }
                } elseif (str_ends_with($name, '.blade.php')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * An existing path as an excludePaths entry that matches that path and nothing else.
     *
     * PHPStan takes an entry holding any of * ? [ ] for an fnmatch pattern, so each is wrapped
     * in a one-character class. A directory is always written as a pattern, its path plus /*:
     * PHPStan 1.x matches a literal entry as a string prefix and drops a trailing separator,
     * so app/Models/User would also exclude app/Models/User.php and app/Models/UserProfile/.
     * The pattern matches the files beneath the directory only, on 1.x and 2.x alike.
     */
    private function literalPhpstanEntry(string $path, bool $isDirectory): string
    {
        $escaped = (string) preg_replace('/[*?\[\]]/', '[$0]', $path);

        return $isDirectory ? $escaped.'/*' : $escaped;
    }

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

                return ! $this->isExcludedFile($file, $this->excludePatterns, $waived);
            })
            ->values();
    }

    /**
     * Is this file excluded, once the patterns an explicit path above it waives are set aside?
     *
     * @param  array<int, string>  $patterns
     * @param  array<string, array<int, string>>  $waived
     */
    private function isExcludedFile(string $file, array $patterns, array $waived): bool
    {
        $relative = ltrim($this->getRelativePath($file), '/');

        foreach ($waived as $root => $rootPatterns) {
            if ($relative === $root || str_starts_with($relative, $root.'/')) {
                $patterns = array_diff($patterns, $rootPatterns);
            }
        }

        return $this->matchesAnyExcludePattern($patterns, $relative, $file);
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
     * The absolute path of a configured path that exists, or null when it does not.
     *
     * Read as resolvePaths() reads it: backslashes, a leading ./, a trailing slash and an
     * absolute spelling under the base path all name the same path.
     */
    private function analysedPath(string $path, string $basePath): ?string
    {
        $normalized = str_replace('\\', '/', $path);

        if (str_starts_with($normalized, '/') || preg_match('#^[A-Za-z]:/#', $normalized) === 1) {
            $absolute = rtrim($normalized, '/');
        } else {
            while (str_starts_with($normalized, './')) {
                $normalized = ltrim(substr($normalized, 2), '/');
            }

            $normalized = rtrim($normalized, '/');
            $absolute = $normalized === '' || $normalized === '.' ? $basePath : $basePath.'/'.$normalized;
        }

        return $absolute !== '' && file_exists($absolute) ? $absolute : null;
    }

    /**
     * The excluded entries beneath one directory, from a walk that reads as little as it can.
     *
     * Entries map each excluded path to whether it is a directory. 'complete' says every file
     * beneath the directory is excluded, so the caller can fold it into one entry.
     *
     * @param  array<int, string>  $patterns
     * @param  array<string, array<int, string>>  $waived
     * @return array{entries: array<string, bool>, complete: bool}
     */
    private function excludedBeneath(string $directory, string $basePath, array $patterns, array $waived): array
    {
        [$relativePrefix, $absolutePrefix] = $this->directoryPrefixes($directory, $basePath);

        // A pattern waived for any file beneath the directory cannot exclude it whole. One waived
        // for every file beneath it cannot exclude anything there at all.
        $coverPatterns = $patterns;
        $reachPatterns = $patterns;

        foreach ($waived as $root => $rootPatterns) {
            $rootPrefix = $root.'/';

            if (str_starts_with($relativePrefix, $rootPrefix)) {
                $reachPatterns = array_diff($reachPatterns, $rootPatterns);
                $coverPatterns = array_diff($coverPatterns, $rootPatterns);
            } elseif (str_starts_with($rootPrefix, $relativePrefix)) {
                $coverPatterns = array_diff($coverPatterns, $rootPatterns);
            }
        }

        if ($this->coversDirectory($coverPatterns, $relativePrefix, $absolutePrefix)) {
            return ['entries' => [$directory => true], 'complete' => true];
        }

        if (! $this->mayExcludeBeneath($reachPatterns, $relativePrefix, $absolutePrefix)) {
            return ['entries' => [], 'complete' => false];
        }

        $names = @scandir($directory);

        // Unreadable here means unreadable to PHPStan as well, which reports it as it does today.
        if ($names === false) {
            return ['entries' => [], 'complete' => false];
        }

        $entries = [];
        $complete = true;

        foreach ($names as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }

            $child = $directory.'/'.$name;

            if (is_dir($child)) {
                // A symlinked directory is not followed, which could loop. It is excluded when a
                // pattern covers it and left to PHPStan otherwise.
                if (is_link($child)) {
                    [$childRelativePrefix, $childAbsolutePrefix] = $this->directoryPrefixes($child, $basePath);

                    if ($this->coversDirectory($coverPatterns, $childRelativePrefix, $childAbsolutePrefix)) {
                        $entries[$child] = true;
                    } else {
                        $complete = false;
                    }

                    continue;
                }

                $walk = $this->excludedBeneath($child, $basePath, $patterns, $waived);
                $entries += $walk['entries'];
                $complete = $complete && $walk['complete'];

                continue;
            }

            if ($this->isExcludedFile($child, $patterns, $waived)) {
                $entries[$child] = false;
            } else {
                $complete = false;
            }
        }

        // An empty directory excludes nothing, so it is not folded into an entry of its own.
        if ($complete && $entries !== []) {
            return ['entries' => [$directory => true], 'complete' => true];
        }

        return ['entries' => $entries, 'complete' => false];
    }

    /**
     * The strings every path beneath a directory starts with, relative and absolute.
     *
     * @return array{string, string}
     */
    private function directoryPrefixes(string $directory, string $basePath): array
    {
        if ($directory === $basePath) {
            return ['', $basePath.'/'];
        }

        return [ltrim($this->getRelativePath($directory), '/').'/', $directory.'/'];
    }

    /**
     * Does a pattern match every path beneath the directory?
     *
     * A pattern that matches the directory plus "/" and ends in a wildcard matches that
     * prefix followed by anything. One that does not end in a wildcard, such as 'app/Legacy/'
     * or 'app/Legacy/*.php', can still leave files beneath it unexcluded.
     *
     * @param  array<int, string>  $patterns
     */
    private function coversDirectory(array $patterns, string $relativePrefix, string $absolutePrefix): bool
    {
        foreach ($patterns as $pattern) {
            if (str_ends_with($pattern, '*') && $this->matchesAnyExcludePattern([$pattern], $relativePrefix, $absolutePrefix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Could any pattern match some path beneath the directory?
     *
     * Decided from each pattern's literal text before its first wildcard, which a match must
     * begin with: it has to agree with the directory's prefix as far as both go. A pattern
     * with no wildcard has to name a path beneath the directory outright.
     *
     * @param  array<int, string>  $patterns
     */
    private function mayExcludeBeneath(array $patterns, string $relativePrefix, string $absolutePrefix): bool
    {
        foreach ($patterns as $pattern) {
            $literalLength = strcspn($pattern, '*?');
            $literal = substr($pattern, 0, $literalLength);

            foreach ([$relativePrefix, $absolutePrefix] as $prefix) {
                $reaches = $literalLength === strlen($pattern)
                    ? str_starts_with($pattern, $prefix)
                    : str_starts_with($literal, $prefix) || str_starts_with($prefix, $literal);

                if ($reaches) {
                    return true;
                }
            }
        }

        return false;
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
