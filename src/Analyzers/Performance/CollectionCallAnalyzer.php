<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Concerns\ExcludesPHPStanFindings;
use ShieldCI\Concerns\ParsesPHPStanResults;
use ShieldCI\Concerns\SanitizesErrorMessages;
use ShieldCI\Support\PHPStanRunner;

/**
 * Detects inefficient collection operations using PHPStan/Larastan.
 *
 * Uses Larastan's built-in noUnnecessaryCollectionCall rule to detect:
 * - Model::all()->count() instead of Model::count()
 * - Model::all()->sum() instead of Model::sum()
 * - get()->count() instead of count()
 * - Other collection aggregations that could be database queries
 *
 * This approach leverages Larastan's battle-tested detection logic
 * instead of custom AST parsing.
 */
class CollectionCallAnalyzer extends AbstractFileAnalyzer
{
    use ExcludesPHPStanFindings;
    use ParsesPHPStanResults;
    use SanitizesErrorMessages;

    /**
     * Larastan's error identifier for the rule this analyzer reads.
     *
     * Public because PHPStanAnalyzer has to recognise the same finding in order to
     * leave it alone, and a literal repeated in two analyzers is a literal that drifts.
     */
    public const IDENTIFIER = 'larastan.noUnnecessaryCollectionCall';

    /**
     * Message shape to fall back on when a finding carries no identifier.
     *
     * This rule sets none before Larastan 2.9.1, and PHPStan's JSON output omits the
     * key entirely before 1.10.10. composer.json still admits both. Larastan builds
     * this message from a fixed literal, so the wording is a reliable stand-in where
     * the identifier is missing.
     */
    public const MESSAGE_PATTERN = '*could have been retrieved as a query*';

    /**
     * PHPStan will not run in CI mode by default (can be slow).
     */
    public static bool $runInCI = false;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'collection-call-optimization',
            name: 'Collection Call Optimization Analyzer',
            description: 'Detects inefficient collection operations that should be performed at the database query level',
            category: Category::Performance,
            severity: Severity::Medium,
            tags: ['database', 'collection', 'performance', 'n+1', 'optimization', 'phpstan'],
            timeToFix: 45
        );
    }

    /**
     * Does this PHPStan finding come from Larastan's collection-call rule?
     *
     * The identifier is authoritative wherever PHPStan emits one: a finding that
     * carries a different identifier belongs to another rule, whatever it reads like.
     *
     * @param  array{file: string, line: int, message: string, identifier?: string|null, tip?: string|null}  $issue
     */
    public static function isCollectionCall(array $issue): bool
    {
        $identifier = $issue['identifier'] ?? null;

        if ($identifier !== null) {
            return $identifier === self::IDENTIFIER;
        }

        return PHPStanRunner::matchesAnyPattern($issue['message'], [self::MESSAGE_PATTERN]);
    }

    protected function runAnalysis(): ResultInterface
    {
        $basePath = $this->getBasePath();

        // None of these three absences is a finding about the user's code, and none of
        // them leaves this analyzer able to say anything. Reporting "no inefficient
        // collection calls" off an analysis that never ran is the defect these guards
        // exist to prevent.
        if ($basePath === '') {
            return $this->skipped('The application base path could not be determined, so collection calls were not analysed');
        }

        $runner = new PHPStanRunner($basePath);

        if (! $runner->isAvailable()) {
            return $this->skipped('PHPStan is not installed, so collection calls were not analysed');
        }

        if (! file_exists($basePath.'/vendor/larastan/larastan/extension.neon')) {
            return $this->skipped('Larastan is not installed, so collection calls were not analysed');
        }

        $paths = $this->resolvePaths();

        if ($paths === []) {
            return $this->skipped('Every analysed path is under resources/views, which holds Blade templates rather than PHP classes, so collection calls were not analysed');
        }

        // shieldci.excluded_paths and Blade templates, by extension wherever they live, are
        // applied before the run: from PHPStan 1.11.6 one unparseable file stops it and drops
        // every finding.
        $exclusions = $this->phpstanExclusions($paths);

        // Skipped rather than passed, as above: nothing was analysed.
        if (! $exclusions['analysable']) {
            return $this->skipped('Every analysed path is excluded by shieldci.excluded_paths, so collection calls were not analysed');
        }

        try {
            $runner->analyze(
                $paths,
                5,
                $this->timeout(),
                $this->memoryLimit(),
                [
                    // The rule this analyzer exists to read. The generated config includes
                    // the user's phpstan.neon, where it could otherwise be switched off,
                    // narrowed to some methods, or ignored. Emptying the Only and Except lists
                    // and ignoreErrors restores Larastan's defaults (every method, nothing
                    // ignored by config). Only this rule's findings are read, so the user's
                    // other ignores do not matter.
                    'noUnnecessaryCollectionCall' => true,
                    'noUnnecessaryCollectionCallOnly' => [],
                    'noUnnecessaryCollectionCallExcept' => [],
                    'ignoreErrors' => [],
                    // reportUnmatchedIgnoredErrors is off for every run the runner generates,
                    // so it no longer needs pinning here.
                ],
                $exclusions['excludePaths']
            );

            // Whether anything is left after the exclusions depends on the project's own
            // fileExtensions and excludePaths, so only PHPStan can say. A run that found nothing
            // because of what was left out analysed nothing, which is not a clean run; one that
            // found nothing with nothing left out stays the error it was before.
            if ($runner->foundNoFiles()) {
                if ($exclusions['excludesConfigured']) {
                    return $this->skipped('PHPStan found no file to analyse once shieldci.excluded_paths and Blade templates were left out, so collection calls were not analysed');
                }

                if ($this->holdsBladeTemplate($paths)) {
                    return $this->skipped('The analysed paths hold only Blade templates, which PHPStan is not given, so collection calls were not analysed');
                }
            }

            $analysisErrors = $runner->getAnalysisErrors();
            $stoppedAt = $this->stoppedAtFiles($runner->getRunStoppingErrors());
            $collectionCalls = $this->withoutExcludedFiles($runner->getIssues())->filter(
                static fn (array $issue): bool => self::isCollectionCall($issue)
            );
        } catch (\Throwable $e) {
            return $this->error(
                sprintf(
                    'PHPStan analysis failed: %s. Ensure PHPStan and Larastan are properly configured.',
                    $this->sanitizedErrorMessage($e->getMessage())
                )
            );
        }

        // Counted before createIssuesFromPHPStanResults(), which caps the rows it renders.
        $totalIssues = $collectionCalls->count();

        // A file PHPStan could not process makes it drop every other file's findings, so an
        // empty list from that run is not a clean one. Truncation leaves only the stopping
        // errors behind, which is why the findings branch below never meets one.
        if ($totalIssues === 0) {
            if ($analysisErrors === [] && $stoppedAt === []) {
                return $this->passed('No inefficient collection calls detected');
            }

            return $this->error(
                $this->describeIncompleteRunWithoutFindings($analysisErrors, $stoppedAt),
                $this->incompleteRunMetadata($analysisErrors, $stoppedAt)
            );
        }

        $issues = $this->createIssuesFromPHPStanResults(
            $collectionCalls,
            'Collection operation that should be a database query',
            Severity::Medium,
            fn (string $message): string => $this->getRecommendationFromMessage($message)
        );

        $displayedCount = count($issues);

        $metadata = [
            'total_issues' => $totalIssues,
            'displayed_issues' => $displayedCount,
            'truncated' => $displayedCount < $totalIssues,
        ];

        if ($analysisErrors !== []) {
            $metadata['analysis_errors'] = $analysisErrors;
        }

        return $this->resultBySeverity(
            $this->appendAnalysisErrorNotice(
                $this->formatIssueCountMessage($totalIssues, $displayedCount, 'inefficient collection operation(s)'),
                $analysisErrors
            ),
            $issues,
            $metadata
        );
    }

    /**
     * Paths to analyse: the ones this analyzer was given, less the Blade templates.
     *
     * AnalyzerManager always sets them, from shieldci.paths.analyze or its shipped
     * defaults, so route closures, migrations, seeders and config are analysed along
     * with app/. Only resources/views is left out: it holds Blade templates rather than
     * PHP classes, so a run over it costs time and memory for code Larastan's rule is
     * not written for. An entry is dropped when it is that directory or one below it,
     * whether written relative, with ./ or a trailing slash, with backslashes, or as an
     * absolute path under the base path. A broader entry such as resources or . is kept:
     * phpstanExclusions() leaves every Blade template out of the run by extension, wherever
     * it lives.
     *
     * No paths at all means the analyzer was built outside AnalyzerManager, and app/
     * stands in for the manager's list. An empty list is returned only when every path
     * given was under resources/views, which leaves nothing to analyse.
     *
     * @return array<int, string>
     */
    private function resolvePaths(): array
    {
        if ($this->paths === []) {
            return ['app'];
        }

        $basePath = rtrim(str_replace('\\', '/', $this->getBasePath()), '/').'/';

        return array_values(array_filter(
            $this->paths,
            static function (string $path) use ($basePath): bool {
                $path = str_replace('\\', '/', $path);

                if (str_starts_with($path, $basePath)) {
                    $path = substr($path, strlen($basePath));
                }

                while (str_starts_with($path, './')) {
                    $path = ltrim(substr($path, 2), '/');
                }

                $path = rtrim($path, '/');

                return $path !== 'resources/views' && ! str_starts_with($path, 'resources/views/');
            }
        ));
    }

    private function timeout(): int
    {
        $timeout = config('shieldci.timeout', 300);

        return is_int($timeout) ? $timeout : (is_numeric($timeout) ? (int) $timeout : 300);
    }

    private function memoryLimit(): ?string
    {
        $memoryLimit = config('shieldci.memory_limit');

        return is_string($memoryLimit) && $memoryLimit !== '' ? $memoryLimit : null;
    }

    /**
     * Turn a Larastan message into advice about the operation it flagged.
     */
    private function getRecommendationFromMessage(string $message): string
    {
        if (preg_match("/Called '([^']+)' on Laravel collection/", $message, $matches) === 1) {
            return sprintf(
                'Ask the database for the %s result directly instead of loading every row and reducing them in PHP. The database can answer this without transferring the rows behind it.',
                $matches[1]
            );
        }

        return 'Perform this aggregation at the database query level instead of the collection level for better performance. This avoids loading unnecessary data into memory.';
    }
}
