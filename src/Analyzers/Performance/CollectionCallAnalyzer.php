<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Concerns\ParsesPHPStanResults;
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
    use ParsesPHPStanResults;

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
     * PHPStan below 1.11 and Larastan below 2.9 emit none, and composer.json still
     * admits both. Larastan builds this message from a fixed literal, so the wording
     * is a reliable stand-in where the identifier is missing.
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
            severity: Severity::High,
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

        if ($basePath === '') {
            return $this->error('Unable to determine base path for PHPStan analysis');
        }

        $runner = new PHPStanRunner($basePath);

        // Neither absence is a finding about the user's code, and neither leaves this
        // analyzer able to say anything. Reporting "no inefficient collection calls"
        // off an analysis that never ran is the defect this guard exists to prevent.
        if (! $runner->isAvailable()) {
            return $this->skipped('PHPStan is not installed, so collection calls were not analysed');
        }

        if (! file_exists($basePath.'/vendor/larastan/larastan/extension.neon')) {
            return $this->skipped('Larastan is not installed, so collection calls were not analysed');
        }

        try {
            $runner->analyze(
                $this->resolvePaths(),
                5,
                $this->timeout(),
                $this->memoryLimit(),
                [
                    // The rule this analyzer exists to read. The generated config includes
                    // the user's phpstan.neon, where it could otherwise be switched off.
                    'noUnnecessaryCollectionCall' => true,
                    // reportUnmatchedIgnoredErrors is off for every run the runner generates,
                    // so it no longer needs pinning here.
                ]
            );

            $analysisErrors = $runner->getAnalysisErrors();
            $collectionCalls = $runner->getIssues()->filter(
                static fn (array $issue): bool => self::isCollectionCall($issue)
            );
        } catch (\Throwable $e) {
            return $this->error(
                sprintf(
                    'PHPStan analysis failed: %s. Ensure PHPStan and Larastan are properly configured.',
                    $e->getMessage()
                )
            );
        }

        // Counted before createIssuesFromPHPStanResults(), which caps the rows it renders.
        $totalIssues = $collectionCalls->count();

        if ($totalIssues === 0) {
            if ($analysisErrors === []) {
                return $this->passed('No inefficient collection calls detected');
            }

            return $this->error(
                $this->describeAnalysisErrors($analysisErrors),
                ['analysis_errors' => $analysisErrors]
            );
        }

        $issues = $this->createIssuesFromPHPStanResults(
            $collectionCalls,
            'Collection operation that should be a database query',
            Severity::High,
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
     * Paths to analyse, narrowed to directories that hold PHP classes.
     *
     * PHPStan should analyse code, not configs, views or migrations.
     *
     * @return array<int, string>
     */
    private function resolvePaths(): array
    {
        if ($this->paths !== []) {
            return array_values($this->paths);
        }

        $configPaths = config('shieldci.paths.analyze', ['app']);

        if (! is_array($configPaths)) {
            return ['app'];
        }

        $paths = array_values(array_filter(
            array_filter($configPaths, 'is_string'),
            static function (string $path): bool {
                return ! str_starts_with($path, 'config')
                    && ! str_starts_with($path, 'database')
                    && ! str_starts_with($path, 'resources')
                    && ! str_starts_with($path, 'routes');
            }
        ));

        return $paths === [] ? ['app'] : $paths;
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
