<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects filtering collections in PHP that should be done in database.
 *
 * Checks for:
 * - ->all()->filter(), ->get()->where() patterns
 * - Collection methods on potentially large datasets
 * - Memory-intensive operations that could be DB queries
 */
class PhpSideFilteringAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'php-side-filtering',
            name: 'PHP-Side Data Filtering Detector',
            description: 'Detects filtering data in PHP that should be done at database level for performance',
            category: Category::BestPractices,
            severity: Severity::Critical,
            tags: ['laravel', 'performance', 'database', 'memory', 'optimization'],
            docsUrl: 'https://docs.shieldci.com/analyzers/php-side-filtering',
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new PhpFilteringVisitor;
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssue(
                        message: $issue['message'],
                        location: new Location($this->getRelativePath($file), $issue['line']),
                        severity: $issue['severity'],
                        recommendation: $issue['recommendation'],
                        code: $issue['code'] ?? null,
                    );
                }
            } catch (\Throwable $e) {
                // Skip files with parse errors
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('All filtering is performed at database level');
        }

        return $this->failed(
            sprintf('Found %d instance(s) of PHP-side filtering that should be done in database', count($issues)),
            $issues
        );
    }
}

/**
 * Visitor to detect PHP-side filtering.
 */
class PhpFilteringVisitor extends NodeVisitorAbstract
{
    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    public function enterNode(Node $node): ?Node
    {
        // Detect chained method calls
        if ($node instanceof Node\Expr\MethodCall) {
            $this->analyzeMethodChain($node);
        }

        return null;
    }

    /**
     * @return array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }

    private function analyzeMethodChain(Node\Expr\MethodCall $node): void
    {
        // Get the full chain of methods
        $chain = $this->getMethodChain($node);

        // Check for problematic patterns
        if ($this->hasPhpSideFiltering($chain)) {
            $pattern = implode('->', $chain);

            $this->issues[] = [
                'message' => sprintf(
                    'CRITICAL: Filtering data in PHP instead of database: %s',
                    $pattern
                ),
                'line' => $node->getLine(),
                'severity' => Severity::Critical,
                'recommendation' => $this->getRecommendation($chain),
                'code' => null,
            ];
        }
    }

    /**
     * @return array<string>
     */
    private function getMethodChain(Node\Expr\MethodCall $node): array
    {
        $chain = [];
        $current = $node;

        while ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\StaticCall) {
            if ($current->name instanceof Node\Identifier) {
                array_unshift($chain, $current->name->toString());
            }

            if ($current instanceof Node\Expr\MethodCall) {
                $current = $current->var;
            } elseif ($current instanceof Node\Expr\StaticCall) {
                break;
            } else {
                break;
            }
        }

        return $chain;
    }

    /**
     * @param  array<string>  $chain
     */
    private function hasPhpSideFiltering(array $chain): bool
    {
        // Critical patterns: fetching all data then filtering
        $criticalPatterns = [
            ['all', 'filter'],
            ['all', 'where'],
            ['all', 'reject'],
            ['all', 'first'],
            ['all', 'last'],
            ['get', 'filter'],
            ['get', 'where'],
            ['get', 'reject'],
            ['get', 'first'],  // ->get()->first() is wasteful
            ['get', 'last'],
        ];

        foreach ($criticalPatterns as $pattern) {
            if ($this->chainContainsPattern($chain, $pattern)) {
                return true;
            }
        }

        // Check for collection filtering methods after database fetch
        $fetchMethods = ['all', 'get'];
        $filterMethods = ['filter', 'where', 'whereIn', 'whereNotIn', 'reject', 'first', 'last', 'take', 'skip'];

        foreach ($fetchMethods as $fetch) {
            if (in_array($fetch, $chain, true)) {
                $fetchIndex = array_search($fetch, $chain, true);
                foreach ($filterMethods as $filter) {
                    $filterIndex = array_search($filter, $chain, true);
                    if ($filterIndex !== false && $filterIndex > $fetchIndex) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * @param  array<string>  $chain
     * @param  array<string>  $pattern
     */
    private function chainContainsPattern(array $chain, array $pattern): bool
    {
        $chainStr = implode('->', $chain);
        $patternStr = implode('->', $pattern);

        return str_contains($chainStr, $patternStr);
    }

    /**
     * @param  array<string>  $chain
     */
    private function getRecommendation(array $chain): string
    {
        $pattern = implode('->', $chain);

        $recommendations = [
            'all()->filter' => 'Replace with Model::where(...)->get() to filter at database level',
            'all()->where' => 'Replace with Model::where(...)->get() to filter at database level',
            'get()->filter' => 'Add where() clauses before get() to filter at database level',
            'get()->where' => 'Add where() clauses before get() to filter at database level',
            'get()->first' => 'Replace with ->first() directly (remove ->get())',
            'get()->last' => 'Replace with ->orderBy()->first() to get last record efficiently',
            'all()->first' => 'Replace with Model::first() or Model::where(...)->first()',
            'all()->last' => 'Replace with Model::latest()->first() or orderBy()->first()',
        ];

        foreach ($recommendations as $badPattern => $recommendation) {
            if (str_contains($pattern, $badPattern)) {
                return sprintf(
                    '%s. Current pattern "%s" loads all data into memory before filtering, which is extremely inefficient and can cause memory exhaustion on large datasets',
                    $recommendation,
                    $pattern
                );
            }
        }

        return 'Move filtering logic to database queries using where(), orderBy(), limit(), etc. Loading all data into memory is inefficient and dangerous';
    }
}
