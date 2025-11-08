<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\NodeFinder;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects inefficient collection operations that should be done at the database level.
 *
 * Checks for:
 * - Model::all()->count() instead of Model::count()
 * - Model::all()->sum() instead of Model::sum()
 * - Model::all()->avg() instead of Model::avg()
 * - Model::all()->max() instead of Model::max()
 * - Model::all()->min() instead of Model::min()
 * - get()->count() instead of count()
 * - Other collection aggregations that could be database queries
 */
class CollectionCallAnalyzer extends AbstractFileAnalyzer
{
    private array $aggregationMethods = [
        'count',
        'sum',
        'avg',
        'average',
        'max',
        'min',
        'pluck',
    ];

    private array $queryMethods = [
        'all',
        'get',
    ];

    private AstParser $parser;

    public function __construct()
    {
        $this->parser = new AstParser;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'collection-call-optimization',
            name: 'Collection Call Optimization',
            description: 'Detects inefficient collection operations that should be performed at the database query level',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['database', 'collection', 'performance', 'n+1', 'optimization'],
            docsUrl: 'https://laravel.com/docs/queries#aggregates'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            try {
                $filePath = $file instanceof \SplFileInfo ? $file->getPathname() : (string) $file;
                $ast = $this->parser->parseFile($filePath);
                $this->analyzeFile($filePath, $ast, $issues);
            } catch (\Throwable $e) {
                // Skip files that can't be parsed
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('No inefficient collection calls detected');
        }

        return $this->failed(
            sprintf('Found %d inefficient collection operations that should be database queries', count($issues)),
            $issues
        );
    }

    private function analyzeFile(string $filePath, array $ast, array &$issues): void
    {
        $nodeFinder = new NodeFinder;

        // Find all method calls
        $methodCalls = $nodeFinder->findInstanceOf($ast, MethodCall::class);

        foreach ($methodCalls as $methodCall) {
            $this->checkMethodCall($filePath, $methodCall, $issues);
        }

        // Find all static calls
        $staticCalls = $nodeFinder->findInstanceOf($ast, StaticCall::class);

        foreach ($staticCalls as $staticCall) {
            $this->checkStaticCall($filePath, $staticCall, $issues);
        }
    }

    private function checkMethodCall(string $filePath, MethodCall $node, array &$issues): void
    {
        // Check if this is an aggregation method call
        if (! $node->name instanceof Node\Identifier) {
            return;
        }

        $methodName = $node->name->toString();

        if (! in_array($methodName, $this->aggregationMethods)) {
            return;
        }

        // Check if the previous call is a query method (all(), get())
        if ($node->var instanceof MethodCall) {
            $previousCall = $node->var;

            if ($previousCall->name instanceof Node\Identifier) {
                $previousMethodName = $previousCall->name->toString();

                if (in_array($previousMethodName, $this->queryMethods)) {
                    $issues[] = $this->createIssue(
                        message: "Inefficient collection operation: ->{$previousMethodName}()->{$methodName}()",
                        location: new Location($filePath, $node->getLine()),
                        severity: Severity::High,
                        recommendation: $this->getRecommendation($previousMethodName, $methodName),
                        code: $this->getCodeSnippet($filePath, $node->getLine()),
                        metadata: [
                            'query_method' => $previousMethodName,
                            'aggregation_method' => $methodName,
                            'pattern' => "->{$previousMethodName}()->{$methodName}()",
                        ]
                    );
                }
            }
        }
    }

    private function checkStaticCall(string $filePath, StaticCall $node, array &$issues): void
    {
        // Check for Model::all()->method() pattern
        if (! $node->name instanceof Node\Identifier) {
            return;
        }

        $methodName = $node->name->toString();

        if ($methodName !== 'all') {
            return;
        }

        // Check if there's a chained method call after ::all()
        $parent = $node->getAttribute('parent');

        if ($parent instanceof MethodCall) {
            if ($parent->name instanceof Node\Identifier) {
                $chainedMethod = $parent->name->toString();

                if (in_array($chainedMethod, $this->aggregationMethods)) {
                    $className = $this->getClassName($node);

                    $issues[] = $this->createIssue(
                        message: "Inefficient collection operation: {$className}::all()->{$chainedMethod}()",
                        location: new Location($filePath, $node->getLine()),
                        severity: Severity::High,
                        recommendation: $this->getRecommendation('all', $chainedMethod, $className),
                        code: $this->getCodeSnippet($filePath, $node->getLine()),
                        metadata: [
                            'query_method' => 'all',
                            'aggregation_method' => $chainedMethod,
                            'pattern' => "::all()->{$chainedMethod}()",
                        ]
                    );
                }
            }
        }
    }

    private function getClassName(StaticCall $node): string
    {
        if ($node->class instanceof Node\Name) {
            return $node->class->toString();
        }

        return 'Model';
    }

    private function getRecommendation(string $queryMethod, string $aggregationMethod, ?string $className = null): string
    {
        $prefix = $className ? "{$className}::" : '';

        return match ($aggregationMethod) {
            'count' => "Replace {$prefix}{$queryMethod}()->{$aggregationMethod}() with {$prefix}{$aggregationMethod}(). This fetches only the count from the database instead of loading all records into memory.",
            'sum', 'avg', 'average', 'max', 'min' => "Replace {$prefix}{$queryMethod}()->{$aggregationMethod}() with {$prefix}{$aggregationMethod}('column_name'). This performs the aggregation at the database level, which is much more efficient.",
            'pluck' => "Replace {$prefix}{$queryMethod}()->pluck() with {$prefix}pluck(). This retrieves only the specified columns instead of all columns.",
            default => 'Perform this operation at the database query level instead of the collection level for better performance.',
        };
    }
}
