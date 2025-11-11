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
 * Flags unnecessary use of raw SQL over Eloquent.
 *
 * Checks for:
 * - DB::raw() where Eloquent method exists
 * - Simple queries written as raw SQL
 * - Suggests Eloquent alternative
 */
class RawEloquentAvoidanceAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'raw-eloquent-avoidance',
            name: 'Unnecessary Raw SQL Detector',
            description: 'Flags unnecessary use of raw SQL when Eloquent methods are available',
            category: Category::BestPractices,
            severity: Severity::Low,
            tags: ['laravel', 'eloquent', 'sql', 'readability', 'security'],
            docsUrl: 'https://docs.shieldci.com/analyzers/raw-eloquent-avoidance',
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

                $visitor = new RawSqlVisitor;
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
            return $this->passed('No unnecessary raw SQL queries detected');
        }

        return $this->failed(
            sprintf('Found %d unnecessary raw SQL query/queries', count($issues)),
            $issues
        );
    }
}

/**
 * Visitor to detect raw SQL usage.
 */
class RawSqlVisitor extends NodeVisitorAbstract
{
    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    public function enterNode(Node $node): ?Node
    {
        // Detect DB::raw() calls
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name && $node->class->toString() === 'DB') {
                if ($node->name instanceof Node\Identifier) {
                    $method = $node->name->toString();

                    if ($method === 'raw') {
                        $this->analyzeRawCall($node);
                    } elseif (in_array($method, ['select', 'insert', 'update', 'delete', 'statement'], true)) {
                        $this->analyzeRawQueryMethod($node, $method);
                    }
                }
            }
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

    private function analyzeRawCall(Node\Expr\StaticCall $node): void
    {
        if (empty($node->args)) {
            return;
        }

        $arg = $node->args[0]->value;
        if ($arg instanceof Node\Scalar\String_) {
            $sql = $arg->value;

            // Check if this is a simple query that could use Eloquent
            if ($this->isSimpleQuery($sql)) {
                $this->issues[] = [
                    'message' => 'Using DB::raw() for simple query that could use Eloquent methods',
                    'line' => $node->getLine(),
                    'severity' => Severity::Low,
                    'recommendation' => sprintf(
                        'Consider using Eloquent methods instead of raw SQL. Example: %s',
                        $this->suggestEloquentAlternative($sql)
                    ),
                    'code' => 'DB::raw(\''.substr($sql, 0, 50).'...\')',
                ];
            }
        }
    }

    private function analyzeRawQueryMethod(Node\Expr\StaticCall $node, string $method): void
    {
        if (empty($node->args)) {
            return;
        }

        $arg = $node->args[0]->value;
        if ($arg instanceof Node\Scalar\String_) {
            $sql = strtolower(trim($arg->value));

            // Check for simple SELECT queries
            if ($method === 'select' && $this->isSimpleSelect($sql)) {
                $this->issues[] = [
                    'message' => sprintf('Simple SELECT query using DB::%s() could use Eloquent', $method),
                    'line' => $node->getLine(),
                    'severity' => Severity::Low,
                    'recommendation' => 'Use Eloquent query builder for better readability and security. Example: Model::where(...)->get()',
                    'code' => 'DB::'.$method.'(\''.substr($sql, 0, 50).'...\')',
                ];
            }

            // Check for simple INSERT/UPDATE/DELETE
            if (in_array($method, ['insert', 'update', 'delete'], true) && $this->isSimpleModification($sql)) {
                $this->issues[] = [
                    'message' => sprintf('Simple %s query could use Eloquent', strtoupper($method)),
                    'line' => $node->getLine(),
                    'severity' => Severity::Low,
                    'recommendation' => sprintf(
                        'Use Eloquent methods: %s',
                        $this->suggestEloquentModification($method)
                    ),
                    'code' => null,
                ];
            }
        }
    }

    private function isSimpleQuery(string $sql): bool
    {
        $sql = strtolower(trim($sql));

        // Check for simple patterns
        $simplePatterns = [
            '/^count\s*\(\s*\*\s*\)$/i',              // COUNT(*)
            '/^sum\s*\(\s*\w+\s*\)$/i',               // SUM(column)
            '/^avg\s*\(\s*\w+\s*\)$/i',               // AVG(column)
            '/^max\s*\(\s*\w+\s*\)$/i',               // MAX(column)
            '/^min\s*\(\s*\w+\s*\)$/i',               // MIN(column)
        ];

        foreach ($simplePatterns as $pattern) {
            if (preg_match($pattern, $sql)) {
                return true;
            }
        }

        return false;
    }

    private function isSimpleSelect(string $sql): bool
    {
        // Simple SELECT with basic WHERE
        if (preg_match('/^select\s+\*\s+from\s+\w+\s+where\s+\w+\s*=\s*\??\s*$/i', $sql)) {
            return true;
        }

        // Simple SELECT without WHERE
        if (preg_match('/^select\s+\*\s+from\s+\w+\s*$/i', $sql)) {
            return true;
        }

        // SELECT with simple column list
        if (preg_match('/^select\s+[\w,\s]+\s+from\s+\w+\s*$/i', $sql)) {
            return true;
        }

        return false;
    }

    private function isSimpleModification(string $sql): bool
    {
        $sql = strtolower(trim($sql));

        // Simple patterns that could use Eloquent
        $patterns = [
            '/^insert\s+into\s+\w+\s*\(/i',
            '/^update\s+\w+\s+set\s+\w+\s*=/i',
            '/^delete\s+from\s+\w+\s+where\s+\w+\s*=/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $sql)) {
                // Check it's not complex (no JOINs, subqueries, etc.)
                if (! str_contains($sql, 'join') && ! str_contains($sql, 'select')) {
                    return true;
                }
            }
        }

        return false;
    }

    private function suggestEloquentAlternative(string $sql): string
    {
        $sql = strtolower(trim($sql));

        if (str_contains($sql, 'count')) {
            return 'Model::count() or Model::where(...)->count()';
        }

        if (str_contains($sql, 'sum')) {
            return 'Model::sum(\'column\')';
        }

        if (str_contains($sql, 'avg')) {
            return 'Model::avg(\'column\')';
        }

        if (str_contains($sql, 'max')) {
            return 'Model::max(\'column\')';
        }

        if (str_contains($sql, 'min')) {
            return 'Model::min(\'column\')';
        }

        return 'Use Eloquent query builder methods';
    }

    private function suggestEloquentModification(string $method): string
    {
        return match ($method) {
            'insert' => 'Model::create([...]) or Model::insert([...])',
            'update' => 'Model::where(...)->update([...]) or $model->update([...])',
            'delete' => 'Model::where(...)->delete() or $model->delete()',
            default => 'Use Eloquent methods',
        };
    }
}
