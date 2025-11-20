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
 * Detects mixing Query Builder and Eloquent for the same model.
 *
 * Checks for:
 * - Model::where() mixed with DB::table('models') for same model
 * - Inconsistent query approach across repository/service
 * - Global scopes bypassed by using Query Builder
 */
class MixedQueryBuilderEloquentAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'mixed-query-builder-eloquent',
            name: 'Mixed Query Builder and Eloquent Detector',
            description: 'Detects inconsistent mixing of Query Builder and Eloquent ORM in the same codebase',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['laravel', 'eloquent', 'query-builder', 'consistency'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/mixed-query-builder-eloquent',
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Only set default paths if not already set (allows tests to override)
        if (empty($this->paths)) {
            $this->setBasePath(base_path());
            $this->setPaths(['app/Repositories', 'app/Services', 'app/Http/Controllers']);
        }

        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new MixedQueryVisitor;
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
            return $this->passed('Consistent use of Eloquent or Query Builder');
        }

        return $this->failed(
            sprintf('Found %d file(s) mixing Query Builder and Eloquent inconsistently', count($issues)),
            $issues
        );
    }
}

/**
 * Visitor to detect mixed query approaches.
 */
class MixedQueryVisitor extends NodeVisitorAbstract
{
    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    /** @var array<string, array{type: string, line: int}> */
    private array $tableUsage = [];

    private ?string $currentClassName = null;

    public function enterNode(Node $node): ?Node
    {
        // Track current class
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClassName = $node->name?->toString();
        }

        // Detect DB::table() calls
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name && $node->class->toString() === 'DB') {
                if ($node->name instanceof Node\Identifier && $node->name->toString() === 'table') {
                    $this->trackDbTableCall($node);
                }
            }

            // Detect Model::where/find/etc calls
            if ($node->class instanceof Node\Name) {
                $className = $node->class->toString();
                if ($this->looksLikeModel($className)) {
                    if ($node->name instanceof Node\Identifier) {
                        $method = $node->name->toString();
                        $eloquentMethods = ['where', 'find', 'all', 'get', 'first', 'create', 'update'];
                        if (in_array($method, $eloquentMethods, true)) {
                            $this->trackEloquentCall($className, $node->getLine());
                        }
                    }
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node): ?Node
    {
        // When leaving a class, check for mixed usage
        if ($node instanceof Node\Stmt\Class_) {
            $this->checkMixedUsage();
            $this->tableUsage = []; // Reset for next class
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

    private function trackDbTableCall(Node\Expr\StaticCall $node): void
    {
        if (empty($node->args)) {
            return;
        }

        $arg = $node->args[0];
        if ($arg->value instanceof Node\Scalar\String_) {
            $tableName = $arg->value->value;
            // Check if table already tracked as eloquent
            if (isset($this->tableUsage[$tableName]) && $this->tableUsage[$tableName]['type'] === 'eloquent') {
                // Mark as mixed by changing type
                $this->tableUsage[$tableName]['type'] = 'mixed';
                $this->tableUsage[$tableName]['qb_line'] = $node->getLine();
            } else {
                $this->tableUsage[$tableName] = [
                    'type' => 'query_builder',
                    'line' => $node->getLine(),
                ];
            }
        }
    }

    private function trackEloquentCall(string $modelName, int $line): void
    {
        // Try to derive table name from model name
        // This is a simple heuristic - in reality, table names can be customized
        $tableName = $this->modelToTableName($modelName);

        if (! isset($this->tableUsage[$tableName])) {
            $this->tableUsage[$tableName] = [
                'type' => 'eloquent',
                'line' => $line,
            ];
        } elseif ($this->tableUsage[$tableName]['type'] === 'query_builder') {
            // Mark as mixed
            $this->tableUsage[$tableName]['type'] = 'mixed';
            $this->tableUsage[$tableName]['eloquent_line'] = $line;
        }
        // If already eloquent or mixed, do nothing
    }

    private function checkMixedUsage(): void
    {
        $eloquentTables = [];
        $queryBuilderTables = [];
        $mixedTables = [];

        foreach ($this->tableUsage as $table => $usage) {
            if ($usage['type'] === 'eloquent') {
                $eloquentTables[$table] = $usage['line'];
            } elseif ($usage['type'] === 'mixed') {
                $mixedTables[$table] = $usage;
            } else {
                $queryBuilderTables[$table] = $usage['line'];
            }
        }

        // Report tables marked as mixed (used with both Eloquent and Query Builder)
        foreach ($mixedTables as $table => $usage) {
            $this->issues[] = [
                'message' => sprintf(
                    'Class "%s" uses both Eloquent and Query Builder for table "%s"',
                    $this->currentClassName ?? 'Unknown',
                    $table
                ),
                'line' => $usage['line'],
                'severity' => Severity::Medium,
                'recommendation' => 'Use consistent approach: prefer Eloquent for better code organization, global scopes, and relationships. Use Query Builder only for performance-critical raw queries. Mixing both approaches can bypass global scopes and make code harder to maintain',
                'code' => null,
            ];
        }

        // Also check if class has significant use of both (even on different tables)
        if (count($eloquentTables) > 0 && count($queryBuilderTables) > 2) {
            $firstQbLine = min($queryBuilderTables);
            $this->issues[] = [
                'message' => sprintf(
                    'Class "%s" mixes Eloquent and Query Builder approaches (%d Eloquent, %d Query Builder)',
                    $this->currentClassName ?? 'Unknown',
                    count($eloquentTables),
                    count($queryBuilderTables)
                ),
                'line' => $firstQbLine,
                'severity' => Severity::Low,
                'recommendation' => 'Consider using a consistent approach throughout the class. If using Eloquent elsewhere, continue with Eloquent for consistency',
                'code' => null,
            ];
        }
    }

    private function looksLikeModel(string $className): bool
    {
        // Simple heuristic: capitalized single word or namespaced class
        // that looks like a model name
        $parts = explode('\\', $className);
        $lastPart = end($parts);

        // Model names are typically capitalized
        if (! ctype_upper($lastPart[0] ?? '')) {
            return false;
        }

        // Exclude common non-model classes
        $excludedClasses = [
            'DB', 'Cache', 'Log', 'Event', 'Mail', 'Queue',
            'Route', 'Artisan', 'Config', 'Session', 'Request',
            'Response', 'Validator', 'Hash', 'Auth', 'Gate',
        ];

        return ! in_array($lastPart, $excludedClasses, true);
    }

    private function modelToTableName(string $modelName): string
    {
        // Simple pluralization - in reality this is more complex
        // This is just a heuristic for detection
        $parts = explode('\\', $modelName);
        $className = end($parts);

        // Convert PascalCase to snake_case and pluralize
        $snakeCase = strtolower(preg_replace('/(?<!^)[A-Z]/', '_$0', $className) ?? $className);

        // Simple pluralization
        if (str_ends_with($snakeCase, 'y')) {
            return substr($snakeCase, 0, -1).'ies';
        }

        if (str_ends_with($snakeCase, 's')) {
            return $snakeCase.'es';
        }

        return $snakeCase.'s';
    }
}
