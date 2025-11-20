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
 * Detects business logic in route files.
 *
 * Finds closures in routes with > 5 lines, DB queries,
 * and business logic that should be in controllers/actions.
 */
class LogicInRoutesAnalyzer extends AbstractFileAnalyzer
{
    public const MAX_CLOSURE_LINES = 5;

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'logic-in-routes',
            name: 'Logic in Routes Detector',
            description: 'Detects business logic in route files that should be moved to controllers or action classes',
            category: Category::BestPractices,
            severity: Severity::High,
            tags: ['laravel', 'routes', 'mvc', 'architecture'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/logic-in-routes',
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Only set default paths if not already set (allows tests to override)
        if (empty($this->paths)) {
            $this->setBasePath(base_path());
            $this->setPaths(['routes']);
        }

        $routeFiles = $this->getPhpFiles();

        foreach ($routeFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new LogicInRoutesVisitor;
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
            return $this->passed('No business logic found in route files');
        }

        return $this->failed(
            sprintf('Found %d route(s) with business logic that should be moved to controllers', count($issues)),
            $issues
        );
    }
}

/**
 * Visitor to detect logic in route closures.
 */
class LogicInRoutesVisitor extends NodeVisitorAbstract
{
    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    public function enterNode(Node $node): ?Node
    {
        // Detect Route::* method calls
        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name && $node->class->toString() === 'Route') {
                $this->analyzeRouteCall($node);
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

    private function analyzeRouteCall(Node\Expr\StaticCall $node): void
    {
        if (empty($node->args)) {
            return;
        }

        // Check each argument for closures
        foreach ($node->args as $arg) {
            if ($arg->value instanceof Node\Expr\Closure) {
                $this->analyzeClosure($arg->value);
            }
        }
    }

    private function analyzeClosure(Node\Expr\Closure $closure): void
    {
        // Count lines in closure
        $lineCount = $closure->getEndLine() - $closure->getStartLine();

        if ($lineCount > LogicInRoutesAnalyzer::MAX_CLOSURE_LINES) {
            $this->issues[] = [
                'message' => sprintf(
                    'Route closure has %d lines (max recommended: %d). Move to controller or action class',
                    $lineCount,
                    LogicInRoutesAnalyzer::MAX_CLOSURE_LINES
                ),
                'line' => $closure->getStartLine(),
                'severity' => Severity::High,
                'recommendation' => 'Move route logic to a controller method or action class. Route files should only define routes, not contain business logic',
                'code' => null,
            ];
        }

        // Check for database queries in closure
        if ($this->hasDbQueries($closure)) {
            $this->issues[] = [
                'message' => 'Route closure contains database queries. Move to controller or repository',
                'line' => $closure->getStartLine(),
                'severity' => Severity::Critical,
                'recommendation' => 'Database queries should not be in route files. Use controllers and repositories for data access',
                'code' => null,
            ];
        }

        // Check for business logic patterns
        if ($this->hasBusinessLogic($closure)) {
            $this->issues[] = [
                'message' => 'Route closure contains business logic (loops, conditionals, calculations)',
                'line' => $closure->getStartLine(),
                'severity' => Severity::High,
                'recommendation' => 'Business logic should be in service classes or controllers, not in route files',
                'code' => null,
            ];
        }
    }

    private function hasDbQueries(Node\Expr\Closure $closure): bool
    {
        $hasQuery = false;

        $visitor = new class($hasQuery) extends NodeVisitorAbstract
        {
            public function __construct(private bool &$hasQuery) {}

            public function enterNode(Node $node): ?Node
            {
                // Skip if already found
                if ($this->hasQuery) {
                    return null;
                }

                // Check for DB facade calls
                if ($node instanceof Node\Expr\StaticCall) {
                    if ($node->class instanceof Node\Name && $node->class->toString() === 'DB') {
                        $this->hasQuery = true;
                    }
                }

                // Check for Eloquent model queries
                if ($node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall) {
                    if ($node->name instanceof Node\Identifier) {
                        $method = $node->name->toString();
                        $queryMethods = ['where', 'find', 'all', 'get', 'first', 'create', 'update', 'delete', 'save'];
                        if (in_array($method, $queryMethods, true)) {
                            $this->hasQuery = true;
                        }
                    }
                }

                return null;
            }
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($closure->stmts ?? []);

        return $hasQuery;
    }

    private function hasBusinessLogic(Node\Expr\Closure $closure): bool
    {
        $hasLogic = false;

        $visitor = new class($hasLogic) extends NodeVisitorAbstract
        {
            public function __construct(private bool &$hasLogic) {}

            public function enterNode(Node $node): ?Node
            {
                // Skip if already found
                if ($this->hasLogic) {
                    return null;
                }

                // Check for loops
                if ($node instanceof Node\Stmt\Foreach_
                    || $node instanceof Node\Stmt\For_
                    || $node instanceof Node\Stmt\While_
                ) {
                    $this->hasLogic = true;
                }

                // Check for conditionals (more than simple checks)
                if ($node instanceof Node\Stmt\If_) {
                    // Count complexity
                    $this->hasLogic = true;
                }

                // Check for calculations
                if ($node instanceof Node\Expr\BinaryOp\Plus
                    || $node instanceof Node\Expr\BinaryOp\Minus
                    || $node instanceof Node\Expr\BinaryOp\Mul
                    || $node instanceof Node\Expr\BinaryOp\Div
                ) {
                    $this->hasLogic = true;
                }

                return null;
            }
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($closure->stmts ?? []);

        return $hasLogic;
    }
}
