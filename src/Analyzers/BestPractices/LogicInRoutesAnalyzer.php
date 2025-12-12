<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Detects business logic in route files.
 *
 * Finds closures in routes with > 5 lines, DB queries,
 * and business logic that should be in controllers/actions.
 */
class LogicInRoutesAnalyzer extends AbstractFileAnalyzer
{
    public const DEFAULT_MAX_CLOSURE_LINES = 5;

    private int $maxClosureLines;

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'logic-in-routes',
            name: 'Logic in Routes Analyzer',
            description: 'Detects business logic in route files that should be moved to controllers or action classes',
            category: Category::BestPractices,
            severity: Severity::High,
            tags: ['laravel', 'routes', 'mvc', 'architecture', 'best-practices'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/logic-in-routes',
            timeToFix: 20
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration
        $analyzerConfig = $this->config->get('shieldci.analyzers.best_practices.logic-in-routes', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->maxClosureLines = $analyzerConfig['max_closure_lines'] ?? self::DEFAULT_MAX_CLOSURE_LINES;

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

                $visitor = new LogicInRoutesVisitor($this->maxClosureLines);
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: $issue['message'],
                        filePath: $file,
                        lineNumber: $issue['line'],
                        severity: $issue['severity'],
                        recommendation: $issue['recommendation'],
                        code: $issue['code'],
                        metadata: $issue['metadata'] ?? []
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
    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string, metadata: array<string, mixed>}> */
    private array $issues = [];

    /** @var array<int, true> Track which lines already have issues to avoid duplicates */
    private array $reportedLines = [];

    public function __construct(
        private int $maxClosureLines
    ) {}

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
     * @return array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string, metadata: array<string, mixed>}>
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
        $line = $closure->getStartLine();

        // Skip if we've already reported an issue for this line
        if (isset($this->reportedLines[$line])) {
            return;
        }

        // Collect all problems with this closure
        $problems = [];
        $maxSeverity = Severity::Low;

        // Check for database queries (highest severity)
        if ($this->hasDbQueries($closure)) {
            $problems[] = 'database queries';
            $maxSeverity = Severity::Critical;
        }

        // Check for complex business logic
        if ($this->hasComplexBusinessLogic($closure)) {
            $problems[] = 'complex business logic';
            if ($maxSeverity->level() < Severity::High->level()) {
                $maxSeverity = Severity::High;
            }
        }

        // Count lines in closure
        $lineCount = $closure->getEndLine() - $closure->getStartLine();
        if ($lineCount > $this->maxClosureLines) {
            $problems[] = sprintf('%d lines (max: %d)', $lineCount, $this->maxClosureLines);
            if ($maxSeverity->level() < Severity::Medium->level()) {
                $maxSeverity = Severity::Medium;
            }
        }

        // If any problems found, create a consolidated issue
        if (! empty($problems)) {
            $this->reportedLines[$line] = true;

            $problemList = implode(', ', $problems);
            $code = $this->determineIssueCode($problems);

            $this->issues[] = [
                'message' => "Route closure contains {$problemList}",
                'line' => $line,
                'severity' => $maxSeverity,
                'recommendation' => $this->getRecommendation($problems),
                'code' => $code,
                'metadata' => [
                    'problems' => $problems,
                    'line_count' => $lineCount,
                    'has_db_queries' => in_array('database queries', $problems),
                    'has_business_logic' => in_array('complex business logic', $problems),
                ],
            ];
        }
    }

    /**
     * @param  array<string>  $problems
     */
    private function determineIssueCode(array $problems): string
    {
        // Prioritize codes by severity
        if (in_array('database queries', $problems)) {
            return 'route-has-db-queries';
        }

        if (in_array('complex business logic', $problems)) {
            return 'route-has-business-logic';
        }

        // Must be line count issue
        return 'route-closure-too-long';
    }

    /**
     * @param  array<string>  $problems
     */
    private function getRecommendation(array $problems): string
    {
        if (in_array('database queries', $problems)) {
            return 'Database queries should not be in route files. Move this logic to a controller method and use repositories or services for data access.';
        }

        if (in_array('complex business logic', $problems)) {
            return 'Complex business logic should be in service classes or controllers, not in route files. Route files should only define routes.';
        }

        return 'Move route logic to a controller method or single-action controller. Route files should only define routes, not contain implementation details.';
    }

    private function hasDbQueries(Node\Expr\Closure $closure): bool
    {
        $hasQuery = false;

        $visitor = new class($hasQuery) extends NodeVisitorAbstract
        {
            public function __construct(private bool &$hasQuery) {}

            public function enterNode(Node $node): ?Node
            {
                if ($this->hasQuery) {
                    return null;
                }

                // Check for DB facade calls
                if ($node instanceof Node\Expr\StaticCall) {
                    if ($node->class instanceof Node\Name && $node->class->toString() === 'DB') {
                        $this->hasQuery = true;

                        return null;
                    }
                }

                // Check for Eloquent model query methods (static calls on potential models)
                if ($node instanceof Node\Expr\StaticCall) {
                    if ($node->name instanceof Node\Identifier) {
                        $method = $node->name->toString();
                        // Only check common Eloquent static query methods
                        $staticQueryMethods = ['where', 'find', 'all', 'first', 'create', 'query'];
                        if (in_array($method, $staticQueryMethods, true)) {
                            // Additional check: is this being called on something that looks like a Model?
                            if ($node->class instanceof Node\Name) {
                                $className = $node->class->toString();
                                // Common model class patterns
                                if (
                                    str_ends_with($className, 'Model') ||
                                    preg_match('/^[A-Z][a-zA-Z]+$/', $className) // CamelCase single word
                                ) {
                                    $this->hasQuery = true;
                                }
                            }
                        }
                    }
                }

                // Check for query builder method chains (->where(), ->get(), etc.)
                if ($node instanceof Node\Expr\MethodCall) {
                    if ($node->name instanceof Node\Identifier) {
                        $method = $node->name->toString();
                        // Methods that are almost certainly query builder methods
                        $queryBuilderMethods = [
                            'select', 'where', 'orWhere', 'whereIn', 'whereNotIn',
                            'join', 'leftJoin', 'orderBy', 'groupBy', 'having',
                            'limit', 'offset', 'take', 'skip',
                        ];
                        if (in_array($method, $queryBuilderMethods, true)) {
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

    private function hasComplexBusinessLogic(Node\Expr\Closure $closure): bool
    {
        $hasComplexLogic = false;
        $ifDepth = 0;
        $hasLoops = false;

        $visitor = new class($hasComplexLogic, $ifDepth, $hasLoops) extends NodeVisitorAbstract
        {
            public function __construct(
                private bool &$hasComplexLogic,
                private int &$ifDepth,
                private bool &$hasLoops
            ) {}

            public function enterNode(Node $node): ?Node
            {
                if ($this->hasComplexLogic) {
                    return null;
                }

                // Check for loops (always complex)
                if ($node instanceof Node\Stmt\Foreach_
                    || $node instanceof Node\Stmt\For_
                    || $node instanceof Node\Stmt\While_
                    || $node instanceof Node\Stmt\Do_
                ) {
                    $this->hasComplexLogic = true;
                    $this->hasLoops = true;

                    return null;
                }

                // Track nested conditionals (nested if = complex)
                if ($node instanceof Node\Stmt\If_) {
                    $this->ifDepth++;
                    if ($this->ifDepth > 1) {
                        // Nested if statements indicate complexity
                        $this->hasComplexLogic = true;
                    }
                }

                // Check for complex calculations (only in loops or nested logic)
                if ($this->hasLoops || $this->ifDepth > 1) {
                    if ($node instanceof Node\Expr\BinaryOp\Plus
                        || $node instanceof Node\Expr\BinaryOp\Minus
                        || $node instanceof Node\Expr\BinaryOp\Mul
                        || $node instanceof Node\Expr\BinaryOp\Div
                    ) {
                        $this->hasComplexLogic = true;
                    }
                }

                return null;
            }

            public function leaveNode(Node $node): ?Node
            {
                // Track when leaving if statements
                if ($node instanceof Node\Stmt\If_) {
                    $this->ifDepth--;
                }

                return null;
            }
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($closure->stmts ?? []);

        return $hasComplexLogic;
    }
}
