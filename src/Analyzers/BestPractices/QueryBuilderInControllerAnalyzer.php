<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
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
 * Detects direct database query building in controllers.
 *
 * Checks for:
 * - DB facade usage in controllers
 * - Model query methods (where, join, etc.) in controllers
 * - Recommends repository pattern
 * - Excludes simple find(), findOrFail()
 */
class QueryBuilderInControllerAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Simple query methods that are acceptable in controllers.
     *
     * @var array<string>
     */
    private array $allowedMethods = [
        'find',
        'findOrFail',
        'findMany',
        'findOr',
        'all',
        'get',
        'first',
        'firstOrFail',
        'count',
    ];

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'query-builder-in-controller',
            name: 'Query Builder in Controller',
            description: 'Detects direct database query building in controllers that should use repositories or services',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['architecture', 'separation-of-concerns', 'maintainability', 'repository-pattern'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/query-builder-in-controller',
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $allowedMethods = $this->allowedMethods;

        foreach ($this->getPhpFiles() as $file) {
            // Only analyze controller files
            if (! $this->isController($file)) {
                continue;
            }

            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new QueryBuilderVisitor($allowedMethods);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Direct database query '{$issue['query']}' used in controller method '{$issue['method']}'",
                    location: new Location($file, $issue['line']),
                    severity: $this->getSeverityForQueryType($issue['type']),
                    recommendation: $this->getRecommendation($issue['query'], $issue['method'], $issue['type']),
                    metadata: [
                        'query' => $issue['query'],
                        'method' => $issue['method'],
                        'class' => $issue['class'],
                        'type' => $issue['type'],
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No direct database queries found in controllers');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} direct database query/queries in controllers",
            $issues
        );
    }

    /**
     * Check if file is a controller.
     */
    private function isController(string $file): bool
    {
        return str_contains($file, '/Controllers/') ||
               str_ends_with($file, 'Controller.php');
    }

    /**
     * Get severity based on query type.
     */
    private function getSeverityForQueryType(string $type): Severity
    {
        return match ($type) {
            'raw_query', 'join' => Severity::High,
            'complex_where', 'aggregation' => Severity::Medium,
            default => Severity::Low,
        };
    }

    /**
     * Get recommendation for query in controller.
     */
    private function getRecommendation(string $query, string $method, string $type): string
    {
        $base = "Controller method '{$method}' contains direct database query '{$query}'. Controllers should be thin and delegate data access to repositories or services. ";

        $strategies = [
            'Create a repository class to encapsulate database queries',
            'Use service classes for complex business logic with multiple queries',
            'Keep controllers focused on HTTP concerns (request/response)',
            'Move query logic to Eloquent model scopes for reusability',
            'Use query objects for complex query scenarios',
            'Follow Single Responsibility Principle for better testability',
        ];

        $example = <<<'PHP'

// Problem - Query logic in controller:
class UserController extends Controller
{
    public function activeUsers(Request $request)
    {
        $users = DB::table('users')
            ->where('active', true)
            ->where('verified', true)
            ->orderBy('last_login', 'desc')
            ->paginate(20);

        return view('users.index', compact('users'));
    }
}

// Solution - Use repository:
class UserController extends Controller
{
    public function __construct(
        private UserRepository $users
    ) {}

    public function activeUsers(Request $request)
    {
        $users = $this->users->getActiveVerified(perPage: 20);

        return view('users.index', compact('users'));
    }
}

// Repository implementation:
class UserRepository
{
    public function getActiveVerified(int $perPage = 20)
    {
        return User::query()
            ->active()
            ->verified()
            ->latest('last_login')
            ->paginate($perPage);
    }
}
PHP;

        return $base.'Best practices: '.implode('; ', $strategies).". Example:{$example}";
    }
}

/**
 * Visitor to detect query builder usage in controllers.
 */
class QueryBuilderVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{query: string, line: int, method: string, class: string, type: string}>
     */
    private array $issues = [];

    /**
     * Current class name.
     */
    private ?string $currentClass = null;

    /**
     * Current method name.
     */
    private ?string $currentMethod = null;

    /**
     * Query builder methods that indicate complex queries.
     *
     * @var array<string>
     */
    private array $queryMethods = [
        'where', 'whereIn', 'whereNotIn', 'whereBetween', 'whereNull', 'whereNotNull',
        'whereHas', 'whereDoesntHave', 'orWhere', 'whereRaw', 'havingRaw',
        'join', 'leftJoin', 'rightJoin', 'crossJoin', 'joinSub',
        'groupBy', 'having', 'orderBy', 'orderByRaw',
        'select', 'selectRaw', 'addSelect',
        'limit', 'offset', 'skip', 'take',
        'union', 'unionAll',
        'when', 'unless',
        'with', 'withCount', 'withSum', 'withAvg', 'withMin', 'withMax',
        'sum', 'avg', 'min', 'max', 'count',
    ];

    /**
     * @param  array<string>  $allowedMethods
     */
    public function __construct(
        private array $allowedMethods = []
    ) {}

    public function enterNode(Node $node)
    {
        // Track class entry
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = $node->name ? $node->name->toString() : 'Anonymous';

            return null;
        }

        // Track method entry
        if ($node instanceof Stmt\ClassMethod) {
            $this->currentMethod = $node->name->toString();

            return null;
        }

        // Only check inside methods
        if ($this->currentMethod === null) {
            return null;
        }

        // Check for DB facade usage
        if ($node instanceof Expr\StaticCall) {
            if ($node->class instanceof Node\Name) {
                $className = $node->class->toString();

                // Detect DB facade
                if ($className === 'DB' || str_ends_with($className, '\\DB')) {
                    if ($node->name instanceof Node\Identifier) {
                        $methodName = $node->name->toString();

                        // Flag raw queries and table() calls
                        if (in_array($methodName, ['table', 'select', 'insert', 'update', 'delete', 'statement', 'raw'])) {
                            $this->issues[] = [
                                'query' => "DB::{$methodName}()",
                                'line' => $node->getStartLine(),
                                'method' => $this->currentMethod,
                                'class' => $this->currentClass ?? 'Unknown',
                                'type' => $methodName === 'raw' ? 'raw_query' : 'db_facade',
                            ];
                        }
                    }
                }
            }
        }

        // Check for Model query builder methods
        if ($node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall) {
            if ($node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();

                // Skip allowed simple methods
                if (in_array($methodName, $this->allowedMethods)) {
                    return null;
                }

                // Check if it's a query builder method
                if (in_array($methodName, $this->queryMethods)) {
                    $queryType = $this->categorizeQuery($methodName);

                    $this->issues[] = [
                        'query' => $methodName.'()',
                        'line' => $node->getStartLine(),
                        'method' => $this->currentMethod,
                        'class' => $this->currentClass ?? 'Unknown',
                        'type' => $queryType,
                    ];
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Clear context on exit
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = null;
        }

        if ($node instanceof Stmt\ClassMethod) {
            $this->currentMethod = null;
        }

        return null;
    }

    /**
     * Categorize query type for severity.
     */
    private function categorizeQuery(string $method): string
    {
        if (in_array($method, ['join', 'leftJoin', 'rightJoin', 'crossJoin', 'joinSub'])) {
            return 'join';
        }

        if (in_array($method, ['whereRaw', 'havingRaw', 'selectRaw', 'orderByRaw'])) {
            return 'raw_query';
        }

        if (in_array($method, ['sum', 'avg', 'min', 'max', 'count', 'withCount', 'withSum', 'withAvg'])) {
            return 'aggregation';
        }

        if (in_array($method, ['where', 'whereIn', 'whereHas', 'orWhere'])) {
            return 'complex_where';
        }

        return 'query_builder';
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{query: string, line: int, method: string, class: string, type: string}>
     */
    public function getIssues(): array
    {
        // Deduplicate - only report first occurrence per method
        $unique = [];
        $seen = [];

        foreach ($this->issues as $issue) {
            $key = $issue['method'].'_'.$issue['query'];
            if (! isset($seen[$key])) {
                $unique[] = $issue;
                $seen[$key] = true;
            }
        }

        return $unique;
    }
}
