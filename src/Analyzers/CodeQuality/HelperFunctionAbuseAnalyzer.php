<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\CodeQuality;

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
 * Detects excessive use of Laravel helper functions.
 *
 * Checks for:
 * - Multiple helper function calls in same class
 * - Threshold violations
 * - Recommends proper dependency injection
 * - Controllers and services primarily affected
 */
class HelperFunctionAbuseAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Maximum allowed helper function calls per class.
     */
    private int $threshold = 5;

    /**
     * Laravel helper functions to track.
     *
     * @var array<string>
     */
    private array $helperFunctions = [
        'app', 'auth', 'cache', 'config', 'cookie', 'event', 'logger', 'old',
        'redirect', 'request', 'response', 'route', 'session', 'storage_path',
        'url', 'view', 'abort', 'abort_if', 'abort_unless', 'bcrypt',
        'collect', 'dd', 'dispatch', 'info', 'now', 'optional', 'policy',
        'resolve', 'retry', 'tap', 'throw_if', 'throw_unless', 'today',
        'validator', 'value', 'report',
    ];

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'helper-function-abuse',
            name: 'Helper Function Abuse',
            description: 'Detects excessive use of Laravel helper functions that hide dependencies and hinder testing',
            category: Category::CodeQuality,
            severity: Severity::Low,
            tags: ['testability', 'dependency-injection', 'laravel', 'helpers', 'code-quality'],
            docsUrl: 'https://laravel.com/docs/helpers'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $threshold = $this->threshold;
        $helpers = $this->helperFunctions;

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new HelperFunctionVisitor($helpers, $threshold);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Class '{$issue['class']}' uses {$issue['count']} helper function calls (threshold: {$threshold})",
                    location: new Location($file, $issue['line']),
                    severity: $this->getSeverityForCount($issue['count'], $threshold),
                    recommendation: $this->getRecommendation($issue['class'], $issue['helpers'], $issue['count']),
                    metadata: [
                        'class' => $issue['class'],
                        'helpers' => $issue['helpers'],
                        'count' => $issue['count'],
                        'threshold' => $threshold,
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No excessive helper function usage detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} class(es) with excessive helper function usage",
            $issues
        );
    }

    /**
     * Get severity based on helper count.
     */
    private function getSeverityForCount(int $count, int $threshold): Severity
    {
        $excess = $count - $threshold;

        if ($excess >= 10) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Get recommendation for helper function abuse.
     *
     * @param  array<string, int>  $helpers
     */
    private function getRecommendation(string $class, array $helpers, int $count): string
    {
        $helperList = [];
        foreach ($helpers as $helper => $usageCount) {
            $helperList[] = "{$helper}() ({$usageCount}x)";
        }
        $helperString = implode(', ', $helperList);

        $base = "Class '{$class}' uses {$count} helper function calls: {$helperString}. While Laravel helpers are convenient, excessive use hides dependencies and makes unit testing difficult. ";

        $strategies = [
            'Use dependency injection in constructor instead of helper functions',
            'Inject specific services rather than using app() or resolve()',
            'For request data, inject Request object instead of using request() helper',
            'For authentication, inject AuthManager instead of auth() helper',
            'For configuration, inject Repository instead of config() helper',
            'Create dedicated service classes for complex logic',
            'Reserve helpers for views, routes, and simple scripts',
        ];

        $example = <<<'PHP'

// Problem - Heavy helper usage (hard to test):
class OrderController
{
    public function store()
    {
        $user = auth()->user();                    // Helper
        $data = request()->all();                  // Helper
        $validator = validator($data, []);         // Helper

        if ($validator->fails()) {
            return redirect()->back();             // Helper
        }

        $order = app(OrderService::class)          // Helper
            ->create($data);

        cache()->put("order_{$order->id}", $order); // Helper
        event(new OrderCreated($order));           // Helper

        return response()->json($order);           // Helper
    }
}

// Solution - Dependency injection (testable):
class OrderController
{
    public function __construct(
        private OrderService $orders,
        private CacheManager $cache,
        private EventDispatcher $events
    ) {}

    public function store(Request $request)
    {
        $user = $request->user();
        $validated = $request->validate([
            // validation rules
        ]);

        $order = $this->orders->create($validated);

        $this->cache->put("order_{$order->id}", $order);
        $this->events->dispatch(new OrderCreated($order));

        return response()->json($order);
    }
}

// Note: Using response() helper at end is acceptable
// as it's just for response creation, not business logic
PHP;

        return $base.'Best practices: '.implode('; ', $strategies).". Example:{$example}";
    }
}

/**
 * Visitor to track helper function usage.
 */
class HelperFunctionVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{class: string, helpers: array<string, int>, count: int, line: int}>
     */
    private array $issues = [];

    /**
     * Current class name.
     */
    private ?string $currentClass = null;

    /**
     * Current class start line.
     */
    private int $currentClassLine = 0;

    /**
     * Helper function calls in current class.
     *
     * @var array<string, int>
     */
    private array $currentHelpers = [];

    /**
     * @param  array<string>  $helperFunctions
     */
    public function __construct(
        private array $helperFunctions,
        private int $threshold
    ) {}

    public function enterNode(Node $node)
    {
        // Track class entry
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = $node->name ? $node->name->toString() : 'Anonymous';
            $this->currentClassLine = $node->getStartLine();
            $this->currentHelpers = [];

            return null;
        }

        // Only track inside classes
        if ($this->currentClass === null) {
            return null;
        }

        // Detect helper function calls
        if ($node instanceof Expr\FuncCall) {
            if ($node->name instanceof Node\Name) {
                $functionName = $node->name->toString();

                // Check if it's a tracked helper
                if (in_array($functionName, $this->helperFunctions, true)) {
                    if (! isset($this->currentHelpers[$functionName])) {
                        $this->currentHelpers[$functionName] = 0;
                    }
                    $this->currentHelpers[$functionName]++;
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Check helper count on class exit
        if ($node instanceof Stmt\Class_) {
            $helperCount = array_sum($this->currentHelpers);

            if ($helperCount > $this->threshold) {
                $this->issues[] = [
                    'class' => $this->currentClass ?? 'Unknown',
                    'helpers' => $this->currentHelpers,
                    'count' => $helperCount,
                    'line' => $this->currentClassLine,
                ];
            }

            // Reset state
            $this->currentClass = null;
            $this->currentClassLine = 0;
            $this->currentHelpers = [];
        }

        return null;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{class: string, helpers: array<string, int>, count: int, line: int}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
