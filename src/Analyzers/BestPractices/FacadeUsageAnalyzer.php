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
 * Identifies excessive facade usage in classes.
 *
 * Checks for:
 * - Multiple different facades used in same class
 * - Threshold: > 5 different facades
 * - Recommends dependency injection
 * - Tracks facade coupling
 */
class FacadeUsageAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Threshold for maximum number of different facades per class.
     */
    private int $threshold = 5;

    /**
     * Known Laravel facades.
     *
     * @var array<string>
     */
    private array $facades = [
        'App', 'Artisan', 'Auth', 'Blade', 'Broadcast', 'Bus', 'Cache', 'Config',
        'Cookie', 'Crypt', 'Date', 'DB', 'Eloquent', 'Event', 'File', 'Gate',
        'Hash', 'Http', 'Lang', 'Log', 'Mail', 'Notification', 'Password',
        'Process', 'Queue', 'Redirect', 'Redis', 'Request', 'Response', 'Route',
        'Schema', 'Session', 'Storage', 'URL', 'Validator', 'View', 'Vite',
    ];

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'facade-usage',
            name: 'Facade Usage',
            description: 'Identifies excessive facade usage that makes classes hard to test and violates dependency inversion',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['architecture', 'testability', 'dependency-injection', 'facades', 'coupling'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/facade-usage',
            timeToFix: 25
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $threshold = $this->threshold;
        $facades = $this->facades;

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new FacadeUsageVisitor($facades, $threshold);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Class '{$issue['class']}' uses {$issue['count']} different facades (threshold: {$threshold})",
                    location: new Location($file, $issue['line']),
                    severity: $this->getSeverityForCount($issue['count'], $threshold),
                    recommendation: $this->getRecommendation($issue['class'], $issue['facades'], $issue['count']),
                    metadata: [
                        'class' => $issue['class'],
                        'facades' => $issue['facades'],
                        'count' => $issue['count'],
                        'threshold' => $threshold,
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No excessive facade usage detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} class(es) with excessive facade usage",
            $issues
        );
    }

    /**
     * Get severity based on facade count.
     */
    private function getSeverityForCount(int $count, int $threshold): Severity
    {
        $excess = $count - $threshold;

        if ($excess >= 5) {
            return Severity::High;
        }

        if ($excess >= 3) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Get recommendation for facade usage.
     *
     * @param  array<string>  $facades
     */
    private function getRecommendation(string $class, array $facades, int $count): string
    {
        $facadeList = implode(', ', array_map(fn ($f) => "'{$f}'", $facades));
        $base = "Class '{$class}' uses {$count} different facades: {$facadeList}. Excessive facade usage creates tight coupling to the framework and makes unit testing difficult. ";

        $strategies = [
            'Use dependency injection via constructor instead of facades',
            'Create interfaces for your dependencies to enable mocking',
            'Inject only the services you need, not entire facades',
            'Use Laravel\'s service container for automatic dependency resolution',
            'Consider splitting the class if it has too many responsibilities',
            'Facades hide dependencies - explicit injection makes them visible',
        ];

        $example = <<<'PHP'

// Problem - Multiple facades (hard to test):
class OrderProcessor
{
    public function process($orderId)
    {
        $order = DB::table('orders')->find($orderId);
        Cache::put("order_{$orderId}", $order, 3600);
        Log::info("Processing order {$orderId}");
        Event::dispatch(new OrderProcessing($order));
        Mail::to($order->customer)->send(new OrderConfirmation($order));
        Queue::push(new GenerateInvoice($order));
    }
}

// Solution - Dependency injection (testable):
class OrderProcessor
{
    public function __construct(
        private OrderRepository $orders,
        private CacheManager $cache,
        private LoggerInterface $logger,
        private EventDispatcher $events,
        private Mailer $mailer,
        private QueueManager $queue
    ) {}

    public function process($orderId)
    {
        $order = $this->orders->find($orderId);
        $this->cache->put("order_{$orderId}", $order, 3600);
        $this->logger->info("Processing order {$orderId}");
        $this->events->dispatch(new OrderProcessing($order));
        $this->mailer->to($order->customer)->send(new OrderConfirmation($order));
        $this->queue->push(new GenerateInvoice($order));
    }
}
PHP;

        return $base.'Best practices: '.implode('; ', $strategies).". Example:{$example}";
    }
}

/**
 * Visitor to track facade usage per class.
 */
class FacadeUsageVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{class: string, facades: array<string>, count: int, line: int}>
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
     * Facades used in current class.
     *
     * @var array<string, true>
     */
    private array $currentFacades = [];

    /**
     * @param  array<string>  $facades
     */
    public function __construct(
        private array $facades,
        private int $threshold
    ) {}

    public function enterNode(Node $node)
    {
        // Track class entry
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = $node->name ? $node->name->toString() : 'Anonymous';
            $this->currentClassLine = $node->getStartLine();
            $this->currentFacades = [];

            return null;
        }

        // Only track inside classes
        if ($this->currentClass === null) {
            return null;
        }

        // Detect facade static calls
        if ($node instanceof Expr\StaticCall) {
            if ($node->class instanceof Node\Name) {
                $className = $node->class->toString();

                // Check if it's a known facade
                if ($this->isFacade($className)) {
                    $facadeName = $this->extractFacadeName($className);
                    $this->currentFacades[$facadeName] = true;
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Check facade count on class exit
        if ($node instanceof Stmt\Class_) {
            $facadeCount = count($this->currentFacades);

            if ($facadeCount > $this->threshold) {
                $this->issues[] = [
                    'class' => $this->currentClass ?? 'Unknown',
                    'facades' => array_keys($this->currentFacades),
                    'count' => $facadeCount,
                    'line' => $this->currentClassLine,
                ];
            }

            // Reset state
            $this->currentClass = null;
            $this->currentClassLine = 0;
            $this->currentFacades = [];
        }

        return null;
    }

    /**
     * Check if class name is a facade.
     */
    private function isFacade(string $className): bool
    {
        // Simple facade name
        if (in_array($className, $this->facades, true)) {
            return true;
        }

        // Fully qualified facade name
        foreach ($this->facades as $facade) {
            if (str_ends_with($className, "\\{$facade}") || str_ends_with($className, "\\Facades\\{$facade}")) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract simple facade name from class reference.
     */
    private function extractFacadeName(string $className): string
    {
        $parts = explode('\\', $className);

        return end($parts);
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{class: string, facades: array<string>, count: int, line: int}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
