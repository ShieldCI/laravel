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
 * Detects manual service container resolution in application code.
 *
 * Checks for:
 * - app()->make() calls
 * - resolve() function calls
 * - App::make() static calls
 * - Excessive container access
 * - Recommends constructor injection
 */
class ServiceContainerResolutionAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'service-container-resolution',
            name: 'Service Container Resolution',
            description: 'Detects manual service container resolution that should use dependency injection',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['dependency-injection', 'architecture', 'testability', 'laravel', 'ioc'],
            docsUrl: 'https://laravel.com/docs/container'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            // Skip service providers - they legitimately use container
            if ($this->isServiceProvider($file)) {
                continue;
            }

            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new ServiceContainerVisitor;
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Manual service resolution in '{$issue['location']}': {$issue['pattern']}",
                    location: new Location($file, $issue['line']),
                    severity: Severity::Medium,
                    recommendation: $this->getRecommendation($issue['pattern'], $issue['location']),
                    metadata: [
                        'pattern' => $issue['pattern'],
                        'location' => $issue['location'],
                        'class' => $issue['class'],
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No manual service container resolution detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} instance(s) of manual service container resolution",
            $issues
        );
    }

    /**
     * Check if file is a service provider.
     */
    private function isServiceProvider(string $file): bool
    {
        return str_contains($file, '/Providers/') ||
               str_ends_with($file, 'ServiceProvider.php');
    }

    /**
     * Get recommendation for container resolution.
     */
    private function getRecommendation(string $pattern, string $location): string
    {
        $base = "Found manual service container resolution using '{$pattern}' in '{$location}'. Manual resolution is a service locator anti-pattern that hides dependencies and makes testing difficult. ";

        $strategies = [
            'Use constructor dependency injection instead of manual resolution',
            'Declare dependencies explicitly in the constructor',
            'Let Laravel\'s service container auto-wire dependencies',
            'Avoid app(), resolve(), or App::make() in application code',
            'Reserve manual resolution for service providers and bootstrap code',
            'Use method injection for dependencies needed in single methods',
            'Create interfaces for dependencies to enable easier mocking',
        ];

        $example = <<<'PHP'

// Problem - Manual service resolution (Service Locator):
class OrderProcessor
{
    public function process($orderId)
    {
        // Hidden dependencies - unclear what this class needs
        $repository = app(OrderRepository::class);
        $payment = resolve(PaymentGateway::class);
        $mailer = App::make('mailer');

        $order = $repository->find($orderId);
        $result = $payment->charge($order);
        $mailer->send(new OrderConfirmation($order));

        return $result;
    }
}

// Solution - Constructor dependency injection:
class OrderProcessor
{
    public function __construct(
        private OrderRepository $repository,
        private PaymentGateway $payment,
        private Mailer $mailer
    ) {}

    public function process($orderId)
    {
        // Dependencies are explicit and injected
        $order = $this->repository->find($orderId);
        $result = $this->payment->charge($order);
        $this->mailer->send(new OrderConfirmation($order));

        return $result;
    }
}

// Laravel automatically resolves constructor dependencies
// Usage in controller:
public function store(OrderProcessor $processor)
{
    return $processor->process($orderId);
}

// For testing:
$mock = Mockery::mock(PaymentGateway::class);
$processor = new OrderProcessor($repository, $mock, $mailer);
// Easy to test with injected mock!

// Note: Manual resolution IS acceptable in:
// - Service providers (bind, singleton, etc.)
// - Bootstrap files
// - Facades (they're designed for it)
// - Routes and middleware registration
PHP;

        return $base.'Best practices: '.implode('; ', $strategies).". Example:{$example}";
    }
}

/**
 * Visitor to detect service container resolution.
 */
class ServiceContainerVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{pattern: string, location: string, class: string, line: int}>
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

    public function __construct() {}

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

        // Detect app()->make() pattern
        if ($node instanceof Expr\MethodCall) {
            // Check for app()->make()
            if ($this->isAppHelper($node->var) && $node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();
                if (in_array($methodName, ['make', 'makeWith', 'resolve', 'get'])) {
                    $this->issues[] = [
                        'pattern' => "app()->{$methodName}()",
                        'location' => $this->getLocation(),
                        'class' => $this->currentClass ?? 'Unknown',
                        'line' => $node->getStartLine(),
                    ];
                }
            }
        }

        // Detect App::make() static calls
        if ($node instanceof Expr\StaticCall) {
            if ($node->class instanceof Node\Name) {
                $className = $node->class->toString();

                if (($className === 'App' || str_ends_with($className, '\\App')) &&
                    $node->name instanceof Node\Identifier) {
                    $methodName = $node->name->toString();
                    if (in_array($methodName, ['make', 'makeWith', 'resolve', 'get'])) {
                        $this->issues[] = [
                            'pattern' => "App::{$methodName}()",
                            'location' => $this->getLocation(),
                            'class' => $this->currentClass ?? 'Unknown',
                            'line' => $node->getStartLine(),
                        ];
                    }
                }
            }
        }

        // Detect resolve() function calls
        if ($node instanceof Expr\FuncCall) {
            if ($node->name instanceof Node\Name) {
                $functionName = $node->name->toString();
                if ($functionName === 'resolve') {
                    $this->issues[] = [
                        'pattern' => 'resolve()',
                        'location' => $this->getLocation(),
                        'class' => $this->currentClass ?? 'Unknown',
                        'line' => $node->getStartLine(),
                    ];
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Clear method context on exit
        if ($node instanceof Stmt\ClassMethod) {
            $this->currentMethod = null;
        }

        // Clear class context on exit
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = null;
        }

        return null;
    }

    /**
     * Check if expression is app() helper call.
     */
    private function isAppHelper(Node $expr): bool
    {
        if ($expr instanceof Expr\FuncCall) {
            if ($expr->name instanceof Node\Name) {
                return $expr->name->toString() === 'app';
            }
        }

        return false;
    }

    /**
     * Get current location string.
     */
    private function getLocation(): string
    {
        if ($this->currentMethod !== null) {
            return ($this->currentClass ?? 'Unknown').'::'.$this->currentMethod;
        }

        if ($this->currentClass !== null) {
            return $this->currentClass;
        }

        return 'global scope';
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{pattern: string, location: string, class: string, line: int}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
