<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\CodeQuality;

use PhpParser\Node;
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
 * Detects methods with too many parameters.
 *
 * Checks for:
 * - Methods exceeding parameter count threshold
 * - Constructor parameter count
 * - Recommends parameter objects/DTOs
 * - Excludes common Laravel patterns
 */
class ParameterCountAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Maximum allowed parameters for regular methods.
     */
    private int $maxParameters = 4;

    /**
     * Maximum allowed parameters for constructors.
     */
    private int $maxConstructorParameters = 6;

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'parameter-count',
            name: 'Parameter Count',
            description: 'Detects methods with too many parameters that should use parameter objects or refactoring',
            category: Category::CodeQuality,
            severity: Severity::Medium,
            tags: ['complexity', 'maintainability', 'code-quality', 'refactoring', 'parameters'],
            docsUrl: 'https://refactoring.guru/smells/long-parameter-list'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $maxParameters = $this->maxParameters;
        $maxConstructorParameters = $this->maxConstructorParameters;

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new ParameterCountVisitor($maxParameters, $maxConstructorParameters);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Method '{$issue['method']}' has {$issue['count']} parameters (threshold: {$issue['threshold']})",
                    location: new Location($file, $issue['line']),
                    severity: $this->getSeverityForCount($issue['count'], $issue['threshold']),
                    recommendation: $this->getRecommendation($issue['method'], $issue['count'], $issue['isConstructor']),
                    metadata: [
                        'method' => $issue['method'],
                        'class' => $issue['class'],
                        'count' => $issue['count'],
                        'threshold' => $issue['threshold'],
                        'isConstructor' => $issue['isConstructor'],
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('All methods have reasonable parameter counts');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} method(s) with too many parameters",
            $issues
        );
    }

    /**
     * Get severity based on parameter count excess.
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
     * Get recommendation for parameter count issue.
     */
    private function getRecommendation(string $method, int $count, bool $isConstructor): string
    {
        $base = "Method '{$method}' has {$count} parameters. Long parameter lists are difficult to understand, remember, and maintain. ";

        $strategies = [
            'Introduce Parameter Object - group related parameters into a dedicated class',
            'Use Data Transfer Objects (DTOs) to encapsulate parameter data',
            'Apply Preserve Whole Object - pass the entire object instead of individual fields',
            'Use builder pattern for objects with many optional parameters',
            'Consider using arrays or collections for variable parameter sets',
            'Review if the method is doing too much - may need to be split',
        ];

        if ($isConstructor) {
            $strategies[] = 'For constructors, consider using Factory pattern or Builder pattern';
            $strategies[] = 'Use setter methods or configuration objects for optional dependencies';
        }

        $example = $isConstructor ? <<<'PHP'

// Problem - Constructor with many parameters:
class OrderProcessor
{
    public function __construct(
        private UserRepository $users,
        private ProductRepository $products,
        private PaymentGateway $payment,
        private ShippingService $shipping,
        private NotificationService $notifications,
        private TaxCalculator $taxCalculator,
        private DiscountCalculator $discountCalculator,
        private InventoryService $inventory
    ) {}
}

// Solution 1 - Use service locator or facade:
class OrderProcessor
{
    public function __construct(
        private OrderDependencies $dependencies
    ) {}
}

class OrderDependencies
{
    public function __construct(
        public UserRepository $users,
        public ProductRepository $products,
        public PaymentGateway $payment,
        public ShippingService $shipping,
        public NotificationService $notifications,
        public TaxCalculator $taxCalculator,
        public DiscountCalculator $discountCalculator,
        public InventoryService $inventory
    ) {}
}

// Solution 2 - Split responsibilities:
class OrderProcessor
{
    public function __construct(
        private OrderValidator $validator,
        private PaymentProcessor $paymentProcessor,
        private FulfillmentService $fulfillment
    ) {}
}
PHP : <<<'PHP'

// Problem - Method with many parameters:
public function createOrder(
    int $userId,
    int $productId,
    int $quantity,
    string $shippingAddress,
    string $billingAddress,
    string $paymentMethod,
    ?string $couponCode,
    bool $giftWrap,
    ?string $giftMessage
) {
    // Complex method
}

// Solution 1 - Parameter Object:
public function createOrder(CreateOrderRequest $request)
{
    $userId = $request->userId;
    $productId = $request->productId;
    // Clear, typed access
}

class CreateOrderRequest
{
    public function __construct(
        public int $userId,
        public int $productId,
        public int $quantity,
        public Address $shippingAddress,
        public Address $billingAddress,
        public PaymentMethod $paymentMethod,
        public ?CouponCode $couponCode = null,
        public bool $giftWrap = false,
        public ?string $giftMessage = null
    ) {}
}

// Solution 2 - Preserve Whole Object:
public function createOrder(User $user, Order $order)
{
    // Access $user->id, $order->productId, etc.
    // More cohesive and self-documenting
}
PHP;

        return $base.'Refactoring strategies: '.implode('; ', $strategies).". Example:{$example}";
    }
}

/**
 * Visitor to detect methods with too many parameters.
 */
class ParameterCountVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{method: string, class: string, count: int, threshold: int, isConstructor: bool, line: int}>
     */
    private array $issues = [];

    /**
     * Current class name.
     */
    private ?string $currentClass = null;

    public function __construct(
        private int $maxParameters,
        private int $maxConstructorParameters
    ) {}

    public function enterNode(Node $node)
    {
        // Track class entry
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = $node->name ? $node->name->toString() : 'Anonymous';

            return null;
        }

        // Check method parameters
        if ($node instanceof Stmt\ClassMethod) {
            $methodName = $node->name->toString();
            $paramCount = count($node->params);
            $isConstructor = $methodName === '__construct';

            // Determine threshold
            $threshold = $isConstructor ? $this->maxConstructorParameters : $this->maxParameters;

            // Check if exceeds threshold
            if ($paramCount > $threshold) {
                $this->issues[] = [
                    'method' => ($this->currentClass ?? 'Unknown').'::'.$methodName,
                    'class' => $this->currentClass ?? 'Unknown',
                    'count' => $paramCount,
                    'threshold' => $threshold,
                    'isConstructor' => $isConstructor,
                    'line' => $node->getStartLine(),
                ];
            }
        }

        // Check standalone functions
        if ($node instanceof Stmt\Function_) {
            $functionName = $node->name->toString();
            $paramCount = count($node->params);

            if ($paramCount > $this->maxParameters) {
                $this->issues[] = [
                    'method' => $functionName.'()',
                    'class' => 'global',
                    'count' => $paramCount,
                    'threshold' => $this->maxParameters,
                    'isConstructor' => false,
                    'line' => $node->getStartLine(),
                ];
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Clear class context on exit
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = null;
        }

        return null;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{method: string, class: string, count: int, threshold: int, isConstructor: bool, line: int}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
