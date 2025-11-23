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
 * Detects inconsistent naming patterns within the codebase.
 *
 * Checks for:
 * - Mixed naming styles (snake_case vs camelCase)
 * - Inconsistent method prefixes (get/fetch, set/update)
 * - Similar methods with different naming patterns
 * - Controller action naming inconsistencies
 */
class InconsistentNamingAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'inconsistent-naming',
            name: 'Inconsistent Naming',
            description: 'Detects inconsistent naming patterns that reduce code readability and predictability',
            category: Category::CodeQuality,
            severity: Severity::Low,
            tags: ['naming', 'consistency', 'code-quality', 'maintainability', 'conventions'],
            docsUrl: 'https://docs.shieldci.com/analyzers/code-quality/inconsistent-naming',
            timeToFix: 20
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Collect all methods from all files
        $allMethods = [];

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new InconsistentNamingVisitor($file);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getMethods() as $method) {
                $allMethods[] = $method;
            }
        }

        // Analyze for inconsistencies
        $inconsistencies = $this->findNamingInconsistencies($allMethods);

        foreach ($inconsistencies as $inconsistency) {
            $issues[] = $this->createIssue(
                message: $inconsistency['message'],
                location: new Location($inconsistency['file'], $inconsistency['line']),
                severity: Severity::Low,
                recommendation: $this->getRecommendation($inconsistency['type'], $inconsistency),
                metadata: [
                    'type' => $inconsistency['type'],
                    'methods' => $inconsistency['methods'] ?? [],
                    'pattern' => $inconsistency['pattern'] ?? '',
                    'file' => $inconsistency['file'],
                ]
            );
        }

        if (empty($issues)) {
            return $this->passed('Naming patterns are consistent across the codebase');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} naming inconsistenc(y|ies)",
            $issues
        );
    }

    /**
     * Find naming inconsistencies.
     *
     * @param  array<array{name: string, class: string, file: string, line: int, type: string}>  $methods
     * @return array<array{message: string, type: string, file: string, line: int, methods?: array<string>, pattern?: string}>
     */
    private function findNamingInconsistencies(array $methods): array
    {
        $issues = [];

        // Group methods by class
        $classMethods = [];
        foreach ($methods as $method) {
            $classMethods[$method['class']][] = $method;
        }

        // Check each class for inconsistencies
        foreach ($classMethods as $className => $methods) {
            // Check for mixed case styles (snake_case and camelCase in same class)
            $snakeCaseMethods = [];
            $camelCaseMethods = [];

            foreach ($methods as $method) {
                if ($this->isSnakeCase($method['name'])) {
                    $snakeCaseMethods[] = $method['name'];
                } elseif ($this->isCamelCase($method['name'])) {
                    $camelCaseMethods[] = $method['name'];
                }
            }

            if (! empty($snakeCaseMethods) && ! empty($camelCaseMethods)) {
                $issues[] = [
                    'message' => "Class '{$className}' mixes snake_case and camelCase method names",
                    'type' => 'mixed_case_style',
                    'file' => $methods[0]['file'],
                    'line' => $methods[0]['line'],
                    'methods' => array_merge($snakeCaseMethods, $camelCaseMethods),
                ];
            }

            // Check for inconsistent prefixes
            $prefixGroups = $this->groupByPrefix($methods);
            foreach ($prefixGroups as $action => $prefixes) {
                if (count($prefixes) > 1) {
                    $issues[] = [
                        'message' => "Class '{$className}' uses inconsistent prefixes for '{$action}' actions: ".implode(', ', array_keys($prefixes)),
                        'type' => 'inconsistent_prefix',
                        'file' => $methods[0]['file'],
                        'line' => $methods[0]['line'],
                        'pattern' => $action,
                        'methods' => array_merge(...array_values($prefixes)),
                    ];
                }
            }
        }

        return $issues;
    }

    /**
     * Check if name is snake_case.
     */
    private function isSnakeCase(string $name): bool
    {
        return str_contains($name, '_') && $name === strtolower($name);
    }

    /**
     * Check if name is camelCase (or PascalCase).
     */
    private function isCamelCase(string $name): bool
    {
        return ! str_contains($name, '_') && preg_match('/[a-z]+[A-Z]/', $name) === 1;
    }

    /**
     * Group methods by their action prefix.
     *
     * @param  array<array{name: string, class: string, file: string, line: int, type: string}>  $methods
     * @return array<string, array<string, array<string>>>
     */
    private function groupByPrefix(array $methods): array
    {
        $prefixGroups = [];

        // Common action patterns
        $actionSynonyms = [
            'retrieve' => ['get', 'fetch', 'find', 'retrieve', 'load'],
            'modify' => ['set', 'update', 'modify', 'change', 'edit'],
            'remove' => ['delete', 'remove', 'destroy', 'clear'],
            'create' => ['create', 'add', 'insert', 'make', 'new'],
            'check' => ['is', 'has', 'can', 'should', 'check', 'verify'],
        ];

        foreach ($methods as $method) {
            $methodName = $method['name'];

            // Skip magic methods and constructors
            if (str_starts_with($methodName, '__')) {
                continue;
            }

            // Find which action group this method belongs to
            foreach ($actionSynonyms as $action => $synonyms) {
                foreach ($synonyms as $prefix) {
                    if (str_starts_with($methodName, $prefix)) {
                        if (! isset($prefixGroups[$action])) {
                            $prefixGroups[$action] = [];
                        }
                        if (! isset($prefixGroups[$action][$prefix])) {
                            $prefixGroups[$action][$prefix] = [];
                        }
                        $prefixGroups[$action][$prefix][] = $methodName;
                        break 2; // Found match, move to next method
                    }
                }
            }
        }

        return $prefixGroups;
    }

    /**
     * Get recommendation for naming inconsistency.
     *
     * @param  array{message: string, type: string, file: string, line: int, methods?: array<string>, pattern?: string}  $issue
     */
    private function getRecommendation(string $type, array $issue): string
    {
        $base = match ($type) {
            'mixed_case_style' => 'Mixing snake_case and camelCase within the same class makes the code harder to read and predict. ',
            'inconsistent_prefix' => 'Using different prefixes for the same action creates confusion about method behavior. ',
            default => 'Inconsistent naming reduces code predictability and readability. ',
        };

        $strategies = [
            'Choose one naming convention and apply it consistently',
            'Follow PSR-12 standard: camelCase for methods and properties',
            'Use consistent verb prefixes: get/set, create/delete, add/remove',
            'Establish naming conventions in your team\'s style guide',
            'Use automated tools to enforce naming consistency',
            'Refactor similar methods to use the same naming pattern',
        ];

        $example = match ($type) {
            'mixed_case_style' => <<<'PHP'

// Problem - Mixed naming styles:
class UserService
{
    public function getUser($id) { }        // camelCase
    public function update_user($data) { }  // snake_case
    public function deleteUser($id) { }     // camelCase
    public function find_by_email($email) { } // snake_case
}

// Solution - Consistent camelCase:
class UserService
{
    public function getUser($id) { }
    public function updateUser($data) { }
    public function deleteUser($id) { }
    public function findByEmail($email) { }
}
PHP,
            'inconsistent_prefix' => <<<'PHP'

// Problem - Inconsistent prefixes:
class ProductRepository
{
    public function getProduct($id) { }      // get
    public function fetchCategories() { }    // fetch (same as get)
    public function findBySku($sku) { }      // find (same as get)

    public function updateProduct($data) { } // update
    public function setPrice($price) { }     // set (same as update)
}

// Solution - Consistent prefixes:
class ProductRepository
{
    public function getProduct($id) { }
    public function getCategories() { }
    public function getBySku($sku) { }

    public function updateProduct($data) { }
    public function updatePrice($price) { }
}

// Alternative - Use semantic names:
class ProductRepository
{
    public function find($id) { }
    public function findBySku($sku) { }
    public function categories() { }

    public function update($data) { }
    public function changePrice($price) { }
}
PHP,
            default => <<<'PHP'

// Problem - Inconsistent naming:
class OrderService
{
    public function create_order() { }
    public function getOrderStatus() { }
    public function UpdateShipping() { }
}

// Solution - Consistent naming:
class OrderService
{
    public function createOrder() { }
    public function getOrderStatus() { }
    public function updateShipping() { }
}
PHP,
        };

        return $base.'Best practices: '.implode('; ', $strategies).". Example:{$example}";
    }
}

/**
 * Visitor to collect method names for consistency analysis.
 */
class InconsistentNamingVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{name: string, class: string, file: string, line: int, type: string}>
     */
    private array $methods = [];

    /**
     * Current class name.
     */
    private ?string $currentClass = null;

    public function __construct(
        private string $file
    ) {}

    public function enterNode(Node $node)
    {
        // Track class entry
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = $node->name ? $node->name->toString() : 'Anonymous';

            return null;
        }

        // Collect method names
        if ($node instanceof Stmt\ClassMethod) {
            $methodName = $node->name->toString();

            $this->methods[] = [
                'name' => $methodName,
                'class' => $this->currentClass ?? 'Unknown',
                'file' => $this->file,
                'line' => $node->getStartLine(),
                'type' => 'method',
            ];
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
     * Get collected methods.
     *
     * @return array<int, array{name: string, class: string, file: string, line: int, type: string}>
     */
    public function getMethods(): array
    {
        return $this->methods;
    }
}
