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
 * Detects methods with multiple parameters of the same type.
 *
 * Checks for:
 * - Multiple parameters of same primitive type (string, int, etc.)
 * - Threshold: > 3 parameters of same type
 * - Recommends Data Transfer Objects (DTOs)
 * - Focuses on type cohesion rather than total count
 */
class LongParameterListAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Maximum allowed parameters of same type.
     */
    private int $threshold = 3;

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'long-parameter-list',
            name: 'Long Parameter List',
            description: 'Detects methods with multiple parameters of the same type that should use DTOs',
            category: Category::CodeQuality,
            severity: Severity::Low,
            tags: ['maintainability', 'code-quality', 'refactoring', 'dto', 'parameters'],
            docsUrl: 'https://refactoring.guru/smells/long-parameter-list'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $threshold = $this->threshold;

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new LongParameterListVisitor($threshold);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: "Method '{$issue['method']}' has {$issue['count']} parameters of type '{$issue['type']}' (threshold: {$threshold})",
                    location: new Location($file, $issue['line']),
                    severity: Severity::Low,
                    recommendation: $this->getRecommendation($issue['method'], $issue['type'], $issue['count'], $issue['paramNames']),
                    metadata: [
                        'method' => $issue['method'],
                        'class' => $issue['class'],
                        'type' => $issue['type'],
                        'count' => $issue['count'],
                        'threshold' => $threshold,
                        'paramNames' => $issue['paramNames'],
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('No methods with excessive same-type parameters detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} method(s) with multiple same-type parameters",
            $issues
        );
    }

    /**
     * Get recommendation for long parameter list.
     *
     * @param  array<string>  $paramNames
     */
    private function getRecommendation(string $method, string $type, int $count, array $paramNames): string
    {
        $paramList = implode(', ', array_map(fn ($p) => "\${$p}", $paramNames));
        $base = "Method '{$method}' has {$count} parameters of type '{$type}': {$paramList}. Multiple parameters of the same type are error-prone and hard to understand. ";

        $strategies = [
            'Create a Data Transfer Object (DTO) to group related parameters',
            'Use Value Objects for parameters that belong together',
            'Consider if the method is doing too much and should be split',
            'Use named parameters (PHP 8.0+) if parameters must remain separate',
            'Create builder pattern for complex object construction',
            'Group related parameters into configuration arrays or objects',
        ];

        $example = <<<'PHP'

// Problem - Multiple string parameters (easy to mix up):
public function createUser(
    string $name,
    string $email,
    string $phone,
    string $address,
    string $city,
    string $country
) {
    // What if you accidentally pass $email as $name?
    // No type safety between parameters of same type!
}

// Calling is error-prone:
createUser($email, $name, $phone, $city, $address, $country);
// ^ Wrong order! Hard to catch

// Solution 1 - Use DTO:
public function createUser(CreateUserDTO $userData)
{
    $name = $userData->name;
    $email = $userData->email;
    // Type-safe access with clear property names
}

class CreateUserDTO
{
    public function __construct(
        public string $name,
        public string $email,
        public string $phone,
        public Address $address  // Nested value object
    ) {}
}

// Calling is clear:
createUser(new CreateUserDTO(
    name: $name,
    email: $email,
    phone: $phone,
    address: new Address($address, $city, $country)
));

// Solution 2 - Use Value Objects:
public function createUser(
    PersonalInfo $personalInfo,
    ContactInfo $contactInfo,
    Address $address
) {
    // Groups related parameters logically
}

// Solution 3 - Builder Pattern:
$user = UserBuilder::create()
    ->withName($name)
    ->withEmail($email)
    ->withPhone($phone)
    ->withAddress($address, $city, $country)
    ->build();
PHP;

        return $base.'Refactoring strategies: '.implode('; ', $strategies).". Example:{$example}";
    }
}

/**
 * Visitor to detect methods with multiple same-type parameters.
 */
class LongParameterListVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{method: string, class: string, type: string, count: int, paramNames: array<string>, line: int}>
     */
    private array $issues = [];

    /**
     * Current class name.
     */
    private ?string $currentClass = null;

    public function __construct(
        private int $threshold
    ) {}

    public function enterNode(Node $node)
    {
        // Track class entry
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = $node->name ? $node->name->toString() : 'Anonymous';

            return null;
        }

        // Check method parameters
        if ($node instanceof Stmt\ClassMethod || $node instanceof Stmt\Function_) {
            $methodName = $node->name->toString();

            // Skip magic methods
            if ($node instanceof Stmt\ClassMethod && str_starts_with($methodName, '__')) {
                return null;
            }

            // Group parameters by type
            $paramsByType = $this->groupParametersByType($node->params);

            // Check each type group
            foreach ($paramsByType as $type => $params) {
                if (count($params) > $this->threshold) {
                    $paramNames = array_map(
                        fn ($param) => $param->var instanceof Node\Expr\Variable && is_string($param->var->name)
                            ? $param->var->name
                            : 'unknown',
                        $params
                    );

                    $this->issues[] = [
                        'method' => $node instanceof Stmt\ClassMethod
                            ? ($this->currentClass ?? 'Unknown').'::'.$methodName
                            : $methodName.'()',
                        'class' => $this->currentClass ?? 'global',
                        'type' => $type,
                        'count' => count($params),
                        'paramNames' => $paramNames,
                        'line' => $node->getStartLine(),
                    ];
                }
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
     * Group parameters by their type.
     *
     * @param  array<Node\Param>  $params
     * @return array<string, array<Node\Param>>
     */
    private function groupParametersByType(array $params): array
    {
        $groups = [];

        foreach ($params as $param) {
            $type = $this->getParameterType($param);

            if (! isset($groups[$type])) {
                $groups[$type] = [];
            }

            $groups[$type][] = $param;
        }

        return $groups;
    }

    /**
     * Get parameter type as string.
     */
    private function getParameterType(Node\Param $param): string
    {
        if ($param->type === null) {
            return 'mixed';
        }

        // Simple type (string, int, etc.)
        if ($param->type instanceof Node\Identifier) {
            return $param->type->toString();
        }

        // Fully qualified class name
        if ($param->type instanceof Node\Name) {
            return $param->type->toString();
        }

        // Union type
        if ($param->type instanceof Node\UnionType) {
            $types = array_map(
                fn ($t) => $t instanceof Node\Identifier || $t instanceof Node\Name ? $t->toString() : 'unknown',
                $param->type->types
            );

            return implode('|', $types);
        }

        // Nullable type
        if ($param->type instanceof Node\NullableType) {
            $innerType = $param->type->type instanceof Node\Identifier || $param->type->type instanceof Node\Name
                ? $param->type->type->toString()
                : 'unknown';

            return '?'.$innerType;
        }

        return 'unknown';
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{method: string, class: string, type: string, count: int, paramNames: array<string>, line: int}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
