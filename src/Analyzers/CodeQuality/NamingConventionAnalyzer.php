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

/**
 * Validates PSR naming standards.
 *
 * Checks for:
 * - Classes: PascalCase
 * - Methods/variables: camelCase
 * - Constants: SCREAMING_SNAKE_CASE
 * - Laravel conventions (table names plural)
 */
class NamingConventionAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'naming-convention',
            name: 'Naming Convention Analyzer',
            description: 'Validates PSR and Laravel naming standards for better code consistency',
            category: Category::CodeQuality,
            severity: Severity::Low,
            tags: ['conventions', 'psr', 'code-quality', 'readability'],
            docsUrl: 'https://docs.shieldci.com/analyzers/code-quality/naming-convention',
            timeToFix: 20
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new NamingConventionVisitor;
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssueWithSnippet(
                    message: $issue['message'],
                    filePath: $file,
                    lineNumber: $issue['line'],
                    severity: Severity::Low,
                    recommendation: $this->getRecommendation($issue['type'], $issue['name'], $issue['suggestion']),
                    column: null,
                    contextLines: null,
                    code: $issue['name'],
                    metadata: [
                        'type' => $issue['type'],
                        'name' => $issue['name'],
                        'suggestion' => $issue['suggestion'],
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('All names follow PSR and Laravel conventions');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} naming convention violation(s)",
            $issues
        );
    }

    /**
     * Get recommendation based on violation type.
     */
    private function getRecommendation(string $type, string $name, string $suggestion): string
    {
        $conventions = match ($type) {
            'class' => 'Classes should use PascalCase (e.g., UserController, OrderService)',
            'method' => 'Methods should use camelCase (e.g., getUserById, processPayment)',
            'property' => 'Properties should use camelCase (e.g., firstName, isActive)',
            'constant' => 'Public constants should use SCREAMING_SNAKE_CASE (e.g., MAX_RETRIES, API_KEY). Private/protected constants may use camelCase',
            'variable' => 'Variables should use camelCase (e.g., userId, totalAmount)',
            'table' => 'Laravel table names should be plural snake_case (e.g., users, order_items, user_profiles)',
            default => 'Follow PSR-12 naming conventions',
        };

        return "{$conventions}. Current name '{$name}' should be renamed to '{$suggestion}'. Consistent naming improves code readability and maintainability. See PSR-12 for full naming standards.";
    }
}

/**
 * Visitor to check naming conventions.
 */
class NamingConventionVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{message: string, line: int, type: string, name: string, suggestion: string}>
     */
    private array $issues = [];

    public function __construct() {}

    public function enterNode(Node $node)
    {
        // Check class names
        if ($node instanceof Stmt\Class_ && $node->name !== null) {
            $this->checkPascalCaseNaming($node, 'Class', $node->name->toString());
        }

        // Check interface names
        if ($node instanceof Stmt\Interface_ && $node->name !== null) {
            $this->checkPascalCaseNaming($node, 'Interface', $node->name->toString());
        }

        // Check trait names
        if ($node instanceof Stmt\Trait_ && $node->name !== null) {
            $this->checkPascalCaseNaming($node, 'Trait', $node->name->toString());
        }

        // Check enum names (PHP 8.1+)
        if ($node instanceof Stmt\Enum_ && $node->name !== null) {
            $this->checkPascalCaseNaming($node, 'Enum', $node->name->toString());
        }

        // Check method names
        if ($node instanceof Stmt\ClassMethod) {
            $methodName = $node->name->toString();

            // Skip magic methods
            if (! str_starts_with($methodName, '__')) {
                if (! $this->isCamelCase($methodName)) {
                    $suggestion = $this->toCamelCase($methodName);
                    $this->issues[] = [
                        'message' => "Method '{$methodName}' does not follow camelCase convention",
                        'line' => $node->getStartLine(),
                        'type' => 'method',
                        'name' => $methodName,
                        'suggestion' => $suggestion,
                    ];
                }
            }
        }

        // Check property names
        if ($node instanceof Stmt\Property) {
            foreach ($node->props as $prop) {
                $propertyName = $prop->name->toString();

                // Laravel convention: protected $table should be plural snake_case
                if ($propertyName === 'table' && $node->isProtected()) {
                    $this->checkLaravelTableNaming($node, $prop);
                } elseif (! $this->isCamelCase($propertyName)) {
                    $suggestion = $this->toCamelCase($propertyName);
                    $this->issues[] = [
                        'message' => "Property '{$propertyName}' does not follow camelCase convention",
                        'line' => $node->getStartLine(),
                        'type' => 'property',
                        'name' => $propertyName,
                        'suggestion' => $suggestion,
                    ];
                }
            }
        }

        // Check constant names (PSR-12: only public constants require SCREAMING_SNAKE_CASE)
        if ($node instanceof Stmt\ClassConst) {
            // Only enforce SCREAMING_SNAKE_CASE for public constants
            // Modern PHP allows: private const maxRetries = 3;
            if ($node->isPublic()) {
                foreach ($node->consts as $const) {
                    $constName = $const->name->toString();

                    if (! $this->isScreamingSnakeCase($constName)) {
                        $suggestion = $this->toScreamingSnakeCase($constName);
                        $this->issues[] = [
                            'message' => "Public constant '{$constName}' does not follow SCREAMING_SNAKE_CASE convention",
                            'line' => $node->getStartLine(),
                            'type' => 'constant',
                            'name' => $constName,
                            'suggestion' => $suggestion,
                        ];
                    }
                }
            }
        }

        return null;
    }

    /**
     * Check if a type (class, interface, trait, enum) follows PascalCase naming.
     */
    private function checkPascalCaseNaming(Node $node, string $type, string $name): void
    {
        if (! $this->isPascalCase($name)) {
            $this->issues[] = [
                'message' => "{$type} '{$name}' does not follow PascalCase convention",
                'line' => $node->getStartLine(),
                'type' => strtolower($type), // class | interface | trait | enum
                'name' => $name,
                'suggestion' => $this->toPascalCase($name),
            ];
        }
    }

    /**
     * Check if string is PascalCase.
     */
    private function isPascalCase(string $name): bool
    {
        // PascalCase: starts with uppercase, at least 1 character, no underscores
        // Allows acronyms like XMLParser, HTTPClient, APIController
        return preg_match('/^[A-Z][a-zA-Z0-9]*$/', $name) === 1;
    }

    /**
     * Check if string is camelCase.
     */
    private function isCamelCase(string $name): bool
    {
        // camelCase: starts with lowercase, allows single characters (PSR-12 compliant)
        // Valid: i, j, x, y, userName, isActive
        // Invalid: user_name, UserName, _private
        return preg_match('/^[a-z][a-zA-Z0-9]*$/', $name) === 1;
    }

    /**
     * Check if string is SCREAMING_SNAKE_CASE.
     */
    private function isScreamingSnakeCase(string $name): bool
    {
        // SCREAMING_SNAKE_CASE: all uppercase with underscores, at least 2 characters
        return preg_match('/^[A-Z][A-Z0-9_]+$/', $name) === 1;
    }

    /**
     * Convert to PascalCase.
     */
    private function toPascalCase(string $name): string
    {
        // Remove underscores and capitalize each word
        $name = str_replace(['_', '-'], ' ', $name);
        $name = ucwords($name);

        return str_replace(' ', '', $name);
    }

    /**
     * Convert to camelCase.
     */
    private function toCamelCase(string $name): string
    {
        $pascal = $this->toPascalCase($name);

        return lcfirst($pascal);
    }

    /**
     * Convert to SCREAMING_SNAKE_CASE.
     */
    private function toScreamingSnakeCase(string $name): string
    {
        // Insert underscore before uppercase letters (except first)
        $name = preg_replace('/(?<!^)[A-Z]/', '_$0', $name) ?? $name;

        // Replace existing separators with underscores
        $name = str_replace(['-', ' '], '_', $name);

        return strtoupper($name);
    }

    /**
     * Check Laravel table naming convention: plural snake_case.
     */
    private function checkLaravelTableNaming(Stmt\Property $node, Node\PropertyItem $prop): void
    {
        // Extract the table name value
        if ($prop->default === null) {
            return; // No default value, skip check
        }

        // Only check string literals
        if (! $prop->default instanceof Node\Scalar\String_) {
            return;
        }

        $tableName = $prop->default->value;

        // Check if it's snake_case
        if (! $this->isSnakeCase($tableName)) {
            $suggestion = $this->toSnakeCase($tableName);
            $this->issues[] = [
                'message' => "Laravel table name '{$tableName}' should use snake_case convention",
                'line' => $node->getStartLine(),
                'type' => 'table',
                'name' => $tableName,
                'suggestion' => $suggestion,
            ];

            return;
        }

        // Check if it's plural
        if (! $this->isPlural($tableName)) {
            $suggestion = $this->toPlural($tableName);
            $this->issues[] = [
                'message' => "Laravel table name '{$tableName}' should be plural",
                'line' => $node->getStartLine(),
                'type' => 'table',
                'name' => $tableName,
                'suggestion' => $suggestion,
            ];
        }
    }

    /**
     * Check if string is snake_case.
     */
    private function isSnakeCase(string $name): bool
    {
        // snake_case: all lowercase with underscores, no consecutive underscores
        return preg_match('/^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/', $name) === 1;
    }

    /**
     * Convert to snake_case.
     */
    private function toSnakeCase(string $name): string
    {
        // Insert underscore before uppercase letters (except first)
        $name = preg_replace('/(?<!^)[A-Z]/', '_$0', $name) ?? $name;

        // Replace existing separators with underscores
        $name = str_replace(['-', ' '], '_', $name);

        return strtolower($name);
    }

    /**
     * Check if a table name is plural (basic check).
     */
    private function isPlural(string $name): bool
    {
        // Handle common irregular plurals
        $irregularPlurals = [
            'people', 'children', 'men', 'women', 'teeth', 'feet',
            'geese', 'mice', 'oxen', 'sheep', 'deer', 'fish',
        ];

        // Extract the last word (after last underscore)
        $parts = explode('_', $name);
        $lastWord = end($parts);

        // Check irregular plurals
        if (in_array($lastWord, $irregularPlurals, true)) {
            return true;
        }

        // Basic plural check: ends with 's' or 'es'
        // This is a simple heuristic - won't catch all cases but covers most
        return str_ends_with($lastWord, 's') || str_ends_with($lastWord, 'es');
    }

    /**
     * Convert to plural form (basic implementation).
     */
    private function toPlural(string $name): string
    {
        // Handle common irregular plurals
        $irregularMap = [
            'person' => 'people',
            'child' => 'children',
            'man' => 'men',
            'woman' => 'women',
            'tooth' => 'teeth',
            'foot' => 'feet',
            'goose' => 'geese',
            'mouse' => 'mice',
            'ox' => 'oxen',
        ];

        // Extract the last word (after last underscore)
        $parts = explode('_', $name);
        $lastWord = end($parts);

        // Check irregular plurals
        if (isset($irregularMap[$lastWord])) {
            $parts[count($parts) - 1] = $irregularMap[$lastWord];

            return implode('_', $parts);
        }

        // Basic pluralization rules
        if (str_ends_with($lastWord, 'y') && ! in_array($lastWord[strlen($lastWord) - 2], ['a', 'e', 'i', 'o', 'u'], true)) {
            // category -> categories
            $parts[count($parts) - 1] = substr($lastWord, 0, -1).'ies';
        } elseif (str_ends_with($lastWord, 's') || str_ends_with($lastWord, 'x') || str_ends_with($lastWord, 'ch') || str_ends_with($lastWord, 'sh')) {
            // class -> classes, box -> boxes
            $parts[count($parts) - 1] = $lastWord.'es';
        } else {
            // user -> users
            $parts[count($parts) - 1] = $lastWord.'s';
        }

        return implode('_', $parts);
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{message: string, line: int, type: string, name: string, suggestion: string}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
