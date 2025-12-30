<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\CodeQuality;

use PhpParser\Comment\Doc;
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

/**
 * Flags public methods without documentation.
 *
 * Checks for:
 * - Public methods missing PHPDoc comments
 * - Requires @param, @return, @throws tags
 * - Excludes simple getters/setters
 */
class MissingDocBlockAnalyzer extends AbstractFileAnalyzer
{
    /**
     * @var array<string>
     */
    private array $excludedPatterns = ['get*', 'set*', 'is*', 'has*'];

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'missing-docblock',
            name: 'Missing DocBlock Analyzer',
            description: 'Flags public methods without proper PHPDoc documentation for better code maintainability',
            category: Category::CodeQuality,
            severity: Severity::Low,
            tags: ['documentation', 'maintainability', 'code-quality', 'readability'],
            docsUrl: 'https://docs.shieldci.com/analyzers/code-quality/missing-docblock',
            timeToFix: 15
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $excludePatterns = $this->excludedPatterns;
        $requireTags = true;

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new DocBlockVisitor($excludePatterns, $requireTags);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssueWithSnippet(
                    message: $issue['message'],
                    filePath: $file,
                    lineNumber: $issue['line'],
                    severity: Severity::Low,
                    recommendation: $this->getRecommendation($issue['type'], $issue['method']),
                    column: null,
                    contextLines: null,
                    code: $issue['method'],
                    metadata: [
                        'method' => $issue['method'],
                        'class' => $issue['class'],
                        'issue_type' => $issue['type'],
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('All public methods have proper documentation');
        }

        $totalIssues = count($issues);

        // Count unique methods affected (one method can have multiple issues)
        $uniqueMethods = [];
        foreach ($issues as $issue) {
            $methodKey = $issue->metadata['class'].'@'.$issue->metadata['method'];
            $uniqueMethods[$methodKey] = true;
        }
        $affectedMethodCount = count($uniqueMethods);

        $issueWord = $totalIssues === 1 ? 'issue' : 'issues';
        $methodWord = $affectedMethodCount === 1 ? 'method' : 'methods';

        return $this->failed(
            "Found {$totalIssues} documentation {$issueWord} across {$affectedMethodCount} public {$methodWord}",
            $issues
        );
    }

    /**
     * Get recommendation based on issue type.
     */
    private function getRecommendation(string $type, string $method): string
    {
        $base = match ($type) {
            'missing' => "The method '{$method}' has no PHPDoc comment. ",
            'missing_param' => "The method '{$method}' is missing @param tags. ",
            'missing_return' => "The method '{$method}' is missing a @return tag. ",
            'missing_throws' => "The method '{$method}' may throw exceptions but has no @throws tags. ",
            default => "The method '{$method}' has incomplete documentation. ",
        };

        $guidelines = [
            'Add a complete PHPDoc block above the method',
            'Include a description of what the method does',
            'Document all parameters with @param tags and types',
            'Document the return value with @return tag',
            'Document any exceptions thrown with @throws tags',
            'Use descriptive parameter and return descriptions',
        ];

        return $base.'Documentation guidelines: '.implode('; ', $guidelines);
    }
}

/**
 * Visitor to detect missing or incomplete DocBlocks.
 */
class DocBlockVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{message: string, line: int, type: string, method: string, class: string}>
     */
    private array $issues = [];

    /**
     * Current class name.
     */
    private ?string $currentClass = null;

    /**
     * @param  array<string>  $excludePatterns
     */
    public function __construct(
        private array $excludePatterns = [],
        private bool $requireTags = true
    ) {}

    public function enterNode(Node $node)
    {
        // Track current class
        if ($node instanceof Stmt\Class_ || $node instanceof Stmt\Trait_ || $node instanceof Stmt\Interface_) {
            $this->currentClass = $node->name ? $node->name->toString() : 'Anonymous';

            return null;
        }

        // Check public methods
        if ($node instanceof Stmt\ClassMethod && $node->isPublic()) {
            $methodName = $node->name->toString();

            // Skip excluded patterns
            if ($this->shouldExclude($methodName)) {
                return null;
            }

            // Skip magic methods
            if (str_starts_with($methodName, '__')) {
                return null;
            }

            $docComment = $node->getDocComment();

            // Check if method has no DocBlock
            if ($docComment === null) {
                $this->issues[] = [
                    'message' => "Public method '{$methodName}' has no PHPDoc comment",
                    'line' => $node->getStartLine(),
                    'type' => 'missing',
                    'method' => $methodName,
                    'class' => $this->currentClass ?? 'Unknown',
                ];

                return null;
            }

            // Check DocBlock completeness if required
            if ($this->requireTags) {
                $this->checkDocBlockCompleteness($node, $methodName, $docComment);
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Clear class context on exit
        if ($node instanceof Stmt\Class_ || $node instanceof Stmt\Trait_ || $node instanceof Stmt\Interface_) {
            $this->currentClass = null;
        }

        return null;
    }

    /**
     * Check if method name matches exclude patterns.
     */
    private function shouldExclude(string $methodName): bool
    {
        foreach ($this->excludePatterns as $pattern) {
            // Convert glob pattern to regex (escape special chars, then replace * with .*)
            $escaped = preg_quote($pattern, '/');
            $regex = '/^'.str_replace('\\*', '.*', $escaped).'$/i';
            if (preg_match($regex, $methodName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if DocBlock has all required tags.
     */
    private function checkDocBlockCompleteness(Stmt\ClassMethod $node, string $methodName, Doc $docComment): void
    {
        $docText = $docComment->getText();

        // Check for @param tags if method has parameters with generic types
        if (! empty($node->params)) {
            // Count parameters that require documentation (generic types or no type)
            $paramsRequiringDocs = [];
            foreach ($node->params as $param) {
                if ($param->type === null || $this->isGenericType($param->type)) {
                    $paramName = $param->var->name ?? 'unknown';
                    $paramsRequiringDocs[] = $paramName;
                }
            }

            if (! empty($paramsRequiringDocs)) {
                // Count actual @param tags in docblock
                $paramTagCount = preg_match_all('/@param\b/i', $docText, $matches);

                // If we have fewer @param tags than parameters requiring documentation
                if ($paramTagCount < count($paramsRequiringDocs)) {
                    $missing = count($paramsRequiringDocs) - $paramTagCount;
                    $this->issues[] = [
                        'message' => "Public method '{$methodName}' has {$missing} parameter(s) missing @param documentation (found {$paramTagCount}, need ".count($paramsRequiringDocs).')',
                        'line' => $node->getStartLine(),
                        'type' => 'missing_param',
                        'method' => $methodName,
                        'class' => $this->currentClass ?? 'Unknown',
                    ];
                }
            }
        }

        // Check for @return tag
        if (! str_contains($docText, '@return')) {
            // Require @return if:
            // - No return type declared (needs documentation)
            // - Return type is generic/ambiguous (array, mixed, union, etc.)
            if ($node->returnType === null || $this->requiresReturnDocumentation($node->returnType)) {
                $this->issues[] = [
                    'message' => "Public method '{$methodName}' is missing @return documentation",
                    'line' => $node->getStartLine(),
                    'type' => 'missing_return',
                    'method' => $methodName,
                    'class' => $this->currentClass ?? 'Unknown',
                ];
            }
        }

        // Check for @throws tag if method might throw exceptions
        if ($this->mightThrowException($node) && ! str_contains($docText, '@throws')) {
            $this->issues[] = [
                'message' => "Public method '{$methodName}' may throw exceptions but has no @throws documentation",
                'line' => $node->getStartLine(),
                'type' => 'missing_throws',
                'method' => $methodName,
                'class' => $this->currentClass ?? 'Unknown',
            ];
        }
    }

    /**
     * Check if a type requires documentation.
     *
     * Returns false only for scalar native types (void, string, int, bool, float, etc.)
     * which are self-documenting. Returns true for:
     * - Generic types (array, iterable, object, mixed, callable) - need to specify structure
     * - No type hint - definitely needs documentation
     */
    private function isGenericType(Node $typeNode): bool
    {
        // Scalars are self-documenting
        if ($typeNode instanceof Node\Identifier) {
            $scalarTypes = [
                'void', 'string', 'int', 'float', 'bool',
                'true', 'false', 'null', 'never',
            ];

            return ! in_array(strtolower($typeNode->toString()), $scalarTypes, true);
        }

        // Concrete class names are self-documenting
        if ($typeNode instanceof Node\Name) {
            return false;
        }

        // Nullable types: defer to inner type
        if ($typeNode instanceof Node\NullableType) {
            return $this->isGenericType($typeNode->type);
        }

        // Union types: require docs if any part is non-scalar or ambiguous
        if ($typeNode instanceof Node\UnionType) {
            foreach ($typeNode->types as $type) {
                if ($this->isGenericType($type)) {
                    return true;
                }
            }

            return false;
        }

        // Intersection types should be documented
        if ($typeNode instanceof Node\IntersectionType) {
            return true;
        }

        return true;
    }

    /**
     * Check if return type requires @return documentation.
     *
     * Require @return when:
     * - Return type is mixed
     * - Return type is array, iterable, callable, object (generic types)
     * - Return type is a union or intersection
     *
     * Do NOT require @return when:
     * - Return type is a scalar (string, int, float, bool, etc.)
     * - Return type is a concrete class (User, Response, BelongsToMany, etc.)
     * - Return type is void or never
     */
    private function requiresReturnDocumentation(Node $typeNode): bool
    {
        // Scalars and void/never don't need docs
        if ($typeNode instanceof Node\Identifier) {
            $selfDocumentingTypes = [
                'void', 'never', 'string', 'int', 'float', 'bool',
                'true', 'false', 'null',
            ];

            $typeName = strtolower($typeNode->toString());

            // Self-documenting types don't need @return
            if (in_array($typeName, $selfDocumentingTypes, true)) {
                return false;
            }

            // Generic types that DO need documentation
            $genericTypes = ['mixed', 'array', 'iterable', 'callable', 'object'];
            if (in_array($typeName, $genericTypes, true)) {
                return true;
            }

            return false;
        }

        // Concrete class names (User, Response, BelongsToMany) don't need docs
        if ($typeNode instanceof Node\Name) {
            return false;
        }

        // Nullable types: defer to inner type
        if ($typeNode instanceof Node\NullableType) {
            return $this->requiresReturnDocumentation($typeNode->type);
        }

        // Union types ALWAYS require documentation (even string|int)
        if ($typeNode instanceof Node\UnionType) {
            return true;
        }

        // Intersection types ALWAYS require documentation
        if ($typeNode instanceof Node\IntersectionType) {
            return true;
        }

        // Unknown type nodes require documentation
        return true;
    }

    /**
     * Check if method might throw exceptions.
     */
    private function mightThrowException(Stmt\ClassMethod $node): bool
    {
        if ($node->stmts === null) {
            return false;
        }

        return $this->hasThrowStatement($node->stmts);
    }

    /**
     * Recursively check for throw statements in statement list.
     *
     * @param  array<Node\Stmt>  $stmts
     */
    private function hasThrowStatement(array $stmts): bool
    {
        foreach ($stmts as $stmt) {
            // Direct throw statement (PHP < 8)
            if ($stmt instanceof Stmt\Throw_) {
                return true;
            }

            // Throw expression wrapped in Expression statement (PHP 8+)
            if ($stmt instanceof Stmt\Expression && $stmt->expr instanceof Expr\Throw_) {
                return true;
            }

            // Check nested blocks
            if ($stmt instanceof Stmt\If_) {
                if ($this->hasThrowStatement($stmt->stmts)) {
                    return true;
                }
                foreach ($stmt->elseifs as $elseif) {
                    if ($this->hasThrowStatement($elseif->stmts)) {
                        return true;
                    }
                }
                if ($stmt->else !== null && $this->hasThrowStatement($stmt->else->stmts)) {
                    return true;
                }
            } elseif ($stmt instanceof Stmt\While_) {
                if ($this->hasThrowStatement($stmt->stmts)) {
                    return true;
                }
            } elseif ($stmt instanceof Stmt\Do_) {
                if ($this->hasThrowStatement($stmt->stmts)) {
                    return true;
                }
            } elseif ($stmt instanceof Stmt\For_) {
                if ($this->hasThrowStatement($stmt->stmts)) {
                    return true;
                }
            } elseif ($stmt instanceof Stmt\Foreach_) {
                if ($this->hasThrowStatement($stmt->stmts)) {
                    return true;
                }
            } elseif ($stmt instanceof Stmt\Switch_) {
                foreach ($stmt->cases as $case) {
                    if ($this->hasThrowStatement($case->stmts)) {
                        return true;
                    }
                }
            } elseif ($stmt instanceof Stmt\TryCatch) {
                // Don't check try block - exceptions there are caught and handled internally
                // Only check catch blocks (for re-throws or new throws) and finally block

                // Check catch blocks for re-throws or new throws
                foreach ($stmt->catches as $catch) {
                    if ($this->hasThrowStatement($catch->stmts)) {
                        return true;
                    }
                }
                // Check finally block
                if ($stmt->finally !== null && $this->hasThrowStatement($stmt->finally->stmts)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{message: string, line: int, type: string, method: string, class: string}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
