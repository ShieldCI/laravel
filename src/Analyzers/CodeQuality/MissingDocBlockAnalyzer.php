<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\CodeQuality;

use PhpParser\Comment\Doc;
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
            name: 'Missing DocBlock',
            description: 'Flags public methods without proper PHPDoc documentation for better code maintainability',
            category: Category::CodeQuality,
            severity: Severity::Low,
            tags: ['documentation', 'maintainability', 'code-quality', 'readability'],
            docsUrl: 'https://docs.phpdoc.org/guide/getting-started/what-is-a-docblock.html'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $excludePatterns = $this->excludedPatterns;
        $requireTags = (bool) (config('shieldci.code_quality.missing_docblock.require_tags', true) ?? true);

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
                $issues[] = $this->createIssue(
                    message: $issue['message'],
                    location: new Location($file, $issue['line']),
                    severity: Severity::Low,
                    recommendation: $this->getRecommendation($issue['type'], $issue['method']),
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

        return $this->failed(
            "Found {$totalIssues} public method(s) with missing or incomplete documentation",
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

        $example = <<<PHP

/**
 * Process the given order and update inventory.
 *
 * @param Order \$order The order to process
 * @param User \$user The user placing the order
 * @return ProcessedOrder The processed order details
 * @throws InsufficientInventoryException When inventory is insufficient
 * @throws PaymentFailedException When payment processing fails
 */
public function {$method}(Order \$order, User \$user): ProcessedOrder
{
    // Implementation
}
PHP;

        return $base.'Documentation guidelines: '.implode('; ', $guidelines).". Example:{$example}";
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
        if ($node instanceof Stmt\Class_) {
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
        if ($node instanceof Stmt\Class_) {
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
            $regex = '/^'.str_replace('*', '.*', $pattern).'$/i';
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

        // Check for @param tags if method has parameters
        if (! empty($node->params) && ! str_contains($docText, '@param')) {
            $this->issues[] = [
                'message' => "Public method '{$methodName}' is missing @param documentation",
                'line' => $node->getStartLine(),
                'type' => 'missing_param',
                'method' => $methodName,
                'class' => $this->currentClass ?? 'Unknown',
            ];
        }

        // Check for @return tag if method has return type or returns value
        if ($node->returnType !== null && ! str_contains($docText, '@return')) {
            $this->issues[] = [
                'message' => "Public method '{$methodName}' is missing @return documentation",
                'line' => $node->getStartLine(),
                'type' => 'missing_return',
                'method' => $methodName,
                'class' => $this->currentClass ?? 'Unknown',
            ];
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
     * Check if method might throw exceptions.
     */
    private function mightThrowException(Stmt\ClassMethod $node): bool
    {
        if ($node->stmts === null) {
            return false;
        }

        // Simple heuristic: check for throw statements or try-catch blocks
        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Stmt\Throw_) {
                return true;
            }

            if ($stmt instanceof Stmt\TryCatch) {
                return true;
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
