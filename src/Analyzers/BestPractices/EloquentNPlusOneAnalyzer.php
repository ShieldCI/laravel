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
 * Identifies missing eager loading that causes N+1 query problems.
 *
 * Checks for:
 * - Relationship access inside loops
 * - Missing with() or load() calls
 * - Common patterns like $post->user in foreach
 */
class EloquentNPlusOneAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'eloquent-n-plus-one',
            name: 'Eloquent N+1 Query Analyzer',
            description: 'Identifies missing eager loading that causes N+1 query performance problems',
            category: Category::BestPractices,
            severity: Severity::High,
            tags: ['performance', 'eloquent', 'database', 'n+1', 'optimization'],
            docsUrl: 'https://docs.shieldci.com/analyzers/best-practices/eloquent-n-plus-one',
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            try {
                $ast = $this->parser->parseFile($file);

                if (empty($ast)) {
                    continue;
                }

                $visitor = new NPlusOneVisitor;
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssue(
                        message: "Potential N+1 query: accessing '{$issue['relationship']}' inside loop",
                        location: new Location($this->getRelativePath($file), $issue['line']),
                        severity: Severity::High,
                        recommendation: $this->getRecommendation($issue['relationship'], $issue['loop_type']),
                        metadata: [
                            'relationship' => $issue['relationship'],
                            'loop_type' => $issue['loop_type'],
                            'variable' => $issue['variable'],
                            'file' => $file,
                        ]
                    );
                }
            } catch (\Throwable $e) {
                // Skip files that can't be parsed
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('No potential N+1 query issues detected');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} potential N+1 query issue(s)",
            $issues
        );
    }

    /**
     * Get recommendation for N+1 issue.
     */
    private function getRecommendation(string $relationship, string $loopType): string
    {
        return "Accessing the '{$relationship}' relationship inside a {$loopType} will trigger a separate database query for each iteration, causing an N+1 query problem. ";
    }
}

/**
 * Visitor to detect N+1 query patterns.
 */
class NPlusOneVisitor extends NodeVisitorAbstract
{
    /** @var string Loop type constants */
    private const LOOP_TYPE_FOREACH = 'foreach';

    private const LOOP_TYPE_FOR = 'for';

    private const LOOP_TYPE_WHILE = 'while';

    private const LOOP_TYPE_DO_WHILE = 'do-while';

    /** @var array<string> Common model properties that are not relationships */
    private const EXCLUDED_PROPERTIES = [
        'id', 'created_at', 'updated_at', 'deleted_at', 'name', 'email',
        'password', 'remember_token', 'email_verified_at', 'title', 'content',
        'description', 'status', 'type', 'value', 'data', 'meta', 'slug',
        'count', 'total', 'amount', 'price', 'quantity', 'active', 'enabled',
    ];

    /**
     * @var array<int, array{relationship: string, line: int, loop_type: string, variable: string}>
     */
    private array $issues = [];

    /**
     * Stack of loop contexts (for nested loop support).
     *
     * @var array<int, array{variable: string|null, type: string}>
     */
    private array $loopStack = [];

    /**
     * Track variables and their eager loaded relationships.
     *
     * @var array<string, array<string>>
     */
    private array $eagerLoadedRelationships = [];

    public function __construct() {}

    public function enterNode(Node $node)
    {
        // Track variable assignments to detect eager loading
        if ($node instanceof Expr\Assign) {
            if ($node->var instanceof Expr\Variable && is_string($node->var->name)) {
                // Check if the assignment uses with() or load() for eager loading
                $this->trackEagerLoading($node->expr, $node->var->name);
            }

            return null;
        }

        // Track load() calls on existing variables: $posts->load('user')
        if ($node instanceof Expr\MethodCall) {
            if ($node->var instanceof Expr\Variable &&
                is_string($node->var->name) &&
                $node->name instanceof Node\Identifier &&
                $node->name->toString() === 'load') {

                $varName = $node->var->name;
                $relationships = $this->extractRelationshipsFromEagerLoadCall($node);

                if (! empty($relationships)) {
                    // Merge with existing eager loaded relationships
                    if (isset($this->eagerLoadedRelationships[$varName])) {
                        $this->eagerLoadedRelationships[$varName] = array_merge(
                            $this->eagerLoadedRelationships[$varName],
                            $relationships
                        );
                    } else {
                        $this->eagerLoadedRelationships[$varName] = $relationships;
                    }
                }
            }
        }

        // Track loop entry
        if ($node instanceof Stmt\Foreach_) {
            $loopVariable = null;

            // Get loop variable name and source variable
            if ($node->valueVar instanceof Expr\Variable && is_string($node->valueVar->name)) {
                $loopVariable = $node->valueVar->name;

                // Check if iterating over a variable with eager loaded relationships
                if ($node->expr instanceof Expr\Variable && is_string($node->expr->name)) {
                    $sourceVar = $node->expr->name;
                    // Copy eager loaded relationships to loop variable context
                    if (isset($this->eagerLoadedRelationships[$sourceVar])) {
                        $this->eagerLoadedRelationships[$loopVariable] =
                            $this->eagerLoadedRelationships[$sourceVar];
                    }
                }
            }

            $this->loopStack[] = [
                'variable' => $loopVariable,
                'type' => self::LOOP_TYPE_FOREACH,
            ];

            return null;
        }

        if ($node instanceof Stmt\For_) {
            $this->loopStack[] = [
                'variable' => null,
                'type' => self::LOOP_TYPE_FOR,
            ];

            return null;
        }

        if ($node instanceof Stmt\While_) {
            $this->loopStack[] = [
                'variable' => null,
                'type' => self::LOOP_TYPE_WHILE,
            ];

            return null;
        }

        if ($node instanceof Stmt\Do_) {
            $this->loopStack[] = [
                'variable' => null,
                'type' => self::LOOP_TYPE_DO_WHILE,
            ];

            return null;
        }

        // Detect relationship access inside loops
        $currentLoop = $this->getCurrentLoop();
        if ($currentLoop !== null && $currentLoop['variable'] !== null) {
            $loopVariable = $currentLoop['variable'];
            $loopType = $currentLoop['type'];

            // Look for property access like $post->user or $post->comments
            if ($node instanceof Expr\PropertyFetch) {
                // Check if accessing property on loop variable
                if ($node->var instanceof Expr\Variable &&
                    is_string($node->var->name) &&
                    $node->var->name === $loopVariable &&
                    $node->name instanceof Node\Identifier) {

                    $propertyName = $node->name->toString();

                    // Check if this looks like a relationship (not typical model properties)
                    if ($this->looksLikeRelationship($propertyName)) {
                        // Only flag if NOT eager loaded
                        if (! $this->isEagerLoaded($loopVariable, $propertyName)) {
                            $this->issues[] = [
                                'relationship' => $propertyName,
                                'line' => $node->getStartLine(),
                                'loop_type' => $loopType,
                                'variable' => $loopVariable,
                            ];
                        }
                    }
                }
            }

            // Look for method calls like $post->user() or $post->comments()
            if ($node instanceof Expr\MethodCall) {
                if ($node->var instanceof Expr\Variable &&
                    is_string($node->var->name) &&
                    $node->var->name === $loopVariable &&
                    $node->name instanceof Node\Identifier) {

                    $methodName = $node->name->toString();

                    // Check if this looks like a relationship method
                    if ($this->looksLikeRelationship($methodName)) {
                        // Only flag if NOT eager loaded
                        if (! $this->isEagerLoaded($loopVariable, $methodName)) {
                            $this->issues[] = [
                                'relationship' => $methodName,
                                'line' => $node->getStartLine(),
                                'loop_type' => $loopType,
                                'variable' => $loopVariable,
                            ];
                        }
                    }
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Track loop exit - pop from stack
        if ($node instanceof Stmt\Foreach_ || $node instanceof Stmt\For_ ||
            $node instanceof Stmt\While_ || $node instanceof Stmt\Do_) {
            array_pop($this->loopStack);
        }

        return null;
    }

    /**
     * Get the current loop context (innermost loop).
     *
     * @return array{variable: string|null, type: string}|null
     */
    private function getCurrentLoop(): ?array
    {
        if (empty($this->loopStack)) {
            return null;
        }

        return end($this->loopStack);
    }

    /**
     * Track eager loading from an expression.
     */
    private function trackEagerLoading(Node $expr, string $varName): void
    {
        // Look for chain like: Post::with(['user', 'comments'])->get()
        // We need to recursively check the chain for with() calls
        $relationships = $this->extractEagerLoadedRelationships($expr);

        if (! empty($relationships)) {
            $this->eagerLoadedRelationships[$varName] = $relationships;
        }
    }

    /**
     * Extract relationships from with() or load() calls in an expression chain.
     *
     * @return array<string>
     */
    private function extractEagerLoadedRelationships(Node $expr): array
    {
        $relationships = [];

        // Check if this is a method call
        if ($expr instanceof Expr\MethodCall) {
            $relationships = $this->extractRelationshipsFromEagerLoadCall($expr);

            // Recursively check the chain (e.g., Post::query()->with()->get())
            $relationships = array_merge(
                $relationships,
                $this->extractEagerLoadedRelationships($expr->var)
            );
        }

        // Check if this is a static call (e.g., Post::with())
        if ($expr instanceof Expr\StaticCall) {
            $relationships = $this->extractRelationshipsFromEagerLoadCall($expr);
        }

        return $relationships;
    }

    /**
     * Extract relationships from a with() or load() method/static call.
     *
     * @return array<string>
     */
    private function extractRelationshipsFromEagerLoadCall(Expr\MethodCall|Expr\StaticCall $expr): array
    {
        // Check if the method is 'with' or 'load'
        if (! ($expr->name instanceof Node\Identifier)) {
            return [];
        }

        $methodName = $expr->name->toString();
        if ($methodName !== 'with' && $methodName !== 'load') {
            return [];
        }

        // Extract relationships from the argument
        if (empty($expr->args)) {
            return [];
        }

        return $this->parseRelationshipArgument($expr->args[0]->value);
    }

    /**
     * Parse relationship argument (string or array).
     *
     * @return array<string>
     */
    private function parseRelationshipArgument(Node $arg): array
    {
        // Handle array of relationships: with(['user', 'comments'])
        if ($arg instanceof Expr\Array_) {
            $relationships = [];
            foreach ($arg->items as $item) {
                if ($item !== null && $item->value instanceof Node\Scalar\String_) {
                    $relationships[] = $item->value->value;
                }
            }

            return $relationships;
        }

        // Handle single relationship: with('user')
        if ($arg instanceof Node\Scalar\String_) {
            return [$arg->value];
        }

        return [];
    }

    /**
     * Check if a relationship is eager loaded for a variable.
     */
    private function isEagerLoaded(string $varName, string $relationship): bool
    {
        if (! isset($this->eagerLoadedRelationships[$varName])) {
            return false;
        }

        return in_array($relationship, $this->eagerLoadedRelationships[$varName], true);
    }

    /**
     * Check if property/method name looks like an Eloquent relationship.
     */
    private function looksLikeRelationship(string $name): bool
    {
        // Exclude common non-relationship properties
        if (in_array(strtolower($name), self::EXCLUDED_PROPERTIES, true)) {
            return false;
        }

        // Relationships often use singular or plural nouns
        // This is a heuristic - not perfect but catches common cases
        return true;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{relationship: string, line: int, loop_type: string, variable: string}>
     */
    public function getIssues(): array
    {
        // Deduplicate issues (same variable accessing same relationship)
        $unique = [];
        $seen = [];

        foreach ($this->issues as $issue) {
            // Include variable name to prevent false deduplication across different variables
            // Don't include line to deduplicate same relationship accessed multiple times
            $key = $issue['variable'].'_'.$issue['relationship'];
            if (! isset($seen[$key])) {
                $unique[] = $issue;
                $seen[$key] = true;
            }
        }

        return $unique;
    }
}
