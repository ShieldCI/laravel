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
            name: 'Eloquent N+1 Query',
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
                    location: new Location($file, $issue['line']),
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
        $base = "Accessing the '{$relationship}' relationship inside a {$loopType} will trigger a separate database query for each iteration, causing an N+1 query problem. ";

        $solutions = [
            "Use eager loading before the loop: ->with('{$relationship}')",
            "If data is already loaded, use lazy eager loading: ->load('{$relationship}')",
            'Consider using select() to load only needed columns',
            'Use Laravel Debugbar or Telescope to verify query reduction',
            'For complex relationships, consider using subqueries or joins',
        ];

        $example = <<<PHP

// Problem:
\$posts = Post::all();
foreach (\$posts as \$post) {
    echo \$post->{$relationship}->name; // N+1 queries
}

// Solution:
\$posts = Post::with('{$relationship}')->get();
foreach (\$posts as \$post) {
    echo \$post->{$relationship}->name; // Single query with join
}
PHP;

        return $base.'Solutions: '.implode('; ', $solutions).". Example:{$example}";
    }
}

/**
 * Visitor to detect N+1 query patterns.
 */
class NPlusOneVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{relationship: string, line: int, loop_type: string, variable: string}>
     */
    private array $issues = [];

    /**
     * Track if we're currently inside a loop.
     */
    private bool $inLoop = false;

    /**
     * Track loop variable name.
     */
    private ?string $loopVariable = null;

    /**
     * Current loop type.
     */
    private string $loopType = 'foreach';

    /**
     * Nesting level of loops.
     */
    private int $loopDepth = 0;

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
                // Check if the assignment uses with() for eager loading
                $this->trackEagerLoading($node->expr, $node->var->name);
            }

            return null;
        }

        // Track loop entry
        if ($node instanceof Stmt\Foreach_) {
            $this->loopDepth++;
            $this->inLoop = true;
            $this->loopType = 'foreach';

            // Get loop variable name and source variable
            if ($node->valueVar instanceof Expr\Variable && is_string($node->valueVar->name)) {
                $this->loopVariable = $node->valueVar->name;

                // Check if iterating over a variable with eager loaded relationships
                if ($node->expr instanceof Expr\Variable && is_string($node->expr->name)) {
                    $sourceVar = $node->expr->name;
                    // Copy eager loaded relationships to loop variable context
                    if (isset($this->eagerLoadedRelationships[$sourceVar])) {
                        $this->eagerLoadedRelationships[$this->loopVariable] =
                            $this->eagerLoadedRelationships[$sourceVar];
                    }
                }
            }

            return null;
        }

        if ($node instanceof Stmt\For_ || $node instanceof Stmt\While_ || $node instanceof Stmt\Do_) {
            $this->loopDepth++;
            $this->inLoop = true;
            $this->loopType = $node instanceof Stmt\For_ ? 'for' : 'while';

            return null;
        }

        // Detect relationship access inside loops
        if ($this->inLoop && $this->loopVariable !== null) {
            // Look for property access like $post->user or $post->comments
            if ($node instanceof Expr\PropertyFetch) {
                // Check if accessing property on loop variable
                if ($node->var instanceof Expr\Variable &&
                    is_string($node->var->name) &&
                    $node->var->name === $this->loopVariable &&
                    $node->name instanceof Node\Identifier) {

                    $propertyName = $node->name->toString();

                    // Check if this looks like a relationship (not typical model properties)
                    if ($this->looksLikeRelationship($propertyName)) {
                        // Only flag if NOT eager loaded
                        if (! $this->isEagerLoaded($this->loopVariable, $propertyName)) {
                            $this->issues[] = [
                                'relationship' => $propertyName,
                                'line' => $node->getStartLine(),
                                'loop_type' => $this->loopType,
                                'variable' => $this->loopVariable,
                            ];
                        }
                    }
                }
            }

            // Look for method calls like $post->user() or $post->comments()
            if ($node instanceof Expr\MethodCall) {
                if ($node->var instanceof Expr\Variable &&
                    is_string($node->var->name) &&
                    $node->var->name === $this->loopVariable &&
                    $node->name instanceof Node\Identifier) {

                    $methodName = $node->name->toString();

                    // Check if this looks like a relationship method
                    if ($this->looksLikeRelationship($methodName)) {
                        // Only flag if NOT eager loaded
                        if (! $this->isEagerLoaded($this->loopVariable, $methodName)) {
                            $this->issues[] = [
                                'relationship' => $methodName,
                                'line' => $node->getStartLine(),
                                'loop_type' => $this->loopType,
                                'variable' => $this->loopVariable,
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
        // Track loop exit
        if ($node instanceof Stmt\Foreach_ || $node instanceof Stmt\For_ ||
            $node instanceof Stmt\While_ || $node instanceof Stmt\Do_) {
            $this->loopDepth--;

            if ($this->loopDepth === 0) {
                $this->inLoop = false;
                $this->loopVariable = null;
                $this->loopType = 'foreach';
            }
        }

        return null;
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
     * Extract relationships from with() calls in an expression chain.
     *
     * @return array<string>
     */
    private function extractEagerLoadedRelationships(Node $expr): array
    {
        $relationships = [];

        // Check if this is a method call
        if ($expr instanceof Expr\MethodCall) {
            // Check if the method is 'with'
            if ($expr->name instanceof Node\Identifier && $expr->name->toString() === 'with') {
                // Extract relationships from the argument
                if (! empty($expr->args)) {
                    $arg = $expr->args[0]->value;

                    // Handle array of relationships: with(['user', 'comments'])
                    if ($arg instanceof Expr\Array_) {
                        foreach ($arg->items as $item) {
                            if ($item !== null && $item->value instanceof Node\Scalar\String_) {
                                $relationships[] = $item->value->value;
                            }
                        }
                    }
                    // Handle single relationship: with('user')
                    elseif ($arg instanceof Node\Scalar\String_) {
                        $relationships[] = $arg->value;
                    }
                }
            }

            // Recursively check the chain (e.g., Post::query()->with()->get())
            $relationships = array_merge(
                $relationships,
                $this->extractEagerLoadedRelationships($expr->var)
            );
        }

        // Check if this is a static call (e.g., Post::with())
        if ($expr instanceof Expr\StaticCall) {
            if ($expr->name instanceof Node\Identifier && $expr->name->toString() === 'with') {
                if (! empty($expr->args)) {
                    $arg = $expr->args[0]->value;

                    if ($arg instanceof Expr\Array_) {
                        foreach ($arg->items as $item) {
                            if ($item !== null && $item->value instanceof Node\Scalar\String_) {
                                $relationships[] = $item->value->value;
                            }
                        }
                    } elseif ($arg instanceof Node\Scalar\String_) {
                        $relationships[] = $arg->value;
                    }
                }
            }
        }

        return $relationships;
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
        $excludedProperties = [
            'id', 'created_at', 'updated_at', 'deleted_at', 'name', 'email',
            'password', 'remember_token', 'email_verified_at', 'title', 'content',
            'description', 'status', 'type', 'value', 'data', 'meta', 'slug',
            'count', 'total', 'amount', 'price', 'quantity', 'active', 'enabled',
        ];

        if (in_array(strtolower($name), $excludedProperties, true)) {
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
        // Deduplicate issues (same relationship accessed multiple times)
        $unique = [];
        $seen = [];

        foreach ($this->issues as $issue) {
            $key = $issue['relationship'].'_'.$issue['line'];
            if (! isset($seen[$key])) {
                $unique[] = $issue;
                $seen[$key] = true;
            }
        }

        return $unique;
    }
}
