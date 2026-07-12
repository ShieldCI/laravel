<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeVisitorAbstract;

/**
 * Infers, for a single method or file body, each variable's Eloquent model type and its
 * eager-loaded relations. Extracted from NPlusOneVisitor so a view can be seeded with the
 * types and eager loads a controller established — knowledge a Blade template cannot derive
 * on its own.
 */
class ModelVariableScanner extends NodeVisitorAbstract
{
    /** @var array<string, string> */
    private array $types = [];

    /** @var array<string, list<string>> */
    private array $eagerLoads = [];

    public function enterNode(Node $node): ?int
    {
        if ($node instanceof Expr\Assign
            && $node->var instanceof Expr\Variable
            && is_string($node->var->name)) {
            $this->trackEagerLoading($node->expr, $node->var->name);
            $this->detectModelQuery($node);

            return null;
        }

        if ($node instanceof Expr\MethodCall
            && $node->var instanceof Expr\Variable
            && is_string($node->var->name)
            && $node->name instanceof Node\Identifier
            && in_array($node->name->toString(), ['load', 'loadMissing'], true)) {
            $relationships = $this->extractRelationshipsFromEagerLoadCall($node);
            if ($relationships !== []) {
                $this->eagerLoads[$node->var->name] = array_values(array_unique(
                    array_merge($this->eagerLoads[$node->var->name] ?? [], $relationships)
                ));
            }
        }

        return null;
    }

    public function typeOf(string $var): ?string
    {
        return $this->types[$var] ?? null;
    }

    public function modelOf(string $var): ?string
    {
        $type = $this->types[$var] ?? null;
        if ($type === null) {
            return null;
        }

        if (str_starts_with($type, 'Collection<')) {
            return trim(str_replace(['Collection<', '>'], '', $type));
        }

        return $type;
    }

    /** @return list<string> */
    public function eagerLoadsOf(string $var): array
    {
        return $this->eagerLoads[$var] ?? [];
    }

    /**
     * Copy inferred model type and eager-loaded relationships from one variable to another.
     *
     * Used when a variable's context derives from another (e.g. a `foreach` loop variable
     * inheriting the model type and eager loads of the collection it iterates), rather than
     * from an assignment the scanner observes directly.
     */
    public function copyContext(string $from, string $to): void
    {
        $type = $this->types[$from] ?? null;
        if ($type !== null && str_starts_with($type, 'Collection<')) {
            $model = $this->modelOf($from);
            if ($model !== null) {
                $this->types[$to] = $model;
            }
        }

        if (isset($this->eagerLoads[$from])) {
            $this->eagerLoads[$to] = $this->eagerLoads[$from];
        }
    }

    /**
     * Detect model query assignments and record variable types.
     *
     * Handles: $posts = Post::get(), $posts = Post::with('user')->get(), $post = Post::find(1)
     */
    private function detectModelQuery(Expr\Assign $node): void
    {
        if (! ($node->var instanceof Expr\Variable) || ! is_string($node->var->name)) {
            return;
        }
        $varName = $node->var->name;
        $expr = $node->expr;

        // Direct static call: Post::all(), Post::get(), Post::find(1)
        if ($expr instanceof Expr\StaticCall &&
            $expr->class instanceof Node\Name &&
            $expr->name instanceof Node\Identifier) {
            $className = $expr->class->getLast();
            $lowerMethod = strtolower($expr->name->toString());
            if (in_array($lowerMethod, ['get', 'all', 'paginate', 'simplepaginate'], true)) {
                $this->types[$varName] = "Collection<{$className}>";
            } elseif (in_array($lowerMethod, ['find', 'first', 'findorfail', 'firstorfail'], true)) {
                $this->types[$varName] = $className;
            }

            return;
        }

        // Chained method calls: Post::where()->get(), Post::with('user')->get()
        if ($expr instanceof Expr\MethodCall && $expr->name instanceof Node\Identifier) {
            $lowerMethod = strtolower($expr->name->toString());
            $className = $this->resolveModelFromChain($expr);
            if ($className !== null) {
                if (in_array($lowerMethod, ['get', 'all', 'paginate', 'simplepaginate'], true)) {
                    $this->types[$varName] = "Collection<{$className}>";
                } elseif (in_array($lowerMethod, ['find', 'first', 'findorfail', 'firstorfail'], true)) {
                    $this->types[$varName] = $className;
                }
            }
        }
    }

    /**
     * Walk a MethodCall chain to find the root StaticCall class name.
     */
    private function resolveModelFromChain(Expr\MethodCall $node): ?string
    {
        $current = $node->var;
        while ($current instanceof Expr\MethodCall) {
            $current = $current->var;
        }

        if ($current instanceof Expr\StaticCall && $current->class instanceof Node\Name) {
            return $current->class->getLast();
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
            $this->eagerLoads[$varName] = array_values($relationships);
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
        if (! in_array($methodName, ['with', 'load', 'loadMissing'], true)) {
            return [];
        }

        // Extract relationships from all arguments (Laravel supports variadic: with('user', 'comments'))
        if (empty($expr->args)) {
            return [];
        }

        $relationships = [];
        foreach ($expr->args as $arg) {
            $relationships = array_merge(
                $relationships,
                $this->parseRelationshipArgument($arg->value)
            );
        }

        return array_unique($relationships);
    }

    /**
     * Parse relationship argument (string or array).
     *
     * Expands dot notation so 'user.team' becomes ['user', 'user.team'].
     *
     * Handles both simple arrays and closure-keyed arrays:
     * - with(['user', 'comments']) - relationship names as values
     * - with(['user' => fn($q) => $q->select('id'), 'comments']) - relationship names as keys
     *
     * @return array<string>
     */
    private function parseRelationshipArgument(Node $arg): array
    {
        $rawRelationships = [];

        // Handle array of relationships: with(['user', 'comments']) or with(['user' => fn() => ...])
        if ($arg instanceof Expr\Array_) {
            foreach ($arg->items as $item) {
                if ($item === null) {
                    continue;
                }

                // Check if relationship name is in the key (closure-keyed arrays)
                // e.g., ['user' => fn($q) => $q->select('id')]
                if ($item->key instanceof Node\Scalar\String_) {
                    $rawRelationships[] = $item->key->value;
                }
                // Check if relationship name is in the value (simple arrays)
                // e.g., ['user', 'comments']
                elseif ($item->value instanceof Node\Scalar\String_) {
                    $rawRelationships[] = $item->value->value;
                }
            }
        }

        // Handle single relationship: with('user')
        if ($arg instanceof Node\Scalar\String_) {
            $rawRelationships[] = $arg->value;
        }

        // Expand dot notation relationships
        $expanded = [];
        foreach ($rawRelationships as $relationship) {
            // Strip Laravel's column-selection constraint: 'project:id,name' → 'project'
            // 'comments.author:id,name' → 'comments.author'
            $relationship = explode(':', $relationship, 2)[0];
            $expanded = array_merge($expanded, $this->expandDotNotation($relationship));
        }

        return array_unique($expanded);
    }

    /**
     * Expand dot notation so 'user.team' becomes ['user', 'user.team'].
     *
     * @return array<string>
     */
    private function expandDotNotation(string $relationship): array
    {
        $parts = explode('.', $relationship);
        $expanded = [];
        $path = '';

        foreach ($parts as $part) {
            $path = $path === '' ? $part : $path.'.'.$part;
            $expanded[] = $path;
        }

        return $expanded;
    }
}
