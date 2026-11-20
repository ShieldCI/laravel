<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Closure;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\Concerns\IdentifiesNonQueryClasses;

/**
 * Infers, for a single method or file body, each variable's Eloquent model type and its
 * eager-loaded relations. Extracted from NPlusOneVisitor so a view can be seeded with the
 * types and eager loads a controller established — knowledge a Blade template cannot derive
 * on its own.
 */
class ModelVariableScanner extends NodeVisitorAbstract
{
    use IdentifiesNonQueryClasses;

    /**
     * The eager load recorded under a relation (`books.*`) when the query that loads it also
     * hydrates the inverse with chaperone() or inverse(). Which relation that is Laravel
     * guesses at runtime, so the relation's elements cannot be judged and stay untyped.
     */
    public const OPAQUE_ELEMENTS = '*';

    /**
     * On top of the shared non-query list: classes whose query-shaped static calls return
     * something other than models. DB::table() reads rows as plain objects, and Request::all()
     * returns the input array. Auth::user() does return a model, but a chain rooted at the
     * facade (`Auth::user()->shelves()->get()`) would be typed by the facade's name, which
     * says nothing about the model the relation returns.
     *
     * @var array<int, string>
     */
    private const NON_MODEL_CLASSES = [
        'Illuminate\Support\Facades\Auth',
        'Illuminate\Support\Facades\DB',
        'Illuminate\Support\Facades\Request',
        'Illuminate\Http\Request',
    ];

    /**
     * Compiled Blade rewrites `@foreach($cities as $city)` into
     * `$__currentLoopData = $cities; foreach ($__currentLoopData as $city): ...`. This is the
     * only bare `$to = $from;` assignment `enterNode()` treats as an alias — a plain user-level
     * `$renamed = $posts;` in ordinary PHP must NOT propagate type/eager-load info, since this
     * scanner also runs over plain `.php` files where no such synthetic variable exists and
     * broadening detection there is out of scope for Blade support.
     */
    private const BLADE_LOOP_SOURCE = '__currentLoopData';

    /** @var array<string, string> */
    private array $types = [];

    /** @var array<string, list<string>> */
    private array $eagerLoads = [];

    /**
     * Maps a variable to the name of the render-bound variable it ultimately derives from
     * (itself, for a directly seeded variable). Lets a Blade N+1 finding on a loop variable
     * trace back to the controller-passed variable a `ViewBindingRegistry` binding is keyed by.
     *
     * @var array<string, string>
     */
    private array $origins = [];

    /**
     * Maps a variable reached through a to-many relation of a render-bound variable to the
     * dotted relation path from that variable (`books` for a loop over `$shelf->books`), so a
     * finding on it can name the path to eager-load where the binding was made.
     *
     * @var array<string, string>
     */
    private array $relationPaths = [];

    /**
     * @param  Closure(Node\Name): string  $resolveClass  The fully qualified name behind a class
     *                                                    reference, as the consumer's import table
     *                                                    resolves it where the reference is written.
     */
    public function __construct(private readonly Closure $resolveClass) {}

    public function enterNode(Node $node): ?int
    {
        if ($node instanceof Expr\Assign
            && $node->var instanceof Expr\Variable
            && is_string($node->var->name)) {
            $varName = $node->var->name;
            $expr = $node->expr;

            // Compiled Blade reassigns this same synthetic variable at every nesting level
            // (`$__currentLoopData = $post->comments;` for the inner loop of a nested
            // `@foreach`). Clear whatever an earlier (outer) assignment left behind before
            // reprocessing this one — otherwise, when this assignment's RHS isn't itself a
            // recognized alias/query shape, the entry is left stale and the inner loop
            // variable silently inherits the OUTER loop's model type and eager loads.
            if ($varName === self::BLADE_LOOP_SOURCE) {
                unset($this->types[$varName], $this->eagerLoads[$varName], $this->origins[$varName], $this->relationPaths[$varName]);
            }

            $this->trackEagerLoading($expr, $varName);
            $this->detectModelQuery($expr, $varName);

            if ($varName === self::BLADE_LOOP_SOURCE
                && $expr instanceof Expr\Variable
                && is_string($expr->name)) {
                $this->aliasVariable($expr->name, $varName);
            }

            return null;
        }

        if ($node instanceof Expr\MethodCall
            && $node->var instanceof Expr\Variable
            && is_string($node->var->name)
            && $node->name instanceof Node\Identifier
            && in_array($node->name->toString(), ['load', 'loadMissing'], true)) {
            $this->addEagerLoads($node->var->name, $this->extractRelationshipsFromEagerLoadCall($node));
        }

        // `$shelf->books->load('publisher')` loads onto every book, which is `books.publisher`
        // loaded on the shelf, and leaves `books` itself in memory.
        if ($node instanceof Expr\MethodCall
            && $node->var instanceof Expr\PropertyFetch
            && $node->var->var instanceof Expr\Variable
            && is_string($node->var->var->name)
            && $node->var->name instanceof Node\Identifier
            && $node->name instanceof Node\Identifier
            && in_array($node->name->toString(), ['load', 'loadMissing'], true)) {
            $relation = $node->var->name->toString();
            $nested = array_map(
                static fn (string $loaded): string => $relation.'.'.$loaded,
                $this->extractRelationshipsFromEagerLoadCall($node),
            );
            $this->addEagerLoads($node->var->var->name, [$relation, ...$nested]);
        }

        // `$shelf->setRelation('books', $x)` puts a value the scan knows nothing about in the
        // relation's place: the relation is in memory, and its elements cannot be judged.
        if ($node instanceof Expr\MethodCall
            && $node->var instanceof Expr\Variable
            && is_string($node->var->name)
            && $node->name instanceof Node\Identifier
            && $node->name->toString() === 'setRelation'
            && ($node->args[0] ?? null) instanceof Node\Arg
            && $node->args[0]->value instanceof Node\Scalar\String_) {
            $relation = $node->args[0]->value->value;
            $this->addEagerLoads($node->var->name, [$relation, $relation.'.'.self::OPAQUE_ELEMENTS]);
        }

        return null;
    }

    /**
     * @param  array<string>  $relationships
     */
    private function addEagerLoads(string $var, array $relationships): void
    {
        if ($relationships !== []) {
            $this->eagerLoads[$var] = array_values(array_unique(
                array_merge($this->eagerLoads[$var] ?? [], $relationships)
            ));
        }
    }

    /**
     * Pre-populate a variable's model type and eager loads from outside the scanner's own
     * AST walk (e.g. controller context passed into a Blade view, which has no query
     * assignment of its own to infer from).
     *
     * @param  list<string>  $eagerLoads
     */
    public function seed(string $var, ?string $type, array $eagerLoads): void
    {
        if ($type !== null) {
            $this->types[$var] = $type;
        }
        if ($eagerLoads !== []) {
            $this->eagerLoads[$var] = array_values($eagerLoads);
        }
        $this->origins[$var] = $var;
    }

    public function typeOf(string $var): ?string
    {
        return $this->types[$var] ?? null;
    }

    /**
     * The model type an expression evaluates to, read as the same expression assigned to a
     * variable would be (`Post::all()` is a `Collection<Post>`), or `null`.
     */
    public function typeOfExpression(Expr $expr): ?string
    {
        return $this->modelQueryType($expr);
    }

    /**
     * The relations an expression's own query chain eager-loads (`Post::with('author')->get()`).
     *
     * @return list<string>
     */
    public function eagerLoadsOfExpression(Expr $expr): array
    {
        return array_values($this->extractEagerLoadedRelationships($expr));
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
     * The render-bound variable name a variable ultimately derives from (see `$origins`), or
     * `null` if it was never seeded or aliased from a seeded variable.
     */
    public function originOf(string $var): ?string
    {
        return $this->origins[$var] ?? null;
    }

    /**
     * Drop everything known about a variable, for a loop that rebinds it to something whose
     * type cannot be derived.
     */
    public function forget(string $var): void
    {
        unset($this->types[$var], $this->eagerLoads[$var], $this->origins[$var], $this->relationPaths[$var]);
    }

    /**
     * The dotted relation path from a variable's origin (see `$relationPaths`), or `null` for
     * a variable that is not reached through a relation.
     */
    public function relationPathOf(string $var): ?string
    {
        return $this->relationPaths[$var] ?? null;
    }

    /**
     * Type a variable that holds a to-many relation read off another, such as `$book` in
     * `foreach ($shelf->books as $book)`, whose model the caller has already established.
     *
     * Eager loads carry over by their path below the relation, so `books.publisher` loaded on
     * `$shelf` reads as `publisher` loaded on `$book`, and the origin carries over unchanged.
     */
    public function deriveFromRelation(string $from, string $relation, string $to, string $type): void
    {
        $prefix = $relation.'.';
        $eagerLoads = [];
        foreach ($this->eagerLoads[$from] ?? [] as $loaded) {
            if (str_starts_with($loaded, $prefix)) {
                $eagerLoads[] = substr($loaded, strlen($prefix));
            }
        }

        $path = isset($this->relationPaths[$from]) ? $this->relationPaths[$from].'.'.$relation : $relation;

        $this->forget($to);

        if (in_array(self::OPAQUE_ELEMENTS, $eagerLoads, true)) {
            return;
        }

        $this->types[$to] = $type;

        if ($eagerLoads !== []) {
            $this->eagerLoads[$to] = $eagerLoads;
        }

        if (isset($this->origins[$from])) {
            $this->origins[$to] = $this->origins[$from];
            $this->relationPaths[$to] = $path;
        }
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
        // Assignment, not merge: compiled Blade copies every loop from the same synthetic key, so a
        // reused loop-variable name must not inherit the previous loop's type, eager loads, or origin.
        unset($this->types[$to], $this->eagerLoads[$to], $this->origins[$to], $this->relationPaths[$to]);

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

        if (isset($this->origins[$from])) {
            $this->origins[$to] = $this->origins[$from];
        }

        if (isset($this->relationPaths[$from])) {
            $this->relationPaths[$to] = $this->relationPaths[$from];
        }
    }

    /**
     * Propagate a variable's type and eager loads, unchanged, to the compiled Blade loop
     * variable that aliases it (`$__currentLoopData = $from;`).
     *
     * Compiled Blade `@foreach` rewrites `foreach ($cities as $city)` into
     * `$__currentLoopData = $cities; foreach ($__currentLoopData as $city): ...` — without this,
     * the loop's actual source variable (`$__currentLoopData`) never resolves back to the
     * seeded/inferred type on `$cities`, so `copyContext()` on the loop var has nothing to read.
     * The caller restricts this to that one synthetic target (see `BLADE_LOOP_SOURCE`) precisely
     * because a real user assignment like `$renamed = $posts;` is not an alias in the same sense —
     * propagating through it would widen plain-`.php` N+1 detection, which is unchanged by design.
     * Unlike `copyContext()`, this keeps a `Collection<Model>` type as-is (an alias holds the
     * same value, not its element).
     */
    private function aliasVariable(string $from, string $to): void
    {
        if (isset($this->types[$from])) {
            $this->types[$to] = $this->types[$from];
        }

        if (isset($this->eagerLoads[$from])) {
            $this->eagerLoads[$to] = $this->eagerLoads[$from];
        }

        if (isset($this->origins[$from])) {
            $this->origins[$to] = $this->origins[$from];
        }

        if (isset($this->relationPaths[$from])) {
            $this->relationPaths[$to] = $this->relationPaths[$from];
        }
    }

    /**
     * Detect model query assignments and record variable types.
     *
     * Handles: $posts = Post::get(), $posts = Post::with('user')->get(), $post = Post::find(1)
     */
    private function detectModelQuery(Expr $expr, string $varName): void
    {
        $type = $this->modelQueryType($expr);
        if ($type !== null) {
            $this->types[$varName] = $type;
        }
    }

    /**
     * The model type a query expression returns, or `null` when it is not a recognized
     * model query.
     */
    private function modelQueryType(Expr $expr): ?string
    {
        // Direct static call: Post::all(), Post::get(), Post::find(1)
        if ($expr instanceof Expr\StaticCall &&
            $expr->class instanceof Node\Name &&
            $expr->name instanceof Node\Identifier) {
            $className = $this->modelClassName($expr->class);

            return $className !== null ? $this->queryResultType($className, $expr->name->toString()) : null;
        }

        // Chained method calls: Post::where()->get(), Post::with('user')->get()
        if ($expr instanceof Expr\MethodCall && $expr->name instanceof Node\Identifier) {
            $className = $this->resolveModelFromChain($expr);
            if ($className !== null) {
                return $this->queryResultType($className, $expr->name->toString());
            }
        }

        return null;
    }

    /**
     * The short name a query rooted at $class types its result by, or null when the class
     * is a facade or utility whose query-shaped methods return something other than models
     * (`Cache::get()`, `DB::table()->get()`).
     *
     * Resolved through the consumer's imports, so an aliased model is named by its class
     * and a model that shares a facade's short name keeps its type.
     */
    private function modelClassName(Node\Name $class): ?string
    {
        if ($this->isNonQueryClass($class, self::NON_MODEL_CLASSES)) {
            return null;
        }

        return $this->lastSegment($this->resolvedClassFqn($class));
    }

    protected function resolvedClassFqn(Node\Name $class): string
    {
        return ($this->resolveClass)($class);
    }

    private function queryResultType(string $className, string $method): ?string
    {
        $lowerMethod = strtolower($method);
        if (in_array($lowerMethod, ['get', 'all', 'paginate', 'simplepaginate'], true)) {
            return "Collection<{$className}>";
        }

        if (in_array($lowerMethod, ['find', 'first', 'findorfail', 'firstorfail'], true)) {
            return $className;
        }

        return null;
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
            return $this->modelClassName($current->class);
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

        // withWhereHas($relation, $callback) eager-loads through with(), as
        // `with([$relation => $callback])` when a constraint is given and `with($relation)`
        // when not, so it is read as that call.
        if ($methodName === 'withWhereHas') {
            $relation = $expr->args[0] ?? null;
            if (! $relation instanceof Node\Arg || ! $relation->value instanceof Node\Scalar\String_) {
                return [];
            }

            $callback = $expr->args[1] ?? null;
            if ($callback instanceof Node\Arg &&
                ($callback->value instanceof Expr\Closure || $callback->value instanceof Expr\ArrowFunction)) {
                return $this->parseRelationshipArgument(new Expr\Array_([new Node\ArrayItem($callback->value, $relation->value)]));
            }

            return $this->parseRelationshipArgument($relation->value);
        }

        if (! in_array($methodName, ['with', 'load', 'loadMissing'], true)) {
            return [];
        }

        // Extract relationships from all arguments (Laravel supports variadic: with('user', 'comments'))
        if (empty($expr->args)) {
            return [];
        }

        $relationships = [];
        foreach ($expr->args as $arg) {
            // A first-class callable (with(...)) yields a VariadicPlaceholder, which has no value.
            if ($arg instanceof Node\Arg) {
                $relationships = array_merge(
                    $relationships,
                    $this->parseRelationshipArgument($arg->value)
                );
            }
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
        $nested = [];

        // Handle array of relationships: with(['user', 'comments']) or with(['user' => fn() => ...])
        if ($arg instanceof Expr\Array_) {
            foreach ($arg->items as $item) {
                // Check if relationship name is in the key (closure-keyed arrays)
                // e.g., ['user' => fn($q) => $q->select('id')]
                if ($item->key instanceof Node\Scalar\String_) {
                    $rawRelationships[] = $item->key->value;

                    $relationship = explode(':', $item->key->value, 2)[0];
                    // A closure constrains the relation and may load more beneath it; an array
                    // lists what is loaded beneath it (`['books' => ['publisher']]`), which
                    // Laravel flattens to `books.publisher`.
                    $inner = match (true) {
                        $item->value instanceof Expr\Closure,
                        $item->value instanceof Expr\ArrowFunction => $this->closureEagerLoads($item->value),
                        $item->value instanceof Expr\Array_ => $this->parseRelationshipArgument($item->value),
                        default => [],
                    };
                    foreach ($inner as $loaded) {
                        $nested[] = $relationship.'.'.$loaded;
                    }
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

        return array_unique([...$expanded, ...$nested]);
    }

    /**
     * What the constraint closure of a closure-keyed eager load loads in turn, relative to
     * the relation it constrains: `fn ($q) => $q->with('publisher')` under `books` loads
     * `publisher`, and a chaperone() or inverse() call there makes the elements opaque (see
     * OPAQUE_ELEMENTS).
     *
     * A closure nested inside is not walked here: its with() is reached through the argument
     * that holds it, which reads it under its own key.
     *
     * @return list<string>
     */
    private function closureEagerLoads(Expr\Closure|Expr\ArrowFunction $closure): array
    {
        $calls = [];
        $this->collectOwnCalls($closure instanceof Expr\Closure ? $closure->stmts : [$closure->expr], $calls);

        $loads = [];
        foreach ($calls as $call) {
            if ($call->name instanceof Node\Identifier &&
                in_array(strtolower($call->name->toString()), ['chaperone', 'inverse'], true)) {
                $loads[] = self::OPAQUE_ELEMENTS;

                continue;
            }

            foreach ($this->extractRelationshipsFromEagerLoadCall($call) as $relationship) {
                $loads[] = $relationship;
            }
        }

        return array_values(array_unique($loads));
    }

    /**
     * Every method and static call under $nodes, stopping at nested function-likes.
     *
     * @param  array<mixed>  $nodes
     * @param  list<Expr\MethodCall|Expr\StaticCall>  $calls
     */
    private function collectOwnCalls(array $nodes, array &$calls): void
    {
        foreach ($nodes as $node) {
            if (is_array($node)) {
                $this->collectOwnCalls($node, $calls);

                continue;
            }

            if (! $node instanceof Node || $node instanceof Node\FunctionLike) {
                continue;
            }

            if ($node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall) {
                $calls[] = $node;
            }

            foreach ($node->getSubNodeNames() as $name) {
                $this->collectOwnCalls([$node->{$name}], $calls);
            }
        }
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
