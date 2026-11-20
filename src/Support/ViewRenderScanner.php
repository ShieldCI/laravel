<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\Concerns\TracksImportedNames;

/**
 * Walks controller and route PHP files for `view(...)` render sites, resolves each view name
 * to its Blade file path, and records what each passed variable IS (its inferred Eloquent
 * model type and eager-loaded relations) so a later Blade-side analysis pass can be seeded
 * with the type information a template cannot derive on its own.
 */
class ViewRenderScanner
{
    // Not a visitor: scanStatements() walks top-level statements by hand, so the import table
    // is driven by hand too, startTrackingImports() per file and trackImports() per statement,
    // and the beforeTraverse() hook the trait also offers goes unused here.
    use TracksImportedNames;

    public function __construct(private readonly ParserInterface $parser) {}

    /**
     * @param  list<string>  $phpFiles
     */
    public function scan(array $phpFiles, string $viewsBasePath): ViewBindingRegistry
    {
        $registry = new ViewBindingRegistry;
        $finder = new NodeFinder;

        foreach ($phpFiles as $file) {
            $ast = $this->parser->parseFile($file);
            if ($ast === []) {
                continue;
            }

            $this->startTrackingImports();
            $this->scanStatements($ast, basename($file), $viewsBasePath, $registry, $finder);
        }

        return $registry;
    }

    /**
     * Two-level walk: recurse into namespaces, then handle each top-level class's methods,
     * each top-level function, and each closure or arrow function in top-level code (a route
     * file's `Route::get('/', function () { ... })`) as its own inference scope.
     *
     * @param  array<Node>  $stmts
     */
    private function scanStatements(array $stmts, string $fileBasename, string $viewsBasePath, ViewBindingRegistry $registry, NodeFinder $finder): void
    {
        foreach ($stmts as $stmt) {
            // In file order, which is where PHP adds an import, so a scope below resolves a
            // class name the way the file does.
            $this->trackImports($stmt);

            if ($stmt instanceof Stmt\Namespace_) {
                $this->scanStatements($stmt->stmts, $fileBasename, $viewsBasePath, $registry, $finder);

                continue;
            }

            if ($stmt instanceof Stmt\Class_) {
                $className = $stmt->name?->toString() ?? $fileBasename;
                foreach ($stmt->stmts as $classStmt) {
                    if ($classStmt instanceof Stmt\ClassMethod && $classStmt->stmts !== null) {
                        $source = $className.'::'.$classStmt->name->toString();
                        $this->scanScope($classStmt->stmts, $source, $viewsBasePath, $registry, $finder);
                    }
                }

                continue;
            }

            if ($stmt instanceof Stmt\Function_) {
                $this->scanScope($stmt->stmts, $fileBasename, $viewsBasePath, $registry, $finder);

                continue;
            }

            if ($stmt instanceof Stmt\ClassLike) {
                continue;
            }

            // Every closure is its own scope, however deeply nested: a route nested in a group
            // callback is a closure inside a closure.
            $noScope = null;
            $this->walkClosureScopes([$stmt], $noScope, $fileBasename, $viewsBasePath, $registry);
        }
    }

    /**
     * One walk over top-level code that treats each closure and arrow function as a scope of
     * its own, feeding each node to the ModelVariableScanner of the closure nearest to it and
     * collecting that closure's render sites and `->with(...)` calls on the way. A closure's
     * render sites are resolved once its body has been walked.
     *
     * A node belongs to its nearest closure only. Were the enclosing closure to read a nested
     * render site too, it would be recorded a second time with whatever that closure assigned
     * to the same name, and walking each closure's subtree again for each scope would cost a
     * pass per nesting level. A node inside a named function-like (an anonymous class's
     * method) belongs to no closure.
     *
     * @param  array<mixed>  $nodes
     * @param  array{scanner: ModelVariableScanner, viewCalls: list<Expr\FuncCall>, withCalls: list<Expr\MethodCall>}|null  $scope
     *
     * @param-out array{scanner: ModelVariableScanner, viewCalls: list<Expr\FuncCall>, withCalls: list<Expr\MethodCall>}|null  $scope
     */
    private function walkClosureScopes(array $nodes, ?array &$scope, string $source, string $viewsBasePath, ViewBindingRegistry $registry): void
    {
        foreach ($nodes as $node) {
            if (is_array($node)) {
                $this->walkClosureScopes($node, $scope, $source, $viewsBasePath, $registry);

                continue;
            }

            if (! $node instanceof Node) {
                continue;
            }

            if ($node instanceof Expr\Closure || $node instanceof Expr\ArrowFunction) {
                $inner = [
                    'scanner' => new ModelVariableScanner(fn (Node\Name $class): string => $this->resolvedClassFqn($class)),
                    'viewCalls' => [],
                    'withCalls' => [],
                ];
                $this->walkClosureScopes($this->subNodes($node), $inner, $source, $viewsBasePath, $registry);

                if ($inner !== null) {
                    foreach ($inner['viewCalls'] as $viewCall) {
                        $this->handleViewCall($viewCall, $inner['withCalls'], $source, $viewsBasePath, $registry, $inner['scanner']);
                    }
                }

                continue;
            }

            if ($node instanceof Node\FunctionLike) {
                $none = null;
                $this->walkClosureScopes($this->subNodes($node), $none, $source, $viewsBasePath, $registry);

                continue;
            }

            if ($scope !== null) {
                $scope['scanner']->enterNode($node);

                if ($this->isViewCall($node)) {
                    $scope['viewCalls'][] = $node;
                } elseif ($this->isWithCall($node)) {
                    $scope['withCalls'][] = $node;
                }
            }

            $this->walkClosureScopes($this->subNodes($node), $scope, $source, $viewsBasePath, $registry);
        }
    }

    /**
     * @return list<mixed>
     */
    private function subNodes(Node $node): array
    {
        $subNodes = [];
        foreach ($node->getSubNodeNames() as $name) {
            $subNodes[] = $node->{$name};
        }

        return $subNodes;
    }

    /**
     * @phpstan-assert-if-true Expr\MethodCall $node
     */
    private function isWithCall(Node $node): bool
    {
        return $node instanceof Expr\MethodCall
            && $node->name instanceof Node\Identifier
            && $node->name->toString() === 'with';
    }

    /**
     * @phpstan-assert-if-true Expr\FuncCall $node
     */
    private function isViewCall(Node $node): bool
    {
        return $node instanceof Expr\FuncCall
            && $node->name instanceof Node\Name
            && $node->name->toString() === 'view';
    }

    /**
     * Run ModelVariableScanner over a single method/function body, then resolve every
     * `view(...)` render site found within it.
     *
     * @param  array<Node>  $stmts
     */
    private function scanScope(array $stmts, string $source, string $viewsBasePath, ViewBindingRegistry $registry, NodeFinder $finder): void
    {
        $viewCalls = array_filter(
            $finder->findInstanceOf($stmts, Expr\FuncCall::class),
            static fn (Expr\FuncCall $n): bool => $n->name instanceof Node\Name
                && $n->name->toString() === 'view',
        );

        if ($viewCalls === []) {
            return;
        }

        $scanner = new ModelVariableScanner(fn (Node\Name $class): string => $this->resolvedClassFqn($class));
        $traverser = new NodeTraverser;
        $traverser->addVisitor($scanner);
        $traverser->traverse($stmts);

        $withCalls = array_values(array_filter(
            $finder->findInstanceOf($stmts, Expr\MethodCall::class),
            static fn (Expr\MethodCall $n): bool => $n->name instanceof Node\Identifier
                && $n->name->toString() === 'with',
        ));

        foreach ($viewCalls as $viewCall) {
            $this->handleViewCall($viewCall, $withCalls, $source, $viewsBasePath, $registry, $scanner);
        }
    }

    /**
     * @param  list<Expr\MethodCall>  $scopeWithCalls  Every `->with(...)` call in the scope,
     *                                                 found once per scope rather than per
     *                                                 render site.
     */
    private function handleViewCall(
        Expr\FuncCall $viewCall,
        array $scopeWithCalls,
        string $source,
        string $viewsBasePath,
        ViewBindingRegistry $registry,
        ModelVariableScanner $scanner,
    ): void {
        if (! isset($viewCall->args[0]) || ! $viewCall->args[0] instanceof Node\Arg) {
            return;
        }

        $nameArg = $viewCall->args[0]->value;
        if (! $nameArg instanceof Node\Scalar\String_) {
            return; // dynamic view name — skip
        }

        $viewFile = $viewsBasePath.'/'.str_replace('.', '/', $nameArg->value).'.blade.php';

        $bindings = [];
        if (isset($viewCall->args[1]) && $viewCall->args[1] instanceof Node\Arg) {
            $bindings = $this->extractBindings($viewCall->args[1]->value);
        }

        $withCalls = array_filter(
            $scopeWithCalls,
            fn (Expr\MethodCall $n): bool => $this->chainRoot($n) === $viewCall,
        );

        foreach ($withCalls as $withCall) {
            $bindings = array_merge($bindings, $this->extractWithBindings($withCall->args));
        }

        foreach ($bindings as $bladeVar => $value) {
            // A variable is typed by what the scope assigned to it; any other expression
            // (`['posts' => Post::all()]`) is typed the way that assignment would have been.
            if ($value instanceof Expr\Variable) {
                $type = is_string($value->name) ? $scanner->typeOf($value->name) : null;
                $eagerLoads = is_string($value->name) ? $scanner->eagerLoadsOf($value->name) : [];
            } else {
                $type = $scanner->typeOfExpression($value);
                $eagerLoads = $type !== null ? $scanner->eagerLoadsOfExpression($value) : [];
            }

            $registry->add($viewFile, $bladeVar, new ViewBinding($type, $eagerLoads, $source));
        }
    }

    /**
     * Walk a `->with(...)` call's object chain back to its root, so it can be matched
     * against the specific `view(...)` FuncCall it was chained onto.
     */
    private function chainRoot(Expr\MethodCall $call): Node
    {
        $current = $call->var;
        while ($current instanceof Expr\MethodCall) {
            $current = $current->var;
        }

        return $current;
    }

    /**
     * Extract the bound value of each variable from a `view('x', <expr>)` second argument:
     * either an array literal (`['cities' => $cities]`) or a `compact('a', 'b')` call.
     *
     * @return array<string, Expr>
     */
    private function extractBindings(Node $expr): array
    {
        if ($expr instanceof Expr\Array_) {
            return $this->extractArrayBindings($expr);
        }

        if ($expr instanceof Expr\FuncCall && $expr->name instanceof Node\Name && $expr->name->toString() === 'compact') {
            return $this->extractCompactBindings($expr);
        }

        return [];
    }

    /**
     * @return array<string, Expr>
     */
    private function extractArrayBindings(Expr\Array_ $array): array
    {
        $bindings = [];
        foreach ($array->items as $item) {
            if (! $item->key instanceof Node\Scalar\String_) {
                continue;
            }

            $bindings[$item->key->value] = $item->value;
        }

        return $bindings;
    }

    /**
     * @return array<string, Expr>
     */
    private function extractCompactBindings(Expr\FuncCall $call): array
    {
        $bindings = [];
        foreach ($call->args as $arg) {
            if ($arg instanceof Node\Arg && $arg->value instanceof Node\Scalar\String_) {
                $bindings[$arg->value->value] = new Expr\Variable($arg->value->value);
            }
        }

        return $bindings;
    }

    /**
     * Extract variable bindings from `->with('key', $value)` or `->with(['key' => $value])`.
     *
     * @param  array<Node>  $args  Raw argument list; only plain Args carry a value.
     * @return array<string, Expr>
     */
    private function extractWithBindings(array $args): array
    {
        $values = [];
        foreach ($args as $arg) {
            if ($arg instanceof Node\Arg) {
                $values[] = $arg;
            }
        }

        if (count($values) === 1 && $values[0]->value instanceof Expr\Array_) {
            return $this->extractArrayBindings($values[0]->value);
        }

        if (count($values) === 2 && $values[0]->value instanceof Node\Scalar\String_) {
            return [$values[0]->value->value => $values[1]->value];
        }

        return [];
    }
}
