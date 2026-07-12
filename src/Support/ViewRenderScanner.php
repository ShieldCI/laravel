<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;

/**
 * Walks controller PHP files for `view(...)` render sites, resolves each view name to its
 * Blade file path, and records what each passed variable IS (its inferred Eloquent model
 * type and eager-loaded relations) so a later Blade-side analysis pass can be seeded with
 * the type information a template cannot derive on its own.
 */
class ViewRenderScanner
{
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

            $this->scanStatements($ast, basename($file), $viewsBasePath, $registry, $finder);
        }

        return $registry;
    }

    /**
     * Two-level walk: recurse into namespaces, then handle each top-level class's methods
     * and each top-level function as its own inference scope.
     *
     * @param  array<Node>  $stmts
     */
    private function scanStatements(array $stmts, string $fileBasename, string $viewsBasePath, ViewBindingRegistry $registry, NodeFinder $finder): void
    {
        foreach ($stmts as $stmt) {
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
            }
        }
    }

    /**
     * Run ModelVariableScanner over a single method/function body, then resolve every
     * `view(...)` render site found within it.
     *
     * @param  array<Node>  $stmts
     */
    private function scanScope(array $stmts, string $source, string $viewsBasePath, ViewBindingRegistry $registry, NodeFinder $finder): void
    {
        $viewCalls = $finder->find($stmts, static fn (Node $n): bool => $n instanceof Expr\FuncCall
            && $n->name instanceof Node\Name
            && $n->name->toString() === 'view');

        if ($viewCalls === []) {
            return;
        }

        $scanner = new ModelVariableScanner;
        $traverser = new NodeTraverser;
        $traverser->addVisitor($scanner);
        $traverser->traverse($stmts);

        foreach ($viewCalls as $viewCall) {
            if (! $viewCall instanceof Expr\FuncCall) {
                continue; // @codeCoverageIgnore — guaranteed by the finder predicate above
            }

            $this->handleViewCall($viewCall, $stmts, $source, $viewsBasePath, $registry, $finder, $scanner);
        }
    }

    /**
     * @param  array<Node>  $scopeStmts
     */
    private function handleViewCall(
        Expr\FuncCall $viewCall,
        array $scopeStmts,
        string $source,
        string $viewsBasePath,
        ViewBindingRegistry $registry,
        NodeFinder $finder,
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

        $withCalls = $finder->find($scopeStmts, fn (Node $n): bool => $n instanceof Expr\MethodCall
            && $n->name instanceof Node\Identifier
            && $n->name->toString() === 'with'
            && $this->chainRoot($n) === $viewCall);

        foreach ($withCalls as $withCall) {
            if (! $withCall instanceof Expr\MethodCall) {
                continue; // @codeCoverageIgnore — guaranteed by the finder predicate above
            }

            $bindings = array_merge($bindings, $this->extractWithBindings($withCall->args));
        }

        foreach ($bindings as $bladeVar => $phpVar) {
            $type = $phpVar !== null ? $scanner->typeOf($phpVar) : null;
            $eagerLoads = $phpVar !== null ? $scanner->eagerLoadsOf($phpVar) : [];
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
     * Extract variable bindings from a `view('x', <expr>)` second argument: either an array
     * literal (`['cities' => $cities]`) or a `compact('a', 'b')` call.
     *
     * @return array<string, ?string>
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
     * @return array<string, ?string>
     */
    private function extractArrayBindings(Expr\Array_ $array): array
    {
        $bindings = [];
        foreach ($array->items as $item) {
            if ($item === null || ! $item->key instanceof Node\Scalar\String_) {
                continue;
            }

            $bindings[$item->key->value] = ($item->value instanceof Expr\Variable && is_string($item->value->name))
                ? $item->value->name
                : null;
        }

        return $bindings;
    }

    /**
     * @return array<string, ?string>
     */
    private function extractCompactBindings(Expr\FuncCall $call): array
    {
        $bindings = [];
        foreach ($call->args as $arg) {
            if ($arg instanceof Node\Arg && $arg->value instanceof Node\Scalar\String_) {
                $bindings[$arg->value->value] = $arg->value->value;
            }
        }

        return $bindings;
    }

    /**
     * Extract variable bindings from `->with('key', $value)` or `->with(['key' => $value])`.
     *
     * @param  array<Node\Arg|Node\VariadicPlaceholder>  $args
     * @return array<string, ?string>
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
            $valueExpr = $values[1]->value;

            return [
                $values[0]->value->value => ($valueExpr instanceof Expr\Variable && is_string($valueExpr->name))
                    ? $valueExpr->name
                    : null,
            ];
        }

        return [];
    }
}
