<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use PhpParser\ErrorHandler;
use PhpParser\NameContext;
use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt;

/**
 * Resolves a class name from imports collected during the walk, rather than from an
 * attribute a separate pass left on the node.
 *
 * A visitor that reads a class name only at the node owning it can let NameResolver share
 * its traverser, because NameResolver resolves `$node->class` on entering the StaticCall
 * itself and a resolver registered first has annotated the node before a later visitor
 * reads it. A visitor that reaches down from an ancestor cannot share a traverser that way.
 * EloquentNPlusOneAnalyzer::getQueryChainDescription() is called on entering the outer
 * MethodCall of `Event::where(...)->get()` and walks down to the chain-root StaticCall,
 * which the traverser has not reached yet, so nothing is annotated there. Reading an
 * attribute there yields nothing, and any reader that answers with the name as written then
 * matches `Event` against the Event facade on its last segment and exempts the query, which
 * is #423 over again.
 *
 * A resolving pass in a traverser of its own does serve a down-reaching read: it finishes
 * annotating every Name in the file before the analysis walk starts, which is the arrangement
 * missing-database-transactions and AuthenticationAnalyzer use. So the choice for a
 * down-reaching reader is between a separate pass and an import table, not between a broken
 * one and a working one.
 *
 * The pass costs a second walk over every file, and resolution written into the tree
 * parseFile() shares, for as long as the cache lives. It also costs a guard: a NameResolver
 * built with no error handler gets ErrorHandler\Throwing, so a file whose two `use`
 * statements land on one alias errors the analyzer unless the call site catches it.
 * missing-database-transactions catches it, through
 * ResolvesClassNames::resolveNamesForMatching(); AuthenticationAnalyzer's four sites do not,
 * which is #445.
 *
 * An import table does not have that problem. The answer comes from the table rather than
 * from an annotation on the node, so it no longer depends on which direction the reader
 * looks: reaching down to a StaticCall the traverser has not visited yet reads the same
 * table the StaticCall's own visit would.
 *
 * Collecting as the walk arrives is also what PHP does, and nothing is given up by it. PHP
 * adds an import where it reads the `use`, not across the enclosing block, so given
 * `namespace A; class C { D::class } use B\D; class E { D::class }` the first class sees
 * `A\D` and the second sees `B\D`. Filling the table from a scope's statement list before
 * the walk would answer `B\D` for both, handing one class an exemption that belongs to
 * another, which is #423 again. Answering as PHP does is resolvedClassFqn()'s contract
 * below, and IdentifiesNonQueryClasses declares it in the same words.
 *
 * Only the alias collection lives here, transcribed from NameResolver::enterNode() and
 * ::addAlias(); resolution itself stays with php-parser's NameContext. Every import type is
 * passed through rather than filtered to TYPE_NORMAL, because NameContext keeps a bucket
 * per type and getResolvedClassName() reads only the one it wants.
 *
 * The table is the visitor's own state, so nothing here is written to the AST. That matters
 * because parseFile() hands back a shared, mtime-cached tree, and a resolving pass over it
 * leaves a resolvedName attribute on every Name node and a namespacedName on every
 * declaration, or a FullyQualified in place of each Name with replaceNodes on, for as long as
 * the cache lives.
 *
 * Whether the walk as a whole is cache-clean is then the consumer's to decide, because it owns
 * the traverser. chunk-missing registers this visitor alone, so its walk writes nothing at all
 * and a test pins that. eloquent-n-plus-one also registers ParentConnectingVisitor, which
 * writes a parent attribute onto every node it reaches, so there the gain is the resolution
 * half only.
 *
 * @internal This trait is an implementation detail shared between this package's analyzers,
 * and its shape is not covered by the package's backward-compatibility promise.
 */
trait TracksImportedNames
{
    /**
     * Built by startTrackingImports() alone, which beforeTraverse() calls before php-parser
     * reaches the first node. Left uninitialised rather than nullable so that a consumer
     * bypassing that call throws on its first lookup instead of resolving a file against a
     * table nothing filled.
     *
     * The throw does not reach the user: both consumers skip a file on \Throwable, so a
     * bypass costs every file and the analyzer still returns passed(). What it buys is a red
     * suite, which the nullable property did not: delete beforeTraverse() with the `??=` in
     * place and every test stays green.
     */
    private NameContext $importedNames;

    /**
     * Start every traversal with an empty table.
     *
     * This is the only place the table is built. A trait method wins over the one inherited
     * from NodeVisitorAbstract, but not over one the consumer declares itself, so a consumer
     * that needs its own beforeTraverse has to call startTrackingImports() from it, which is
     * the reason that method is separate from this one.
     *
     * This resets the table and nothing else. It is the trait's own state, not the consumer's,
     * so a visitor with other per-file state still has to reset that itself or be built fresh
     * per file, which is what both consumers do.
     *
     * @param  array<Node>  $nodes
     */
    public function beforeTraverse(array $nodes): ?array
    {
        $this->startTrackingImports();

        return null;
    }

    /**
     * Begin a fresh import table, discarding any previous traversal's.
     *
     * A colliding alias is an import set PHP would itself reject. The collecting handler
     * records it and keeps the first spelling rather than throwing part-way through a walk,
     * so a file that could never have compiled is still analysed with the imports that do
     * make sense, instead of falling back to bare names for the whole file.
     *
     * NameContext::$namespace is typed with no default, so startNamespace() has to run
     * before any lookup or reading it throws.
     */
    private function startTrackingImports(): void
    {
        // Nothing reads this handler's errors, and that is the point. Collecting is chosen
        // over Throwing so that a collision costs one alias instead of the file, and over a
        // handler that reports so that a file which could never have compiled does not turn
        // into an analyzer finding about the analyzer.
        $this->importedNames = new NameContext(new ErrorHandler\Collecting);
        $this->importedNames->startNamespace();
    }

    /**
     * Record a namespace or import declaration as the traversal reaches it.
     */
    private function trackImports(Node $node): void
    {
        if ($node instanceof Stmt\Namespace_) {
            $this->importedNames->startNamespace($node->name);

            return;
        }

        if ($node instanceof Stmt\Use_) {
            foreach ($node->uses as $use) {
                $this->importedNames->addAlias(
                    $use->name,
                    (string) $use->getAlias(),
                    $node->type | $use->type,
                    $use->getAttributes(),
                );
            }

            return;
        }

        if ($node instanceof Stmt\GroupUse) {
            foreach ($node->uses as $use) {
                // Spelled out rather than Name::concat(), whose signature is nullable on
                // both operands and so reads as fallible here when it is not.
                $this->importedNames->addAlias(
                    new Name($node->prefix->toString().'\\'.$use->name->toString()),
                    (string) $use->getAlias(),
                    $node->type | $use->type,
                    $use->getAttributes(),
                );
            }
        }
    }

    /**
     * The fully qualified name behind a class reference, as PHP would resolve it at the
     * point the file writes it.
     *
     * This satisfies the declaration IdentifiesNonQueryClasses leaves open, so that every
     * caller of classMatches() and isNonQueryClass() in a visitor using both traits is
     * resolved this way without having to know it. protected to match that declaration, which
     * cannot be private without pinning every consumer's resolver into the consumer's own file.
     */
    protected function resolvedClassFqn(Name $class): string
    {
        return ltrim($this->importedNames->getResolvedClassName($class)->toString(), '\\');
    }

    /**
     * The fully qualified name of a class-like declaration, or null for an anonymous class,
     * which nothing elsewhere can name to ask about.
     *
     * A declaration is not a reference and does not go through getResolvedClassName(): its name
     * is always a single segment and always qualified by the namespace it is written in, never
     * by an import. `use App\Order;` followed by `class Order {}` in `namespace App\Http`
     * declares App\Http\Order, and resolving the name as a reference would answer App\Order.
     *
     * Reading the namespace off the table rather than a namespacedName property is what lets a
     * reader answer this without a NameResolver pass having annotated the tree.
     */
    protected function declarationFqn(Stmt\ClassLike $class): ?string
    {
        if ($class->name === null) {
            return null;
        }

        $namespace = $this->importedNames->getNamespace();

        return $namespace === null
            ? $class->name->toString()
            : ltrim($namespace->toString(), '\\').'\\'.$class->name->toString();
    }
}
