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
 * missing-database-transactions and AuthenticationAnalyzer use, and it works. What it costs is
 * a second walk over every file and, because parseFile() hands back a shared tree, resolution
 * written into that tree for as long as the cache lives. So the choice for a down-reaching
 * reader is between a separate pass and an import table, not between a broken one and a
 * working one.
 *
 * An import table does not have that problem. `namespace` and `use` are always ancestors or
 * earlier siblings of the code using them, so the table is complete before any expression
 * is entered and the answer no longer depends on which direction the reader looks, or on
 * when the traverser arrives. The one shape this gives up is a `use` written textually
 * after the code it applies to: PHP accepts it, a single forward pass does not.
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
    private ?NameContext $importedNames = null;

    /**
     * Start every traversal with an empty table.
     *
     * Declared here rather than left to each consumer, because a consumer that forgot it would
     * not fail: importedNames() would hand back a lazily built table that is then never reset
     * between files, so file N would be resolved with file N-1's imports and nothing in the
     * suite would notice. A trait method wins over the one inherited from NodeVisitorAbstract,
     * but not over one the consumer declares itself; a consumer that needs its own
     * beforeTraverse has to call startTrackingImports() from it.
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
     */
    private function startTrackingImports(): void
    {
        $this->importedNames = $this->freshImportTable();
    }

    /**
     * Record a namespace or import declaration as the traversal reaches it.
     */
    private function trackImports(Node $node): void
    {
        if ($node instanceof Stmt\Namespace_) {
            $this->importedNames()->startNamespace($node->name);

            return;
        }

        if ($node instanceof Stmt\Use_) {
            foreach ($node->uses as $use) {
                $this->importedNames()->addAlias(
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
                $this->importedNames()->addAlias(
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
        return ltrim($this->importedNames()->getResolvedClassName($class)->toString(), '\\');
    }

    private function importedNames(): NameContext
    {
        return $this->importedNames ??= $this->freshImportTable();
    }

    /**
     * NameContext::$namespace is typed with no default, so startNamespace() has to run
     * before any lookup or reading it throws.
     */
    private function freshImportTable(): NameContext
    {
        // Nothing reads this handler's errors, and that is the point: the only error it can
        // collect is a colliding alias, which is an import set PHP would itself reject, and the
        // documented answer to one is to keep the first spelling and carry on. Collecting is
        // chosen over Throwing so that the collision costs one alias instead of the file, and
        // over a handler that reports so that a file which could never have compiled does not
        // turn into an analyzer finding about the analyzer.
        $context = new NameContext(new ErrorHandler\Collecting);
        $context->startNamespace();

        return $context;
    }
}
