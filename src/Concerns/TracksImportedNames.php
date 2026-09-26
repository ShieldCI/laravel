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
 * reads it. A visitor that reaches down from an ancestor cannot.
 * EloquentNPlusOneAnalyzer::getQueryChainDescription() is called on entering the outer
 * MethodCall of `Event::where(...)->get()` and walks down to the chain-root StaticCall,
 * which the traverser has not reached yet, so nothing is annotated there. Reading an
 * attribute there yields nothing, and any reader that answers with the name as written then
 * matches `Event` against the Event facade on its last segment and exempts the query, which
 * is #423 over again. AuthenticationAnalyzer keeps a separate resolving pass for the same
 * reason.
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
 * the cache lives. It does not make the walk as a whole cache-clean: ParentConnectingVisitor,
 * in the same traverser, still writes a parent attribute onto every node it reaches.
 */
trait TracksImportedNames
{
    private ?NameContext $importedNames = null;

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
     * resolved this way without having to know it.
     */
    private function resolvedClassFqn(Name $class): string
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
        $context = new NameContext(new ErrorHandler\Collecting);
        $context->startNamespace();

        return $context;
    }
}
