<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use PhpParser\ErrorHandler;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;

/**
 * Turns the names a file writes into the names it means.
 *
 * An analyzer that decides anything from a class name has to resolve it first, or
 * `Event::` reads as whichever Event the analyzer thought of rather than the one the
 * file imported. That is what #423 was filed about, and the three analyzers that match
 * on class names had each grown their own copy of the same two lines.
 *
 * The copies mattered because they shared a failure too. NameResolver rejects an import
 * set PHP would itself reject, two `use` statements landing on one alias, by throwing,
 * and each of those analyzers wraps its file loop in a catch-and-continue. A file whose
 * imports collide was therefore dropped from the analysis entirely, without so much as a
 * recorded parse failure to say so, even though the file had parsed and most of what the
 * analyzer looks for does not turn on a class name at all.
 *
 * None of those three is left: missing-database-transactions, eloquent-n-plus-one and
 * chunk-missing all collect imports during their own traversal instead (TracksImportedNames).
 * Each reads a class name by reaching down from an ancestor, which this pass does serve,
 * because it runs in a traverser of its own and finishes before the analysis walk starts;
 * what the table saves them is the second walk over every file and the resolution this pass
 * leaves in the shared parse cache.
 *
 * Two callers remain, and neither was one of the three. unguarded-models matches class names
 * from a findNodes() query rather than a walk, so there is no traversal for an import table
 * to piggyback on. authentication-authorization reads route files with a visitor that reaches
 * down from an ancestor, and its middleware alias maps with findNodes() queries, so it needs
 * the whole file annotated before it looks.
 */
trait ResolvesClassNames
{
    /**
     * Resolve names on an AST, losing only the alias a collision lands on.
     *
     * A collision is recorded and ignored rather than thrown: the first spelling is kept and
     * every other name in the file still resolves. That is the policy TracksImportedNames
     * applies, for the same reason.
     *
     * Catching the throw and handing back the unresolved AST is not equivalent. NameResolver
     * throws where it reaches the second `use`, so every name after it would stay as written.
     * For unguarded-models that only loses a finding on a file PHP could not have run. For
     * authentication-authorization it adds findings, because that analyzer reports the
     * absence of auth: a middleware class left as its bare short name reads as an
     * unregistered alias, and a route the middleware protects is reported as unauthenticated.
     *
     * replaceNodes stays off because parseFile() hands back a shared, cached AST, and
     * replacing nodes in it would rewrite what every later analyzer sees.
     *
     * @param  array<Node>  $ast
     * @return array<Node>
     */
    private function resolveNamesForMatching(array $ast): array
    {
        $traverser = new NodeTraverser;
        $traverser->addVisitor(new NameResolver(new ErrorHandler\Collecting, ['replaceNodes' => false]));

        return $traverser->traverse($ast);
    }
}
