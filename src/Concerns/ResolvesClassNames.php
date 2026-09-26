<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use PhpParser\Error;
use PhpParser\Node;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;

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
 * One of those three is left, missing-database-transactions. eloquent-n-plus-one and
 * chunk-missing collect imports during their own traversal instead (TracksImportedNames),
 * because each reads a class name by reaching down from an ancestor, which a pass that
 * annotates nodes on arrival cannot serve.
 *
 * unguarded-models is a caller too, and not one of the three. It matches class names from a
 * findNodes() query rather than a walk, so there is no traversal for an import table to
 * piggyback on and the arrival-order problem never arises; what it needs from here is the
 * caught throw.
 */
trait ResolvesClassNames
{
    /**
     * Resolve names on an AST, degrading to the unresolved AST rather than failing.
     *
     * What gets dropped is the resolution, not the file: matching falls back to the name
     * as written, which is what every one of these analyzers did before any of them
     * resolved names. That loses a true positive on a file PHP could not have run anyway,
     * and it loses nothing else.
     *
     * replaceNodes stays off because parseFile() hands back a shared, cached AST, and
     * replacing nodes in it would rewrite what every later analyzer sees.
     *
     * @param  array<Node>  $ast
     * @return array<Node>
     */
    private function resolveNamesForMatching(ParserInterface $parser, array $ast): array
    {
        try {
            return $parser->resolveNames($ast, ['replaceNodes' => false]);
        } catch (Error) {
            return $ast;
        }
    }
}
