<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use PhpParser\Node;

/**
 * One spelling of the subject a declaration is reported under.
 *
 * A named class, trait, interface or enum reports under its own name. An anonymous class
 * has none, and the two ways of coping with that are both bad on their own: withholding
 * the finding hides a real defect, and reporting "Unknown" names nothing the reader can
 * open. So it reports under the thing that identifies it, in the order PHP itself uses
 * when it builds a runtime name, which is what a stack trace will show for the same
 * declaration.
 *
 * Shared because several analyzers answer this question, and the answers had drifted:
 * one withheld the finding, one said "Unknown" and one said "Anonymous" for the very
 * same construct.
 */
trait NamesDeclarations
{
    /**
     * The subject to report this declaration under.
     *
     * PHP spells the parent or interface an anonymous class borrows its name from as it
     * resolves it, so `use Illuminate\Database\Migrations\Migration;` followed by
     * `new class extends Migration {}` is Illuminate\Database\Migrations\Migration@anonymous.
     * A caller walking a tree no resolver has rewritten passes the resolution it uses for
     * every other name; without one, the name is taken as written.
     *
     * @param  string|null  $enclosing  Name of the declaration this one sits inside, if any
     * @param  (\Closure(Node\Name): string)|null  $resolve  Fully qualified name behind a reference
     */
    private function declarationName(Node\Stmt\ClassLike $node, ?string $enclosing = null, ?\Closure $resolve = null): string
    {
        if ($node->name !== null) {
            return $node->name->toString();
        }

        // Only a class reaches here, because every other declaration carries a name. PHP
        // names an anonymous one after its parent, or failing that the first interface it
        // implements. The check is what tells the type checker those two properties exist,
        // not a real branch.
        if ($node instanceof Node\Stmt\Class_) {
            $inherited = $node->extends ?? $node->implements[0] ?? null;

            if ($inherited !== null) {
                return ($resolve === null ? $inherited->toString() : $resolve($inherited)).'@anonymous';
            }
        }

        // Nothing inherited to borrow from, so fall back to the declaration it sits in.
        // A bare anonymous class at file level keeps PHP's own spelling, class@anonymous.
        return ($enclosing ?? 'class').'@anonymous';
    }
}
